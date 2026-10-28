"""PyShark capture backend (needs Wireshark / tshark installed). It does the same job as
capture.py, but lets Wireshark's decoder read the packets. Same queue, same records."""
import asyncio
import os
import queue
import threading
import time

from src import live_config

TCP_FLAG_NAMES = [(0x02, 'SYN'), (0x10, 'ACK'), (0x01, 'FIN'), (0x04, 'RST'),
                  (0x08, 'PSH'), (0x20, 'URG'), (0x40, 'ECE'), (0x80, 'CWR')]


def _flag_text(flags):
    return ','.join(name for bit, name in TCP_FLAG_NAMES if flags & bit)


def tshark_path():
    """The tshark.exe from live_config, or None to let PyShark search the PATH."""
    path = live_config.TSHARK_PATH
    return path if path and os.path.exists(path) else None


def parse_packet(pkt):
    """PyShark packet -> the same plain dict capture.parse() makes, or None to ignore it."""
    ts = float(pkt.sniff_timestamp) * 1e6
    frame = int(pkt.length)
    names = {layer.layer_name for layer in pkt.layers}
    base = dict(ts=ts, length=frame, flags='', tflags=0, payload=0, hdr=0, win=-1,
                sport=0, dport=0, ipv4=False)

    if 'arp' in names:
        a = pkt.arp
        op = int(a.opcode)
        psrc, hwsrc, pdst = str(a.src_proto_ipv4), str(a.src_hw_mac), str(a.dst_proto_ipv4)
        info = f'Who has {pdst}? Tell {psrc}' if op == 1 else f'{psrc} is at {hwsrc}'
        return {**base, 'proto': 'ARP', 'src': psrc, 'dst': pdst, 'info': info,
                'arp_psrc': psrc, 'arp_hwsrc': hwsrc, 'arp_op': op, 'ipv4': True}

    if 'ip' in names:
        ip, v4 = pkt.ip, True
        src, dst, ihl, ip_len = str(ip.src), str(ip.dst), int(ip.hdr_len), int(ip.len)
    elif 'ipv6' in names:
        ip, v4 = pkt.ipv6, False
        src, dst, ihl, ip_len = str(ip.src), str(ip.dst), 40, int(ip.plen) + 40
    else:
        return None
    padded = live_config.COUNT_PADDING and 'eth' in names

    def payload_len(l4_header):
        total = frame - 14 - ihl - l4_header if padded else ip_len - ihl - l4_header
        return max(0, int(total))

    if 'icmp' in names:                      # checked first: ICMP errors can carry an inner TCP header
        kind = int(pkt.icmp.type)
        info = {8: 'Echo request', 0: 'Echo reply'}.get(kind, f'ICMP type {kind}')
        return {**base, 'proto': 'ICMP', 'src': src, 'dst': dst, 'info': info, 'icmp_type': kind, 'ipv4': v4}
    if 'tcp' in names:
        t = pkt.tcp
        hl, flags = int(t.hdr_len), int(str(t.flags), 16)
        payload = payload_len(hl)
        win = int(t.window_size_value)
        info = f'{t.srcport} -> {t.dstport} [{_flag_text(flags)}] Win={win} Len={payload}'
        return {**base, 'proto': 'TCP', 'src': src, 'dst': dst, 'sport': int(t.srcport), 'dport': int(t.dstport),
                'flags': _flag_text(flags), 'tflags': flags, 'payload': payload, 'hdr': hl,
                'win': win, 'info': info, 'ipv4': v4}
    if 'udp' in names:
        u = pkt.udp
        payload = payload_len(8)
        if 'dns' in names:
            try:
                info = f"DNS {'response' if str(pkt.dns.flags_response) == '1' else 'query'} {pkt.dns.qry_name}"
            except AttributeError:
                info = 'DNS'
        else:
            info = f'{u.srcport} -> {u.dstport} Len={payload}'
        return {**base, 'proto': 'UDP', 'src': src, 'dst': dst, 'sport': int(u.srcport), 'dport': int(u.dstport),
                'payload': payload, 'hdr': 8, 'info': info, 'ipv4': v4}
    return None


class PySharkCapture:
    def __init__(self, iface=None, pcap=None, bpf=''):
        self.iface = iface or live_config.CAPTURE_IFACE or 'Wi-Fi'
        self.pcap, self.bpf = pcap, bpf
        self.q = queue.Queue(maxsize=live_config.QUEUE_SIZE)
        self.dropped = 0
        self.done = threading.Event()
        self.error = None
        self._cap = None

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        time.sleep(3.0)                      # tshark fails fast on a bad interface, so wait and check
        if self.error is not None:
            raise RuntimeError(str(self.error))

    def _run(self):
        import pyshark
        loop = asyncio.new_event_loop()      # this thread needs its own event loop
        asyncio.set_event_loop(loop)
        try:
            kw = dict(tshark_path=tshark_path(), eventloop=loop)
            if self.pcap:
                self._cap = pyshark.FileCapture(self.pcap, keep_packets=False, **kw)
                packets = self._cap
            else:
                self._cap = pyshark.LiveCapture(interface=self.iface, bpf_filter=self.bpf or None, **kw)
                packets = self._cap.sniff_continuously()
            for pkt in packets:
                try:
                    rec = parse_packet(pkt)
                except Exception:            # a packet with missing fields is skipped
                    continue
                if rec is None:
                    continue
                if rec['src'] == rec['dst'] == '127.0.0.1' and 5000 in (rec['sport'], rec['dport']):
                    continue                 # the dashboard talking to itself
                if self.pcap:
                    self.q.put(rec)
                else:
                    try:
                        self.q.put_nowait(rec)
                    except queue.Full:
                        self.dropped += 1
        except Exception as e:
            self.error = e
        finally:
            self.done.set()

    def stop(self):
        try:
            if self._cap is not None:
                self._cap.close()
        except Exception:
            pass


def list_interfaces():
    import subprocess
    path = tshark_path() or 'tshark'
    subprocess.run([path, '-D'])
