"""Capture layer: reads packets from a network card (or a .pcap file) with Scapy,
turns each one into a small record and puts it on a queue for the detection side.
Capture and detection run in separate threads so a slow detector never makes us lose packets."""
import queue
import threading
import time

from src import live_config

try:
    from scapy.all import AsyncSniffer
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    raise SystemExit('Scapy is not installed. Run: pip install scapy')

TCP_FLAG_NAMES = [(0x02, 'SYN'), (0x10, 'ACK'), (0x01, 'FIN'), (0x04, 'RST'),
                  (0x08, 'PSH'), (0x20, 'URG'), (0x40, 'ECE'), (0x80, 'CWR')]


def _flag_text(flags):
    return ','.join(name for bit, name in TCP_FLAG_NAMES if flags & bit)


def _dns_text(pkt):
    try:
        d = pkt[DNS]
        name = d.qd.qname.decode(errors='replace').rstrip('.') if d.qd else ''
        return f"DNS {'response' if d.qr else 'query'} {name}"
    except Exception:
        return 'DNS'


def parse(pkt):
    """Scapy packet -> plain dict, or None for packets we ignore."""
    ts = float(pkt.time) * 1e6
    frame = len(pkt)
    base = dict(ts=ts, length=frame, flags='', tflags=0, payload=0, hdr=0, win=-1,
                sport=0, dport=0, ipv4=False)

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        op = int(a.op)
        info = f'Who has {a.pdst}? Tell {a.psrc}' if op == 1 else f'{a.psrc} is at {a.hwsrc}'
        return {**base, 'proto': 'ARP', 'src': str(a.psrc), 'dst': str(a.pdst), 'info': info,
                'arp_psrc': str(a.psrc), 'arp_hwsrc': str(a.hwsrc), 'arp_op': op, 'ipv4': True}

    if pkt.haslayer(IP):
        ip, v4 = pkt[IP], True
        ip_proto = int(ip.proto)
        src, dst, ihl, ip_len = str(ip.src), str(ip.dst), ip.ihl * 4, ip.len
    elif pkt.haslayer(IPv6):
        ip, v4 = pkt[IPv6], False
        ip_proto = None
        src, dst, ihl, ip_len = str(ip.src), str(ip.dst), 40, ip.plen + 40
    else:
        return None
    padded = live_config.COUNT_PADDING and pkt.haslayer(Ether)

    def payload_len(l4_header):
        total = frame - 14 - ihl - l4_header if padded else ip_len - ihl - l4_header
        return max(0, int(total))

    if pkt.haslayer(TCP) and ip_proto in (6, None):
        t = pkt[TCP]
        hl, flags = t.dataofs * 4, int(t.flags)
        payload = payload_len(hl)
        info = f'{t.sport} -> {t.dport} [{_flag_text(flags)}] Win={t.window} Len={payload}'
        return {**base, 'proto': 'TCP', 'src': src, 'dst': dst, 'sport': int(t.sport), 'dport': int(t.dport),
                'flags': _flag_text(flags), 'tflags': flags, 'payload': payload, 'hdr': hl,
                'win': int(t.window), 'info': info, 'ipv4': v4}
    if pkt.haslayer(UDP) and ip_proto in (17, None):
        u = pkt[UDP]
        payload = payload_len(8)
        info = _dns_text(pkt) if pkt.haslayer(DNS) else f'{u.sport} -> {u.dport} Len={payload}'
        return {**base, 'proto': 'UDP', 'src': src, 'dst': dst, 'sport': int(u.sport), 'dport': int(u.dport),
                'payload': payload, 'hdr': 8, 'info': info, 'ipv4': v4}
    if pkt.haslayer(ICMP) and ip_proto in (1, None):
        kind = int(pkt[ICMP].type)
        info = {8: 'Echo request', 0: 'Echo reply'}.get(kind, f'ICMP type {kind}')
        return {**base, 'proto': 'ICMP', 'src': src, 'dst': dst, 'info': info, 'icmp_type': kind, 'ipv4': v4}
    return None


class Capture:
    def __init__(self, iface=None, pcap=None, bpf=''):
        self.iface = iface or live_config.CAPTURE_IFACE
        self.pcap, self.bpf = pcap, bpf
        self.q = queue.Queue(maxsize=live_config.QUEUE_SIZE)
        self.dropped = 0
        self.done = threading.Event()      # set when a pcap file has been read completely
        self._sniffer = None

    def _on_packet(self, pkt):
        try:
            rec = parse(pkt)
        except Exception:
            return
        if rec is None:
            return
        if rec['src'] == rec['dst'] == '127.0.0.1' and 5000 in (rec['sport'], rec['dport']):
            return                         # the dashboard talking to itself, not network traffic
        if self.pcap:
            self.q.put(rec)                # reading a file: wait instead of dropping
        else:
            try:
                self.q.put_nowait(rec)
            except queue.Full:
                self.dropped += 1

    def start(self):
        try:
            self._start(self.bpf)
        except RuntimeError as e:
            if self.bpf and 'filter' in str(e).lower():
                print(f'Warning: the capture filter could not be applied ({e}). Capturing everything instead.')
                self._start('')
            else:
                raise

    def _start(self, bpf):
        kw = dict(prn=self._on_packet, store=False)
        if self.pcap:
            kw['offline'] = str(self.pcap)
        else:
            iface = self.iface
            if iface is not None and str(iface).isdigit():       # allow the Index number from --list-ifaces
                from scapy.all import conf
                iface = conf.ifaces.dev_from_index(int(iface))
            kw['iface'] = iface
            if bpf:
                kw['filter'] = bpf
        self._sniffer = AsyncSniffer(**kw)
        self._sniffer.start()
        time.sleep(1.0)
        err = getattr(self._sniffer, 'exception', None)
        if err is not None:
            raise RuntimeError(str(err))
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self):
        try:
            self._sniffer.join()
        finally:
            self.done.set()

    def stop(self):
        try:
            if self._sniffer is not None and self._sniffer.running:
                self._sniffer.stop()
        except Exception:
            pass


def list_interfaces():
    from scapy.all import show_interfaces
    show_interfaces()
