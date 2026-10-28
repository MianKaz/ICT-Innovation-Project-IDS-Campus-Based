"""Primary-design signature engine: JSON rules with sliding-window counters.

Each rule in rules.json has a protocol, condition, threshold, time window and severity:
  distinct_dst_ports  one source probing many TCP ports on one target (port scan)
  syn_count           one source sending many SYNs to one target port (SYN flood)
  packet_count        one source sending many ICMP echo requests (ICMP flood)
  ip_mac_change       an IP address suddenly claimed by a different MAC (ARP spoofing)
  bad_port            any traffic to or from a listed port, e.g. known backdoor ports (needs a "ports" list)
Add or change rules by editing rules.json, no code changes needed."""
import json
from collections import deque

from src import live_config

ACK, RST, SYN = 0x10, 0x04, 0x02


class PacketRules:
    def __init__(self, rules=None):
        self.rules = rules if rules is not None else json.loads(live_config.RULES_FILE.read_text())
        self.windows = {}    # (rule number, source, target) -> deque of (time, value)
        self.arp_table = {}  # IP -> MAC first seen

    @staticmethod
    def _event(cond, p, r):
        f = p['tflags']
        if cond == 'distinct_dst_ports':
            return p['dport'] if not (f & ACK) and not (f & RST) else None
        if cond == 'syn_count':
            return 1 if (f & SYN) and not (f & ACK) else None
        if cond == 'packet_count':
            return 1 if p.get('icmp_type') == 8 else None
        if cond == 'bad_port':
            return 1 if p['sport'] in r['ports'] or p['dport'] in r['ports'] else None
        return None

    def check(self, p):
        """Returns a list of alerts (usually empty) for one packet."""
        alerts = []
        for i, r in enumerate(self.rules):
            protocols = r['protocol'] if isinstance(r['protocol'], list) else [r['protocol']]
            if p['proto'] not in protocols:
                continue
            cond = r['condition']
            if cond == 'ip_mac_change':
                hit = self._arp_changed(p)
            else:
                value = self._event(cond, p, r)
                if value is None:
                    continue
                # a flood hits one service, so SYNs are counted per target port; a scan spreads over many
                key = (i, p['src'], '' if cond == 'packet_count' else p['dst'],
                       p['dport'] if cond == 'syn_count' else '')
                dq = self.windows.setdefault(key, deque())
                dq.append((p['ts'], value))
                cutoff = p['ts'] - r['window_sec'] * 1e6
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                count = len({v for _, v in dq}) if cond == 'distinct_dst_ports' else len(dq)
                hit = count >= r['threshold']
                if hit:
                    dq.clear()
            if hit:
                alerts.append({'threat_type': r['name'], 'severity': r['severity'], 'detector': 'signature',
                               'source_ip': p['src'], 'source_port': p['sport'],
                               'destination_ip': p['dst'], 'destination_port': p['dport']})
        return alerts

    def _arp_changed(self, p):
        ip, mac = p.get('arp_psrc'), p.get('arp_hwsrc')
        if not ip or ip == '0.0.0.0':
            return False
        known = self.arp_table.get(ip)
        self.arp_table[ip] = mac
        return known is not None and known != mac

    def cleanup(self, now_us):
        """Forget sources that went quiet, so memory stays small."""
        for key in [k for k, dq in self.windows.items() if not dq or now_us - dq[-1][0] > 60e6]:
            del self.windows[key]
