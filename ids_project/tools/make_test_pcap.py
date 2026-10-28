"""Writes test_traffic.pcap: normal traffic plus a port scan, SYN flood, ICMP flood, ARP spoof and a known-bad-port connection.
It only writes a file, nothing is sent on any network.
Use it with:  python main.py --pcap test_traffic.pcap"""
import random
import sys
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Padding, wrpcap

random.seed(7)
pkts = []
VICTIM, VMAC = '192.168.1.10', '02:00:00:00:00:10'
GATEWAY, GMAC, EVIL = '192.168.1.1', '02:00:00:00:00:01', '02:00:00:00:00:66'


def add(p, t):
    raw = bytes(p)
    if len(raw) < 60:                       # tiny frames are padded to 60 bytes on the wire
        p = p / Padding(b'\x00' * (60 - len(raw)))
    p.time = t
    pkts.append(p)


def tcp(src, dst, sport, dport, flags, t, payload=b'', win=29200, options=None):
    return add(Ether(src='02:00:00:00:00:aa', dst=VMAC) / IP(src=src, dst=dst) /
               TCP(sport=sport, dport=dport, flags=flags, window=win, options=options or []) / payload, t)


def conversation(client, server, dport, t):
    sport = random.randint(40000, 60000)
    tcp(client, server, sport, dport, 'S', t, options=[('MSS', 1460)])
    tcp(server, client, dport, sport, 'SA', t + .01, options=[('MSS', 1460)])
    tcp(client, server, sport, dport, 'A', t + .02)
    tcp(client, server, sport, dport, 'PA', t + .03, b'G' * 300)
    tcp(server, client, dport, sport, 'PA', t + .06, b'H' * 1200)
    tcp(client, server, sport, dport, 'A', t + .07)
    tcp(client, server, sport, dport, 'FA', t + .10)
    tcp(server, client, dport, sport, 'FA', t + .11)
    tcp(client, server, sport, dport, 'A', t + .12)


# normal traffic: web conversations and DNS lookups for ten minutes of "office" activity
for i in range(40):
    t = 1.0 + i * 1.5
    conversation(f'192.168.1.{20 + i % 8}', random.choice(['93.184.216.34', '151.101.1.69']), random.choice([80, 443]), t)
    add(Ether() / IP(src=f'192.168.1.{20 + i % 8}', dst='8.8.8.8') / UDP(sport=50000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname='example.com')), t + .2)
    add(Ether() / IP(src='8.8.8.8', dst=f'192.168.1.{20 + i % 8}') / UDP(sport=53, dport=50000 + i) /
        DNS(qr=1, qd=DNSQR(qname='example.com'), an=DNSRR(rrname='example.com', rdata='93.184.216.34')), t + .22)

# a machine connects out to a known backdoor port (4444)
conversation('192.168.1.23', '10.0.0.99', 4444, 65.0)

# port scan: one attacker probes 60 ports, closed ports answer with RST
for n, port in enumerate(range(20, 80)):
    t = 70 + n * 0.004
    tcp('10.0.0.66', VICTIM, 40000, port, 'S', t, win=1024, options=[('MSS', 1460)])
    tcp(VICTIM, '10.0.0.66', port, 40000, 'RA', t + .001, win=0)

# SYN flood: 300 SYNs at one web server within a second
for n in range(300):
    tcp('10.0.0.77', VICTIM, random.randint(1024, 65000), 80, 'S', 90 + n * 0.003)

# ICMP flood: 150 pings in a second
for n in range(150):
    add(Ether() / IP(src='10.0.0.88', dst=VICTIM) / ICMP(type=8) / (b'x' * 32), 100 + n * 0.006)

# ARP spoofing: the gateway's address is first claimed by its real MAC, then by another one
add(Ether(src=GMAC) / ARP(op=2, psrc=GATEWAY, hwsrc=GMAC, pdst=VICTIM, hwdst=VMAC), 110)
add(Ether(src=EVIL) / ARP(op=2, psrc=GATEWAY, hwsrc=EVIL, pdst=VICTIM, hwdst=VMAC), 112)

pkts.sort(key=lambda p: p.time)
out = Path(sys.argv[1] if len(sys.argv) > 1 else 'test_traffic.pcap')
wrpcap(str(out), pkts)
print(f'Wrote {len(pkts)} packets to {out}')
