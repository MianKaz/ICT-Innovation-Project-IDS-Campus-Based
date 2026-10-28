"""Demo traffic generator. Makes fake packets and occasional fake attacks so the
dashboard has something to show. Later this gets replaced by real capture and the
detection pipeline writing through storage.add_packet / storage.add_alert."""
import random
import time
from datetime import datetime

from src import storage

HOSTS = ['192.168.1.10', '192.168.1.20', '192.168.1.35', '192.168.1.50', '192.168.1.77']
SERVERS = ['8.8.8.8', '142.250.4.100', '104.16.85.20', '192.168.1.1']
SERVICES = [(80, 'TCP', 'HTTP'), (443, 'TCP', 'TLS'), (53, 'UDP', 'DNS'), (22, 'TCP', 'SSH')]

# (threat name, detector, base confidence)
ATTACKS = [
    ('Port Scan', 'signature', 0.97),
    ('SYN Flood Attack', 'signature', 0.98),
    ('DoS Hulk', 'random_forest', 0.92),
    ('Suspicious Flow', 'isolation_forest', 0.75),
]


def _packet(src, sport, dst, dport, proto, flags, length, info):
    storage.add_packet(datetime.now().strftime('%H:%M:%S'),
                       src, sport, dst, dport, proto, flags, length, info)


def normal_packet():
    src, dst = random.choice(HOSTS), random.choice(SERVERS)
    port, proto, name = random.choice(SERVICES)
    _packet(src, random.randint(49152, 65535), dst, port, proto,
            'ACK' if proto == 'TCP' else '', random.randint(60, 1400), f'{name} traffic')


def attack():
    name, detector, conf = random.choice(ATTACKS)
    src = f'10.0.0.{random.randint(2, 250)}'
    dst = random.choice(HOSTS)
    sport = random.randint(49152, 65535)
    dport = random.choice([22, 80, 443, 3389])
    for _ in range(4):
        _packet(src, sport, dst, random.choice([dport, random.randint(1, 1024)]),
                'TCP', 'SYN', 60, 'SYN (suspicious)')
    storage.add_alert(datetime.now().isoformat(timespec='seconds'), name, src, sport,
                      dst, dport, round(min(conf + random.uniform(-0.05, 0.02), 0.99), 2), detector)


def run(rate=5, attack_every=15):
    """rate = packets per second, attack_every = roughly seconds between attacks."""
    n = 0
    while True:
        normal_packet()
        n += 1
        if n % (rate * attack_every) == 0:
            attack()
        if n % 500 == 0:
            storage.prune_packets()
        time.sleep(1 / rate)
