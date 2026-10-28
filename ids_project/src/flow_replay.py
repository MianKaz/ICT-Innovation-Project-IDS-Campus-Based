"""Replays real flows from the test set through the full hybrid pipeline
(signature rules + Random Forest + Isolation Forest), so the dashboard shows
genuine detections. The dataset has no IP addresses, so IPs and source ports
are made up for the demo. Each flow appears as one row in the traffic table."""
import time
from datetime import datetime

import numpy as np
import pandas as pd

from src import decision, preprocess, signature, storage
from src.ml_engine import MLEngine

ATTACK_SHARE = 0.05                    # about 5% of replayed flows are attacks
BATCH = 10                             # flows scored together per tick
INTERNAL = [f'192.168.10.{i}' for i in (5, 9, 12, 14, 15, 16, 17, 19, 25, 50)]
EXTERNAL = ['8.8.8.8', '142.250.4.100', '104.16.85.20', '151.101.1.69', '13.107.42.14']
ATTACKERS = ['205.174.165.73', '172.16.0.1', '205.174.165.69', '205.174.165.70']
UDP_PORTS = {53, 123, 137, 5353}


def run(flows_per_sec=10):
    test = preprocess.load_split('test')
    ml = MLEngine()
    is_attack = (test['Label'] != 'BENIGN').to_numpy()
    normal, attack = test[~is_attack], test[is_attack]
    rng = np.random.default_rng()
    ticks = 0

    while True:
        k = int(rng.binomial(BATCH, ATTACK_SHARE))
        batch = pd.concat([attack.sample(k), normal.sample(BATCH - k)]).sample(frac=1)
        res = decision.decide(signature.detect(batch), ml.predict(batch), ml.iso_threshold)

        for (_, flow), (_, r) in zip(batch.iterrows(), res.iterrows()):
            bad = flow['Label'] != 'BENIGN'
            src = str(rng.choice(ATTACKERS)) if bad else str(rng.choice(INTERNAL))
            dst = str(rng.choice(INTERNAL)) if bad else str(rng.choice(EXTERNAL + INTERNAL))
            sport, dport = int(rng.integers(1024, 65535)), int(flow['Destination Port'])
            now = datetime.now()
            storage.add_packet(
                now.strftime('%H:%M:%S'), src, sport, dst, dport,
                'UDP' if dport in UDP_PORTS else 'TCP', '',
                int(flow['Total Length of Fwd Packets'] + flow['Total Length of Bwd Packets']),
                f"Flow: {int(flow['Total Fwd Packets'])} fwd / {int(flow['Total Backward Packets'])} bwd pkts, "
                f"{flow['Flow Duration'] / 1000:,.1f} ms")
            if r['alert']:
                storage.add_alert(now.isoformat(timespec='seconds'), r['threat_type'], src, sport,
                                  dst, dport, float(r['confidence']), r['detector'])

        ticks += 1
        if ticks % 50 == 0:
            storage.prune_packets()
        time.sleep(BATCH / flows_per_sec)
