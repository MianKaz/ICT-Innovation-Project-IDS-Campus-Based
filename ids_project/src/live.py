"""The live detector. Packets come in from capture.py, then:
  1. every packet is shown in the Live Traffic table
  2. JSON rules with sliding windows look for scans, floods and ARP spoofing (primary design)
  3. packets are grouped into flows, and each finished flow goes through the flow
     signature rules, the Random Forest and the Isolation Forest (AI design)
  4. alerts are merged, stored in the database and logged to logs/alerts.jsonl"""
import queue
import time
from datetime import datetime

import pandas as pd

from src import config, decision, live_config, signature, storage
from src.alerting import AlertSink
from src.flow_builder import FlowBuilder
from src.packet_rules import PacketRules


def models_available():
    d = config.MODELS_DIR
    return all((d / f).exists() for f in ('rf_model.joblib', 'iso_model.joblib',
                                          'features.json', 'thresholds.json'))


class LivePipeline:
    def __init__(self, iface=None, pcap=None, bpf='', backend='scapy'):
        if backend == 'pyshark':
            from src.capture_pyshark import PySharkCapture
            self.cap = PySharkCapture(iface, pcap, bpf or live_config.CAPTURE_FILTER)
        else:
            from src import capture
            self.cap = capture.Capture(iface, pcap, bpf or live_config.CAPTURE_FILTER)
        self.offline = pcap is not None
        self.rules, self.flows, self.sink = PacketRules(), FlowBuilder(), AlertSink()
        self.ml = None
        if models_available():
            from src.ml_engine import MLEngine
            self.ml = MLEngine()
            print('AI models loaded (Random Forest + Isolation Forest).')
        else:
            print('No trained models found, so only the rules are active. Run train.py for the AI part.')
        self.stats = {'packets': 0, 'flows': 0, 'alerts': 0}
        self._sec, self._shown, self._last_ts = 0, 0, 0.0

    def start_capture(self):
        self.cap.start()

    # ---- per packet ----
    def _handle(self, p, batch, pending):
        self.stats['packets'] += 1
        self._last_ts = p['ts']
        sec = int(time.time())
        if sec != self._sec:
            self._sec, self._shown = sec, 0
        if self.offline or self._shown < live_config.DISPLAY_MAX_PPS:   # the cap only applies to live capture
            self._shown += 1
            batch.append((datetime.now().strftime('%H:%M:%S'), p['src'], p['sport'], p['dst'],
                          p['dport'], p['proto'], p['flags'], p['length'], p['info']))
        if p['ipv4']:
            for alert in self.rules.check(p):
                self._emit(alert)
            if p['proto'] in ('TCP', 'UDP'):
                pending.extend(self.flows.add(p))

    def _emit(self, alert):
        if self.sink.emit(alert):
            self.stats['alerts'] += 1

    # ---- once a second ----
    def _flush(self, batch, pending, force=False):
        if batch:
            storage.add_packets(batch)
            batch.clear()
        now_us = self._last_ts if self.offline else time.time() * 1e6
        pending.extend(self.flows.expire(now_us, force=force))
        if pending:
            self._score(pending)
            pending.clear()
        self.rules.cleanup(now_us)

    def _score(self, rows):
        df = pd.DataFrame(rows)
        df = df[df['Flow Duration'] > 0]          # one-packet flows have no rates; the packet rules cover them
        if df.empty:
            return
        self.stats['flows'] += len(df)
        sig = signature.detect(df)
        if self.ml is not None:
            res = decision.decide(sig, self.ml.predict(df), self.ml.iso_threshold)
        else:
            res = pd.DataFrame({'alert': sig['sig_threat'] != '', 'threat_type': sig['sig_threat'],
                                'confidence': sig['sig_conf'], 'detector': 'signature'}, index=df.index)
        for (_, f), (_, r) in zip(df.iterrows(), res.iterrows()):
            if r['alert']:
                self._emit({'threat_type': r['threat_type'], 'confidence': float(r['confidence']),
                            'detector': r['detector'], 'source_ip': f['_src'], 'source_port': int(f['_sport']),
                            'destination_ip': f['_dst'], 'destination_port': int(f['_dport'])})

    def run(self):
        batch, pending, last_tick, last_report = [], [], time.time(), time.time()
        while True:
            try:
                p = self.cap.q.get(timeout=0.2)
                self._handle(p, batch, pending)
            except queue.Empty:
                p = None
            now = time.time()
            if now - last_tick >= 1.0 or len(batch) >= 500:
                self._flush(batch, pending)
                last_tick = now
            if not self.offline and now - last_report >= 15:
                print(f"[live] packets={self.stats['packets']:,} flows={self.stats['flows']:,} "
                      f"alerts={self.stats['alerts']:,} merged={self.sink.suppressed:,} "
                      f"dropped={self.cap.dropped:,}")
                last_report = now
            if self.offline and p is None and self.cap.done.is_set() and self.cap.q.empty():
                self._flush(batch, pending, force=True)
                print(f"Finished reading the file: {self.stats['packets']:,} packets, "
                      f"{self.stats['flows']:,} flows scored, {self.stats['alerts']:,} alerts.")
                return
