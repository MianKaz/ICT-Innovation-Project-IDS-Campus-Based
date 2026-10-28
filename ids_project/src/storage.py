"""All reads/writes to db/ids.db for the detection side (api.py only reads).
Alerts are also appended to logs/alerts.jsonl, one JSON object per line."""
import json
import sqlite3
import threading
from pathlib import Path

from api import DB, init_db

KEEP_PACKETS = 50000   # older packets are deleted so the database stays small
LOG_FILE = Path(DB).resolve().parent.parent / 'logs' / 'alerts.jsonl'
_log_lock = threading.Lock()


def init():
    init_db()
    with sqlite3.connect(DB) as con:
        con.execute('PRAGMA journal_mode=WAL')   # lets the API read while we write


def _run(sql, args=(), many=False):
    con = sqlite3.connect(DB, timeout=10)
    try:
        with con:
            (con.executemany if many else con.execute)(sql, args)
    finally:
        con.close()


def add_packet(time, src, sport, dst, dport, proto, flags, length, info):
    add_packets([(time, src, sport, dst, dport, proto, flags, length, info)])


def add_packets(rows):
    """rows: list of (time, src, sport, dst, dport, proto, flags, length, info)."""
    _run('INSERT INTO packets (time, src, sport, dst, dport, proto, flags, length, info) '
         'VALUES (?,?,?,?,?,?,?,?,?)', rows, many=True)


def severity_of(confidence):
    return 'high' if confidence >= 0.85 else 'medium' if confidence >= 0.7 else 'low'


def add_alert(timestamp, threat_type, source_ip, source_port,
              destination_ip, destination_port, confidence, detector, severity=None):
    """detector: 'signature' for rule hits, or a model name like 'random_forest'."""
    _run('INSERT INTO alerts (timestamp, threat_type, source_ip, source_port, '
         'destination_ip, destination_port, confidence, detector) VALUES (?,?,?,?,?,?,?,?)',
         (timestamp, threat_type, source_ip, source_port,
          destination_ip, destination_port, confidence, detector))
    record = {'timestamp': timestamp, 'rule': threat_type, 'severity': severity or severity_of(confidence),
              'source_ip': source_ip, 'source_port': source_port, 'destination_ip': destination_ip,
              'destination_port': destination_port, 'confidence': confidence, 'detector': detector}
    with _log_lock:
        LOG_FILE.parent.mkdir(exist_ok=True)
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')


def prune_packets():
    _run('DELETE FROM packets WHERE id <= (SELECT MAX(id) FROM packets) - ?', (KEEP_PACKETS,))
