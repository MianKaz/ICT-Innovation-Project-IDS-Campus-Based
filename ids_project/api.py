import os
import sqlite3
from flask import Flask, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'db', 'ids.db')
app = Flask(__name__, static_folder=os.path.join(BASE, 'web'), static_url_path='')

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, src TEXT, sport INTEGER,
    dst TEXT, dport INTEGER, proto TEXT, flags TEXT, length INTEGER, info TEXT);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, threat_type TEXT,
    source_ip TEXT, source_port INTEGER, destination_ip TEXT, destination_port INTEGER,
    confidence REAL, detector TEXT);   -- detector: 'signature' or an ML model name
"""

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with db() as con:
        con.executescript(SCHEMA)

@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/alerts')
def alerts():
    limit = request.args.get('limit', 100, type=int)
    with db() as con:
        rows = [dict(r) for r in con.execute(
            'SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))]
        s = con.execute(
            "SELECT COUNT(*) t, SUM(confidence >= 0.85) h, "
            "SUM(detector IN ('signature', 'random_forest')) s, "
            "SUM(detector = 'isolation_forest') a FROM alerts").fetchone()
        by_type = {r['threat_type']: r['n'] for r in con.execute(
            'SELECT threat_type, COUNT(*) n FROM alerts GROUP BY threat_type')}
    return jsonify(alerts=rows, stats=dict(
        total=s['t'] or 0, high=s['h'] or 0, signature=s['s'] or 0,
        anomaly=s['a'] or 0, by_type=by_type))

@app.route('/api/packets')
def packets():
    limit = request.args.get('limit', 50, type=int)
    where, args = [], []
    if ip := request.args.get('ip'):
        where.append('(src = ? OR dst = ?)'); args += [ip, ip]
    if proto := request.args.get('proto'):
        where.append('UPPER(proto) = ?'); args.append(proto.upper())
    if port := request.args.get('port', type=int):
        where.append('(sport = ? OR dport = ?)'); args += [port, port]
    sql = 'SELECT * FROM packets' + (' WHERE ' + ' AND '.join(where) if where else '') \
          + ' ORDER BY id DESC LIMIT ?'
    with db() as con:
        return jsonify([dict(r) for r in con.execute(sql, args + [limit])])

@app.route('/api/clear', methods=['POST'])
def clear():
    if request.headers.get('X-IDS-Action') != 'clear':
        return jsonify(error='Missing or invalid X-IDS-Action header'), 400

    try:
        from datetime import datetime
        from src.storage import LOG_FILE, _log_lock

        con = sqlite3.connect(DB, timeout=10)
        try:
            with con:
                alerts_deleted = con.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
                packets_deleted = con.execute('SELECT COUNT(*) FROM packets').fetchone()[0]
                con.execute('DELETE FROM alerts')
                con.execute('DELETE FROM packets')
                con.execute(
                    "DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'packets')")
        finally:
            con.close()

        with _log_lock:
            if LOG_FILE.exists():
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup = LOG_FILE.with_name(
                    f'alerts_backup_{timestamp}.jsonl')
                LOG_FILE.rename(backup)

        return jsonify(status='cleared', alerts_deleted=alerts_deleted,
                       packets_deleted=packets_deleted)
    except Exception as exc:
        return jsonify(error=str(exc)), 500

def run():
    init_db()
    app.run(host='127.0.0.1', port=5000, threaded=True)

if __name__ == '__main__':
    run()
