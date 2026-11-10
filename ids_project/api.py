import os
import sqlite3
from datetime import datetime, timedelta
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
    where = []
    params = []
    range_since = None
    range_until = None

    if 'minutes' in request.args:
        raw_minutes = request.args.get('minutes', '')
        try:
            minutes = int(raw_minutes)
        except ValueError:
            return jsonify(error='minutes must be a positive integer no greater than 525600'), 400
        if minutes <= 0 or minutes > 525600:
            return jsonify(error='minutes must be a positive integer no greater than 525600'), 400

        now = datetime.now()
        range_since = (now - timedelta(minutes=minutes)).isoformat(timespec='seconds')
        range_until = now.isoformat(timespec='seconds')
        where.append('timestamp >= ?')
        params.extend([range_since, range_until])
        where.append('timestamp <= ?')
    else:
        since = None
        until = None
        try:
            if 'since' in request.args:
                since = datetime.fromisoformat(request.args['since'])
                if since.tzinfo is not None:
                    since = since.astimezone().replace(tzinfo=None)
                range_since = since.isoformat(timespec='seconds')
                where.append('timestamp >= ?')
                params.append(range_since)

            if 'until' in request.args:
                until = datetime.fromisoformat(request.args['until'])
                if until.tzinfo is not None:
                    until = until.astimezone().replace(tzinfo=None)
                range_until = until.isoformat(timespec='seconds')
                where.append('timestamp <= ?')
                params.append(range_until)
        except ValueError:
            return jsonify(error='since and until must be valid ISO date/time values'), 400

        if since and until and since > until:
            return jsonify(error='since must not be later than until'), 400

    where_sql = ' WHERE ' + ' AND '.join(where) if where else ''
    with db() as con:
        rows = [dict(r) for r in con.execute(
            'SELECT * FROM alerts' + where_sql + ' ORDER BY id DESC LIMIT ?',
            params + [limit])]
        s = con.execute(
            "SELECT COUNT(*) t, SUM(confidence >= 0.85) h, "
            "SUM(detector IN ('signature', 'random_forest')) s, "
            "SUM(detector = 'isolation_forest') a FROM alerts" + where_sql,
            params).fetchone()
        by_type = {r['threat_type']: r['n'] for r in con.execute(
            'SELECT threat_type, COUNT(*) n FROM alerts' + where_sql +
            ' GROUP BY threat_type', params)}
    response = dict(alerts=rows, stats=dict(
        total=s['t'] or 0, high=s['h'] or 0, signature=s['s'] or 0,
        anomaly=s['a'] or 0, by_type=by_type))
    response['range'] = {'since': range_since, 'until': range_until} if where else None
    return jsonify(response)

@app.route('/api/alerts/<int:alert_id>')
def alert_detail(alert_id):
    with db() as con:
        alert = con.execute(
            'SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        if alert is None:
            return jsonify(error='not found'), 404

        related_packets = [dict(r) for r in con.execute(
            'SELECT * FROM packets WHERE (src = ? AND dst = ?) OR (src = ? AND dst = ?) '
            'ORDER BY id DESC LIMIT 25',
            (alert['source_ip'], alert['destination_ip'],
             alert['destination_ip'], alert['source_ip']))]
        similar_alerts = con.execute(
            'SELECT COUNT(*) FROM alerts WHERE threat_type = ? AND source_ip = ?',
            (alert['threat_type'], alert['source_ip'])).fetchone()[0]

    return jsonify(alert=dict(alert), related_packets=related_packets,
                   similar_alerts=similar_alerts)

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
