import json
from collections import Counter

from flask import Flask, jsonify, request
from flask_cors import CORS

RULE_LABELS = {
    "syn_flood": "SYN Flood Attack",
    "port_scan": "Port Scan",
}

WARNING_MARKER = " - WARNING - "


def parse_alert_line(line):
    """Turn one ids_alerts.log line into a clean dict, or None.

    AlertSystem writes the alert JSON on the WARNING line. The CRITICAL line
    for high-confidence threats is a duplicate, so it is skipped.
    """
    if WARNING_MARKER not in line:
        return None

    try:
        raw = json.loads(line.split(WARNING_MARKER, 1)[1])
    except ValueError:
        return None

    details = raw.get("details") or {}
    kind = raw.get("threat_type", "unknown")

    if kind == "signature":
        rule = details.get("rule", "signature")
        label = RULE_LABELS.get(rule, rule)
    else:
        label = "Anomaly Detected"

    return {
        "timestamp": raw.get("timestamp", ""),
        "threat_type": label,
        "kind": kind,
        "source_ip": raw.get("source_ip"),
        "source_port": raw.get("source_port"),
        "destination_ip": raw.get("destination_ip"),
        "destination_port": raw.get("destination_port"),
        "confidence": raw.get("confidence") or 0.0,
    }


def read_alerts(log_file):
    try:
        with open(log_file, encoding="utf-8", errors="replace") as f:
            return [a for a in map(parse_alert_line, f) if a]
    except FileNotFoundError:
        return []


def create_app(packet_capture, log_file="ids_alerts.log"):
    app = Flask(__name__)
    CORS(app)  

    @app.route("/api/alerts")
    def alerts():
        limit = request.args.get("limit", 100, type=int)
        all_alerts = read_alerts(log_file)

        stats = {
            "total": len(all_alerts),
            "high": sum(a["confidence"] > 0.8 for a in all_alerts),
            "signature": sum(a["kind"] == "signature" for a in all_alerts),
            "anomaly": sum(a["kind"] == "anomaly" for a in all_alerts),
            "by_type": dict(Counter(a["threat_type"] for a in all_alerts)),
        }

        # newest first
        return jsonify({"alerts": all_alerts[-limit:][::-1], "stats": stats})

    @app.route("/api/packets")
    def packets():
        limit = request.args.get("limit", 50, type=int)
        return jsonify(packet_capture.get_recent(limit)[::-1])

    return app