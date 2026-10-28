"""Last step before an alert is stored: whitelist, merge repeats, add severity."""
import ipaddress
import time
from datetime import datetime

from src import live_config, storage


class AlertSink:
    def __init__(self):
        self.last = {}
        self.suppressed = 0
        self.nets = [ipaddress.ip_network(n, strict=False) for n in live_config.WHITELIST_SUBNETS]

    def _whitelisted(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.nets)

    def emit(self, a):
        """Stores the alert unless it is whitelisted or a recent repeat. Returns True if stored."""
        if self._whitelisted(a['source_ip']):
            return False
        now = time.time()
        key = (a['threat_type'], a['source_ip'], a['destination_ip'])
        if now - self.last.get(key, 0) < live_config.ALERT_COOLDOWN_S:
            self.suppressed += 1
            return False
        self.last[key] = now
        if len(self.last) > 20_000:                       # keep memory small
            self.last = {k: t for k, t in self.last.items() if now - t < live_config.ALERT_COOLDOWN_S}

        confidence = a.get('confidence')
        if confidence is None:
            confidence = live_config.SEVERITY_CONFIDENCE.get(a.get('severity', 'high'), 0.9)
        storage.add_alert(datetime.now().isoformat(timespec='seconds'), a['threat_type'],
                          a['source_ip'], a['source_port'], a['destination_ip'], a['destination_port'],
                          round(float(confidence), 2), a['detector'], a.get('severity'))
        return True
