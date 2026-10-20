class DetectionEngine:

    # Lowered for a demo-friendly IDS; these can be tuned back higher later.
    SYN_FLOOD_THRESHOLD = 10
    PORT_SCAN_THRESHOLD = 3

    def generate_demo_threats(self):
        """Create a synthetic attack pattern that reliably triggers alerts."""
        return self.detect_threats({
            'syn_count_1s': max(self.SYN_FLOOD_THRESHOLD + 5, 15),
            'unique_syn_destination_ports': max(self.PORT_SCAN_THRESHOLD + 2, 5),
        })

    def detect_threats(self, features):
        """Analyze packet metrics and return a list of triggered IDS threats."""

        threats = []

        # Count SYN packets across connections to the same destination host.
        syn_count = features['syn_count_1s']
        if syn_count >= self.SYN_FLOOD_THRESHOLD:
            threats.append({
                'type': 'signature',
                'rule': 'syn_flood',
                'confidence': 1.0,
                'syn_count_1s': syn_count
            })

        # Count distinct SYN destination ports from one source to one host.
        port_count = features['unique_syn_destination_ports']
        if port_count >= self.PORT_SCAN_THRESHOLD:
            threats.append({
                'type': 'signature',
                'rule': 'port_scan',
                'confidence': 1.0,
                'unique_destination_ports': port_count
            })

        return threats