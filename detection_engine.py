class DetectionEngine:

    # These are simple starting thresholds; tune them against campus traffic.
    SYN_FLOOD_THRESHOLD = 100
    PORT_SCAN_THRESHOLD = 10

    def detect_threats(self, features):

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