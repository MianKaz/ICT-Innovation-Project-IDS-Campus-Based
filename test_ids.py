import unittest

from scapy.all import IP, TCP

from detection_engine import DetectionEngine
from traffic_analyzer import TrafficAnalyzer


class TrafficDetectionTests(unittest.TestCase):

    def setUp(self):
        self.analyzer = TrafficAnalyzer()
        self.detector = DetectionEngine()

    def make_packet(self, source_ip, source_port, destination_port, timestamp):
        packet = (
            IP(src=source_ip, dst='192.168.1.2')
            / TCP(sport=source_port, dport=destination_port, flags='S')
        )
        packet.time = timestamp
        return packet

    def test_one_syn_packet_does_not_trigger_alert(self):
        packet = self.make_packet('192.168.1.100', 4321, 22, 1.0)

        features = self.analyzer.analyze_packet(packet)
        threats = self.detector.detect_threats(features)

        # One initial packet is not enough evidence for either signature.
        self.assertEqual(features['packet_rate'], 0.0)
        self.assertEqual(threats, [])

    def test_scan_is_counted_across_destination_ports(self):
        for port_offset in range(self.detector.PORT_SCAN_THRESHOLD):
            packet = self.make_packet(
                '192.168.1.100',
                4321,
                20 + port_offset,
                2.0 + port_offset * 0.1
            )
            features = self.analyzer.analyze_packet(packet)

        threats = self.detector.detect_threats(features)

        self.assertIn('port_scan', [threat['rule'] for threat in threats])

    def test_syn_burst_is_counted_across_connections(self):
        for packet_number in range(self.detector.SYN_FLOOD_THRESHOLD):
            packet = self.make_packet(
                '192.168.1.100',
                40000 + packet_number,
                80,
                3.0 + packet_number * 0.005
            )
            features = self.analyzer.analyze_packet(packet)

        threats = self.detector.detect_threats(features)

        self.assertIn('syn_flood', [threat['rule'] for threat in threats])


if __name__ == '__main__':
    unittest.main()