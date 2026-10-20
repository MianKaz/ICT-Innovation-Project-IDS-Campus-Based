import unittest

from detection_engine import DetectionEngine


class DetectionEngineTests(unittest.TestCase):
    def test_demo_thresholds_are_low_enough_for_demo(self):
        engine = DetectionEngine()
        self.assertLessEqual(engine.SYN_FLOOD_THRESHOLD, 10)
        self.assertLessEqual(engine.PORT_SCAN_THRESHOLD, 3)

    def test_demo_features_trigger_alert(self):
        engine = DetectionEngine()
        features = {
            'syn_count_1s': 15,
            'unique_syn_destination_ports': 5,
        }

        threats = engine.detect_threats(features)
        self.assertTrue(threats)


if __name__ == '__main__':
    unittest.main()
