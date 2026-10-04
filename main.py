import queue
import threading

from scapy.all import IP, TCP

from api import create_app
from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem


class IntrusionDetectionSystem:

    def __init__(self, interface):

        self.packet_capture = (
            PacketCapture()
        )

        self.traffic_analyzer = (
            TrafficAnalyzer()
        )

        self.detection_engine = (
            DetectionEngine()
        )

        self.alert_system = (
            AlertSystem()
        )

        self.interface = interface

    def start(self):

        print(
            f"Starting IDS on interface: "
            f"{self.interface}"
        )

        self.packet_capture.start_capture(
            self.interface
        )

        print(
            "Packet capture started."
        )

        print(
            "Monitoring network traffic..."
        )

        print(
            "Press CTRL+C to stop.\n"
        )

        while True:

            try:

                packet = (
                    self.packet_capture
                    .packet_queue
                    .get(timeout=1)
                )

                features = (
                    self.traffic_analyzer
                    .analyze_packet(packet)
                )

                if features:

                    threats = (
                        self.detection_engine
                        .detect_threats(features)
                    )

                    for threat in threats:

                        packet_info = {

                            'source_ip':
                                packet[IP].src,

                            'destination_ip':
                                packet[IP].dst,

                            'source_port':
                                packet[TCP].sport,

                            'destination_port':
                                packet[TCP].dport

                        }

                        self.alert_system.generate_alert(
                            threat,
                            packet_info
                        )

            except queue.Empty:

                continue

            except KeyboardInterrupt:

                print(
                    "\nStopping IDS..."
                )

                self.packet_capture.stop()

                break


if __name__ == "__main__":

    interface = (
        "Wi-Fi"
    )

    ids = IntrusionDetectionSystem(
        interface
    )

    
    app = create_app(ids.packet_capture)
    threading.Thread(
        target=lambda: app.run(port=5000, use_reloader=False),
        daemon=True
    ).start()

    ids.start()