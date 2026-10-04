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

        # Each component handles one stage of the IDS packet-processing flow.
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

        # Packet capture runs in the background and places TCP/IP packets in a queue.
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

        try:
            while True:

                try:

                    # The timeout keeps the loop responsive when traffic is quiet.
                    packet = (
                        self.packet_capture
                        .packet_queue
                        .get(timeout=1)
                    )

                    # Convert a packet into measurements used by signature rules.
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

                            # Preserve connection details alongside the rule result.
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

                    # An empty queue is normal; keep monitoring for new packets.
                    continue

        except KeyboardInterrupt:

            print(
                "\nStopping IDS..."
            )

        finally:
            # Also request capture shutdown if packet processing raises an error.
            self.packet_capture.stop()


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