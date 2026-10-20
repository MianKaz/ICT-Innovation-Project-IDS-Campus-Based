from scapy.all import sniff, IP, TCP
from collections import deque
import threading
import queue


class PacketCapture:

    def __init__(self, max_recent_packets=200):
        """Create the queue and a short in-memory history for the web dashboard."""
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.recent_packets = deque(maxlen=max_recent_packets)

    def packet_callback(self, packet):
        """Store TCP/IP packets for the IDS queue and dashboard history."""
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
            self.recent_packets.append({
                'time': float(packet.time),
                'src': packet[IP].src,
                'sport': packet[TCP].sport,
                'dst': packet[IP].dst,
                'dport': packet[TCP].dport,
                'flags': packet[TCP].flags,
                'length': len(packet),
            })

    def get_recent(self, limit=50):
        """Return the newest packets collected so the dashboard can render them."""
        packet_list = list(self.recent_packets)
        return packet_list[-limit:]

    def start_capture(self, interface):
        """Start a background thread that captures packets from the selected interface."""

        def capture_thread():

            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_capture.is_set()
            )

        self.capture_thread = threading.Thread(
            target=capture_thread
        )

        self.capture_thread.start()

    def stop(self):
        """Stop the packet capture thread cleanly."""
        self.stop_capture.set()
        self.capture_thread.join()