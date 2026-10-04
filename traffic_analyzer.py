from collections import defaultdict, deque

from scapy.all import IP, TCP


class TrafficAnalyzer:

    ACTIVITY_WINDOW_SECONDS = 10
    SYN_RATE_WINDOW_SECONDS = 1

    def __init__(self):

        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

        # Keep recent packets by host pair so scans across ports are grouped.
        self.host_activity = defaultdict(deque)

    def analyze_packet(self, packet):

        if IP in packet and TCP in packet:

            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (
                ip_src,
                ip_dst,
                port_src,
                port_dst
            )

            stats = self.flow_stats[flow_key]

            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)

            current_time = float(packet.time)

            if stats['start_time'] is None:
                stats['start_time'] = current_time

            stats['last_time'] = current_time

            tcp_flags = int(packet[TCP].flags)
            is_syn = bool(tcp_flags & 0x02 and not tcp_flags & 0x10)

            activity_key = (ip_src, ip_dst)
            activity = self.host_activity[activity_key]
            activity.append((current_time, port_dst, is_syn))

            # Expire old events so the counters represent only recent traffic.
            window_start = current_time - self.ACTIVITY_WINDOW_SECONDS
            while activity and activity[0][0] < window_start:
                activity.popleft()

            return self.extract_features(
                packet,
                stats,
                activity,
                current_time
            )

        return None

    def extract_features(self, packet, stats, activity, current_time):

        duration = (
            stats['last_time'] -
            stats['start_time']
        )

        # A single packet has no measurable rate yet; don't invent one.
        if duration > 0:
            packet_rate = stats['packet_count'] / duration
            byte_rate = stats['byte_count'] / duration
        else:
            packet_rate = 0.0
            byte_rate = 0.0

        syn_count_1s = sum(
            1
            for event_time, _, is_syn in activity
            if is_syn and event_time >= current_time - self.SYN_RATE_WINDOW_SECONDS
        )

        unique_syn_destination_ports = len({
            destination_port
            for _, destination_port, is_syn in activity
            if is_syn
        })

        return {

            'packet_size': len(packet),

            'flow_duration': duration,

            'packet_rate': packet_rate,

            'byte_rate': byte_rate,

            'syn_count_1s': syn_count_1s,

            'unique_syn_destination_ports': unique_syn_destination_ports,

            'tcp_flags':
                packet[TCP].flags,

            'window_size':
                packet[TCP].window
        }