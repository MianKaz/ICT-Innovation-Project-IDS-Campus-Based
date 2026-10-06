import pyshark
import asyncio
import json
import logging
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import time

TARGET_INTERFACE = 'Wi-Fi'
TSHARK_PATH = r'C:\Program Files\Wireshark\tshark.exe'
LOG_FILE = 'ids_alerts.log'
CAPTURE_LOG_FILE = Path(__file__).resolve().parent / 'ids_capture.log'

capture_data = {
    "interface": TARGET_INTERFACE,
    "packets": [],
    "alerts": [],
}

# ---------- Detection thresholds ----------
PORT_SCAN_THRESHOLD = 15      # distinct destination ports from one source IP
PORT_SCAN_WINDOW = 10         # seconds
# example known bad ports, add your own
BLOCKED_SIGNATURE_PORTS = {4444, 31337}

# ---------- Logger setup ----------
logger = logging.getLogger("ids")
logger.setLevel(logging.WARNING)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.WARNING)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# ---------- State for port scan tracking ----------
port_scan_tracker = defaultdict(lambda: {"ports": set(), "start": time.time()})


def log_alert(threat_type, src_ip, dst_ip, src_port, dst_port, confidence, details):
    """Writes one structured alert line to the log file, matching the required format."""
    event = {
        "timestamp": datetime.now().isoformat(),
        "threat_type": threat_type,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "confidence": confidence,
        "details": details,
    }
    capture_data["alerts"].append(event)
    logger.warning(json.dumps(event))


def check_port_scan(src_ip, dst_ip, src_port, dst_port):
    """Flags a source IP hitting many distinct destination ports in a short window."""
    entry = port_scan_tracker[src_ip]

    if time.time() - entry["start"] > PORT_SCAN_WINDOW:
        entry["ports"] = set()
        entry["start"] = time.time()

    entry["ports"].add(dst_port)

    if len(entry["ports"]) > PORT_SCAN_THRESHOLD:
        log_alert(
            threat_type="signature",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            confidence=1.0,
            details={"type": "signature",
                     "rule": "port_scan", "confidence": 1.0},
        )
        entry["ports"] = set()  # reset so it does not fire every packet


def check_known_bad_ports(src_ip, dst_ip, src_port, dst_port):
    """Flags traffic touching a port commonly associated with known malware/backdoors."""
    if dst_port in BLOCKED_SIGNATURE_PORTS or src_port in BLOCKED_SIGNATURE_PORTS:
        log_alert(
            threat_type="signature",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            confidence=0.8,
            details={"type": "signature",
                     "rule": "known_bad_port", "confidence": 0.8},
        )


def print_packet_details(packet):
    """Extracts metadata from every intercepted packet, prints a summary, and runs detection rules."""
    try:
        protocol = packet.highest_layer

        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            length = packet.length

            src_port = None
            dst_port = None
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)

            print(f"[{protocol}] {src_ip} --> {dst_ip} | Size: {length} bytes")

            capture_data["packets"].append({
                "timestamp": datetime.now().isoformat(),
                "protocol": protocol,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "length": length,
            })

            if src_port is not None and dst_port is not None:
                check_port_scan(src_ip, dst_ip, src_port, dst_port)
                check_known_bad_ports(src_ip, dst_ip, src_port, dst_port)

    except AttributeError:
        # Silently skip incomplete link-layer headers or background noise frames
        pass
    except Exception as e:
        print(f"[!] Error parsing packet frame: {e}")


def write_capture_data():
    """Writes captured packet metadata and alerts to a plain-text log file."""
    finished_at = datetime.now().isoformat()
    with open(CAPTURE_LOG_FILE, "w", encoding="utf-8") as data_file:
        data_file.write(f"Interface: {capture_data['interface']}\n")
        data_file.write(f"Started at: {capture_data['started_at']}\n")
        data_file.write(f"Finished at: {finished_at}\n")
        data_file.write(f"Packets captured: {len(capture_data['packets'])}\n")
        data_file.write(f"Alerts detected: {len(capture_data['alerts'])}\n")
        data_file.write("\nPACKETS\n")
        data_file.write(
            f"{'PROTOCOL':<10} {'SOURCE IP':<18} "
            f"{'DESTINATION IP':<18} {'SIZE'}\n"
        )
        data_file.write("-" * 60 + "\n")

        for packet in capture_data["packets"]:
            source = packet["source_ip"]
            if packet["source_port"] is not None:
                source += f":{packet['source_port']}"
            destination = packet["destination_ip"]
            if packet["destination_port"] is not None:
                destination += f":{packet['destination_port']}"
            data_file.write(
                f"{packet['protocol']:<10} {source:<18} "
                f"{destination:<18} {packet['length']} bytes\n"
            )

        data_file.write("\nALERTS\n")
        for alert in capture_data["alerts"]:
            data_file.write(f"{json.dumps(alert, sort_keys=True)}\n")

    print(f"[*] Captured data written to {CAPTURE_LOG_FILE}")


def main():
    capture_data["started_at"] = datetime.now().isoformat()
    print(f"[*] Initializing Raw Packet Sniffer...")
    print(
        f"[*] Streaming live network frames on interface: {TARGET_INTERFACE}...\n")
    print(f"{'PROTOCOL':<10} {'SOURCE IP':<18} {'DESTINATION IP':<18} {'SIZE'}")
    print("-" * 60)
    print(f"[*] Alerts will be written to {LOG_FILE}\n")

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        capture = pyshark.LiveCapture(
            interface=TARGET_INTERFACE,
            tshark_path=TSHARK_PATH
        )

        for packet in capture.sniff_continuously():
            print_packet_details(packet)

    except KeyboardInterrupt:
        print("\n[*] Sniffer paused. Exiting cleanly.")
    except Exception as e:
        print(f"\n[!] Sniffer Initialization Failure: {e}")
    finally:
        try:
            write_capture_data()
        except OSError as e:
            print(
                f"\n[!] Could not write captured data to "
                f"{CAPTURE_LOG_FILE}: {e}"
            )


if __name__ == "__main__":
    main()
