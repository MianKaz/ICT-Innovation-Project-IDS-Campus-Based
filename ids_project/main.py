import argparse
import shutil
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path

from api import run as run_server
from src import config, live_config, preprocess, storage


def guarded(fn):
    """Print errors from a background thread instead of dying silently."""
    def go():
        try:
            fn()
        except Exception:
            traceback.print_exc()
    return go


def pick_backend(args):
    """PyShark for live capture when Wireshark is installed, otherwise Scapy."""
    if args.backend:
        return args.backend
    has_tshark = Path(live_config.TSHARK_PATH).exists() or shutil.which('tshark')
    return 'pyshark' if args.live and has_tshark else 'scapy'


def main():
    ap = argparse.ArgumentParser(description='Campus IDS')
    ap.add_argument('--live', action='store_true', help='watch real network traffic')
    ap.add_argument('--iface', help="interface for --live: PyShark takes a name like 'Wi-Fi', "
                                    "Scapy takes the Index number or name from --list-ifaces")
    ap.add_argument('--backend', choices=['pyshark', 'scapy'],
                    help='capture library (default: pyshark for --live if Wireshark is installed)')
    ap.add_argument('--pcap', help='analyse a .pcap file instead of live traffic')
    ap.add_argument('--bpf', default='', help="optional capture filter, e.g. 'ip or arp'")
    ap.add_argument('--list-ifaces', action='store_true', help='show network interfaces and exit')
    ap.add_argument('--fake', action='store_true', help='demo with made-up traffic')
    ap.add_argument('--no-browser', action='store_true', help="don't open the browser")
    args = ap.parse_args()
    backend = pick_backend(args)

    if args.list_ifaces:
        if backend == 'pyshark':
            from src import capture_pyshark
            capture_pyshark.list_interfaces()
        else:
            from src import capture
            capture.list_interfaces()
        return

    storage.init()
    if args.live or args.pcap:
        from src import live
        pipeline = live.LivePipeline(args.iface, args.pcap, args.bpf, backend)
        try:
            pipeline.start_capture()
        except Exception as e:
            print(f'\nCould not start capture ({backend}): {e}\n'
                  'Check that the terminal is running as Administrator and the interface is right '
                  '(python main.py --list-ifaces). Scapy needs Npcap, PyShark needs Wireshark.')
            sys.exit(1)
        source = pipeline.run
        print(f'Capturing live traffic with {backend}...' if args.live else f'Analysing {args.pcap} with {backend}...')
    elif (config.MODELS_DIR / 'rf_model.joblib').exists() and preprocess.ready() and not args.fake:
        from src import flow_replay
        print('Demo: replaying dataset flows through the hybrid detector (loading models, a few seconds)...')
        source = flow_replay.run
    else:
        from src import replay
        print('Demo: using made-up traffic.')
        source = replay.run

    threading.Thread(target=run_server, daemon=True).start()   # dashboard + API
    threading.Thread(target=guarded(source), daemon=True).start()

    time.sleep(1)
    if not args.no_browser:
        webbrowser.open('http://localhost:5000')
    print('Dashboard at http://localhost:5000  (Ctrl+C to stop)')

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('Stopped.')


if __name__ == '__main__':
    main()
