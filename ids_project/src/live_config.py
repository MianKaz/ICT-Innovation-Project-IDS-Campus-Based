"""Settings for live capture. Edit these values, not the code."""
from src import config

RULES_FILE = config.ROOT / 'rules.json'

CAPTURE_IFACE = None       # None = Scapy's default. Or a name like 'Wi-Fi' (list them: python main.py --list-ifaces)
TSHARK_PATH = r'C:\Program Files\Wireshark\tshark.exe'   # used by the PyShark backend; if missing, PATH is searched
CAPTURE_FILTER = ''        # optional BPF filter to drop bulk traffic early, e.g. 'ip or arp'. Empty = capture everything
QUEUE_SIZE = 50_000        # packets waiting between capture and detection; extras are dropped and counted

DISPLAY_MAX_PPS = 300      # packets per second shown in the Live Traffic table (detection still sees all of them)
COUNT_PADDING = True       # count Ethernet padding as payload, like the CICIDS2017 capture did

FLOW_TIMEOUT_S = 120       # a flow older than this is closed (same as CICFlowMeter)
FLOW_IDLE_S = 15           # a flow with no packets for this long is closed and scored
ACTIVITY_TIMEOUT_S = 5     # a gap longer than this counts as idle time inside a flow

ALERT_COOLDOWN_S = 30      # repeats of the same threat, source and target are merged for this long
WHITELIST_SUBNETS = []     # sources to ignore, e.g. ['192.168.50.0/24'] for a student lab
SEVERITY_CONFIDENCE = {'critical': 0.98, 'high': 0.95, 'medium': 0.80, 'low': 0.60}
