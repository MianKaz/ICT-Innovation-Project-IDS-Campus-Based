from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / 'data'
# Use data/raw if it exists, otherwise read the CSVs straight from data/
RAW_DIR = DATA_DIR / 'raw' if (DATA_DIR / 'raw').is_dir() else DATA_DIR
PROCESSED_DIR = DATA_DIR / 'processed'
MODELS_DIR = ROOT / 'models'
RESULTS_DIR = ROOT / 'results'

RANDOM_STATE = 42
TEST_SIZE = 0.3

# Keep this share of BENIGN rows (every attack row is always kept).
# Use 0.3 for a fast first run, then 1.0 for the final results.
BENIGN_FRAC = 1.0

# Columns that identify a flow instead of describing its behaviour.
# Dropping them also makes both dataset versions end up with the same features.
DROP_COLS = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp',
             'Protocol', 'SimillarHTTP', 'Unnamed: 0', 'Fwd Header Length.1']

RF_PARAMS = dict(n_estimators=100, max_depth=20, min_samples_leaf=2,
                 class_weight='balanced_subsample', n_jobs=-1, random_state=RANDOM_STATE)
ISO_PARAMS = dict(n_estimators=100, max_samples=10_000,
                  n_jobs=-1, random_state=RANDOM_STATE)
# Isolation Forest threshold is set so ~1% of normal flows get flagged
ISO_TARGET_FPR = 0.002
UNSEEN_TYPES = ['PortScan', 'Bot',
                'Web Attack - Brute Force', 'FTP-Patator', 'DoS Hulk']

# ---------------------------------------------------------------
# Detection settings (used by signature.py, decision.py, evaluate.py)
# ---------------------------------------------------------------
RF_MIN_PROB = 0.6      # Random Forest must be at least this sure before it raises an alert

# Signature rule thresholds. These are starting points: check them against
# the signature-only results from evaluate.py and tune.
SIG = dict(
    heartbleed_port=444,
    # Port scan: tiny flow with no data in either direction
    scan_max_fwd_pkts=2, scan_max_bwd_pkts=1,
    # True = also require nmap's TCP window sizes (fewer false alarms)
    scan_nmap_windows_only=False,
    # FTP/SSH brute force: short flow to a login port
    login_ports={21: 'FTP Brute Force', 22: 'SSH Brute Force'},
    login_max_duration_us=10_000_000, login_min_pkts=3, login_max_pkts=40,
    # Slow HTTP DoS: long, quiet connection to a web port
    slow_ports=(80, 8080), slow_min_duration_us=5_000_000,
    slow_max_fwd_pkts=12, slow_max_fwd_bytes=1000, slow_max_pkts_per_s=5,
    # Packet flood: very fast one-way flow
    flood_min_pkts_per_s=100_000, flood_min_fwd_pkts=3,
)

# Attack types hidden from the Random Forest in the "unseen attack" test
UNSEEN_TYPES = ['PortScan', 'Bot',
                'Web Attack - Brute Force', 'FTP-Patator', 'DoS Hulk']
