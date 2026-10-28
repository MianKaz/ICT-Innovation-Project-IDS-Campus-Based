"""Stage 1: hand-written rules for known attack patterns. No training needed.

Works on flow features (same columns as the CICIDS2017 CSVs), either a whole
DataFrame or a single flow. The first matching rule wins. Rules are meant to be
precise: they should fire on almost no normal traffic. Thresholds are in SIG below."""
import pandas as pd

REQUIRED = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Flow Packets/s', 'Init_Win_bytes_forward']

# Flow Duration is in microseconds.
SIG = dict(
    # Port 444 is normally unused. Heartbleed and Infiltration traffic in the dataset uses it.
    suspicious_port=444,
    # Port scan: one packet each way, 0 or 2 bytes out, a 6 byte reply, scanner-style TCP window
    scan_fwd_bytes=(0, 2), scan_bwd_bytes=6, scan_windows=(1024, 29200),   # () = skip window check
    # FTP brute force: short flow to the FTP port
    ftp_max_duration_us=10_000_000, ftp_min_pkts=3, ftp_max_pkts=40,
    # SSH brute force: repeated logins give flows of about 10-14 s and 20 packets
    ssh_min_duration_us=8_000_000, ssh_max_duration_us=16_000_000,
    ssh_min_fwd_pkts=15, ssh_max_fwd_pkts=30,
    # Slow HTTP DoS: very long, quiet connection where the server sends almost nothing back
    slow_ports=(80, 8080), slow_min_duration_us=30_000_000, slow_max_fwd_pkts=12,
    slow_max_bytes=100, slow_max_pkts_per_s=5,
)


def detect(df):
    """Returns a DataFrame with sig_threat ('' if no rule matched) and sig_conf."""
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f'signature.detect is missing columns: {missing}')

    s = SIG
    port, dur = df['Destination Port'], df['Flow Duration']
    fwd, bwd = df['Total Fwd Packets'], df['Total Backward Packets']
    fwd_len, bwd_len = df['Total Length of Fwd Packets'], df['Total Length of Bwd Packets']
    pps = df['Flow Packets/s']

    threat = pd.Series('', index=df.index, dtype=object)
    conf = pd.Series(0.0, index=df.index)

    def rule(mask, name, confidence):
        free = mask & (threat == '')          # earlier rules take priority
        threat[free] = name
        conf[free] = confidence

    rule(port == s['suspicious_port'], 'Port 444 Attack', 0.90)

    scan = (fwd == 1) & (bwd == 1) & fwd_len.isin(s['scan_fwd_bytes']) & (bwd_len == s['scan_bwd_bytes'])
    if s['scan_windows']:
        scan &= df['Init_Win_bytes_forward'].isin(s['scan_windows'])
    rule(scan, 'Port Scan', 0.90)

    rule((port == 21) & (dur < s['ftp_max_duration_us']) &
         fwd.between(s['ftp_min_pkts'], s['ftp_max_pkts']), 'FTP Brute Force', 0.85)

    rule((port == 22) & dur.between(s['ssh_min_duration_us'], s['ssh_max_duration_us']) &
         fwd.between(s['ssh_min_fwd_pkts'], s['ssh_max_fwd_pkts']), 'SSH Brute Force', 0.85)

    rule(port.isin(s['slow_ports']) & (dur > s['slow_min_duration_us']) &
         (fwd <= s['slow_max_fwd_pkts']) & (fwd_len < s['slow_max_bytes']) &
         (bwd_len < s['slow_max_bytes']) & (pps < s['slow_max_pkts_per_s']),
         'Slow HTTP DoS', 0.80)

    return pd.DataFrame({'sig_threat': threat, 'sig_conf': conf})
