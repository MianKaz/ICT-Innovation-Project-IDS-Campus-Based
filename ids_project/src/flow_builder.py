"""Groups packets into flows and computes the same 77 statistics as the CICIDS2017
CSVs (CICFlowMeter style), so the trained models can score live traffic.

The values are close to CICFlowMeter's but not identical, which is the main
accuracy risk of live detection. Copied behaviours: a FIN packet closes a flow,
flows end after 120 s, lengths are payload bytes, durations are in microseconds."""
import numpy as np

from src import live_config

FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


class Flow:
    __slots__ = ('src', 'sport', 'dst', 'dport', 'pkts', 'start', 'last')

    def __init__(self, p):
        self.src, self.sport, self.dst, self.dport = p['src'], p['sport'], p['dst'], p['dport']
        self.pkts = []          # (time us, is forward, payload bytes, header bytes, tcp flags, tcp window)
        self.start = self.last = p['ts']

    def add(self, p):
        forward = p['src'] == self.src and p['sport'] == self.sport
        self.pkts.append((p['ts'], forward, p['payload'], p['hdr'], p['tflags'], p['win']))
        self.last = p['ts']


def _stats(values):
    """mean, std, max, min (sample standard deviation, zeros when empty)."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    a = np.asarray(values, dtype=float)
    return float(a.mean()), float(a.std(ddof=1)) if len(a) > 1 else 0.0, float(a.max()), float(a.min())


def _gaps(times):
    return [b - a for a, b in zip(times, times[1:])]


def compute(f):
    P = f.pkts
    fw, bw = [p for p in P if p[1]], [p for p in P if not p[1]]
    ts = [p[0] for p in P]
    dur = f.last - f.start
    secs = dur / 1e6
    f_len, b_len = [p[2] for p in fw], [p[2] for p in bw]
    all_len = f_len + b_len
    fl, bl, al = _stats(f_len), _stats(b_len), _stats(all_len)
    flow_iat = _gaps(ts)
    f_iat, b_iat = _gaps([p[0] for p in fw]), _gaps([p[0] for p in bw])
    fi, bi, wi = _stats(f_iat), _stats(b_iat), _stats(flow_iat)

    def count(sub, mask):
        return sum(1 for p in sub if p[4] & mask)

    # idle / active periods (gap longer than the activity timeout = idle)
    limit = live_config.ACTIVITY_TIMEOUT_S * 1e6
    active, idle, start, last = [], [], ts[0], ts[0]
    for t in ts[1:]:
        if t - last > limit:
            if last - start > 0:
                active.append(last - start)
            idle.append(t - last)
            start = t
        last = t
    if idle and last - start > 0:
        active.append(last - start)
    ac, idl = _stats(active), _stats(idle)

    def init_win(sub):
        return next((p[5] for p in sub if p[5] >= 0), -1)

    subflows = 1 + sum(1 for g in flow_iat if g > 1e6)
    n_f, n_b = len(fw), len(bw)
    var = al[1] ** 2

    row = {
        'Destination Port': f.dport, 'Flow Duration': dur,
        'Total Fwd Packets': n_f, 'Total Backward Packets': n_b,
        'Total Length of Fwd Packets': sum(f_len), 'Total Length of Bwd Packets': sum(b_len),
        'Fwd Packet Length Max': fl[2], 'Fwd Packet Length Min': fl[3],
        'Fwd Packet Length Mean': fl[0], 'Fwd Packet Length Std': fl[1],
        'Bwd Packet Length Max': bl[2], 'Bwd Packet Length Min': bl[3],
        'Bwd Packet Length Mean': bl[0], 'Bwd Packet Length Std': bl[1],
        'Flow Bytes/s': sum(all_len) / secs if secs > 0 else 0.0,
        'Flow Packets/s': len(P) / secs if secs > 0 else 0.0,
        'Flow IAT Mean': wi[0], 'Flow IAT Std': wi[1], 'Flow IAT Max': wi[2], 'Flow IAT Min': wi[3],
        'Fwd IAT Total': sum(f_iat), 'Fwd IAT Mean': fi[0], 'Fwd IAT Std': fi[1],
        'Fwd IAT Max': fi[2], 'Fwd IAT Min': fi[3],
        'Bwd IAT Total': sum(b_iat), 'Bwd IAT Mean': bi[0], 'Bwd IAT Std': bi[1],
        'Bwd IAT Max': bi[2], 'Bwd IAT Min': bi[3],
        'Fwd PSH Flags': count(fw, PSH), 'Bwd PSH Flags': count(bw, PSH),
        'Fwd URG Flags': count(fw, URG), 'Bwd URG Flags': count(bw, URG),
        'Fwd Header Length': sum(p[3] for p in fw), 'Bwd Header Length': sum(p[3] for p in bw),
        'Fwd Packets/s': n_f / secs if secs > 0 else 0.0, 'Bwd Packets/s': n_b / secs if secs > 0 else 0.0,
        'Min Packet Length': al[3], 'Max Packet Length': al[2], 'Packet Length Mean': al[0],
        'Packet Length Std': al[1], 'Packet Length Variance': var,
        'FIN Flag Count': count(P, FIN), 'SYN Flag Count': count(P, SYN), 'RST Flag Count': count(P, RST),
        'PSH Flag Count': count(P, PSH), 'ACK Flag Count': count(P, ACK), 'URG Flag Count': count(P, URG),
        'CWE Flag Count': count(P, CWR), 'ECE Flag Count': count(P, ECE),
        'Down/Up Ratio': int(n_b / n_f) if n_f else 0,
        'Average Packet Size': al[0], 'Avg Fwd Segment Size': fl[0], 'Avg Bwd Segment Size': bl[0],
        'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0,
        'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0,
        'Subflow Fwd Packets': n_f / subflows, 'Subflow Fwd Bytes': sum(f_len) / subflows,
        'Subflow Bwd Packets': n_b / subflows, 'Subflow Bwd Bytes': sum(b_len) / subflows,
        'Init_Win_bytes_forward': init_win(fw), 'Init_Win_bytes_backward': init_win(bw),
        'act_data_pkt_fwd': sum(1 for p in fw if p[2] > 0),
        'min_seg_size_forward': min((p[3] for p in fw), default=0),
        'Active Mean': ac[0], 'Active Std': ac[1], 'Active Max': ac[2], 'Active Min': ac[3],
        'Idle Mean': idl[0], 'Idle Std': idl[1], 'Idle Max': idl[2], 'Idle Min': idl[3],
    }
    row['_src'], row['_sport'], row['_dst'], row['_dport'] = f.src, f.sport, f.dst, f.dport
    return row


class FlowBuilder:
    def __init__(self):
        self.flows = {}

    @staticmethod
    def _key(p):
        a, b = (p['src'], p['sport']), (p['dst'], p['dport'])
        return (a, b, p['proto']) if a <= b else (b, a, p['proto'])

    def add(self, p):
        """Adds a TCP/UDP packet. Returns the flows (as feature rows) that this packet closed."""
        done, key = [], self._key(p)
        flow = self.flows.get(key)
        if flow is not None and p['ts'] - flow.start > live_config.FLOW_TIMEOUT_S * 1e6:
            done.append(self._finish(key))
            flow = None
        if flow is None:
            flow = self.flows[key] = Flow(p)
        flow.add(p)
        if p['proto'] == 'TCP' and p['tflags'] & FIN:      # like CICFlowMeter, FIN ends the flow
            done.append(self._finish(key))
        return done

    def expire(self, now_us, force=False):
        """Closes flows that went quiet or got too old. force=True closes everything."""
        idle, age = live_config.FLOW_IDLE_S * 1e6, live_config.FLOW_TIMEOUT_S * 1e6
        return [self._finish(k) for k, f in list(self.flows.items())
                if force or now_us - f.last > idle or now_us - f.start > age]

    def _finish(self, key):
        return compute(self.flows.pop(key))
