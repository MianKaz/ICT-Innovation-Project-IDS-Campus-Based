"""Shows how each signature rule behaves on the test set, to help tune config.SIG.
Run after train.py:  python rule_check.py
It uses the TRAIN split by default, so the rules are tuned without peeking at the
test set that evaluate.py scores them on. Use  --split test  only for a final look."""
import argparse

import pandas as pd

from src import preprocess, signature

pd.set_option('display.width', 220)
pd.set_option('display.max_columns', 30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--split', default='train', choices=['train', 'test'])
    split = ap.parse_args().split
    test = preprocess.load_split(split)
    y = test['Label']
    sig = signature.detect(test)
    hit = sig['sig_threat']
    fired = hit != ''

    print(f'Using the {split.upper()} split: {len(test):,} flows\n')
    print('1. WHICH RULE FIRES ON WHAT (rows = true label, columns = rule that fired)')
    print(pd.crosstab(y, hit.where(fired, 'no rule')).to_string())

    print('\n2. PRECISION OF EACH RULE (share of its alerts that are real attacks)')
    prec = (y[fired] != 'BENIGN').groupby(hit[fired]).agg(['mean', 'size'])
    prec.columns = ['precision', 'alerts']
    print(prec.to_string(float_format=lambda v: f'{v:,.3f}'))

    cols = signature.REQUIRED
    focus = [c for c in ['BENIGN', 'PortScan', 'SSH-Patator', 'FTP-Patator', 'DDoS',
                         'DoS Hulk', 'DoS slowloris', 'Bot'] if (y == c).any()]
    print('\n3. TYPICAL VALUES (median) PER CLASS')
    print(test.groupby(y)[cols].median().loc[focus].T.to_string(float_format=lambda v: f'{v:,.1f}'))

    keys = ['Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets']
    groups = [('PortScan', test[y == 'PortScan']),
              ('BENIGN flows with 2 or fewer forward packets',
               test[(y == 'BENIGN') & (test['Total Fwd Packets'] <= 2)])]
    for name, d in groups:
        if len(d) == 0:
            continue
        print(f'\n4. {name}: {len(d):,} flows. Most common (fwd pkts, bwd pkts, fwd bytes, bwd bytes):')
        print((d.groupby(keys).size().sort_values(ascending=False).head(6) / len(d)).to_string(float_format=lambda v: f'{v:.3f}'))
        print('   Most common Init_Win_bytes_forward:')
        print(d['Init_Win_bytes_forward'].value_counts(normalize=True).head(5).to_string(float_format=lambda v: f'{v:.3f}'))

    for name, d in [('SSH-Patator', test[y == 'SSH-Patator']),
                    ('BENIGN to port 22', test[(y == 'BENIGN') & (test['Destination Port'] == 22)]),
                    ('FTP-Patator', test[y == 'FTP-Patator']),
                    ('BENIGN to port 21', test[(y == 'BENIGN') & (test['Destination Port'] == 21)])]:
        if len(d):
            print(f'\n5. {name}: {len(d):,} flows (10th, 50th, 90th percentile)')
            print(d[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']]
                  .quantile([.1, .5, .9]).to_string(float_format=lambda v: f'{v:,.1f}'))

    print('\n6. FLOWS THAT FIRED EACH RULE: typical values (median), normal vs attack')
    for name in sorted(set(hit[fired])):
        d = test[hit == name]
        is_b = d['Label'] == 'BENIGN'
        if is_b.any() and (~is_b).any():
            print(f'\n   {name}: {is_b.sum():,} normal flows, {(~is_b).sum():,} attack flows')
            print(pd.DataFrame({'normal': d[is_b][cols].median(), 'attack': d[~is_b][cols].median()})
                  .to_string(float_format=lambda v: f'{v:,.1f}'))


if __name__ == '__main__':
    main()
