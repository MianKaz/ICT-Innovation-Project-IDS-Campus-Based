"""Tests everything on the held-out test set. Run after train.py:  python evaluate.py
Saves tables and charts to results/ and prints a summary."""
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

from src import config, decision, preprocess, signature
from src.ml_engine import MLEngine

LINES = []


def log(text=''):
    print(text)
    LINES.append(str(text))


def binary_metrics(is_attack, flagged):
    tp = (flagged & is_attack).sum()
    fp = (flagged & ~is_attack).sum()
    fn = (~flagged & is_attack).sum()
    tn = (~flagged & ~is_attack).sum()
    precision, recall = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return dict(precision=precision, recall=recall,
                f1=2 * precision * recall / max(precision + recall, 1e-9),
                false_positive_rate=fp / max(fp + tn, 1))


def fmt(v):
    return f'{v:.4f}'


def main():
    config.RESULTS_DIR.mkdir(exist_ok=True)
    test = preprocess.load_split('test')
    ml = MLEngine()
    y = test['Label'].to_numpy()
    is_attack = y != 'BENIGN'

    sig = signature.detect(test)
    out = ml.predict(test)
    hybrid = decision.decide(sig, out, ml.iso_threshold)
    setups = {
        'Signature only': (sig['sig_threat'] != '').to_numpy(),
        'Random Forest only': (out['rf_attack_prob'] >= config.RF_MIN_PROB).to_numpy(),
        'Isolation Forest only': out['iso_anomaly'].to_numpy(),
        'Hybrid': hybrid['alert'].to_numpy(),
    }

    # ---- 1. Overall comparison ----
    log(f'TEST SET: {len(test):,} flows ({is_attack.sum():,} attacks)\n')
    log('1. OVERALL COMPARISON (attack vs normal)')
    table = pd.DataFrame({k: binary_metrics(is_attack, v) for k, v in setups.items()}).T
    table.to_csv(config.RESULTS_DIR / 'comparison.csv')
    log(table.to_string(float_format=fmt))
    log(f'Isolation Forest ROC-AUC: {roc_auc_score(is_attack, -out["iso_score"]):.4f}')

    # ---- 2. Which layer raises the hybrid's alerts ----
    log('\n2. WHO RAISES THE HYBRID ALERTS (an alert is credited to the first layer that fires)')
    det = hybrid['detector'].to_numpy()
    who = pd.DataFrame({d: {'true_alerts': int(((det == d) & is_attack).sum()),
                            'false_alarms': int(((det == d) & ~is_attack).sum())}
                        for d in ['signature', 'random_forest', 'isolation_forest']}).T
    who['precision'] = who['true_alerts'] / (who['true_alerts'] + who['false_alarms']).clip(lower=1)
    who.to_csv(config.RESULTS_DIR / 'hybrid_alert_sources.csv')
    log(who.to_string(float_format=fmt))

    # ---- 3. Detection rate per attack type ----
    log('\n3. DETECTION RATE PER ATTACK TYPE (share of that attack caught)')
    attacks = sorted(set(y) - {'BENIGN'})
    per_class = pd.DataFrame({k: {a: v[y == a].mean() for a in attacks} for k, v in setups.items()})
    per_class.insert(0, 'flows', [int((y == a).sum()) for a in attacks])
    per_class.to_csv(config.RESULTS_DIR / 'per_class_recall.csv')
    log(per_class.to_string(float_format=lambda v: f'{v:.3f}'))

    # ---- 4. Random Forest detail ----
    log('\n4. RANDOM FOREST PER-CLASS REPORT')
    log(classification_report(y, out['rf_label'], zero_division=0))

    # ---- 5. Unseen attack test ----
    log('5. UNSEEN ATTACK TEST (Random Forest retrained WITHOUT that attack)')
    log('   "RF unseen" counts any alert, even if the attack name is wrong.')
    train = preprocess.load_split('train')
    rows = []
    for atk in config.UNSEEN_TYPES:
        m = y == atk
        if m.sum() == 0 or (train['Label'] == atk).sum() == 0:
            log(f'   skipped {atk} (not in data)')
            continue
        sub = train[train['Label'] != atk]
        benign, others = sub[sub['Label'] == 'BENIGN'], sub[sub['Label'] != 'BENIGN']
        sub = pd.concat([others, benign.sample(min(len(benign), 200_000), random_state=config.RANDOM_STATE)])
        rf2 = RandomForestClassifier(**{**config.RF_PARAMS, 'n_estimators': 50}).fit(
            sub[ml.features].to_numpy(), sub['Label'].to_numpy())
        proba = rf2.predict_proba(test.loc[m, ml.features].to_numpy())
        rf2_hit = (1 - proba[:, list(rf2.classes_).index('BENIGN')]) >= config.RF_MIN_PROB
        sig_hit, iso_hit = setups['Signature only'][m], setups['Isolation Forest only'][m]
        rows.append({'attack': atk, 'flows': int(m.sum()),
                     'RF seen': setups['Random Forest only'][m].mean(), 'RF unseen': rf2_hit.mean(),
                     'Isolation Forest': iso_hit.mean(), 'Signature': sig_hit.mean(),
                     'Hybrid (unseen)': (rf2_hit | iso_hit | sig_hit).mean()})
    if rows:
        unseen = pd.DataFrame(rows).set_index('attack')
        unseen.to_csv(config.RESULTS_DIR / 'unseen_attack_test.csv')
        log(unseen.to_string(float_format=lambda v: f'{v:.3f}'))

    # ---- 6. Isolation Forest trade-off ----
    log('\n6. ISOLATION FOREST TRADE-OFF (alone; cutoffs picked on the test set, for illustration only)')
    scores = out['iso_score'].to_numpy()
    rows = []
    for fpr in [0.001, 0.002, 0.005, 0.01, 0.02]:
        flagged = scores < np.percentile(scores[~is_attack], fpr * 100)
        row = {'false alarm rate': f'{fpr:.1%}', 'all attacks': flagged[is_attack].mean()}
        row.update({a: flagged[y == a].mean() for a in config.UNSEEN_TYPES if (y == a).any()})
        rows.append(row)
    log(pd.DataFrame(rows).set_index('false alarm rate').to_string(float_format=lambda v: f'{v:.3f}'))

    # ---- 7. Speed ----
    sample = test.sample(min(20_000, len(test)), random_state=config.RANDOM_STATE)
    t = time.perf_counter()
    decision.decide(signature.detect(sample), ml.predict(sample), ml.iso_threshold)
    dt = time.perf_counter() - t
    log(f'\n7. SPEED: {len(sample) / dt:,.0f} flows per second ({dt / len(sample) * 1000:.3f} ms per flow)')

    # ---- Charts ----
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        per_class.drop(columns='flows').plot.bar(figsize=(12, 5), width=0.8)
        plt.ylabel('Share of attack caught'); plt.title('Detection rate per attack type')
        plt.xticks(rotation=40, ha='right'); plt.tight_layout()
        plt.savefig(config.RESULTS_DIR / 'per_class_recall.png', dpi=150); plt.close()

        labels = sorted(set(y) | set(out['rf_label']))
        cm = confusion_matrix(y, out['rf_label'], labels=labels, normalize='true')
        plt.figure(figsize=(9, 8)); plt.imshow(cm, cmap='Blues')
        plt.xticks(range(len(labels)), labels, rotation=60, ha='right', fontsize=7)
        plt.yticks(range(len(labels)), labels, fontsize=7)
        plt.xlabel('Predicted'); plt.ylabel('Actual'); plt.title('Random Forest confusion matrix')
        plt.colorbar(); plt.tight_layout()
        plt.savefig(config.RESULTS_DIR / 'confusion_matrix.png', dpi=150); plt.close()
        log('\nCharts saved to results/')
    except ImportError:
        log('\n(matplotlib not installed, charts skipped: pip install matplotlib)')

    (config.RESULTS_DIR / 'evaluation_summary.txt').write_text('\n'.join(LINES), encoding='utf-8')


if __name__ == '__main__':
    main()
