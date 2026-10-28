"""Train the Random Forest (known attacks) and Isolation Forest (anomalies). Run once."""
import json
import time

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

from src import config, preprocess


def main():
    if not preprocess.ready():
        preprocess.build()
    train, test = preprocess.load_split('train'), preprocess.load_split('test')
    feats = json.loads((config.MODELS_DIR / 'features.json').read_text())
    X_train, y_train = train[feats].to_numpy(), train['Label'].to_numpy()
    X_test, y_test = test[feats].to_numpy(), test['Label'].to_numpy()

    # ---- Random Forest: learns every attack type from labelled data ----
    print(f'\nTraining Random Forest on {len(X_train):,} flows...')
    t = time.time()
    rf = RandomForestClassifier(**config.RF_PARAMS).fit(X_train, y_train)
    pred = rf.predict(X_test)
    print(f'  done in {time.time() - t:.0f}s | test accuracy {accuracy_score(y_test, pred):.4f} '
          f'| macro F1 {f1_score(y_test, pred, average="macro"):.4f}')

    # ---- Isolation Forest: learns what NORMAL looks like (benign flows only) ----
    benign = X_train[y_train == 'BENIGN']
    fit_part, val_part = train_test_split(benign, test_size=0.1, random_state=config.RANDOM_STATE)
    print(f'\nTraining Isolation Forest on {len(fit_part):,} benign flows...')
    t = time.time()
    iso = IsolationForest(**config.ISO_PARAMS).fit(fit_part)
    # lower score = more unusual. Pick the cutoff so ~1% of normal validation flows get flagged.
    threshold = float(np.percentile(iso.score_samples(val_part), config.ISO_TARGET_FPR * 100))
    flagged = iso.score_samples(X_test) < threshold
    is_benign = y_test == 'BENIGN'
    print(f'  done in {time.time() - t:.0f}s | on test set: '
          f'{flagged[is_benign].mean():.1%} of benign flagged, '
          f'{flagged[~is_benign].mean():.1%} of attacks flagged')

    # ---- Save ----
    config.MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(rf, config.MODELS_DIR / 'rf_model.joblib', compress=3)
    joblib.dump(iso, config.MODELS_DIR / 'iso_model.joblib', compress=3)
    (config.MODELS_DIR / 'thresholds.json').write_text(json.dumps({'iso_threshold': threshold}))
    print('\nSaved models to', config.MODELS_DIR)


if __name__ == '__main__':
    main()
