"""Stage 2: loads the trained models and scores flows."""
import json

import joblib
import numpy as np
import pandas as pd

from src import config


class MLEngine:
    def __init__(self):
        d = config.MODELS_DIR
        self.rf = joblib.load(d / 'rf_model.joblib')
        self.iso = joblib.load(d / 'iso_model.joblib')
        self.features = json.loads((d / 'features.json').read_text())
        self.iso_threshold = json.loads((d / 'thresholds.json').read_text())['iso_threshold']
        self.benign_idx = int(np.where(self.rf.classes_ == 'BENIGN')[0][0])

    def predict(self, df):
        """df needs the model's feature columns. Works for many flows or one."""
        X = df[self.features].to_numpy()
        proba = self.rf.predict_proba(X)
        p_attack = 1 - proba[:, self.benign_idx]              # how likely it is ANY attack
        attack_only = proba.copy()
        attack_only[:, self.benign_idx] = -1
        iso_score = self.iso.score_samples(X)                 # lower = more unusual
        return pd.DataFrame({
            'rf_label': self.rf.classes_[proba.argmax(axis=1)],            # most likely class overall
            'rf_attack_prob': p_attack,
            'rf_attack_label': self.rf.classes_[attack_only.argmax(axis=1)],  # most likely attack type
            'iso_score': iso_score,
            'iso_anomaly': iso_score < self.iso_threshold,
        }, index=df.index)
