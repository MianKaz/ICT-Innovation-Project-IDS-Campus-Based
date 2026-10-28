"""Combines the signature rules and both ML models into one alert per flow.

Priority:
  1. a signature rule matched                  -> alert (cheap and reliable)
  2. Random Forest thinks it is an attack      -> alert, named after the most likely attack type
     (probability of ANY attack >= RF_MIN_PROB)
  3. only Isolation Forest is suspicious (Random Forest said normal)
                                               -> 'Suspicious Flow' (possible new attack)"""
import numpy as np
import pandas as pd

from src import config


def decide(sig, ml, iso_threshold):
    n = len(sig)
    sig_hit = (sig['sig_threat'] != '').to_numpy()
    rf_hit = (ml['rf_attack_prob'] >= config.RF_MIN_PROB).to_numpy() & ~sig_hit
    iso_hit = ml['iso_anomaly'].to_numpy() & ~sig_hit & ~rf_hit

    # Isolation Forest confidence: the further below the threshold, the surer (0.5 to 0.8, always lower than a confirmed attack)
    iso_conf = np.clip(0.5 + (iso_threshold - ml['iso_score'].to_numpy()) * 2, 0.5, 0.80)

    def text(value):
        return np.full(n, value, dtype=object)

    conds = [sig_hit, rf_hit, iso_hit]
    return pd.DataFrame({
        'alert': sig_hit | rf_hit | iso_hit,
        'threat_type': np.select(conds, [sig['sig_threat'].to_numpy(dtype=object),
                                         ml['rf_attack_label'].to_numpy(dtype=object),
                                         text('Suspicious Flow')], default=text('')),
        'confidence': np.round(np.select(conds, [sig['sig_conf'].to_numpy(),
                                                 ml['rf_attack_prob'].to_numpy(), iso_conf],
                                         default=0.0), 2),
        'detector': np.select(conds, [text('signature'), text('random_forest'),
                                      text('isolation_forest')], default=text('')),
    }, index=sig.index)
