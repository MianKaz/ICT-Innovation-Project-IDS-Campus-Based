"""Load the CICIDS2017 CSVs, clean them, and save train/test files."""
import json
import re

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src import config


def load_file(path):
    df = pd.read_csv(path, encoding='latin-1', low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.drop(columns=[c for c in config.DROP_COLS if c in df.columns])
    # Fix odd characters in labels, e.g. "Web Attack <?> XSS" -> "Web Attack - XSS"
    df['Label'] = df['Label'].astype(str).map(lambda s: re.sub(r'[^A-Za-z0-9 ]+', '-', s).strip())
    feats = df.columns.drop('Label')
    df[feats] = df[feats].apply(pd.to_numeric, errors='coerce').astype('float32')
    return df


def build():
    files = sorted(config.RAW_DIR.glob('*.csv'))
    if not files:
        raise SystemExit(f'No CSV files found in {config.RAW_DIR}')

    parts = []
    for f in files:
        print('Loading', f.name)
        parts.append(load_file(f))
    for f, p in zip(files, parts):
        if set(p.columns) != set(parts[0].columns):
            raise SystemExit(f'{f.name} has different columns from {files[0].name}')

    df = pd.concat(parts, ignore_index=True)
    del parts
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()
    print(f'Cleaned: {before:,} -> {len(df):,} rows (removed inf, NaN and duplicates)')

    if config.BENIGN_FRAC < 1:
        benign = df['Label'] == 'BENIGN'
        df = pd.concat([df[~benign],
                        df[benign].sample(frac=config.BENIGN_FRAC, random_state=config.RANDOM_STATE)])
        print(f'Kept {config.BENIGN_FRAC:.0%} of BENIGN rows -> {len(df):,} rows')

    train, test = train_test_split(df, test_size=config.TEST_SIZE,
                                   stratify=df['Label'], random_state=config.RANDOM_STATE)
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    config.MODELS_DIR.mkdir(exist_ok=True)
    train.reset_index(drop=True).to_parquet(config.PROCESSED_DIR / 'train.parquet')
    test.reset_index(drop=True).to_parquet(config.PROCESSED_DIR / 'test.parquet')
    features = [c for c in df.columns if c != 'Label']
    (config.MODELS_DIR / 'features.json').write_text(json.dumps(features))

    print(f'Saved train ({len(train):,}) and test ({len(test):,}). {len(features)} features.')
    print(df['Label'].value_counts().to_string())


def ready():
    return all((config.PROCESSED_DIR / f'{n}.parquet').exists() for n in ('train', 'test'))


def load_split(name):
    return pd.read_parquet(config.PROCESSED_DIR / f'{name}.parquet')


if __name__ == '__main__':
    build()
