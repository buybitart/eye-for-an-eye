"""Versioned dataset build, write and bounded load. CSV plus a manifest, no new dependency.

Parquet was not adopted: the corpus is a few thousand rows and pyarrow is not in the
locked extras, so a binary dependency is not justified for this size. Rows keep the raw
FeatureVector; the fitted tensor is always produced by the single shared FeatureTransformer,
so training and inference cannot drift apart.
"""
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from eye_for_an_eye.decision.features import NAMES, SCHEMA_VERSION, FeatureVector, from_samples
from . import corpus, schema

DATASET_VERSION = corpus.CORPUS_VERSION
SPLITS = ('train', 'validation', 'test')
WINDOW_STEP = 6
FIRST_WINDOW = 6
EVIDENCE_COLUMNS = ('sample_count', 'observation_seconds', 'capped', 'loss_fraction')
RAW_COLUMNS = tuple('raw_' + name for name in NAMES)
COLUMNS = ('sample_id', 'dataset_version', 'feature_schema_version', 'timestamp', 'scenario_id',
           'scenario_group', 'source_group', 'split', 'label', 'label_source') + EVIDENCE_COLUMNS + RAW_COLUMNS

MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 200_000
MAX_FIELD_CHARS = 4096


def build_rows():
    """Deterministic corpus. Labels come from generator intent, never from a system decision."""
    rows = []
    for name, trial, split in corpus.sequences():
        samples = corpus.scenario_samples(name, trial)
        label = corpus.label_of(name)
        for count in range(FIRST_WINDOW, len(samples) + 1, WINDOW_STEP):
            active = samples[:count]
            vector = from_samples(active, now=active[-1].time, loss_fraction=0.0)
            row = {'sample_id': f'{name}:{trial:03d}:{count:04d}', 'dataset_version': DATASET_VERSION,
                   'feature_schema_version': SCHEMA_VERSION, 'timestamp': round(active[-1].time, 6),
                   'scenario_id': name, 'scenario_group': name, 'source_group': f'{name}:{trial:03d}',
                   'split': split, 'label': label, 'label_source': 'synthetic_scenario',
                   'sample_count': vector.sample_count, 'observation_seconds': round(vector.observation_seconds, 6),
                   'capped': int(vector.capped),
                   'loss_fraction': '' if vector.loss_fraction is None else vector.loss_fraction}
            for column, value in zip(RAW_COLUMNS, vector.values, strict=True):
                row[column] = '' if value is None else round(float(value), 9)
            rows.append(row)
    return rows


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(directory, rows=None, *, seed_note=corpus.SEED_PREFIX):
    """Write train/validation/test plus dataset_manifest.json into a new directory."""
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    rows = build_rows() if rows is None else rows
    files = {}
    for split in SPLITS:
        subset = [row for row in rows if row['split'] == split]
        target = path / (split + '.csv')
        with target.open('w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=COLUMNS, lineterminator='\n')
            writer.writeheader()
            writer.writerows(subset)
        files[split] = {'file': target.name, 'rows': len(subset), 'bytes': target.stat().st_size,
                        'sha256': _digest(target),
                        'label_counts': {str(v): sum(r['label'] == v for r in subset) for v in (0, 1)},
                        'source_groups': len({r['source_group'] for r in subset}),
                        'scenario_groups': sorted({r['scenario_group'] for r in subset})}
    manifest = {
        'dataset_version': DATASET_VERSION,
        'feature_schema_version': SCHEMA_VERSION,
        'feature_contract_version': schema.FEATURE_CONTRACT_VERSION,
        'created_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        'generator': 'training.corpus', 'seed': f'{seed_note}:<scenario>:<trial>',
        'source': 'locally generated synthetic scenarios; no capture, no live traffic, no Internet',
        'quality_warning': 'NOT SUFFICIENT FOR PRODUCTION MODEL QUALITY - engineering validation corpus only',
        'raw_feature_names': list(NAMES), 'evidence_columns': list(EVIDENCE_COLUMNS),
        'model_feature_names': list(schema.MODEL_FEATURES),
        'excluded_from_model': schema.EXCLUDED_FEATURES,
        'transform': 'eye_for_an_eye.decision.features.FeatureTransformer (shared by training and inference)',
        'label_schema': {'0': 'benign_like', '1': schema.POSITIVE_CLASS, 'meaning': schema.LABEL_MEANING},
        'label_source': 'synthetic_scenario', 'columns': list(COLUMNS),
        'record_count': len(rows),
        'split_policy': 'whole source sequences never cross splits; four held-out families are test only',
        'held_out_scenario_groups': corpus.HELD_OUT,
        'window_policy': f'prefix windows every {WINDOW_STEP} observations from {FIRST_WINDOW}',
        'files': files,
    }
    manifest['sha256'] = hashlib.sha256(
        ''.join(files[s]['sha256'] for s in SPLITS).encode()).hexdigest()
    target = path / 'dataset_manifest.json'
    target.write_text(json.dumps(manifest, indent=2, sort_keys=False) + '\n', encoding='utf-8')
    return manifest


def _parse(row):
    values = []
    for column in RAW_COLUMNS:
        text = row[column]
        values.append(None if text == '' else float(text))
    vector = FeatureVector(tuple(values), float(row['observation_seconds']), int(row['sample_count']),
                           bool(int(row['capped'])),
                           None if row['loss_fraction'] == '' else float(row['loss_fraction']))
    return {'sample_id': row['sample_id'], 'dataset_version': row['dataset_version'],
            'feature_schema_version': int(row['feature_schema_version']), 'timestamp': float(row['timestamp']),
            'scenario_id': row['scenario_id'], 'scenario_group': row['scenario_group'],
            'source_group': row['source_group'], 'split': row['split'], 'label': int(row['label']),
            'label_source': row['label_source'], 'vector': vector}


def load(directory):
    """Bounded read with manifest hash verification. Returns (manifest, rows)."""
    path = Path(directory)
    manifest = json.loads((path / 'dataset_manifest.json').read_text(encoding='utf-8'))
    if manifest.get('feature_schema_version') != SCHEMA_VERSION:
        raise ValueError('dataset feature schema does not match this build')
    if manifest.get('label_source') in schema.FORBIDDEN_LABEL_SOURCES:
        raise ValueError('decision-derived labels forbidden')
    rows = []
    for split in SPLITS:
        target = path / manifest['files'][split]['file']
        if target.stat().st_size > MAX_BYTES:
            raise ValueError('dataset split exceeds size budget')
        if _digest(target) != manifest['files'][split]['sha256']:
            raise ValueError('dataset file hash mismatch')
        with target.open(encoding='utf-8', newline='') as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != COLUMNS:
                raise ValueError('dataset column contract mismatch')
            for row in reader:
                if len(rows) >= MAX_ROWS:
                    raise ValueError('dataset row budget exceeded')
                if any(value is None or len(value) > MAX_FIELD_CHARS for value in row.values()):
                    raise ValueError('malformed dataset field')
                if row['split'] != split:
                    raise ValueError('row split does not match its file')
                if row['label_source'] in schema.FORBIDDEN_LABEL_SOURCES:
                    raise ValueError('decision-derived labels forbidden')
                rows.append(_parse(row))
    if not rows:
        raise ValueError('empty dataset')
    return manifest, rows


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Build the versioned synthetic dataset (offline, deterministic).')
    parser.add_argument('--output', required=True, type=Path, help='new dataset directory')
    args = parser.parse_args()
    if (args.output / 'dataset_manifest.json').exists():
        raise FileExistsError('dataset directory already holds a manifest; choose a new path')
    manifest = write(args.output)
    print(json.dumps({k: manifest[k] for k in ('dataset_version', 'record_count', 'sha256', 'created_at')}, indent=2))


if __name__ == '__main__':
    main()
