"""Build a model-scoped reference distribution from a validated dataset.

Offline only. The artifact records what the model was fitted on, so runtime OOD
and drift have a fixed, versioned baseline that production traffic can never
silently redefine.

    python -m training.export_distribution \
        --dataset datasets/processed/dataset-v1/train.csv \
        --model-version risk-logreg-v1 --dataset-version dataset-v1 \
        --output models/risk-logreg-v1-distribution.json
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from dataset.deduplicate import tensors
from dataset.statistics import feature_report
from dataset.store import read
from eye_for_an_eye.decision.distribution import DISTRIBUTION_VERSION, QUANTILES
from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION

BINS = 10


def histogram(values, low, high, bins=BINS):
    """Equal-width bins between the observed bounds; these become the fixed reference bins."""
    if high <= low:
        edges = [low, low + 1e-6]
        return edges, [1.0]
    width = (high - low) / bins
    edges = [low + width * index for index in range(bins)] + [high]
    counts = [0] * bins
    for value in values:
        index = min(bins - 1, max(0, int((value - low) / width)))
        counts[index] += 1
    total = sum(counts) or 1
    return edges, [count / total for count in counts]


def build(samples, *, model_version, dataset_version):
    # One transformed matrix, shared with feature_report, so the artifact and the
    # dataset statistics can never disagree about what the model was shown.
    matrix = tensors(samples)
    report = feature_report(samples, matrix)
    features, columns = {}, []
    for name in INPUT_ORDER:
        entry = report.get(name)
        if entry is None:
            continue  # previous_risk is deliberately outside the model feature set
        overall, flags = entry['overall'], entry.get('flags', {})
        position = INPUT_ORDER.index(name)
        values = [row[position] for row in matrix]
        if not values:
            continue
        edges, fractions = histogram(values, overall['min'], overall['max'])
        features[name] = {
            'count': int(overall['count']),
            'missing_rate': round(overall['missing_percent'] / 100.0, 6),
            'min': overall['min'], 'max': overall['max'],
            'mean': overall['mean'], 'std': overall['std'],
            **{q: overall[q] for q in QUANTILES},
            'bin_edges': edges, 'bin_fractions': fractions,
            'constant': bool(flags.get('constant', False)),
            'nearly_constant': bool(flags.get('nearly_constant', False)),
        }
        columns.append(name)
    if not features:
        raise SystemExit('no comparable features found in the dataset')
    return {
        'distribution_version': DISTRIBUTION_VERSION,
        'model_version': model_version,
        'dataset_version': dataset_version,
        'feature_schema_version': SCHEMA_VERSION,
        'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'sample_count': len(samples),
        'value_space': 'transformed',
        'bins': BINS,
        'columns': columns,
        'features': features,
        'limitations': [
            'statistics describe the training corpus only, not any production network',
            'quantiles are estimated from a finite sample',
            'this baseline is never updated from production traffic',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m training.export_distribution',
                                     description='Export a reference distribution for OOD and drift.')
    parser.add_argument('--dataset', required=True, help='processed dataset CSV')
    parser.add_argument('--model-version', required=True)
    parser.add_argument('--dataset-version', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--supervised-only', action='store_true',
                        help='use only labelled rows, the population the classifier was fitted on')
    args = parser.parse_args(argv)
    samples = read(args.dataset)
    if args.supervised_only:
        samples = [s for s in samples if s.supervised]
    if not samples:
        raise SystemExit('dataset is empty after filtering')
    payload = build(samples, model_version=args.model_version, dataset_version=args.dataset_version)
    target = Path(args.output)
    if target.exists():
        raise SystemExit(f'{target} already exists; a reference distribution is immutable')
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode('utf-8')
    target.write_bytes(encoded)
    print(json.dumps({'output': str(target), 'sha256': hashlib.sha256(encoded).hexdigest(),
                      'features': len(payload['features']), 'samples': payload['sample_count'],
                      'model_version': args.model_version, 'dataset_version': args.dataset_version}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
