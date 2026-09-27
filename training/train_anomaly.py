"""Train the unsupervised anomaly baseline. Offline, reproducible, no network.

The detector answers "is this unusual?", not "is this an attack?". It is fitted
on trusted benign-like behaviour only, so "unusual" means "unlike normal traffic
we validated", and never "similar to attacks we labelled".

    python -m training.train_anomaly \
        --dataset datasets/processed/dataset-v1/train.csv \
        --dataset-version dataset-v1 --version isolation-v1 \
        --output-dir models

Exports ONNX, so the production runtime never unpickles a model.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import warnings

TRUSTED_BENIGN = 'trusted_benign'
RAW_SEMANTICS = 'sklearn_isolation_forest_decision_function_higher_is_more_normal'


def _quantile(ordered, fraction):
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return float(ordered[index])


def normalisation(raw_scores):
    """Map the raw decision function onto documented 0..1 anomaly semantics.

    0 means "common in the trusted baseline", 1 means "far outside it". The
    anchors come from the benign training population, so the meaning of the
    number is fixed by data and recorded in the manifest, not invented at
    runtime.
    """
    ordered = sorted(raw_scores)
    high = _quantile(ordered, 0.75)   # comfortably normal
    low = _quantile(ordered, 0.01)    # the edge of the trusted baseline
    if high - low < 1e-9:
        high, low = high + 1e-6, low - 1e-6
    return {'method': 'linear_clamped_on_benign_quantiles',
            'formula': 'anomaly_score = clamp01((high - raw) / (high - low))',
            'high': high, 'low': low,
            'raw_semantics': RAW_SEMANTICS}


def apply_normalisation(spec, raw):
    span = spec['high'] - spec['low']
    return min(1.0, max(0.0, (spec['high'] - float(raw)) / span))


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m training.train_anomaly',
                                     description='Train and export the Isolation Forest anomaly baseline.')
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--dataset-version', required=True)
    parser.add_argument('--version', default='isolation-v1')
    parser.add_argument('--output-dir', default='models')
    parser.add_argument('--estimators', type=int, default=128)
    parser.add_argument('--max-samples', type=int, default=256)
    parser.add_argument('--contamination', type=float, default=0.02)
    parser.add_argument('--seed', type=int, default=20260910)
    parser.add_argument('--holdout-groups', type=int, default=4,
                        help='source groups held out of training, for group-based evaluation')
    args = parser.parse_args(argv)

    warnings.filterwarnings('ignore')
    import numpy as np
    import onnxruntime as ort
    import sklearn
    import skl2onnx
    from skl2onnx import to_onnx
    from sklearn.ensemble import IsolationForest

    from dataset import schema
    from dataset.deduplicate import tensors
    from dataset.store import read
    from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION

    rows = read(args.dataset)
    # Trusted benign only. Training on a mixture and then calling the output
    # "attack likelihood" is the mistake this whole component exists to avoid.
    benign = [r for r in rows if r.label == schema.BENIGN and r.supervised]
    if len(benign) < 200:
        raise SystemExit(f'need at least 200 trusted benign rows, found {len(benign)}')

    groups = sorted({r.group for r in benign if r.group})
    holdout = set(groups[:args.holdout_groups])
    train_rows = [r for r in benign if r.group not in holdout]
    eval_rows = [r for r in benign if r.group in holdout]
    if len(train_rows) < 100:
        raise SystemExit('not enough rows left after holding out evaluation groups')

    columns = [name for name in INPUT_ORDER if name in schema.MODEL_FEATURES]
    positions = [INPUT_ORDER.index(name) for name in columns]
    matrix = tensors(train_rows)
    features = np.array([[row[p] for p in positions] for row in matrix], dtype=np.float32)
    if not np.isfinite(features).all():
        raise SystemExit('training matrix contains non-finite values')

    model = IsolationForest(n_estimators=args.estimators, max_samples=args.max_samples,
                            contamination=args.contamination, random_state=args.seed, n_jobs=1)
    model.fit(features)

    spec = normalisation([float(v) for v in model.decision_function(features)])

    onx = to_onnx(model, features[:1], target_opset={'': 17, 'ai.onnx.ml': 3})
    onx.graph.name = args.version  # deterministic graph name, as for the classifier
    blob = onx.SerializeToString()

    session = ort.InferenceSession(blob, providers=['CPUExecutionProvider'])
    input_name = session.get_inputs()[0].name
    onnx_raw = np.asarray(session.run(None, {input_name: features})[1]).ravel()
    parity = float(np.max(np.abs(model.decision_function(features) - onnx_raw)))
    if parity > 1e-5:
        raise SystemExit(f'ONNX parity failed: {parity}')

    normalised = [apply_normalisation(spec, value) for value in onnx_raw]
    evaluation = {'train_rows': len(train_rows), 'holdout_rows': len(eval_rows),
                  'holdout_groups': sorted(holdout), 'onnx_parity_max_abs_error': parity,
                  'train_anomaly_score': {
                      'mean': statistics.fmean(normalised),
                      'p50': _quantile(sorted(normalised), 0.50),
                      'p95': _quantile(sorted(normalised), 0.95),
                      'p99': _quantile(sorted(normalised), 0.99),
                      'share_above_0_5': sum(v > 0.5 for v in normalised) / len(normalised)}}
    if eval_rows:
        holdout_matrix = tensors(eval_rows)
        holdout_features = np.array([[row[p] for p in positions] for row in holdout_matrix], dtype=np.float32)
        holdout_raw = np.asarray(session.run(None, {input_name: holdout_features})[1]).ravel()
        holdout_scores = [apply_normalisation(spec, value) for value in holdout_raw]
        evaluation['holdout_anomaly_score'] = {
            'mean': statistics.fmean(holdout_scores),
            'p95': _quantile(sorted(holdout_scores), 0.95),
            'share_above_0_5': sum(v > 0.5 for v in holdout_scores) / len(holdout_scores)}

    target = Path(args.output_dir)
    target.mkdir(parents=True, exist_ok=True)
    model_path = target / f'{args.version}.onnx'
    manifest_path = target / f'{args.version}.json'
    features_path = Path('datasets') / 'anomaly_features_v1.json'
    for path in (model_path, manifest_path):
        if path.exists():
            raise SystemExit(f'{path} already exists; a trained artifact is immutable')
    model_path.write_bytes(blob)

    manifest = {
        'manifest_version': 1,
        'model_version': args.version,
        'model_family': 'isolation_forest',
        'feature_schema_version': SCHEMA_VERSION,
        'dataset_version': args.dataset_version,
        'feature_names': columns,
        'input_name': input_name,
        'input_shape': [1, len(columns)],
        'input_dtype': 'float32',
        'output_names': [o.name for o in session.get_outputs()],
        'raw_score_output_index': 1,
        'normalization': spec,
        'score_semantics': 'normalised_anomaly_score_0_common_1_unusual',
        'training_population': {
            'mode': TRUSTED_BENIGN,
            'description': 'validated benign-like rows only; no malicious rows and no unreviewed shadow rows',
            'rows': len(train_rows), 'groups_excluded_for_evaluation': sorted(holdout)},
        'parameters': {'n_estimators': args.estimators, 'max_samples': args.max_samples,
                       'contamination': args.contamination, 'random_state': args.seed},
        'evaluation': evaluation,
        'software': {'python': platform.python_version(), 'scikit_learn': sklearn.__version__,
                     'skl2onnx': skl2onnx.__version__, 'onnxruntime': ort.__version__},
        'sha256': hashlib.sha256(blob).hexdigest(),
        'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'recommended_mode': 'shadow',
        'limitations': [
            'an anomaly is unusual behaviour, not evidence of an attack',
            'fitted on one synthetic corpus; it has not seen production traffic',
            'scores are uncalibrated and are not probabilities',
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf-8')
    features_path.parent.mkdir(parents=True, exist_ok=True)
    features_path.write_text(json.dumps({
        'schema_version': 1, 'feature_schema_version': SCHEMA_VERSION,
        'anomaly_feature_set': 'anomaly-features-v1', 'columns': columns,
        'excluded': sorted(set(INPUT_ORDER) - set(columns)),
        'never_permitted': sorted(schema.NEVER_MODEL_INPUT),
        'note': 'behaviour only; no address, ASN, country, previous decision or final risk',
    }, indent=2, sort_keys=True), encoding='utf-8')

    print(json.dumps({'model': str(model_path), 'manifest': str(manifest_path),
                      'features': str(features_path), 'bytes': len(blob),
                      'sha256': manifest['sha256'], 'onnx_parity': parity,
                      'train_rows': len(train_rows), 'holdout_rows': len(eval_rows)}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
