"""Train LR, then GBT; select on validation only and report locked test results."""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import time
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.utils.class_weight import compute_sample_weight
from eye_for_an_eye.config import MLConfig
from eye_for_an_eye.decision.features import FeatureVector, FeatureTransformer, INPUT_ORDER
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel
from .evaluate import metrics, regression_gate
from .export_onnx import export


def load_dataset(path):
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('dataset exceeds 64 MiB')
    rows, groups = [], defaultdict(set)
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            if len(line) > 8192 or len(rows) >= 50000:
                raise ValueError('dataset row/count budget')
            row = json.loads(line)
            if row['split'] not in ('train', 'validation', 'test') or type(row['label']) is not int or row['label'] not in (0, 1):
                raise ValueError('invalid labels/split')
            if row['label_source'] in ('blocked', 'automatically_blocked'):
                raise ValueError('decision-derived labels forbidden')
            row['features']['values'] = tuple(row['features']['values'])
            row['vector'] = FeatureVector(**row['features'])
            groups[row['source_group']].add(row['split'])
            rows.append(row)
    if any(len(parts) != 1 for parts in groups.values()):
        raise ValueError('source-group leakage')
    if len({r['dataset_version'] for r in rows}) != 1:
        raise ValueError('mixed dataset versions')
    return rows


def train(path, output):
    rows = load_dataset(path)
    output.mkdir(parents=True, exist_ok=True)
    split = {name: [r for r in rows if r['split'] == name] for name in ('train', 'validation', 'test')}
    arrays = {name: (np.asarray([FeatureTransformer.transform(r['vector']) for r in data], dtype=np.float32),
                     np.asarray([r['label'] for r in data])) for name, data in split.items()}
    candidates = {'logistic': LogisticRegression(C=1.0, class_weight='balanced', random_state=7, max_iter=1000),
        'gradient_boosting': GradientBoostingClassifier(n_estimators=48, max_depth=2, min_samples_leaf=12, random_state=7)}
    result = {'dataset_version': rows[0]['dataset_version'], 'dataset_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'feature_schema_version': 1, 'synthetic_only': True, 'split': {name: {'rows': len(data),
            'sources': len({r['source_group'] for r in data}), 'labels': dict(Counter(r['label'] for r in data))} for name, data in split.items()},
        'versions': {name: importlib.metadata.version(name) for name in ('numpy', 'onnx', 'onnxruntime', 'scikit-learn', 'skl2onnx')},
        'platform': platform.platform(), 'candidates': {}}
    x, y = arrays['train']
    for name, model in candidates.items():
        kwargs = {'sample_weight': compute_sample_weight('balanced', y)} if name == 'gradient_boosting' else {}
        model.fit(x, y, **kwargs)
        val = metrics(arrays['validation'][1], model.predict_proba(arrays['validation'][0])[:, 1])
        model_path, manifest_path = export(model, output, name + '-research-v1', rows[0]['dataset_version'])
        adapter = OnnxRiskModel()
        if adapter.load(MLConfig(model_path=str(model_path), manifest_path=str(manifest_path)))['status'] != 'healthy':
            raise RuntimeError('export rejected by production adapter: ' + str(adapter.health()))
        durations, predictions = [], []
        for row in arrays['test'][0]:
            start = time.perf_counter()
            prediction = adapter.predict(row.tolist())
            durations.append((time.perf_counter() - start) * 1000)
            if prediction.status != 'healthy':
                raise RuntimeError('ONNX test inference failed')
            predictions.append(prediction.risk_score)
        parity = float(np.max(np.abs(np.asarray(predictions) - model.predict_proba(arrays['test'][0])[:, 1])))
        if parity > 1e-5:
            raise RuntimeError('ONNX parity exceeds 1e-5')
        importance = model.coef_[0] if name == 'logistic' else model.feature_importances_
        result['candidates'][name] = {'validation': val, 'test': metrics(arrays['test'][1], predictions),
            'onnx_max_absolute_error': parity, 'model_bytes': model_path.stat().st_size,
            'cpu_ms': dict(zip(('p50', 'p95', 'p99'), map(float, np.percentile(durations, [50, 95, 99])))),
            'offline_importance': dict(sorted(zip(INPUT_ORDER, map(float, importance)), key=lambda kv: abs(kv[1]), reverse=True)[:10])}
    # Prefer lower FPR, then higher recall, then the simpler model. Never tune against test labels.
    result['selected'] = min(candidates, key=lambda name: (result['candidates'][name]['validation']['false_positive_rate'],
        -result['candidates'][name]['validation']['recall'], name != 'logistic'))
    result['promotion'] = regression_gate(result['candidates']['gradient_boosting']['validation'], result['candidates']['logistic']['validation'])
    result['active_model_changed'] = False
    (output / 'evaluation.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(train(args.dataset, args.output), indent=2))
