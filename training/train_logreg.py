"""Train the risk-logreg-v1 baseline: validate, split-check, fit, select, export, verify.

Offline only. Nothing here reads live traffic, contacts a network, writes runtime
configuration or promotes a model. The dataset validator runs before any fit; a critical
finding aborts. Preprocessing is the shared FeatureTransformer, so training and inference
cannot use two different normalisations.
"""
import argparse
from dataclasses import dataclass
import importlib.metadata
import json
from pathlib import Path
import platform
import numpy as np
from sklearn.linear_model import LogisticRegression
from eye_for_an_eye.config import MLConfig
from eye_for_an_eye.decision.features import FeatureTransformer, INPUT_ORDER
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel
from . import schema, split as split_module
from .dataset import load
from .evaluate import point_metrics, ranking_metrics
from .export_onnx import export, finalize_manifest, widen
from .validation import validate_dataset

SEED = 20260909
C_GRID = (0.01, 0.1, 1.0, 10.0)
CLASS_WEIGHTS = (None, 'balanced')
SOLVER = 'lbfgs'
MAX_ITER = 5000
LIBRARIES = ('numpy', 'scikit-learn', 'scipy', 'onnx', 'onnxruntime', 'skl2onnx')
PARITY_TOLERANCE = 1e-5

# PROVISIONAL quality gate. These are conservative starting candidates, not established
# production targets; no measured deployment data supports them yet.
@dataclass(frozen=True, slots=True)
class QualityGate:
    reference_block_threshold: float = .90
    max_test_false_positive_rate: float = .02
    min_test_block_precision: float = .95
    max_onnx_parity_error: float = PARITY_TOLERANCE
    status: str = 'PROVISIONAL'


def prepare(rows):
    for row in rows:
        row['tensor'] = FeatureTransformer.transform(row['vector'])
        row['model_row'] = schema.select(row['tensor'])
    return rows


def matrix(rows, features=None):
    if features is None:
        return (np.asarray([row['model_row'] for row in rows], dtype=np.float32),
                np.asarray([row['label'] for row in rows], dtype=np.int64))
    index = [INPUT_ORDER.index(name) for name in features]
    return (np.asarray([[row['tensor'][i] for i in index] for row in rows], dtype=np.float32),
            np.asarray([row['label'] for row in rows], dtype=np.int64))


def fit(x, y, penalty_c, class_weight):
    # l1_ratio=0 is the current spelling of an L2 penalty; penalty='l2' is deprecated in sklearn 1.9.
    model = LogisticRegression(C=penalty_c, l1_ratio=0, solver=SOLVER, class_weight=class_weight,
                               max_iter=MAX_ITER, random_state=SEED)
    model.fit(x, y)
    return model


def score(model, x):
    return model.predict_proba(x)[:, 1]


def search(parts, gate):
    """Controlled grid. Selection uses validation only; test labels are never consulted."""
    train_x, train_y = matrix(parts['train'])
    val_x, val_y = matrix(parts['validation'])
    candidates = []
    for class_weight in CLASS_WEIGHTS:
        for penalty_c in C_GRID:
            model = fit(train_x, train_y, penalty_c, class_weight)
            probabilities = score(model, val_x)
            entry = {'C': penalty_c, 'class_weight': class_weight or 'none',
                     'converged': bool(model.n_iter_[0] < MAX_ITER), 'iterations': int(model.n_iter_[0]),
                     'validation': {**ranking_metrics(val_y, probabilities),
                                    'at_0.50': point_metrics(val_y, probabilities, .5),
                                    'at_block_reference': point_metrics(val_y, probabilities,
                                                                        gate.reference_block_threshold)}}
            candidates.append((entry, model))
    # Rank on threshold-free separation first: the model emits a score, policy picks actions.
    best = min(candidates, key=lambda item: (-item[0]['validation']['pr_auc'],
                                             item[0]['validation']['at_0.50']['false_positive_rate'],
                                             C_GRID.index(item[0]['C'])))
    return [entry for entry, _ in candidates], best


def ablation(parts, penalty_c, class_weight, gate):
    report = {}
    for name, features in schema.ABLATIONS.items():
        train_x, train_y = matrix(parts['train'], features)
        val_x, val_y = matrix(parts['validation'], features)
        model = fit(train_x, train_y, penalty_c, class_weight)
        probabilities = score(model, val_x)
        report[name] = {'features': len(features), **ranking_metrics(val_y, probabilities),
                        'at_0.50': point_metrics(val_y, probabilities, .5),
                        'at_block_reference': point_metrics(val_y, probabilities, gate.reference_block_threshold)}
    return report


def train(dataset_dir, output_dir, version=schema.MODEL_VERSION, gate=QualityGate()):
    manifest, rows = load(dataset_dir)
    report = validate_dataset(manifest, rows)
    if report['critical']:
        raise ValueError('dataset validation failed: ' + '; '.join(report['critical']))
    split_module.assert_group_separation(rows, keys=('source_group',))
    parts = split_module.partition(rows)
    split_module.assert_disjoint(parts['train'], parts['test'])
    split_module.assert_disjoint(parts['train'], parts['validation'])
    prepare(rows)

    candidates, (best_entry, best_model) = search(parts, gate)
    ablations = ablation(parts, best_entry['C'], None if best_entry['class_weight'] == 'none' else 'balanced', gate)

    full = widen(best_model)
    test_x, test_y = matrix(parts['test'])
    sklearn_scores = score(best_model, test_x)
    widened_scores = full.predict_proba(np.asarray([row['tensor'] for row in parts['test']], dtype=np.float32))[:, 1]
    widening_error = float(np.max(np.abs(sklearn_scores - widened_scores)))
    if widening_error > PARITY_TOLERANCE:
        raise RuntimeError('coefficient widening changed the model output')

    coefficients = dict(zip(schema.MODEL_FEATURES, map(float, best_model.coef_[0]), strict=True))
    run = {
        'model_version': version, 'model_family': 'logistic_regression',
        'dataset_version': manifest['dataset_version'], 'dataset_sha256': manifest['sha256'],
        'feature_schema_version': schema.FEATURE_SCHEMA_VERSION,
        'feature_contract_version': schema.FEATURE_CONTRACT_VERSION,
        'model_feature_names': list(schema.MODEL_FEATURES),
        'excluded_from_model': schema.EXCLUDED_FEATURES,
        'preprocessing': 'eye_for_an_eye.decision.features.FeatureTransformer only; no fitted scaler, '
                         'because the transformer already emits the float32 [0,1] runtime contract',
        'seed': SEED, 'solver': SOLVER, 'penalty': 'l2 (l1_ratio=0)', 'max_iter': MAX_ITER,
        'grid': {'C': list(C_GRID), 'class_weight': ['none', 'balanced']},
        'selection_rule': 'highest validation PR-AUC, then lowest validation FPR at 0.50, then strongest '
                          'regularisation; test labels are never used for selection',
        'selected': {'C': best_entry['C'], 'class_weight': best_entry['class_weight'],
                     'iterations': best_entry['iterations'], 'converged': best_entry['converged']},
        'candidates': candidates, 'ablation': ablations,
        'coefficients': coefficients, 'intercept': float(best_model.intercept_[0]),
        'coefficient_widening_max_error': widening_error,
        'dataset_validation': report,
        'split': split_module.chronological_order(rows),
        'environment': {'python': platform.python_version(), 'platform': platform.platform(),
                        **{name: importlib.metadata.version(name) for name in LIBRARIES}},
        'quality_gate': {'status': gate.status, 'reference_block_threshold': gate.reference_block_threshold,
                         'max_test_false_positive_rate': gate.max_test_false_positive_rate,
                         'min_test_block_precision': gate.min_test_block_precision,
                         'max_onnx_parity_error': gate.max_onnx_parity_error},
    }

    test_at_reference = point_metrics(test_y, sklearn_scores, gate.reference_block_threshold)
    gate_result = {
        'test_false_positive_rate_ok': test_at_reference['false_positive_rate'] <= gate.max_test_false_positive_rate,
        'test_block_precision_ok': (test_at_reference['block_precision'] is not None and
                                    test_at_reference['block_precision'] >= gate.min_test_block_precision),
        'no_group_leakage': not report['group_leakage']['source_groups_in_multiple_splits'],
    }
    extra = {
        'model_family': 'logistic_regression', 'positive_class': schema.POSITIVE_CLASS,
        'label_meaning': schema.LABEL_MEANING,
        'model_feature_names': list(schema.MODEL_FEATURES),
        'excluded_from_model': schema.EXCLUDED_FEATURES,
        'zero_weight_columns': list(schema.EXCLUDED_FEATURES),
        'training_dataset_sha256': manifest['sha256'], 'training_seed': SEED,
        'training_synthetic_only': True,
        'threshold_authority': 'DecisionFusion and PolicyGuard; the model never selects an action',
        'recommended_mode': 'shadow', 'recommended_shadow_only': True,
        'quality_gate_status': gate.status,
        'library_versions': run['environment'],
    }
    model_path, manifest_path = export(full, output_dir, version, manifest['dataset_version'], extra,
                                      deterministic_name=True)

    # Parity is measured through the production adapter, not a private session.
    adapter = OnnxRiskModel()
    health = adapter.load(MLConfig(model_path=str(model_path), manifest_path=str(manifest_path)))
    if health['status'] != 'healthy':
        raise RuntimeError('production adapter rejected the export: ' + json.dumps(health))
    onnx_scores = []
    for row in parts['test']:
        prediction = adapter.predict(list(row['tensor']))
        if prediction.status != 'healthy':
            raise RuntimeError('ONNX inference failed during export validation')
        onnx_scores.append(prediction.risk_score)
    onnx_scores = np.asarray(onnx_scores)
    difference = np.abs(onnx_scores - sklearn_scores)
    parity = {'rows': int(len(difference)), 'max_absolute_difference': float(difference.max()),
              'mean_absolute_difference': float(difference.mean()), 'tolerance': PARITY_TOLERANCE,
              'training_dtype': 'float64', 'runtime_dtype': 'float32',
              'passed': bool(difference.max() <= PARITY_TOLERANCE)}
    if not parity['passed']:
        raise RuntimeError('ONNX parity exceeds tolerance; export rejected')

    locked_test = {'at_0.50': point_metrics(test_y, onnx_scores, .5),
                   'at_block_reference': point_metrics(test_y, onnx_scores, gate.reference_block_threshold),
                   **ranking_metrics(test_y, onnx_scores)}
    gate_result['onnx_parity_ok'] = parity['passed']
    gate_result['passed'] = all(gate_result.values())
    run['onnx_parity'] = parity
    run['locked_test_metrics'] = locked_test
    run['artifacts'] = {'model': str(model_path), 'manifest': str(manifest_path),
                        'model_bytes': model_path.stat().st_size,
                        'manifest_bytes': manifest_path.stat().st_size}
    run['gate_result'] = gate_result
    finalize_manifest(manifest_path, {
        'quality_gate_passed': gate_result['passed'],
        'quality_gate_detail': gate_result,
        'onnx_parity': parity,
        'metrics': {'validation_pr_auc': best_entry['validation']['pr_auc'],
                    'validation_roc_auc': best_entry['validation']['roc_auc'],
                    'test_pr_auc': locked_test['pr_auc'], 'test_roc_auc': locked_test['roc_auc'],
                    'test_at_0.50': locked_test['at_0.50'],
                    'test_at_reference_block_threshold': locked_test['at_block_reference'],
                    'reference_block_threshold': gate.reference_block_threshold,
                    'metrics_source': 'held-out synthetic test split, scored through the production adapter'},
        'hyperparameters': {'C': best_entry['C'], 'class_weight': best_entry['class_weight'],
                            'penalty': 'l2 (l1_ratio=0)', 'solver': SOLVER, 'max_iter': MAX_ITER, 'seed': SEED},
    })
    (Path(output_dir) / (version + '-training.json')).write_text(
        json.dumps(run, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    return run


def main():
    parser = argparse.ArgumentParser(description='Train and export the risk-logreg-v1 baseline (offline).')
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--model-version', default=schema.MODEL_VERSION)
    args = parser.parse_args()
    run = train(args.dataset, args.output_dir, args.model_version)
    print(json.dumps({'selected': run['selected'], 'artifacts': run['artifacts'],
                      'gate_result': run['gate_result'], 'onnx_parity': run['onnx_parity'],
                      'locked_test_metrics': run['locked_test_metrics'],
                      'coefficient_widening_max_error': run['coefficient_widening_max_error']}, indent=2))


if __name__ == '__main__':
    main()
