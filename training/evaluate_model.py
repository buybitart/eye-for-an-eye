"""Evaluate an exported model without retraining it.

Scores come from the production ONNX adapter, so the numbers describe the artifact that
would run in shadow mode. Coefficients are read out of the exported graph for the same
reason. Nothing here selects a threshold or promotes anything.
"""
import argparse
import json
from pathlib import Path
import time
import numpy as np
from eye_for_an_eye.config import MLConfig
from eye_for_an_eye.decision.features import FeatureTransformer, INPUT_ORDER
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel, benchmark_batch_runner
from . import corpus, schema
from .dataset import load
from .evaluate import (by_scenario, calibration, coefficient_table, error_analysis,
                       false_positive_concentration, point_metrics, ranking_metrics, score_distribution,
                       threshold_table)
from .export_onnx import coefficients_from_onnx
from .validation import distribution_report, validate_dataset

# Production caps the benchmark clone at 16 rows; that bound is a safety limit, not a
# measurement limit, so larger batches are reported as not measurable through this path.
BATCH_SIZES = (1, 8, 16)


def score_rows(adapter, rows):
    scores, durations = [], []
    for row in rows:
        start = time.perf_counter()
        prediction = adapter.predict(list(row['tensor']))
        durations.append((time.perf_counter() - start) * 1000)
        if prediction.status != 'healthy':
            raise RuntimeError('ONNX inference failed: ' + str(prediction.error))
        scores.append(prediction.risk_score)
    return np.asarray(scores), durations


def benchmark(config, tensor, iterations=3000):
    adapter = OnnxRiskModel()
    start = time.perf_counter()
    if adapter.load(config)['status'] != 'healthy':
        raise RuntimeError('benchmark load failed')
    load_ms = (time.perf_counter() - start) * 1000
    adapter.predict(list(tensor))
    durations = []
    begin = time.perf_counter()
    for _ in range(iterations):
        moment = time.perf_counter()
        adapter.predict(list(tensor))
        durations.append((time.perf_counter() - moment) * 1000)
    elapsed = time.perf_counter() - begin
    result = {'iterations': iterations, 'load_ms': load_ms,
              'latency_ms': dict(zip(('p50', 'p95', 'p99'), map(float, np.percentile(durations, [50, 95, 99])))),
              'inferences_per_second': iterations / elapsed, 'batches': {}}
    try:
        import psutil
        result['process_rss_bytes'] = psutil.Process().memory_info().rss
    except ImportError:
        result['process_rss_bytes'] = None
    for size in BATCH_SIZES:
        if size == 1:
            result['batches']['1'] = {'rows_per_second': result['inferences_per_second'],
                                      'per_row_ms': result['latency_ms']['p50']}
            continue
        runner = benchmark_batch_runner(config, size)
        rows = [list(tensor)] * size
        runner(rows)
        begin = time.perf_counter()
        for _ in range(500):
            runner(rows)
        elapsed = time.perf_counter() - begin
        result['batches'][str(size)] = {'rows_per_second': 500 * size / elapsed,
                                        'per_row_ms': 1000 * elapsed / (500 * size)}
    result['batch_note'] = ('offline measurement only; production keeps the strict [1,36] contract and one '
                            'in-flight request per source')
    return result


def evaluate(dataset_dir, model_dir, version, *, run_benchmark=True):
    manifest, rows = load(dataset_dir)
    validation = validate_dataset(manifest, rows)
    if validation['critical']:
        raise ValueError('dataset validation failed: ' + '; '.join(validation['critical']))
    for row in rows:
        row['tensor'] = FeatureTransformer.transform(row['vector'])
    test = [row for row in rows if row['split'] == 'test']
    labels = np.asarray([row['label'] for row in test])

    model_path = Path(model_dir) / (version + '.onnx')
    manifest_path = Path(model_dir) / (version + '.json')
    config = MLConfig(model_path=str(model_path), manifest_path=str(manifest_path))
    adapter = OnnxRiskModel()
    health = adapter.load(config)
    if health['status'] != 'healthy':
        raise RuntimeError('production adapter rejected the model: ' + json.dumps(health))
    model_manifest = json.loads(manifest_path.read_text(encoding='utf-8'))

    scores, durations = score_rows(adapter, test)
    weights, intercept = coefficients_from_onnx(model_path)
    ordered = [weights[name] for name in INPUT_ORDER]
    analytic = 1 / (1 + np.exp(-(np.asarray([row['tensor'] for row in test], dtype=np.float64) @
                                 np.asarray(ordered, dtype=np.float64) + intercept)))
    reference_error = float(np.max(np.abs(analytic - scores)))

    unseen = [i for i, row in enumerate(test) if row['scenario_group'] in corpus.HELD_OUT]
    seen = [i for i, row in enumerate(test) if row['scenario_group'] not in corpus.HELD_OUT]
    subsets = {}
    for name, index in (('unseen_scenario_families', unseen), ('seen_scenario_families', seen)):
        if index:
            subsets[name] = {**ranking_metrics(labels[index], scores[index]),
                             'at_0.50': point_metrics(labels[index], scores[index], .5),
                             'at_0.90': point_metrics(labels[index], scores[index], .9),
                             'families': sorted({test[i]['scenario_group'] for i in index})}

    return {
        'model_version': version, 'model_family': model_manifest.get('model_family'),
        'model_sha256': model_manifest['sha256'], 'model_bytes': model_path.stat().st_size,
        'manifest_bytes': manifest_path.stat().st_size,
        'dataset_version': manifest['dataset_version'], 'dataset_sha256': manifest['sha256'],
        'dataset_validation': validation,
        'feature_distribution_train': distribution_report([r for r in rows if r['split'] == 'train']),
        'test': {**ranking_metrics(labels, scores), 'at_0.50': point_metrics(labels, scores, .5)},
        'threshold_table': threshold_table(labels, scores),
        'score_distribution': score_distribution(labels, scores),
        'calibration': calibration(labels, scores),
        'coefficients': coefficient_table(schema.MODEL_FEATURES,
                                          [weights[name] for name in schema.MODEL_FEATURES], intercept),
        'zero_weight_check': {name: weights[name] for name in schema.EXCLUDED_FEATURES},
        'error_analysis': error_analysis(test, scores, INPUT_ORDER, ordered, .5),
        'error_analysis_at_0.90': error_analysis(test, scores, INPUT_ORDER, ordered, .9, limit=8),
        'by_scenario': by_scenario(test, scores),
        'false_positive_concentration': {str(t): false_positive_concentration(test, scores, t)
                                        for t in (.5, .9)},
        'generalisation': subsets,
        'analytic_reference_max_error': reference_error,
        'inference_ms_during_scoring': dict(zip(('p50', 'p95', 'p99'),
                                                map(float, np.percentile(durations, [50, 95, 99])))),
        'benchmark': benchmark(config, test[-1]['tensor']) if run_benchmark else None,
        'quality_gate': model_manifest.get('quality_gate_detail'),
        'quality_gate_passed': model_manifest.get('quality_gate_passed'),
        'recommended_mode': model_manifest.get('recommended_mode'),
        'synthetic_only': True,
        'limitations': [
            'synthetic corpus generated locally; not a representative security dataset',
            'test prevalence is an artefact of the generator and cannot estimate deployment prevalence',
            'validation shares scenario families with train, so it cannot detect family-level overfitting',
            'scores are uncalibrated; they are model scores, not probabilities of maliciousness',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description='Evaluate an exported model against a dataset (no retraining).')
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--model-dir', required=True, type=Path)
    parser.add_argument('--model-version', default=schema.MODEL_VERSION)
    parser.add_argument('--output', required=True, type=Path, help='evaluation JSON path')
    parser.add_argument('--report', type=Path, help='optional Markdown report path')
    parser.add_argument('--shadow', type=Path, help='optional shadow replay JSON to fold into the report')
    parser.add_argument('--pcap', type=Path, help='optional offline PCAP replay JSON to fold into the report')
    parser.add_argument('--skip-benchmark', action='store_true')
    args = parser.parse_args()
    result = evaluate(args.dataset, args.model_dir, args.model_version, run_benchmark=not args.skip_benchmark)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    if args.report:
        from .report import render
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            render(result, Path(args.model_dir) / (args.model_version + '-training.json'), args.shadow,
                   args.pcap),
            encoding='utf-8')
    print(json.dumps({'test': result['test'], 'generalisation': {
        k: {'pr_auc': v['pr_auc'], 'fpr_at_0.90': v['at_0.90']['false_positive_rate']}
        for k, v in result['generalisation'].items()},
        'quality_gate_passed': result['quality_gate_passed'],
        'recommended_mode': result['recommended_mode']}, indent=2))


if __name__ == '__main__':
    main()
