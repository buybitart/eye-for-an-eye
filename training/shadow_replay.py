"""Replay held-out feature vectors through the production fusion and policy, in shadow only.

No packet is transmitted, no firewall rule is touched and no configuration is written.
Enforcement stays disabled and the decision engine runs in shadow mode, so 'would_enforce'
is a recorded hypothesis, never an action.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from eye_for_an_eye.analysis import EventAnalysis
from eye_for_an_eye.config import Config, MLConfig
from eye_for_an_eye.decision.features import FeatureTransformer
from eye_for_an_eye.decision.onnx_model import MLResult, OnnxRiskModel
from eye_for_an_eye.decision.policy import ACTIONS
from eye_for_an_eye.decision.shadow import ShadowReport
from eye_for_an_eye.events import NetworkEvent
from . import schema
from .dataset import load

ORIGIN = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _config():
    config = Config()
    config.decision.mode = 'shadow'
    config.enforcement.enabled = False
    config.ml.enabled = False
    return config


def replay(dataset_dir, model_dir, version, split='test'):
    _, rows = load(dataset_dir)
    rows = [row for row in rows if row['split'] == split]
    rows.sort(key=lambda row: (row['source_group'], row['timestamp']))
    for row in rows:
        row['tensor'] = FeatureTransformer.transform(row['vector'])
    result = {}
    for candidate in ('math_only', version):
        model = OnnxRiskModel()
        if candidate != 'math_only':
            state = model.load(MLConfig(model_path=str(Path(model_dir) / (candidate + '.onnx')),
                                        manifest_path=str(Path(model_dir) / (candidate + '.json'))))
            if state['status'] != 'healthy':
                raise RuntimeError('adapter rejected the model: ' + json.dumps(state))
        engine = EventAnalysis(_config()).decisions
        summary = ShadowReport()
        addresses, disagreements = {}, defaultdict(list)
        scenarios = defaultdict(lambda: {'sources': set(), 'would_block': set(), 'label': 0})
        for row in rows:
            group = row['source_group']
            addresses.setdefault(group, f'203.0.113.{1 + len(addresses) % 250}')
            event = NetworkEvent(addresses[group], sensor_id=f'replay-{len(addresses)}',
                                 timestamp=ORIGIN + timedelta(seconds=row['timestamp']))
            ml = model.predict(list(row['tensor'])) if candidate != 'math_only' else MLResult()
            record = engine._record(event, row['vector'], ml)
            summary.observe(record.to_dict(), row['label'])
            data = record.observations
            scenario = scenarios[row['scenario_id']]
            scenario['sources'].add(group)
            scenario['label'] = row['label']
            if data['would_enforce']:
                scenario['would_block'].add(group)
            if data['disagreement'] != 'none' and len(disagreements[data['disagreement']]) < 12:
                disagreements[data['disagreement']].append({
                    'sample_id': row['sample_id'], 'scenario_id': row['scenario_id'], 'label': row['label'],
                    'math_score': data['math_score'], 'model_score': data['ml']['risk_score'],
                    'fused_risk': data['risk'], 'action': data['action'],
                    'policy_reasons': data['policy_reasons']})
        result[candidate] = {
            'summary': summary.snapshot(),
            'action_totals': {name: engine.metrics.get('decision_' + name.lower() + '_total', 0) for name in ACTIONS},
            'disagreement_examples': dict(disagreements),
            'disagreement_counts': {k: len(v) for k, v in disagreements.items()},
            'scenarios': {name: {'label': info['label'], 'sources': len(info['sources']),
                                 'would_block_sources': len(info['would_block'])}
                          for name, info in sorted(scenarios.items())},
            'benign_sources_that_would_block': sorted(
                name for name, info in scenarios.items() if info['label'] == 0 and info['would_block']),
        }
    return {'dataset_split': split, 'rows': len(rows), 'synthetic_only': True,
            'enforcement': 'disabled; shadow mode; no firewall interaction',
            'positive_class': schema.POSITIVE_CLASS, 'candidates': result,
            'release_recommendation': 'SHADOW ONLY',
            'limitations': ['synthetic replay is not deployment evidence',
                            'per-source timing is generator time, not captured wall clock']}


def main():
    parser = argparse.ArgumentParser(description='Shadow replay of a dataset split through fusion and policy.')
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--model-dir', required=True, type=Path)
    parser.add_argument('--model-version', default=schema.MODEL_VERSION)
    parser.add_argument('--split', default='test', choices=('train', 'validation', 'test'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = replay(args.dataset, args.model_dir, args.model_version, args.split)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    print(json.dumps({name: {'would_block_sources': info['summary']['would_block_sources'],
                             'block_precision': info['summary']['block_precision'],
                             'benign_families_that_would_block': info['benign_sources_that_would_block'],
                             'disagreements': info['disagreement_counts']}
                      for name, info in result['candidates'].items()}, indent=2))


if __name__ == '__main__':
    main()
