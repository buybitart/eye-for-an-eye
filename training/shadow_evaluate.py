"""Replay held-out feature sequences through the production fusion and policy."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
from eye_for_an_eye.analysis import EventAnalysis
from eye_for_an_eye.config import Config, MLConfig
from eye_for_an_eye.decision.features import FeatureTransformer
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel, MLResult
from eye_for_an_eye.decision.shadow import ShadowReport
from eye_for_an_eye.events import NetworkEvent
from .train_baseline import load_dataset


def evaluate(dataset, directory):
    rows = [r for r in load_dataset(dataset) if r['split'] == 'test']
    result = {}
    for candidate in ('math_only', 'logistic', 'gradient_boosting'):
        model = OnnxRiskModel()
        if candidate != 'math_only':
            state = model.load(MLConfig(model_path=str(directory / (candidate + '-research-v1.onnx')),
                manifest_path=str(directory / (candidate + '-research-v1.json'))))
            if state['status'] != 'healthy':
                raise RuntimeError(state)
        engine = EventAnalysis(Config()).decisions
        summary = ShadowReport()
        starts, reached, sources = {}, {}, {}
        scenarios = defaultdict(lambda: {'sources': set(), 'blocked': set(), 'times': defaultdict(list)})
        false_positives = []
        for row in rows:
            group = row['source_group']
            sources.setdefault(group, f'192.0.2.{len(sources)+1}')
            starts.setdefault(group, row['timestamp'])
            event = NetworkEvent(sources[group], timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=row['timestamp']))
            ml = model.predict(FeatureTransformer.transform(row['vector'])) if candidate != 'math_only' else MLResult()
            record = engine._record(event, row['vector'], ml)
            summary.observe(record.to_dict(), row['label'])
            data = record.observations
            scenario = scenarios[row['scenario_id']]
            scenario['sources'].add(group)
            if data['would_enforce']:
                scenario['blocked'].add(group)
                if row['label'] == 0 and group not in false_positives:
                    false_positives.append(group)
            for action in ('WATCH', 'RATE_LIMIT', 'TEMP_BLOCK'):
                from eye_for_an_eye.decision.policy import ACTIONS
                if ACTIONS.index(data['action']) >= ACTIONS.index(action) and (group, action) not in reached:
                    reached[group, action] = row['timestamp'] - starts[group]
                    scenario['times'][action].append(reached[group, action])
        result[candidate] = {'summary': summary.snapshot(), 'false_positive_block_sources': false_positives,
            'scenarios': {name: {'sources': len(s['sources']), 'would_block': len(s['blocked']),
                'time_from_first_feature_seconds': {action: {'reached': len(values), 'min': min(values),
                    'mean': sum(values)/len(values), 'max': max(values)} for action, values in s['times'].items()}}
                for name, s in scenarios.items()}}
    return {'synthetic_only': True, 'test_rows': len(rows), 'candidates': result,
        'timing_origin': 'first feature at four observations; all per-source sequences retained; unreached actions omitted',
        'release_recommendation': 'SHADOW ONLY'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--models', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(evaluate(args.dataset, args.models), stream, indent=2, allow_nan=False)
