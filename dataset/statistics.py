"""Distribution, coverage and balance reporting. Nothing here changes the data."""
from collections import Counter, defaultdict
import math
import statistics as stats
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES, FeatureTransformer
from . import schema
from .deduplicate import tensors

QUANTILES = ((1, 'p01'), (5, 'p05'), (25, 'p25'), (50, 'p50'), (75, 'p75'), (95, 'p95'), (99, 'p99'))


def _quantile(ordered, fraction):
    if not ordered:
        return None
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return float(ordered[index])


def feature_report(samples, matrix=None):
    """Per model feature, overall and per label."""
    matrix = matrix if matrix is not None else tensors(samples)
    groups = {'overall': list(range(len(samples)))}
    for label in schema.SUPERVISED_LABELS:
        groups[label] = [index for index, sample in enumerate(samples) if sample.label == label]
    report = {}
    for name in schema.MODEL_FEATURES:
        position = INPUT_ORDER.index(name)
        raw_name = name[len('available_'):] if name.startswith('available_') else name
        raw_index = NAMES.index(raw_name)
        entry = {}
        for group, indexes in groups.items():
            column = [matrix[index][position] for index in indexes]
            if not column:
                entry[group] = {'count': 0}
                continue
            ordered = sorted(column)
            missing = sum(samples[index].features.values[raw_index] is None for index in indexes)
            entry[group] = {
                'count': len(column), 'missing': missing,
                'missing_percent': 100.0 * missing / len(column),
                'min': min(column), 'max': max(column), 'mean': stats.fmean(column),
                'median': stats.median(column),
                'std': stats.pstdev(column) if len(column) > 1 else 0.0,
                **{name_: _quantile(ordered, percent / 100) for percent, name_ in QUANTILES},
            }
        overall = entry['overall']
        entry['flags'] = {
            'constant': overall['min'] == overall['max'],
            'always_zero': overall['min'] == overall['max'] == 0.0,
            'always_one': overall['min'] == overall['max'] == 1.0,
            'nearly_constant': overall['std'] < 1e-6,
            'high_missing': overall['missing_percent'] > 40.0,
        }
        report[name] = entry
    return report


def label_report(samples):
    report = {}
    for label in schema.ALL_LABELS:
        subset = [sample for sample in samples if sample.label == label]
        if not subset:
            continue
        report[label] = {
            'rows': len(subset),
            'scenarios': len({sample.scenario_id for sample in subset}),
            'scenario_groups': len({sample.scenario_group for sample in subset}),
            'source_groups': len({sample.source_group for sample in subset}),
            'observed_seconds': round(sum(s.features.observation_seconds for s in subset), 2),
            'confidence': dict(Counter(sample.label_confidence for sample in subset)),
            'label_sources': dict(Counter(sample.label_source for sample in subset)),
        }
    return report


def scenario_report(samples):
    """Scenario coverage and share, so one long scenario cannot quietly dominate."""
    total = len(samples) or 1
    grouped = defaultdict(list)
    for sample in samples:
        grouped[sample.scenario_id or sample.provenance.get('source_type', 'unknown')].append(sample)
    report = {}
    for scenario, subset in sorted(grouped.items()):
        report[scenario] = {
            'label': subset[0].label,
            'scenario_group': subset[0].scenario_group,
            'kind': subset[0].provenance.get('scenario_kind'),
            'runs': len({sample.group for sample in subset}),
            'samples': len(subset),
            'share_percent': 100.0 * len(subset) / total,
            'seeds': sorted({sample.provenance.get('seed') for sample in subset
                             if sample.provenance.get('seed')}),
            'duration_seconds': round(max(s.features.observation_seconds for s in subset), 2),
        }
    return report


def balance_report(samples):
    """Row balance is not the only balance that matters; scenario share matters more."""
    scenarios = scenario_report(samples)
    shares = sorted(((info['share_percent'], name) for name, info in scenarios.items()), reverse=True)
    kinds = Counter(sample.provenance.get('scenario_kind') for sample in samples)
    return {
        'rows': len(samples),
        'labels': dict(Counter(sample.label for sample in samples)),
        'label_percent': {label: 100.0 * count / max(1, len(samples))
                          for label, count in Counter(sample.label for sample in samples).items()},
        'scenario_kinds': dict(kinds),
        'largest_scenario_share_percent': shares[0][0] if shares else 0.0,
        'largest_scenario': shares[0][1] if shares else None,
        'top_five_share_percent': sum(share for share, _ in shares[:5]),
        'scenarios': len(scenarios),
        'hard_negative_scenarios': sum(1 for info in scenarios.values() if info['kind'] == 'hard_negative'),
        'hard_positive_scenarios': sum(1 for info in scenarios.values() if info['kind'] == 'hard_positive'),
    }


def training_statistics(samples, matrix=None):
    """datasets/stats_v1.json: ranges and quantiles production can later compare against."""
    report = feature_report(samples, matrix)
    return {
        'statistics_version': 1,
        'feature_schema_version': schema.FEATURE_SCHEMA_VERSION,
        'rows': len(samples),
        'tensor_order': list(INPUT_ORDER),
        'model_features': list(schema.MODEL_FEATURES),
        'features': {name: {key: value for key, value in entry['overall'].items()}
                     for name, entry in report.items()},
        'flags': {name: entry['flags'] for name, entry in report.items()},
        'purpose': ('offline diagnostics only: comparing live feature quantiles against these ranges '
                    'indicates distribution shift, it does not by itself invalidate a decision'),
    }


def source_report(samples, matrix=None):
    """Per-source feature distributions. LAB, PCAP and SHADOW are not interchangeable."""
    matrix = matrix if matrix is not None else tensors(samples)
    report = {}
    for source in sorted({sample.source_type for sample in samples}):
        index = [position for position, sample in enumerate(samples) if sample.source_type == source]
        subset = [samples[position] for position in index]
        report[source] = {
            'rows': len(subset),
            'role': schema.SOURCE_ROLES[source],
            'groups': len({sample.group for sample in subset}),
            'labels': dict(Counter(sample.label for sample in subset)),
            'supervised_eligible': sum(1 for sample in subset if sample.supervised),
            'features': feature_report(subset, [matrix[position] for position in index]),
        }
    return report


def _psi(left, right, bins=10):
    """Population stability index between two samples of one feature. Bounded, dependency free."""
    if not left or not right:
        return None
    edges = [index / bins for index in range(bins + 1)]
    total_left, total_right = len(left), len(right)
    score = 0.0
    for low, high in zip(edges[:-1], edges[1:], strict=True):
        share_left = sum(1 for value in left if low <= value < high or (high == 1 and value == 1)) / total_left
        share_right = sum(1 for value in right if low <= value < high or (high == 1 and value == 1)) / total_right
        share_left = max(share_left, 1e-4)
        share_right = max(share_right, 1e-4)
        score += (share_right - share_left) * math.log(share_right / share_left)
    return score


def distribution_shift(samples, matrix=None, *, reference=None):
    """Compare every pair of sources feature by feature.

    Reported, never corrected. A large shift means the sources are not interchangeable, which
    is expected: it is the size and the direction that matter.
    """
    matrix = matrix if matrix is not None else tensors(samples)
    columns = {}
    for source in sorted({sample.source_type for sample in samples}):
        index = [position for position, sample in enumerate(samples) if sample.source_type == source]
        columns[source] = {name: [matrix[position][INPUT_ORDER.index(name)] for position in index]
                           for name in schema.MODEL_FEATURES}
    pairs = {}
    names = sorted(columns)
    for left in names:
        for right in names:
            if left >= right:
                continue
            rows = []
            for name in schema.MODEL_FEATURES:
                a, b = columns[left][name], columns[right][name]
                if not a or not b:
                    continue
                rows.append({
                    'feature': name,
                    'median_delta': stats.median(b) - stats.median(a),
                    'mean_delta': stats.fmean(b) - stats.fmean(a),
                    'p95_delta': (_quantile(sorted(b), .95) or 0) - (_quantile(sorted(a), .95) or 0),
                    'psi': _psi(a, b),
                    'range_covered': (min(b) >= min(a) - 1e-9 and max(b) <= max(a) + 1e-9),
                })
            rows.sort(key=lambda item: -(item['psi'] or 0))
            pairs[f'{left}_vs_{right}'] = {
                'features': rows,
                'largest_shifts': rows[:8],
                'features_with_large_shift': [row['feature'] for row in rows if (row['psi'] or 0) >= .25],
            }
    coverage = {}
    if reference and reference in columns:
        for source in names:
            if source == reference:
                continue
            gaps = []
            for name in schema.MODEL_FEATURES:
                a, b = columns[reference][name], columns[source][name]
                if not a or not b:
                    continue
                if max(a) + 1e-9 < _quantile(sorted(b), .95):
                    gaps.append({'feature': name, 'reference_max': max(a),
                                 'observed_p95': _quantile(sorted(b), .95)})
            coverage[source] = {'features_reference_does_not_reach': gaps,
                                'note': 'the reference generator does not produce the range this source shows'}
    return {'pairs': pairs, 'range_coverage': coverage, 'psi_threshold': .25,
            'note': 'PSI over ten fixed bins on the [0,1] transformed feature; descriptive only'}


def out_of_distribution(samples, quantiles, *, low='p01', high='p99'):
    """Which observed rows sit outside the training quantiles, and on how many features."""
    report = {}
    for sample in samples:
        tensor = FeatureTransformer.transform(sample.features)
        outside, deviation = [], 0.0
        for name in schema.MODEL_FEATURES:
            bounds = quantiles.get(name)
            if not bounds:
                continue
            value = tensor[INPUT_ORDER.index(name)]
            lower, upper = bounds.get(low), bounds.get(high)
            if lower is not None and value < lower:
                outside.append(name)
                deviation += lower - value
            elif upper is not None and value > upper:
                outside.append(name)
                deviation += value - upper
        if outside:
            report[sample.sample_id] = {'features': len(outside), 'names': outside[:6],
                                        'deviation': round(deviation, 4)}
    return report


def training_quantiles(samples, matrix=None):
    """Reference quantiles from supervised training rows, for later drift and OOD checks."""
    report = feature_report([s for s in samples if s.supervised], matrix)
    return {name: {key: entry['overall'][key] for key in ('min', 'max', 'p01', 'p05', 'p95', 'p99')}
            for name, entry in report.items()}
