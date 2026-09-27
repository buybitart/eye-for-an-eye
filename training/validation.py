"""Dataset validator. Critical findings stop training; nothing is silently repaired.

Range, missing-value and duplicate policy is reported, never applied behind the caller's
back: a value outside the declared contract fails instead of being clipped in place.
"""
from collections import Counter, defaultdict
import math
import statistics
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES, SCHEMA_VERSION, SPEC, FeatureTransformer
from . import schema

NEAR_DUPLICATE_DECIMALS = 3
CEILINGS = {name: ceiling for name, ceiling, *_ in SPEC}


def tensors(rows):
    return [FeatureTransformer.transform(row['vector']) for row in rows]


def _percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return float(ordered[index])


def distribution_report(rows, tensor_rows=None):
    """Per model feature: bounds, central tendency, missing share and tail percentiles."""
    matrix = tensor_rows if tensor_rows is not None else tensors(rows)
    report = {}
    for name in schema.MODEL_FEATURES:
        column = [row[INPUT_ORDER.index(name)] for row in matrix]
        raw_name = name[len('available_'):] if name.startswith('available_') else name
        missing = sum(row['vector'].values[NAMES.index(raw_name)] is None for row in rows)
        report[name] = {
            'min': min(column), 'max': max(column), 'mean': statistics.fmean(column),
            'median': statistics.median(column),
            'std': statistics.pstdev(column) if len(column) > 1 else 0.0,
            'missing_percent': 100.0 * missing / len(rows),
            'p01': _percentile(column, .01), 'p05': _percentile(column, .05),
            'p95': _percentile(column, .95), 'p99': _percentile(column, .99),
            'constant': min(column) == max(column),
            'raw_above_ceiling_percent': 100.0 * sum(
                1 for row in rows
                if (v := row['vector'].values[NAMES.index(raw_name)]) is not None and v > CEILINGS[raw_name]
            ) / len(rows) if not name.startswith('available_') else 0.0,
        }
    return report


def duplicate_report(rows, tensor_rows=None):
    matrix = tensor_rows if tensor_rows is not None else tensors(rows)
    exact, near = defaultdict(set), defaultdict(set)
    exact_rows, near_rows = Counter(), Counter()
    for row, tensor in zip(rows, matrix, strict=True):
        key = tuple(tensor)
        rounded = tuple(round(v, NEAR_DUPLICATE_DECIMALS) for v in tensor)
        exact[key].add(row['split'])
        near[rounded].add(row['split'])
        exact_rows[key] += 1
        near_rows[rounded] += 1
    cross_exact = [k for k, splits in exact.items() if {'train', 'test'} <= splits or {'train', 'validation'} <= splits]
    cross_near = [k for k, splits in near.items() if {'train', 'test'} <= splits or {'train', 'validation'} <= splits]
    return {'rows': len(rows), 'distinct_exact_vectors': len(exact), 'distinct_near_vectors': len(near),
            'exact_duplicate_rows': sum(c - 1 for c in exact_rows.values()),
            'near_duplicate_rows': sum(c - 1 for c in near_rows.values()),
            'exact_vectors_crossing_train_boundary': len(cross_exact),
            'near_vectors_crossing_train_boundary': len(cross_near),
            'near_duplicate_decimals': NEAR_DUPLICATE_DECIMALS}


def class_distribution(rows):
    report = {}
    for split in ('train', 'validation', 'test'):
        subset = [row for row in rows if row['split'] == split]
        counts = Counter(row['label'] for row in subset)
        total = len(subset) or 1
        report[split] = {'rows': len(subset), 'sources': len({r['source_group'] for r in subset}),
                         'scenario_groups': len({r['scenario_group'] for r in subset}),
                         'counts': {'0': counts[0], '1': counts[1]},
                         'percent': {'0': 100.0 * counts[0] / total, '1': 100.0 * counts[1] / total}}
    return report


def group_leakage(rows):
    groups = defaultdict(set)
    scenarios = defaultdict(set)
    for row in rows:
        groups[row['source_group']].add(row['split'])
        scenarios[row['scenario_group']].add(row['split'])
    return {'source_groups_in_multiple_splits': sorted(g for g, s in groups.items() if len(s) > 1),
            'scenario_groups_in_multiple_splits': sorted(g for g, s in scenarios.items() if len(s) > 1),
            'test_only_scenario_groups': sorted(g for g, s in scenarios.items() if s == {'test'}),
            'source_group_count': len(groups), 'scenario_group_count': len(scenarios)}


def validate_dataset(manifest, rows, *, require_scenario_group_separation=False):
    """Return a report. Anything in report['critical'] must stop training."""
    critical, warnings = [], []
    if manifest.get('feature_schema_version') != SCHEMA_VERSION:
        critical.append('feature_schema_version mismatch')
    if list(manifest.get('model_feature_names', ())) != list(schema.MODEL_FEATURES):
        critical.append('manifest model feature order does not match the frozen contract')
    if set(manifest.get('model_feature_names', ())) & schema.FORBIDDEN_FEATURES:
        critical.append('forbidden identity or decision feature present in model contract')
    # A dataset may draw on more than one trusted source: a controlled corpus plus
    # reviewed rows, for example. Every one of them must be independently
    # trustworthy, so this widens what can be *stated* without widening what is
    # *accepted* — one bad source in a list still fails the whole dataset.
    declared = manifest.get('label_source')
    declared = declared if isinstance(declared, (list, tuple)) else [declared]
    if not declared or any(item not in schema.ALLOWED_LABEL_SOURCES for item in declared):
        critical.append('label_source is not an accepted independent source')

    matrix = tensors(rows)
    for row in rows:
        if row['label'] not in (0, 1):
            critical.append('label outside the binary schema')
            break
        if row['label_source'] in schema.FORBIDDEN_LABEL_SOURCES:
            critical.append('decision-derived label found in rows')
            break
        if row['feature_schema_version'] != SCHEMA_VERSION:
            critical.append('row feature_schema_version mismatch')
            break

    out_of_range = non_finite = 0
    for tensor in matrix:
        for value in tensor:
            if not math.isfinite(value):
                non_finite += 1
            elif not schema.FEATURE_RANGE[0] <= value <= schema.FEATURE_RANGE[1]:
                out_of_range += 1
    if non_finite:
        critical.append(f'{non_finite} non-finite transformed values')
    if out_of_range:
        critical.append(f'{out_of_range} transformed values outside the declared [0,1] contract')

    mask_errors = 0
    for row, tensor in zip(rows, matrix, strict=True):
        for index, name in enumerate(NAMES):
            observed = row['vector'].values[index] is not None
            if tensor[INPUT_ORDER.index('available_' + name)] != float(observed):
                mask_errors += 1
            if not observed and tensor[index] != 0.0:
                mask_errors += 1
    if mask_errors:
        critical.append(f'{mask_errors} availability-mask inconsistencies')

    distribution = distribution_report(rows, matrix)
    duplicates = duplicate_report(rows, matrix)
    classes = class_distribution(rows)
    leakage = group_leakage(rows)

    if leakage['source_groups_in_multiple_splits']:
        critical.append('source_group leakage across splits')
    if require_scenario_group_separation and leakage['scenario_groups_in_multiple_splits']:
        critical.append('scenario_group leakage across splits')
    if duplicates['exact_vectors_crossing_train_boundary']:
        critical.append('identical feature vectors appear in train and a held-out split')
    if duplicates['near_vectors_crossing_train_boundary']:
        warnings.append(f"{duplicates['near_vectors_crossing_train_boundary']} near-duplicate vectors "
                        'cross the train boundary')
    for split, info in classes.items():
        if not info['rows']:
            critical.append(f'empty {split} split')
        elif min(info['counts'].values()) == 0:
            critical.append(f'{split} split contains a single class')
    constants = [name for name, info in distribution.items() if info['constant']]
    if constants:
        warnings.append('constant columns carry no evidence in this corpus: ' + ', '.join(constants))
    clipped = [name for name, info in distribution.items() if info['raw_above_ceiling_percent'] > 5.0]
    if clipped:
        warnings.append('documented ceiling clipping above 5% of rows: ' + ', '.join(clipped))

    return {'critical': critical, 'warnings': warnings, 'class_distribution': classes,
            'group_leakage': leakage, 'duplicates': duplicates, 'feature_distribution': distribution,
            'constant_columns': constants, 'rows': len(rows),
            'dataset_version': manifest.get('dataset_version'),
            'model_feature_count': len(schema.MODEL_FEATURES)}


def main():
    import argparse
    import json
    from pathlib import Path
    from .dataset import load
    parser = argparse.ArgumentParser(description='Validate a dataset directory without training anything.')
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--output', type=Path, help='optional JSON report path')
    args = parser.parse_args()
    manifest, rows = load(args.dataset)
    report = validate_dataset(manifest, rows)
    text = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(text + '\n', encoding='utf-8')
    print(json.dumps({'critical': report['critical'], 'warnings': report['warnings'],
                      'class_distribution': report['class_distribution'],
                      'duplicates': report['duplicates'], 'group_leakage': {
                          k: v for k, v in report['group_leakage'].items() if not k.startswith('test_only')}},
                     indent=2))
    raise SystemExit(1 if report['critical'] else 0)


if __name__ == '__main__':
    main()
