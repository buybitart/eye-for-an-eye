"""Dataset validation and the training readiness gate.

Critical findings stop a build. Nothing is silently repaired: an out-of-range value names the
scenario that produced it, so the generator or the extractor gets fixed rather than the data.
"""
from collections import Counter
import math
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES
from . import schema
from .deduplicate import analyse as duplicate_analysis, cross_source, cross_split, tensors
from .manifest import READINESS, verify_files
from .statistics import balance_report, feature_report, label_report, scenario_report, source_report

MIN_SCENARIOS_PER_LABEL = 3
MIN_SOURCE_GROUPS_PER_LABEL = 6


def _structure(samples, critical, warnings):
    seen = Counter()
    for sample in samples:
        seen[sample.sample_id] += 1
        if sample.dataset_schema_version not in schema.READABLE_SCHEMA_VERSIONS:
            critical.append('dataset schema version mismatch')
            break
        # A row may declare an older feature schema: it was written before a
        # column existed, and `schema.sample_from_row` reads it with that column
        # explicitly unknown. What is never acceptable is a row from the future,
        # whose columns this build cannot interpret at all.
        if sample.feature_schema_version not in schema.READABLE_FEATURE_SCHEMA_VERSIONS:
            critical.append('feature schema version mismatch')
            break
        if sample.label not in schema.ALL_LABELS:
            critical.append('unknown label')
            break
        if sample.label_source not in schema.ALL_LABEL_SOURCES:
            critical.append('unknown label source')
            break
        if sample.label_source in schema.FORBIDDEN_LABEL_SOURCES:
            critical.append('a decision made by this system was used as ground truth')
            break
        if sample.label_confidence not in schema.CONFIDENCES:
            critical.append('unknown label confidence')
            break
        if len(sample.features.values) != len(NAMES):
            critical.append('feature count does not match the schema')
            break
    repeated = [name for name, count in seen.items() if count > 1]
    if repeated:
        critical.append(f'{len(repeated)} duplicate sample ids')
    return repeated


def _values(samples, matrix, critical, warnings):
    non_finite, out_of_range, mask_errors = [], [], []
    for sample, tensor in zip(samples, matrix, strict=True):
        for index, value in enumerate(tensor):
            if not math.isfinite(value):
                non_finite.append((sample.sample_id, INPUT_ORDER[index]))
            elif not schema.FEATURE_RANGE[0] <= value <= schema.FEATURE_RANGE[1]:
                out_of_range.append({'sample_id': sample.sample_id, 'scenario_id': sample.scenario_id,
                                     'feature': INPUT_ORDER[index], 'value': value})
        for index, name in enumerate(NAMES):
            observed = sample.features.values[index] is not None
            if tensor[INPUT_ORDER.index('available_' + name)] != float(observed):
                mask_errors.append(sample.sample_id)
            elif not observed and tensor[index] != 0.0:
                mask_errors.append(sample.sample_id)
    if non_finite:
        critical.append(f'{len(non_finite)} non-finite feature values')
    if out_of_range:
        scenarios = sorted({row['scenario_id'] for row in out_of_range})
        critical.append(f'{len(out_of_range)} values outside the declared [0,1] contract, '
                        f'produced by: {", ".join(scenarios[:5])}')
    if mask_errors:
        critical.append(f'{len(set(mask_errors))} rows with inconsistent availability masks')
    return {'non_finite': len(non_finite), 'out_of_range': out_of_range[:20],
            'out_of_range_count': len(out_of_range), 'mask_errors': len(set(mask_errors))}


def _groups(samples, critical, warnings):
    by_source = {}
    by_scenario = {}
    for sample in samples:
        by_source.setdefault(sample.group, set()).add(sample.split or 'unassigned')
        if sample.scenario_group:
            by_scenario.setdefault(sample.scenario_group, set()).add(sample.split or 'unassigned')
    shared = sorted(group for group, splits in by_source.items() if len(splits) > 1)
    if shared:
        critical.append(f'{len(shared)} grouping keys appear in more than one split')
    return {'source_groups': len(by_source), 'scenario_groups': len(by_scenario),
            'group_keys_in_multiple_splits': shared[:10],
            'source_groups_in_multiple_splits': shared[:10],
            'scenario_groups_in_multiple_splits': sorted(
                group for group, splits in by_scenario.items() if len(splits) > 1)}


def readiness(critical, labels, scenarios, duplicates, coverage, split_assigned, *, sources=None,
              cross=None, leakage_report=False, parts=None):
    """ENGINEERING_ONLY is the honest default; READY_FOR_BASELINE_TRAINING has to be earned."""
    reasons = []
    if critical:
        return READINESS[0], ['critical validation findings: ' + '; '.join(critical[:4])]
    supervised = {label: info for label, info in labels.items() if label in schema.SUPERVISED_LABELS}
    if len(supervised) < 2:
        reasons.append('fewer than two supervised labels')
    for label, info in supervised.items():
        if info['scenarios'] < MIN_SCENARIOS_PER_LABEL:
            reasons.append(f'{label} has fewer than {MIN_SCENARIOS_PER_LABEL} independent scenarios')
        if info['source_groups'] < MIN_SOURCE_GROUPS_PER_LABEL:
            reasons.append(f'{label} has fewer than {MIN_SOURCE_GROUPS_PER_LABEL} independent sources')
    kinds = {info['kind'] for info in scenarios.values()}
    if 'hard_negative' not in kinds:
        reasons.append('no hard negative scenario present')
    if 'hard_positive' not in kinds:
        reasons.append('no hard positive scenario present')
    if duplicates['conflicting_label_vectors']:
        reasons.append('identical feature vectors carry conflicting labels')
    if duplicates['duplicate_sample_ids']:
        reasons.append('duplicate sample ids')
    if not split_assigned:
        reasons.append('no split assigned yet')
    elif coverage['group_keys_in_multiple_splits']:
        reasons.append('grouping key leakage across splits')
    sources = sources or {}
    if not sources.get(schema.PCAP):
        reasons.append('no PCAP contribution: the dataset has no source outside the behaviour generator')
    if not sources.get(schema.LAB):
        reasons.append('no LAB contribution: nothing with controlled ground truth')
    if cross and cross.get('with_conflicting_labels'):
        reasons.append('the same feature vector appears under two sources with conflicting labels')
    if not leakage_report:
        reasons.append('no leakage report was produced')
    if parts is not None and not parts.get('test'):
        reasons.append('no test holdout exists')
    if reasons:
        return READINESS[1], reasons
    return READINESS[2], ['schema, ranges, labels, groups, duplicates and hard cases all check out']


def validate(samples, *, manifest=None, directory=None, matrix=None, leakage_report=False):
    critical, warnings = [], []
    matrix = matrix if matrix is not None else tensors(samples)
    if not samples:
        return {'critical': ['dataset is empty'], 'warnings': [], 'readiness': READINESS[0],
                'readiness_reasons': ['dataset is empty']}
    duplicate_ids = _structure(samples, critical, warnings)
    values = _values(samples, matrix, critical, warnings)
    coverage = _groups(samples, critical, warnings)
    duplicates = duplicate_analysis(samples, matrix)
    if duplicates['conflicting_label_vectors']:
        critical.append(f"{duplicates['conflicting_label_vectors']} identical feature vectors carry "
                        'conflicting labels')
    if duplicates['exact_duplicate_rows']:
        warnings.append(f"{duplicates['exact_duplicate_rows']} exactly repeated feature vectors")
    split_assigned = any(sample.split for sample in samples)
    boundary = cross_split(samples, matrix) if split_assigned else {}
    if boundary.get('exact_vectors_crossing_train_boundary'):
        critical.append('identical feature vectors appear in train and a held-out split')
    if boundary.get('near_vectors_crossing_train_boundary'):
        warnings.append(f"{boundary['near_vectors_crossing_train_boundary']} near-duplicate vectors cross "
                        'the train boundary')
    cross = cross_source(samples, matrix)
    if cross['with_conflicting_labels']:
        critical.append(f"{cross['with_conflicting_labels']} feature vectors appear under more than "
                        'one source with conflicting labels')
    labels = label_report(samples)
    scenarios = scenario_report(samples)
    sources = source_report(samples, matrix)
    source_counts = {name: info['rows'] for name, info in sources.items()}
    parts = {name: sum(1 for sample in samples if sample.split == name)
             for name in ('train', 'validation', 'test')}
    unreviewed_in_split = [sample.sample_id for sample in samples
                           if sample.source_type == schema.SHADOW_UNLABELED and sample.split]
    if unreviewed_in_split:
        critical.append(f'{len(unreviewed_in_split)} unreviewed shadow rows entered a supervised split')
    balance = balance_report(samples)
    features = feature_report(samples, matrix)
    flagged = {name: entry['flags'] for name, entry in features.items() if any(entry['flags'].values())}
    if flagged:
        warnings.append('features with no or almost no variation in this dataset: ' +
                        ', '.join(sorted(flagged)))
    if balance['largest_scenario_share_percent'] > 25:
        warnings.append(f"one scenario contributes {balance['largest_scenario_share_percent']:.1f}% of rows "
                        f"({balance['largest_scenario']})")
    unlabelled = labels.get(schema.UNLABELED, {}).get('rows', 0) + labels.get(schema.UNCERTAIN, {}).get('rows', 0)
    if unlabelled:
        warnings.append(f'{unlabelled} unlabelled or uncertain rows are present and are excluded from '
                        'supervised splits')
    if manifest is not None:
        if manifest.get('record_count') != len(samples):
            critical.append('manifest record count does not match the data')
        if list(manifest.get('model_feature_names', ())) != list(schema.MODEL_FEATURES):
            critical.append('manifest model feature list does not match the frozen contract')
        if set(manifest.get('model_feature_names', ())) & set(schema.NEVER_MODEL_INPUT):
            critical.append('manifest lists a forbidden column as a model feature')
        if directory is not None:
            problems = verify_files(manifest, directory)
            if problems:
                critical.append('manifest file verification failed: ' + '; '.join(problems[:3]))
    state, reasons = readiness(critical, labels, scenarios, duplicates, coverage, split_assigned,
                               sources=source_counts, cross=cross, leakage_report=leakage_report,
                               parts=parts if split_assigned else None)
    return {'critical': critical, 'warnings': warnings, 'readiness': state, 'readiness_reasons': reasons,
            'rows': len(samples), 'values': values, 'coverage': coverage, 'duplicates': duplicates,
            'cross_source_duplicates': cross, 'sources': source_counts,
            'source_distributions': sources, 'splits': parts,
            'supervised_eligible': sum(1 for sample in samples if sample.supervised),
            'unlabelled_pool': sum(1 for sample in samples if not sample.supervised),
            'cross_split': boundary, 'labels': labels, 'balance': balance,
            'feature_flags': flagged, 'duplicate_sample_ids': duplicate_ids[:10],
            'scenarios': scenarios, 'features': features,
            'production_note': ('READY_FOR_BASELINE_TRAINING is not production readiness. Automatic '
                                'enforcement readiness is NO until a model evaluated on this dataset '
                                'is also validated in shadow mode against real traffic.'),
            'automatic_enforcement_ready': False}
