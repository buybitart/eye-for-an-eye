"""Leakage analysis: can something other than behaviour predict the label?

A generated dataset can teach a model the harness instead of the phenomenon. These checks
look for the usual ways that happens - a port that only one class ever touches, a spacing
only one generator produces, a payload length unique to one family, or a single feature that
separates the classes almost perfectly. Findings are reported, never silently corrected.
"""
from collections import Counter, defaultdict
from eye_for_an_eye.decision.features import INPUT_ORDER
from . import schema
from .deduplicate import tensors

MIN_SUPPORT = 4
NEAR_PERFECT_AUC = 0.99
NEAR_PERFECT_CORRELATION = 0.95


def auc(values, labels):
    """Rank-based AUC of one column against a binary label. No dependency, ties handled."""
    pairs = sorted(zip(values, labels, strict=True))
    ranks, index = {}, 0
    while index < len(pairs):
        end = index
        while end + 1 < len(pairs) and pairs[end + 1][0] == pairs[index][0]:
            end += 1
        shared = (index + end) / 2 + 1
        for position in range(index, end + 1):
            ranks[position] = shared
        index = end + 1
    positives = sum(1 for _, label in pairs if label == 1)
    negatives = len(pairs) - positives
    if not positives or not negatives:
        return None
    rank_sum = sum(ranks[position] for position, (_, label) in enumerate(pairs) if label == 1)
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def correlation(values, labels):
    count = len(values)
    if count < 2:
        return None
    mean_x = sum(values) / count
    mean_y = sum(labels) / count
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in zip(values, labels, strict=True))
    spread_x = sum((x - mean_x) ** 2 for x in values) ** .5
    spread_y = sum((y - mean_y) ** 2 for y in labels) ** .5
    if spread_x == 0 or spread_y == 0:
        return 0.0
    return covariance / (spread_x * spread_y)


def _binary(samples):
    return [schema.BINARY_CODE[sample.label] for sample in samples]


def feature_separation(samples, matrix=None):
    """Which single features come close to separating the classes on their own."""
    matrix = matrix if matrix is not None else tensors(samples)
    labels = _binary(samples)
    rows = []
    for name in schema.MODEL_FEATURES:
        position = INPUT_ORDER.index(name)
        column = [tensor[position] for tensor in matrix]
        rows.append({'feature': name, 'auc': auc(column, labels), 'correlation': correlation(column, labels)})
    rows.sort(key=lambda item: abs(item['auc'] - .5) if item['auc'] is not None else 0, reverse=True)
    suspicious = [row for row in rows
                  if (row['auc'] is not None and (row['auc'] >= NEAR_PERFECT_AUC or row['auc'] <= 1 - NEAR_PERFECT_AUC))
                  or (row['correlation'] is not None and abs(row['correlation']) >= NEAR_PERFECT_CORRELATION)]
    return {'features': rows, 'suspicious': suspicious,
            'threshold': {'auc': NEAR_PERFECT_AUC, 'correlation': NEAR_PERFECT_CORRELATION},
            'note': 'a near-perfect single feature usually means the generator, not the phenomenon'}


def port_leakage(runs, *, min_support=MIN_SUPPORT):
    """Does any destination port, on its own, predict the label?"""
    runs = [run for run in runs if run.get('label') in schema.BINARY_CODE and run.get('ports')]
    by_port = defaultdict(Counter)
    for run in runs:
        for port in run.get('ports') or ():
            by_port[port][run['label']] += 1
    rows = []
    for port, counts in sorted(by_port.items()):
        total = sum(counts.values())
        majority = counts.most_common(1)[0]
        rows.append({'port': port, 'runs': total, 'benign_like': counts.get(schema.BENIGN, 0),
                     'malicious_automation_like': counts.get(schema.MALICIOUS, 0),
                     'purity': majority[1] / total, 'majority_label': majority[0]})
    supported = [row for row in rows if row['runs'] >= min_support]
    exclusive = [row for row in supported if row['purity'] == 1.0]
    shared = [row for row in supported if row['purity'] < 1.0]
    labels = [schema.BINARY_CODE[run['label']] for run in runs]
    if not supported or not runs:
        return {'ports_observed': len(rows), 'ports_with_support': 0, 'exclusive_to_one_label': [],
                'shared_ports': 0, 'shared_port_fraction': None,
                'best_single_port_rule_accuracy': None, 'best_single_port': None,
                'top_ports': [], 'min_support': min_support}
    best_single_port = max(
        ((sum(1 for run, label in zip(runs, labels, strict=True)
              if (row['port'] in run['ports']) == (label == schema.BINARY_CODE[row['majority_label']])) / len(runs),
          row['port']) for row in supported), default=(None, None))
    return {'ports_observed': len(rows), 'ports_with_support': len(supported),
            'exclusive_to_one_label': [row['port'] for row in exclusive],
            'shared_ports': len(shared),
            'shared_port_fraction': len(shared) / len(supported) if supported else None,
            'best_single_port_rule_accuracy': best_single_port[0],
            'best_single_port': best_single_port[1],
            'top_ports': sorted(supported, key=lambda row: -row['runs'])[:12],
            'min_support': min_support}


def timing_leakage(runs):
    """Does inter-contact spacing alone separate the classes?"""
    runs = [run for run in runs if run.get('label') in schema.BINARY_CODE
            and run.get('interarrival_mean') is not None]
    labels = [schema.BINARY_CODE[run['label']] for run in runs]
    report = {}
    for field in ('interarrival_mean', 'interarrival_stdev', 'interarrival_min', 'interarrival_max'):
        column = [run[field] for run in runs]
        report[field] = {'auc': auc(column, labels), 'correlation': correlation(column, labels),
                         'benign_median': _median([value for value, code in zip(column, labels, strict=True)
                                                   if code == 0]),
                         'positive_median': _median([value for value, code in zip(column, labels, strict=True)
                                                     if code == 1])}
    overlap = _overlap([run['interarrival_mean'] for run, label in zip(runs, labels, strict=True) if label == 0],
                       [run['interarrival_mean'] for run, label in zip(runs, labels, strict=True) if label == 1])
    fixed = [run['source_group'] for run in runs if run['interarrival_stdev'] is not None
             and run['interarrival_mean'] and run['interarrival_stdev'] / run['interarrival_mean'] < 0.02]
    return {'by_field': report, 'mean_interarrival_range_overlap': overlap,
            'runs_with_near_fixed_spacing': fixed,
            'note': 'both classes deliberately cover fast and slow spacing; overlap is the point'}


def generator_fingerprint(runs):
    """Artefacts that could identify the generator rather than the behaviour."""
    runs = [run for run in runs if run.get('label') in schema.BINARY_CODE]
    lengths = defaultdict(Counter)
    shapes = defaultdict(Counter)
    for run in runs:
        for length in run.get('request_lengths') or ():
            lengths[length][run['label']] += 1
        for shape, count in (run.get('shapes') or {}).items():
            shapes[shape][run['label']] += count
    exclusive_lengths = [length for length, counts in lengths.items()
                         if sum(counts.values()) >= MIN_SUPPORT and len(counts) == 1]
    exclusive_shapes = [shape for shape, counts in shapes.items() if len(counts) == 1]
    source_ports = Counter()
    for run in runs:
        source_ports[run.get('source_port_range', 'ephemeral')] += 1
    if not runs:
        return {'distinct_request_lengths': 0, 'request_lengths_exclusive_to_one_label': [],
                'contact_shapes_exclusive_to_one_label': [], 'source_port_ranges': {},
                'destinations_shared': 0, 'note': 'no labelled runs'}
    return {'distinct_request_lengths': len(lengths),
            'request_lengths_exclusive_to_one_label': sorted(exclusive_lengths),
            'contact_shapes_exclusive_to_one_label': sorted(exclusive_shapes),
            'source_port_ranges': dict(source_ports),
            'destinations_shared': len({address for run in runs for address in (run.get('destinations') or ())}),
            'note': 'shared payload bodies, shared destinations and one ephemeral source port range '
                    'are used by both classes on purpose'}


def _median(values):
    values = sorted(value for value in values if value is not None)
    if not values:
        return None
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2


def _overlap(left, right):
    left = [value for value in left if value is not None]
    right = [value for value in right if value is not None]
    if not left or not right:
        return None
    low = max(min(left), min(right))
    high = min(max(left), max(right))
    if high <= low:
        return 0.0
    span = max(max(left), max(right)) - min(min(left), min(right))
    return (high - low) / span if span else 1.0


def report(samples, runs, matrix=None):
    matrix = matrix if matrix is not None else tensors(samples)
    labelled = [sample for sample in samples if sample.label in schema.BINARY_CODE]
    labelled_matrix = [tensor for sample, tensor in zip(samples, matrix, strict=True)
                       if sample.label in schema.BINARY_CODE]
    separation = feature_separation(labelled, labelled_matrix)
    ports = port_leakage(runs)
    timing = timing_leakage(runs)
    fingerprint = generator_fingerprint(runs)
    sources = source_type_leakage(samples, matrix)
    rate_size = rate_and_size_leakage(runs)
    stamps = timestamp_leakage(samples)
    findings = list(sources['findings']) + list(rate_size['findings']) + list(stamps['findings'])
    if separation['suspicious']:
        findings.append('a single feature separates the classes almost perfectly: ' +
                        ', '.join(row['feature'] for row in separation['suspicious']))
    if ports['exclusive_to_one_label']:
        findings.append('ports used by only one label: ' +
                        ', '.join(str(port) for port in ports['exclusive_to_one_label']))
    if ports['best_single_port_rule_accuracy'] and ports['best_single_port_rule_accuracy'] > .9:
        findings.append('a single-port rule reaches '
                        f"{ports['best_single_port_rule_accuracy']:.2f} run accuracy")
    for field, entry in timing['by_field'].items():
        if entry['auc'] is not None and (entry['auc'] >= NEAR_PERFECT_AUC or entry['auc'] <= 1 - NEAR_PERFECT_AUC):
            findings.append(f'{field} alone separates the classes (AUC {entry["auc"]:.3f})')
    if fingerprint['request_lengths_exclusive_to_one_label']:
        findings.append('payload lengths exclusive to one label: ' +
                        ', '.join(str(v) for v in fingerprint['request_lengths_exclusive_to_one_label'][:8]))
    return {'feature_separation': separation, 'port_leakage': ports, 'timing_leakage': timing,
            'generator_fingerprint': fingerprint, 'source_type_leakage': sources,
            'rate_and_size_leakage': rate_size, 'timestamp_leakage': stamps, 'findings': findings}


def source_type_leakage(samples, matrix=None):
    """Can a feature tell LAB from PCAP from SHADOW - and does source type predict the label?

    The environment must not become a shortcut. If one source contributes only one label, a
    model that learns the environment scores well and detects nothing.
    """
    from . import schema
    matrix = matrix if matrix is not None else tensors(samples)
    per_source = defaultdict(Counter)
    for sample in samples:
        per_source[sample.source_type][sample.label] += 1
    rows = []
    present = sorted({sample.source_type for sample in samples})
    for source in present:
        codes = [1 if sample.source_type == source else 0 for sample in samples]
        best = None
        for name in schema.MODEL_FEATURES:
            position = INPUT_ORDER.index(name)
            column = [tensor[position] for tensor in matrix]
            value = auc(column, codes)
            if value is not None and (best is None or abs(value - .5) > abs(best[1] - .5)):
                best = (name, value)
        counts = per_source[source]
        supervised = {label: counts.get(label, 0) for label in schema.SUPERVISED_LABELS}
        total = sum(supervised.values())
        rows.append({'source_type': source, 'rows': sum(counts.values()),
                     'labels': dict(counts),
                     'label_share': {label: (count / total if total else None)
                                     for label, count in supervised.items()},
                     'single_label_only': total > 0 and min(supervised.values()) == 0,
                     'most_separating_feature': best[0] if best else None,
                     'most_separating_auc': best[1] if best else None})
    supervised_sources = [row for row in rows if sum(row['labels'].get(label, 0)
                                                     for label in schema.SUPERVISED_LABELS)]
    findings = []
    for row in supervised_sources:
        if row['single_label_only']:
            findings.append(f"{row['source_type']} contributes only one label")
        if row['most_separating_auc'] is not None and abs(row['most_separating_auc'] - .5) > .45:
            findings.append(f"{row['source_type']} is almost perfectly identifiable from "
                            f"`{row['most_separating_feature']}` alone "
                            f"(AUC {row['most_separating_auc']:.3f})")
    return {'sources': rows, 'findings': findings,
            'note': ('sources are expected to differ; what matters is that source type does not '
                     'stand in for the label')}


def rate_and_size_leakage(runs):
    """Rate and packet size must overlap between the classes, not separate them."""
    labels = [schema.BINARY_CODE[run['label']] for run in runs if run.get('label') in schema.BINARY_CODE]
    subset = [run for run in runs if run.get('label') in schema.BINARY_CODE]
    report = {}
    for field, accessor in (('contacts_per_second', lambda r: (r.get('contacts') or 0) /
                             max(.001, r.get('duration_seconds') or .001)),
                            ('packets', lambda r: r.get('packets') or 0),
                            ('mean_request_bytes', lambda r: (sum(r.get('request_lengths') or [0]) /
                                                              max(1, len(r.get('request_lengths') or [0])))),
                            ('distinct_request_sizes', lambda r: len(r.get('request_lengths') or []))):
        column = [accessor(run) for run in subset]
        report[field] = {
            'auc': auc(column, labels), 'correlation': correlation(column, labels),
            'benign_median': _median([v for v, code in zip(column, labels, strict=True) if code == 0]),
            'positive_median': _median([v for v, code in zip(column, labels, strict=True) if code == 1]),
            'range_overlap': _overlap([v for v, code in zip(column, labels, strict=True) if code == 0],
                                      [v for v, code in zip(column, labels, strict=True) if code == 1]),
        }
    findings = [f'{field} alone separates the classes (AUC {entry["auc"]:.3f})'
                for field, entry in report.items()
                if entry['auc'] is not None and (entry['auc'] >= NEAR_PERFECT_AUC
                                                 or entry['auc'] <= 1 - NEAR_PERFECT_AUC)]
    return {'by_field': report, 'findings': findings,
            'note': 'both classes deliberately span fast and slow, small and large'}


def timestamp_leakage(samples):
    """Does when a row was produced predict what it is?"""
    supervised = [sample for sample in samples if sample.label in schema.BINARY_CODE]
    if not supervised:
        return {'rows': 0, 'findings': []}
    codes = [schema.BINARY_CODE[sample.label] for sample in supervised]
    epochs = [sample.timestamp.timestamp() for sample in supervised]
    hours = [sample.timestamp.hour + sample.timestamp.minute / 60 for sample in supervised]
    order = list(range(len(supervised)))
    report = {'absolute_time': {'auc': auc(epochs, codes), 'correlation': correlation(epochs, codes)},
              'hour_of_day': {'auc': auc(hours, codes), 'correlation': correlation(hours, codes)},
              'row_order': {'auc': auc(order, codes), 'correlation': correlation(order, codes)}}
    findings = [f'{name} alone separates the classes (AUC {entry["auc"]:.3f})'
                for name, entry in report.items()
                if entry['auc'] is not None and (entry['auc'] >= NEAR_PERFECT_AUC
                                                 or entry['auc'] <= 1 - NEAR_PERFECT_AUC)]
    return {'rows': len(supervised), 'by_field': report, 'findings': findings,
            'note': ('generated corpora share a synthetic clock, so absolute time is expected to '
                     'correlate; it is metadata and never a feature')}
