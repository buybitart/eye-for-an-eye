"""Duplicate analysis. A repeated row is a nuisance; a contradicted row is a defect."""
from collections import Counter, defaultdict
from eye_for_an_eye.decision.features import FeatureTransformer
from .schema import SUPERVISED_LABELS

NEAR_DUPLICATE_DECIMALS = 3


def tensors(samples):
    return [FeatureTransformer.transform(sample.features) for sample in samples]


def analyse(samples, matrix=None, *, decimals=NEAR_DUPLICATE_DECIMALS):
    matrix = matrix if matrix is not None else tensors(samples)
    exact, near = Counter(), Counter()
    labels_by_vector = defaultdict(set)
    scenarios_by_vector = defaultdict(set)
    identifiers = Counter(sample.sample_id for sample in samples)
    for sample, tensor in zip(samples, matrix, strict=True):
        key = tuple(tensor)
        rounded = tuple(round(value, decimals) for value in tensor)
        exact[key] += 1
        near[rounded] += 1
        # Only supervised labels can contradict each other. An unlabelled row asserts nothing.
        if sample.label in SUPERVISED_LABELS:
            labels_by_vector[key].add(sample.label)
        scenarios_by_vector[key].add(sample.scenario_id)
    conflicting = [{'labels': sorted(labels), 'scenarios': sorted(scenarios_by_vector[key]),
                    'occurrences': exact[key]}
                   for key, labels in labels_by_vector.items() if len(labels) > 1]
    return {
        'rows': len(samples),
        'distinct_exact_vectors': len(exact),
        'exact_duplicate_rows': sum(count - 1 for count in exact.values()),
        'distinct_near_vectors': len(near),
        'near_duplicate_rows': sum(count - 1 for count in near.values()),
        'near_duplicate_decimals': decimals,
        'duplicate_sample_ids': sorted(name for name, count in identifiers.items() if count > 1),
        'conflicting_label_vectors': len(conflicting),
        'conflicting_examples': conflicting[:8],
        'most_repeated_vector_occurrences': max(exact.values(), default=0),
    }


def cross_split(samples, matrix=None, *, decimals=NEAR_DUPLICATE_DECIMALS):
    """Which identical or nearly identical vectors appear on both sides of a split."""
    matrix = matrix if matrix is not None else tensors(samples)
    exact, near = defaultdict(set), defaultdict(set)
    for sample, tensor in zip(samples, matrix, strict=True):
        split = sample.split or 'unassigned'
        exact[tuple(tensor)].add(split)
        near[tuple(round(value, decimals) for value in tensor)].add(split)

    def crossing(mapping):
        return sum(1 for splits in mapping.values()
                   if {'train', 'test'} <= splits or {'train', 'validation'} <= splits)
    return {'exact_vectors_crossing_train_boundary': crossing(exact),
            'near_vectors_crossing_train_boundary': crossing(near)}


def cross_source(samples, matrix=None):
    """Identical feature vectors appearing under more than one source type.

    This happens when the same lab capture enters the pipeline twice under two names. It is a
    leakage risk before it is a duplication problem, because the two copies can land on
    opposite sides of a split.
    """
    matrix = matrix if matrix is not None else tensors(samples)
    by_vector = defaultdict(lambda: {'sources': set(), 'groups': set(), 'labels': set(), 'rows': []})
    for sample, tensor in zip(samples, matrix, strict=True):
        entry = by_vector[tuple(tensor)]
        entry['sources'].add(sample.source_type)
        entry['groups'].add(f'{sample.source_type}:{sample.group}')
        if sample.label in SUPERVISED_LABELS:
            entry['labels'].add(sample.label)
        entry['rows'].append(sample.sample_id)
    shared = [entry for entry in by_vector.values() if len(entry['sources']) > 1]
    conflicting = [entry for entry in shared if len(entry['labels']) > 1]
    return {
        'vectors_in_multiple_sources': len(shared),
        'rows_involved': sum(len(entry['rows']) for entry in shared),
        'source_pairs': sorted({' + '.join(sorted(entry['sources'])) for entry in shared}),
        'with_conflicting_labels': len(conflicting),
        'examples': [{'sources': sorted(entry['sources']), 'groups': sorted(entry['groups'])[:4],
                      'labels': sorted(entry['labels']), 'rows': entry['rows'][:3]}
                     for entry in shared[:6]],
    }
