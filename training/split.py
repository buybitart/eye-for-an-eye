"""Group-aware splitting. Rows of one source sequence never cross a split boundary.

A plain row-level random split would put prefix windows of the same simulated source in
both train and test, which inflates every metric. Splitting by group is the property this
module enforces, and leakage is an exception, not a warning.
"""
from collections import defaultdict
import hashlib

SPLITS = ('train', 'validation', 'test')


class LeakageError(ValueError):
    """Raised when a grouping key appears in more than one split."""


def partition(rows):
    result = {name: [] for name in SPLITS}
    for row in rows:
        if row['split'] not in result:
            raise ValueError('unknown split name')
        result[row['split']].append(row)
    return result


def assert_group_separation(rows, keys=('source_group',)):
    """Fail closed on any grouping key shared between splits."""
    for key in keys:
        seen = defaultdict(set)
        for row in rows:
            seen[row[key]].add(row['split'])
        shared = sorted(group for group, splits in seen.items() if len(splits) > 1)
        if shared:
            raise LeakageError(f'{key} present in multiple splits: ' + ', '.join(shared[:8]))
    return True


def assert_disjoint(left, right, key='source_group'):
    overlap = {row[key] for row in left} & {row[key] for row in right}
    if overlap:
        raise LeakageError(f'{key} intersection is not empty: ' + ', '.join(sorted(overlap)[:8]))
    return True


def _bucket(group, salt, buckets=1000):
    digest = hashlib.sha256(f'{salt}:{group}'.encode()).digest()
    return int.from_bytes(digest[:4], 'big') % buckets


def assign(groups, *, salt, validation=.15, test=.15):
    """Deterministic group assignment for datasets that arrive without a split column.

    Hash-based rather than shuffle-based so the same group always lands in the same split,
    whatever order or subset the caller passes in.
    """
    if not 0 < validation + test < 1:
        raise ValueError('invalid split fractions')
    edges = (round(1000 * (1 - validation - test)), round(1000 * (1 - test)))
    result = {}
    for group in sorted(set(groups)):
        bucket = _bucket(group, salt)
        result[group] = 'train' if bucket < edges[0] else 'validation' if bucket < edges[1] else 'test'
    return result


def chronological_order(rows, key='timestamp'):
    """Report whether held-out rows are later than training rows.

    The synthetic corpus has no shared wall clock across sources, so this is descriptive
    only. A dataset built from one real temporal stream must split chronologically.
    """
    spans = {}
    for name, subset in partition(rows).items():
        times = [row[key] for row in subset]
        spans[name] = {'rows': len(subset), 'min': min(times) if times else None,
                       'max': max(times) if times else None}
    ordered = all(spans[a]['max'] is not None and spans[b]['min'] is not None and spans[a]['max'] <= spans[b]['min']
                  for a, b in (('train', 'validation'), ('validation', 'test')))
    return {'spans': spans, 'chronologically_ordered': ordered,
            'applies': 'only when the dataset comes from a single real temporal stream'}
