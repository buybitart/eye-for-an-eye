"""Deterministic group split across three sources, with deliberate holdouts and a frozen test set.

Two rules. Correlated rows never cross a split - which key keeps them together depends on the
source: a LAB run, a whole PCAP capture, a pseudonymous shadow source. And some scenario
families are never trained on at all, because a split that only holds out unseen runs of
familiar behaviour flatters a model that has memorised the families it saw.

Unreviewed shadow telemetry is not split at all. It has no label, so it belongs to the
unlabelled pool and to nothing else.
"""
from collections import Counter, defaultdict
import hashlib
from . import schema

SPLITS = ('train', 'validation', 'test')
DEFAULT_SALT = 'dataset-v1'
DEFAULT_FRACTIONS = (0.70, 0.15, 0.15)
MIN_SOURCES_FOR_FULL_COVERAGE = 5

# Whole families withheld from training. Test holds hard positives and hard negatives the model
# never saw; validation holds one of each so selection is not blind to unseen behaviour either.
HOLDOUT = {
    'scan-slow': ('test', 'unseen hard positive: quiet, patient scanning'),
    'credential-low-rate': ('test', 'unseen hard positive: credential attempts under a rate threshold'),
    'hard-negative-health-check': ('test', 'unseen hard negative: high-rate periodic health checking'),
    'hard-negative-admin': ('test', 'unseen hard negative: an administrator probing several services'),
    'scan-burst': ('validation', 'unseen hard positive during selection: burst and pause'),
    'hard-negative-discovery': ('validation', 'unseen hard negative during selection: service discovery'),
    # P15.3. New compositions of existing primitives, withheld from training
    # entirely and present only in the locked generalisation benchmark. These
    # families did not exist when the MathRisk v2 weights were chosen, so no
    # feature, weight, calibrator or gate was fitted against them.
    'composite-paced-breadth': ('test', 'unseen composition: slow pacing + port breadth + address breadth'),
    'composite-credential-spray': ('test', 'unseen composition: credential shapes spread across addresses'),
    'composite-decoy-recon': ('test', 'unseen composition: decoy contact followed by service enumeration'),
    'hard-negative-backup': ('test', 'unseen hard negative: sustained volume, one service, everything completed'),
    'hard-negative-crawler': ('test', 'unseen hard negative: a polite crawler across several addresses'),
    'hard-negative-batch-api': ('test', 'unseen hard negative: authenticated batch jobs in bursts'),
    # P15.4. The two families withheld from every fitting corpus. The matrix
    # check in `tests/test_p15_4_withheld.py` is the primary guard and keeps
    # them out of a development or calibration corpus altogether; these entries
    # are the second one, for the case where they reach a corpus that is also
    # trained on. Belt and braces, because getting this wrong produces a
    # generalisation number that is quietly meaningless rather than obviously
    # broken.
    'withheld-mobile-sync': ('test', 'withheld hard negative: an app waking, retrying and syncing'),
    'withheld-probe-login': ('test', 'withheld hard positive: a small sweep, then a few refusals'),
    # P15.4, and for the reason `credential-low-rate` and `hard-negative-health-check`
    # are already here: the hardest case of a new evidence type belongs on the
    # far side of the split, or the claim that the system handles it is a claim
    # about memorisation. These two are the authentication pair at its most
    # ambiguous -- a patient walk with no rate at all, and a legitimate service
    # account that does genuinely fail.
    'positive-api-patient-walk': ('test', 'unseen hard positive: refusals across accounts, minutes apart'),
    'profile-api-service-account': ('test', 'unseen hard negative: a service account whose token expires'),
    'profile-api-stale-credential': ('test', 'unseen hard negative: a job retrying an old password'),
}
# Whole captures withheld, so a held-out capture is judged as a capture and not as a window.
CAPTURE_HOLDOUT = {
    'pcap-fixture-scan': ('test', 'pre-existing project capture, never trained on'),
    'pcap-realism-slow-probe': ('test', 'held-out capture with unseen packet timing'),
    'pcap-realism-retransmit': ('validation', 'held-out capture exercising retransmission'),
}


class LeakageError(ValueError):
    """Raised when a grouping key would appear in more than one split."""


def _bucket(key, salt, buckets=1000):
    digest = hashlib.sha256(f'{salt}:{key}'.encode()).digest()
    return int.from_bytes(digest[:4], 'big') % buckets


def supervised(samples):
    """Rows eligible for a supervised split: a real label from an independent source."""
    return [sample for sample in samples if sample.supervised]


def assign(samples, *, salt=DEFAULT_SALT, fractions=DEFAULT_FRACTIONS, holdout=None,
           capture_holdout=None):
    """Return {(source_type, group): split} over supervised rows only."""
    holdout = HOLDOUT if holdout is None else holdout
    capture_holdout = CAPTURE_HOLDOUT if capture_holdout is None else capture_holdout
    if abs(sum(fractions) - 1) > 1e-9 or any(value <= 0 for value in fractions):
        raise ValueError('invalid split fractions')
    edges = (round(1000 * fractions[0]), round(1000 * (fractions[0] + fractions[1])))
    families = defaultdict(set)
    for sample in supervised(samples):
        family = sample.capture_group if sample.source_type == schema.PCAP else sample.scenario_group
        families[(sample.source_type, family)].add(sample.group)
    assignment = {}
    for (source_type, family), groups in sorted(families.items(), key=lambda item: str(item[0])):
        table = capture_holdout if source_type == schema.PCAP else holdout
        if family in table:
            target = table[family][0]
            assignment.update({(source_type, group): target for group in sorted(groups)})
            continue
        ordered = sorted(groups)
        for group in ordered:
            bucket = _bucket(f'{source_type}|{family}|{group}', salt)
            assignment[(source_type, group)] = ('train' if bucket < edges[0]
                                                else 'validation' if bucket < edges[1] else 'test')
        # A family with enough independent groups should be visible in every split, so no split
        # ends up representing only the withheld families.
        for target in SPLITS:
            counts = Counter(assignment[(source_type, group)] for group in ordered)
            if counts.get(target) or len(ordered) < MIN_SOURCES_FOR_FULL_COVERAGE:
                continue
            donor = counts.most_common(1)[0][0]
            if counts[donor] < 2:
                continue
            moved = next(group for group in ordered if assignment[(source_type, group)] == donor)
            assignment[(source_type, moved)] = target
    return assignment


def apply(samples, assignment):
    """Stamp the split. Unlabelled rows are left unassigned on purpose."""
    for sample in samples:
        if not sample.supervised:
            sample.split = None
            continue
        key = (sample.source_type, sample.group)
        if key not in assignment:
            raise ValueError('sample has no split assignment: ' + str(key))
        sample.split = assignment[key]
    return samples


def partition(samples):
    parts = {name: [] for name in SPLITS}
    for sample in samples:
        if sample.split is None:
            continue
        if sample.split not in parts:
            raise ValueError('sample carries no valid split')
        parts[sample.split].append(sample)
    return parts


def assert_no_leakage(samples):
    """Fail closed on any grouping key shared between splits, per source type."""
    seen = defaultdict(set)
    for sample in samples:
        if sample.split is None:
            continue
        seen[(sample.source_type, sample.group)].add(sample.split)
    shared = sorted((f'{source}:{group}' for (source, group), splits in seen.items() if len(splits) > 1))
    if shared:
        raise LeakageError('grouping keys present in multiple splits: ' + ', '.join(shared[:6]))
    unlabelled = [sample.sample_id for sample in samples
                  if sample.source_type == schema.SHADOW_UNLABELED and sample.split]
    if unlabelled:
        raise LeakageError('unreviewed shadow telemetry entered a supervised split')
    return True


def describe(samples, assignment):
    parts = partition(samples)
    families = defaultdict(lambda: defaultdict(int))
    sources = defaultdict(lambda: defaultdict(int))
    for sample in samples:
        if sample.split is None:
            continue
        family = sample.capture_group if sample.source_type == schema.PCAP else sample.scenario_group
        families[family or sample.source_type][sample.split] += 1
        sources[sample.source_type][sample.split] += 1
    return {
        'policy': ('correlated rows never cross a split: LAB groups by scenario run, PCAP by whole '
                   'capture, reviewed shadow by pseudonymous source. Listed scenario families and '
                   'whole captures are withheld from training entirely; the rest are bucketed by '
                   'group so every split keeps representative data. Unreviewed shadow telemetry is '
                   'never split.'),
        'salt': DEFAULT_SALT,
        'grouping_rules': {source: key for source, key in schema.GROUP_KEY.items()},
        'holdout': {family: {'split': target, 'reason': reason}
                    for family, (target, reason) in HOLDOUT.items()},
        'capture_holdout': {name: {'split': target, 'reason': reason}
                            for name, (target, reason) in CAPTURE_HOLDOUT.items()},
        'groups': {name: len({sample.group for sample in rows}) for name, rows in parts.items()},
        'samples': {name: len(rows) for name, rows in parts.items()},
        'labels': {name: {label: sum(1 for sample in rows if sample.label == label)
                          for label in schema.SUPERVISED_LABELS} for name, rows in parts.items()},
        'sources': {source: dict(counts) for source, counts in sorted(sources.items())},
        'families': {family: dict(counts) for family, counts in sorted(families.items())},
        'unseen_families_in_test': sorted(f for f, (t, _) in HOLDOUT.items() if t == 'test'),
        'unseen_captures_in_test': sorted(c for c, (t, _) in CAPTURE_HOLDOUT.items() if t == 'test'),
        'excluded_from_splits': sum(1 for sample in samples if sample.split is None),
        'assignment_size': len(assignment),
    }
