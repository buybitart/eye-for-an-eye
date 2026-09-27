"""P9 candidate dataset: a parent dataset plus reviewed rows, with lineage.

A candidate dataset is never built from nothing. It is always *this parent, plus
these new reviewed rows*, and the manifest says exactly which. That is what makes
a bad model traceable back to the data that produced it.

The limits in this module exist for one reason. Reviewed rows come from observed
traffic, and observed traffic is chosen by whoever is sending it. Somebody who
wants to shape the next model will try to fill the new rows with behaviour of
their choosing. Every limit here narrows how much of a candidate dataset any one
source, one group or one day can be responsible for.

None of this trains anything. It writes a dataset and a report.
"""
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from eye_for_an_eye.decision.review_queue import vector_from_payload
from . import provenance as provenance_module
from . import schema

CANDIDATE_SCHEMA_VERSION = 1

#: A reviewed answer becomes a dataset label. The names differ on purpose: the
#: queue speaks about what a person saw, the dataset speaks about what a row is.
LABEL_FROM_REVIEW = {'benign_like': schema.BENIGN,
                     'malicious_automation_like': schema.MALICIOUS,
                     'uncertain': schema.UNCERTAIN}


class CandidateError(Exception):
    """A candidate dataset was refused. Refusing is the safe outcome."""


@dataclass(frozen=True)
class IntakeLimits:
    """How much of a candidate dataset new observed rows may account for.

    Defaults are conservative on purpose. It is easy to raise a limit after
    watching a few cycles; it is not easy to notice a poisoned dataset later.
    """

    #: Rows one pseudonymous source may contribute.
    per_source: int = 25
    #: Rows one review day may contribute.
    per_day: int = 200
    #: Total new rows in one candidate dataset.
    max_new_rows: int = 1000
    #: Share of the whole candidate dataset that may be new observed rows.
    max_new_fraction: float = 0.25
    #: Share of the new rows that any single source may account for.
    max_single_source_fraction: float = 0.10
    #: Distinct sources the new rows must come from.
    min_distinct_sources: int = 10
    #: New rows of each supervised label needed before the batch is worth using.
    min_per_label: int = 20

    def __post_init__(self):
        if not 1 <= self.per_source <= 100_000:
            raise CandidateError('per_source is out of range')
        if not 1 <= self.per_day <= 100_000:
            raise CandidateError('per_day is out of range')
        if not 1 <= self.max_new_rows <= 1_000_000:
            raise CandidateError('max_new_rows is out of range')
        if not 0 < self.max_new_fraction <= 1.0:
            raise CandidateError('max_new_fraction is out of range')
        if not 0 < self.max_single_source_fraction <= 1.0:
            raise CandidateError('max_single_source_fraction is out of range')
        if self.min_distinct_sources < 1:
            raise CandidateError('min_distinct_sources is out of range')
        if self.min_per_label < 0:
            raise CandidateError('min_per_label is out of range')

    def explain(self):
        return {'per_source': self.per_source, 'per_day': self.per_day,
                'max_new_rows': self.max_new_rows, 'max_new_fraction': self.max_new_fraction,
                'max_single_source_fraction': self.max_single_source_fraction,
                'min_distinct_sources': self.min_distinct_sources,
                'min_per_label': self.min_per_label}


@dataclass
class IntakeReport:
    """What was accepted, what was dropped, and why. Written beside the dataset."""

    accepted: int = 0
    dropped: Counter = field(default_factory=Counter)
    distinct_sources: int = 0
    largest_source_rows: int = 0
    per_label: Counter = field(default_factory=Counter)
    warnings: list = field(default_factory=list)

    def explain(self):
        return {'accepted': self.accepted, 'dropped': dict(self.dropped),
                'distinct_sources': self.distinct_sources,
                'largest_source_rows': self.largest_source_rows,
                'per_label': dict(self.per_label), 'warnings': list(self.warnings)}


def _stamp(value=None):
    moment = value or datetime.now(timezone.utc)
    return moment.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _row_digest(vector):
    """A stable fingerprint of a row's features, for exact-duplicate removal."""
    coarse = '|'.join('na' if value is None else f'{float(value):.6g}' for value in vector.values)
    return hashlib.sha256(coarse.encode()).hexdigest()[:24]


def read_review_export(path):
    """Load rows a person answered. Refuses anything that is not a review export."""
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    if document.get('review_export_version') != 1:
        raise CandidateError('this file is not a review export')
    rows = document.get('samples')
    if not isinstance(rows, list):
        raise CandidateError('the review export has no rows')
    return rows


def _sample_from_review(row, *, dataset_version, sensor_placement):
    """One answered review row, as a dataset sample. Raises if it is not usable."""
    label_name = row.get('label')
    if label_name not in LABEL_FROM_REVIEW:
        raise CandidateError(f'unknown review label: {label_name!r}')
    if row.get('label_source') != 'manual_review':
        raise CandidateError('only a manual review may label an observed row')
    label = LABEL_FROM_REVIEW[label_name]
    confidence = row.get('label_confidence') if row.get('label_confidence') in ('MEDIUM', 'LOW') else 'MEDIUM'
    if label == schema.UNCERTAIN:
        confidence = 'LOW'
    group = row.get('source_group')
    if not isinstance(group, str) or not group:
        raise CandidateError('an observed row needs a source group')
    vector = vector_from_payload(row.get('features') or {})
    review = {'decision': label, 'confidence': confidence,
              'reason': str(row.get('reviewer_note', ''))[:500],
              'reviewed_at': row.get('reviewed_at') or _stamp()}
    return schema.DatasetSample(
        dataset_version=dataset_version,
        feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
        sample_id=str(row.get('entry_id'))[:200],
        timestamp=datetime.fromisoformat(str(row['observed_at']).replace('Z', '+00:00')),
        source_type=schema.SHADOW_REVIEWED,
        scenario_group=None, source_group=group, capture_group=None,
        label=label, label_source='manual_review', label_confidence=confidence,
        features=vector,
        provenance=provenance_module.shadow(
            sensor_placement=sensor_placement,
            collected_at=str(row.get('observed_at')),
            reviewed=True, review=review))


def admit(rows, *, dataset_version, sensor_placement, limits=None, parent_rows=0,
          existing_digests=()):
    """Apply every intake limit to reviewed rows. Returns `(samples, report)`.

    Order matters. Cheap structural refusals come first, then per-source and
    per-day caps, then the whole-batch shape checks. A row dropped by any of them
    is counted with its reason so the report explains itself.
    """
    limits = limits or IntakeLimits()
    report = IntakeReport()
    seen = set(existing_digests)
    per_source = Counter()
    per_day = Counter()
    accepted = []

    for row in rows:
        try:
            sample = _sample_from_review(row, dataset_version=dataset_version,
                                         sensor_placement=sensor_placement)
        except (CandidateError, KeyError, TypeError, ValueError):
            report.dropped['unusable_row'] += 1
            continue

        if sample.label == schema.UNCERTAIN:
            # A real answer, and the right one when evidence is thin. It is kept
            # out of supervised training rather than turned into a guess.
            report.dropped['uncertain_not_supervised'] += 1
            continue

        digest = _row_digest(sample.features)
        if digest in seen:
            report.dropped['duplicate_behaviour'] += 1
            continue

        group = sample.source_group
        if per_source[group] >= limits.per_source:
            report.dropped['per_source_limit'] += 1
            continue

        day = sample.timestamp.date().isoformat()
        if per_day[day] >= limits.per_day:
            report.dropped['per_day_limit'] += 1
            continue

        if len(accepted) >= limits.max_new_rows:
            report.dropped['batch_limit'] += 1
            continue

        seen.add(digest)
        per_source[group] += 1
        per_day[day] += 1
        accepted.append(sample)

    # Whole-batch shape. A source that is a large share of the new rows is
    # trimmed back, because a dataset should not be mostly one point of view.
    if accepted:
        cap = max(1, int(len(accepted) * limits.max_single_source_fraction))
        trimmed, kept_per_source = [], Counter()
        for sample in accepted:
            if kept_per_source[sample.source_group] >= cap:
                report.dropped['single_source_share'] += 1
                continue
            kept_per_source[sample.source_group] += 1
            trimmed.append(sample)
        accepted = trimmed

    report.accepted = len(accepted)
    report.per_label = Counter(sample.label for sample in accepted)
    sources = Counter(sample.source_group for sample in accepted)
    report.distinct_sources = len(sources)
    report.largest_source_rows = max(sources.values()) if sources else 0

    total = parent_rows + len(accepted)
    if total and len(accepted) / total > limits.max_new_fraction:
        report.warnings.append(
            f'new rows are {len(accepted) / total:.0%} of the candidate dataset, above the '
            f'{limits.max_new_fraction:.0%} limit')
    if report.distinct_sources < limits.min_distinct_sources:
        report.warnings.append(
            f'new rows come from {report.distinct_sources} sources, '
            f'{limits.min_distinct_sources} needed')
    for label in schema.SUPERVISED_LABELS:
        if report.per_label[label] < limits.min_per_label:
            report.warnings.append(
                f'only {report.per_label[label]} new {label} rows, {limits.min_per_label} needed')
    return accepted, report


@dataclass(frozen=True)
class Lineage:
    """Where a candidate dataset came from. Written into its manifest."""

    dataset_version: str
    parent_dataset: str
    parent_rows: int
    parent_digest: str
    new_reviewed_samples: int
    new_benign_samples: int
    new_malicious_samples: int
    new_distinct_sources: int
    built_at: str

    def explain(self):
        return {'candidate_schema_version': CANDIDATE_SCHEMA_VERSION,
                'dataset_version': self.dataset_version,
                'parent_dataset': self.parent_dataset,
                'parent_rows': self.parent_rows,
                'parent_digest': self.parent_digest,
                'new_reviewed_samples': self.new_reviewed_samples,
                'new_benign_samples': self.new_benign_samples,
                'new_malicious_samples': self.new_malicious_samples,
                'new_distinct_sources': self.new_distinct_sources,
                'built_at': self.built_at,
                'label_origin': ('parent rows keep their original label source; new rows are '
                                 'labelled only by a person answering a review entry')}


def quality_gate(samples, report, *, limits=None, minimum_rows=500):
    """Is this candidate dataset worth training on? Returns `(status, reasons)`.

    `FAIL` means do not train. `PASS_WITH_WARNINGS` means a person should read
    the reasons first. Nothing here promotes, trains or deletes anything.
    """
    limits = limits or IntakeLimits()
    reasons, blocking = [], []
    counts = Counter(sample.label for sample in samples)
    supervised = sum(counts[label] for label in schema.SUPERVISED_LABELS)

    if supervised < minimum_rows:
        blocking.append(f'{supervised} supervised rows, {minimum_rows} needed')
    for label in schema.SUPERVISED_LABELS:
        if counts[label] == 0:
            blocking.append(f'no {label} rows at all')
    if supervised:
        share = min(counts[label] for label in schema.SUPERVISED_LABELS) / supervised
        if share < 0.10:
            blocking.append(f'the smaller class is {share:.0%} of the data, below 10%')
        elif share < 0.25:
            reasons.append(f'the smaller class is {share:.0%} of the data')

    groups = Counter(provenance_module.group_value(sample) for sample in samples)
    if groups:
        largest = max(groups.values()) / len(samples)
        if largest > 0.25:
            blocking.append(f'one group is {largest:.0%} of the dataset')
        elif largest > 0.10:
            reasons.append(f'one group is {largest:.0%} of the dataset')

    kinds = {sample.source_type for sample in samples}
    if len(kinds) < 2:
        reasons.append('every row comes from one kind of source')

    reasons.extend(report.warnings)
    if blocking:
        return 'FAIL', tuple(blocking + reasons)
    return ('PASS_WITH_WARNINGS', tuple(reasons)) if reasons else ('PASS', ())


def build(*, parent_samples, parent_dataset, review_rows, dataset_version, sensor_placement,
          limits=None, minimum_rows=500):
    """Parent dataset + reviewed rows -> candidate dataset, lineage and report.

    This function writes nothing and starts nothing. It returns what a candidate
    dataset would be, so a person can look at the report before anything else
    happens.
    """
    if not dataset_version or not isinstance(dataset_version, str):
        raise CandidateError('a candidate dataset needs a version identifier')
    if dataset_version == parent_dataset:
        raise CandidateError('a candidate dataset needs its own version, not the parent one')
    parent_samples = list(parent_samples)
    existing = {_row_digest(sample.features) for sample in parent_samples}

    accepted, report = admit(review_rows, dataset_version=dataset_version,
                             sensor_placement=sensor_placement, limits=limits,
                             parent_rows=len(parent_samples), existing_digests=existing)

    combined = parent_samples + accepted
    counts = Counter(sample.label for sample in accepted)
    lineage = Lineage(
        dataset_version=dataset_version, parent_dataset=parent_dataset,
        parent_rows=len(parent_samples),
        parent_digest=hashlib.sha256(
            '|'.join(sorted(existing)).encode()).hexdigest()[:24] if existing else '',
        new_reviewed_samples=len(accepted),
        new_benign_samples=counts[schema.BENIGN],
        new_malicious_samples=counts[schema.MALICIOUS],
        new_distinct_sources=report.distinct_sources,
        built_at=_stamp())
    status, reasons = quality_gate(combined, report, limits=limits, minimum_rows=minimum_rows)
    return {'samples': combined, 'new_samples': accepted, 'lineage': lineage,
            'intake': report, 'quality_gate': status, 'quality_reasons': reasons,
            'limits': (limits or IntakeLimits()).explain()}


def write_report(result, path):
    """The human-readable record of what a candidate dataset is made of."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    document = {'candidate_schema_version': CANDIDATE_SCHEMA_VERSION,
                'lineage': result['lineage'].explain(),
                'intake': result['intake'].explain(),
                'limits': result['limits'],
                'quality_gate': result['quality_gate'],
                'quality_reasons': list(result['quality_reasons']),
                'total_rows': len(result['samples']),
                'authority': ('this file describes a dataset; it does not train a model and '
                              'cannot promote one')}
    target.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return {'file': str(target), 'quality_gate': result['quality_gate']}
