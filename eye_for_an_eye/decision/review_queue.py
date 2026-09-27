"""P9 review queue: the only place a training label can come from is a person.

A decision is not a label. When the sensor cannot settle something by itself it
puts a short behaviour summary here, bounded and expiring, so a person can look
at it later. This module never writes a label, never changes a firewall, and
never sends anything anywhere.

Three rules hold the whole design together:

* An entry is admitted because the evidence is *unclear*, not because the risk
  was high. "The system blocked it" is not a reason to review it, and would turn
  the model's own output back into its next training target.
* Every limit is a hard limit. One source cannot fill the queue, one day cannot
  fill the queue, and the queue cannot grow without bound. An attacker who can
  make the sensor unsure still cannot choose what the next dataset looks like.
* The queue holds behaviour numbers only. No payload, no address, no credential,
  no header. A source is grouped by a keyed digest so a reviewer can see the same
  source twice without the file carrying who it was.
"""
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path

from .features import NAMES

REVIEW_QUEUE_VERSION = 1

UNREVIEWED = 'UNREVIEWED'
BENIGN_LIKE = 'BENIGN_LIKE'
MALICIOUS_AUTOMATION_LIKE = 'MALICIOUS_AUTOMATION_LIKE'
UNCERTAIN = 'UNCERTAIN'
IGNORE = 'IGNORE'

STATES = (UNREVIEWED, BENIGN_LIKE, MALICIOUS_AUTOMATION_LIKE, UNCERTAIN, IGNORE)
ANSWERS = (BENIGN_LIKE, MALICIOUS_AUTOMATION_LIKE, UNCERTAIN, IGNORE)

#: A reviewed answer maps to a dataset label. `IGNORE` maps to nothing on purpose:
#: it means "not worth a person's time", not "benign".
LABEL_FOR_ANSWER = {BENIGN_LIKE: 'benign_like',
                    MALICIOUS_AUTOMATION_LIKE: 'malicious_automation_like',
                    UNCERTAIN: 'uncertain'}

#: Behaviour shown to a reviewer. These are the model's own inputs, so a person
#: judges the same evidence the system judged.
SUMMARY_FEATURES = ('connections_60s', 'connections_900s', 'ports_60s', 'ports_900s',
                    'destinations_60s', 'families_60s', 'repetition_60s', 'sequential_60s',
                    'anomaly_60s', 'credentials_60s', 'continuation_60s', 'persistence_900s',
                    'burst_10s', 'interarrival_mean_60s', 'interarrival_cv_60s', 'deception_60s')

MAX_NOTE_CHARS = 500
MAX_REASONS = 6


class ReviewQueueError(Exception):
    """The queue refused something. Never raised for an ordinary full queue."""


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment):
    return moment.isoformat().replace('+00:00', 'Z')


def _parse(text):
    try:
        parsed = datetime.fromisoformat(str(text).replace('Z', '+00:00'))
    except ValueError as exc:
        raise ReviewQueueError('invalid timestamp in review queue') from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def source_key(secret, source):
    """Group one source across time without keeping its address.

    Truncated keyed digest. Enough to count how much of the queue one source is
    using, not enough to recover the source from the file. This value is a queue
    accounting key and an aid to a human reviewer. It is never a model feature.
    """
    if not secret:
        raise ReviewQueueError('a review queue needs a local secret to group sources')
    return 'src-' + hmac.new(secret, str(source).encode()[:512], hashlib.sha256).hexdigest()[:16]


def behaviour_signature(behaviour):
    """Coarse fingerprint of a behaviour shape, used only to drop near-duplicates.

    Values are rounded hard before hashing. Two windows that look the same to a
    reviewer collapse into one entry, so a source repeating itself cannot buy
    extra room in the queue by varying the fourth decimal place.
    """
    coarse = []
    for name in SUMMARY_FEATURES:
        value = behaviour.get(name)
        coarse.append('na' if value is None else str(round(float(value) * 20) / 20))
    return hashlib.sha256('|'.join(coarse).encode()).hexdigest()[:20]


@dataclass(frozen=True)
class QueueLimits:
    """Hard bounds. Every one of these is a refusal, never a warning."""

    max_entries: int = 2000
    per_source_entries: int = 20
    per_day_entries: int = 500
    ttl_days: int = 30
    min_observations: int = 5

    def __post_init__(self):
        if not 1 <= self.max_entries <= 100_000:
            raise ReviewQueueError('max_entries is out of range')
        if not 1 <= self.per_source_entries <= self.max_entries:
            raise ReviewQueueError('per_source_entries is out of range')
        if not 1 <= self.per_day_entries <= 100_000:
            raise ReviewQueueError('per_day_entries is out of range')
        if not 1 <= self.ttl_days <= 365:
            raise ReviewQueueError('ttl_days is out of range')
        if not 0 <= self.min_observations <= 1000:
            raise ReviewQueueError('min_observations is out of range')

    def explain(self):
        return {'max_entries': self.max_entries, 'per_source_entries': self.per_source_entries,
                'per_day_entries': self.per_day_entries, 'ttl_days': self.ttl_days,
                'min_observations': self.min_observations}


@dataclass
class ReviewEntry:
    """One window of behaviour waiting for a person.

    `state` starts at UNREVIEWED and only a person's answer moves it. Nothing in
    the running system writes to `state`.
    """

    entry_id: str
    signature: str
    source_key: str
    created_at: str
    expires_at: str
    priority: float
    reasons: tuple
    behaviour: dict
    evidence: dict
    #: The complete feature vector, kept so an answered entry can become a
    #: training row without needing the original traffic again. `behaviour` above
    #: is the shorter view a reviewer reads; this is what the model would see.
    features: dict = field(default_factory=dict)
    analysis_only: dict = field(default_factory=dict)
    state: str = UNREVIEWED
    occurrences: int = 1
    last_seen_at: str = ''
    reviewed_at: str = ''
    reviewer_note: str = ''
    confidence: str = ''

    def to_row(self):
        return {'entry_id': self.entry_id, 'signature': self.signature,
                'source_key': self.source_key, 'created_at': self.created_at,
                'expires_at': self.expires_at, 'priority': round(self.priority, 4),
                'reasons': list(self.reasons), 'behaviour': self.behaviour,
                'evidence': self.evidence, 'features': self.features,
                'analysis_only': self.analysis_only,
                'state': self.state, 'occurrences': self.occurrences,
                'last_seen_at': self.last_seen_at or self.created_at,
                'reviewed_at': self.reviewed_at, 'reviewer_note': self.reviewer_note,
                'confidence': self.confidence}

    @classmethod
    def from_row(cls, row):
        if row.get('state') not in STATES:
            raise ReviewQueueError('unknown review state in queue file')
        return cls(entry_id=str(row['entry_id']), signature=str(row['signature']),
                   source_key=str(row['source_key']), created_at=str(row['created_at']),
                   expires_at=str(row['expires_at']), priority=float(row.get('priority', 0.0)),
                   reasons=tuple(str(item)[:200] for item in row.get('reasons', ())[:MAX_REASONS]),
                   behaviour=dict(row.get('behaviour') or {}),
                   evidence=dict(row.get('evidence') or {}),
                   features=dict(row.get('features') or {}),
                   analysis_only=dict(row.get('analysis_only') or {}),
                   state=row['state'], occurrences=int(row.get('occurrences', 1)),
                   last_seen_at=str(row.get('last_seen_at', '')),
                   reviewed_at=str(row.get('reviewed_at', '')),
                   reviewer_note=str(row.get('reviewer_note', ''))[:MAX_NOTE_CHARS],
                   confidence=str(row.get('confidence', '')))


def admission(*, math_score=None, model_score=None, fused_risk=None, acted=False,
              ood_score=None, ood_band='', anomaly_score=None, observations=0,
              disagreement_gap=0.4, uncertain_band=(0.30, 0.80), challenge=None):
    """Why this window is worth a person's time, and how much.

    Only *uncertainty* earns a place in the queue. A confident, acted-on decision
    is deliberately not a reason: reviewing what the system already blocked is
    how a model ends up being trained on its own opinion.

    `challenge` is the `(priority, reasons)` pair from the P11 challenge layer's
    own assessment (§44). It is added here rather than computed here, so that the
    challenge subsystem keeps its own reasoning and this function keeps its single
    job: deciding what a person should look at. Note what it cannot do — it adds
    priority and reasons, and nothing else. A challenge outcome still cannot
    become a label, because the only thing that writes a label is a person
    answering an entry.

    Returns `(priority, reasons)`. A priority of zero means "do not queue".
    """
    reasons, priority = [], 0.0
    low, high = uncertain_band

    if challenge:
        challenge_priority, challenge_reasons = challenge
        if challenge_priority and float(challenge_priority) > 0:
            priority += float(challenge_priority)
            reasons.extend(challenge_reasons)

    if math_score is not None and model_score is not None:
        gap = abs(float(math_score) - float(model_score))
        if gap >= disagreement_gap:
            priority += 2.0 * gap
            reasons.append(f'the mathematical engine and the model disagree by {gap:.2f}')

    if fused_risk is not None and low <= float(fused_risk) <= high:
        priority += 1.0
        reasons.append('the risk landed in the middle, where the evidence does not settle it')

    if fused_risk is not None and float(fused_risk) >= high and not acted:
        priority += 0.75
        reasons.append('high risk that the policy did not act on')

    if ood_score is not None and float(ood_score) >= 0.35:
        priority += min(1.5, float(ood_score) * 1.5)
        reasons.append(f'behaviour is outside the training distribution ({ood_band or "outer band"})')

    if anomaly_score is not None and float(anomaly_score) >= 0.6:
        priority += 0.5
        reasons.append('the anomaly model finds this unusual, which is not the same as bad')

    if observations and observations < 5:
        priority -= 0.5
        reasons.append('very little evidence in this window')

    if priority <= 0:
        return 0.0, ()
    return round(priority, 4), tuple(reasons[:MAX_REASONS])


class ReviewQueue:
    """Bounded, expiring, on-disk queue of behaviour awaiting human review.

    The file is rewritten atomically. A crash leaves either the old queue or the
    new one, never half of either.
    """

    def __init__(self, path, *, secret=None, limits=None, clock=_now):
        self.path = Path(path)
        self.limits = limits or QueueLimits()
        self.secret = secret
        self._clock = clock

    # --- reading -------------------------------------------------------

    def _load(self):
        if not self.path.is_file():
            return []
        try:
            document = json.loads(self.path.read_text(encoding='utf-8'))
        except ValueError as exc:
            raise ReviewQueueError('the review queue file is not valid JSON') from exc
        if document.get('review_queue_version') != REVIEW_QUEUE_VERSION:
            raise ReviewQueueError('unsupported review queue version')
        entries = [ReviewEntry.from_row(row) for row in document.get('entries', [])]
        if len(entries) > self.limits.max_entries * 4:
            raise ReviewQueueError('the review queue file is larger than any configured limit')
        return entries

    def _save(self, entries):
        payload = {'review_queue_version': REVIEW_QUEUE_VERSION,
                   'written_at': _stamp(self._clock()),
                   'limits': self.limits.explain(),
                   'contents': ('behaviour features only; no payload, no address, no credential; '
                                'a source is grouped by a keyed digest'),
                   'authority': ('this file cannot change a firewall and cannot start training; '
                                 'a label exists only where a person answered'),
                   'entries': [entry.to_row() for entry in entries]}
        text = json.dumps(payload, indent=2, sort_keys=True) + '\n'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=str(self.path.parent), prefix='.review-')
        try:
            with os.fdopen(handle, 'w', encoding='utf-8') as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        directory = os.open(str(self.path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return entries

    def entries(self, *, state=None, limit=200):
        """Highest priority first, so a person spends their time where it counts."""
        found = [entry for entry in self._load() if state is None or entry.state == state]
        found.sort(key=lambda entry: (-entry.priority, entry.created_at))
        return found[:max(0, int(limit))]

    def stats(self):
        entries = self._load()
        counts = {name: 0 for name in STATES}
        for entry in entries:
            counts[entry.state] += 1
        sources = {}
        for entry in entries:
            sources[entry.source_key] = sources.get(entry.source_key, 0) + 1
        busiest = max(sources.values()) if sources else 0
        return {'schema_version': 1, 'total': len(entries), 'by_state': counts,
                'distinct_sources': len(sources), 'largest_single_source': busiest,
                'capacity_used': round(len(entries) / self.limits.max_entries, 4),
                'limits': self.limits.explain(),
                'labelled_by_a_person': counts[BENIGN_LIKE] + counts[MALICIOUS_AUTOMATION_LIKE]}

    # --- writing -------------------------------------------------------

    def prune(self, entries=None):
        """Drop expired entries, then trim to capacity by dropping the least useful.

        A reviewed entry is never dropped for capacity: a person's answer is the
        scarce thing here, and throwing it away to make room for unreviewed
        traffic would let volume erase judgement.
        """
        entries = self._load() if entries is None else entries
        now = self._clock()
        kept = [entry for entry in entries
                if entry.state != UNREVIEWED or _parse(entry.expires_at) > now]
        if len(kept) > self.limits.max_entries:
            reviewed = [entry for entry in kept if entry.state != UNREVIEWED]
            pending = [entry for entry in kept if entry.state == UNREVIEWED]
            pending.sort(key=lambda entry: (-entry.priority, entry.created_at))
            room = max(0, self.limits.max_entries - len(reviewed))
            kept = reviewed + pending[:room]
        return kept

    def offer(self, *, source, behaviour, evidence=None, priority=0.0, reasons=(),
              features=None, analysis_only=None):
        """Offer one window for review. Returns what happened and why.

        This is the only entry point the running sensor uses, and it can only ever
        add an UNREVIEWED row. Refusals are normal operation, not errors.
        """
        if priority <= 0:
            return {'admitted': False, 'reason': 'nothing about this window is unclear'}
        clean = {name: (None if behaviour.get(name) is None else float(behaviour[name]))
                 for name in SUMMARY_FEATURES if name in behaviour}
        evidence = dict(evidence or {})
        observations = int(evidence.get('observations', 0) or 0)
        if observations < self.limits.min_observations:
            return {'admitted': False,
                    'reason': f'only {observations} observations; too little to judge'}

        key = source_key(self.secret, source)
        signature = behaviour_signature(clean)
        now = self._clock()
        entries = self.prune()

        for entry in entries:
            if entry.signature == signature and entry.source_key == key:
                entry.occurrences += 1
                entry.last_seen_at = _stamp(now)
                self._save(entries)
                return {'admitted': False, 'reason': 'already in the queue',
                        'entry_id': entry.entry_id, 'occurrences': entry.occurrences}

        from_source = sum(1 for entry in entries if entry.source_key == key)
        if from_source >= self.limits.per_source_entries:
            return {'admitted': False, 'source_key': key,
                    'reason': (f'this source already holds {from_source} of the '
                               f'{self.limits.per_source_entries} places it may hold')}

        today = _stamp(now)[:10]
        today_count = sum(1 for entry in entries if entry.created_at[:10] == today)
        if today_count >= self.limits.per_day_entries:
            return {'admitted': False,
                    'reason': f'the daily limit of {self.limits.per_day_entries} entries is reached'}

        if len(entries) >= self.limits.max_entries:
            reviewed = sum(1 for entry in entries if entry.state != UNREVIEWED)
            if reviewed >= self.limits.max_entries:
                return {'admitted': False,
                        'reason': ('the queue is full of reviewed entries; export them into a '
                                   'dataset so there is room to collect more')}
            return {'admitted': False, 'reason': 'the queue is full; review some entries first'}

        entry = ReviewEntry(
            entry_id=hashlib.sha256(f'{key}|{signature}|{_stamp(now)}'.encode()).hexdigest()[:24],
            signature=signature, source_key=key, created_at=_stamp(now),
            expires_at=_stamp(now + timedelta(days=self.limits.ttl_days)),
            priority=float(priority), reasons=tuple(str(r)[:200] for r in reasons)[:MAX_REASONS],
            behaviour=clean, evidence=evidence, features=dict(features or {}),
            analysis_only=dict(analysis_only or {}), last_seen_at=_stamp(now))
        entries.append(entry)
        self._save(entries)
        return {'admitted': True, 'entry_id': entry.entry_id, 'source_key': key,
                'priority': entry.priority, 'expires_at': entry.expires_at}

    def record_review(self, entry_id, answer, *, note='', confidence='MEDIUM'):
        """Write a person's answer. This is the only way a state ever changes."""
        if answer not in ANSWERS:
            raise ReviewQueueError(f'unknown review answer: {answer!r}')
        if confidence not in ('HIGH', 'MEDIUM', 'LOW'):
            raise ReviewQueueError('confidence must be HIGH, MEDIUM or LOW')
        if answer == UNCERTAIN:
            confidence = 'LOW'
        elif confidence == 'HIGH':
            # Only deterministic controlled ground truth is HIGH. A person looking
            # at a behaviour summary is doing their best, which is MEDIUM.
            confidence = 'MEDIUM'
        entries = self._load()
        for index, entry in enumerate(entries):
            if entry.entry_id == entry_id:
                entries[index] = replace(entry, state=answer,
                                         reviewed_at=_stamp(self._clock()),
                                         reviewer_note=str(note)[:MAX_NOTE_CHARS],
                                         confidence=confidence)
                self._save(entries)
                return entries[index]
        raise ReviewQueueError(f'no queue entry with id {entry_id}')

    def reset_review(self, entry_id):
        """Undo an answer. A person may change their mind; the system may not."""
        entries = self._load()
        for index, entry in enumerate(entries):
            if entry.entry_id == entry_id:
                entries[index] = replace(entry, state=UNREVIEWED, reviewed_at='',
                                         reviewer_note='', confidence='')
                self._save(entries)
                return entries[index]
        raise ReviewQueueError(f'no queue entry with id {entry_id}')

    # --- moving labels out ---------------------------------------------

    def labelled(self):
        """Entries a person actually answered, ready to become dataset rows.

        IGNORE and UNREVIEWED are excluded. UNCERTAIN is included and stays
        uncertain: it is a real answer and it keeps a row out of supervised
        training rather than guessing at it.
        """
        return [entry for entry in self._load() if entry.state in LABEL_FOR_ANSWER]

    def export_labels(self, path):
        """Write reviewed rows for the dataset builder. Behaviour and label only."""
        rows = []
        for entry in self.labelled():
            rows.append({'entry_id': entry.entry_id, 'signature': entry.signature,
                         'source_group': entry.source_key,
                         'label': LABEL_FOR_ANSWER[entry.state],
                         'label_source': 'manual_review',
                         'label_confidence': entry.confidence or 'MEDIUM',
                         'observed_at': entry.created_at,
                         'reviewed_at': entry.reviewed_at,
                         'reviewer_note': entry.reviewer_note,
                         'behaviour': entry.behaviour, 'evidence': entry.evidence,
                         'features': entry.features})
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        document = {'review_export_version': 1, 'written_at': _stamp(self._clock()),
                    'rows': len(rows),
                    'label_origin': 'human review only; no decision, score or threshold made a label',
                    'samples': rows}
        target.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        return {'file': str(target), 'rows': len(rows)}


def summarise_vector(vector):
    """Behaviour dictionary for a feature vector, limited to the reviewer's view."""
    values = dict(zip(NAMES, vector.values, strict=True))
    return {name: (None if values.get(name) is None else float(values[name]))
            for name in SUMMARY_FEATURES if name in values}


def vector_payload(vector):
    """The whole feature vector, stored so an answered entry can become a row.

    Kept in the schema's own order and tagged with the schema version, so a queue
    written by one build is never silently read as features of another. These are
    the same bounded behaviour counters the reviewer sees, only more of them:
    nothing here identifies anyone.
    """
    return {'feature_schema_version': int(vector.schema_version),
            'names': list(NAMES),
            'values': [None if value is None else float(value) for value in vector.values],
            'observation_seconds': float(vector.observation_seconds),
            'sample_count': int(vector.sample_count),
            'capped': bool(vector.capped),
            'loss_fraction': (None if vector.loss_fraction is None
                              else float(vector.loss_fraction))}


def vector_from_payload(payload):
    """Rebuild a FeatureVector from a stored payload, or refuse.

    A payload written against a different feature schema, or with the names in a
    different order, is refused rather than reinterpreted. Reading one model's
    features as another's is how a dataset acquires silent nonsense.
    """
    from .features import FeatureVector, SCHEMA_VERSION
    if not isinstance(payload, dict) or not payload:
        raise ReviewQueueError('this entry has no stored feature vector')
    if payload.get('feature_schema_version') != SCHEMA_VERSION:
        raise ReviewQueueError('the stored feature vector uses a different feature schema')
    if list(payload.get('names') or ()) != list(NAMES):
        raise ReviewQueueError('the stored feature vector uses a different feature order')
    values = payload.get('values')
    if not isinstance(values, list) or len(values) != len(NAMES):
        raise ReviewQueueError('the stored feature vector has the wrong length')
    return FeatureVector(values=tuple(None if v is None else float(v) for v in values),
                         observation_seconds=float(payload['observation_seconds']),
                         sample_count=int(payload['sample_count']),
                         capped=bool(payload.get('capped', False)),
                         loss_fraction=(None if payload.get('loss_fraction') is None
                                        else float(payload['loss_fraction'])))
