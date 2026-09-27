"""The assessment record: why a candidate was or was not accepted.

A promotion that cannot be explained afterwards is a promotion nobody can defend
when a site owner asks why their traffic started being challenged. So the record
is the product, and the decision is one field in it.

Two rules shape everything here.

**No opaque score decides anything** (§26). A summary number may exist for a
status line, and one does, but it is derived *from* the gate outcomes and never
the other way around. `decision` is computed by looking at which gates failed and
how, so that "why" is always answerable by reading a list rather than by
reverse-engineering an arithmetic.

**The record is immutable.** It is a frozen dataclass and it is written once. An
assessment that could be edited after the fact is not evidence; it is a note.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json

ASSESSMENT_SCHEMA_VERSION = 1

#: Every gate passed, and every gate that needed ground truth had it.
ELIGIBLE = 'ELIGIBLE'
#: A gate failed on the evidence available. The candidate is not acceptable.
NOT_ELIGIBLE = 'NOT_ELIGIBLE'
#: No gate failed, but a gate that requires trusted outcomes did not have
#: enough of them. This is not a soft NOT_ELIGIBLE and must never be treated as
#: one: it says the question was not answered, not that the answer was no.
NEED_MORE_DATA = 'NEED_MORE_DATA'
#: Something about the artifact itself is wrong. Not a quality judgement.
QUARANTINED = 'QUARANTINED'

DECISIONS = (ELIGIBLE, NOT_ELIGIBLE, NEED_MORE_DATA, QUARANTINED)

#: A failed BLOCKING gate refuses the promotion. A failed ADVISORY gate is
#: reported and does not, because a system where every measurement can veto ends
#: up with an operator who disables the ones that are merely noisy.
BLOCKING = 'blocking'
ADVISORY = 'advisory'
#: This gate could not be evaluated for lack of trusted labels. It is neither a
#: pass nor a failure, and it is the whole reason NEED_MORE_DATA exists.
UNPROVEN = 'unproven'

#: Categories, so a status page can group thirty gates into six headings (§13).
SECURITY_QUALITY = 'security_quality'
BENIGN_SAFETY = 'benign_safety'
GENERALIZATION = 'generalization'
MODEL_HEALTH = 'model_health'
RESOURCE_COST = 'resource_cost'
SYSTEM_COMPATIBILITY = 'system_compatibility'
INTEGRITY = 'integrity'
GOVERNANCE = 'governance'

CATEGORIES = (INTEGRITY, SYSTEM_COMPATIBILITY, SECURITY_QUALITY, BENIGN_SAFETY,
              GENERALIZATION, MODEL_HEALTH, RESOURCE_COST, GOVERNANCE)


def _now():
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class GateOutcome:
    """One named check, its verdict, and the numbers behind it.

    `active` and `candidate` are kept even when the gate passes. An operator
    reading an assessment six months later wants the measurements, not only the
    word PASS — and a gate that passed narrowly is a different fact from one that
    passed by a mile.
    """

    name: str
    category: str
    severity: str
    passed: bool
    detail: str
    active_value: float | None = None
    candidate_value: float | None = None
    #: True when the gate could not be evaluated at all for lack of evidence.
    unproven: bool = False

    @property
    def blocks(self):
        return self.severity == BLOCKING and not self.passed and not self.unproven

    def explain(self):
        return {'gate': self.name, 'category': self.category,
                'severity': self.severity,
                'result': 'UNPROVEN' if self.unproven else ('PASS' if self.passed else 'FAIL'),
                'detail': self.detail,
                'active': self.active_value, 'candidate': self.candidate_value}


def gate(name, category, severity, passed, detail, *, active=None, candidate=None,
         unproven=False):
    """Build a `GateOutcome`. An unproven gate is never also a pass."""
    return GateOutcome(name=name, category=category, severity=severity,
                       passed=bool(passed) and not unproven, detail=str(detail),
                       active_value=active, candidate_value=candidate,
                       unproven=bool(unproven))


def decide(outcomes, *, quarantined=False, quarantine_reasons=()):
    """Turn a list of gate outcomes into one of four decisions.

    The order matters and is the safety property: integrity first, then
    blocking failures, then missing evidence. A candidate with a corrupt
    artifact is QUARANTINED even if every quality gate would have passed, and a
    candidate with one failing gate is NOT_ELIGIBLE even if another gate was
    unproven — because "we could not measure X" never excuses "Y regressed".
    """
    if quarantined:
        return QUARANTINED, tuple(quarantine_reasons)
    blocking = [outcome for outcome in outcomes if outcome.blocks]
    if blocking:
        return NOT_ELIGIBLE, tuple(
            f'{outcome.name}: {outcome.detail}' for outcome in blocking)
    unproven = [outcome for outcome in outcomes
                if outcome.unproven and outcome.severity == BLOCKING]
    if unproven:
        return NEED_MORE_DATA, tuple(
            f'{outcome.name}: {outcome.detail}' for outcome in unproven)
    return ELIGIBLE, ()


@dataclass(frozen=True, slots=True)
class PromotionAssessmentRecord:
    """One assessment of one candidate, for one scope, under one policy.

    Written once, never edited. `assessment_id` is derived from the content, so
    two assessments that reached the same verdict on the same evidence under the
    same policy have the same id — which makes a re-assessment that changed
    nothing visibly a re-assessment that changed nothing.
    """

    scope: str
    candidate_version: str
    decision: str
    policy_version: str
    policy_digest: str
    active_version: str = ''
    dataset_version: str = ''
    feature_schema_version: int = 0
    offline_report_hash: str = ''
    shadow_report_hash: str = ''
    outcomes: tuple = field(default_factory=tuple)
    reasons: tuple = field(default_factory=tuple)
    created_at: str = ''
    assessment_schema_version: int = ASSESSMENT_SCHEMA_VERSION

    def __post_init__(self):
        if self.decision not in DECISIONS:
            raise ValueError(f'{self.decision!r} is not a promotion decision')

    @property
    def assessment_id(self):
        """Content-addressed, and deliberately excluding the timestamp.

        Including the clock would make every re-assessment look like new
        evidence. Excluding it means an operator can see at a glance that
        yesterday's answer and today's are the same answer.
        """
        body = {'scope': self.scope, 'candidate': self.candidate_version,
                'active': self.active_version, 'decision': self.decision,
                'policy_digest': self.policy_digest,
                'offline': self.offline_report_hash, 'shadow': self.shadow_report_hash,
                'outcomes': [outcome.explain() for outcome in self.outcomes]}
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(',', ':'))
            .encode('utf-8')).hexdigest()[:24]

    @property
    def eligible(self):
        return self.decision == ELIGIBLE

    def is_stale_under(self, policy):
        """Whether this assessment was reached under different rules (§29).

        A policy change does not retroactively authorise anything. It also does
        not retroactively forbid anything — a stale assessment is simply one
        that has to be taken again.
        """
        return self.policy_digest != policy.digest

    def by_category(self):
        grouped = {}
        for outcome in self.outcomes:
            grouped.setdefault(outcome.category, []).append(outcome.explain())
        return grouped

    def failures(self):
        return tuple(outcome for outcome in self.outcomes if outcome.blocks)

    def unproven(self):
        return tuple(outcome for outcome in self.outcomes if outcome.unproven)

    def explain(self):
        return {'assessment_schema_version': self.assessment_schema_version,
                'assessment_id': self.assessment_id,
                'created_at': self.created_at,
                'scope': self.scope,
                'active_version': self.active_version,
                'candidate_version': self.candidate_version,
                'dataset_version': self.dataset_version,
                'feature_schema_version': self.feature_schema_version,
                'offline_report_hash': self.offline_report_hash[:16],
                'shadow_report_hash': self.shadow_report_hash[:16],
                'governance_policy_version': self.policy_version,
                'policy_digest': self.policy_digest[:16],
                'decision': self.decision,
                'reasons': list(self.reasons),
                'gates': [outcome.explain() for outcome in self.outcomes],
                'gates_by_category': self.by_category(),
                'note': ('the decision follows from the gate list; there is no '
                         'score that overrides it')}

    def render(self):
        """The human form, for the CLI. §83's shape."""
        lines = ['AUTO-PROMOTION ASSESSMENT', '',
                 f'Scope:\n{self.scope}', '',
                 f'Active:\n{self.active_version or "none"}', '',
                 f'Candidate:\n{self.candidate_version}', '']
        for category in CATEGORIES:
            outcomes = [outcome for outcome in self.outcomes
                        if outcome.category == category]
            if not outcomes:
                continue
            lines.append(category.replace('_', ' ').capitalize() + ':')
            for outcome in outcomes:
                mark = 'UNPROVEN' if outcome.unproven else ('PASS' if outcome.passed else 'FAIL')
                lines.append(f'  {outcome.name}: {mark}')
            lines.append('')
        lines.append(f'Decision:\n{self.decision}')
        if self.reasons:
            lines.extend(['', 'Reasons:'])
            lines.extend(f'  - {reason}' for reason in self.reasons)
        lines.extend(['', f'Governance policy:\n{self.policy_version} '
                          f'({self.policy_digest[:16]})'])
        return '\n'.join(lines) + '\n'


def build(*, scope, candidate_version, policy, outcomes, active_version='',
          dataset_version='', feature_schema_version=0, offline_report_hash='',
          shadow_report_hash='', quarantined=False, quarantine_reasons=(),
          now=None):
    """Assemble an immutable record from gate outcomes. Decides nothing itself."""
    decision, reasons = decide(outcomes, quarantined=quarantined,
                               quarantine_reasons=quarantine_reasons)
    moment = now or _now()
    return PromotionAssessmentRecord(
        scope=scope, candidate_version=candidate_version, decision=decision,
        policy_version=policy.version, policy_digest=policy.digest,
        active_version=active_version, dataset_version=dataset_version,
        feature_schema_version=feature_schema_version,
        offline_report_hash=offline_report_hash,
        shadow_report_hash=shadow_report_hash,
        outcomes=tuple(outcomes), reasons=reasons,
        created_at=moment.isoformat(timespec='seconds'))


def report_hash(document):
    """A stable hash of an evaluation report, for the record to point at.

    The record stores the hash rather than the report so that an assessment stays
    small and bounded, while still being tied to the exact evidence it was
    reached from.
    """
    if document is None:
        return ''
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(',', ':'), default=str)
        .encode('utf-8')).hexdigest()


def asdict_record(record):
    """A plain dict, for the durable history file."""
    body = asdict(record)
    body['outcomes'] = [outcome.explain() for outcome in record.outcomes]
    body['assessment_id'] = record.assessment_id
    return body
