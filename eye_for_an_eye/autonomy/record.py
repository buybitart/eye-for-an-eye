"""What was decided, and everything the decision rested on.

A decision nobody can reconstruct is not a decision, it is an outcome. Weeks
after a block, somebody asks why a customer could not reach the site, and the
only acceptable answer is a complete one: what the source did, how many
independent kinds of evidence said so, how complete the data was, whether the
client address was trustworthy, what a mistake would have cost, and which gate
would have stopped the block if it had failed.

So every ALLOW and every TEMP_BLOCK produces an `AutonomousDecisionRecord`, and
the record is validated rather than merely populated. Three of those validations
are the reason this module is worth reading.

**A block must name behaviour.** §90 forbids "BLOCK because AI score 0.93", and
forbidding it in prose is worth nothing. A record with `action=TEMP_BLOCK` and no
behavioural reason code raises — the classifier and the anomaly model can
corroborate a block and can never be the whole case for one. That is a structural
guarantee, not a convention, and `tests/test_p15_invariants.py` holds it down.

**An ALLOW must name a reason too.** §89: allowing is a decision, and "nothing
happened" is not an explanation. Every ALLOW carries at least one restraining
code, which in the ordinary case is the honest one — the arithmetic preferred
allowing.

**A block carries no restraining code.** If any gate refused, the answer is ALLOW.
A record that blocked *and* recorded a reason not to block would mean something
overrode a refusal, and nothing in this package can.

### On the source identifier

§87 asks for a pseudonymous identifier *or* the operational address as required,
and both are real needs: the executor needs an address to act on, and an audit
trail that is kept, exported or graphed should not be a log of who visited.
`pseudonym()` gives a stable keyed digest under a local secret. Without a secret
it uses a per-process salt, so records correlate inside one run and across none —
which is a weaker property, stated rather than papered over.
"""
from dataclasses import dataclass, field
import datetime as dt
import hashlib
import hmac
import os
import secrets

from .evidence import (ANOMALY, AUTH_BEHAVIOR, DECEPTION_INTERACTION,
                       HTTP_DISCOVERY, ML_CLASSIFIER, NETWORK_RATE,
                       PERSISTENCE, PORT_BREADTH, PROTOCOL_BEHAVIOR, TIMING)

DECISION_RECORD_VERSION = 1

#: The two final actions. Everything softer (OBSERVE, WATCH, SOFT_CHALLENGE,
#: RATE_LIMIT) belongs to the ladders in `web/sensor.py` and `challenge/policy.py`
#: and is chosen before this package is consulted. §10.
ALLOW = 'ALLOW'
TEMP_BLOCK = 'TEMP_BLOCK'
FINAL_ACTIONS = (ALLOW, TEMP_BLOCK)

#: The hard ceiling on any autonomous block, matching the bound `config.py`
#: already enforces on `enforcement.block_seconds`. §198 lists the maximum block
#: TTL among the limits no learned component may change, so it is a module
#: constant here rather than a tunable.
MAX_BLOCK_TTL_SECONDS = 43_200


class DecisionRecordError(ValueError):
    """A record that would misrepresent what happened."""


# ---------------------------------------------------------------------------
# Reason codes (§88). A bounded enum, because these become metric labels (§159)
# and an unbounded label set is how a metrics endpoint becomes a memory problem.
# ---------------------------------------------------------------------------

#: What the source *did*. At least one of these is required for a block.
HIGH_CONNECTION_RATE = 'HIGH_CONNECTION_RATE'
HIGH_PORT_BREADTH = 'HIGH_PORT_BREADTH'
PROTOCOL_ANOMALY = 'PROTOCOL_ANOMALY'
HTTP_PATH_ENUMERATION = 'HTTP_PATH_ENUMERATION'
AUTH_FAILURE_AUTOMATION = 'AUTH_FAILURE_AUTOMATION'
MACHINE_TIMING = 'MACHINE_TIMING'
PERSISTENT_PROBING = 'PERSISTENT_PROBING'
DECEPTION_CONTINUATION = 'DECEPTION_CONTINUATION'

BEHAVIOURAL_CODES = (HIGH_CONNECTION_RATE, HIGH_PORT_BREADTH, PROTOCOL_ANOMALY,
                     HTTP_PATH_ENUMERATION, AUTH_FAILURE_AUTOMATION,
                     MACHINE_TIMING, PERSISTENT_PROBING, DECEPTION_CONTINUATION)

#: Model opinion. Corroborates; never carries a block on its own (§25, §26, §86).
ML_SUPPORT = 'ML_SUPPORT'
ANOMALY_SUPPORT = 'ANOMALY_SUPPORT'
MODEL_CODES = (ML_SUPPORT, ANOMALY_SUPPORT)

#: Conditions that had to hold for a block to be permitted at all.
LOW_OOD = 'LOW_OOD'
HIGH_DATA_QUALITY = 'HIGH_DATA_QUALITY'
IDENTITY_CONFIRMED = 'IDENTITY_CONFIRMED'
SIGNAL_DIVERSITY_MET = 'SIGNAL_DIVERSITY_MET'
COST_BLOCK_PREFERRED = 'COST_BLOCK_PREFERRED'
MARGIN_SATISFIED = 'MARGIN_SATISFIED'
REPEAT_OFFENCE = 'REPEAT_OFFENCE'
MODEL_HEALTHY = 'MODEL_HEALTHY'
SUPPORTING_CODES = BEHAVIOURAL_CODES + MODEL_CODES + (
    LOW_OOD, HIGH_DATA_QUALITY, IDENTITY_CONFIRMED, SIGNAL_DIVERSITY_MET,
    COST_BLOCK_PREFERRED, MARGIN_SATISFIED, REPEAT_OFFENCE, MODEL_HEALTHY)

#: Why a block did not happen. Every ALLOW carries at least one (§89).
PROTECTED_SOURCE = 'PROTECTED_SOURCE'
MANAGEMENT_NETWORK = 'MANAGEMENT_NETWORK'
IDENTITY_UNCERTAIN = 'IDENTITY_UNCERTAIN'
NOT_NETWORK_ENFORCEABLE = 'NOT_NETWORK_ENFORCEABLE'
SHARED_PROXY_RISK = 'SHARED_PROXY_RISK'
INSUFFICIENT_DATA_QUALITY = 'INSUFFICIENT_DATA_QUALITY'
INSUFFICIENT_OBSERVATIONS = 'INSUFFICIENT_OBSERVATIONS'
INSUFFICIENT_OBSERVATION_TIME = 'INSUFFICIENT_OBSERVATION_TIME'
INSUFFICIENT_SIGNAL_DIVERSITY = 'INSUFFICIENT_SIGNAL_DIVERSITY'
MODEL_ONLY_EVIDENCE = 'MODEL_ONLY_EVIDENCE'
HIGH_OOD = 'HIGH_OOD'
MODEL_UNHEALTHY = 'MODEL_UNHEALTHY'
MODEL_DISAGREEMENT = 'MODEL_DISAGREEMENT'
DRIFT_DEGRADED = 'DRIFT_DEGRADED'
CALIBRATION_UNAVAILABLE = 'CALIBRATION_UNAVAILABLE'
UNCERTAINTY_HIGH = 'UNCERTAINTY_HIGH'
COST_ALLOW_PREFERRED = 'COST_ALLOW_PREFERRED'
MARGIN_NOT_MET = 'MARGIN_NOT_MET'
NETWORK_BLOCK_NOT_PERMITTED = 'NETWORK_BLOCK_NOT_PERMITTED'
BLOCK_BUDGET_EXHAUSTED = 'BLOCK_BUDGET_EXHAUSTED'
MASS_BLOCK_FREEZE = 'MASS_BLOCK_FREEZE'
FALSE_POSITIVE_FREEZE = 'FALSE_POSITIVE_FREEZE'
TECHNICAL_FREEZE = 'TECHNICAL_FREEZE'
AUTONOMOUS_SAFE_MODE = 'AUTONOMOUS_SAFE_MODE'
ENFORCEMENT_UNHEALTHY = 'ENFORCEMENT_UNHEALTHY'
POLICY_GUARD_REFUSED = 'POLICY_GUARD_REFUSED'
EXISTING_BLOCK_LEASE = 'EXISTING_BLOCK_LEASE'
ASSUMPTION_FAILED = 'ASSUMPTION_FAILED'
SHADOW_MODE = 'SHADOW_MODE'
AUTONOMY_DISABLED = 'AUTONOMY_DISABLED'
RESTRAINING_CODES = (
    PROTECTED_SOURCE, MANAGEMENT_NETWORK, IDENTITY_UNCERTAIN,
    NOT_NETWORK_ENFORCEABLE, SHARED_PROXY_RISK, INSUFFICIENT_DATA_QUALITY,
    INSUFFICIENT_OBSERVATIONS, INSUFFICIENT_OBSERVATION_TIME,
    INSUFFICIENT_SIGNAL_DIVERSITY, MODEL_ONLY_EVIDENCE, HIGH_OOD,
    MODEL_UNHEALTHY, MODEL_DISAGREEMENT, DRIFT_DEGRADED,
    CALIBRATION_UNAVAILABLE, UNCERTAINTY_HIGH, COST_ALLOW_PREFERRED,
    MARGIN_NOT_MET, NETWORK_BLOCK_NOT_PERMITTED, BLOCK_BUDGET_EXHAUSTED,
    MASS_BLOCK_FREEZE, FALSE_POSITIVE_FREEZE, TECHNICAL_FREEZE,
    AUTONOMOUS_SAFE_MODE, ENFORCEMENT_UNHEALTHY, POLICY_GUARD_REFUSED,
    EXISTING_BLOCK_LEASE, ASSUMPTION_FAILED, SHADOW_MODE, AUTONOMY_DISABLED)

REASON_CODES = frozenset(SUPPORTING_CODES + RESTRAINING_CODES)

#: Which behavioural code names a signal family's evidence. The map is total over
#: the families that can support a block, so a family with evidence always has a
#: word for what it saw.
FAMILY_CODES = {
    NETWORK_RATE: HIGH_CONNECTION_RATE,
    PORT_BREADTH: HIGH_PORT_BREADTH,
    PROTOCOL_BEHAVIOR: PROTOCOL_ANOMALY,
    HTTP_DISCOVERY: HTTP_PATH_ENUMERATION,
    AUTH_BEHAVIOR: AUTH_FAILURE_AUTOMATION,
    TIMING: MACHINE_TIMING,
    PERSISTENCE: PERSISTENT_PROBING,
    DECEPTION_INTERACTION: DECEPTION_CONTINUATION,
    ML_CLASSIFIER: ML_SUPPORT,
    ANOMALY: ANOMALY_SUPPORT,
}

#: Plain-English readings, for the incident view and the CLI. A code is a stable
#: token for machines; this is what a person is owed alongside it.
CODE_MEANINGS = {
    HIGH_CONNECTION_RATE: 'many connections or requests in a short window',
    HIGH_PORT_BREADTH: 'a wide spread of ports or destinations was touched',
    PROTOCOL_ANOMALY: 'traffic did not match the protocol it claimed',
    HTTP_PATH_ENUMERATION: 'many distinct or sensitive paths were requested',
    AUTH_FAILURE_AUTOMATION: 'automated credential attempts',
    MACHINE_TIMING: 'request timing was regular in a way people are not',
    PERSISTENT_PROBING: 'the behaviour continued over a long window',
    DECEPTION_CONTINUATION: 'interaction continued with a decoy service',
    ML_SUPPORT: 'the classifier found this similar to training examples of '
                'malicious automation (corroboration only)',
    ANOMALY_SUPPORT: 'the anomaly model found this unusual (corroboration only; '
                     'unusual is not malicious)',
    LOW_OOD: 'the observation is inside the distribution the model was fitted on',
    HIGH_DATA_QUALITY: 'the features were complete enough to judge',
    IDENTITY_CONFIRMED: 'the address is the machine that connected to this server',
    SIGNAL_DIVERSITY_MET: 'enough independent evidence families agreed',
    COST_BLOCK_PREFERRED: 'expected loss favours blocking under this site cost profile',
    MARGIN_SATISFIED: 'the expected-loss advantage exceeded the decision margin',
    REPEAT_OFFENCE: 'this source has been blocked before within the offence window',
    MODEL_HEALTHY: 'the model is healthy and undrifted',
    PROTECTED_SOURCE: 'the source is protected by policy and is never blocked',
    MANAGEMENT_NETWORK: 'the source is in a configured management network',
    IDENTITY_UNCERTAIN: 'the client address could not be established',
    NOT_NETWORK_ENFORCEABLE: 'a network block would hit a proxy, not this client',
    SHARED_PROXY_RISK: 'the address is shared by other clients',
    INSUFFICIENT_DATA_QUALITY: 'the data was too incomplete to act on',
    INSUFFICIENT_OBSERVATIONS: 'too few observations',
    INSUFFICIENT_OBSERVATION_TIME: 'the observation window was too short',
    INSUFFICIENT_SIGNAL_DIVERSITY: 'too few independent evidence families',
    MODEL_ONLY_EVIDENCE: 'only model opinion supported this; no behaviour did',
    HIGH_OOD: 'the observation is outside the model training distribution, so the '
              'classifier carries less authority here',
    MODEL_UNHEALTHY: 'the model is degraded or unavailable',
    MODEL_DISAGREEMENT: 'the deterministic engine and the classifier disagreed materially',
    DRIFT_DEGRADED: 'population drift has reduced model authority',
    CALIBRATION_UNAVAILABLE: 'the classifier output is a score, not a probability',
    UNCERTAINTY_HIGH: 'the estimate was too uncertain to act on',
    COST_ALLOW_PREFERRED: 'expected loss favours allowing under this site cost profile',
    MARGIN_NOT_MET: 'blocking was only marginally preferable, which is not enough',
    NETWORK_BLOCK_NOT_PERMITTED: 'this cost profile forbids autonomous network blocking',
    BLOCK_BUDGET_EXHAUSTED: 'the autonomous block budget for this window is spent',
    MASS_BLOCK_FREEZE: 'the mass-block circuit breaker is open',
    FALSE_POSITIVE_FREEZE: 'the false-positive circuit breaker is open',
    TECHNICAL_FREEZE: 'a technical circuit breaker is open',
    AUTONOMOUS_SAFE_MODE: 'the runtime is in autonomous safe mode',
    ENFORCEMENT_UNHEALTHY: 'the enforcement subsystem is not healthy',
    POLICY_GUARD_REFUSED: 'PolicyGuard refused the action',
    EXISTING_BLOCK_LEASE: 'this source already has an unexpired block',
    ASSUMPTION_FAILED: 'a required assumption did not hold',
    SHADOW_MODE: 'the runtime is in shadow mode and records what it would have done',
    AUTONOMY_DISABLED: 'autonomous decision-making is switched off',
}

#: Words for how much evidence there was, so an ALLOW can say "moderate" rather
#: than printing a number nobody asked for (§89).
BANDS = ((0.05, 'NEGLIGIBLE'), (0.35, 'LOW'), (0.75, 'MODERATE'), (1.01, 'HIGH'))


def band(value):
    for ceiling, name in BANDS:
        if value < ceiling:
            return name
    return 'HIGH'


# ---------------------------------------------------------------------------
# Assumptions (§118)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Assumption:
    """One thing a decision silently relies on, named so its failure is visible.

    `required_for_block` marks the assumptions whose failure makes a block
    unsafe rather than merely less informed. A failed assumption never produces
    a block; at worst it produces an ALLOW that says which one failed.
    """

    name: str
    statement: str
    subsystem: str
    required_for_block: bool = True


ASSUMPTIONS = (
    Assumption('feature_schema_compatible',
               'the feature vector uses the schema the model was built for',
               'features'),
    Assumption('features_finite',
               'every present feature is a finite number in its declared range',
               'features'),
    Assumption('model_calibrated',
               'the classifier output is a calibrated probability rather than a score',
               'model', required_for_block=False),
    Assumption('model_artifact_valid',
               'the loaded model artifact passed manifest and digest validation',
               'model'),
    Assumption('client_identity_resolvable',
               'the address names the machine that connected to this server',
               'identity'),
    Assumption('minimum_sample_mature',
               'enough observations over enough time to describe behaviour',
               'features'),
    Assumption('cost_policy_available',
               'a cost profile applies to this scope',
               'cost'),
    Assumption('enforcement_healthy',
               'the enforcement subsystem can apply and verify a rule',
               'enforcement'),
    Assumption('clock_sane',
               'the clock has not jumped, so a TTL means what it says',
               'runtime'),
    Assumption('data_quality_measured',
               'data quality was computed rather than assumed',
               'quality'),
)

ASSUMPTION_NAMES = tuple(item.name for item in ASSUMPTIONS)


class AssumptionRegistry:
    """The registry §118 asks for: what was assumed, and what actually held.

    Deterministic and machine-checkable, which is the point of §117. The
    questions it answers — what did this need, was it satisfied, which subsystem
    failed — are answered from recorded observations rather than from a model
    being asked to criticise itself.
    """

    def __init__(self, assumptions=ASSUMPTIONS):
        self.assumptions = {item.name: item for item in assumptions}
        self.results = {}

    def record(self, name, satisfied, detail=''):
        if name not in self.assumptions:
            raise DecisionRecordError(f'unknown assumption {name!r}')
        self.results[name] = (bool(satisfied), str(detail)[:120])
        return self

    def record_many(self, **observations):
        for name, value in observations.items():
            self.record(name, value)
        return self

    @property
    def unchecked(self):
        """Assumptions nobody tested. Treated as failures where a block is
        concerned: an assumption that was never checked is not a satisfied one."""
        return tuple(name for name in self.assumptions if name not in self.results)

    @property
    def failed(self):
        return tuple(sorted(name for name, (ok, _) in self.results.items() if not ok))

    @property
    def blocking_failures(self):
        """Failures, plus unchecked assumptions, that make a block unsafe."""
        names = set(self.failed) | set(self.unchecked)
        return tuple(sorted(name for name in names
                            if self.assumptions[name].required_for_block))

    @property
    def satisfied(self):
        return tuple(sorted(name for name, (ok, _) in self.results.items() if ok))

    def subsystems(self):
        """Which subsystem each failure belongs to, for §117's third question."""
        return tuple(sorted({self.assumptions[name].subsystem
                             for name in self.blocking_failures}))

    def explain(self):
        return {'checked': len(self.results),
                'satisfied': list(self.satisfied),
                'failed': [{'assumption': name,
                            'statement': self.assumptions[name].statement,
                            'subsystem': self.assumptions[name].subsystem,
                            'detail': self.results[name][1]}
                           for name in self.failed],
                'unchecked': list(self.unchecked),
                'blocking_failures': list(self.blocking_failures),
                'failed_subsystems': list(self.subsystems())}


# ---------------------------------------------------------------------------
# Pseudonymous source identifiers
# ---------------------------------------------------------------------------

#: Used when no local secret is configured. Random per process: records correlate
#: within one run and across none. Weaker, and said out loud rather than hidden.
_SESSION_SALT = secrets.token_bytes(32)


def pseudonym(source, secret=None):
    """A stable keyed digest of a source address. Never reversible to an address
    without the secret, and never a person either way (§141: an IP is not a
    person, and this is not an identity)."""
    key = secret if secret else _SESSION_SALT
    if isinstance(key, str):
        key = key.encode('utf-8')
    return 'src-' + hmac.new(key, str(source).encode('utf-8')[:512],
                             hashlib.sha256).hexdigest()[:16]


def new_decision_id():
    """A short opaque identifier. Not derived from the source: a decision id that
    leaked the address it was about would defeat the pseudonym beside it."""
    return 'dec-' + os.urandom(9).hex()


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AutonomousDecisionRecord:
    """One final decision, with everything §87 asks for and the checks §90 needs.

    Constructed by `authority.py` and by nothing else that decides. Validation
    happens in `__post_init__`, so an incoherent record cannot be written to a
    journal, exported, or counted in a metric.
    """

    action: str
    decision_id: str = field(default_factory=new_decision_id)
    timestamp: str = ''
    record_version: int = DECISION_RECORD_VERSION

    # Where and who
    scope: str = 'GLOBAL'
    site_id: str = ''
    source: str = ''
    source_pseudonym: str = ''
    identity_confidence: str = 'LOW'
    identity_origin: str = ''
    network_enforceable: bool = False
    enforcement_scope: str = 'UNKNOWN'

    # What was measured
    feature_schema_version: int = 1
    observations: int = 0
    observation_seconds: float = 0.0
    math_risk: float = 0.0
    math_version: str = ''
    math_contributions: dict = field(default_factory=dict)
    web_math_risk: float | None = None
    persistence: float = 0.0

    # What the models said
    ml_model_version: str = 'none'
    ml_status: str = 'not_loaded'
    model_score: float | None = None
    calibrated: bool = False
    calibrated_probability: float | None = None
    calibration_version: str = ''
    anomaly_score: float | None = None
    ood_score: float | None = None
    ood_status: str = 'INSUFFICIENT_REFERENCE'
    drift_status: str = 'UNKNOWN'
    model_health: str = 'UNKNOWN'

    # How much of that could be trusted
    data_quality: float = 0.0
    uncertainty: dict = field(default_factory=dict)
    signal_families: dict = field(default_factory=dict)
    signal_diversity: int = 0
    behavioural_diversity: int = 0

    # The arithmetic
    probability: float = 0.0
    conservative_probability: float = 0.0
    loss_allow: float = 0.0
    loss_block: float = 0.0
    threshold: float = 0.0
    decision_margin: float = 0.0
    cost_profile: str = ''
    cost_policy_version: str = ''
    cost_policy_digest: str = ''

    # The gates
    safety_gates: dict = field(default_factory=dict)
    failed_assumptions: tuple = ()
    failed_subsystems: tuple = ()
    policy_guard_action: str = ''
    policy_guard_reasons: tuple = ()

    # The outcome
    block_ttl_seconds: int = 0
    offence_count: int = 0
    reason_codes: tuple = ()
    mode: str = 'autonomous'
    shadow: bool = False
    enforced: bool = False

    def __post_init__(self):
        if self.action not in FINAL_ACTIONS:
            raise DecisionRecordError(
                f'the final action must be {ALLOW} or {TEMP_BLOCK}, not {self.action!r}')
        unknown = [code for code in self.reason_codes if code not in REASON_CODES]
        if unknown:
            raise DecisionRecordError(f'reason codes outside the enum: {unknown}')
        if len(self.reason_codes) > 16:
            raise DecisionRecordError('at most 16 reason codes; a record is not a log')
        if type(self.block_ttl_seconds) is not int or self.block_ttl_seconds < 0:
            raise DecisionRecordError('the block TTL must be a whole number of seconds')
        if self.action == TEMP_BLOCK:
            self._validate_block()
        elif self.block_ttl_seconds:
            raise DecisionRecordError('an ALLOW cannot carry a block TTL')
        elif not self.restraining:
            # §89. "Nothing happened" is not an explanation, and an ALLOW whose
            # reason nobody recorded is indistinguishable from a bug.
            raise DecisionRecordError(
                'an ALLOW must record why a block did not happen')
        if not self.timestamp:
            object.__setattr__(self, 'timestamp',
                               dt.datetime.now(dt.UTC).isoformat(timespec='milliseconds'))

    def _validate_block(self):
        """The §90 guarantee, enforced rather than documented."""
        if not 0 < self.block_ttl_seconds <= MAX_BLOCK_TTL_SECONDS:
            # §45 and §188: autonomous means temporary. There is no code path
            # here that produces a permanent ban, and none that produces one
            # longer than the ceiling `config.py` already enforces.
            raise DecisionRecordError(
                f'an autonomous block lasts between 1 and {MAX_BLOCK_TTL_SECONDS} seconds')
        if not self.behavioural:
            raise DecisionRecordError(
                'a block must name what the source did: a model score is '
                'corroboration and is never the whole case for blocking (§90)')
        if COST_BLOCK_PREFERRED not in self.reason_codes:
            raise DecisionRecordError(
                'a block must record that the cost model preferred it')
        if self.restraining:
            raise DecisionRecordError(
                f'a block cannot also record reasons not to block: {self.restraining}')
        if self.failed_assumptions:
            raise DecisionRecordError(
                f'a block cannot rest on failed assumptions: {tuple(self.failed_assumptions)}')

    # -- derived views ------------------------------------------------------

    @property
    def behavioural(self):
        """Reason codes describing what the source did. A block needs one."""
        return tuple(code for code in self.reason_codes if code in BEHAVIOURAL_CODES)

    @property
    def model_support(self):
        return tuple(code for code in self.reason_codes if code in MODEL_CODES)

    @property
    def restraining(self):
        return tuple(code for code in self.reason_codes if code in RESTRAINING_CODES)

    @property
    def evidence_band(self):
        """How strong the evidence was, in a word."""
        return band(self.conservative_probability)

    @property
    def blocked(self):
        return self.action == TEMP_BLOCK

    @property
    def model_only(self):
        """True when nothing but model opinion argued for acting. Never blocks."""
        return bool(self.model_support) and not self.behavioural

    # -- output -------------------------------------------------------------

    def explain(self):
        """The full record, as a JSON-safe dict. Bounded: contributions and reason
        codes are already capped, and no free text from a request appears here."""
        return {
            'record_version': self.record_version,
            'decision_id': self.decision_id,
            'timestamp': self.timestamp,
            'mode': self.mode, 'shadow': self.shadow, 'enforced': self.enforced,
            'scope': self.scope, 'site_id': self.site_id,
            'source': self.source, 'source_pseudonym': self.source_pseudonym,
            'identity': {'confidence': self.identity_confidence,
                         'origin': self.identity_origin,
                         'network_enforceable': self.network_enforceable,
                         'enforcement_scope': self.enforcement_scope},
            'features': {'schema_version': self.feature_schema_version,
                         'observations': self.observations,
                         'observation_seconds': round(self.observation_seconds, 3),
                         'data_quality': round(self.data_quality, 4)},
            'math': {'risk': round(self.math_risk, 6), 'version': self.math_version,
                     'contributions': dict(self.math_contributions),
                     'web_risk': (None if self.web_math_risk is None
                                  else round(self.web_math_risk, 6)),
                     'persistence': round(self.persistence, 6)},
            'model': {'version': self.ml_model_version, 'status': self.ml_status,
                      'score': self.model_score, 'calibrated': self.calibrated,
                      'calibrated_probability': self.calibrated_probability,
                      'calibration_version': self.calibration_version,
                      'anomaly_score': self.anomaly_score,
                      'ood_score': self.ood_score, 'ood_status': self.ood_status,
                      'drift_status': self.drift_status,
                      'health': self.model_health},
            'evidence': {'signal_families': dict(self.signal_families),
                         'signal_diversity': self.signal_diversity,
                         'behavioural_diversity': self.behavioural_diversity,
                         'band': self.evidence_band},
            'uncertainty': dict(self.uncertainty),
            'cost': {'profile': self.cost_profile,
                     'policy_version': self.cost_policy_version,
                     'policy_digest': self.cost_policy_digest,
                     'threshold': round(self.threshold, 6),
                     'decision_margin': round(self.decision_margin, 6),
                     'probability': round(self.probability, 6),
                     'conservative_probability': round(self.conservative_probability, 6),
                     'loss_allow': round(self.loss_allow, 6),
                     'loss_block': round(self.loss_block, 6)},
            'gates': dict(self.safety_gates),
            'assumptions': {'failed': list(self.failed_assumptions),
                            'failed_subsystems': list(self.failed_subsystems)},
            'policy_guard': {'action': self.policy_guard_action,
                             'reasons': list(self.policy_guard_reasons)},
            'action': self.action,
            'block_ttl_seconds': self.block_ttl_seconds,
            'offence_count': self.offence_count,
            'reason_codes': list(self.reason_codes),
            'limitations': ['behaviour is not identity',
                            'an address is not a person',
                            'a block is never a training label',
                            'autonomy is an operational property, not an accuracy claim'],
        }

    def summary(self):
        """One bounded line, for a log or a status table."""
        return (f'{self.decision_id} {self.action} scope={self.scope} '
                f'evidence={self.evidence_band} p={self.conservative_probability:.3f} '
                f'ttl={self.block_ttl_seconds}s '
                f'codes={",".join(self.reason_codes) or "none"}')

    def explanation(self):
        """What a person is owed. Never a bare score (§89, §90).

        A block reads as: what the source did, what corroborated it, what the
        mistake would have cost. An ALLOW reads as: how strong the evidence was,
        and what stopped it short of a block.
        """
        lines = [f'{self.action} — {self.scope}' + (f' site={self.site_id}' if self.site_id else ''),
                 f'Risk evidence: {self.evidence_band.lower()} '
                 f'(conservative estimate {self.conservative_probability:.3f}, '
                 f'cutoff {self.threshold:.3f} under cost profile '
                 f'{self.cost_profile or "unset"})']
        if self.blocked:
            lines.append('What this source did:')
            lines += [f'  - {CODE_MEANINGS[code]}' for code in self.behavioural]
            if self.model_support:
                lines.append('Corroboration:')
                lines += [f'  - {CODE_MEANINGS[code]}' for code in self.model_support]
            lines.append(f'Expected loss: allow {self.loss_allow:.4f} vs '
                         f'block {self.loss_block:.4f}')
            lines.append(f'Temporary: this block expires after {self.block_ttl_seconds} '
                         'seconds with no human action')
        else:
            supporting = self.behavioural + self.model_support
            if supporting:
                lines.append('What was observed:')
                lines += [f'  - {CODE_MEANINGS[code]}' for code in supporting]
            lines.append('Reason not blocked:')
            lines += [f'  - {CODE_MEANINGS[code]}' for code in self.restraining]
            lines.append('ALLOW means not currently eligible for an autonomous '
                         'temporary block. It does not mean this source is benign, '
                         'and it is never a training label.')
        if self.failed_assumptions:
            lines.append('Assumptions that did not hold: '
                         + ', '.join(self.failed_assumptions))
        return '\n'.join(lines)
