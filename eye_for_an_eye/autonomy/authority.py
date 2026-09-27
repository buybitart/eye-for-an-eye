"""The one algorithm. ALLOW or TEMP_BLOCK, in an order anybody can audit.

§119 asks for a single explicit auditable algorithm, and §43 fixes its shape.
This module is that algorithm and nothing else: it computes no features, runs no
model, opens no socket and holds no firewall handle. Every engine it consults
already existed before P15 — `MathRiskEngine`, the ONNX worker, the anomaly
model, `OODEngine`, `DriftEngine`, `DataQualityResult`, `ClientResolver`,
`PolicyGuard` — and their results arrive here as a `DecisionInputs` value the
caller assembled. Duplicating any of them would have created a second opinion to
keep in sync, and a second opinion is how two parts of a system quietly start
disagreeing about what happened.

### The order, and why it is that order

    protected?                      -> ALLOW
    can we even act on this address? -> ALLOW
    is the data good enough?         -> ALLOW
    is the evidence enough?          -> ALLOW
    does the cost model prefer it,
      by a margin, under doubt?      -> and only then TEMP_BLOCK
    otherwise                        -> ALLOW

The cheap, certain refusals come first. Not for speed — for honesty. Asking
"what does the model think?" about a management address or a CDN edge is asking
a question whose answer must not matter, and a system that computes it anyway
will eventually find a way to use it.

### Restraints are collected, not short-circuited

The gates do not return early. Every reason not to block is gathered, so the
record answers "why wasn't this blocked?" completely rather than naming whichever
gate happened to be checked first. A decision with no restraints left, and a cost
model that prefers blocking, is a block. Anything else is ALLOW — which is also
how `record.py`'s validation stays satisfiable: a block carries no restraining
code because a restraining code means it was not a block.

### What this class cannot do

It cannot enforce. §91 separates the authority from the executor, and the
separation is real: there is no enforcer, no `security.firewall` import, and no
attribute anywhere in this file that could hold one. The authority returns a
record; something else decides whether it has the privilege to act on it.
"""
from dataclasses import dataclass, field, replace
import time

from ..compatibility import FEATURE_SCHEMA
from . import record as codes
from .breakers import BreakerPanel
from .cost import CostPolicy
from .evidence import ANOMALY, ML_CLASSIFIER, SignalFamilies
from .maturity import MaturityPolicy
from .maturity import evaluate as maturity_of
from .record import (ALLOW, ASSUMPTION_NAMES, AssumptionRegistry,
                     AutonomousDecisionRecord, MAX_BLOCK_TTL_SECONDS, TEMP_BLOCK,
                     new_decision_id, pseudonym)
from .uncertainty import assess, evaluate

AUTHORITY_VERSION = 'autonomous-decision-authority-v1'

#: Runtime modes. `shadow` computes the same decision and records it without any
#: expectation that it will be enforced (§191).
AUTONOMOUS = 'autonomous'
SHADOW = 'shadow'
MODES = (AUTONOMOUS, SHADOW)


@dataclass(frozen=True, slots=True)
class DecisionGates:
    """The minimum evidence a block requires (§38, §120).

    Every number here is a floor on *the system's willingness to act*, not a
    tuned detector threshold. They were chosen conservatively and without
    deployment data, which is stated rather than hidden: an operator who raises
    them is being more careful, and one who lowers them should know they are
    spending the project's safety margin.
    """

    minimum_observations: int = 20
    minimum_observation_seconds: float = 10.0
    minimum_data_quality: float = 0.55
    #: Distinct evidence families, counting model opinion (§22).
    minimum_signal_diversity: int = 3
    #: Of those, how many must describe what the source *did* (§86).
    minimum_behavioural_diversity: int = 2
    #: Total decision uncertainty above which no block is taken (§34).
    maximum_uncertainty: float = 0.60
    #: Escalating block durations (§46). Bounded by MAX_BLOCK_TTL_SECONDS, and
    #: uncalibrated: these are the durations `config.py` already ships, kept
    #: rather than invented so P15 adds no new unvalidated numbers.
    block_ttl_ladder: tuple = (300, 1800, 7200, 43_200)

    def __post_init__(self):
        if not self.block_ttl_ladder:
            raise ValueError('at least one block duration is required')
        if any(not 0 < value <= MAX_BLOCK_TTL_SECONDS for value in self.block_ttl_ladder):
            raise ValueError(f'block durations must be within {MAX_BLOCK_TTL_SECONDS}s')
        if list(self.block_ttl_ladder) != sorted(self.block_ttl_ladder):
            raise ValueError('block durations must escalate')
        if not 0 <= self.minimum_data_quality <= 1 or not 0 <= self.maximum_uncertainty <= 1:
            raise ValueError('quality and uncertainty gates are fractions')
        if self.minimum_behavioural_diversity > self.minimum_signal_diversity:
            raise ValueError('behavioural diversity cannot exceed total diversity')

    def ttl_for(self, offences):
        """§46: longer for repeats, capped. Never permanent, at any count."""
        index = min(max(0, int(offences)), len(self.block_ttl_ladder) - 1)
        return min(MAX_BLOCK_TTL_SECONDS, int(self.block_ttl_ladder[index]))

    def explain(self):
        return {'minimum_observations': self.minimum_observations,
                'minimum_observation_seconds': self.minimum_observation_seconds,
                'minimum_data_quality': self.minimum_data_quality,
                'minimum_signal_diversity': self.minimum_signal_diversity,
                'minimum_behavioural_diversity': self.minimum_behavioural_diversity,
                'maximum_uncertainty': self.maximum_uncertainty,
                'block_ttl_ladder': list(self.block_ttl_ladder),
                'maximum_block_ttl_seconds': MAX_BLOCK_TTL_SECONDS}


@dataclass(frozen=True, slots=True)
class DecisionInputs:
    """Everything the authority is told, assembled from engines that already ran.

    Deliberately a plain value: it can be built in a test, replayed from a PCAP
    run, or constructed by the sensor, and the algorithm cannot tell the
    difference. Every field that could be missing defaults to the value that
    argues *against* acting, so a caller that forgets to wire something up gets
    an ALLOW rather than a block founded on a default.
    """

    source: str
    scope: str = 'GLOBAL'
    site_id: str = ''

    # Policy context
    protected: bool = False
    management: bool = False

    # Identity (§39, §40)
    identity_confidence: str = 'LOW'
    identity_origin: str = ''
    network_enforceable: bool = False
    enforcement_scope: str = 'UNKNOWN'

    # Observation window
    feature_schema_version: int = 1
    observations: int = 0
    observation_seconds: float = 0.0
    data_quality: float | None = None
    features_finite: bool = True

    # Deterministic evidence
    math_risk: float = 0.0
    math_version: str = ''
    math_contributions: dict = field(default_factory=dict)
    #: P15.4. Every family the engine *observed*, above its floor — including
    #: the ones that may corroborate but never carry. Diversity is counted from
    #: this rather than from the composition's own terms, because "observed" and
    #: "allowed to convict alone" are different questions. Empty under v3, where
    #: `math_contributions` was the only account available.
    math_family_scores: dict = field(default_factory=dict)
    web_math_risk: float | None = None
    persistence: float = 0.0

    # Learned evidence
    ml_usable: bool = False
    ml_model_version: str = 'none'
    ml_status: str = 'not_loaded'
    model_score: float | None = None
    calibrated: bool = False
    calibrated_probability: float | None = None
    #: The calibrator's Wilson lower bound on that probability, over its own
    #: fitting sample. P15.2: the quantity P15's width term was reaching for,
    #: computed over the sample size it actually belongs to.
    calibrated_lower: float | None = None
    calibration_version: str = ''
    model_artifact_valid: bool = True
    anomaly_score: float | None = None
    ood_score: float | None = None
    ood_status: str = 'INSUFFICIENT_REFERENCE'
    drift_status: str = 'STABLE'
    model_health: str = 'HEALTHY'
    model_disagreement: float | None = None

    # Runtime state
    offence_count: int = 0
    existing_block: bool = False
    enforcement_healthy: bool = True
    clock_sane: bool = True

    # PolicyGuard, which ran before this and can only ever weaken (§42)
    policy_guard_action: str = ''
    policy_guard_reasons: tuple = ()


class AutonomousDecisionAuthority:
    """The final authority for ALLOW / TEMP_BLOCK. Holds no enforcement power.

    One instance per runtime. It owns the cost policy, the gates and the breaker
    panel, and it owns no connection to anything that can change the world.
    """

    #: Structural, and asserted by `tests/test_p15_invariants.py`: an authority
    #: that could enforce would make §91's separation a naming convention.
    has_enforcement_privilege = False

    def __init__(self, *, cost_policy=None, gates=None, panel=None,
                 enabled=False, mode=SHADOW, pseudonym_secret=None,
                 maturity=None, clock=time.monotonic):
        self.version = AUTHORITY_VERSION
        self.cost_policy = cost_policy or CostPolicy()
        self.gates = gates or DecisionGates()
        #: P15.4. How much observation is enough, with more than one answer.
        #: Its standard road reproduces `gates` exactly, so the default
        #: behaviour of this object is unchanged for anything that already
        #: matured.
        self.maturity = maturity or MaturityPolicy(
            minimum_observations=self.gates.minimum_observations,
            minimum_observation_seconds=self.gates.minimum_observation_seconds,
            minimum_data_quality=self.gates.minimum_data_quality)
        self.panel = panel or BreakerPanel(clock=clock)
        #: Off until an administrator turns it on (§103, §185). Enabled or not,
        #: the algorithm runs and records; only the action it is willing to
        #: return changes.
        self.enabled = bool(enabled)
        self.mode = mode if mode in MODES else SHADOW
        self.pseudonym_secret = pseudonym_secret
        self.counters = {'total': 0, 'allow': 0, 'block': 0, 'suppressed': 0}
        #: §38, §39. Which assumption refused a block the arithmetic wanted,
        #: counted per assumption. Bounded by construction: the keys are
        #: `ASSUMPTION_NAMES` and nothing else can be added, so no source
        #: address, scope or schema number can ever become a metric label.
        #:
        #: The count exists because of how P15.4 presented. Every gate agreed on
        #: every one of 889 windows, one assumption refused all of them, and the
        #: only visible symptom was a recall of zero on a benchmark that ran
        #: days later. "Blocks suppressed" was already counted; *which
        #: assumption suppressed them* was not, and that is the number that
        #: turns a silent failure into an alarm.
        self.suppressed_by = {name: 0 for name in ASSUMPTION_NAMES}

    # -- state ---------------------------------------------------------------

    @property
    def safe_mode(self):
        return self.panel.safe_mode

    def enter_safe_mode(self, fault, detail=''):
        """§55 and §192. Automatic; no administrator is waited for."""
        self.panel.technical.fault(fault, detail)
        return self

    def resolve_fault(self, fault):
        """§54. Clearing a fault starts a cooldown, it does not end one (§194)."""
        self.panel.technical.resolve(fault)
        return self

    def activate(self, *, mode=AUTONOMOUS):
        self.enabled = True
        self.mode = mode if mode in MODES else SHADOW
        return self

    def deactivate(self):
        """§189's kill switch, from this side. Local, immediate, no cloud."""
        self.enabled = False
        self.mode = SHADOW
        return self

    # -- the algorithm -------------------------------------------------------

    def decide(self, inputs):
        """Return an `AutonomousDecisionRecord`. Never raises on bad evidence.

        A malformed input produces an ALLOW that says the assumption failed,
        because the alternative — an exception on the decision path — would mean
        the caller decides what to do about it, and the caller is not the place
        that rule belongs.
        """
        self.counters['total'] += 1
        self.panel.observe_source(inputs.source)
        assumptions = self._assumptions(inputs)
        families = self._families(inputs)
        doubt = self._uncertainty(inputs)
        probability, calibrated = self._probability(inputs)
        profile = self._profile(inputs, assumptions)
        margin = self._margin(inputs)
        loss = evaluate(probability=probability, uncertainty=doubt, profile=profile,
                        margin=margin, calibrated=calibrated,
                        calibrated_lower=self._calibrated_lower(inputs, calibrated))

        supporting = self._supporting_codes(inputs, families, loss, doubt)
        restraints, gates = self._restraints(inputs, families, loss, doubt,
                                             assumptions, profile)
        block = not restraints
        ttl = self.gates.ttl_for(inputs.offence_count) if block else 0
        shadow = self.mode != AUTONOMOUS or not self.enabled

        if block:
            self.counters['block'] += 1
            self.panel.record_block(enforced=not shadow)
        else:
            self.counters['allow'] += 1
            if self._was_arithmetically_eligible(loss, supporting):
                self.counters['suppressed'] += 1
                for name in assumptions.blocking_failures:
                    if name in self.suppressed_by:
                        self.suppressed_by[name] += 1

        # Ordered and deduplicated: two gates can reach for the same code, and a
        # record that said "too few independent evidence families" twice would
        # read as two findings rather than one.
        reasons = tuple(dict.fromkeys(supporting + restraints))[:16]
        return AutonomousDecisionRecord(
            action=TEMP_BLOCK if block else ALLOW,
            decision_id=new_decision_id(),
            scope=inputs.scope, site_id=inputs.site_id,
            source=inputs.source,
            source_pseudonym=pseudonym(inputs.source, self.pseudonym_secret),
            identity_confidence=inputs.identity_confidence,
            identity_origin=inputs.identity_origin,
            network_enforceable=inputs.network_enforceable,
            enforcement_scope=inputs.enforcement_scope,
            feature_schema_version=inputs.feature_schema_version,
            observations=inputs.observations,
            observation_seconds=inputs.observation_seconds,
            math_risk=inputs.math_risk, math_version=inputs.math_version,
            math_contributions=self._top_contributions(inputs.math_contributions),
            web_math_risk=inputs.web_math_risk, persistence=inputs.persistence,
            ml_model_version=inputs.ml_model_version, ml_status=inputs.ml_status,
            model_score=inputs.model_score, calibrated=calibrated,
            calibrated_probability=inputs.calibrated_probability,
            calibration_version=inputs.calibration_version,
            anomaly_score=inputs.anomaly_score, ood_score=inputs.ood_score,
            ood_status=inputs.ood_status, drift_status=inputs.drift_status,
            model_health=inputs.model_health,
            data_quality=float(inputs.data_quality or 0.0),
            uncertainty=doubt.explain(), signal_families=families.explain(),
            signal_diversity=families.diversity,
            behavioural_diversity=families.behavioural_diversity,
            probability=loss.probability,
            conservative_probability=loss.conservative_probability,
            loss_allow=loss.loss_allow, loss_block=loss.loss_block,
            threshold=loss.threshold, decision_margin=margin,
            cost_profile=profile.name,
            cost_policy_version=self.cost_policy.version,
            cost_policy_digest=self.cost_policy.digest[:16],
            safety_gates=gates,
            failed_assumptions=assumptions.blocking_failures,
            failed_subsystems=assumptions.subsystems(),
            policy_guard_action=inputs.policy_guard_action,
            policy_guard_reasons=tuple(inputs.policy_guard_reasons)[:8],
            block_ttl_seconds=ttl, offence_count=inputs.offence_count,
            reason_codes=reasons,
            mode=self.mode, shadow=shadow, enforced=False)

    # -- the pieces ----------------------------------------------------------

    def _assumptions(self, inputs):
        """§118. What this decision needed, and whether it held."""
        registry = AssumptionRegistry()
        # Membership of the schemas this build can serve, never a pinned literal.
        #
        # This was `== 1`, and it is the same defect `decision.policy.usable_ml`
        # documents having already been fixed for: a literal that stopped meaning
        # "a schema we understand" the moment schema 2 appended a column. Its
        # twin here was missed, and the consequence was total — this assumption
        # failed on every window of every source, `ASSUMPTION_FAILED` refused
        # every block, and the system could not act at all.
        #
        # It is what the P15.4 locked benchmark found. Every gate agreed: cost,
        # margin, signal diversity, data quality, identity, model health,
        # observations, a conservative bound of 0.981951 against a cutoff of
        # 0.975610 — and one assumption comparing an integer to 1 refused all
        # 889 of them. Safe and useless, which is the exact failure the
        # `calibrated_estimate` gate below was made hard to prevent, arriving by
        # a different road.
        registry.record('feature_schema_compatible',
                        FEATURE_SCHEMA.supports(inputs.feature_schema_version),
                        f'schema {inputs.feature_schema_version}')
        registry.record('features_finite', inputs.features_finite)
        registry.record('model_calibrated', bool(inputs.calibrated),
                        '' if inputs.calibrated else 'classifier output is a score')
        registry.record('model_artifact_valid', bool(inputs.model_artifact_valid))
        registry.record('client_identity_resolvable',
                        inputs.identity_confidence == 'HIGH' and inputs.network_enforceable,
                        f'confidence {inputs.identity_confidence}')
        registry.record('minimum_sample_mature',
                        inputs.observations >= self.gates.minimum_observations
                        and inputs.observation_seconds >= self.gates.minimum_observation_seconds,
                        f'{inputs.observations} observations')
        registry.record('cost_policy_available', True)
        registry.record('enforcement_healthy', bool(inputs.enforcement_healthy))
        registry.record('clock_sane', bool(inputs.clock_sane))
        registry.record('data_quality_measured', inputs.data_quality is not None)
        return registry

    def _families(self, inputs):
        """§22, §23. Families, not features, and each counted once.

        Diversity counts every family that was **observed**, which is a wider
        set than the families allowed to *carry* a case. `NETWORK_RATE`,
        `TIMING` and `PERSISTENCE` may not convict alone — they describe how a
        client ran rather than what it did, and every automated client on the
        network produces them — but they are real, independent observations, and
        "several weak families agreeing" is exactly what signal diversity exists
        to measure.

        Reading diversity only out of the composition's own terms would exclude
        them, which is the P15.3 defect rebuilt one storey up: a gate asked to
        count families the engine had already declined to hand it.
        """
        families = SignalFamilies()
        families.record_contributions(inputs.math_family_scores or inputs.math_contributions)
        if inputs.math_family_scores:
            # Interaction terms still credit their halves, so a pair cannot be
            # overlooked — and cannot be the sole reason a family is counted,
            # because a pair only exists when both halves already scored.
            families.record_contributions({name: value for name, value
                                           in (inputs.math_contributions or {}).items()
                                           if '+' in name})
        if inputs.ml_usable and inputs.model_score is not None:
            families.record(ML_CLASSIFIER, inputs.model_score, witness='classifier')
        if inputs.anomaly_score is not None:
            families.record(ANOMALY, inputs.anomaly_score, witness='anomaly')
        return families

    def _uncertainty(self, inputs):
        return assess(calibrated=inputs.calibrated,
                      ood_score=inputs.ood_score,
                      data_quality_score=inputs.data_quality,
                      model_health=inputs.model_health,
                      observations=inputs.observations,
                      model_disagreement=inputs.model_disagreement,
                      drift_status=inputs.drift_status)

    def _probability(self, inputs):
        """The estimate the cost model is given, and whether it is a probability.

        §19 and §20 are the whole of this method. A calibrated classifier gives a
        probability and it is used as one. An uncalibrated one gives a *score*,
        and a score fed into an expected-loss calculation is a number pretending
        to be a probability — so the deterministic engine carries the estimate
        instead, and the classifier's opinion survives only as a signal family
        and as corroboration. `MathRisk` is itself explicitly uncalibrated, so
        this is a fallback that keeps the arithmetic honest about its inputs,
        not one that claims to be as good.
        """
        if inputs.calibrated and inputs.calibrated_probability is not None:
            return max(0.0, min(1.0, float(inputs.calibrated_probability))), True
        return max(0.0, min(1.0, float(inputs.math_risk))), False

    def _calibrated_lower(self, inputs, calibrated):
        """The calibrator's own Wilson lower bound, when there is one.

        `None` for every uncalibrated decision, which keeps the P15 arithmetic
        exactly as it was on the path that still uses it — and that path cannot
        block, because `calibrated_estimate` gates above it.

        A calibrated estimate with no bound also returns `None` and therefore
        falls back to the shrinkage, which in practice means no block. That is
        the intended reading of §79: an artifact that ships a point estimate and
        no interval has not said how sure it is, and "I am not saying" is not a
        reason to deny somebody a service.
        """
        if not calibrated:
            return None
        bound = getattr(inputs, 'calibrated_lower', None)
        if bound is None:
            return None
        value = max(0.0, min(1.0, float(bound)))
        estimate = float(inputs.calibrated_probability or 0.0)
        return min(value, max(0.0, min(1.0, estimate)))

    def _profile(self, inputs, assumptions):
        try:
            return self.cost_policy.for_scope(inputs.scope)
        except Exception:
            assumptions.record('cost_policy_available', False, 'scope has no profile')
            return self.cost_policy.profiles[self.cost_policy.default_profile]

    def _margin(self, inputs):
        """§121, §122. The bar, and the slightly lower bar for a known repeat.

        Hysteresis here means: a source that has already been blocked inside the
        offence window does not have to re-clear the full margin on every
        adjacent window, which is what makes a borderline source flap in and out
        of enforcement. It lowers one number and nothing else — every gate below
        still applies at full strength, so a repeat offender with weak evidence
        is still allowed.
        """
        if inputs.offence_count > 0:
            return self.cost_policy.release_margin
        return self.cost_policy.decision_margin

    def _supporting_codes(self, inputs, families, loss, doubt):
        """What argued for acting. Behaviour first; model opinion is never alone."""
        found = []
        for family in families.active:
            code = codes.FAMILY_CODES.get(family)
            if code:
                found.append(code)
        if loss.block_arithmetically_preferred:
            found.append(codes.COST_BLOCK_PREFERRED)
        if loss.relative_advantage >= loss.margin and loss.block_arithmetically_preferred:
            found.append(codes.MARGIN_SATISFIED)
        if inputs.ood_status == 'IN_DISTRIBUTION':
            found.append(codes.LOW_OOD)
        if (inputs.data_quality or 0.0) >= self.gates.minimum_data_quality:
            found.append(codes.HIGH_DATA_QUALITY)
        if inputs.identity_confidence == 'HIGH' and inputs.network_enforceable:
            found.append(codes.IDENTITY_CONFIRMED)
        if families.behavioural_diversity >= self.gates.minimum_behavioural_diversity:
            found.append(codes.SIGNAL_DIVERSITY_MET)
        if inputs.model_health == 'HEALTHY' and inputs.drift_status != 'DRIFTED':
            found.append(codes.MODEL_HEALTHY)
        if inputs.offence_count > 0:
            found.append(codes.REPEAT_OFFENCE)
        return found

    def _restraints(self, inputs, families, loss, doubt, assumptions, profile):
        """Every reason not to block, collected. One of these means ALLOW.

        The §43 order is preserved in the sequence of checks, so the record reads
        top-down the way the rule does, but nothing returns early: an operator
        looking at an ALLOW wants all the reasons, not the first one.
        """
        found = []
        gates = {}

        def gate(name, passed, code):
            gates[name] = bool(passed)
            if not passed:
                found.append(code)

        # Switched off, or shadow: both still compute and record. Neither is a
        # restraint on the *decision* — §105 wants the honest counterfactual —
        # so they are gates for the record and not reasons in it.
        gates['autonomy_enabled'] = self.enabled
        gates['mode'] = self.mode == AUTONOMOUS

        # §43, in order.
        gate('not_protected', not (inputs.protected or inputs.management),
             codes.MANAGEMENT_NETWORK if inputs.management else codes.PROTECTED_SOURCE)
        gate('identity_certain', inputs.identity_confidence == 'HIGH',
             codes.IDENTITY_UNCERTAIN)
        # §40 and §178: the address we know is behind somebody else's
        # infrastructure, so a network block hits every other client on it.
        gate('network_enforceable', inputs.network_enforceable,
             codes.NOT_NETWORK_ENFORCEABLE)
        gate('enforcement_scope', inputs.enforcement_scope == 'NETWORK_SOURCE',
             codes.SHARED_PROXY_RISK)
        gate('data_quality', (inputs.data_quality or 0.0) >= self.gates.minimum_data_quality,
             codes.INSUFFICIENT_DATA_QUALITY)
        # P15.4. One question — is there enough observation to act? — with three
        # ways to answer it rather than one. The standard road is the P15.3 rule
        # unchanged, so nothing that matured before stops maturing; the other two
        # exist because a source that spreads itself thinly enough never
        # accumulates twenty of anything in one window, and patience was
        # therefore a defence. `maturity.py` carries the reasoning, and the two
        # numbers this used to check are still exactly where they were.
        maturity = maturity_of(
            observations=inputs.observations,
            observation_seconds=inputs.observation_seconds,
            data_quality=inputs.data_quality,
            families=families.active,
            policy=self.maturity)
        gate('evidence_maturity', maturity.mature,
             codes.INSUFFICIENT_OBSERVATIONS
             if inputs.observations < self.gates.minimum_observations
             else codes.INSUFFICIENT_OBSERVATION_TIME)
        gate('signal_diversity', families.diversity >= self.gates.minimum_signal_diversity,
             codes.INSUFFICIENT_SIGNAL_DIVERSITY)
        # §86. Two models agreeing about one feature vector is one opinion. The
        # code distinguishes the two ways this fails: model opinion standing on
        # its own, and simply not enough behaviour — a reader of the record
        # should not have to guess which happened.
        gate('behavioural_evidence',
             families.behavioural_diversity >= self.gates.minimum_behavioural_diversity,
             codes.MODEL_ONLY_EVIDENCE if families.model_only
             else codes.INSUFFICIENT_SIGNAL_DIVERSITY)
        # §27, §82. Not guilt: the classifier simply knows less here.
        gate('in_distribution', inputs.ood_status != 'OUT_OF_DISTRIBUTION', codes.HIGH_OOD)
        gate('model_health', inputs.model_health in ('HEALTHY', 'UNKNOWN'),
             codes.MODEL_UNHEALTHY)
        # §28. Drift is population health, and it withdraws authority rather
        # than adding suspicion.
        gate('no_drift', str(inputs.drift_status).upper() != 'DRIFTED', codes.DRIFT_DEGRADED)
        gate('models_agree',
             inputs.model_disagreement is None or inputs.model_disagreement < 0.5,
             codes.MODEL_DISAGREEMENT)
        gate('uncertainty', doubt.total <= self.gates.maximum_uncertainty,
             codes.UNCERTAINTY_HIGH)
        # §19, §20, and the P15.1 measurement that made this a hard gate rather
        # than a caveat. The cutoff is `C_FP / (C_FP + C_FN)` — a *probability*
        # of maliciousness at which blocking becomes the cheaper error. Comparing
        # an uncalibrated score to it is a units error: the two numbers live on
        # different scales and their ordering means nothing.
        #
        # P15 shipped this as a soft check, and replaying a trusted labelled
        # corpus through the whole system showed what that cost: the system
        # blocked nothing at all, on any scenario, because the deterministic
        # engine's raw sigmoid never approaches 0.9756. Safe, and useless, and
        # for a reason nobody had written down. It is a hard gate now, so the
        # record says CALIBRATION_UNAVAILABLE instead of leaving an operator to
        # infer it from an absence of blocks.
        gate('calibrated_estimate', inputs.calibrated, codes.CALIBRATION_UNAVAILABLE)
        gate('cost_prefers_block', loss.block_arithmetically_preferred,
             codes.COST_ALLOW_PREFERRED)
        gate('robust_margin', loss.block_robustly_preferred, codes.MARGIN_NOT_MET)
        # §136. Some routes are never network-blocked, at any probability.
        gate('network_block_permitted', profile.network_block_permitted,
             codes.NETWORK_BLOCK_NOT_PERMITTED)
        gate('assumptions', not assumptions.blocking_failures, codes.ASSUMPTION_FAILED)
        gate('enforcement_healthy', inputs.enforcement_healthy, codes.ENFORCEMENT_UNHEALTHY)
        # §42. PolicyGuard sits above this and its refusal is final.
        gate('policy_guard', inputs.policy_guard_action != 'REFUSED',
             codes.POLICY_GUARD_REFUSED)
        gate('no_existing_lease', not inputs.existing_block, codes.EXISTING_BLOCK_LEASE)

        allowed, breaker_code, _ = self.panel.permits_block()
        gates['circuit_breakers'] = allowed
        if not allowed:
            found.append(breaker_code)
            self.panel.budget.refuse()

        if not found and not self.enabled:
            # Nothing refused on the merits; autonomy is simply off. The record
            # says so plainly rather than inventing a safety reason (§105).
            found.append(codes.AUTONOMY_DISABLED)

        # An ALLOW must say something (§89). When every gate passed but the
        # decision is still ALLOW — only possible in the ordering above when
        # autonomy is off — the code above already covers it; this is the
        # last-resort honest answer for any future path.
        if not found and not loss.block_robustly_preferred:
            found.append(codes.COST_ALLOW_PREFERRED)
        return found, gates

    def _was_arithmetically_eligible(self, loss, supporting):
        """Did the arithmetic want a block that a gate then refused? (§157)"""
        return loss.block_arithmetically_preferred and codes.COST_BLOCK_PREFERRED in supporting

    @staticmethod
    def _top_contributions(contributions, count=6):
        items = sorted((contributions or {}).items(), key=lambda item: -item[1])[:count]
        return {name: round(float(value), 5) for name, value in items}

    # -- reporting -----------------------------------------------------------

    def metrics(self):
        """§158. Bounded counters, no source identifier anywhere."""
        body = {'autonomous_decisions_total': self.counters['total'],
                'autonomous_allow_total': self.counters['allow'],
                'autonomous_block_total': self.counters['block']}
        body.update(self.panel.metrics())
        body['autonomous_block_suppressed_total'] += self.counters['suppressed']
        # §38. One series per assumption, and the label set is the frozen
        # `ASSUMPTION_NAMES` tuple — a metric whose labels come from the data
        # rather than from a closed vocabulary is an unbounded cardinality bug
        # waiting for the first hostile source to supply the label.
        for name in ASSUMPTION_NAMES:
            body[f'autonomous_block_suppressed_by_{name}_total'] = self.suppressed_by[name]
        # 0 or 1, not the word. `metrics()` is a counter surface and every
        # value on it has to be a number; the readable state belongs in
        # `status()`, which is where an operator reads prose.
        body['autonomous_assumption_health_degraded'] = int(
            self.assumption_health()['state'] == 'DEGRADED')
        return body

    #: §39. Above this share of suppressed-but-eligible decisions attributable
    #: to a single assumption, health degrades. Not a tuned number: it means
    #: "almost all of them", and the P15.4 failure sat at 1.0.
    MASS_SUPPRESSION_SHARE = 0.9
    #: Below this many eligible-but-suppressed decisions the share is noise. A
    #: single suppressed decision is 100% of one assumption by arithmetic.
    MASS_SUPPRESSION_FLOOR = 20

    def assumption_health(self):
        """§39. Is one assumption refusing nearly everything the maths wanted?

        This is the shape the P15.4 defect had, and it is worth being precise
        about why it needs its own signal. Nothing was unhealthy. No component
        was down, no artifact was corrupt, no gate was misconfigured, and the
        readiness gate passed. The system was *working* — computing evidence,
        reaching the cost threshold, clearing the margin — and then declining to
        act, every single time, for one reason.

        A defender that never blocks looks identical to a defender with nothing
        to block, and the difference is exactly this ratio. `DEGRADED` here does
        not mean a block was wrong; it means the machine is doing all the work
        and one assumption is discarding the result, which is a question for a
        person before it is a question for a benchmark.
        """
        eligible = self.counters['suppressed']
        ranked = sorted(self.suppressed_by.items(), key=lambda item: -item[1])
        dominant, count = ranked[0] if ranked else ('', 0)
        share = (count / eligible) if eligible else 0.0
        degraded = (eligible >= self.MASS_SUPPRESSION_FLOOR
                    and share >= self.MASS_SUPPRESSION_SHARE)
        return {
            'state': 'DEGRADED' if degraded else 'OK',
            'eligible_but_suppressed': eligible,
            'dominant_assumption': dominant if count else '',
            'dominant_share': round(share, 4),
            'threshold_share': self.MASS_SUPPRESSION_SHARE,
            'floor': self.MASS_SUPPRESSION_FLOOR,
            'by_assumption': {name: value for name, value
                              in sorted(self.suppressed_by.items()) if value},
            'meaning': ('DEGRADED means the arithmetic reached a block and a '
                        'single assumption refused nearly all of them. That is '
                        'how the P15.4 schema defect presented: healthy, '
                        'confident, and unable to act'),
        }

    def status(self):
        """§153. What mode the authority is in and what the brakes are doing."""
        return {'authority_version': self.version,
                'enabled': self.enabled, 'mode': self.mode,
                'runtime_state': self.panel.state,
                'gates': self.gates.explain(),
                'cost_policy': self.cost_policy.summary(),
                'breakers': self.panel.explain(),
                'counters': dict(self.counters),
                'assumption_health': self.assumption_health(),
                'has_enforcement_privilege': self.has_enforcement_privilege,
                'note': ('autonomy is an operational property: no human approves '
                         'each decision. It is not a claim about accuracy.')}


def from_config(config, *, panel=None, pseudonym_secret=None):
    """Build an authority from configuration. Disabled unless asked (§187)."""
    from .breakers import from_config as breakers_from_config
    from .cost import from_config as cost_from_config
    settings = getattr(config, 'autonomy', None)
    gates = DecisionGates()
    if settings is not None:
        gates = replace(
            gates,
            minimum_observations=int(getattr(settings, 'minimum_observations',
                                             gates.minimum_observations)),
            minimum_observation_seconds=float(getattr(settings, 'minimum_observation_seconds',
                                                      gates.minimum_observation_seconds)),
            minimum_data_quality=float(getattr(settings, 'minimum_data_quality',
                                               gates.minimum_data_quality)),
            minimum_signal_diversity=int(getattr(settings, 'minimum_signal_diversity',
                                                 gates.minimum_signal_diversity)),
            minimum_behavioural_diversity=int(getattr(settings, 'minimum_behavioural_diversity',
                                                      gates.minimum_behavioural_diversity)),
            maximum_uncertainty=float(getattr(settings, 'maximum_uncertainty',
                                              gates.maximum_uncertainty)))
    enabled = bool(getattr(settings, 'enabled', False)) if settings else False
    mode = getattr(settings, 'mode', SHADOW) if settings else SHADOW
    return AutonomousDecisionAuthority(
        cost_policy=cost_from_config(config), gates=gates,
        panel=panel or breakers_from_config(config),
        enabled=enabled, mode=mode, pseudonym_secret=pseudonym_secret)
