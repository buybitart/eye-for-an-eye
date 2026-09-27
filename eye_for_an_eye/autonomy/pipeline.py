"""The one place a decision is assembled. P15.5R §17, §18, §19, §34.

P15.5 proved the components compose. §1 of this cycle proved the running sensor
does not compose them: `DecisionFusion` decided, `TemporaryBlocks` enforced, and
`AutonomousDecisionAuthority` was imported without ever being instantiated.

This module is the missing component, and its shape follows from one rule — the
rule P15.4 was written in blood to teach:

    **The runtime and the evaluator must assemble the decision with the same
    code, or they are evaluating different products.**

So `decision_inputs` below is not "the runtime's assembly". It is *the*
assembly. `training/decision_replay.py` calls it, `DecisionEngine` calls it, and
the whole-system smoke test calls it through them. A second copy is how the
46-column tensor reached the 36-column model in P15.4 while every unit test
passed, and how the replay harness priced eight corpora at the wrong cutoff
without anybody noticing until the locked benchmark.

### What this owns, and what it deliberately does not

It owns the *order*: scope, calibration, authority, enforcement. It owns none of
the arithmetic. `MathRiskEngine`, `PolicyGuard`, `DataQualityResult`, `OODEngine`
and the anomaly model all run before this and their results arrive as arguments,
exactly as `DecisionInputs` was designed for. Recomputing any of them here would
create a second opinion to keep in sync, which is the defect this cycle exists
to remove rather than to add a fresh instance of.

It also owns no privilege. `AutonomousDecisionAuthority.has_enforcement_privilege`
is `False` and `HostEnforcer.has_firewall_privilege` is `False`; this object sits
between them and holds neither. What it holds is the decision about whether the
record is *allowed* to be handed to the enforcer at all, which is §4 and §30:

    shadow                      -> never
    autonomy disabled           -> never
    no host enforcer configured -> never
    record.blocked is False     -> never
    otherwise                   -> HostEnforcer.execute(record), which may still refuse
"""
from dataclasses import dataclass, field
import time

from ..decision.families import FLOOR as FAMILY_FLOOR
from ..decision.features import NAMES
from ..decision.math_risk import VERSION as MATH_RISK_VERSION
from ..decision.policy import POLICY_GUARD_VERSION, usable_ml
from . import calibrator as calibration_loader
from .authority import AUTONOMOUS, DecisionInputs, SHADOW
from .journal import JOURNAL_SCHEMA_VERSION
from .authority import from_config as authority_from_config
from .cost import from_config as cost_from_config
from .scope import ScopeResolver, services_in

PIPELINE_VERSION = 'autonomous-decision-pipeline-v1'

#: §20's four component states, named once.
NOT_CONFIGURED = calibration_loader.NOT_CONFIGURED
HEALTHY = calibration_loader.HEALTHY
DEGRADED = calibration_loader.DEGRADED
UNAVAILABLE = calibration_loader.UNAVAILABLE


def persistence_of(vector):
    """The persistence term the fusion and the authority both use.

    One expression rather than two identical ones in two files. It looks like
    over-engineering until the day somebody changes the 300 in one of them.
    """
    values = dict(zip(NAMES, vector.values))
    return min(1.0, (values['persistence_900s'] or 0) / 300)


def carrying_families(math_result):
    """Every family the engine observed above its floor, carrying or not.

    Signal diversity is counted from this rather than from the composition's
    terms, because "observed" and "allowed to convict alone" are different
    questions — see `authority._families`.
    """
    return {name: value for name, value in (math_result.family_scores or {}).items()
            if value is not None and value >= FAMILY_FLOOR}


def decision_inputs(*, source, vector, math_result, ml, quality, resolution,
                    calibration=None, ood=None, anomaly=None,
                    identity_confidence='HIGH', identity_origin='direct_peer',
                    network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
                    protected=False, management=False,
                    offence_count=0, existing_block=False,
                    enforcement_healthy=True, clock_sane=True,
                    policy_guard_action='ALLOW', policy_guard_reasons=(),
                    model_health=''):
    """Assemble `DecisionInputs` from engines that already ran. The only copy.

    Every argument is a result, never an engine: this function computes nothing
    that a component upstream of it already computed, so there is no second
    opinion for the two callers to drift apart on.

    The defaults are the P15 defaults — each field that could be missing takes
    the value that argues *against* acting — so a caller that forgets to wire
    something up gets an ALLOW rather than a block founded on a default.
    """
    anomaly_usable = anomaly is not None and getattr(anomaly, 'usable', False)
    ood_usable = ood is not None and getattr(ood, 'usable', False)
    calibrated = calibration is not None
    return DecisionInputs(
        source=source,
        scope=resolution.scope,
        site_id=resolution.site_id,
        protected=bool(protected),
        management=bool(management),
        identity_confidence=identity_confidence,
        identity_origin=identity_origin,
        network_enforceable=bool(network_enforceable),
        enforcement_scope=enforcement_scope,
        # The vector's own schema, asked of the vector. P15.4's defect was a
        # literal here; P15.5's contract is what makes the literal unnecessary.
        feature_schema_version=vector.schema_version,
        observations=vector.sample_count,
        observation_seconds=vector.observation_seconds,
        data_quality=quality.score if quality is not None else None,
        math_risk=math_result.score,
        math_version=math_result.model_version,
        math_contributions=dict(math_result.contributions),
        math_family_scores=carrying_families(math_result),
        persistence=persistence_of(vector),
        ml_usable=usable_ml(ml),
        ml_model_version=ml.model_version,
        ml_status=ml.status,
        model_score=ml.risk_score if usable_ml(ml) else None,
        # §10. `calibration` is `None` whenever the calibrator is absent,
        # incompatible or carries no conservative bound, and `None` here means
        # `calibrated=False`, which the authority's `calibrated_estimate` gate
        # turns into a refusal. The raw MathRisk score never arrives as a
        # probability by this route, because this route has no branch that
        # would let it.
        calibrated=calibrated,
        calibrated_probability=float(calibration) if calibrated else None,
        calibrated_lower=calibration.lower if calibrated else None,
        calibration_version=calibration.calibrator_version if calibrated else '',
        anomaly_score=anomaly.anomaly_score if anomaly_usable else None,
        ood_score=ood.score if ood_usable else None,
        ood_status=getattr(ood, 'status', 'INSUFFICIENT_REFERENCE')
                   if ood is not None else 'INSUFFICIENT_REFERENCE',
        drift_status='STABLE',
        model_health=model_health or ('HEALTHY' if usable_ml(ml) else 'UNKNOWN'),
        offence_count=int(offence_count),
        existing_block=bool(existing_block),
        enforcement_healthy=bool(enforcement_healthy),
        clock_sane=bool(clock_sane),
        policy_guard_action=policy_guard_action,
        policy_guard_reasons=tuple(policy_guard_reasons)[:8])


@dataclass(frozen=True, slots=True)
class PipelineOutcome:
    """One window's decision, with everything a reader needs to re-derive it."""

    record: object
    resolution: object
    calibrated: bool
    execution: object = None
    #: Why the enforcer was not called, when it was not. Empty when it was, or
    #: when the record was an ALLOW and there was nothing to enforce.
    enforcement_withheld: str = ''

    @property
    def blocked(self):
        return bool(self.record.blocked)

    @property
    def enforced(self):
        return bool(self.execution is not None and self.execution.succeeded)

    @property
    def actual_action(self):
        """What happened, as distinct from what was decided.

        `record.action` is the decision; this is its consequence. In shadow they
        differ on every block, and that difference is the whole reason a shadow
        deployment exists.
        """
        return 'TEMP_BLOCK' if self.enforced else 'NONE'

    def explain(self):
        """Everything, for the decision journal and the shadow export.

        `would_action` and `actual_action` are derived here rather than left to
        the reader. P15S §7: a journal entry has to explain on its own that the
        decision was TEMP_BLOCK, that nothing happened, and why. "The export row
        for the same decision id also carries it" is not a property of the
        entry, and the journal is the file this project calls canonical.
        """
        body = {'pipeline_version': PIPELINE_VERSION,
                'decision': self.record.explain(),
                'cost_scope': self.resolution.explain(),
                'calibrated': self.calibrated,
                'would_action': self.record.action,
                'actual_action': self.actual_action,
                'enforcement_withheld': self.enforcement_withheld,
                'policy_guard_version': POLICY_GUARD_VERSION}
        if self.execution is not None:
            body['enforcement'] = self.execution.explain()
        return body

    def summary(self):
        """The bounded form that fits in one log line. P15.5R.

        `serialize_event` refuses any log record over 4096 bytes and replaces
        its observations with `{'record_truncated': True}` — the whole record,
        not the verbose parts of it. A full `explain()` is several times that, so
        putting one in a DECISION event meant the operator-facing log lost the
        action, the address and the reasons as well as the detail. A decision
        record that answers "why was this blocked" only when it is short is not
        one an operator can rely on six months later.

        So the event carries this, and the journal carries `explain()`. What
        survives here is what a person reads first: what was decided, at which
        cutoff, on what probability, and why it was or was not enforced.
        """
        record = self.record
        return {
            'pipeline_version': PIPELINE_VERSION,
            'decision_id': record.decision_id,
            'action': record.action,
            'blocked': bool(record.blocked),
            'shadow': bool(record.shadow),
            'block_ttl_seconds': record.block_ttl_seconds,
            'reason_codes': list(record.reason_codes)[:10],
            'failed_assumptions': list(record.failed_assumptions)[:6],
            'scope': self.resolution.scope,
            'site_id': self.resolution.site_id,
            'cost_profile': self.resolution.profile.name,
            'threshold': round(self.resolution.profile.threshold, 6),
            'network_block_permitted': self.resolution.profile.network_block_permitted,
            'calibrated': self.calibrated,
            'calibrated_probability': record.calibrated_probability,
            'conservative_probability': round(record.conservative_probability, 6),
            'signal_diversity': record.signal_diversity,
            'behavioural_diversity': record.behavioural_diversity,
            'evidence_band': record.evidence_band,
            'enforcement_withheld': self.enforcement_withheld,
            'enforced': bool(self.enforced),
            'policy_guard_version': POLICY_GUARD_VERSION,
            # §3. Where the complete record is, named in the summary so that a
            # reader of one line knows the rest exists and where to look.
            'full_record': {'journal_schema_version': JOURNAL_SCHEMA_VERSION,
                            'find_by': 'decision_id',
                            'configured_at': 'autonomy.decision_journal_path'},
        }


@dataclass(frozen=True, slots=True)
class FailedOutcome:
    """The pipeline did not produce a decision — which is not a decision to allow.

    A separate type rather than a `PipelineOutcome` carrying an ALLOW, because
    the two are different facts and a reader six months later must be able to
    tell them apart. An ALLOW means the authority considered this window and
    declined to act. This means nobody considered it, and the only safe thing to
    do with a window nobody considered is nothing.
    """

    reason: str
    record: object = None
    resolution: object = None
    calibrated: bool = False
    execution: object = None
    enforcement_withheld: str = 'autonomous_pipeline_failed'

    @property
    def blocked(self):
        return False

    @property
    def enforced(self):
        return False

    def explain(self):
        return {'pipeline_version': PIPELINE_VERSION, 'status': 'FAILED',
                'reason': self.reason,
                'enforcement_withheld': self.enforcement_withheld,
                'meaning': ('the decision path raised; no decision was taken for '
                            'this window and nothing was enforced')}

    def summary(self):
        return self.explain()


class AutonomousDecisionPipeline:
    """Scope, calibrate, decide, and hand over — in that order, once.

    One instance per runtime, built by `from_config`. It is constructed even in
    shadow mode and even without a calibrator, because a pipeline that refuses
    to exist when it cannot act is a pipeline nobody can inspect on the day it
    is not acting.
    """

    version = PIPELINE_VERSION

    #: Structural, and asserted by `tests/test_p15_5r_single_authority.py`. This
    #: object decides *whether* the enforcer may be called; it can no more
    #: change a firewall than the authority can.
    has_firewall_privilege = False

    def __init__(self, *, authority, cost_policy, calibrator_state=None,
                 enforcer=None, journal=None, shadow_export=None,
                 clock=time.monotonic):
        self.authority = authority
        self.cost_policy = cost_policy
        self.scopes = ScopeResolver(cost_policy)
        self.calibrator_state = calibrator_state or calibration_loader.CalibratorState(
            status=NOT_CONFIGURED, reason='no calibrator was supplied')
        self.enforcer = enforcer
        #: P15.5R §2, §3. The canonical full record. `None` means the operator
        #: did not ask for one, which is the default and a supported state.
        self.journal = journal
        #: P15.5R §8-§11. Analytic rows for independent evaluation, from the
        #: same outcomes. Also `None` by default.
        self.shadow_export = shadow_export
        #: What the runtime last reported about its optional components, copied
        #: into each export row. Set by `DecisionEngine`, which is where those
        #: states are known; empty until it does, which is honest rather than a
        #: guess.
        self._component_health = {}
        self.clock = clock
        self.counters = {'decisions': 0, 'blocks': 0, 'shadow_blocks': 0,
                         'enforced': 0, 'enforcement_refused': 0,
                         'enforcement_failed': 0, 'enforcement_withheld': 0,
                         'journalled': 0, 'journal_failures': 0,
                         'exported': 0, 'export_failures': 0}

    # -- state ---------------------------------------------------------------

    @property
    def enabled(self):
        return bool(self.authority.enabled)

    @property
    def mode(self):
        return self.authority.mode

    @property
    def shadow(self):
        """True whenever a TEMP_BLOCK record may not be handed to an enforcer."""
        return self.authority.mode != AUTONOMOUS or not self.authority.enabled

    @property
    def owns_enforcement(self):
        """Whether this pipeline is the deployment's single block authority.

        §2 and §4: when it is, no other runtime path may reach host enforcement,
        and `DecisionEngine` does not construct the legacy enforcer at all. This
        is true whenever autonomy is enabled — including in shadow mode, where
        the answer is that *nothing* enforces, which is still one authority.
        """
        return bool(self.authority.enabled)

    # -- the decision --------------------------------------------------------

    def decide(self, *, source, vector, math_result, ml, quality, services=(),
               site_id='', declared_scope='', ood=None, anomaly=None, protected=False,
               management=False, offence_count=0, existing_block=False,
               enforcement_healthy=True, clock_sane=True,
               policy_guard_action='ALLOW', policy_guard_reasons=(),
               network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
               identity_confidence='HIGH', identity_origin='direct_peer',
               model_health=''):
        """One window, from scope to a record and — where allowed — a request.

        `services` is a tuple of scope strings, not correlation samples. The
        caller derives them with `scope.services_in` where the window is, because
        the asynchronous classifier path reaches this from `poll()` — by which
        time the correlation state has moved on and the samples that produced
        this vector are no longer the samples in the cache.
        """
        resolution = self.scopes.resolve(site_id=site_id, services=services,
                                         declared=declared_scope)
        calibration = calibration_loader.calibrated_probability(
            self.calibrator_state, math_risk=math_result.score)
        inputs = decision_inputs(
            source=source, vector=vector, math_result=math_result, ml=ml,
            quality=quality, resolution=resolution, calibration=calibration,
            ood=ood, anomaly=anomaly, protected=protected, management=management,
            offence_count=offence_count, existing_block=existing_block,
            enforcement_healthy=enforcement_healthy, clock_sane=clock_sane,
            policy_guard_action=policy_guard_action,
            policy_guard_reasons=policy_guard_reasons,
            network_enforceable=network_enforceable,
            enforcement_scope=enforcement_scope,
            identity_confidence=identity_confidence,
            identity_origin=identity_origin, model_health=model_health)
        record = self.authority.decide(inputs)
        self.counters['decisions'] += 1
        if record.blocked:
            self.counters['blocks'] += 1

        # §3. The journal is written *before* the enforcement attempt, so a
        # block that lands always has a record that preceded it rather than one
        # that raced it. The outcome journalled here carries no execution result
        # yet; the amendment below adds one, and the entry written here is the
        # one that survives if the process dies between the two.
        #
        # P15S §7. The reason no enforcer will be called is knowable *before*
        # the call in every case where there will not be one — not a block, in
        # shadow, or no enforcer configured — so it goes in the first entry
        # rather than in an amendment that, in shadow, never came. It is a
        # recording change and nothing else: `_enforce` still decides, still
        # counts, and still returns the same reason.
        pending = PipelineOutcome(record=record, resolution=resolution,
                                  calibrated=calibration is not None,
                                  enforcement_withheld=self._withheld_before_attempt(record))
        journalled = self._journal(pending)

        if record.blocked and not journalled and self._journal_gates_action():
            # §6, the stricter reading, and only when the operator chose it.
            self.counters['enforcement_withheld'] += 1
            self.counters['shadow_blocks'] += int(self.shadow)
            return PipelineOutcome(record=record, resolution=resolution,
                                   calibrated=calibration is not None,
                                   enforcement_withheld='decision_not_journalled')

        execution, withheld = self._enforce(record)
        outcome = PipelineOutcome(record=record, resolution=resolution,
                                  calibrated=calibration is not None,
                                  execution=execution, enforcement_withheld=withheld)
        if execution is not None:
            self._journal(outcome)
        # §8. The analytic row is written once, from the final outcome, so
        # `actual_action` is what actually happened rather than what was about
        # to be attempted. Its result is deliberately ignored: §11 says runtime
        # availability wins, and nothing upstream may act on a slow export.
        self._export(outcome)
        return outcome

    def _export(self, outcome):
        if self.shadow_export is None:
            return False
        landed = self.shadow_export.write(
            outcome, component_health=self._component_health)
        self.counters['exported' if landed else 'export_failures'] += 1
        return landed

    def _journal(self, outcome):
        """Write the canonical record, or report that there was nowhere to.

        Returns True when a record landed. With no journal configured the answer
        is False, and it means "not configured" rather than "failed" — which is
        why `_journal_gates_action` asks the journal itself rather than
        treating a False here as a fault.
        """
        if self.journal is None:
            return False
        landed = self.journal.write(outcome)
        self.counters['journalled' if landed else 'journal_failures'] += 1
        return landed

    def _journal_gates_action(self):
        return (self.journal is not None
                and self.journal.required_for_action)

    def _withheld_before_attempt(self, record):
        """The reason no enforcer will be called, where that is already known.

        The same three answers `_enforce` gives for the cases in which it makes
        no call, asked before the journal write rather than after it. Empty means
        "an attempt will be made", and the entry written then is deliberately
        bare: what happened is not known yet, and guessing would put a claim in
        the forensic record that the enforcer had not yet had a chance to
        contradict.

        Deliberately not the whole of `_enforce`. This decides nothing and
        counts nothing; it reads state `_enforce` will read again.
        """
        if not record.blocked:
            return ''
        if self.shadow:
            return 'shadow_mode'
        if self.enforcer is None:
            return 'no_host_enforcer_configured'
        return ''

    def _enforce(self, record):
        """Hand the record over, or say why not. Four refusals, in order.

        Each is checked separately and named separately. "Nothing was enforced"
        is a fact an operator will eventually have to explain, and a single
        boolean cannot tell them whether the answer is shadow mode, a missing
        helper or a decision that was never a block.
        """
        if not record.blocked:
            return None, ''
        if self.shadow:
            self.counters['shadow_blocks'] += 1
            self.counters['enforcement_withheld'] += 1
            return None, 'shadow_mode'
        if self.enforcer is None:
            self.counters['enforcement_withheld'] += 1
            return None, 'no_host_enforcer_configured'
        execution = self.enforcer.execute(record)
        if execution.succeeded:
            self.counters['enforced'] += 1
        else:
            # The authority charged the block budget when it decided; nothing is
            # occupying a firewall rule, so the lease goes back. Without this a
            # broken helper would silently exhaust the system's willingness to
            # act, turning a firewall problem into a detection outage — which is
            # the reasoning `HostEnforcer`'s own docstring gives for charging
            # only on success.
            self.authority.panel.release_block()
            self.counters['enforcement_refused' if execution.refused
                          else 'enforcement_failed'] += 1
        return execution, ''

    # -- health --------------------------------------------------------------

    def health(self):
        """§21. What each part of the decision path is, in §20's four words."""
        enforcement = NOT_CONFIGURED if self.enforcer is None else HEALTHY
        if self.enforcer is None and self.owns_enforcement and not self.shadow:
            # Autonomous mode asked for, no way to act: that is not "not
            # configured", it is a deployment that believes it is defending.
            enforcement = UNAVAILABLE
        assumptions = self.authority.assumption_health()
        return {
            'pipeline_version': PIPELINE_VERSION,
            'mode': self.mode,
            'enabled': self.enabled,
            'shadow': self.shadow,
            'owns_enforcement': self.owns_enforcement,
            'components': {
                'decision_authority': HEALTHY,
                'calibrator': self.calibrator_state.status,
                'cost_policy': HEALTHY,
                'scope_resolver': HEALTHY,
                'policy_guard': HEALTHY,
                'enforcement': enforcement,
                'decision_journal': (NOT_CONFIGURED if self.journal is None
                                     else self.journal.status()['status']),
                'shadow_export': (NOT_CONFIGURED if self.shadow_export is None
                                  else self.shadow_export.status()['status']),
            },
            'journal': (None if self.journal is None else self.journal.status()),
            'shadow_export': (None if self.shadow_export is None
                              else self.shadow_export.status()),
            'calibrator': self.calibrator_state.explain(),
            'cost_policy': self.cost_policy.summary(),
            'assumptions': assumptions,
            'counters': dict(self.counters),
            'authority_counters': dict(self.authority.counters),
        }

    def metrics(self):
        """Bounded counters for the metrics endpoint (§38). No unbounded labels."""
        body = {'autonomous_decisions_total': self.counters['decisions'],
                'autonomous_block_records_total': self.counters['blocks'],
                'autonomous_shadow_blocks_total': self.counters['shadow_blocks'],
                'autonomous_enforced_total': self.counters['enforced'],
                'autonomous_enforcement_refused_total': self.counters['enforcement_refused'],
                'autonomous_enforcement_failed_total': self.counters['enforcement_failed'],
                'autonomous_enforcement_withheld_total': self.counters['enforcement_withheld'],
                'autonomous_calibrator_usable': int(
                    self.calibrator_state.supports_autonomous_block)}
        for name, value in self.authority.suppressed_by.items():
            body[f'autonomous_block_suppressed_by_{name}_total'] = value
        body['autonomous_assumption_health_degraded'] = int(
            self.authority.assumption_health()['state'] == DEGRADED)
        if self.journal is not None:
            body.update(self.journal.metrics())
        if self.shadow_export is not None:
            body.update(self.shadow_export.metrics())
        return body

    def close(self):
        """Release what the pipeline opened. Idempotent."""
        for sink in (self.journal, self.shadow_export):
            if sink is not None:
                sink.close()


def from_config(config, *, enforcer=None, clock=time.monotonic,
                attach_enforcer=True, attach_journal=True):
    """Build the pipeline a configuration asks for. Never raises on a bad artifact.

    A host enforcer is attached only when every one of these is true, and the
    conjunction is deliberately narrow: autonomy enabled, autonomous mode, and
    `enforcement.host_enabled`. Shadow deployments and lab deployments get a
    pipeline with no enforcer at all, which is the strongest possible statement
    of §30 — there is nothing there to call.

    The enforcer is built **without** a breaker panel. There is one accountant
    for the block budget and it is the authority; `_enforce` gives the lease back
    when the helper refuses. See `BreakerPanel.release_block`.

    `attach_enforcer=False` builds the same pipeline with no enforcer whatever
    the configuration says. It exists for the startup self-check (§23, §24),
    which forces its throwaway authority into autonomous mode to exercise the
    gates below the enablement check — and must not, on an autonomous host
    deployment, then hand a synthetic fixture to a real firewall helper.

    `attach_journal=False` is the same idea for the other side effect. The
    self-check's two fixtures are not decisions about anybody, and a journal
    entry carrying one would sit in the forensic record looking exactly like a
    decision about a real source — with a real-looking decision id — every time
    somebody ran `doctor`.
    """
    from .journal import from_config as journal_from_config
    from .shadow_export import from_config as export_from_config

    authority = authority_from_config(config)
    cost_policy = cost_from_config(config)
    state = calibration_loader.load_for(config)
    attached = enforcer
    if attached is None and attach_enforcer and _host_enforcement_requested(config):
        attached = _host_enforcer(config)
    return AutonomousDecisionPipeline(
        authority=authority, cost_policy=cost_policy, calibrator_state=state,
        enforcer=attached,
        journal=journal_from_config(config) if attach_journal else None,
        shadow_export=export_from_config(config) if attach_journal else None,
        clock=clock)


def _host_enforcement_requested(config):
    autonomy = getattr(config, 'autonomy', None)
    enforcement = getattr(config, 'enforcement', None)
    return bool(autonomy is not None and enforcement is not None
                and getattr(autonomy, 'enabled', False)
                and getattr(autonomy, 'mode', SHADOW) == AUTONOMOUS
                and getattr(enforcement, 'host_enabled', False))


def _host_enforcer(config):
    """The unprivileged side of P15.1, pointed at this deployment's config file.

    Imported here rather than at module scope so that a shadow deployment does
    not load the enforcement path at all — a weaker guarantee than the checks
    above and meant as one, but it does make `sys.modules` an honest answer to
    "could this process have enforced anything".

    No `panel`: one accountant, and it is the authority.
    """
    from ..security.host_enforcer import HostEnforcer
    path = str(getattr(getattr(config, 'runtime', None), 'config_path', '') or '')
    if not path:
        # A programmatically built configuration has no file, and the helper
        # reads its protected networks from one. Returning `None` leaves
        # `health()` reporting UNAVAILABLE rather than silently pointing the
        # helper at whatever it would find on its own.
        return None
    return HostEnforcer(path)
