"""Starting autonomously, degrading out of it, and coming back. Without a person.

§104 says autonomous mode starts only when a self-check passes. §105 says that a
failed self-check must not become a system that pretends to be enforcing. §192
says a runtime whose confidence infrastructure degrades may fall back on its own,
and §193 says it may return on its own too — after a health gate and a cooldown,
because a mode that flipped on every twitch would be worse than either mode.

Those four rules are one state machine with three states:

    AUTONOMOUS      decisions are made and acted on, nobody approves them
    SAFE_OBSERVE    everything runs, nothing new is blocked, blocks still expire
    SHADOW          decisions are computed and recorded, never acted on

and two transitions that happen without being asked. Degradation is immediate:
the moment a fault is recorded the runtime is in SAFE_OBSERVE, because the
alternative is acting on a broken measurement. Recovery is deliberate: the fault
must be gone, the readiness gate must pass again, and the cooldown must have
elapsed.

### The readiness gate is allowed to say no

`evaluate_readiness` is the §186 gate, and its answer is evidence-shaped rather
than encouraging. Each check reports PASS, FAIL or NOT_APPLICABLE with a reason,
critical checks are marked as such, and one critical failure means
`AUTONOMOUS_READY: NO` (§216). Nothing here downgrades a failure to a warning
because the rest looks good.

The enforcement check reads differently depending on which of the two
enforcement paths an installation asked for, and neither answer is a default.

With `enforcement.host_enabled`, P15.1's host path applies and the gate asks
whether *this* machine can use it: Linux, `nft` present, at least one protected
network configured. With `enforcement.enabled`, the P7 namespace path applies and
the gate asks for a lab profile and a named namespace. With neither, enforcement
is off and the gate says so — decisions are recorded and nothing is blocked,
which is a supported posture and not a degraded one.

The capability probe here is three lines rather than an import of the firewall
backend, deliberately: Invariant 1 says no module in `autonomy/` imports anything
that can write a rule, and that is worth more as a structural fact than as a
convenience.
"""
from dataclasses import dataclass, field
from pathlib import Path
import math
import time

PASS = 'PASS'
FAIL = 'FAIL'
NOT_APPLICABLE = 'NOT_APPLICABLE'

#: Runtime modes (§103, §105, §191). Uppercase, and deliberately not the same
#: strings as the *configured* mode in `autonomy/authority.py`, which is
#: lowercase `'shadow'` / `'autonomous'`.
#:
#: Two vocabularies with the same names and different cases is a trap, and it
#: caught the first attempt at the check in `start()` below: `'autonomous' ==
#: 'AUTONOMOUS'` is quietly False, so the configured mode was never equal to
#: anything and the test suite said so. The configured constant is therefore
#: imported under a name that cannot be confused with this one.
AUTONOMOUS = 'AUTONOMOUS'
SAFE_OBSERVE = 'SAFE_OBSERVE'
SHADOW = 'SHADOW'

#: The configured mode's value for "act on decisions", as `[autonomy] mode` in
#: the configuration file spells it.
CONFIGURED_AUTONOMOUS = 'autonomous'

READINESS_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ReadinessCheck:
    """One question, its answer, and whether the answer is allowed to be no."""

    name: str
    status: str
    detail: str
    critical: bool = True

    @property
    def blocking(self):
        return self.critical and self.status == FAIL

    def explain(self):
        return {'check': self.name, 'status': self.status, 'detail': self.detail,
                'critical': self.critical}


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """What the gate found. `ready` is computed, never set."""

    checks: tuple = ()
    schema_version: int = READINESS_SCHEMA_VERSION

    @property
    def blocking(self):
        return tuple(check for check in self.checks if check.blocking)

    @property
    def warnings(self):
        return tuple(check for check in self.checks
                     if check.status == FAIL and not check.critical)

    @property
    def ready(self):
        """§216. One critical failure is enough, and it is not hidden."""
        return not self.blocking

    @property
    def recommended_mode(self):
        """What a runtime should start in, given this report (§105).

        Never AUTONOMOUS on a failed gate. SHADOW rather than SAFE_OBSERVE when
        the gate failed on evidence rather than on machinery, because shadow
        keeps producing the counterfactual an operator needs to fix it.
        """
        return AUTONOMOUS if self.ready else SHADOW

    def explain(self):
        return {'readiness_schema_version': self.schema_version,
                'autonomous_ready': 'YES' if self.ready else 'NO',
                'recommended_mode': self.recommended_mode,
                'checks': [check.explain() for check in self.checks],
                'blocking': [check.name for check in self.blocking],
                'warnings': [check.name for check in self.warnings],
                'note': ('readiness is about machinery and configuration. It is '
                         'not a measurement of how often the decisions are '
                         'right, and passing it is not evidence of accuracy.')}


def _check_config(config):
    try:
        config.validate()
        return ReadinessCheck('config_valid', PASS, 'the configuration validates')
    except Exception as exc:
        return ReadinessCheck('config_valid', FAIL, f'{type(exc).__name__}: {exc}'[:160])


def _check_feature_schema():
    """The tensor has the shape the schema implies, and every name is distinct.

    This pinned the literal numbers 1 and 36 until P15.4, which made it a
    tripwire for the wrong thing: it would have failed a correct schema change
    and passed a schema whose column names had silently collided. What matters
    is that the contract is internally consistent — one availability flag per
    feature, no duplicate names. Whether the shipped artifacts can still be
    served is a different question, and `_check_classifier` asks it.
    """
    try:
        from ..decision.features import INPUT_ORDER, NAMES, SCHEMA_VERSION
        if len(INPUT_ORDER) == 2 * len(NAMES) and len(set(INPUT_ORDER)) == len(INPUT_ORDER):
            return ReadinessCheck('feature_schema', PASS,
                                  f'schema {SCHEMA_VERSION}, {len(NAMES)} features '
                                  f'and {len(NAMES)} availability masks')
        return ReadinessCheck('feature_schema', FAIL,
                              f'schema {SCHEMA_VERSION} is inconsistent: {len(NAMES)} names, '
                              f'{len(INPUT_ORDER)} columns, '
                              f'{len(INPUT_ORDER) - len(set(INPUT_ORDER))} duplicated')
    except Exception as exc:
        return ReadinessCheck('feature_schema', FAIL, type(exc).__name__)


def _check_math_engine():
    """The engine that carries a decision when everything learned is unavailable.

    Checked by running it, not by importing it: a deterministic engine that
    imports and then raises on the first vector is the one failure that would
    leave the system with no fallback at all.
    """
    try:
        from ..decision.features import NAMES, FeatureVector
        from ..decision.math_risk import MathRiskEngine
        vector = FeatureVector(tuple([0.0] * len(NAMES)), observation_seconds=1.0, sample_count=1)
        result = MathRiskEngine().evaluate(vector)
        if math.isfinite(result.score) and 0 <= result.score <= 1:
            return ReadinessCheck('math_engine', PASS,
                                  f'{result.model_version} evaluated a vector')
        return ReadinessCheck('math_engine', FAIL, 'the engine produced a non-score')
    except Exception as exc:
        return ReadinessCheck('math_engine', FAIL, f'{type(exc).__name__}'[:160])


def _check_model(config):
    """A healthy model, or an explicit deterministic fallback. §104 accepts either.

    Not critical: the whole point of the fallback is that a missing classifier
    is a supported state. What would be critical is a classifier configured as
    required and absent, and `config.validate()` already refuses that.
    """
    ml = getattr(config, 'ml', None)
    if ml is None or not ml.enabled:
        return ReadinessCheck('model_available', NOT_APPLICABLE,
                              'the classifier is off; the deterministic engine decides',
                              critical=False)
    for label, value in (('model', ml.model_path), ('manifest', ml.manifest_path)):
        if not value or not Path(value).is_file():
            return ReadinessCheck('model_available', FAIL,
                                  f'the classifier is enabled but its {label} is missing',
                                  critical=bool(ml.required))
    return ReadinessCheck('model_available', PASS, 'model and manifest are present')


def _check_rollback(config):
    """§186. Something to go back to, before anything is allowed to go forward."""
    root = getattr(config.reliability, 'registry_path', '') or ''
    if not root:
        return ReadinessCheck('rollback_available', NOT_APPLICABLE,
                              'no model registry is configured, so there is no model '
                              'change to roll back', critical=False)
    try:
        from ..decision.registry import ModelRegistry
        state = ModelRegistry(root).state
        if state.active and state.previous_active:
            return ReadinessCheck('rollback_available', PASS,
                                  f'active {state.active}, rollback target '
                                  f'{state.previous_active}')
        if state.active:
            return ReadinessCheck('rollback_available', FAIL,
                                  'an active model with no previous version to roll '
                                  'back to', critical=False)
        return ReadinessCheck('rollback_available', NOT_APPLICABLE,
                              'no active model', critical=False)
    except Exception as exc:
        return ReadinessCheck('rollback_available', FAIL, f'{type(exc).__name__}: {exc}'[:160])


def _check_protected_networks(config):
    """§41, §186. The addresses autonomy is never allowed to act against.

    An empty list is a failure rather than a default. A machine whose operator
    has not said which networks are management is a machine that can lock its
    operator out, and a security tool that does that has failed at the only job
    where failure is unrecoverable in the field.
    """
    enforcement = config.enforcement
    configured = len(enforcement.management_networks) + len(enforcement.allowlist)
    if configured:
        return ReadinessCheck('protected_networks', PASS,
                              f'{configured} protected network(s) configured; '
                              'loopback and link-local are always protected')
    return ReadinessCheck('protected_networks', FAIL,
                          'no management network or allowlist is configured; '
                          'set enforcement.management_networks before enabling '
                          'autonomous enforcement')


def _check_cost_policy(config):
    try:
        from .cost import from_config
        policy = from_config(config)
        return ReadinessCheck('cost_policy', PASS,
                              f'{policy.version} ({policy.digest[:12]}), default '
                              f'profile {policy.default_profile}, cutoff '
                              f'{policy.for_scope("GLOBAL").threshold:.3f}')
    except Exception as exc:
        return ReadinessCheck('cost_policy', FAIL, f'{type(exc).__name__}: {exc}'[:160])


def _check_breakers(config):
    try:
        from .breakers import from_config
        panel = from_config(config)
        limits = panel.limits
        if limits.blocks_per_minute <= 0:
            return ReadinessCheck('block_circuit_breaker', FAIL,
                                  'the block budget is zero; nothing would ever be blocked')
        return ReadinessCheck('block_circuit_breaker', PASS,
                              f'{limits.blocks_per_minute}/minute, at most '
                              f'{limits.max_active_blocks} active, mass-block ceiling '
                              f'{limits.max_block_share:.1%}')
    except Exception as exc:
        return ReadinessCheck('block_circuit_breaker', FAIL, f'{type(exc).__name__}: {exc}'[:160])


def _check_enforcement(config):
    """The honest one.

    Autonomous *decisions* need none of this. Autonomous *enforcement* needs a
    path from a decision to a rule, and in this project that path ends inside a
    network namespace on a Linux lab machine. This check reports which of the two
    the installation can actually do. It is not critical, because a decision
    authority with nothing to act on is a legitimate and useful deployment — it
    is shadow mode, and shadow mode is how a site earns the evidence for anything
    stronger.
    """
    enforcement = config.enforcement
    if getattr(enforcement, 'host_enabled', False):
        # P15.1 §21. The host path exists now, so the gate asks whether *this*
        # machine can use it rather than reporting the lab restriction.
        #
        # The probe is deliberately done here rather than by importing the
        # firewall backend. Invariant 1 says no module in `autonomy/` imports
        # anything that can write a rule, and it is worth more as a structural
        # fact than as a convenience: three lines of capability check keep the
        # readiness gate honest without giving the decision half a handle on the
        # enforcement half. Whether the helper actually works is reported by the
        # helper, out of process, in `autonomy status`.
        import shutil
        import sys
        if not sys.platform.startswith('linux'):
            return ReadinessCheck('enforcement_available', FAIL,
                                  'host enforcement is switched on and this is not Linux')
        if not shutil.which('nft'):
            return ReadinessCheck('enforcement_available', FAIL,
                                  'host enforcement is switched on and nft is not installed')
        protected = len(enforcement.management_networks) + len(enforcement.allowlist)
        if not protected:
            return ReadinessCheck('enforcement_available', FAIL,
                                  'host enforcement with no protected network')
        return ReadinessCheck(
            'enforcement_available', PASS,
            f'host enforcement via an owned nftables table, {protected} protected '
            f'network(s), maximum block {max(enforcement.block_seconds)}s')
    if not enforcement.enabled:
        return ReadinessCheck(
            'enforcement_available', NOT_APPLICABLE,
            'temporary enforcement is off: decisions are recorded, nothing is '
            'blocked. Set enforcement.host_enabled for this host, or '
            'enforcement.enabled with a lab namespace',
            critical=False)
    if config.deployment.profile != 'lab' or not config.firewall.lab_namespace:
        return ReadinessCheck(
            'enforcement_available', FAIL,
            'enforcement requires deployment.profile=lab and firewall.lab_namespace; '
            'the namespace backend refuses the host network namespace',
            critical=False)
    return ReadinessCheck('enforcement_available', PASS,
                          f'lab namespace {config.firewall.lab_namespace}')


def _check_storage(config):
    storage = getattr(config, 'storage', None)
    path = getattr(storage, 'path', '') if storage else ''
    if not storage or not getattr(storage, 'enabled', False) or not path:
        return ReadinessCheck('storage', NOT_APPLICABLE, 'storage is off', critical=False)
    parent = Path(path).parent
    if not parent.is_dir():
        return ReadinessCheck('storage', FAIL, 'the storage directory does not exist')
    try:
        import shutil
        free = shutil.disk_usage(parent).free
        if free < 64 * 1024 * 1024:
            return ReadinessCheck('storage', FAIL,
                                  f'{free // (1024 * 1024)} MiB free; retention and '
                                  'block state need room to work')
        return ReadinessCheck('storage', PASS, f'{free // (1024 * 1024)} MiB free')
    except OSError as exc:
        return ReadinessCheck('storage', FAIL, type(exc).__name__)


def _check_decision_pipeline(config):
    """§40. Does a decision still reach the end of the pipeline?

    Critical, and it is worth saying why a *wiring* check earns that. Every other
    check here asks whether one component is present and configured, and P15.4
    passed all of them while the product could not act at all — the components
    were each fine and the join between two of them was not. This is the only
    check that asks the question end to end, and a build that fails it is a build
    that will enforce nothing while reporting itself ready.

    It measures nothing about accuracy (§41). A synthetic vector reaching
    TEMP_BLOCK says the gates are connected and says nothing whatever about
    whether real traffic would.
    """
    try:
        from .selfcheck import check as selfcheck
        result = selfcheck(config)
        if result['verdict'] == 'WIRED':
            return ReadinessCheck('decision_pipeline', PASS,
                                  'a synthetic vector reached TEMP_BLOCK through '
                                  'MathRisk, the calibrator and the authority; '
                                  'wiring only, not a detection result')
        return ReadinessCheck('decision_pipeline', FAIL,
                              '; '.join(result['failures'])[:160])
    except Exception as exc:                                    # noqa: BLE001
        return ReadinessCheck('decision_pipeline', FAIL,
                              f'{type(exc).__name__}: {exc}'[:160])


def _check_clock():
    """§53, §104. A TTL is a promise about time; a broken clock breaks it."""
    monotonic_start, wall_start = time.monotonic(), time.time()
    time.sleep(0.001)
    monotonic_delta = time.monotonic() - monotonic_start
    wall_delta = time.time() - wall_start
    if monotonic_delta <= 0:
        return ReadinessCheck('clock_sane', FAIL, 'the monotonic clock did not advance')
    if wall_delta < -1.0:
        return ReadinessCheck('clock_sane', FAIL, 'the wall clock went backwards')
    return ReadinessCheck('clock_sane', PASS, 'monotonic and wall clocks advance')


def _check_sites(config):
    sites = getattr(config, 'sites', None)
    if sites is None or not getattr(sites, 'enabled', False):
        return ReadinessCheck('site_resolver', NOT_APPLICABLE,
                              'multi-site is off; every decision is global scope',
                              critical=False)
    try:
        from ..sites.identity import normalise_site_id
        names = [normalise_site_id(name) for name in (getattr(sites, 'profiles', {}) or {})]
        if len(set(names)) != len(names):
            return ReadinessCheck('site_resolver', FAIL,
                                  'two site identifiers normalise to the same name')
        return ReadinessCheck('site_resolver', PASS,
                              f'{len(names)} site identifier(s) resolve')
    except Exception as exc:
        return ReadinessCheck('site_resolver', FAIL, f'{type(exc).__name__}: {exc}'[:160])


def _check_autonomy_settings(config):
    autonomy = getattr(config, 'autonomy', None)
    if autonomy is None:
        return ReadinessCheck('autonomy_configured', FAIL,
                              'this build has no autonomy configuration section')
    if not config.decision.enabled:
        return ReadinessCheck('autonomy_configured', FAIL,
                              'the decision engine is off')
    return ReadinessCheck(
        'autonomy_configured', PASS,
        f'mode {autonomy.mode}, '
        + ('enabled' if autonomy.enabled else 'not yet enabled — run '
                                              '`eye-for-an-eye autonomy enable`'))


def _check_calibrator(config):
    """P15.5R §9, §50. Is there a calibrator, and is it this build's?

    Critical in autonomous mode, because the alternative is a deployment that
    believes it is defending. Without a usable calibrator the authority has no
    probability, the `calibrated_estimate` gate refuses every block, and the
    visible symptom is a recall of zero on a sensor whose every other light is
    green — precisely how P15.4 presented, and precisely what this gate exists
    to say out loud before an operator discovers it from a benchmark.

    A warning rather than a refusal in shadow mode: shadow is where a deployment
    goes to find out what it *would* have done, and refusing to start it because
    it cannot act would remove the one mode in which "nothing" is the right
    answer.
    """
    from . import calibrator as loader
    autonomy = getattr(config, 'autonomy', None)
    shadow = autonomy is None or getattr(autonomy, 'mode', 'shadow') != 'autonomous'
    state = loader.load_for(config)
    if state.status == loader.HEALTHY:
        return ReadinessCheck(
            'calibrator', PASS,
            f'{state.version} on {state.model_version}, fitted per {state.unit} '
            f'over {state.samples} examples')
    if state.status == loader.NOT_CONFIGURED:
        return ReadinessCheck(
            'calibrator', FAIL,
            'no calibrator is configured (autonomy.calibrator_path); the '
            'authority has no probability, so every block is refused with '
            'CALIBRATION_UNAVAILABLE', critical=not shadow)
    return ReadinessCheck('calibrator', FAIL, state.reason, critical=not shadow)


def evaluate_readiness(config):
    """§104 and §186, as one report. Changes nothing; only looks."""
    return ReadinessReport(checks=(
        _check_config(config),
        _check_autonomy_settings(config),
        _check_feature_schema(),
        _check_math_engine(),
        _check_model(config),
        _check_calibrator(config),
        _check_cost_policy(config),
        _check_protected_networks(config),
        _check_breakers(config),
        _check_rollback(config),
        _check_sites(config),
        _check_storage(config),
        _check_enforcement(config),
        _check_decision_pipeline(config),
        _check_clock()))


def _configured_autonomous(settings):
    """Does `[autonomy] mode` ask for decisions to be acted on?

    One function rather than two comparisons, so the case collision above has
    exactly one place it can be got wrong.
    """
    return str(getattr(settings, 'mode', '') or '').lower() == CONFIGURED_AUTONOMOUS


@dataclass
class AutonomousRuntime:
    """The mode this installation is in, and what is allowed to change it.

    Wraps an `AutonomousDecisionAuthority` with the §192–§194 transitions. The
    authority decides; this decides whether the authority's decisions are in
    force, which is a separate question and belongs in a separate object.
    """

    authority: object
    cooldown_seconds: float = 900.0
    clock: object = time.monotonic
    mode: str = SHADOW
    degraded_reason: str = ''
    degraded_at: float = 0.0
    recovered_at: float = 0.0
    transitions: list = field(default_factory=list)

    def start(self, config):
        """§104, §105. Start autonomous only if the gate says so; say which, either way.

        Never raises on a failed gate: a security tool that refuses to start
        because it could not be perfect is a security tool that is not running.

        P15.5R §44. "Asked for" is two settings, not one. This read only
        `autonomy.enabled` and ignored `autonomy.mode`, so the default and
        recommended production state — enabled, in shadow — came back
        `AUTONOMOUS`, and `eye-for-an-eye autonomy status` told an operator
        checking whether they were blocking anybody that they were. The sensor
        was never wrong: `authority.from_config` reads both settings and the
        pipeline stays in shadow. Only the one command an operator would use to
        confirm it was.
        """
        report = evaluate_readiness(config)
        settings = getattr(config, 'autonomy', None)
        enabled = bool(getattr(settings, 'enabled', False))
        wanted = enabled and _configured_autonomous(settings)
        if report.ready and wanted:
            self._transition(AUTONOMOUS, 'readiness gate passed')
            self.authority.activate(mode='autonomous')
        else:
            reason = self._not_autonomous_because(report, enabled, wanted)
            # SAFE_OBSERVE means "this wanted to be autonomous and cannot be",
            # which is a fault state. A deployment configured for shadow is not
            # in a fault state; it is doing what it was asked.
            self._transition(SAFE_OBSERVE if wanted else SHADOW, reason)
            self.authority.deactivate()
        return report

    @staticmethod
    def _not_autonomous_because(report, enabled, wanted):
        if not report.ready:
            return 'readiness: ' + ', '.join(check.name for check in report.blocking)
        if not enabled:
            return 'autonomy is not enabled in configuration'
        if not wanted:
            return ('autonomy.mode is shadow: decisions are recorded and nothing '
                    'is enforced')
        return 'not autonomous'

    def degrade(self, fault, detail=''):
        """§192. Immediate, automatic, and not a request for permission."""
        self.authority.enter_safe_mode(fault, detail)
        self.degraded_reason = f'{fault}: {detail}'[:160] if detail else str(fault)[:160]
        self.degraded_at = self.clock()
        self.recovered_at = 0.0
        if self.mode == AUTONOMOUS:
            self._transition(SAFE_OBSERVE, self.degraded_reason)
            self.authority.deactivate()
        return self.mode

    def resolve(self, fault):
        """The fault is gone. This starts a cooldown; `attempt_recovery` ends it.

        The clock starts when the last *fault* clears, not when the breaker's own
        cooldown finishes. Those are two separate waits and both still apply —
        `attempt_recovery` will not return while the breaker is in cooldown — but
        starting this one only after that one ended would stack them, and a
        recovery that takes twice as long as either setting says is a recovery
        nobody configured.
        """
        self.authority.resolve_fault(fault)
        if not self.authority.panel.technical.faults and not self.recovered_at:
            self.recovered_at = self.clock()
        return self.mode

    @property
    def cooldown_remaining(self):
        if self.mode == AUTONOMOUS or not self.recovered_at:
            return 0.0
        return max(0.0, self.cooldown_seconds - (self.clock() - self.recovered_at))

    def attempt_recovery(self, config):
        """§193, §54. Automatic return, and only when all three conditions hold.

        Health, cooldown, and a readiness gate that passes again. A runtime that
        returned on health alone would oscillate across the boundary of whatever
        measurement degraded it, which §194 is about.
        """
        if self.mode == AUTONOMOUS:
            return self.mode, 'already autonomous'
        if self.authority.panel.technical.faults:
            return self.mode, 'a technical fault is still set'
        if self.authority.safe_mode:
            # Covers the breaker's own cooldown as well as any breaker still open.
            # Named individually: "a breaker is open" and "a breaker is counting
            # down" call for different things from whoever is reading this.
            return self.mode, self._breaker_reason()
        if not self.recovered_at:
            return self.mode, 'no fault has cleared yet'
        if self.cooldown_remaining > 0:
            return self.mode, f'cooldown: {self.cooldown_remaining:.0f}s remaining'
        report = evaluate_readiness(config)
        if not report.ready:
            return self.mode, ('readiness: '
                               + ', '.join(check.name for check in report.blocking))
        settings = getattr(config, 'autonomy', None)
        if not bool(getattr(settings, 'enabled', False)):
            return self.mode, 'autonomy is not enabled in configuration'
        # The same two settings `start` reads. Recovering *into* a mode the
        # configuration did not ask for would be this object deciding on its own
        # that a shadow deployment should start enforcing, which is the one
        # transition it must never make.
        if not _configured_autonomous(settings):
            return self.mode, ('autonomy.mode is shadow: decisions are recorded '
                               'and nothing is enforced')
        self._transition(AUTONOMOUS, 'health gate and cooldown passed')
        self.authority.activate(mode='autonomous')
        self.degraded_reason = ''
        return self.mode, 'recovered'

    def _breaker_reason(self):
        panel = self.authority.panel
        parts = []
        for name, breaker in (('mass-block', panel.mass_block.breaker),
                              ('false-positive', panel.false_positive.breaker),
                              ('technical', panel.technical.breaker)):
            if breaker.permits:
                continue
            remaining = breaker.cooldown_remaining
            parts.append(f'{name} breaker cooldown: {remaining:.0f}s remaining'
                         if remaining > 0 else f'{name} breaker is open')
        return '; '.join(parts) or 'a circuit breaker is still open'

    def disable(self, reason='operator kill switch'):
        """§189, §190. Local, immediate, and no cloud anywhere in the path."""
        self.authority.deactivate()
        self._transition(SHADOW, reason)
        return self.mode

    def _transition(self, mode, reason):
        if mode != self.mode:
            self.transitions.append({'at': round(self.clock(), 3), 'from': self.mode,
                                     'to': mode, 'reason': str(reason)[:160]})
            del self.transitions[:-32]
        self.mode = mode

    def status(self):
        return {'mode': self.mode,
                'degraded_reason': self.degraded_reason,
                'cooldown_remaining_seconds': round(self.cooldown_remaining, 1),
                'recent_transitions': list(self.transitions[-8:]),
                'authority': self.authority.status(),
                'note': ('SAFE_OBSERVE means no new autonomous blocks. Everything '
                         'else keeps running and existing blocks still expire.')}
