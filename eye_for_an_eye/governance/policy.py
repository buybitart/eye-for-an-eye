"""The governance policy: every number that decides a promotion, in one place.

A policy is a versioned, frozen value. Nothing computes it, nothing tunes it, and
the classifier cannot see it. That is the separation the whole stage rests on: if
a model could influence the thresholds it is judged against, the gates would be
decoration.

Two conventions run through everything here.

**The numbers are operator policy, not science.** Not one of these tolerances is
derived from a study, and none should be presented as though it were. They are a
starting point chosen to be conservative, and an operator who changes them is
making a judgement about their own site, not correcting an error. The source says
so at each one, because a threshold that looks authoritative gets copied.

**Every policy carries a digest of its own contents.** Changing a threshold
changes the digest, which makes every assessment reached under the old numbers
detectably stale (§29). The alternative — a version string bumped by hand — fails
in exactly the case that matters, where somebody edits a tolerance and forgets.
"""
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json

#: Bumped when the *shape* of the policy changes, not when a number does. A
#: number change is caught by the digest instead, which cannot be forgotten.
GOVERNANCE_POLICY_VERSION = 'model-governance-v1'

#: The action ladder, weakest first. Shared with the web sensor and the challenge
#: policy; a guarded ceiling is an index into this.
ACTION_LADDER = ('OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT', 'TEMP_BLOCK')


class PolicyError(ValueError):
    """A governance policy that does not make sense."""


@dataclass(frozen=True, slots=True)
class GuardedStage:
    """One rung of guarded activation: a ceiling, and what it costs to leave it.

    The evidence requirements are deliberately not "time". Twenty-four hours on a
    site that saw eleven requests is not evidence of anything, and a stage that
    advanced on the clock alone would give a candidate full authority for free on
    exactly the quiet sites where a regression is hardest to notice (§41).
    """

    name: str
    #: The strongest action this model may cause **on its own** while in this
    #: stage. Deterministic multi-signal policy is unaffected (§38).
    action_ceiling: str
    minimum_seconds: float
    minimum_feature_vectors: int
    minimum_source_groups: int
    #: Reviewed, trusted outcomes. Zero means "not required at this rung" — the
    #: first stage cannot demand human review that has not happened yet.
    minimum_trusted_outcomes: int = 0
    #: Fraction of scored windows where this model and the previous one would
    #: have chosen materially different actions. Above this, the stage does not
    #: advance and a person is asked to look (§52).
    maximum_disagreement_ratio: float = 0.20
    maximum_inference_failures: int = 0

    def __post_init__(self):
        if self.action_ceiling not in ACTION_LADDER:
            raise PolicyError(f'{self.action_ceiling!r} is not an action on the ladder')
        if self.minimum_seconds < 0 or self.minimum_feature_vectors < 0:
            raise PolicyError('guarded stage requirements cannot be negative')

    @property
    def ceiling_index(self):
        return ACTION_LADDER.index(self.action_ceiling)

    def explain(self):
        return asdict(self)


#: The default staircase. Stage 1 lets a newly promoted model raise attention and
#: nothing more; stage 2 lets it slow a source down; full authority comes last.
#:
#: The shape matters more than the numbers: each rung costs real observations,
#: and the first rung cannot block anybody no matter how confident the model is.
DEFAULT_STAGES = (
    GuardedStage(name='GUARDED_ACTIVE_STAGE_1', action_ceiling='WATCH',
                 minimum_seconds=86_400.0, minimum_feature_vectors=2_000,
                 minimum_source_groups=200, minimum_trusted_outcomes=0,
                 maximum_disagreement_ratio=0.20, maximum_inference_failures=0),
    GuardedStage(name='GUARDED_ACTIVE_STAGE_2', action_ceiling='RATE_LIMIT',
                 minimum_seconds=259_200.0, minimum_feature_vectors=10_000,
                 minimum_source_groups=1_000, minimum_trusted_outcomes=20,
                 maximum_disagreement_ratio=0.10, maximum_inference_failures=0),
)


@dataclass(frozen=True, slots=True)
class ShadowRequirements:
    """What a candidate must have seen before its shadow evidence means anything.

    These are per-scope and configurable on purpose (§10): one arbitrary event
    count applied to every site would be far too strict for a quiet admin panel
    and far too lax for a busy API.
    """

    minimum_seconds: float = 604_800.0          # one week
    minimum_feature_vectors: int = 5_000
    minimum_source_groups: int = 500
    minimum_sites_with_activity: int = 1
    #: Reviewed outcomes with trusted provenance. Below this, quality gates
    #: return NEED_MORE_DATA instead of a verdict (§11, §12, §122).
    minimum_trusted_outcomes: int = 50
    maximum_inference_failure_ratio: float = 0.001
    maximum_ood_ratio: float = 0.50

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RegressionBudgets:
    """How much worse a candidate may be, per dimension, and still be accepted.

    Every one of these is a policy choice an operator owns. The defaults lean
    the same way throughout: a candidate that finds more attacks while blocking
    more ordinary people is not an improvement, so the benign-safety budgets are
    the tightest numbers here (§15, §19).
    """

    max_block_precision_drop: float = 0.02
    max_false_block_increase_per_1000: float = 0.5
    max_hard_negative_regression: float = 0.01
    max_hard_positive_recall_drop: float = 0.05
    max_latency_increase_ratio: float = 1.50
    max_rss_increase_ratio: float = 1.50
    max_model_load_seconds: float = 30.0
    max_model_size_bytes: int = 33_554_432
    max_onnx_parity_error: float = 1e-5
    #: A candidate whose action distribution is wildly different from the active
    #: model's is not necessarily wrong, but it is not something to activate
    #: without a person having looked (§52, §53).
    max_action_distribution_shift: float = 0.25

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PromotionBudgets:
    """Bounds on how often anything may change (§32, §34, §79).

    Model churn is its own failure mode. A system that promotes whenever
    retraining produces something is a system whose production behaviour nobody
    can reason about, even if every individual promotion passed its gates.
    """

    minimum_promotion_interval_seconds: float = 604_800.0     # one week
    max_promotions_per_day: int = 2
    max_promotions_per_site_per_day: int = 1
    max_rollbacks_per_day: int = 3
    #: Activating a model costs memory and CPU. Twenty at once is an outage.
    max_concurrent_promotions: int = 1
    #: Repeated failures mean something is wrong that another attempt will not
    #: fix, so the system stops trying and asks for a person (§55).
    failures_before_freeze: int = 3

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RollbackThresholds:
    """When a promoted model is withdrawn automatically (§47, §48, §51).

    The asymmetry between the two halves is the design. **Technical failures roll
    back fast**, because a model producing non-finite output or failing inference
    is broken in a way that no amount of further observation will clarify, and
    every minute it stays is a minute the site is defended by something that does
    not work.

    **Quality regressions roll back slowly**, because the evidence is reviewed
    outcomes and review takes time. A system that withdrew a model on one
    ambiguous unlabelled request would be a system whose model changes with the
    weather, and it would be wrong far more often than it was right (§48).

    Neither half is reachable by out-of-distribution rate or drift on their own
    (§49, §50). Both of those say the world changed, and the model that would be
    rolled back to has seen even less of the new world than the current one.
    """

    #: Technical. Evaluated over a rolling window and acted on quickly.
    max_inference_failure_ratio: float = 0.02
    max_consecutive_inference_failures: int = 20
    technical_window_seconds: float = 900.0
    #: Resource. Website availability outranks model experimentation (§51, §147).
    max_latency_increase_ratio: float = 2.0
    max_rss_increase_ratio: float = 2.0
    sustained_seconds_before_resource_rollback: float = 600.0
    #: Quality. Needs trusted, reviewed evidence and a minimum amount of it.
    minimum_reviewed_outcomes_for_quality_rollback: int = 20
    max_reviewed_false_block_increase: int = 3
    max_block_precision_drop: float = 0.10
    #: Action surge. Freezes advancement and asks for a person; on its own it is
    #: not a rollback, because a surge can be a real attack wave (§52).
    action_surge_ratio: float = 3.0

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AutoPromoteSettings:
    """Whether any of this is switched on. Both default to false (§4, §98).

    `enabled` and `global_enabled` are separate because their blast radii are
    not comparable. A site-scoped promotion affects one website; a global
    promotion affects every site on the machine, including ones whose operator
    never opted in (§6, §73).
    """

    enabled: bool = False
    global_enabled: bool = False
    #: Sites that opted in by name. A site absent from here does not
    #: auto-promote, whatever the global switch says (§5).
    sites: tuple = ()

    def allows(self, scope):
        """Whether auto-promotion is permitted for this scope. Never raises."""
        if not self.enabled:
            return False, 'auto-promotion is disabled'
        text = str(scope or '')
        if text == 'GLOBAL':
            if not self.global_enabled:
                return False, ('global auto-promotion is disabled; a global model '
                               'reaches every site on this machine, so it is a '
                               'separate decision from any one site')
            return True, 'global auto-promotion is enabled'
        if text.startswith('SITE:'):
            site = text[len('SITE:'):]
            if site in self.sites:
                return True, f'site {site} opted in to auto-promotion'
            return False, (f'site {site} has not opted in to auto-promotion; one '
                           'site opting in never enables another')
        return False, f'unknown promotion scope {scope!r}'

    def explain(self):
        return {'enabled': self.enabled, 'global_enabled': self.global_enabled,
                'sites': list(self.sites)}


@dataclass(frozen=True, slots=True)
class GovernancePolicy:
    """Everything that decides a promotion, versioned and content-addressed."""

    version: str = GOVERNANCE_POLICY_VERSION
    auto_promote: AutoPromoteSettings = field(default_factory=AutoPromoteSettings)
    shadow: ShadowRequirements = field(default_factory=ShadowRequirements)
    budgets: RegressionBudgets = field(default_factory=RegressionBudgets)
    promotion: PromotionBudgets = field(default_factory=PromotionBudgets)
    rollback: RollbackThresholds = field(default_factory=RollbackThresholds)
    stages: tuple = DEFAULT_STAGES
    #: Guarded activation and auto-rollback can be switched off, and switching
    #: either off switches auto-promotion off with it: promoting automatically
    #: without a guarded stage or without a way back is not a supported
    #: configuration, and silently allowing it would be the worst kind of
    #: flexibility.
    guarded_activation_enabled: bool = True
    auto_rollback_enabled: bool = True

    def __post_init__(self):
        if not self.stages:
            raise PolicyError('a governance policy needs at least one guarded stage')
        ceilings = [stage.ceiling_index for stage in self.stages]
        if ceilings != sorted(ceilings):
            raise PolicyError(
                'guarded stages must not loosen and then tighten again; each rung '
                'may only permit at least as much as the one before it')
        if self.auto_promote.enabled and not self.guarded_activation_enabled:
            raise PolicyError(
                'auto-promotion without guarded activation is not supported: a '
                'candidate would go straight to full authority on evidence that '
                'cannot cover every production case')
        if self.auto_promote.enabled and not self.auto_rollback_enabled:
            raise PolicyError(
                'auto-promotion without automatic rollback is not supported: an '
                'automatic change with no automatic way back is a one-way door')

    @property
    def digest(self):
        """A stable hash of every value in the policy.

        This is what makes a stale assessment detectable. A version string alone
        fails in the one case that matters — somebody edits a tolerance and does
        not think to bump it — and that case is indistinguishable, afterwards,
        from a promotion that was properly authorised.
        """
        return hashlib.sha256(
            json.dumps(self.explain(), sort_keys=True, separators=(',', ':'))
            .encode('utf-8')).hexdigest()

    @property
    def first_stage(self):
        return self.stages[0]

    def stage_after(self, name):
        """The next rung, or None when this is the last one before ACTIVE."""
        names = [stage.name for stage in self.stages]
        if name not in names:
            return None
        index = names.index(name) + 1
        return self.stages[index] if index < len(self.stages) else None

    def stage(self, name):
        for candidate in self.stages:
            if candidate.name == name:
                return candidate
        return None

    def with_auto_promote(self, **changes):
        """A copy with different auto-promotion settings. Policies are frozen."""
        return replace(self, auto_promote=replace(self.auto_promote, **changes))

    def explain(self):
        return {'governance_policy_version': self.version,
                'auto_promote': self.auto_promote.explain(),
                'shadow': self.shadow.explain(),
                'regression_budgets': self.budgets.explain(),
                'promotion_budgets': self.promotion.explain(),
                'rollback_thresholds': self.rollback.explain(),
                'guarded_stages': [stage.explain() for stage in self.stages],
                'guarded_activation_enabled': self.guarded_activation_enabled,
                'auto_rollback_enabled': self.auto_rollback_enabled,
                'note': ('every tolerance here is operator policy, not a measured '
                         'or derived value')}

    def summary(self):
        """What `model governance status` prints. Includes the digest, because
        "which policy authorised this" is the question asked after an incident."""
        return {'governance_policy_version': self.version,
                'policy_digest': self.digest[:16],
                'auto_promote': self.auto_promote.enabled,
                'global_auto_promote': self.auto_promote.global_enabled,
                'sites_opted_in': list(self.auto_promote.sites),
                'guarded_stages': [stage.name for stage in self.stages],
                'auto_rollback': self.auto_rollback_enabled}


def from_config(config):
    """Build a policy from validated configuration, or the default if absent.

    A configuration with no governance section produces the default policy with
    auto-promotion off, which is exactly what a fresh install gets. That equality
    is deliberate: "the section is missing" and "the section says no" must not be
    two different behaviours, or an upgrade that adds the section becomes a
    behaviour change (§98, §144).
    """
    settings = getattr(config, 'model_governance', None)
    if settings is None:
        return GovernancePolicy()
    auto = AutoPromoteSettings(
        enabled=bool(settings.auto_promote_enabled),
        global_enabled=bool(settings.auto_promote_global_enabled),
        sites=tuple(str(site) for site in (settings.auto_promote_sites or ())))
    shadow = ShadowRequirements(
        minimum_seconds=float(settings.minimum_shadow_seconds),
        minimum_feature_vectors=int(settings.minimum_shadow_samples),
        minimum_source_groups=int(settings.minimum_source_groups),
        minimum_trusted_outcomes=int(settings.minimum_trusted_outcomes))
    promotion = PromotionBudgets(
        minimum_promotion_interval_seconds=float(settings.promotion_cooldown_seconds),
        max_promotions_per_day=int(settings.max_promotions_per_day),
        max_promotions_per_site_per_day=int(settings.max_promotions_per_site_per_day),
        max_rollbacks_per_day=int(settings.max_rollbacks_per_day))
    return GovernancePolicy(
        auto_promote=auto, shadow=shadow, promotion=promotion,
        guarded_activation_enabled=bool(settings.guarded_activation_enabled),
        auto_rollback_enabled=bool(settings.auto_rollback_enabled))
