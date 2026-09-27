"""What the governance engine is allowed to look at, and where it came from.

Every input to a promotion decision arrives through one of these types. That is
a deliberate narrowing: the engine cannot reach into a model, a registry or a
sensor to go looking for a number, so the set of things that can influence a
promotion is the set of fields below, and it can be read in one sitting.

The distinction that does the most work here is **provenance**. A count of
requests that a candidate would have challenged is a real measurement and proves
nothing about whether those challenges would have been correct. A reviewed
outcome with trusted provenance proves something. Mixing the two is how a system
talks itself into "the candidate is more precise" from unlabelled traffic, which
§11 and §12 forbid and which this module makes structurally awkward: unlabelled
statistics live on `ShadowEvidence`, trusted outcomes live in their own counted
field, and the quality gates read only the latter.
"""
from dataclasses import asdict, dataclass, field

#: Where a label came from, and how much a promotion decision may lean on it.
#: Carried over from the dataset provenance vocabulary rather than invented here.
TRUSTED_PROVENANCE = ('controlled_lab', 'trusted_labeled_dataset', 'manual_review',
                      'controlled_scenario', 'trusted_fixture')

#: Candidate health states (§24). Only HEALTHY may auto-promote.
HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNRELIABLE = 'UNRELIABLE'
UNAVAILABLE = 'UNAVAILABLE'
HEALTH_STATES = (HEALTHY, DEGRADED, UNRELIABLE, UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class ArtifactEvidence:
    """What is true of the model file itself, independent of its quality.

    Everything here is checked by the governance engine against the registry and
    the loader, never taken from the candidate's own manifest claims (§30). A
    manifest saying `precision = 1.0` is metadata; a manifest saying
    `feature_schema_version = 1` is a claim to be verified.
    """

    version: str = ''
    scope: str = ''
    #: Recomputed from the bytes on disk, not copied from the manifest.
    sha256: str = ''
    declared_sha256: str = ''
    feature_schema_version: int = 0
    feature_order_matches: bool = False
    dataset_version: str = ''
    parent_model: str = ''
    size_bytes: int = 0
    load_seconds: float = 0.0
    #: The manifest may declare which fusion and policy versions it was built
    #: against (§88). Empty means "did not say", which is not the same as
    #: "compatible" and is treated as unknown rather than as agreement.
    compatible_fusion_version: str = ''
    compatible_policy_version: str = ''

    def explain(self):
        body = asdict(self)
        body['sha256'] = self.sha256[:16]
        body['declared_sha256'] = self.declared_sha256[:16]
        return body


@dataclass(frozen=True, slots=True)
class OfflineEvidence:
    """Measurements from evaluation, produced independently of the candidate.

    `None` means not measured. It never means zero, and the gates treat it as
    unknown — a missing number is never silently read as an improvement.
    """

    dataset_validation_passed: bool = False
    group_split_verified: bool = False
    onnx_parity_max_abs_error: float | None = None
    #: Security quality (§14).
    pr_auc: float | None = None
    roc_auc: float | None = None
    precision: float | None = None
    recall: float | None = None
    hard_positive_recall: float | None = None
    #: Benign safety (§15, §16).
    false_blocks_per_1000_benign: float | None = None
    hard_negative_false_block_rate: float | None = None
    #: System-level, simulated through the whole stack rather than from the
    #: classifier's own output (§18).
    block_precision: float | None = None
    system_replay_completed: bool = False
    #: Calibration (§22). None when the model is not calibrated, in which case
    #: its output is a score and must not be called a probability.
    calibration_error: float | None = None
    calibrated: bool = False
    #: Resource cost (§20).
    inference_p95_ms: float | None = None
    rss_bytes: int | None = None
    #: How many trusted, reviewed outcomes the measurements above rest on.
    #: Quality gates that need ground truth read this and nothing else.
    trusted_outcomes: int = 0
    label_provenance: tuple = ()

    @property
    def trusted(self):
        """Whether the labels behind these numbers are ones we may lean on."""
        if not self.label_provenance:
            return False
        return all(source in TRUSTED_PROVENANCE for source in self.label_provenance)

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ShadowEvidence:
    """What the candidate did beside the active model, on real traffic.

    Almost all of this is unlabelled. It can establish health, stability,
    compatibility and how different the two models are; it cannot establish that
    one of them is more often right (§12). The one field that can carry weight in
    a quality gate is `trusted_outcomes`, and it is counted separately for that
    reason.
    """

    observed_seconds: float = 0.0
    feature_vectors: int = 0
    source_groups: int = 0
    sites_with_activity: int = 0
    scored_by_both: int = 0
    agreement_ratio: float | None = None
    large_disagreements: int = 0
    #: Would-be actions, per model. A distribution, not a verdict (§53).
    active_actions: dict = field(default_factory=dict)
    candidate_actions: dict = field(default_factory=dict)
    inference_failures: int = 0
    inference_p95_ms: float | None = None
    active_ood_ratio: float | None = None
    candidate_ood_ratio: float | None = None
    trusted_outcomes: int = 0
    #: Reviewed outcomes where the candidate would have been wrong about a
    #: benign source. The strongest single piece of evidence against promotion.
    reviewed_false_blocks_active: int | None = None
    reviewed_false_blocks_candidate: int | None = None

    @property
    def disagreement_ratio(self):
        if not self.scored_by_both:
            return None
        return self.large_disagreements / self.scored_by_both

    @property
    def failure_ratio(self):
        if not self.feature_vectors:
            return None
        return self.inference_failures / self.feature_vectors

    def action_shift(self):
        """Total variation distance between the two action distributions.

        Bounded in [0, 1] and symmetric. A large value is a reason to look, not
        a reason to conclude: a candidate that watches more sources may be
        better or worse, and this number does not say which (§52).
        """
        names = set(self.active_actions) | set(self.candidate_actions)
        if not names:
            return None
        active_total = sum(self.active_actions.values()) or 1
        candidate_total = sum(self.candidate_actions.values()) or 1
        return 0.5 * sum(
            abs(self.active_actions.get(name, 0) / active_total
                - self.candidate_actions.get(name, 0) / candidate_total)
            for name in names)

    def explain(self):
        body = asdict(self)
        body['disagreement_ratio'] = self.disagreement_ratio
        body['failure_ratio'] = self.failure_ratio
        body['action_shift'] = self.action_shift()
        return body


@dataclass(frozen=True, slots=True)
class HealthEvidence:
    """Candidate and active model health (§24, §25).

    The asymmetry here is the point: a degraded ACTIVE model is a reason to want
    a replacement, and never a reason to accept a worse one. `active_state` is
    recorded so an operator can see the context, and no gate reads it as a
    licence.
    """

    candidate_state: str = UNAVAILABLE
    active_state: str = UNAVAILABLE
    candidate_load_succeeded: bool = False
    candidate_finite_outputs: bool = False
    candidate_inference_errors: int = 0
    candidate_timeouts: int = 0
    warmup_completed: bool = False

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ContextEvidence:
    """Drift, out-of-distribution rate and data quality around the decision.

    None of these is evidence that anything is hostile, and none of them alone
    refuses or authorises a promotion (§21, §23, §49, §50). They lower or raise
    how much the rest of the evidence can be trusted.
    """

    drift_status: str = 'INSUFFICIENT_DATA'
    active_ood_ratio: float | None = None
    candidate_ood_ratio: float | None = None
    data_quality: str = 'UNKNOWN'
    site_state: str = 'UNKNOWN'
    #: Per-site numbers for a global candidate (§74, §75). Aggregates hide the
    #: site that got worse, so the worst site is inspected separately.
    per_site_block_precision: dict = field(default_factory=dict)
    per_site_false_blocks: dict = field(default_factory=dict)

    def worst_site(self, metric='per_site_false_blocks'):
        """The site with the least favourable value, or None.

        False blocks: higher is worse. Block precision: lower is worse.
        """
        values = getattr(self, metric, {}) or {}
        if not values:
            return None, None
        if metric == 'per_site_block_precision':
            site = min(values, key=lambda name: values[name])
        else:
            site = max(values, key=lambda name: values[name])
        return site, values[site]

    def explain(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GovernanceState:
    """What the system already knows about promotions, independent of evidence.

    Cooldowns, budgets, freezes and the rollback target are governance facts
    rather than measurements, and keeping them in their own type is what stops a
    quality gate from quietly reading one.
    """

    frozen: bool = False
    freeze_reason: str = ''
    safe_mode: bool = False
    #: Seconds since the last promotion in this scope. None means never.
    seconds_since_last_promotion: float | None = None
    promotions_today: int = 0
    promotions_today_this_scope: int = 0
    rollbacks_today: int = 0
    in_flight_promotions: int = 0
    consecutive_failures: int = 0
    #: The version this promotion would fall back to. Empty means there is
    #: none, which alone makes a candidate ineligible (§58).
    rollback_target: str = ''
    last_known_good: str = ''
    #: Versions that have been rolled back or quarantined and may not retry
    #: unchanged (§80, §81).
    quarantined_versions: tuple = ()
    rolled_back_versions: tuple = ()

    def explain(self):
        return asdict(self)
