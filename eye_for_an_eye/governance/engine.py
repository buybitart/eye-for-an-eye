"""The governance engine: deterministic gates, one verdict, every reason kept.

This is the module §1 is about. It does not ask whether the candidate is better.
It asks a list of named questions with stated tolerances, records every answer,
and derives a decision from the answers. Nothing here is learned, adaptive or
scored — a promotion policy that could be influenced by the thing it judges is
not a policy.

The order the questions are asked in is itself a safety property:

    integrity        is this artifact what it claims to be?
    compatibility    does it fit the system that will run it?
    health           does it work?
    governance       are we allowed to change anything right now?
    sufficiency      is there enough evidence to have this conversation?
    quality          is it acceptable? (benign safety before security quality)

An artifact that fails integrity is QUARANTINED whatever its metrics say, because
"the hash is wrong" is not a quality trade-off. A candidate that passes
everything but lacks trusted labels is NEED_MORE_DATA, which is a different
answer from no and must never be collapsed into one — the difference between "it
regressed" and "we could not tell" is the difference between a decision and a
guess.

Benign safety is evaluated before security quality, and its budgets are the
tightest in the policy. A candidate that catches more scanners while blocking
more ordinary visitors is not an improvement, and the people it blocks are
disproportionately the ones on unusual networks, unusual clients and unusual
schedules — the ones least able to get a block lifted.
"""
from . import assessment as record_module
from .assessment import (ADVISORY, BENIGN_SAFETY, BLOCKING, GENERALIZATION,
                         GOVERNANCE, INTEGRITY, MODEL_HEALTH, RESOURCE_COST,
                         SECURITY_QUALITY, SYSTEM_COMPATIBILITY, gate)
from .evidence import (ContextEvidence, GovernanceState, HEALTHY, HealthEvidence,
                       OfflineEvidence, ShadowEvidence)
from .policy import GovernancePolicy

GOVERNANCE_ENGINE_VERSION = 1


class ModelGovernanceEngine:
    """Assesses a candidate. Changes nothing, ever.

    `assess` is pure with respect to the system: it reads evidence and returns a
    record. Activation is a separate authority in a separate module, and the only
    thing it accepts from here is an `ELIGIBLE` record — which means a bug in the
    gates can refuse a good model but cannot promote a bad one.
    """

    def __init__(self, policy=None):
        self.policy = policy or GovernancePolicy()

    # --- the public entry point ------------------------------------------

    def assess(self, *, scope, artifact, offline=None, shadow=None, health=None,
               context=None, state=None, active_artifact=None, active_offline=None,
               now=None):
        """One candidate, one scope, one verdict, with every gate recorded."""
        offline = offline or OfflineEvidence()
        shadow = shadow or ShadowEvidence()
        health = health or HealthEvidence()
        context = context or ContextEvidence()
        state = state or GovernanceState()
        active_offline = active_offline or OfflineEvidence()

        integrity, quarantine_reasons = self._integrity_gates(artifact, health, scope)
        outcomes = list(integrity)
        outcomes += self._compatibility_gates(artifact, offline)
        outcomes += self._health_gates(health)
        outcomes += self._governance_gates(artifact, state, scope)
        outcomes += self._sufficiency_gates(shadow)
        outcomes += self._benign_safety_gates(offline, active_offline, shadow, context)
        outcomes += self._security_quality_gates(offline, active_offline)
        outcomes += self._generalization_gates(shadow, context, scope)
        outcomes += self._resource_gates(artifact, offline, active_offline, shadow)

        return record_module.build(
            scope=scope, candidate_version=artifact.version, policy=self.policy,
            outcomes=tuple(outcomes),
            active_version=getattr(active_artifact, 'version', '') or '',
            dataset_version=artifact.dataset_version,
            feature_schema_version=artifact.feature_schema_version,
            offline_report_hash=record_module.report_hash(offline.explain()),
            shadow_report_hash=record_module.report_hash(shadow.explain()),
            quarantined=bool(quarantine_reasons),
            quarantine_reasons=quarantine_reasons, now=now)

    # --- integrity --------------------------------------------------------

    def _integrity_gates(self, artifact, health, scope):
        """Is the artifact what it says it is? A failure here is quarantine.

        Quarantine rather than rejection, because these failures say the file
        cannot be trusted rather than that the model is not good enough, and the
        two deserve different treatment: a rejected candidate can be superseded
        by a better one, a quarantined artifact needs a person to look at why it
        is wrong before anything similar is tried again (§31).
        """
        outcomes, reasons = [], []

        matches = bool(artifact.sha256) and artifact.sha256 == artifact.declared_sha256
        outcomes.append(gate('artifact_hash', INTEGRITY, BLOCKING, matches,
                             'the bytes on disk must match the manifest digest'))
        if not matches:
            reasons.append('artifact_hash: the model file does not match its manifest')

        scope_ok = bool(artifact.scope) and artifact.scope == scope
        outcomes.append(gate('model_scope', INTEGRITY, BLOCKING, scope_ok,
                             f'the model declares {artifact.scope!r} and would be '
                             f'promoted for {scope!r}'))
        if not scope_ok:
            reasons.append("model_scope: a model built for one scope must never run for another")

        outcomes.append(gate('feature_order', INTEGRITY, BLOCKING,
                             artifact.feature_order_matches,
                             'the column order must be this build\'s column order'))
        if not artifact.feature_order_matches:
            reasons.append('feature_order: the model reads the columns in a different order')

        outcomes.append(gate('finite_outputs', INTEGRITY, BLOCKING,
                             health.candidate_finite_outputs,
                             'the model must not produce NaN or infinity'))
        if not health.candidate_finite_outputs:
            reasons.append('finite_outputs: the model produced a non-finite score')

        size_ok = 0 < artifact.size_bytes <= self.policy.budgets.max_model_size_bytes
        outcomes.append(gate('artifact_size', INTEGRITY, BLOCKING, size_ok,
                             'the artifact must be within the configured size bound',
                             candidate=artifact.size_bytes))
        if not size_ok:
            reasons.append('artifact_size: the model file is outside the permitted size')

        return outcomes, tuple(reasons)

    # --- compatibility ----------------------------------------------------

    def _compatibility_gates(self, artifact, offline):
        from ..decision.features import MODEL_SCHEMAS, SCHEMA_VERSION
        budgets = self.policy.budgets
        outcomes = []

        # The question is whether this build can *serve* the model, which is not
        # the same as whether the schemas are equal. A model fitted on an older
        # schema is served correctly through `FeatureTransformer.project`; one
        # fitted on a schema this build does not know is refused, because nothing
        # here could construct its columns. Demanding equality would have blocked
        # every promotion the moment a feature was appended — which looks like a
        # safety gate doing its job and is in fact a build that can no longer
        # ship anything.
        outcomes.append(gate(
            'feature_schema', SYSTEM_COMPATIBILITY, BLOCKING,
            artifact.feature_schema_version in MODEL_SCHEMAS,
            f'the model was built for feature schema '
            f'{artifact.feature_schema_version}; this build serves '
            f'{sorted(MODEL_SCHEMAS)} and constructs {SCHEMA_VERSION}',
            candidate=artifact.feature_schema_version))

        parity = offline.onnx_parity_max_abs_error
        outcomes.append(gate(
            'onnx_parity', SYSTEM_COMPATIBILITY, BLOCKING,
            parity is not None and parity <= budgets.max_onnx_parity_error,
            'the exported graph must reproduce the trained model',
            candidate=parity, unproven=parity is None))

        outcomes.append(gate(
            'dataset_validation', SYSTEM_COMPATIBILITY, BLOCKING,
            offline.dataset_validation_passed,
            'the training dataset must have passed validation'))

        outcomes.append(gate(
            'group_split', SYSTEM_COMPATIBILITY, BLOCKING,
            offline.group_split_verified,
            'the split must be by source group, never by row'))

        # §18, §90: the candidate must have been replayed through the whole
        # stack, not scored on its own. A classifier compared in isolation tells
        # you about a number nobody acts on.
        outcomes.append(gate(
            'system_replay', SYSTEM_COMPATIBILITY, BLOCKING,
            offline.system_replay_completed,
            'the candidate must be evaluated through maths, fusion and PolicyGuard, '
            'not from its own score alone'))

        # §88. Empty means the manifest did not say, which is unknown rather
        # than compatible.
        for name, declared in (('fusion_compatibility', artifact.compatible_fusion_version),
                               ('policy_compatibility', artifact.compatible_policy_version)):
            outcomes.append(gate(
                name, SYSTEM_COMPATIBILITY, ADVISORY, bool(declared),
                'the manifest did not declare a compatible version' if not declared
                else f'declared compatible with {declared}'))

        return outcomes

    # --- health -----------------------------------------------------------

    def _health_gates(self, health):
        outcomes = [
            gate('candidate_health', MODEL_HEALTH, BLOCKING,
                 health.candidate_state == HEALTHY,
                 f'only a HEALTHY candidate may auto-promote; this one is '
                 f'{health.candidate_state}'),
            gate('candidate_load', MODEL_HEALTH, BLOCKING,
                 health.candidate_load_succeeded,
                 'the candidate must load in an isolated process before activation'),
            gate('warmup', MODEL_HEALTH, BLOCKING, health.warmup_completed,
                 'the candidate must answer a synthetic feature vector before it '
                 'is allowed to answer a real one'),
            gate('inference_errors', MODEL_HEALTH, BLOCKING,
                 health.candidate_inference_errors == 0,
                 'the candidate must not fail inference during evaluation',
                 candidate=health.candidate_inference_errors),
            gate('inference_timeouts', MODEL_HEALTH, BLOCKING,
                 health.candidate_timeouts == 0,
                 'the candidate must not exceed the inference deadline',
                 candidate=health.candidate_timeouts),
        ]
        # §25, recorded and deliberately not blocking in either direction: a
        # degraded active model is context for a person, never a licence to
        # accept a candidate that has not passed its own gates.
        outcomes.append(gate(
            'active_health_context', MODEL_HEALTH, ADVISORY, True,
            f'the active model is {health.active_state}; this does not lower any '
            'threshold the candidate must meet'))
        return outcomes

    # --- governance -------------------------------------------------------

    def _governance_gates(self, artifact, state, scope):
        budgets = self.policy.promotion
        outcomes = []

        allowed, reason = self.policy.auto_promote.allows(scope)
        outcomes.append(gate('auto_promote_permitted', GOVERNANCE, BLOCKING,
                             allowed, reason))

        outcomes.append(gate('not_frozen', GOVERNANCE, BLOCKING, not state.frozen,
                             state.freeze_reason or 'governance is not frozen'))
        outcomes.append(gate('not_safe_mode', GOVERNANCE, BLOCKING, not state.safe_mode,
                             'model safe mode disables automatic promotion'))

        # §58. The single most important governance gate: no way back, no
        # automatic way forward.
        outcomes.append(gate(
            'rollback_target', GOVERNANCE, BLOCKING, bool(state.rollback_target),
            'a promotion with no model to fall back to is not reversible, and '
            'nothing irreversible happens automatically'))

        elapsed = state.seconds_since_last_promotion
        cooled = elapsed is None or elapsed >= budgets.minimum_promotion_interval_seconds
        outcomes.append(gate(
            'promotion_cooldown', GOVERNANCE, BLOCKING, cooled,
            'models must not churn; a promotion waits out the configured interval',
            candidate=elapsed))

        outcomes.append(gate(
            'daily_promotion_budget', GOVERNANCE, BLOCKING,
            state.promotions_today < budgets.max_promotions_per_day,
            'the daily promotion budget for this installation is spent',
            candidate=state.promotions_today))
        outcomes.append(gate(
            'scope_promotion_budget', GOVERNANCE, BLOCKING,
            state.promotions_today_this_scope < budgets.max_promotions_per_site_per_day,
            'the daily promotion budget for this scope is spent',
            candidate=state.promotions_today_this_scope))
        outcomes.append(gate(
            'concurrency', GOVERNANCE, BLOCKING,
            state.in_flight_promotions < budgets.max_concurrent_promotions,
            'another promotion is in flight; one scope changes at a time',
            candidate=state.in_flight_promotions))

        # §80, §81. A withdrawn candidate does not get to try again unchanged.
        retried = (artifact.version in state.rolled_back_versions
                   or artifact.version in state.quarantined_versions)
        outcomes.append(gate(
            'not_previously_withdrawn', GOVERNANCE, BLOCKING, not retried,
            f'{artifact.version} was rolled back or quarantined before; it needs a '
            'new evaluation or a new version, not another attempt at the same one'))

        return outcomes

    # --- evidence sufficiency --------------------------------------------

    def _sufficiency_gates(self, shadow):
        """Is there enough shadow evidence for any of this to mean anything?

        These are BLOCKING and marked unproven rather than failed, which makes
        the verdict NEED_MORE_DATA. "Not enough evidence" is not a fault of the
        candidate, and reporting it as one would teach an operator to read a
        refusal as a judgement.
        """
        required = self.policy.shadow
        outcomes = []

        for name, observed, minimum, unit in (
                ('shadow_duration', shadow.observed_seconds, required.minimum_seconds, 'seconds'),
                ('shadow_samples', shadow.feature_vectors, required.minimum_feature_vectors,
                 'feature vectors'),
                ('shadow_source_groups', shadow.source_groups, required.minimum_source_groups,
                 'source groups'),
                ('shadow_site_activity', shadow.sites_with_activity,
                 required.minimum_sites_with_activity, 'sites with activity')):
            enough = observed >= minimum
            outcomes.append(gate(
                name, GENERALIZATION, BLOCKING, enough,
                f'{observed:g} of {minimum:g} {unit} observed in shadow',
                candidate=observed, unproven=not enough))

        ratio = shadow.failure_ratio
        outcomes.append(gate(
            'shadow_inference_failures', MODEL_HEALTH, BLOCKING,
            ratio is not None and ratio <= required.maximum_inference_failure_ratio,
            'the candidate must run reliably on real traffic before it runs it',
            candidate=ratio, unproven=ratio is None))

        return outcomes

    # --- benign safety ----------------------------------------------------

    def _benign_safety_gates(self, offline, active, shadow, context):
        """The strongest constraints in the policy, and the first ones evaluated.

        Every gate here needs ground truth, so every one of them becomes
        UNPROVEN rather than passing when the trusted outcomes are not there.
        That is the §12 rule made mechanical: a large pile of unlabelled shadow
        traffic cannot demonstrate that a candidate blocks fewer innocent people.
        """
        budgets = self.policy.budgets
        required = self.policy.shadow.minimum_trusted_outcomes
        trusted = max(offline.trusted_outcomes, shadow.trusted_outcomes)
        enough = trusted >= required and (offline.trusted or shadow.trusted_outcomes > 0)
        outcomes = [gate(
            'trusted_outcomes', BENIGN_SAFETY, BLOCKING, enough,
            f'{trusted} trusted reviewed outcomes of {required} required; quality '
            'gates need labels whose provenance we trust',
            candidate=trusted, unproven=not enough)]

        def compare(name, key, limit, higher_is_worse=True, category=BENIGN_SAFETY):
            a, c = getattr(active, key), getattr(offline, key)
            if a is None or c is None or not enough:
                outcomes.append(gate(
                    name, category, BLOCKING, False,
                    f'{key} was not measured for both models on trusted labels',
                    active=a, candidate=c, unproven=True))
                return
            ok = c <= a + limit if higher_is_worse else c >= a - limit
            outcomes.append(gate(
                name, category, BLOCKING, ok,
                f'{key}: active {a:g}, candidate {c:g}, budget {limit:g}',
                active=a, candidate=c))

        compare('false_blocks', 'false_blocks_per_1000_benign',
                budgets.max_false_block_increase_per_1000)
        compare('hard_negatives', 'hard_negative_false_block_rate',
                budgets.max_hard_negative_regression)

        # §48, §132. Reviewed false blocks observed during shadow, which is the
        # most direct evidence available and the least ambiguous.
        a = shadow.reviewed_false_blocks_active
        c = shadow.reviewed_false_blocks_candidate
        if a is None or c is None:
            outcomes.append(gate(
                'reviewed_false_blocks', BENIGN_SAFETY, ADVISORY, False,
                'no reviewed false blocks were recorded for either model',
                unproven=True))
        else:
            outcomes.append(gate(
                'reviewed_false_blocks', BENIGN_SAFETY, BLOCKING, c <= a,
                f'reviewed false blocks: active {a}, candidate {c}',
                active=a, candidate=c))

        return outcomes

    # --- security quality -------------------------------------------------

    def _security_quality_gates(self, offline, active):
        """Does it still catch what the active model catches?

        Note what is *not* here: no gate requires the candidate to improve
        anything. §14 asks for regression budgets, not for improvement, and a
        candidate that matches the active model on security while costing less
        or generalising better is a perfectly good reason to promote.
        """
        budgets = self.policy.budgets
        trusted = offline.trusted and active.trusted
        outcomes = []

        a, c = active.block_precision, offline.block_precision
        if a is None or c is None or not trusted:
            outcomes.append(gate(
                'block_precision', SECURITY_QUALITY, BLOCKING, False,
                'system-level block precision was not measured for both models on '
                'trusted labels', active=a, candidate=c, unproven=True))
        else:
            outcomes.append(gate(
                'block_precision', SECURITY_QUALITY, BLOCKING,
                c >= a - budgets.max_block_precision_drop,
                f'block precision: active {a:g}, candidate {c:g}, budget '
                f'{budgets.max_block_precision_drop:g}', active=a, candidate=c))

        a, c = active.hard_positive_recall, offline.hard_positive_recall
        if a is None or c is None:
            outcomes.append(gate(
                'hard_positives', SECURITY_QUALITY, ADVISORY, False,
                'hard-positive recall was not measured for both models', unproven=True))
        else:
            outcomes.append(gate(
                'hard_positives', SECURITY_QUALITY, BLOCKING,
                c >= a - budgets.max_hard_positive_recall_drop,
                'the candidate must not buy precision by ignoring patient scanners',
                active=a, candidate=c))

        for name in ('pr_auc', 'roc_auc'):
            a, c = getattr(active, name), getattr(offline, name)
            if a is None or c is None:
                continue
            outcomes.append(gate(
                name, SECURITY_QUALITY, ADVISORY, c >= a,
                f'{name}: active {a:g}, candidate {c:g}', active=a, candidate=c))

        return outcomes

    # --- generalization ---------------------------------------------------

    def _generalization_gates(self, shadow, context, scope):
        """OOD, drift and per-site fairness. None of these refuses on its own.

        §21, §23, §49, §50. A higher out-of-distribution rate means the model
        recognises less of what it is seeing, not that what it is seeing is
        hostile; drift means the population moved, not that the model is bad.
        Both are recorded as advisory, and both can stop a *stage advance* later
        without ever being read as an accusation.
        """
        outcomes = []

        a, c = context.active_ood_ratio, context.candidate_ood_ratio
        if a is not None and c is not None:
            outcomes.append(gate(
                'ood_comparison', GENERALIZATION, ADVISORY, c <= a,
                f'out-of-distribution rate: active {a:g}, candidate {c:g}. Lower is '
                'more familiar traffic, not better security', active=a, candidate=c))
        else:
            outcomes.append(gate('ood_comparison', GENERALIZATION, ADVISORY, False,
                                 'out-of-distribution rate was not measured for both',
                                 unproven=True))

        outcomes.append(gate(
            'drift_context', GENERALIZATION, ADVISORY,
            context.drift_status not in ('DRIFTED',),
            f'population drift is {context.drift_status}; drift lowers how much the '
            'model can be trusted and is never evidence of an attack'))

        shift = shadow.action_shift()
        if shift is None:
            outcomes.append(gate('action_distribution', GENERALIZATION, ADVISORY, False,
                                 'no action distribution was recorded for either model',
                                 unproven=True))
        else:
            outcomes.append(gate(
                'action_distribution', GENERALIZATION,
                BLOCKING if shift > self.policy.budgets.max_action_distribution_shift else ADVISORY,
                shift <= self.policy.budgets.max_action_distribution_shift,
                f'the candidate would act differently on {shift:.1%} of traffic; a '
                'large shift is a reason for a person to look, not a verdict',
                candidate=shift))

        # §73, §74, §75. A global candidate is judged by its worst site, because
        # an aggregate that improves while one site gets much worse is exactly
        # the outcome the aggregate is good at hiding.
        if scope == 'GLOBAL':
            site, value = context.worst_site('per_site_false_blocks')
            if site is None:
                outcomes.append(gate(
                    'worst_site_false_blocks', BENIGN_SAFETY, BLOCKING, False,
                    'a global promotion needs per-site evidence; an aggregate hides '
                    'the site that got worse', unproven=True))
            else:
                limit = self.policy.budgets.max_false_block_increase_per_1000
                outcomes.append(gate(
                    'worst_site_false_blocks', BENIGN_SAFETY, BLOCKING, value <= limit,
                    f'worst site is {site} at {value:g} false blocks per 1000 benign '
                    f'sources, budget {limit:g}', candidate=value))

        return outcomes

    # --- resource cost ----------------------------------------------------

    def _resource_gates(self, artifact, offline, active, shadow):
        budgets = self.policy.budgets
        outcomes = []

        a = active.inference_p95_ms
        c = offline.inference_p95_ms if offline.inference_p95_ms is not None else shadow.inference_p95_ms
        if a and c:
            outcomes.append(gate(
                'inference_latency', RESOURCE_COST, BLOCKING,
                c <= a * budgets.max_latency_increase_ratio,
                f'p95 inference: active {a:g} ms, candidate {c:g} ms, budget '
                f'x{budgets.max_latency_increase_ratio:g}', active=a, candidate=c))
        else:
            outcomes.append(gate('inference_latency', RESOURCE_COST, BLOCKING, False,
                                 'inference latency was not measured for both models',
                                 active=a, candidate=c, unproven=True))

        a, c = active.rss_bytes, offline.rss_bytes
        if a and c:
            outcomes.append(gate(
                'memory', RESOURCE_COST, BLOCKING, c <= a * budgets.max_rss_increase_ratio,
                f'resident memory: active {a} bytes, candidate {c} bytes',
                active=a, candidate=c))
        else:
            outcomes.append(gate('memory', RESOURCE_COST, ADVISORY, False,
                                 'resident memory was not measured for both models',
                                 unproven=True))

        outcomes.append(gate(
            'model_load_time', RESOURCE_COST, BLOCKING,
            0 <= artifact.load_seconds <= budgets.max_model_load_seconds,
            'a model that takes too long to load makes activation a visible pause',
            candidate=artifact.load_seconds))

        return outcomes

    # --- reporting --------------------------------------------------------

    def explain(self):
        return {'governance_engine_version': GOVERNANCE_ENGINE_VERSION,
                'policy': self.policy.summary(),
                'note': ('the engine assesses and records; activation is a separate '
                         'authority that accepts only an ELIGIBLE record')}
