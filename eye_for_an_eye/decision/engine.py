"""Source-window decisions, bounded history, and structured auditable explanations."""
from collections import Counter
from dataclasses import asdict
import queue
import time
from ..compatibility import FEATURE_SCHEMA
from ..enrichment.cache import TTLCache
from ..events import NetworkEvent
from ..event_types import EventType
from .anomaly import AnomalyModel, AnomalyResult
from .distribution import DistributionError, RollingDistribution, load_reference, transformed_values
from .drift import DriftEngine, model_health
from .features import from_samples, NAMES, FeatureTransformer
from .math_risk import MathRiskEngine, decay
from .ood import OODEngine
from .onnx_model import IsolatedModel, MLResult
from .policy import DecisionFusion, POLICY_GUARD_VERSION, PolicyGuard, usable_ml
from .worker import InferenceWorker

#: §20's four words for an optional component. `NOT_CONFIGURED` is a statement
#: about the operator's intent; the other three are statements about the
#: component. Keeping them in one vocabulary is what lets a status page say "one
#: thing you asked for is broken" instead of "one thing is missing".
NOT_CONFIGURED = 'NOT_CONFIGURED'
HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNAVAILABLE = 'UNAVAILABLE'


def _component(status, detail=''):
    return {'status': status, 'detail': str(detail)[:200]}


class DecisionEngine:
    """Windows in, decisions out — and, since P15.5R, through the P15 authority.

    ### Two authorities, one at a time

    Until P15.5R this class was the whole of the shipped decision path:
    `DecisionFusion` produced a fused risk, three fixed thresholds turned it into
    an action, and a `TEMP_BLOCK` went straight to `TemporaryBlocks`. The P15
    stack — calibrated probability, evidence maturity, expected loss,
    `AutonomousDecisionAuthority` — was validated across five cycles and never
    constructed by a running sensor. `reports/P15_5R_RUNTIME_BEFORE.md` traced
    it: twelve modules on the decision path, none of them in `autonomy/`.

    So this class now holds an `AutonomousDecisionPipeline` when
    `config.autonomy.enabled`, and when it does, **that pipeline owns TEMP_BLOCK
    outright**:

    * `TemporaryBlocks` is not constructed at all (§2, §4, §32) — the legacy
      enforcer is absent rather than merely unused, because an object that
      exists is an object somebody can call;
    * the fused ladder keeps WATCH and RATE_LIMIT, which is what §3 asks for:
      the old path still carries intermediate evidence and telemetry, and only
      its block authority is withdrawn;
    * a fused `TEMP_BLOCK` the authority did not confirm is reduced to `WATCH`,
      by the same reduction rule `PolicyGuard.apply` already applies when it
      refuses, and the record says `autonomous_authority_allowed`.

    With `autonomy.enabled` false, every line below behaves exactly as it did at
    P15.5, which is what makes this a wiring change rather than a rewrite.
    """

    def __init__(self, config, correlator, *, offline=False, enforcer=None,
                 pipeline=None):
        self.config, self.correlator, self.offline = config, correlator, offline
        self.math, self.fusion, self.guard = MathRiskEngine(), DecisionFusion(config.decision), PolicyGuard(config)
        self.history = TTLCache(config.decision.history_entries, config.decision.history_ttl_seconds, max_bytes=8_388_608)
        self.worker = None
        self.pending = {}
        self.metrics = Counter()
        self.enforcer = enforcer
        self.healthy = True
        self.loss_fraction = None
        self.local_addresses = ()
        self.load_failure_recorded = False
        # P8 reliability. Absent artifacts leave every factor neutral, so a
        # deployment without a reference distribution behaves exactly as P7 did.
        self.reference = None
        self.ood = OODEngine(None)
        self.rolling = None
        self.drift = DriftEngine(None)
        self.drift_result = None
        self.ood_observations = 0
        self.ood_high = 0
        self.anomaly = AnomalyModel(enabled=False)
        # P9 review queue. Optional and off by default. It can only ever add an
        # UNREVIEWED row; no code path here writes a label.
        self.review_queue = None
        #: Why the last review-queue offer failed, for `doctor`. Empty is healthy.
        self.review_queue_last_error = ''
        # P15.5R. The P15 decision stack, built here or not at all. `None` means
        # the deployment did not ask for autonomy and the legacy path decides;
        # anything else means it owns TEMP_BLOCK and the legacy enforcer is
        # never constructed.
        self.autonomy = pipeline
        #: Why the last autonomous decision failed, for `doctor`. Empty is healthy.
        self.autonomous_last_error = ''
        if self.autonomy is None and getattr(config, 'autonomy', None) is not None \
                and config.autonomy.enabled and config.decision.enabled:
            from ..autonomy.pipeline import from_config as pipeline_from_config
            self.autonomy = pipeline_from_config(config)
        self._load_reference()
        self._prepare_anomaly()
        self._prepare_review_queue()

    @property
    def autonomous_authority(self):
        """Whether the P15 authority owns TEMP_BLOCK in this process.

        Asked rather than assumed at every site that could enforce, so the
        single-authority invariant is one expression and not five.
        """
        return self.autonomy is not None and self.autonomy.owns_enforcement

    def _prepare_review_queue(self):
        """Open the review queue if the operator asked for one.

        A missing secret or an unusable path leaves the queue closed and counts a
        metric. Collecting behaviour for later human review is a convenience; it
        is never allowed to put the decision path at risk.
        """
        reliability = getattr(self.config, 'reliability', None)
        if reliability is None or not getattr(reliability, 'review_queue_enabled', False):
            return
        if not reliability.review_queue_path or not reliability.review_queue_secret_file:
            self.metrics['review_queue_unavailable_total'] += 1
            return
        try:
            from pathlib import Path
            from .review_queue import QueueLimits, ReviewQueue
            secret = Path(reliability.review_queue_secret_file).read_bytes().strip()
            if len(secret) < 32:
                raise ValueError('the review queue secret must be at least 32 bytes')
            self.review_queue = ReviewQueue(
                reliability.review_queue_path, secret=secret,
                limits=QueueLimits(max_entries=reliability.review_queue_max_entries,
                                   per_source_entries=reliability.review_queue_per_source,
                                   per_day_entries=reliability.review_queue_per_day,
                                   ttl_days=reliability.review_queue_ttl_days,
                                   min_observations=reliability.review_queue_min_observations))
        except (OSError, ValueError, ImportError):
            self.review_queue = None
            self.metrics['review_queue_unavailable_total'] += 1

    def _offer_for_review(self, vector, source, *, math_result, ml, risk, action,
                          ood_result, anomaly_result):
        """Offer an unclear window for later human review.

        Called after the decision is already made and cannot change it. What earns
        a place is disagreement, a middle risk or unfamiliar behaviour: never the
        fact that the system acted. A failure here is counted and dropped, because
        no part of collecting training material may interrupt defending.
        """
        if self.review_queue is None:
            return
        try:
            from .review_queue import admission, summarise_vector, vector_payload
            priority, reasons = admission(
                math_score=math_result.score,
                model_score=ml.risk_score if usable_ml(ml) else None,
                fused_risk=risk, acted=action in ('TEMP_BLOCK', 'RATE_LIMIT'),
                ood_score=ood_result.score if (ood_result is not None and ood_result.usable) else None,
                ood_band=ood_result.status if ood_result is not None else '',
                anomaly_score=anomaly_result.anomaly_score if anomaly_result.usable else None,
                observations=vector.sample_count)
            if priority <= 0:
                return
            result = self.review_queue.offer(
                source=source, behaviour=summarise_vector(vector),
                evidence={'observations': vector.sample_count,
                          'observation_seconds': round(vector.observation_seconds, 2)},
                priority=priority, reasons=reasons, features=vector_payload(vector),
                analysis_only={'math_score': round(math_result.score, 6),
                               'model_score': round(ml.risk_score, 6) if usable_ml(ml) else None,
                               'final_score': round(risk, 6), 'action': action,
                               'note': 'shown to a reviewer for context; never a label, never a feature'})
            self.metrics['review_queue_offered_total'] += 1
            self.metrics['review_queue_admitted_total'] += int(bool(result.get('admitted')))
        except Exception as exc:
            # Swallowing is deliberate: collecting training material must never
            # interrupt defending. But a *permanent* failure here is invisible —
            # the queue simply stays empty and nothing says why — so the reason
            # is kept for `doctor` and the counter is split by exception type.
            self.metrics['review_queue_failures_total'] += 1
            self.review_queue_last_error = f'{type(exc).__name__}: {exc}'[:200]

    def _prepare_anomaly(self):
        reliability = getattr(self.config, 'reliability', None)
        if reliability is None:
            return
        self.anomaly = AnomalyModel(
            enabled=reliability.anomaly_enabled,
            manifest_path=reliability.anomaly_manifest_path,
            model_path=reliability.anomaly_model_path,
            timeout_ms=reliability.anomaly_timeout_ms,
            max_failures=reliability.anomaly_max_failures)

    def _load_reference(self):
        """Load the reference distribution bound to the configured model.

        A missing or mismatched baseline is never fatal and never silently
        substituted: the system simply keeps no distribution opinion.
        """
        reliability = getattr(self.config, 'reliability', None)
        if reliability is None or not reliability.distribution_path:
            return
        if not (reliability.ood_enabled or reliability.drift_enabled):
            return
        try:
            self.reference = load_reference(reliability.distribution_path)
        except (DistributionError, OSError, ValueError):
            self.metrics['distribution_load_failures_total'] += 1
            return
        if reliability.ood_enabled:
            self.ood = OODEngine(self.reference, borderline_threshold=reliability.ood_borderline_threshold,
                                 high_threshold=reliability.ood_high_threshold,
                                 minimum_features=reliability.ood_minimum_features)
        if reliability.drift_enabled:
            self.rolling = RollingDistribution(self.reference)
            self.drift = DriftEngine(self.reference, warning_threshold=reliability.drift_warning_threshold,
                                     drifted_threshold=reliability.drift_drifted_threshold,
                                     minimum_samples=reliability.drift_minimum_samples)

    @property
    def ood_rate(self):
        """Share of recent observations the model has not seen before, or None."""
        return self.ood_high / self.ood_observations if self.ood_observations else None

    def model_health(self):
        return model_health(loaded=self.worker is not None,
                            model_version=self.health().get('model_version', 'none'),
                            drift=self.drift_result, ood_rate=self.ood_rate)

    def component_health(self):
        """P15.5R §20, §21. Every optional component, in four words.

        The four are `NOT_CONFIGURED`, `HEALTHY`, `DEGRADED`, `UNAVAILABLE`, and
        the rule that makes them worth having is the one §20 states: **a
        configured component that is broken never reports `NOT_CONFIGURED`.**

        That rule exists because the opposite is what P15.4 shipped. The
        classifier was configured, every prediction failed on a column-count
        mismatch, and the health surface said the same thing it says for a
        deployment that never wanted a classifier at all. "Nobody asked for it"
        and "it is broken" are opposite facts and they were reported with the
        same word, so the only visible symptom of a broken component was an
        absence — and an absence is exactly what a component nobody configured
        looks like.

        `detail` is bounded text for a person, never a metric label.
        """
        reliability = getattr(self.config, 'reliability', None)
        report = {}

        # -- the auxiliary classifier ---------------------------------------
        configured = bool(self.config.ml.enabled and self.config.ml.model_path
                          and self.config.ml.manifest_path)
        if not configured:
            report['auxiliary_ml'] = _component(NOT_CONFIGURED, 'no classifier is configured')
        elif self.worker is None:
            report['auxiliary_ml'] = _component(
                UNAVAILABLE, 'a classifier is configured and was not started')
        else:
            state = self.health()
            if state.get('status') == 'healthy':
                failed = self.metrics.get('ml_inference_failed_total', 0)
                total = self.metrics.get('ml_inference_total', 0)
                report['auxiliary_ml'] = _component(
                    DEGRADED if failed and failed == total and total else HEALTHY,
                    f"{state.get('model_version', 'none')}, "
                    f"{failed}/{total} inferences failed")
            else:
                report['auxiliary_ml'] = _component(
                    UNAVAILABLE,
                    str(state.get('error') or state.get('status'))[:120])

        # -- anomaly ---------------------------------------------------------
        # `anomaly_enabled` ships true and the artifact paths ship empty, so
        # "enabled" alone is not a request for anomaly scoring — it is the
        # absence of a refusal. Naming an artifact is the request, and only then
        # is a failure to load somebody's problem.
        if not (self.anomaly.enabled and self.anomaly.model_path):
            report['anomaly'] = _component(NOT_CONFIGURED, 'no anomaly model is configured')
        elif self.anomaly.loaded:
            failed = self.metrics.get('anomaly_inference_failures_total', 0)
            report['anomaly'] = _component(DEGRADED if failed else HEALTHY,
                                           f'{failed} scoring failures')
        else:
            report['anomaly'] = _component(
                UNAVAILABLE, str(self.anomaly.load_error or 'artifact not loaded')[:120])

        # -- OOD and drift, which share one reference distribution ----------
        for name, wanted, live in (
                ('ood', bool(reliability and reliability.ood_enabled), self.reference is not None),
                ('drift', bool(reliability and reliability.drift_enabled), self.rolling is not None)):
            path = bool(reliability and reliability.distribution_path)
            if not (wanted and path):
                report[name] = _component(NOT_CONFIGURED,
                                          'no reference distribution is configured')
            elif live:
                report[name] = _component(HEALTHY, 'reference distribution loaded')
            else:
                report[name] = _component(
                    UNAVAILABLE,
                    f'the reference distribution at {reliability.distribution_path} '
                    f'could not be loaded')

        # -- authentication context -----------------------------------------
        ledger = getattr(self.correlator, 'auth', None)
        report['auth_context'] = (
            _component(UNAVAILABLE, 'the correlation engine has no authentication ledger')
            if ledger is None else
            _component(HEALTHY, f'{len(ledger.cache)} sources tracked'))

        # -- the calibrator and the authority -------------------------------
        if self.autonomy is None:
            report['calibrator'] = _component(NOT_CONFIGURED, 'autonomy is off')
            report['decision_authority'] = _component(
                NOT_CONFIGURED, 'the legacy fused path decides in this deployment')
        else:
            state = self.autonomy.calibrator_state
            report['calibrator'] = _component(state.status, state.reason or state.version)
            report['decision_authority'] = _component(
                UNAVAILABLE if self.autonomous_last_error else HEALTHY,
                self.autonomous_last_error or
                f'{self.autonomy.mode}, {self.autonomy.counters["decisions"]} decisions')
        return report

    def evaluate_drift(self, window='24h'):
        """Periodic, never on the hot path. Returns None when drift is not configured."""
        if self.rolling is None:
            return None
        self.drift_result = self.drift.evaluate(self.rolling.snapshot(window))
        self.metrics['drift_evaluations_total'] += 1
        self.metrics['drift_drifted_features'] = self.drift_result.drifted_features
        self.metrics['drift_warning_features'] = self.drift_result.warning_features
        return self.drift_result

    def start(self):
        if not self.config.decision.enabled:
            return
        # §2, §4, §32. One final authority at a time. When the P15 pipeline owns
        # TEMP_BLOCK the legacy enforcer is not built, so there is no second
        # object in this process that could place a block — a stronger statement
        # than a flag somebody has to remember to check, and the one
        # `tests/test_p15_5r_single_authority.py` asserts.
        if (self.config.enforcement.enabled and not self.offline
                and self.enforcer is None and not self.autonomous_authority):
            from ..security.temporary_blocks import TemporaryBlocks
            self.enforcer = TemporaryBlocks(self.config)
        # An anomaly artifact is never trained at startup; a missing one is a
        # supported state and the sensor continues without it.
        if self.anomaly.enabled and not self.anomaly.load():
            self.metrics['anomaly_model_unavailable_total'] += 1
        if self.config.ml.enabled and self.config.ml.model_path and self.config.ml.manifest_path:
            self.worker = IsolatedModel(self.config.ml) if self.offline else InferenceWorker(self.config.ml)
            if self.offline:
                status = self.worker.load()
                if self.config.ml.required and status['status'] != 'healthy':
                    raise RuntimeError('required ML unavailable')
            else:
                self.worker.start()

    def health(self):
        if self.worker is None:
            # The schema this build computes, asked of the contract rather than
            # written down. A literal here said 1 while the schema in force was
            # 2 — harmless on its own, and the same class of mistake that made
            # P15.4 block nothing (P15.5 §2, §3).
            return {'status': 'disabled' if not self.config.ml.enabled else 'unavailable',
                    'model_version': 'none',
                    'feature_schema_version': FEATURE_SCHEMA.current, 'loaded': False}
        state = self.worker.health() if self.offline else self.worker.model.health()
        if (not self.load_failure_recorded and state.get('error') and
                (self.offline or self.worker.ready.is_set()) and state['status'] == 'unavailable'):
            self.metrics['model_load_failure_total'] += 1
            self.load_failure_recorded = True
        return state

    def _autonomous(self, base, vector, math_result, ml, quality, services,
                    ood_result, anomaly_result, reasons, previous, offense, stamp):
        """Run the P15 decision for this window. Never raises onto the hot path.

        A failure here must not become an exception in `_record`, because the
        caller of `_record` is the event loop and its answer to an exception is
        to stop consuming events. So a broken pipeline produces an ALLOW outcome
        with a reason, which is a state the rest of this method already knows how
        to report.
        """
        from ..autonomy.pipeline import FailedOutcome
        # §8. The export row carries the component states this decision was
        # taken under, which is information only this class has. Refreshed per
        # window rather than cached, because "the classifier was healthy when
        # this decision happened" is the claim the row makes.
        self.autonomy._component_health = {
            name: entry['status'] for name, entry in self.component_health().items()}
        try:
            return self.autonomy.decide(
                source=base.src_ip, vector=vector, math_result=math_result, ml=ml,
                quality=quality, services=services, ood=ood_result,
                anomaly=anomaly_result,
                protected='protected_source' in reasons,
                offence_count=offense,
                existing_block=stamp < previous.get('blocked_until', 0),
                enforcement_healthy=self.healthy,
                policy_guard_action='REFUSED' if 'protected_source' in reasons else 'ALLOW',
                policy_guard_reasons=tuple(reasons),
                model_health=self.model_health().state if self.reference is not None else '')
        except Exception as exc:                                   # noqa: BLE001
            self.metrics['autonomous_pipeline_failures_total'] += 1
            self.autonomous_last_error = f'{type(exc).__name__}: {exc}'[:200]
            return FailedOutcome(reason=self.autonomous_last_error)

    def _record(self, base, vector, ml, services=()):
        key = (base.sensor_id, base.src_ip)
        stamp = base.timestamp.timestamp()
        previous = self.history.get(key, {})
        if stamp < previous.get('stamp', 0):
            return None
        math_result = self.math.evaluate(vector)
        values = dict(zip(NAMES, vector.values))
        ood_result = None
        if self.reference is not None:
            transformed = transformed_values(vector)
            ood_result = self.ood.evaluate(transformed)
            if ood_result.usable:
                self.ood_observations += 1
                self.ood_high += int(ood_result.status == 'OUT_OF_DISTRIBUTION')
                self.metrics['ood_evaluations_total'] += 1
                self.metrics['ood_high_total'] += int(ood_result.status == 'OUT_OF_DISTRIBUTION')
            else:
                self.metrics['ood_insufficient_reference_total'] += 1
            if self.rolling is not None:
                self.rolling.observe(transformed)
        anomaly_result = AnomalyResult(status='disabled')
        if self.anomaly.loaded:
            # Projected to the schema this artifact was fitted on, so a column
            # added after it was exported cannot shift the slots underneath it.
            anomaly_result = self.anomaly.score(
                FeatureTransformer.project(vector, self.anomaly.feature_schema_version))
            self.metrics['anomaly_inference_total'] += 1
            if not anomaly_result.usable:
                self.metrics['anomaly_inference_failures_total'] += 1
            self.metrics['anomaly_inference_seconds_sum'] += anomaly_result.inference_ms / 1000.0
            self.metrics['anomaly_inference_seconds_count'] += 1
        confidence = ood_result.distribution_confidence if ood_result is not None else 1.0
        evidence = self.fusion.evaluate(math_result, ml, min(1, (values['persistence_900s'] or 0) / 300),
                                        distribution_confidence=confidence, anomaly=anomaly_result)
        fused = evidence.threat_evidence
        historical = previous.get('before_pending', previous) if stamp == previous.get('stamp') and ml.status != 'pending' else previous
        decayed = decay(historical.get('risk', 0.0), max(0, stamp - historical.get('stamp', stamp)), self.config.decision.half_life_seconds)
        risk = max(fused, decayed)
        proposed = self.fusion.state(risk, historical.get('action', 'OBSERVE'))
        try:
            action, reasons, quality = self.guard.apply(proposed, vector, math_result, ml, source=base.src_ip,
                healthy=self.healthy, local_addresses=self.local_addresses,
                ood=ood_result, model_health=self.model_health() if self.reference is not None else None,
                evidence=evidence)
        except Exception:
            action, reasons, quality = 'OBSERVE', ['policy_failure'], None
        fused_action = action
        offense = previous.get('offense', 0)
        last_offense = previous.get('last_offense', 0.0)
        if stamp - last_offense >= self.config.enforcement.offense_decay_seconds:
            offense = 0
        # -- P15.5R: the authority, where one is configured ---------------------
        outcome = None
        if self.autonomy is not None:
            outcome = self._autonomous(base, vector, math_result, ml, quality,
                                       services, ood_result, anomaly_result,
                                       reasons, previous, offense, stamp)
            if outcome.blocked:
                action = 'TEMP_BLOCK'
            elif fused_action == 'TEMP_BLOCK':
                # The fused ladder wanted a block and the authority did not
                # grant one. Reduced by the rule `PolicyGuard.apply` already
                # uses when it refuses, rather than a mapping invented here.
                action = 'WATCH'
                reasons.append('autonomous_authority_allowed')
        would = action == 'TEMP_BLOCK'
        enforced, duration = False, 0
        if would and outcome is not None:
            enforced = outcome.enforced
            duration = outcome.record.block_ttl_seconds if enforced else 0
            if outcome.enforcement_withheld:
                reasons.append(outcome.enforcement_withheld)
            elif outcome.execution is not None and not enforced:
                reasons.append('host_enforcement_refused' if outcome.execution.refused
                               else 'host_enforcement_failed')
            if enforced:
                offense += 1
                last_offense = stamp
        elif would:
            if self.offline or self.config.decision.mode == 'shadow':
                reasons.append('shadow_mode')
            elif not self.config.enforcement.enabled:
                reasons.append('enforcement_disabled')
            elif self.enforcer is None:
                reasons.append('firewall_unavailable')
            elif stamp < previous.get('blocked_until', 0):
                reasons.append('existing_temporary_lease')
            else:
                duration = self.config.enforcement.block_seconds[min(offense, len(self.config.enforcement.block_seconds) - 1)]
                try:
                    enforced = self.enforcer.block(base.src_ip, duration)
                    if not enforced:
                        reasons.append('firewall_refused_or_capacity')
                except Exception:
                    reasons.append('firewall_failure')
                if enforced:
                    offense += 1
                    last_offense = stamp
        if action == 'RATE_LIMIT':
            reasons.append('rate_limit_observation_only')
        stored = {'stamp': stamp, 'evaluated': stamp, 'risk': risk, 'action': action,
            'offense': offense, 'last_offense': last_offense,
            'blocked_until': stamp + duration if enforced else previous.get('blocked_until', 0.0)}
        if ml.status == 'pending':
            stored['before_pending'] = {k: previous[k] for k in ('risk', 'stamp', 'action') if k in previous}
        self.history.set(key, stored)
        disagreement = 'none'
        if usable_ml(ml):
            if math_result.score >= .8 and ml.risk_score <= .2:
                disagreement = 'math_high_ml_low'
            elif math_result.score <= .2 and ml.risk_score >= .8:
                disagreement = 'math_low_ml_high'
        self.metrics['math_decision_total'] += 1
        self.metrics['decision_' + action.lower() + '_total'] += 1
        self.metrics['decision_disagreement_total'] += int(disagreement != 'none')
        self.metrics['shadow_would_block_total'] += int(would and (self.offline or self.config.decision.mode == 'shadow'))
        self.metrics['enforced_block_total'] += int(enforced)
        self.metrics['policy_override_total'] += int(action != proposed)
        self.metrics['policy_ood_suppressed_total'] += int('out_of_distribution' in reasons)
        self.metrics['policy_model_health_suppressed_total'] += int(
            any(r.startswith('model_health_') for r in reasons))
        self.metrics['data_quality_low_total'] += int('insufficient_data_quality' in reasons)
        self._offer_for_review(vector, base.src_ip, math_result=math_result, ml=ml, risk=risk,
                               action=action, ood_result=ood_result, anomaly_result=anomaly_result)
        observations = {
            # §34. The schema this build computes, asked of the contract. The
            # literal that used to sit here reported 1 while schema 2 was in
            # force, so every consumer of a decision record was told the wrong
            # number — the same class of defect as P15.4's, without its
            # consequences, which is exactly how that one started.
            'decision_version': 1, 'feature_schema_version': FEATURE_SCHEMA.current,
            'action': action, 'proposed_action': proposed,
            'risk': round(risk, 6), 'math_score': round(math_result.score, 6),
            'math_version': math_result.model_version,
            'math_contributions': {k: round(v, 5) for k, v in sorted(math_result.contributions.items(), key=lambda p: p[1], reverse=True)[:6]},
            'ml': asdict(ml), 'quality': asdict(quality) if quality else {},
            'sample_count': vector.sample_count,
            'evidence': evidence.explain(), 'anomaly': anomaly_result.explain(),
            'ood': ood_result.explain() if ood_result is not None else {'status': 'INSUFFICIENT_REFERENCE'},
            'model_health': self.model_health().explain() if self.reference is not None else {},
            'observation_seconds': vector.observation_seconds,
            'would_enforce': would, 'enforced': enforced,
            'block_seconds': duration if enforced else 0,
            'policy_reasons': reasons[:12], 'disagreement': disagreement,
            'policy_guard_version': POLICY_GUARD_VERSION,
            'supporting_event_id': base.event_id}
        limitations = ['single_sensor_behavior_not_identity', 'bounded_observation_windows']
        if outcome is None:
            # The fused risk is a weighted sum of scores, not a probability, and
            # the record has always said so. With the authority wired in the
            # decision *is* taken against a calibrated probability, so repeating
            # the disclaimer there would be false modesty in the other direction.
            limitations.append('uncalibrated_scores')
        else:
            # The bounded form. `serialize_event` replaces the observations of
            # any log record over 4096 bytes with `{'record_truncated': True}`,
            # so a full `explain()` here cost the operator the action and the
            # address as well as the detail. `summary()` is what a person reads
            # first; the journal keeps everything.
            observations['autonomous'] = outcome.summary()
            observations['fused_action'] = fused_action
            if not outcome.calibrated:
                limitations.append('uncalibrated_scores')
        return NetworkEvent(base.src_ip, event_type=EventType.DECISION, timestamp=base.timestamp,
                            sensor_id=base.sensor_id, observations=observations,
                            limitations=limitations)

    def observe(self, event):
        if not self.config.decision.enabled:
            return []
        stamp = event.timestamp.timestamp()
        key = (event.sensor_id, event.src_ip)
        previous = self.history.get(key, {})
        if stamp < previous.get('evaluated', float('-inf')) + self.config.decision.interval_ms / 1000:
            return []
        state = self.correlator.cache.get(key)
        if not state or not any(s.event_id == event.event_id for s in state['samples']):
            return []
        try:
            vector = from_samples(state['samples'], now=stamp, horizon=max(self.config.correlation.windows),
                previous_risk=decay(previous.get('risk', 0.0), max(0, stamp - previous.get('stamp', stamp)), self.config.decision.half_life_seconds),
                capped=state['capped'], loss_fraction=self.loss_fraction,
                # P15.4. The authentication ledger is keyed the same way this
                # cache is, and it is the only place the five schema-2 columns
                # can come from. Without this argument the ledger records
                # outcomes that nothing ever reads, and `AUTH_BEHAVIOR` scores
                # zero on a brute force — which is exactly what it did until
                # this line existed.
                auth=self.correlator.auth.features(key, now=stamp))
        except ValueError:
            return []
        # P15.5R §11. Which priced services this window touched, for the cost
        # scope. Derived here, where the window is, and carried with the vector
        # rather than re-derived later — the asynchronous classifier path reaches
        # `_record` from `poll()`, by which time the correlation state has moved
        # on. Bounded strings from `Sample.port` filtered by the operator's own
        # map; no address and no host, ever.
        services = (self.autonomy.scopes.services_for(state['samples'])
                    if self.autonomy is not None else ())
        ml = MLResult(error='not_loaded')
        if self.worker and self.offline:
            # Projected to the schema the loaded artifact declares — see the
            # note on the asynchronous path in `worker.py`.
            ml = self.worker.predict(FeatureTransformer.project(
                vector, self.worker.health()['feature_schema_version']))
            self._ml_metric(ml)
        elif self.worker and len(self.pending) < self.config.ml.max_pending:
            # Retain only bounded metadata and numeric vectors, never original observations/payload.
            base = NetworkEvent(event.src_ip, timestamp=event.timestamp, event_id=event.event_id, sensor_id=event.sensor_id)
            if self.worker.submit(event.event_id, vector):
                self.pending[event.event_id] = (base, vector, time.monotonic(), services)
                ml = MLResult('pending')
            else:
                self.metrics['ml_inference_failed_total'] += 1
        elif self.worker:
            self.metrics['ml_inference_failed_total'] += 1
        record = self._record(event, vector, ml, services)
        return [record] if record else []

    def _ml_metric(self, result):
        self.metrics['ml_inference_total'] += 1
        self.metrics['ml_inference_failed_total'] += int(result.status != 'healthy')
        self.metrics['ml_inference_seconds_sum'] += result.inference_ms / 1000
        self.metrics['ml_inference_seconds_count'] += 1

    def poll(self):
        records = []
        if self.worker and not self.offline:
            for _ in range(self.config.ml.max_pending):
                try:
                    identifier, result = self.worker.results.get_nowait()
                except queue.Empty:
                    break
                task = self.pending.pop(identifier, None)
                self._ml_metric(result)
                if task:
                    record = self._record(task[0], task[1], result, task[3])
                    if record:
                        records.append(record)
            now = time.monotonic()
            for identifier in [k for k, v in self.pending.items() if now - v[2] > self.config.ml.inference_timeout_ms / 1000 + 1]:
                self.pending.pop(identifier)
                self.metrics['ml_inference_failed_total'] += 1
        return records

    def close(self):
        if self.worker:
            self.worker.close()
        if self.autonomy is not None:
            try:
                self.autonomy.close()
            except Exception:                                      # noqa: BLE001
                self.metrics['autonomous_pipeline_failures_total'] += 1
        self.pending.clear()
        if self.enforcer:
            try:
                self.enforcer.close()
            except Exception:
                # Kernel entries still expire; never attempt a broader cleanup.
                self.metrics['policy_override_total'] += 1
