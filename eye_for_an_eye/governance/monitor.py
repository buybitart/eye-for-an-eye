"""What happens after a promotion, and when to undo it.

Guarded activation limits the damage a wrong promotion can do. This module is the
other half: noticing that one happened, and putting it back.

The shape of the decision is three-tiered, and the tiers are not interchangeable.

**Technical failures withdraw the model quickly.** Inference errors, non-finite
output, a model that stops loading, a health state of UNRELIABLE. These are
unambiguous — nothing about them gets clearer with more observation — and every
minute the broken model stays is a minute the site is defended by something that
does not work.

**Resource regressions withdraw it too, and for a reason that is not about
security at all.** If the new model makes the site slow, the site is worse off
than it would be with no model, and website availability outranks model
experimentation every time (§51, §147).

**Quality regressions withdraw it slowly, on reviewed evidence only.** A model
that is technically fine but blocks more real visitors is the worst case in this
whole stage, and it is also the one where acting fast is wrong: the evidence is
human review, review takes time, and a system that rolled back on one ambiguous
unlabelled request would change its model with the weather.

Two things are deliberately *not* rollback triggers on their own.

**Out-of-distribution rate** (§49). A high rate says the model recognises less of
what it is seeing. The model it would be rolled back to is older and has seen
even less. Rolling back on OOD alone would systematically swap a model that knows
it is uncertain for one that does not.

**Drift** (§50). The population moved. That is a fact about the traffic, not a
fault in the model, and the previous model is not less drifted.

Both can pause a stage advance and ask for a person. Neither is an accusation.
"""
from dataclasses import asdict, dataclass, field

MONITOR_SCHEMA_VERSION = 1

#: What the monitor recommends.
KEEP = 'KEEP'
#: Stop advancing and ask for a person. Not a rollback.
FREEZE_ADVANCEMENT = 'FREEZE_ADVANCEMENT'
ROLLBACK_TECHNICAL = 'ROLLBACK_TECHNICAL'
ROLLBACK_RESOURCE = 'ROLLBACK_RESOURCE'
ROLLBACK_QUALITY = 'ROLLBACK_QUALITY'

ROLLBACKS = (ROLLBACK_TECHNICAL, ROLLBACK_RESOURCE, ROLLBACK_QUALITY)
VERDICTS = (KEEP, FREEZE_ADVANCEMENT) + ROLLBACKS


@dataclass
class PostPromotionSignals:
    """What has been observed since the promotion.

    Counters and rates only. Nothing here grows with traffic, because this runs
    unattended for as long as a guarded stage lasts.
    """

    observed_seconds: float = 0.0
    feature_vectors: int = 0
    #: Technical.
    inference_failures: int = 0
    consecutive_inference_failures: int = 0
    non_finite_outputs: int = 0
    model_health: str = 'HEALTHY'
    load_failures: int = 0
    #: Resource. `baseline_*` is the previous model's measurement, so the
    #: comparison is against what the site had, not against an absolute.
    latency_p95_ms: float | None = None
    baseline_latency_p95_ms: float | None = None
    rss_bytes: int | None = None
    baseline_rss_bytes: int | None = None
    sustained_resource_seconds: float = 0.0
    event_drops: int = 0
    #: Quality, from reviewed outcomes only.
    reviewed_outcomes: int = 0
    reviewed_false_blocks: int = 0
    baseline_reviewed_false_blocks: int = 0
    block_precision: float | None = None
    baseline_block_precision: float | None = None
    #: Context. Never a rollback trigger on its own.
    ood_ratio: float | None = None
    baseline_ood_ratio: float | None = None
    drift_status: str = 'STABLE'
    #: Action distribution, this model against the previous one.
    actions: dict = field(default_factory=dict)
    baseline_actions: dict = field(default_factory=dict)
    large_disagreements: int = 0
    scored_by_both: int = 0

    @property
    def failure_ratio(self):
        if not self.feature_vectors:
            return None
        return self.inference_failures / self.feature_vectors

    def strong_action_ratio(self, actions):
        """Fraction of decisions at RATE_LIMIT or above."""
        total = sum(actions.values())
        if not total:
            return None
        strong = sum(count for name, count in actions.items()
                     if name in ('RATE_LIMIT', 'TEMP_BLOCK'))
        return strong / total

    def explain(self):
        body = asdict(self)
        body['failure_ratio'] = self.failure_ratio
        body['strong_action_ratio'] = self.strong_action_ratio(self.actions)
        body['baseline_strong_action_ratio'] = self.strong_action_ratio(self.baseline_actions)
        return body


@dataclass(frozen=True, slots=True)
class MonitorVerdict:
    """One recommendation, with every reason that produced it."""

    verdict: str
    reasons: tuple = field(default_factory=tuple)
    signals: dict = field(default_factory=dict)

    @property
    def rollback(self):
        return self.verdict in ROLLBACKS

    def explain(self):
        return {'monitor_schema_version': MONITOR_SCHEMA_VERSION,
                'verdict': self.verdict, 'reasons': list(self.reasons),
                'rollback': self.rollback, 'signals': self.signals}

    def render(self):
        """§85's shape, for the CLI and the audit log."""
        lines = [f'POST-PROMOTION VERDICT\n\n{self.verdict}\n']
        if self.reasons:
            lines.append('Reasons:')
            lines.extend(f'  - {reason}' for reason in self.reasons)
        if self.rollback:
            lines.append('\nFirewall state:\nunchanged\n\nDataset:\nunchanged')
        return '\n'.join(lines) + '\n'


class PostPromotionMonitor:
    """Reads signals, returns a recommendation. Withdraws nothing itself.

    Same separation as the governance engine: this computes, the activator acts.
    A bug here can recommend a rollback that was not needed — which costs a
    promotion and nothing else — but cannot itself change which model is running.
    """

    def __init__(self, policy):
        self.policy = policy

    def evaluate(self, signals, *, guarded=True):
        """The recommendation, in severity order. Technical first, always."""
        limits = self.policy.rollback
        reasons = []

        technical = self._technical(signals, limits)
        if technical:
            return MonitorVerdict(ROLLBACK_TECHNICAL, tuple(technical),
                                  signals.explain())

        resource = self._resource(signals, limits)
        if resource:
            return MonitorVerdict(ROLLBACK_RESOURCE, tuple(resource),
                                  signals.explain())

        quality, insufficient = self._quality(signals, limits)
        if quality:
            return MonitorVerdict(ROLLBACK_QUALITY, tuple(quality), signals.explain())
        reasons.extend(insufficient)

        freeze = self._freeze(signals, limits)
        if freeze:
            return MonitorVerdict(FREEZE_ADVANCEMENT, tuple(freeze + reasons),
                                  signals.explain())

        return MonitorVerdict(KEEP, tuple(reasons) or
                              ('no technical, resource or reviewed-quality problem '
                               'has been observed',), signals.explain())

    # --- tiers ------------------------------------------------------------

    def _technical(self, signals, limits):
        """§47. Unambiguous, and not made clearer by waiting."""
        reasons = []
        if signals.non_finite_outputs:
            reasons.append(f'{signals.non_finite_outputs} non-finite outputs; a '
                           'model producing NaN is not producing evidence')
        if signals.load_failures:
            reasons.append(f'the model failed to load {signals.load_failures} times '
                           'after activation')
        if signals.model_health == 'UNRELIABLE':
            reasons.append('model health is UNRELIABLE')
        if signals.consecutive_inference_failures >= limits.max_consecutive_inference_failures:
            reasons.append(
                f'{signals.consecutive_inference_failures} consecutive inference '
                f'failures, at or above the limit of '
                f'{limits.max_consecutive_inference_failures}')
        ratio = signals.failure_ratio
        if (ratio is not None and ratio > limits.max_inference_failure_ratio
                and signals.observed_seconds >= limits.technical_window_seconds):
            reasons.append(
                f'inference failed on {ratio:.1%} of windows over '
                f'{signals.observed_seconds:.0f}s, above the '
                f'{limits.max_inference_failure_ratio:.1%} limit')
        return reasons

    def _resource(self, signals, limits):
        """§51. The site being slow is worse than the site being unmodelled."""
        reasons = []
        if signals.sustained_resource_seconds < limits.sustained_seconds_before_resource_rollback:
            # A spike is not a regression. Without this, a garbage collection
            # pause would withdraw a perfectly good model.
            return reasons
        current, baseline = signals.latency_p95_ms, signals.baseline_latency_p95_ms
        if current and baseline and current > baseline * limits.max_latency_increase_ratio:
            reasons.append(
                f'p95 inference latency {current:g} ms against a baseline of '
                f'{baseline:g} ms, sustained for '
                f'{signals.sustained_resource_seconds:.0f}s')
        current, baseline = signals.rss_bytes, signals.baseline_rss_bytes
        if current and baseline and current > baseline * limits.max_rss_increase_ratio:
            reasons.append(f'resident memory {current} bytes against a baseline of '
                           f'{baseline} bytes, sustained')
        if signals.event_drops:
            reasons.append(f'{signals.event_drops} events were dropped; the sensor '
                           'is losing traffic it should be seeing')
        return reasons

    def _quality(self, signals, limits):
        """§48, §132. Reviewed evidence only, and enough of it."""
        if signals.reviewed_outcomes < limits.minimum_reviewed_outcomes_for_quality_rollback:
            return [], [
                f'{signals.reviewed_outcomes} reviewed outcomes of '
                f'{limits.minimum_reviewed_outcomes_for_quality_rollback} needed '
                'before a quality regression can be acted on; unlabelled traffic '
                'cannot establish that a model is blocking the wrong people']
        reasons = []
        increase = signals.reviewed_false_blocks - signals.baseline_reviewed_false_blocks
        if increase > limits.max_reviewed_false_block_increase:
            reasons.append(
                f'{increase} more reviewed false blocks than the previous model '
                f'({signals.reviewed_false_blocks} against '
                f'{signals.baseline_reviewed_false_blocks}) across '
                f'{signals.reviewed_outcomes} reviewed outcomes')
        current, baseline = signals.block_precision, signals.baseline_block_precision
        if (current is not None and baseline is not None
                and current < baseline - limits.max_block_precision_drop):
            reasons.append(f'block precision fell from {baseline:g} to {current:g} '
                           'on reviewed outcomes')
        return reasons, []

    def _freeze(self, signals, limits):
        """§52, §49, §50. Stop advancing, ask a person, withdraw nothing."""
        reasons = []
        current = signals.strong_action_ratio(signals.actions)
        baseline = signals.strong_action_ratio(signals.baseline_actions)
        if current is not None and baseline is not None:
            if baseline == 0 and current > 0:
                reasons.append(
                    f'the previous model never reached RATE_LIMIT or above and this '
                    f'one does on {current:.1%} of decisions; that may be a real '
                    'attack wave or a regression, and the difference needs a person')
            elif baseline > 0 and current > baseline * limits.action_surge_ratio:
                reasons.append(
                    f'decisions at RATE_LIMIT or above went from {baseline:.1%} to '
                    f'{current:.1%}; a surge is not by itself evidence of anything, '
                    'and advancement waits until somebody has looked')
        if signals.drift_status == 'DRIFTED':
            reasons.append('the population has drifted, which lowers how much any '
                           'model can be trusted here and is not a fault in this '
                           'one; advancement pauses rather than rolling back')
        current, baseline = signals.ood_ratio, signals.baseline_ood_ratio
        if (current is not None and baseline is not None and current > baseline * 2
                and current > 0.5):
            reasons.append(
                f'out-of-distribution rate {current:.0%} against {baseline:.0%} for '
                'the previous model; this model recognises less of the current '
                'traffic, which is a reason to review and not a reason to return to '
                'an older model that has seen even less of it')
        return reasons

    def explain(self):
        return {'monitor_schema_version': MONITOR_SCHEMA_VERSION,
                'thresholds': self.policy.rollback.explain(),
                'note': ('the monitor recommends; the activator acts. Neither '
                         'out-of-distribution rate nor drift can withdraw a model '
                         'on its own')}
