"""P14 phase 6: the post-promotion monitor and automatic rollback.

The tests are organised by the three tiers, because the tiers are the design and
confusing them is how this feature would go wrong in either direction — a system
that withdraws a model on one ambiguous request, or one that keeps a broken model
because the evidence was not tidy enough.

The two negative results matter as much as the positive ones. A high
out-of-distribution rate and a drifted population must **not** withdraw a model,
and there are tests that fail if they ever start doing so. Both say the traffic
changed; the model that would be rolled back to is older and has seen even less
of it, so rolling back on either would reliably make things worse while looking
responsible.
"""
import unittest

from eye_for_an_eye.governance.monitor import (FREEZE_ADVANCEMENT, KEEP,
                                               ROLLBACK_QUALITY, ROLLBACK_RESOURCE,
                                               ROLLBACK_TECHNICAL,
                                               PostPromotionMonitor,
                                               PostPromotionSignals)
from eye_for_an_eye.governance.policy import GovernancePolicy


def signals(**changes):
    """A healthy, uneventful guarded period."""
    base = dict(observed_seconds=7_200.0, feature_vectors=5_000,
                inference_failures=0, consecutive_inference_failures=0,
                non_finite_outputs=0, model_health='HEALTHY', load_failures=0,
                latency_p95_ms=1.6, baseline_latency_p95_ms=1.5,
                rss_bytes=54_000_000, baseline_rss_bytes=52_000_000,
                sustained_resource_seconds=0.0, event_drops=0,
                reviewed_outcomes=40, reviewed_false_blocks=1,
                baseline_reviewed_false_blocks=1, block_precision=0.92,
                baseline_block_precision=0.90, ood_ratio=0.10,
                baseline_ood_ratio=0.14, drift_status='STABLE',
                actions={'OBSERVE': 4_600, 'WATCH': 350, 'RATE_LIMIT': 48,
                         'TEMP_BLOCK': 2},
                baseline_actions={'OBSERVE': 4_620, 'WATCH': 330, 'RATE_LIMIT': 48,
                                  'TEMP_BLOCK': 2},
                large_disagreements=120, scored_by_both=5_000)
    base.update(changes)
    return PostPromotionSignals(**base)


def monitor():
    return PostPromotionMonitor(GovernancePolicy())


class TestAQuietGuardedPeriodKeepsTheModel(unittest.TestCase):
    """If this fails, every other test here proves nothing."""

    def test_nothing_wrong_means_keep(self):
        verdict = monitor().evaluate(signals())
        self.assertEqual(verdict.verdict, KEEP, list(verdict.reasons))
        self.assertFalse(verdict.rollback)

    def test_the_verdict_carries_its_reasons_and_its_signals(self):
        verdict = monitor().evaluate(signals())
        self.assertTrue(verdict.reasons)
        self.assertIn('failure_ratio', verdict.signals)

    def test_it_renders_for_a_person(self):
        rendered = monitor().evaluate(signals(non_finite_outputs=3)).render()
        self.assertIn('POST-PROMOTION VERDICT', rendered)
        self.assertIn('unchanged', rendered)


class TestTechnicalRollback(unittest.TestCase):
    """§47, §130. Unambiguous, and not made clearer by waiting."""

    def test_non_finite_output_withdraws_the_model(self):
        verdict = monitor().evaluate(signals(non_finite_outputs=3))
        self.assertEqual(verdict.verdict, ROLLBACK_TECHNICAL)
        self.assertTrue(any('NaN' in reason for reason in verdict.reasons))

    def test_repeated_consecutive_inference_failures_withdraw_the_model(self):
        verdict = monitor().evaluate(signals(consecutive_inference_failures=25))
        self.assertEqual(verdict.verdict, ROLLBACK_TECHNICAL)

    def test_a_sustained_failure_rate_withdraws_the_model(self):
        verdict = monitor().evaluate(signals(inference_failures=500,
                                             feature_vectors=5_000,
                                             observed_seconds=3_600.0))
        self.assertEqual(verdict.verdict, ROLLBACK_TECHNICAL)

    def test_a_brief_failure_rate_does_not_withdraw_the_model(self):
        """A model is not withdrawn for a bad first minute."""
        verdict = monitor().evaluate(signals(inference_failures=500,
                                             feature_vectors=5_000,
                                             observed_seconds=30.0))
        self.assertNotEqual(verdict.verdict, ROLLBACK_TECHNICAL)

    def test_an_unreliable_health_state_withdraws_the_model(self):
        self.assertEqual(monitor().evaluate(signals(model_health='UNRELIABLE')).verdict,
                         ROLLBACK_TECHNICAL)

    def test_a_model_that_stops_loading_withdraws(self):
        self.assertEqual(monitor().evaluate(signals(load_failures=2)).verdict,
                         ROLLBACK_TECHNICAL)

    def test_technical_outranks_everything_else(self):
        """A broken model is withdrawn even when its numbers look excellent."""
        verdict = monitor().evaluate(signals(non_finite_outputs=1,
                                             block_precision=1.0,
                                             reviewed_false_blocks=0))
        self.assertEqual(verdict.verdict, ROLLBACK_TECHNICAL)


class TestResourceRollback(unittest.TestCase):
    """§51, §131, §147. Website availability outranks model experimentation."""

    def test_sustained_excess_latency_withdraws_the_model(self):
        verdict = monitor().evaluate(signals(latency_p95_ms=12.0,
                                             baseline_latency_p95_ms=1.5,
                                             sustained_resource_seconds=1_200.0))
        self.assertEqual(verdict.verdict, ROLLBACK_RESOURCE)

    def test_a_latency_spike_does_not_withdraw_the_model(self):
        """Without this, a garbage collection pause withdraws a good model."""
        verdict = monitor().evaluate(signals(latency_p95_ms=12.0,
                                             baseline_latency_p95_ms=1.5,
                                             sustained_resource_seconds=5.0))
        self.assertEqual(verdict.verdict, KEEP)

    def test_sustained_excess_memory_withdraws_the_model(self):
        verdict = monitor().evaluate(signals(rss_bytes=400_000_000,
                                             baseline_rss_bytes=52_000_000,
                                             sustained_resource_seconds=1_200.0))
        self.assertEqual(verdict.verdict, ROLLBACK_RESOURCE)

    def test_dropped_events_withdraw_the_model(self):
        """The sensor losing traffic is the clearest possible signal that the
        model is costing more than it is worth."""
        verdict = monitor().evaluate(signals(event_drops=40,
                                             sustained_resource_seconds=1_200.0))
        self.assertEqual(verdict.verdict, ROLLBACK_RESOURCE)


class TestQualityRollbackNeedsReviewedEvidence(unittest.TestCase):
    """§48, §132. Slow on purpose."""

    def test_a_confirmed_false_block_regression_withdraws_the_model(self):
        verdict = monitor().evaluate(signals(reviewed_outcomes=60,
                                             reviewed_false_blocks=14,
                                             baseline_reviewed_false_blocks=2))
        self.assertEqual(verdict.verdict, ROLLBACK_QUALITY)
        self.assertTrue(any('false blocks' in reason for reason in verdict.reasons))

    def test_too_few_reviewed_outcomes_does_not_withdraw_the_model(self):
        """The same regression, with three reviews behind it, is not evidence."""
        verdict = monitor().evaluate(signals(reviewed_outcomes=3,
                                             reviewed_false_blocks=14,
                                             baseline_reviewed_false_blocks=2))
        self.assertNotEqual(verdict.verdict, ROLLBACK_QUALITY)
        self.assertTrue(any('reviewed outcomes' in reason for reason in verdict.reasons))

    def test_one_unlabelled_event_can_never_withdraw_a_model(self):
        """The property §48 exists to guarantee."""
        verdict = monitor().evaluate(signals(reviewed_outcomes=0,
                                             feature_vectors=1,
                                             actions={'TEMP_BLOCK': 1},
                                             baseline_actions={'OBSERVE': 1}))
        self.assertNotIn(verdict.verdict, (ROLLBACK_QUALITY,))

    def test_a_block_precision_collapse_on_reviewed_outcomes_withdraws(self):
        verdict = monitor().evaluate(signals(reviewed_outcomes=80,
                                             block_precision=0.40,
                                             baseline_block_precision=0.90))
        self.assertEqual(verdict.verdict, ROLLBACK_QUALITY)

    def test_a_small_increase_within_budget_does_not_withdraw(self):
        verdict = monitor().evaluate(signals(reviewed_outcomes=60,
                                             reviewed_false_blocks=3,
                                             baseline_reviewed_false_blocks=1))
        self.assertEqual(verdict.verdict, KEEP)


class TestOodAndDriftNeverWithdrawAModel(unittest.TestCase):
    """§49, §50, §133, §134. The two negative results."""

    def test_a_high_out_of_distribution_rate_does_not_withdraw(self):
        verdict = monitor().evaluate(signals(ood_ratio=0.85, baseline_ood_ratio=0.14))
        self.assertFalse(verdict.rollback,
                         'a model was withdrawn for recognising less of the traffic')
        self.assertEqual(verdict.verdict, FREEZE_ADVANCEMENT)

    def test_the_reason_says_why_rolling_back_would_be_worse(self):
        verdict = monitor().evaluate(signals(ood_ratio=0.85, baseline_ood_ratio=0.14))
        self.assertTrue(any('seen even less' in reason for reason in verdict.reasons))

    def test_a_drifted_population_does_not_withdraw(self):
        verdict = monitor().evaluate(signals(drift_status='DRIFTED'))
        self.assertFalse(verdict.rollback)
        self.assertEqual(verdict.verdict, FREEZE_ADVANCEMENT)

    def test_neither_is_described_as_hostile(self):
        verdict = monitor().evaluate(signals(drift_status='DRIFTED', ood_ratio=0.9,
                                             baseline_ood_ratio=0.1))
        text = ' '.join(verdict.reasons).lower()
        for forbidden in ('malicious', 'attack wave', 'hostile'):
            with self.subTest(word=forbidden):
                if forbidden in text:
                    window = text[max(0, text.find(forbidden) - 80):]
                    self.assertTrue(
                        any(denial in window for denial in
                            ('not ', 'never', 'may be', 'rather than')),
                        f'{forbidden!r} is asserted rather than discussed')

    def test_both_together_still_do_not_withdraw(self):
        verdict = monitor().evaluate(signals(drift_status='DRIFTED', ood_ratio=0.95,
                                             baseline_ood_ratio=0.05))
        self.assertFalse(verdict.rollback)


class TestActionSurge(unittest.TestCase):
    """§52, §53. A surge freezes advancement; it is not a verdict."""

    def test_a_surge_in_strong_actions_freezes_advancement(self):
        verdict = monitor().evaluate(signals(
            actions={'OBSERVE': 3_000, 'WATCH': 1_000, 'RATE_LIMIT': 600,
                     'TEMP_BLOCK': 400}))
        self.assertEqual(verdict.verdict, FREEZE_ADVANCEMENT)
        self.assertFalse(verdict.rollback)

    def test_a_surge_is_not_immediately_called_an_attack(self):
        """§52. It may be one. The system does not get to assume either way."""
        verdict = monitor().evaluate(signals(
            actions={'OBSERVE': 3_000, 'WATCH': 1_000, 'RATE_LIMIT': 600,
                     'TEMP_BLOCK': 400}))
        self.assertTrue(any('needs a person' in reason or 'somebody has looked' in reason
                            for reason in verdict.reasons))

    def test_a_model_that_starts_blocking_where_the_previous_never_did_freezes(self):
        verdict = monitor().evaluate(signals(
            actions={'OBSERVE': 4_000, 'TEMP_BLOCK': 1_000},
            baseline_actions={'OBSERVE': 5_000}))
        self.assertEqual(verdict.verdict, FREEZE_ADVANCEMENT)

    def test_an_unchanged_distribution_does_not_freeze(self):
        self.assertEqual(monitor().evaluate(signals()).verdict, KEEP)


class TestTheMonitorWithdrawsNothingItself(unittest.TestCase):
    """§45, §114. It computes; the activator acts."""

    def test_the_monitor_cannot_reach_the_registry_or_the_activator(self):
        import ast
        from pathlib import Path
        from eye_for_an_eye.governance import monitor as module
        tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module)
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
        for forbidden in ('registry', 'ModelRegistry', 'activation',
                          'PromotionActivator', 'firewall', 'os', 'subprocess'):
            with self.subTest(name=forbidden):
                self.assertNotIn(forbidden, names)

    def test_evaluating_twice_gives_the_same_answer(self):
        first = monitor().evaluate(signals(non_finite_outputs=1))
        second = monitor().evaluate(signals(non_finite_outputs=1))
        self.assertEqual(first.verdict, second.verdict)
        self.assertEqual(first.reasons, second.reasons)

    def test_every_verdict_is_one_of_the_named_ones(self):
        from eye_for_an_eye.governance.monitor import VERDICTS
        cases = [signals(), signals(non_finite_outputs=1),
                 signals(latency_p95_ms=99.0, sustained_resource_seconds=9_000.0),
                 signals(reviewed_outcomes=60, reviewed_false_blocks=30),
                 signals(drift_status='DRIFTED')]
        for case in cases:
            with self.subTest(case=case.drift_status):
                self.assertIn(monitor().evaluate(case).verdict, VERDICTS)


if __name__ == '__main__':
    unittest.main()
