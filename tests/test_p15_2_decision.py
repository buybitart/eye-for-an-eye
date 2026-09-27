"""What the repaired decision layer must keep doing, and must never start doing.

P15.2 changed two things in the authority: a calibrated probability may now
carry a conservative bound computed over the calibration sample rather than over
the packet count, and the release gate refuses a system that blocks nothing.
Both changes make the system act where it previously could not, so the tests
that matter most here are the ones asserting it still refuses everything it
refused before.
"""
import unittest

from eye_for_an_eye.autonomy import evaluation as ev
from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               DecisionGates, DecisionInputs)
from eye_for_an_eye.autonomy.cost import PROFILES, CostPolicy, CostProfile
from eye_for_an_eye.autonomy.record import ALLOW, TEMP_BLOCK
from eye_for_an_eye.autonomy import record as codes
from eye_for_an_eye.autonomy.uncertainty import DecisionUncertainty, assess, evaluate

#: A window with every gate satisfied except whatever a test is varying: mature,
#: complete, in distribution, directly connected, four behavioural families.
GOOD = {
    'source': '198.51.100.20', 'scope': 'GLOBAL',
    'identity_confidence': 'HIGH', 'identity_origin': 'direct_peer',
    'network_enforceable': True, 'enforcement_scope': 'NETWORK_SOURCE',
    'observations': 240, 'observation_seconds': 600.0, 'data_quality': 0.95,
    'math_risk': 0.9, 'math_version': 'math-risk-v1',
    'math_contributions': {'ports_60s': 0.4, 'repetition_60s': 0.3,
                           'interarrival_cv_60s': 0.2, 'deception_60s': 0.2},
    'ml_usable': True, 'ml_model_version': 'risk-logreg-v1', 'ml_status': 'healthy',
    'model_score': 0.95, 'anomaly_score': 0.8, 'ood_score': 0.05,
    'ood_status': 'IN_DISTRIBUTION', 'drift_status': 'STABLE', 'model_health': 'HEALTHY',
    'calibrated': True, 'calibrated_probability': 0.999, 'calibrated_lower': 0.995,
    'calibration_version': 'mathrisk-cal-v1-isotonic',
    'enforcement_healthy': True, 'clock_sane': True, 'policy_guard_action': 'ALLOW',
}


def decide(**changes):
    body = dict(GOOD)
    body.update(changes)
    authority = AutonomousDecisionAuthority(cost_policy=CostPolicy(), enabled=True,
                                            mode=AUTONOMOUS)
    return authority.decide(DecisionInputs(**body))


class TestTheCalibratedBoundIsWhatUnlockedBlocking(unittest.TestCase):
    """The repair, and its limits."""

    def test_a_well_evidenced_window_now_blocks(self):
        """P15.1's headline was that this was impossible. It is the point of P15.2."""
        record = decide()
        self.assertEqual(record.action, TEMP_BLOCK)
        self.assertTrue(record.safety_gates['calibrated_estimate'])
        self.assertTrue(record.safety_gates['robust_margin'])

    def test_an_uncalibrated_estimate_still_cannot_block_however_high(self):
        """P15.1's hard gate, unchanged. §83."""
        for math_risk in (0.5, 0.9, 0.99, 1.0):
            with self.subTest(math_risk=math_risk):
                record = decide(calibrated=False, calibrated_probability=None,
                                calibrated_lower=None, math_risk=math_risk)
                self.assertEqual(record.action, ALLOW)
                self.assertIn(codes.CALIBRATION_UNAVAILABLE, record.reason_codes)

    def test_a_calibrated_estimate_with_no_bound_does_not_block(self):
        """§79. An artifact that ships a point estimate has not said how sure it is."""
        record = decide(calibrated_lower=None)
        self.assertEqual(record.action, ALLOW)

    def test_the_bound_and_not_the_point_estimate_decides(self):
        """A confident claim with a wide interval is not a reason to act."""
        blocked = decide(calibrated_probability=1.0, calibrated_lower=0.999)
        allowed = decide(calibrated_probability=1.0, calibrated_lower=0.90)
        self.assertEqual(blocked.action, TEMP_BLOCK)
        self.assertEqual(allowed.action, ALLOW)
        self.assertIn(codes.MARGIN_NOT_MET, allowed.reason_codes)

    def test_a_bound_above_its_estimate_is_clamped_down_not_up(self):
        record = decide(calibrated_probability=0.5, calibrated_lower=0.999)
        self.assertLessEqual(record.conservative_probability, 0.5)
        self.assertEqual(record.action, ALLOW)

    def test_the_record_says_which_bound_the_decision_rested_on(self):
        """§89. Do not hide the score conversion."""
        loss = evaluate(probability=0.99, uncertainty=assess(calibrated=True, observations=200),
                        profile=PROFILES['public_website'], margin=0.1, calibrated=True,
                        calibrated_lower=0.98)
        self.assertEqual(loss.explain()['bound_source'], 'calibration_wilson')
        legacy = evaluate(probability=0.99, uncertainty=assess(calibrated=False, observations=200),
                          profile=PROFILES['public_website'], margin=0.1, calibrated=False)
        self.assertEqual(legacy.explain()['bound_source'], 'shrinkage')

    def test_the_legacy_estimate_is_still_reported_beside_the_new_one(self):
        loss = evaluate(probability=0.99, uncertainty=assess(calibrated=True, observations=200),
                        profile=PROFILES['public_website'], margin=0.1, calibrated=True,
                        calibrated_lower=0.98)
        body = loss.explain()
        self.assertEqual(body['conservative_probability'], 0.98)
        self.assertLess(body['legacy_conservative_probability'], 0.98)


class TestEveryRestraintStillRestrains(unittest.TestCase):
    """§104, §105, §106, §107, §53. Nothing was traded for the new capability."""

    def test_low_data_quality_refuses_the_block(self):
        record = decide(data_quality=0.2)
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.INSUFFICIENT_DATA_QUALITY, record.reason_codes)

    def test_out_of_distribution_refuses_the_block(self):
        record = decide(ood_status='OUT_OF_DISTRIBUTION')
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.HIGH_OOD, record.reason_codes)

    def test_more_uncertainty_never_makes_blocking_easier(self):
        """§104, as a property rather than a case."""
        base = DecisionUncertainty(observations=500)
        for component in ('out_of_distribution', 'data_quality', 'model_health',
                          'sample', 'disagreement', 'uncalibrated'):
            with self.subTest(component=component):
                worse = DecisionUncertainty(observations=500, **{component: 0.25})
                self.assertLessEqual(worse.conservative_probability(0.9),
                                     base.conservative_probability(0.9))

    def test_one_signal_family_cannot_manufacture_three_votes(self):
        """§107. Five features of one family are one family."""
        record = decide(math_contributions={'ports_60s': 0.4, 'ports_900s': 0.4,
                                            'destinations_60s': 0.3},
                        model_score=None, ml_usable=False, anomaly_score=None)
        self.assertEqual(record.action, ALLOW)
        self.assertLess(record.behavioural_diversity, 2)

    def test_an_immature_window_refuses_the_block(self):
        for change in ({'observations': 4}, {'observation_seconds': 1.0}):
            with self.subTest(**change):
                self.assertEqual(decide(**change).action, ALLOW)

    def test_a_client_behind_a_proxy_is_never_network_blocked(self):
        """§53. Proxy and CDN safety is not negotiable for a recall number."""
        for change in ({'network_enforceable': False},
                       {'enforcement_scope': 'SITE_SCOPED'},
                       {'identity_confidence': 'LOW'}):
            with self.subTest(**change):
                self.assertEqual(decide(**change).action, ALLOW)

    def test_a_protected_source_is_never_blocked(self):
        for change in ({'protected': True}, {'management': True}):
            with self.subTest(**change):
                self.assertEqual(decide(**change).action, ALLOW)

    def test_policy_guard_refusal_is_final(self):
        """§54. PolicyGuard sits above the authority and cannot be bypassed."""
        record = decide(policy_guard_action='REFUSED')
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.POLICY_GUARD_REFUSED, record.reason_codes)


class TestTheCostCutoffFollowsTheCosts(unittest.TestCase):
    """§101, §102, §103, §49."""

    def test_the_cutoff_is_the_documented_formula(self):
        for name, profile in sorted(PROFILES.items()):
            with self.subTest(profile=name):
                expected = profile.false_block / (profile.false_block + profile.false_allow)
                self.assertAlmostEqual(profile.threshold, expected, places=12)

    def test_expected_loss_matches_the_cost_matrix(self):
        profile = PROFILES['public_website']
        for p in (0.0, 0.25, 0.5, 0.9756, 1.0):
            with self.subTest(p=p):
                loss = evaluate(probability=p, uncertainty=DecisionUncertainty(observations=10 ** 6),
                                profile=profile, margin=0.0, calibrated=True,
                                calibrated_lower=p)
                self.assertAlmostEqual(loss.loss_allow, p * profile.false_allow, places=9)
                self.assertAlmostEqual(loss.loss_block, (1 - p) * profile.false_block, places=9)
                self.assertEqual(loss.block_arithmetically_preferred, p > profile.threshold)

    def test_a_payment_route_never_network_blocks_at_any_probability(self):
        """§62, §102. Not a model failure: a policy that outranks the arithmetic.

        A scope reaches its profile through the policy's own mapping, so the
        mapping is part of what is being tested — an unmapped scope silently
        getting `public_website` is exactly the kind of quiet fallback that
        would put a payment route one configuration mistake from a block.
        """
        policy = CostPolicy(scope_profiles={'checkout': 'payment_webhook'})
        self.assertEqual(policy.for_scope('checkout').name, 'payment_webhook')
        authority = AutonomousDecisionAuthority(cost_policy=policy, enabled=True,
                                                mode=AUTONOMOUS)
        record = authority.decide(DecisionInputs(**dict(
            GOOD, scope='checkout', calibrated_probability=1.0, calibrated_lower=1.0)))
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.NETWORK_BLOCK_NOT_PERMITTED, record.reason_codes)
        self.assertFalse(record.safety_gates['network_block_permitted'])

    def test_an_unmapped_scope_gets_the_protective_default_not_a_cheap_one(self):
        policy = CostPolicy()
        self.assertEqual(policy.for_scope('never-configured').name, policy.default_profile)
        self.assertGreaterEqual(policy.for_scope('never-configured').threshold,
                                PROFILES['admin'].threshold)

    def test_a_higher_false_negative_cost_lowers_the_cutoff(self):
        """§103. The formula, exercised rather than restated."""
        cautious = CostProfile(name='cautious', description='x', false_block=40.0,
                               false_allow=1.0)
        eager = CostProfile(name='eager', description='x', false_block=40.0,
                            false_allow=10.0)
        self.assertLess(eager.threshold, cautious.threshold)

    def test_a_higher_false_positive_cost_raises_the_cutoff(self):
        self.assertGreater(PROFILES['payment_webhook'].threshold,
                           PROFILES['public_website'].threshold)
        self.assertGreater(PROFILES['public_website'].threshold,
                           PROFILES['honeypot'].threshold)

    def test_no_shipped_cutoff_is_one_half(self):
        for name, profile in sorted(PROFILES.items()):
            with self.subTest(profile=name):
                self.assertNotAlmostEqual(profile.threshold, 0.5, places=3)


class TestTheNonDegenerateGate(unittest.TestCase):
    """§41 to §44, §97, §98. The two trivial defenders, refused by name."""

    @staticmethod
    def outcomes(benign_blocked, benign_total, positives_blocked, positives_total):
        rows = []
        rows += [ev.Outcome(blocked=index < benign_blocked, label=ev.BENIGN, score=0.1)
                 for index in range(benign_total)]
        rows += [ev.Outcome(blocked=index < positives_blocked,
                            label=ev.MALICIOUS_AUTOMATION, score=0.9)
                 for index in range(positives_total)]
        return rows

    def test_allow_all_fails_even_with_a_perfect_false_block_rate(self):
        """§97. The exact system P15.1 measured."""
        metrics = ev.evaluate(self.outcomes(0, 600, 0, 100))
        self.assertEqual(metrics.false_blocks_per_1000_benign, 0.0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        gate = ev.non_degenerate_gate(metrics)
        self.assertEqual(gate['verdict'], ev.DEGENERATE_ALLOW_ALL)
        self.assertEqual(ev.release_gate(metrics)['verdict'], 'FAIL')

    def test_block_all_fails_even_with_perfect_recall(self):
        """§98."""
        metrics = ev.evaluate(self.outcomes(600, 600, 100, 100))
        self.assertEqual(metrics.recall, 1.0)
        gate = ev.non_degenerate_gate(metrics)
        self.assertEqual(gate['verdict'], ev.DEGENERATE_BLOCK_ALL)
        self.assertEqual(ev.release_gate(metrics)['verdict'], 'FAIL')

    def test_one_correct_block_and_a_quiet_benign_population_passes(self):
        metrics = ev.evaluate(self.outcomes(0, 600, 10, 100))
        gate = ev.non_degenerate_gate(metrics)
        self.assertEqual(gate['verdict'], ev.NON_DEGENERATE)
        self.assertEqual(gate['true_blocks'], 10)
        self.assertEqual(gate['false_blocks'], 0)

    def test_blocks_that_are_all_wrong_do_not_count_as_detection(self):
        """Blocking only benign sources is not non-degenerate, it is worse."""
        metrics = ev.evaluate(self.outcomes(5, 600, 0, 100))
        self.assertEqual(ev.non_degenerate_gate(metrics)['verdict'],
                         ev.DEGENERATE_ALLOW_ALL)

    def test_the_gate_sets_no_recall_target(self):
        """§42. One correct block out of a hundred is not degenerate, only weak."""
        metrics = ev.evaluate(self.outcomes(0, 600, 1, 100))
        self.assertEqual(ev.non_degenerate_gate(metrics)['verdict'], ev.NON_DEGENERATE)

    def test_the_gate_appears_in_every_report(self):
        body = ev.report(self.outcomes(0, 600, 0, 100))
        self.assertIn('non_degenerate_decision_gate', body)
        self.assertEqual(body['non_degenerate_decision_gate']['verdict'],
                         ev.DEGENERATE_ALLOW_ALL)
        self.assertIn('non_degenerate_decision_gate', body['release_gate'])

    def test_without_positives_the_gate_declines_to_judge(self):
        metrics = ev.evaluate(self.outcomes(0, 600, 0, 0))
        self.assertEqual(ev.non_degenerate_gate(metrics)['verdict'],
                         ev.GROUND_TRUTH_UNAVAILABLE)


class TestGatesAreNotQuietlyRelaxed(unittest.TestCase):
    """The numbers P15.2 was not allowed to move, pinned."""

    def test_the_shipped_gates_are_unchanged(self):
        gates = DecisionGates()
        self.assertEqual(gates.minimum_observations, 20)
        self.assertEqual(gates.minimum_observation_seconds, 10.0)
        self.assertEqual(gates.minimum_data_quality, 0.55)
        self.assertEqual(gates.minimum_signal_diversity, 3)
        self.assertEqual(gates.minimum_behavioural_diversity, 2)
        self.assertEqual(gates.maximum_uncertainty, 0.60)
        self.assertEqual(gates.block_ttl_ladder, (300, 1800, 7200, 43_200))

    def test_the_shipped_cost_profiles_are_unchanged(self):
        expected = {'public_website': 40.0, 'api': 80.0, 'payment_webhook': 500.0,
                    'admin': 8.0, 'honeypot': 2.0}
        for name, false_block in expected.items():
            with self.subTest(profile=name):
                self.assertEqual(PROFILES[name].false_block, false_block)
                self.assertEqual(PROFILES[name].false_allow, 1.0)

    def test_the_release_thresholds_are_unchanged(self):
        thresholds = ev.ReleaseThresholds()
        self.assertEqual(thresholds.max_false_blocks_per_1000_benign, 1.0)
        self.assertEqual(thresholds.min_block_precision, 0.95)
        self.assertEqual(thresholds.min_benign_sample, 500)
        self.assertEqual(thresholds.min_positive_sample, 50)


if __name__ == '__main__':
    unittest.main()
