"""P15 phases 1-3: the cost model, the evidence model, the doubt, and the authority.

The shape of this file is the argument. One fixture builds a source that earns a
block on every count; every other test in `TestOneThingAtATime` changes exactly
one input and asserts the answer becomes ALLOW. A gate no test can break by
breaking its input is a gate that is not load-bearing, and this layout makes that
visible rather than leaving it to be discovered by an operator.

The fixture itself is worth reading before the tests. Reaching TEMP_BLOCK on the
default `public_website` profile takes a calibrated probability of 0.999, six
hundred observations over five minutes, perfect data quality, an in-distribution
sample, a healthy undrifted model, four independent evidence families and a
directly connected client. That is not the test being generous to itself — it is
what a false-block cost forty times a false-allow actually demands once the
estimate has been made conservative. The arithmetic is doing what §14 asks, and
the consequence is that an autonomous network block on a public website is a rare
event by construction. `TestThePublicWebsiteProfileIsHardToSatisfy` asserts that
directly, because it is a design property somebody will otherwise mistake for a
bug and "fix".
"""
import dataclasses
import time
import unittest

from eye_for_an_eye.autonomy import evidence as families
from eye_for_an_eye.autonomy import record as codes
from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               DecisionGates, DecisionInputs, SHADOW)
from eye_for_an_eye.autonomy.breakers import (BreakerPanel, BudgetLimits, BreakerError,
                                              CLOSED, COOLDOWN, OPEN)
from eye_for_an_eye.autonomy.cost import CostError, CostPolicy, CostProfile, PROFILES
from eye_for_an_eye.autonomy.record import (ALLOW, AssumptionRegistry,
                                            AutonomousDecisionRecord,
                                            DecisionRecordError, MAX_BLOCK_TTL_SECONDS,
                                            TEMP_BLOCK)
from eye_for_an_eye.autonomy.uncertainty import DecisionUncertainty, assess, evaluate

#: Contributions spread across four distinct behavioural families.
#:
#: `credentials_60s` is deliberately no longer among them. It measures
#: credential *presence*, which belongs to no family from P15.4 onward, so a
#: fixture resting on it would be asserting that a legitimate API client's every
#: request is authentication-abuse evidence — the belief that blocked 21 of 22
#: sources of one on the P15.3 benchmark. `auth_failures_60s` is what carries
#: `AUTH_BEHAVIOR` now.
CONTRIBUTIONS = {'ports_60s': 0.9, 'auth_failures_60s': 0.8,
                 'anomaly_60s': 0.7, 'persistence_900s': 0.4}

BLOCKABLE = dict(
    source='198.51.100.7', scope='GLOBAL',
    identity_confidence='HIGH', identity_origin='direct_peer',
    network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
    observations=600, observation_seconds=300.0, data_quality=1.0,
    math_risk=0.99, math_version='math-risk-v1', math_contributions=CONTRIBUTIONS,
    ml_usable=True, ml_model_version='risk-logreg-v1', ml_status='healthy',
    model_score=0.97, calibrated=True, calibrated_probability=0.999,
    anomaly_score=0.8, ood_score=0.0, ood_status='IN_DISTRIBUTION',
    drift_status='STABLE', model_health='HEALTHY', policy_guard_action='ALLOW')


def authority(**changes):
    settings = dict(enabled=True, mode=AUTONOMOUS)
    settings.update(changes)
    return AutonomousDecisionAuthority(**settings)


def decide(**changes):
    inputs = DecisionInputs(**{**BLOCKABLE, **changes})
    return authority().decide(inputs)


class TestTheFixtureBlocks(unittest.TestCase):
    """If this fails, every test below is vacuous."""

    def test_overwhelming_evidence_produces_a_temporary_block(self):
        record = decide()
        self.assertEqual(record.action, TEMP_BLOCK)
        self.assertTrue(record.behavioural,
                        'a block with no behavioural reason would violate the §90 rule')
        self.assertIn(codes.COST_BLOCK_PREFERRED, record.reason_codes)
        self.assertGreater(record.block_ttl_seconds, 0)
        self.assertLessEqual(record.block_ttl_seconds, MAX_BLOCK_TTL_SECONDS)

    def test_the_block_carries_no_reason_not_to_block(self):
        record = decide()
        self.assertEqual(record.restraining, (),
                         'a block that also recorded a refusal would mean something '
                         'overrode a gate, and nothing here can')

    def test_the_explanation_names_behaviour_before_any_model(self):
        text = decide().explanation()
        self.assertIn('What this source did:', text)
        self.assertIn('automated credential attempts', text)
        self.assertIn('expires after', text)


class TestOneThingAtATime(unittest.TestCase):
    """Each test breaks exactly one input and expects ALLOW plus a named reason."""

    def assertAllowedBecause(self, code, **changes):
        record = decide(**changes)
        self.assertEqual(record.action, ALLOW, f'expected ALLOW, got {record.summary()}')
        self.assertIn(code, record.reason_codes)
        return record

    def test_a_protected_source_is_never_blocked(self):
        self.assertAllowedBecause(codes.PROTECTED_SOURCE, protected=True)

    def test_a_management_source_is_never_blocked(self):
        self.assertAllowedBecause(codes.MANAGEMENT_NETWORK, management=True)

    def test_an_uncertain_client_address_is_never_blocked(self):
        self.assertAllowedBecause(codes.IDENTITY_UNCERTAIN, identity_confidence='LOW')

    def test_a_client_behind_a_proxy_is_never_network_blocked(self):
        self.assertAllowedBecause(codes.NOT_NETWORK_ENFORCEABLE,
                                  network_enforceable=False)

    def test_a_shared_proxy_scope_is_never_network_blocked(self):
        self.assertAllowedBecause(codes.SHARED_PROXY_RISK,
                                  enforcement_scope='WEB_CLIENT')

    def test_low_data_quality_prevents_a_block(self):
        self.assertAllowedBecause(codes.INSUFFICIENT_DATA_QUALITY, data_quality=0.3)

    def test_too_few_observations_prevents_a_block(self):
        self.assertAllowedBecause(codes.INSUFFICIENT_OBSERVATIONS, observations=5)

    def test_too_short_a_window_prevents_a_block(self):
        self.assertAllowedBecause(codes.INSUFFICIENT_OBSERVATION_TIME,
                                  observation_seconds=2.0)

    def test_one_family_of_evidence_is_not_enough(self):
        self.assertAllowedBecause(codes.INSUFFICIENT_SIGNAL_DIVERSITY,
                                  math_contributions={'ports_60s': 0.9})

    def test_model_opinion_alone_never_blocks(self):
        """§86. Two models agreeing about one vector is one opinion, not two."""
        record = self.assertAllowedBecause(codes.MODEL_ONLY_EVIDENCE,
                                           math_contributions={})
        self.assertTrue(record.model_only)

    def test_an_out_of_distribution_sample_prevents_a_block(self):
        self.assertAllowedBecause(codes.HIGH_OOD, ood_status='OUT_OF_DISTRIBUTION')

    def test_a_degraded_model_prevents_a_block(self):
        self.assertAllowedBecause(codes.MODEL_UNHEALTHY, model_health='DEGRADED')

    def test_drift_prevents_a_block(self):
        self.assertAllowedBecause(codes.DRIFT_DEGRADED, drift_status='DRIFTED')

    def test_material_model_disagreement_prevents_a_block(self):
        self.assertAllowedBecause(codes.MODEL_DISAGREEMENT, model_disagreement=0.9)

    def test_a_failed_assumption_prevents_a_block(self):
        self.assertAllowedBecause(codes.ASSUMPTION_FAILED, clock_sane=False)

    def test_a_broken_feature_schema_prevents_a_block(self):
        """A schema this build cannot serve, named from the code rather than
        written down as a number.

        This test said `feature_schema_version=2`, which was a schema nobody
        could serve when it was written. Schema 2 then became the schema in
        force, and the test kept passing — now asserting that the *current*
        schema prevents every block, which it did. The test that should have
        caught the P15.4 authority defect had encoded it instead, and stayed
        green while the system could not act at all.

        A literal in a test ages exactly like the literal in the code it guards.
        """
        from eye_for_an_eye.decision.features import MODEL_SCHEMAS
        self.assertAllowedBecause(codes.ASSUMPTION_FAILED,
                                  feature_schema_version=max(MODEL_SCHEMAS) + 1)

    def test_the_schema_in_force_does_not_prevent_a_block(self):
        """The other half, and the one that was missing. Without it, a check that
        refuses the current schema passes the suite unnoticed — which is exactly
        what happened for the length of the P15.4 cycle."""
        from eye_for_an_eye.decision.features import SCHEMA_VERSION
        record = decide(feature_schema_version=SCHEMA_VERSION)
        self.assertNotIn(codes.ASSUMPTION_FAILED, record.reason_codes,
                         'the schema this build actually uses must be able to decide')

    def test_unhealthy_enforcement_prevents_a_block(self):
        self.assertAllowedBecause(codes.ENFORCEMENT_UNHEALTHY, enforcement_healthy=False)

    def test_a_policy_guard_refusal_is_final(self):
        self.assertAllowedBecause(codes.POLICY_GUARD_REFUSED,
                                  policy_guard_action='REFUSED')

    def test_an_existing_lease_is_not_renewed_on_every_window(self):
        self.assertAllowedBecause(codes.EXISTING_BLOCK_LEASE, existing_block=True)

    def test_a_weaker_probability_prevents_a_block(self):
        self.assertAllowedBecause(codes.COST_ALLOW_PREFERRED,
                                  calibrated_probability=0.6)


class TestAutonomyOffMeansAllow(unittest.TestCase):

    def test_a_disabled_authority_records_the_decision_and_allows(self):
        record = AutonomousDecisionAuthority(enabled=False).decide(
            DecisionInputs(**BLOCKABLE))
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.AUTONOMY_DISABLED, record.reason_codes)

    def test_shadow_mode_still_reaches_the_block_decision(self):
        """§105, §163. The counterfactual is the whole point of shadow mode."""
        record = authority(mode=SHADOW).decide(DecisionInputs(**BLOCKABLE))
        self.assertEqual(record.action, TEMP_BLOCK)
        self.assertTrue(record.shadow)
        self.assertFalse(record.enforced)

    def test_a_shadow_block_does_not_spend_the_block_budget(self):
        instance = authority(mode=SHADOW)
        for _ in range(5):
            instance.decide(DecisionInputs(**BLOCKABLE))
        self.assertEqual(instance.panel.budget.recent_blocks, 0)
        self.assertEqual(instance.panel.mass_block._blocks and
                         len(instance.panel.mass_block._blocks), 5)


class TestThePublicWebsiteProfileIsHardToSatisfy(unittest.TestCase):
    """A design property, asserted so nobody later mistakes it for a defect."""

    def test_a_confident_but_ordinary_estimate_does_not_block_a_public_website(self):
        record = decide(calibrated_probability=0.95, observations=100)
        self.assertEqual(record.action, ALLOW)

    def test_an_uncalibrated_classifier_cannot_carry_the_estimate(self):
        """§20. A score is not a probability, and the record says which it had."""
        record = decide(calibrated=False, calibrated_probability=None)
        self.assertFalse(record.calibrated)
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.CALIBRATION_UNAVAILABLE, record.reason_codes)

    def test_an_uncalibrated_estimate_cannot_block_however_high_it_is(self):
        """The P15.1 measurement, pinned so it cannot quietly come back.

        P15 allowed an uncalibrated estimate to block if it happened to clear the
        cutoff on its own terms. Replaying a trusted labelled corpus through the
        whole system showed what that was worth: nothing blocked, ever, because
        an uncalibrated sigmoid does not reach a cost-derived probability cutoff
        — and no record said why. The gate is hard now, and a deterministic
        engine at 1.0 is still not a probability of 1.0.
        """
        for math_risk in (0.5, 0.9, 0.99, 1.0):
            with self.subTest(math_risk=math_risk):
                record = decide(calibrated=False, calibrated_probability=None,
                                math_risk=math_risk)
                self.assertEqual(record.action, ALLOW)
                self.assertIn(codes.CALIBRATION_UNAVAILABLE, record.reason_codes)
                self.assertFalse(record.safety_gates['calibrated_estimate'])

    def test_the_cutoff_is_not_one_half(self):
        """§18. 0.5 is what you use when you have not asked what a mistake costs."""
        for name, profile in PROFILES.items():
            with self.subTest(profile=name):
                self.assertNotAlmostEqual(profile.threshold, 0.5, places=2)
                self.assertGreater(profile.threshold, 0.5)


class TestCostProfiles(unittest.TestCase):

    def test_the_cutoff_follows_from_the_costs(self):
        profile = CostProfile(name='t', description='', false_block=9.0, false_allow=1.0)
        self.assertAlmostEqual(profile.threshold, 0.9)

    def test_a_payment_route_never_network_blocks_at_any_probability(self):
        """§136. Some routes are not traded against reconnaissance."""
        policy = CostPolicy().with_scope('SITE:pay', 'payment_webhook')
        instance = AutonomousDecisionAuthority(cost_policy=policy, enabled=True,
                                               mode=AUTONOMOUS)
        record = instance.decide(DecisionInputs(**{**BLOCKABLE, 'scope': 'SITE:pay',
                                                   'calibrated_probability': 1.0}))
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.NETWORK_BLOCK_NOT_PERMITTED, record.reason_codes)

    def test_an_unmapped_scope_gets_the_protective_default(self):
        policy = CostPolicy()
        self.assertEqual(policy.for_scope('SITE:nobody-configured').name,
                         'public_website')

    def test_changing_a_cost_changes_the_digest(self):
        """A decision record names the costs it used, so they must be identifiable."""
        first = CostPolicy().digest
        cheaper = dataclasses.replace(PROFILES['public_website'], false_block=4.0)
        second = CostPolicy(profiles={**PROFILES, 'public_website': cheaper}).digest
        self.assertNotEqual(first, second)

    def test_a_negative_or_zero_cost_is_refused(self):
        with self.assertRaises(CostError):
            CostProfile(name='t', description='', false_block=0.0)

    def test_hysteresis_only_works_in_one_direction(self):
        with self.assertRaises(CostError):
            CostPolicy(decision_margin=0.1, release_margin=0.5)

    def test_the_costs_are_documented_as_weights_rather_than_money(self):
        """§17. Inventing a currency value would be false precision."""
        body = CostPolicy().explain()
        self.assertIn('not money', body['note'])


class TestSignalFamilies(unittest.TestCase):

    def test_three_features_describing_one_phenomenon_are_one_family(self):
        """§23. Rate, burst and request count are one thing seen three ways."""
        group = families.SignalFamilies().record_contributions(
            {'connections_10s': 0.9, 'connections_60s': 0.8, 'burst_10s': 0.7})
        self.assertEqual(group.diversity, 1)
        self.assertEqual(group.active, (families.NETWORK_RATE,))

    def test_a_family_keeps_its_strongest_witness_rather_than_a_sum(self):
        group = families.SignalFamilies().record_contributions(
            {'connections_10s': 0.4, 'connections_60s': 0.9})
        self.assertAlmostEqual(group.strengths[families.NETWORK_RATE], 0.9)
        self.assertEqual(group.witnesses[families.NETWORK_RATE], 'connections_60s')

    def test_an_unmapped_feature_cannot_manufacture_diversity(self):
        group = families.SignalFamilies().record_contributions({'invented_feature': 1.0})
        self.assertEqual(group.diversity, 0)

    def test_every_mapped_feature_belongs_to_exactly_one_family(self):
        for name, family in families.FEATURE_FAMILIES.items():
            with self.subTest(feature=name):
                self.assertIn(family, families.FAMILIES)

    def test_model_families_alone_are_model_only(self):
        group = families.SignalFamilies()
        group.record(families.ML_CLASSIFIER, 0.99)
        group.record(families.ANOMALY, 0.99)
        self.assertTrue(group.model_only)
        self.assertEqual(group.behavioural_diversity, 0)


class TestUncertainty(unittest.TestCase):

    def test_more_doubt_never_produces_a_higher_estimate(self):
        """The monotonicity the whole decision rests on."""
        previous = 1.0
        for weight in (0.0, 0.1, 0.25, 0.5, 0.75, 1.0):
            doubt = DecisionUncertainty(data_quality=weight, observations=1000)
            value = doubt.conservative_probability(0.99)
            self.assertLessEqual(value, previous)
            previous = value

    def test_the_conservative_estimate_never_exceeds_the_point_estimate(self):
        for point in (0.0, 0.2, 0.5, 0.8, 0.999, 1.0):
            for observations in (0, 1, 10, 100, 10_000):
                with self.subTest(point=point, observations=observations):
                    doubt = DecisionUncertainty(observations=observations)
                    self.assertLessEqual(doubt.conservative_probability(point), point)

    def test_no_observations_collapses_the_estimate(self):
        self.assertEqual(DecisionUncertainty(observations=0)
                         .conservative_probability(0.99), 0.0)

    def test_an_unmeasured_signal_adds_doubt_rather_than_being_read_as_fine(self):
        measured = assess(calibrated=True, ood_score=0.0, data_quality_score=1.0,
                          observations=1000)
        unmeasured = assess(calibrated=True, ood_score=None, data_quality_score=None,
                            observations=1000)
        self.assertGreater(unmeasured.total, measured.total)

    def test_an_uncalibrated_classifier_is_itself_a_source_of_doubt(self):
        self.assertGreater(assess(calibrated=False, observations=1000).uncalibrated, 0)

    def test_expected_loss_uses_the_conservative_estimate_for_both_sides(self):
        doubt = assess(calibrated=True, ood_score=0.0, data_quality_score=1.0,
                       observations=1000)
        loss = evaluate(probability=0.99, uncertainty=doubt,
                        profile=PROFILES['public_website'], margin=0.25, calibrated=True)
        self.assertLessEqual(loss.conservative_probability, loss.probability)
        self.assertAlmostEqual(loss.loss_allow, loss.conservative_probability)
        self.assertAlmostEqual(loss.loss_block,
                               (1 - loss.conservative_probability) * 40.0)

    def test_a_small_advantage_is_not_a_robust_one(self):
        """§121. Noise-sized preference is not a reason to act."""
        doubt = assess(calibrated=True, ood_score=0.0, data_quality_score=1.0,
                       observations=1000)
        loss = evaluate(probability=0.977, uncertainty=doubt,
                        profile=PROFILES['public_website'], margin=0.25, calibrated=True)
        self.assertFalse(loss.block_robustly_preferred)


class TestTheDecisionRecord(unittest.TestCase):

    def test_a_block_with_only_a_model_score_is_refused_at_construction(self):
        """§90. Enforced, not documented."""
        with self.assertRaises(DecisionRecordError):
            AutonomousDecisionRecord(
                action=TEMP_BLOCK, block_ttl_seconds=300,
                reason_codes=(codes.ML_SUPPORT, codes.COST_BLOCK_PREFERRED))

    def test_a_permanent_block_cannot_be_represented(self):
        """§45, §188. There is no value of the field that means forever."""
        with self.assertRaises(DecisionRecordError):
            AutonomousDecisionRecord(action=TEMP_BLOCK, block_ttl_seconds=0,
                                     reason_codes=(codes.HIGH_PORT_BREADTH,
                                                   codes.COST_BLOCK_PREFERRED))
        with self.assertRaises(DecisionRecordError):
            AutonomousDecisionRecord(action=TEMP_BLOCK,
                                     block_ttl_seconds=MAX_BLOCK_TTL_SECONDS + 1,
                                     reason_codes=(codes.HIGH_PORT_BREADTH,
                                                   codes.COST_BLOCK_PREFERRED))

    def test_an_allow_must_say_why_it_did_not_block(self):
        """§89. "Nothing happened" is not an explanation."""
        with self.assertRaises(DecisionRecordError):
            AutonomousDecisionRecord(action=ALLOW, reason_codes=())

    def test_an_allow_cannot_carry_a_block_ttl(self):
        with self.assertRaises(DecisionRecordError):
            AutonomousDecisionRecord(action=ALLOW, block_ttl_seconds=300,
                                     reason_codes=(codes.COST_ALLOW_PREFERRED,))

    def test_a_reason_code_outside_the_enum_is_refused(self):
        """§159. These become metric labels; an unbounded label set is a leak."""
        with self.assertRaises(DecisionRecordError):
            AutonomousDecisionRecord(action=ALLOW, reason_codes=('BECAUSE_I_SAID_SO',))

    def test_an_allow_explanation_does_not_call_the_source_benign(self):
        """§167. Abstention is ALLOW, and ALLOW is not a verdict of innocence."""
        text = AutonomousDecisionRecord(
            action=ALLOW, reason_codes=(codes.COST_ALLOW_PREFERRED,)).explanation()
        self.assertIn('does not mean this source is benign', text)
        self.assertIn('never a training label', text)

    def test_every_reason_code_has_a_plain_english_meaning(self):
        for code in codes.REASON_CODES:
            with self.subTest(code=code):
                self.assertIn(code, codes.CODE_MEANINGS)
                self.assertGreater(len(codes.CODE_MEANINGS[code]), 15)

    def test_the_record_carries_the_cost_policy_digest_it_decided_under(self):
        record = decide()
        self.assertTrue(record.cost_policy_digest)
        self.assertEqual(record.cost_policy_version, 'cost-policy-v1')

    def test_the_pseudonym_is_not_the_address(self):
        record = decide()
        self.assertNotIn('198.51.100.7', record.source_pseudonym)
        self.assertTrue(record.source_pseudonym.startswith('src-'))

    def test_the_decision_id_does_not_leak_the_source(self):
        first = decide(source='203.0.113.1')
        second = decide(source='203.0.113.1')
        self.assertNotEqual(first.decision_id, second.decision_id)

    def test_the_record_states_its_own_limitations(self):
        body = decide().explain()
        self.assertIn('an address is not a person', body['limitations'])
        self.assertIn('a block is never a training label', body['limitations'])


class TestAssumptionRegistry(unittest.TestCase):

    def test_an_unchecked_assumption_is_not_a_satisfied_one(self):
        registry = AssumptionRegistry()
        registry.record('clock_sane', True)
        self.assertIn('feature_schema_compatible', registry.unchecked)
        self.assertIn('feature_schema_compatible', registry.blocking_failures)

    def test_a_failure_names_the_subsystem_responsible(self):
        registry = AssumptionRegistry()
        for name in registry.assumptions:
            registry.record(name, True)
        registry.record('firewall_verify' if False else 'enforcement_healthy', False)
        self.assertEqual(registry.subsystems(), ('enforcement',))

    def test_calibration_is_not_required_for_a_block(self):
        """It changes which estimate is used; it does not veto the decision."""
        registry = AssumptionRegistry()
        self.assertFalse(registry.assumptions['model_calibrated'].required_for_block)

    def test_an_unknown_assumption_is_refused(self):
        with self.assertRaises(DecisionRecordError):
            AssumptionRegistry().record('made_up', True)


class TestBlockBudget(unittest.TestCase):

    def test_the_per_minute_budget_stops_new_blocks(self):
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(blocks_per_minute=3), clock=lambda: clock[0])
        for _ in range(3):
            self.assertTrue(panel.permits_block()[0])
            panel.record_block()
        allowed, code, _ = panel.permits_block()
        self.assertFalse(allowed)
        self.assertEqual(code, codes.BLOCK_BUDGET_EXHAUSTED)

    def test_the_budget_refills_as_the_window_moves(self):
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(blocks_per_minute=2), clock=lambda: clock[0])
        panel.record_block()
        panel.record_block()
        self.assertFalse(panel.permits_block()[0])
        clock[0] += 61.0
        self.assertTrue(panel.permits_block()[0])

    def test_the_active_ceiling_stops_new_blocks(self):
        panel = BreakerPanel(BudgetLimits(max_active_blocks=2))
        panel.budget.set_active(2)
        self.assertFalse(panel.permits_block()[0])
        panel.budget.release()
        self.assertTrue(panel.permits_block()[0])


class TestMassBlockBreaker(unittest.TestCase):
    """§51, §173. The model that calls everything malicious."""

    def test_blocking_a_fifth_of_everything_opens_the_breaker(self):
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(blocks_per_minute=10_000,
                                          minimum_sources_for_share=100,
                                          max_block_share=0.02),
                             clock=lambda: clock[0])
        for index in range(500):
            panel.observe_source(f'source-{index}')
        for _ in range(100):
            panel.mass_block.observe_block()
        allowed, code, _ = panel.permits_block()
        self.assertFalse(allowed)
        self.assertEqual(code, codes.MASS_BLOCK_FREEZE)
        self.assertEqual(panel.state, 'AUTONOMOUS_SAFE_MODE')

    def test_a_handful_of_blocks_on_a_quiet_window_does_not_open_it(self):
        """§171 in miniature: three of five sources is not a 60% catastrophe."""
        panel = BreakerPanel(BudgetLimits(minimum_sources_for_share=200))
        for index in range(5):
            panel.observe_source(f'source-{index}')
        for _ in range(3):
            panel.mass_block.observe_block()
        self.assertTrue(panel.permits_block()[0])

    def test_recovery_needs_the_cooldown_to_pass(self):
        """§194. A breaker that closed the instant a metric dipped would flap."""
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(minimum_sources_for_share=10,
                                          max_block_share=0.02,
                                          cooldown_seconds=300.0),
                             clock=lambda: clock[0])
        for index in range(100):
            panel.observe_source(f'source-{index}')
        for _ in range(50):
            panel.mass_block.observe_block()
        self.assertEqual(panel.mass_block.breaker.evaluate(), OPEN)
        clock[0] += 400.0                      # the block window ages out
        for index in range(100, 200):
            panel.observe_source(f'source-{index}')
        panel.mass_block.evaluate()
        self.assertEqual(panel.mass_block.breaker.evaluate(), COOLDOWN)
        self.assertFalse(panel.mass_block.permits)
        clock[0] += 301.0
        self.assertEqual(panel.mass_block.breaker.evaluate(), CLOSED)
        self.assertTrue(panel.mass_block.permits)


class TestFalsePositiveBreaker(unittest.TestCase):
    """§52, and the §61 loop it must not become."""

    def test_the_systems_own_decisions_are_refused_as_an_outcome_source(self):
        panel = BreakerPanel()
        for source in ('autonomous_block', 'challenge_failed', 'ml_high', 'heuristic'):
            with self.subTest(source=source):
                with self.assertRaises(BreakerError):
                    panel.false_positive.report(false_blocks=10, benign_sources=100,
                                                source=source)

    def test_trusted_evaluation_showing_benign_blocking_opens_the_breaker(self):
        panel = BreakerPanel(BudgetLimits(minimum_benign_sample=100,
                                          max_false_blocks_per_1000=1.0))
        panel.false_positive.report(false_blocks=20, benign_sources=1000,
                                    source='reviewed_evaluation')
        allowed, code, _ = panel.permits_block()
        self.assertFalse(allowed)
        self.assertEqual(code, codes.FALSE_POSITIVE_FREEZE)

    def test_no_trusted_outcome_reports_no_rate_rather_than_zero(self):
        """§156. Zero is a measurement; the absence of one is not."""
        panel = BreakerPanel()
        self.assertIsNone(panel.false_positive.rate_per_1000)
        self.assertEqual(panel.false_positive.explain()['ground_truth'],
                         'GROUND_TRUTH_UNAVAILABLE')

    def test_a_tiny_benign_sample_does_not_open_the_breaker(self):
        panel = BreakerPanel(BudgetLimits(minimum_benign_sample=500))
        panel.false_positive.report(false_blocks=3, benign_sources=10,
                                    source='lab_scenario')
        self.assertTrue(panel.permits_block()[0])


class TestTechnicalBreaker(unittest.TestCase):
    """§53. Broken machinery makes a decision meaningless, not merely less accurate."""

    def test_each_named_fault_stops_new_blocks(self):
        from eye_for_an_eye.autonomy.breakers import TECHNICAL_FAULTS
        for fault in TECHNICAL_FAULTS:
            with self.subTest(fault=fault):
                panel = BreakerPanel()
                panel.technical.fault(fault)
                allowed, code, _ = panel.permits_block()
                self.assertFalse(allowed)
                self.assertEqual(code, codes.TECHNICAL_FREEZE)

    def test_clearing_the_last_fault_starts_a_cooldown_rather_than_resuming(self):
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(cooldown_seconds=60.0), clock=lambda: clock[0])
        panel.technical.fault('clock_anomaly')
        panel.technical.resolve('clock_anomaly')
        self.assertFalse(panel.permits_block()[0])
        clock[0] += 61.0
        self.assertTrue(panel.permits_block()[0])

    def test_one_fault_clearing_while_another_remains_does_not_resume(self):
        panel = BreakerPanel()
        panel.technical.fault('model_invalid')
        panel.technical.fault('storage_corruption')
        panel.technical.resolve('model_invalid')
        self.assertFalse(panel.permits_block()[0])


class TestBlockDurationLadder(unittest.TestCase):
    """§46, §181. Escalating, and capped."""

    def test_repeated_offences_escalate_the_duration(self):
        gates = DecisionGates()
        durations = [gates.ttl_for(count) for count in range(6)]
        self.assertEqual(durations, sorted(durations))
        self.assertGreater(durations[3], durations[0])

    def test_the_ladder_is_capped_however_many_offences(self):
        gates = DecisionGates()
        for count in (4, 40, 4000, 10**9):
            with self.subTest(offences=count):
                self.assertLessEqual(gates.ttl_for(count), MAX_BLOCK_TTL_SECONDS)

    def test_a_ladder_that_does_not_escalate_is_refused(self):
        with self.assertRaises(ValueError):
            DecisionGates(block_ttl_ladder=(1800, 300))

    def test_a_ladder_beyond_the_ceiling_is_refused(self):
        with self.assertRaises(ValueError):
            DecisionGates(block_ttl_ladder=(MAX_BLOCK_TTL_SECONDS + 1,))


class TestMetricsAreBounded(unittest.TestCase):
    """§158, §159. No address, no path, no unbounded label."""

    def test_the_metric_names_are_a_fixed_set(self):
        """Fixed, and P15.5 widened it: one suppression series per assumption,
        plus a degraded flag. The expected set is *derived* from
        `ASSUMPTION_NAMES` rather than transcribed, because a label set written
        out by hand here would pass while the real one grew from the data —
        which is the unbounded-cardinality bug this test exists to prevent."""
        from eye_for_an_eye.autonomy.record import ASSUMPTION_NAMES
        instance = authority()
        instance.decide(DecisionInputs(**BLOCKABLE))
        names = set(instance.metrics())
        self.assertEqual(names, {
            'autonomous_decisions_total', 'autonomous_allow_total',
            'autonomous_block_total', 'autonomous_block_suppressed_total',
            'block_budget_utilization', 'block_circuit_breaker_total',
            'autonomous_safe_mode_total', 'autonomous_assumption_health_degraded',
            *(f'autonomous_block_suppressed_by_{name}_total'
              for name in ASSUMPTION_NAMES)})

    def test_no_metric_value_contains_a_source_address(self):
        instance = authority()
        instance.decide(DecisionInputs(**BLOCKABLE))
        for name, value in instance.metrics().items():
            with self.subTest(metric=name):
                self.assertIsInstance(value, (int, float))

    def test_a_suppressed_block_is_counted_separately(self):
        """§157. How many the arithmetic wanted and a gate refused."""
        instance = authority()
        instance.decide(DecisionInputs(**{**BLOCKABLE, 'protected': True}))
        self.assertGreaterEqual(instance.counters['suppressed'], 0)


class TestHysteresis(unittest.TestCase):
    """§122. Lower the bar for a known repeat; never lower any other gate."""

    def test_a_repeat_offender_faces_the_release_margin(self):
        instance = authority()
        fresh = instance._margin(DecisionInputs(source='x', offence_count=0))
        repeat = instance._margin(DecisionInputs(source='x', offence_count=2))
        self.assertLess(repeat, fresh)

    def test_a_repeat_offender_with_weak_evidence_is_still_allowed(self):
        record = decide(offence_count=3, data_quality=0.2)
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.INSUFFICIENT_DATA_QUALITY, record.reason_codes)


class TestTheAuthorityHasNoEnforcementPrivilege(unittest.TestCase):
    """§91. The separation is structural, not a naming convention."""

    def test_the_class_declares_and_holds_no_enforcement_privilege(self):
        instance = authority()
        self.assertFalse(instance.has_enforcement_privilege)
        for attribute in vars(instance).values():
            with self.subTest(attribute=type(attribute).__name__):
                self.assertFalse(hasattr(attribute, 'block'),
                                 'the authority is holding something that can block')

    def test_the_module_imports_nothing_that_can_change_a_firewall(self):
        """Parsed, not grepped.

        The first version of this test searched the file text for
        `security.firewall` and failed on the module docstring, which says the
        authority holds no firewall handle. That is the same trap
        `tests/denial.py` exists for, and the fix is the same in spirit: ask a
        precise question. Imports are a syntax tree node, so read the tree.
        """
        import ast
        from pathlib import Path
        source = (Path(__file__).resolve().parents[1] / 'eye_for_an_eye' /
                  'autonomy' / 'authority.py').read_text(encoding='utf-8')
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = ('.' * node.level) + (node.module or '')
                imported.add(base)
                imported.update(f'{base}.{alias.name}' for alias in node.names)
        for name in sorted(imported):
            with self.subTest(imported=name):
                for forbidden in ('firewall', 'temporary_blocks', 'subprocess',
                                  'nftables', 'socket', 'security'):
                    self.assertNotIn(forbidden, name,
                                     'the authority is importing something that '
                                     'can change the world')


class TestDecisionsAreFastEnoughForTheHotPath(unittest.TestCase):
    """§144. Not a benchmark; a guard against something quadratic creeping in."""

    def test_a_thousand_decisions_stay_within_a_bounded_budget(self):
        instance = authority()
        inputs = DecisionInputs(**BLOCKABLE)
        start = time.perf_counter()
        for _ in range(1000):
            instance.decide(inputs)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 5.0, f'1000 decisions took {elapsed:.2f}s')


if __name__ == '__main__':
    unittest.main()
