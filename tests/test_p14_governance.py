"""P14 phases 1-2: the lifecycle, the policy, and every eligibility gate.

The structure of this file is the argument it makes. One fixture builds a
candidate that passes everything; every other test changes exactly one thing and
asserts the verdict changes. A gate that no test can break by breaking its input
is a gate that is not load-bearing, and this layout makes that visible rather
than leaving it to be discovered later.

The four verdicts are kept distinct throughout, because collapsing them is the
most likely way this goes wrong:

    ELIGIBLE        every gate passed, and the ones needing labels had them
    NOT_ELIGIBLE    a gate failed on the evidence available
    NEED_MORE_DATA  no gate failed; a gate that needs ground truth lacked it
    QUARANTINED     the artifact is not what it claims to be

NEED_MORE_DATA is not a polite NOT_ELIGIBLE. It says the question was not
answered. Treating it as a refusal would teach an operator to read "we could not
tell" as "it regressed", and treating it as a pass would let a large pile of
unlabelled traffic authorise a promotion — which is the single failure §11 and
§12 exist to prevent.
"""
import dataclasses
import unittest

from eye_for_an_eye.governance import lifecycle
from eye_for_an_eye.governance.assessment import (ELIGIBLE, NEED_MORE_DATA,
                                                  NOT_ELIGIBLE, QUARANTINED)
from eye_for_an_eye.governance.engine import ModelGovernanceEngine
from eye_for_an_eye.governance.evidence import (ArtifactEvidence, ContextEvidence,
                                                GovernanceState, HEALTHY,
                                                HealthEvidence, OfflineEvidence,
                                                ShadowEvidence, UNRELIABLE)
from eye_for_an_eye.governance.policy import (AutoPromoteSettings, GovernancePolicy,
                                              PolicyError)

SITE = 'SITE:main'
TRUSTED = ('controlled_lab', 'manual_review')


def policy(**changes):
    """A policy with site `main` opted in, so the fixture can reach ELIGIBLE."""
    auto = AutoPromoteSettings(enabled=True, global_enabled=False, sites=('main',))
    return dataclasses.replace(GovernancePolicy(auto_promote=auto), **changes)


def artifact(**changes):
    base = dict(version='web-risk-v5', scope=SITE, sha256='a' * 64,
                declared_sha256='a' * 64, feature_schema_version=1,
                feature_order_matches=True, dataset_version='dataset-v2',
                parent_model='web-risk-v4', size_bytes=1_048_576,
                load_seconds=0.8, compatible_fusion_version='fusion-v2',
                compatible_policy_version='policy-v3')
    base.update(changes)
    return ArtifactEvidence(**base)


def offline(**changes):
    base = dict(dataset_validation_passed=True, group_split_verified=True,
                onnx_parity_max_abs_error=3e-7, pr_auc=0.81, roc_auc=0.88,
                hard_positive_recall=0.74, false_blocks_per_1000_benign=0.30,
                hard_negative_false_block_rate=0.004, block_precision=0.92,
                system_replay_completed=True, inference_p95_ms=1.6,
                rss_bytes=54_000_000, trusted_outcomes=140,
                label_provenance=TRUSTED)
    base.update(changes)
    return OfflineEvidence(**base)


def active_offline(**changes):
    base = dict(dataset_validation_passed=True, group_split_verified=True,
                onnx_parity_max_abs_error=2e-7, pr_auc=0.79, roc_auc=0.86,
                hard_positive_recall=0.75, false_blocks_per_1000_benign=0.32,
                hard_negative_false_block_rate=0.005, block_precision=0.90,
                system_replay_completed=True, inference_p95_ms=1.5,
                rss_bytes=52_000_000, trusted_outcomes=140,
                label_provenance=TRUSTED)
    base.update(changes)
    return OfflineEvidence(**base)


def shadow(**changes):
    base = dict(observed_seconds=864_000.0, feature_vectors=41_000,
                source_groups=2_400, sites_with_activity=1, scored_by_both=41_000,
                agreement_ratio=0.96, large_disagreements=700,
                active_actions={'OBSERVE': 38_000, 'WATCH': 2_600, 'RATE_LIMIT': 380,
                                'TEMP_BLOCK': 20},
                candidate_actions={'OBSERVE': 37_800, 'WATCH': 2_750,
                                   'RATE_LIMIT': 430, 'TEMP_BLOCK': 20},
                inference_failures=0, inference_p95_ms=1.6,
                active_ood_ratio=0.14, candidate_ood_ratio=0.08,
                trusted_outcomes=140, reviewed_false_blocks_active=3,
                reviewed_false_blocks_candidate=2)
    base.update(changes)
    return ShadowEvidence(**base)


def health(**changes):
    base = dict(candidate_state=HEALTHY, active_state=HEALTHY,
                candidate_load_succeeded=True, candidate_finite_outputs=True,
                candidate_inference_errors=0, candidate_timeouts=0,
                warmup_completed=True)
    base.update(changes)
    return HealthEvidence(**base)


def context(**changes):
    base = dict(drift_status='STABLE', active_ood_ratio=0.14,
                candidate_ood_ratio=0.08, data_quality='GOOD', site_state='ACTIVE')
    base.update(changes)
    return ContextEvidence(**base)


def state(**changes):
    base = dict(frozen=False, safe_mode=False,
                seconds_since_last_promotion=1_209_600.0, promotions_today=0,
                promotions_today_this_scope=0, rollbacks_today=0,
                in_flight_promotions=0, rollback_target='web-risk-v4',
                last_known_good='web-risk-v4')
    base.update(changes)
    return GovernanceState(**base)


def assess(*, scope=SITE, engine=None, **overrides):
    """Assess the good candidate, with named pieces swapped out."""
    parts = {'artifact': artifact(), 'offline': offline(), 'shadow': shadow(),
             'health': health(), 'context': context(), 'state': state(),
             'active_offline': active_offline()}
    parts.update(overrides)
    return (engine or ModelGovernanceEngine(policy())).assess(scope=scope, **parts)


class TestTheFixtureIsActuallyEligible(unittest.TestCase):
    """If this fails, every other test in the file proves nothing."""

    def test_a_good_candidate_is_eligible(self):
        result = assess()
        self.assertEqual(result.decision, ELIGIBLE,
                         f'reasons: {list(result.reasons)}')

    def test_the_record_names_every_gate_rather_than_one_score(self):
        """§26. A promotion nobody can take apart is not explainable."""
        result = assess()
        self.assertGreater(len(result.outcomes), 20)
        document = result.explain()
        self.assertIn('gates', document)
        self.assertIn('gates_by_category', document)
        for forbidden in ('promotion_score', 'score', 'confidence'):
            self.assertNotIn(forbidden, document,
                             'the record exposes a summary score as the decision')

    def test_the_record_is_immutable(self):
        result = assess()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.decision = ELIGIBLE

    def test_the_assessment_id_is_content_addressed(self):
        """Re-assessing unchanged evidence must be visibly the same answer."""
        self.assertEqual(assess().assessment_id, assess().assessment_id)
        different = assess(artifact=artifact(version='web-risk-v6'))
        self.assertNotEqual(assess().assessment_id, different.assessment_id)

    def test_the_record_renders_for_a_person(self):
        rendered = assess().render()
        self.assertIn('AUTO-PROMOTION ASSESSMENT', rendered)
        self.assertIn(SITE, rendered)
        self.assertIn('Decision:', rendered)


class TestIntegrityFailuresQuarantine(unittest.TestCase):
    """§31, §121. Not a quality judgement: the file is not what it claims."""

    def test_a_bad_hash_is_quarantined(self):
        result = assess(artifact=artifact(sha256='b' * 64))
        self.assertEqual(result.decision, QUARANTINED)
        self.assertTrue(any('artifact_hash' in reason for reason in result.reasons))

    def test_a_wrong_scope_is_quarantined(self):
        result = assess(artifact=artifact(scope='SITE:other'))
        self.assertEqual(result.decision, QUARANTINED)
        self.assertTrue(any('scope' in reason for reason in result.reasons))

    def test_a_shuffled_feature_order_is_quarantined(self):
        """The mismatch with no symptom: right width, wrong meaning."""
        result = assess(artifact=artifact(feature_order_matches=False))
        self.assertEqual(result.decision, QUARANTINED)

    def test_non_finite_output_is_quarantined(self):
        result = assess(health=health(candidate_finite_outputs=False))
        self.assertEqual(result.decision, QUARANTINED)

    def test_an_absurdly_large_artifact_is_quarantined(self):
        """§111. A model that would not fit is a resource attack, not a model."""
        result = assess(artifact=artifact(size_bytes=900_000_000))
        self.assertEqual(result.decision, QUARANTINED)

    def test_integrity_outranks_every_quality_metric(self):
        """A corrupt artifact with perfect numbers is still quarantined."""
        result = assess(artifact=artifact(sha256='b' * 64),
                        offline=offline(block_precision=1.0,
                                        false_blocks_per_1000_benign=0.0))
        self.assertEqual(result.decision, QUARANTINED)


class TestCompatibilityFailures(unittest.TestCase):
    """§121. Wrong schema is a refusal, not a quarantine: the file is fine."""

    def test_a_wrong_feature_schema_is_not_eligible(self):
        result = assess(artifact=artifact(feature_schema_version=99))
        self.assertEqual(result.decision, NOT_ELIGIBLE)

    def test_a_candidate_never_replayed_through_the_stack_is_not_eligible(self):
        """§18, §90. A classifier compared in isolation describes a number
        nobody acts on."""
        result = assess(offline=offline(system_replay_completed=False))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('system_replay' in reason for reason in result.reasons))

    def test_an_unvalidated_dataset_is_not_eligible(self):
        self.assertEqual(assess(offline=offline(dataset_validation_passed=False)).decision,
                         NOT_ELIGIBLE)

    def test_an_unverified_split_is_not_eligible(self):
        self.assertEqual(assess(offline=offline(group_split_verified=False)).decision,
                         NOT_ELIGIBLE)

    def test_a_missing_parity_measurement_is_need_more_data_not_a_pass(self):
        result = assess(offline=offline(onnx_parity_max_abs_error=None))
        self.assertEqual(result.decision, NEED_MORE_DATA)

    def test_a_failed_parity_measurement_is_not_eligible(self):
        result = assess(offline=offline(onnx_parity_max_abs_error=0.2))
        self.assertEqual(result.decision, NOT_ELIGIBLE)


class TestHealthGates(unittest.TestCase):
    """§24, §25. Only a HEALTHY candidate may auto-promote."""

    def test_an_unreliable_candidate_is_not_eligible(self):
        self.assertEqual(assess(health=health(candidate_state=UNRELIABLE)).decision,
                         NOT_ELIGIBLE)

    def test_a_candidate_that_did_not_warm_up_is_not_eligible(self):
        """§149. It must answer a synthetic vector before it answers a real one."""
        self.assertEqual(assess(health=health(warmup_completed=False)).decision,
                         NOT_ELIGIBLE)

    def test_inference_errors_during_evaluation_are_not_eligible(self):
        self.assertEqual(assess(health=health(candidate_inference_errors=3)).decision,
                         NOT_ELIGIBLE)

    def test_a_degraded_active_model_does_not_lower_any_candidate_threshold(self):
        """§25. The most tempting shortcut in the whole stage."""
        weak = assess(health=health(active_state='DEGRADED'),
                      offline=offline(hard_negative_false_block_rate=0.9))
        self.assertEqual(weak.decision, NOT_ELIGIBLE,
                         'a weak candidate was accepted because the active model '
                         'was degraded')

    def test_a_degraded_active_model_does_not_block_a_good_candidate_either(self):
        self.assertEqual(assess(health=health(active_state='DEGRADED')).decision,
                         ELIGIBLE)


class TestBenignSafetyGates(unittest.TestCase):
    """§15, §16, §19, §123, §124. The tightest budgets in the policy."""

    def test_a_hard_negative_regression_is_not_eligible(self):
        """§124. It finds more attacks and blocks the monitoring client."""
        result = assess(offline=offline(hard_negative_false_block_rate=0.25,
                                        pr_auc=0.95, block_precision=0.99))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('hard_negatives' in reason for reason in result.reasons))

    def test_more_false_blocks_is_not_eligible_however_good_the_rest_is(self):
        """§123. F1 improves; false blocks double. The answer is still no."""
        result = assess(offline=offline(false_blocks_per_1000_benign=1.4,
                                        pr_auc=0.97, roc_auc=0.98,
                                        block_precision=0.99,
                                        hard_positive_recall=0.95))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('false_blocks' in reason for reason in result.reasons))

    def test_reviewed_false_blocks_that_got_worse_are_not_eligible(self):
        result = assess(shadow=shadow(reviewed_false_blocks_active=1,
                                      reviewed_false_blocks_candidate=9))
        self.assertEqual(result.decision, NOT_ELIGIBLE)

    def test_a_small_improvement_within_budget_is_fine(self):
        self.assertEqual(assess(offline=offline(false_blocks_per_1000_benign=0.20)).decision,
                         ELIGIBLE)


class TestSecurityQualityGates(unittest.TestCase):
    """§14. Regression budgets, never a demand for improvement."""

    def test_a_block_precision_collapse_is_not_eligible(self):
        result = assess(offline=offline(block_precision=0.40))
        self.assertEqual(result.decision, NOT_ELIGIBLE)

    def test_matching_the_active_model_exactly_is_eligible(self):
        """A candidate that is no better and no worse, but cheaper or newer, is
        not required to improve anything."""
        numbers = dict(pr_auc=0.79, roc_auc=0.86, hard_positive_recall=0.75,
                       false_blocks_per_1000_benign=0.32,
                       hard_negative_false_block_rate=0.005, block_precision=0.90)
        self.assertEqual(assess(offline=offline(**numbers)).decision, ELIGIBLE)

    def test_buying_precision_by_ignoring_patient_scanners_is_not_eligible(self):
        result = assess(offline=offline(hard_positive_recall=0.20,
                                        block_precision=0.99,
                                        false_blocks_per_1000_benign=0.05))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('hard_positives' in reason for reason in result.reasons))


class TestGroundTruthIsRequiredForQualityClaims(unittest.TestCase):
    """§11, §12, §122. The rule that keeps this honest."""

    def test_a_huge_unlabelled_shadow_run_cannot_prove_better_precision(self):
        result = assess(shadow=shadow(feature_vectors=5_000_000,
                                      source_groups=90_000,
                                      trusted_outcomes=0,
                                      reviewed_false_blocks_active=None,
                                      reviewed_false_blocks_candidate=None),
                        offline=offline(trusted_outcomes=0, label_provenance=()))
        self.assertEqual(result.decision, NEED_MORE_DATA,
                         'unlabelled traffic was accepted as proof of quality')

    def test_need_more_data_is_not_reported_as_a_failure(self):
        result = assess(offline=offline(trusted_outcomes=0, label_provenance=()),
                        shadow=shadow(trusted_outcomes=0))
        self.assertEqual(result.decision, NEED_MORE_DATA)
        self.assertEqual(result.failures(), (),
                         'a gate was reported as failed when it was merely unmeasured')
        self.assertTrue(result.unproven())

    def test_untrusted_label_provenance_does_not_count(self):
        """A large number of outcomes from a source we do not trust is not
        ground truth, however large it is."""
        result = assess(offline=offline(trusted_outcomes=9_999,
                                        label_provenance=('synthetic_generator',)))
        self.assertIn(result.decision, (NEED_MORE_DATA, NOT_ELIGIBLE))

    def test_a_real_regression_outranks_a_missing_measurement(self):
        """§: "we could not measure X" never excuses "Y regressed"."""
        result = assess(offline=offline(onnx_parity_max_abs_error=None,
                                        hard_negative_false_block_rate=0.9))
        self.assertEqual(result.decision, NOT_ELIGIBLE)


class TestShadowSufficiency(unittest.TestCase):
    """§10, §121. Not enough observation is NEED_MORE_DATA, not a refusal."""

    def test_a_short_shadow_run_is_need_more_data(self):
        self.assertEqual(assess(shadow=shadow(observed_seconds=600.0)).decision,
                         NEED_MORE_DATA)

    def test_too_few_feature_vectors_is_need_more_data(self):
        self.assertEqual(assess(shadow=shadow(feature_vectors=12)).decision,
                         NEED_MORE_DATA)

    def test_too_few_source_groups_is_need_more_data(self):
        """Volume from four addresses is not evidence about a population."""
        self.assertEqual(assess(shadow=shadow(source_groups=4)).decision,
                         NEED_MORE_DATA)

    def test_shadow_inference_failures_are_a_refusal_not_missing_evidence(self):
        result = assess(shadow=shadow(inference_failures=4_000))
        self.assertEqual(result.decision, NOT_ELIGIBLE)

    def test_requirements_are_configurable_per_installation(self):
        """§10. One event count for every site would be wrong for every site."""
        from eye_for_an_eye.governance.policy import ShadowRequirements
        lenient = policy(shadow=ShadowRequirements(
            minimum_seconds=60.0, minimum_feature_vectors=100,
            minimum_source_groups=10, minimum_trusted_outcomes=5))
        small = shadow(observed_seconds=120.0, feature_vectors=150,
                       source_groups=12, trusted_outcomes=6)
        result = assess(shadow=small, offline=offline(trusted_outcomes=6),
                        engine=ModelGovernanceEngine(lenient))
        self.assertEqual(result.decision, ELIGIBLE, list(result.reasons))


class TestResourceGates(unittest.TestCase):
    """§20, §121, §131. Website availability outranks model experimentation."""

    def test_excess_latency_is_not_eligible(self):
        result = assess(offline=offline(inference_p95_ms=90.0))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('latency' in reason for reason in result.reasons))

    def test_excess_memory_is_reported(self):
        result = assess(offline=offline(rss_bytes=900_000_000))
        self.assertIn(result.decision, (NOT_ELIGIBLE, ELIGIBLE))
        names = {outcome.name: outcome for outcome in result.outcomes}
        self.assertFalse(names['memory'].passed)

    def test_a_model_that_takes_a_minute_to_load_is_not_eligible(self):
        """§147. Activation must not be a visible pause on a live site."""
        self.assertEqual(assess(artifact=artifact(load_seconds=120.0)).decision,
                         NOT_ELIGIBLE)


class TestOodAndDriftAreNeverAccusations(unittest.TestCase):
    """§21, §23, §49, §50, §133, §134."""

    def test_high_candidate_ood_alone_does_not_refuse_promotion(self):
        result = assess(context=context(candidate_ood_ratio=0.62,
                                        active_ood_ratio=0.14))
        self.assertEqual(result.decision, ELIGIBLE,
                         'a high out-of-distribution rate was treated as a fault')
        names = {outcome.name: outcome for outcome in result.outcomes}
        self.assertFalse(names['ood_comparison'].passed)
        self.assertEqual(names['ood_comparison'].severity, 'advisory')

    def test_drift_alone_does_not_refuse_promotion(self):
        result = assess(context=context(drift_status='DRIFTED'))
        self.assertEqual(result.decision, ELIGIBLE)

    #: Words that turn an occurrence into a denial of the thing named. The gate
    #: text says drift "is never evidence of an attack", and a plain substring
    #: search cannot tell that sentence from the claim it refutes — failing on
    #: the sentence that states the rule most clearly is how a test teaches
    #: people to delete the sentence instead of fixing the problem.
    DENIALS = ('never', 'not ', 'no ', 'rather than', 'is not')

    def asserted(self, text, word):
        """Occurrences of `word` that are not inside a denial of it."""
        found, start = [], 0
        while (index := text.find(word, start)) != -1:
            window = text[max(0, index - 90):index + len(word) + 30]
            if not any(denial in window for denial in self.DENIALS):
                found.append(window)
            start = index + len(word)
        return found

    def test_neither_is_ever_described_as_hostile(self):
        result = assess(context=context(drift_status='DRIFTED',
                                        candidate_ood_ratio=0.9))
        text = ' '.join(outcome.detail for outcome in result.outcomes).lower()
        for forbidden in ('malicious', 'attack', 'hostile', 'suspicious'):
            with self.subTest(word=forbidden):
                self.assertFalse(self.asserted(text, forbidden),
                                 f'a gate describes something as {forbidden!r}')

    def test_a_large_action_shift_blocks_promotion_and_says_why(self):
        """§52. Not an accusation either: a reason for a person to look."""
        result = assess(shadow=shadow(
            candidate_actions={'OBSERVE': 20_000, 'WATCH': 8_000,
                               'RATE_LIMIT': 8_000, 'TEMP_BLOCK': 5_000}))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('act differently' in reason for reason in result.reasons))


class TestGovernanceGates(unittest.TestCase):
    """§4, §5, §6, §32, §33, §54, §58, §80, §126."""

    def test_auto_promotion_disabled_means_nothing_is_eligible(self):
        engine = ModelGovernanceEngine(GovernancePolicy())
        result = assess(engine=engine)
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('disabled' in reason for reason in result.reasons))

    def test_a_site_that_did_not_opt_in_is_not_eligible(self):
        """§5. One site opting in must not enable another."""
        result = assess(scope='SITE:api',
                        artifact=artifact(scope='SITE:api'))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('opted in' in reason for reason in result.reasons))

    def test_global_promotion_is_refused_while_global_is_disabled(self):
        """§126. Global is a separate decision with a separate switch."""
        result = assess(scope='GLOBAL', artifact=artifact(scope='GLOBAL'),
                        context=context(per_site_false_blocks={'main': 0.2}))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('global' in reason.lower() for reason in result.reasons))

    def test_a_global_candidate_is_judged_by_its_worst_site(self):
        """§74. An aggregate is good at hiding the site that got worse."""
        engine = ModelGovernanceEngine(policy().with_auto_promote(global_enabled=True))
        result = assess(scope='GLOBAL', artifact=artifact(scope='GLOBAL'),
                        context=context(per_site_false_blocks={'main': 0.1,
                                                               'api': 0.2,
                                                               'tiny': 8.0}),
                        engine=engine)
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('tiny' in reason for reason in result.reasons))

    def test_a_global_candidate_with_no_per_site_evidence_is_need_more_data(self):
        engine = ModelGovernanceEngine(policy().with_auto_promote(global_enabled=True))
        result = assess(scope='GLOBAL', artifact=artifact(scope='GLOBAL'),
                        engine=engine)
        self.assertEqual(result.decision, NEED_MORE_DATA)

    def test_no_rollback_target_is_not_eligible(self):
        """§58. Nothing irreversible happens automatically."""
        result = assess(state=state(rollback_target=''))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('rollback' in reason for reason in result.reasons))

    def test_a_frozen_installation_promotes_nothing(self):
        result = assess(state=state(frozen=True, freeze_reason='operator freeze'))
        self.assertEqual(result.decision, NOT_ELIGIBLE)

    def test_safe_mode_promotes_nothing(self):
        self.assertEqual(assess(state=state(safe_mode=True)).decision, NOT_ELIGIBLE)

    def test_the_cooldown_prevents_churn(self):
        self.assertEqual(assess(state=state(seconds_since_last_promotion=600.0)).decision,
                         NOT_ELIGIBLE)

    def test_a_spent_daily_budget_stops_promotion(self):
        self.assertEqual(assess(state=state(promotions_today=9)).decision, NOT_ELIGIBLE)

    def test_only_one_transition_per_scope_at_a_time(self):
        """§33, §140."""
        self.assertEqual(assess(state=state(in_flight_promotions=1)).decision,
                         NOT_ELIGIBLE)

    def test_a_rolled_back_version_cannot_immediately_retry(self):
        """§80, §81, §139. The oscillation this exists to prevent."""
        result = assess(state=state(rolled_back_versions=('web-risk-v5',)))
        self.assertEqual(result.decision, NOT_ELIGIBLE)
        self.assertTrue(any('rolled back' in reason for reason in result.reasons))

    def test_a_quarantined_version_cannot_retry_either(self):
        result = assess(state=state(quarantined_versions=('web-risk-v5',)))
        self.assertEqual(result.decision, NOT_ELIGIBLE)


class TestThePolicyItself(unittest.TestCase):
    """§28, §29, §141. Versioned, content-addressed, and never self-tuning."""

    def test_a_policy_carries_a_digest_of_its_own_contents(self):
        self.assertNotEqual(GovernancePolicy().digest, policy().digest)

    def test_changing_a_tolerance_changes_the_digest(self):
        from eye_for_an_eye.governance.policy import RegressionBudgets
        strict = dataclasses.replace(
            GovernancePolicy(),
            budgets=RegressionBudgets(max_false_block_increase_per_1000=0.1))
        self.assertNotEqual(GovernancePolicy().digest, strict.digest)

    def test_an_assessment_made_under_another_policy_is_stale(self):
        """§29. A policy change never retroactively authorises a verdict."""
        result = assess()
        self.assertFalse(result.is_stale_under(policy()))
        self.assertTrue(result.is_stale_under(GovernancePolicy()))

    def test_auto_promotion_without_guarded_activation_is_refused(self):
        with self.assertRaises(PolicyError):
            GovernancePolicy(auto_promote=AutoPromoteSettings(enabled=True),
                             guarded_activation_enabled=False)

    def test_auto_promotion_without_rollback_is_refused(self):
        with self.assertRaises(PolicyError):
            GovernancePolicy(auto_promote=AutoPromoteSettings(enabled=True),
                             auto_rollback_enabled=False)

    def test_guarded_stages_may_not_loosen_then_tighten(self):
        from eye_for_an_eye.governance.policy import GuardedStage
        with self.assertRaises(PolicyError):
            GovernancePolicy(stages=(
                GuardedStage('a', 'RATE_LIMIT', 60, 10, 1),
                GuardedStage('b', 'WATCH', 60, 10, 1)))

    def test_the_first_stage_ceiling_is_not_a_blocking_action(self):
        """§37. A newly promoted model must not be able to block anybody."""
        first = GovernancePolicy().first_stage
        self.assertEqual(first.action_ceiling, 'WATCH')

    def test_the_default_policy_is_off_in_both_directions(self):
        """§4, §6, §143."""
        settings = GovernancePolicy().auto_promote
        self.assertFalse(settings.enabled)
        self.assertFalse(settings.global_enabled)
        self.assertEqual(settings.sites, ())


class TestTheLifecycleTable(unittest.TestCase):
    """§76, §77, §80. The transitions are data; invalid ones are refused."""

    def test_nothing_reaches_active_except_through_guarded_active(self):
        for origin in lifecycle.STATES:
            if origin == lifecycle.GUARDED_ACTIVE:
                continue
            with self.subTest(origin=origin):
                self.assertFalse(lifecycle.can_transition(origin, lifecycle.ACTIVE),
                                 f'{origin} can reach ACTIVE without a guarded stage')

    def test_the_happy_path_is_allowed_end_to_end(self):
        path = [lifecycle.TRAINED, lifecycle.VALIDATED, lifecycle.SHADOW,
                lifecycle.ELIGIBLE, lifecycle.PENDING_ACTIVATION,
                lifecycle.GUARDED_ACTIVE, lifecycle.ACTIVE]
        for current, target in zip(path, path[1:]):
            with self.subTest(step=f'{current}->{target}'):
                self.assertEqual(lifecycle.transition(current, target), target)

    def test_a_rolled_back_model_goes_to_quarantine_not_back_to_validated(self):
        self.assertTrue(lifecycle.can_transition(lifecycle.ROLLED_BACK,
                                                 lifecycle.QUARANTINED))
        self.assertFalse(lifecycle.can_transition(lifecycle.ROLLED_BACK,
                                                  lifecycle.VALIDATED))
        self.assertFalse(lifecycle.can_transition(lifecycle.ROLLED_BACK,
                                                  lifecycle.SHADOW))

    def test_leaving_quarantine_requires_an_operator(self):
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.transition(lifecycle.QUARANTINED, lifecycle.VALIDATED)
        self.assertEqual(
            lifecycle.transition(lifecycle.QUARANTINED, lifecycle.VALIDATED,
                                 operator=True), lifecycle.VALIDATED)

    def test_the_operator_flag_unlocks_exactly_one_edge(self):
        """Not a general override: a flag that bypassed the table would make
        the table decorative."""
        self.assertFalse(lifecycle.can_transition(lifecycle.SHADOW, lifecycle.ACTIVE,
                                                  operator=True))
        self.assertFalse(lifecycle.can_transition(lifecycle.REJECTED, lifecycle.ACTIVE,
                                                  operator=True))

    def test_an_invalid_transition_names_both_states_and_what_is_allowed(self):
        with self.assertRaises(lifecycle.LifecycleError) as caught:
            lifecycle.transition(lifecycle.SHADOW, lifecycle.ACTIVE)
        message = str(caught.exception)
        self.assertIn(lifecycle.SHADOW, message)
        self.assertIn(lifecycle.ACTIVE, message)
        self.assertIn(lifecycle.ELIGIBLE, message)

    def test_archived_is_terminal(self):
        self.assertEqual(lifecycle.TRANSITIONS[lifecycle.ARCHIVED], ())
        self.assertFalse(lifecycle.reaches_active(lifecycle.ARCHIVED))

    def test_quarantine_and_rejection_are_reachable_from_every_live_stage(self):
        for origin in (lifecycle.TRAINED, lifecycle.VALIDATED, lifecycle.SHADOW,
                       lifecycle.ELIGIBLE):
            with self.subTest(origin=origin):
                self.assertTrue(lifecycle.can_transition(origin, lifecycle.QUARANTINED))

    def test_a_stale_eligible_assessment_can_be_sent_back_to_shadow(self):
        """§29, §141. How a policy change undoes a verdict."""
        self.assertTrue(lifecycle.can_transition(lifecycle.ELIGIBLE, lifecycle.SHADOW))


class TestTheEngineChangesNothing(unittest.TestCase):
    """§1, §86, §109. The separation the whole package rests on."""

    def test_the_engine_cannot_reach_the_registry_or_the_firewall(self):
        import ast
        from pathlib import Path
        from eye_for_an_eye.governance import engine as module
        tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for forbidden in ('registry', 'ModelRegistry', 'firewall', 'enforcement',
                          'security.firewall', 'subprocess', 'os'):
            with self.subTest(name=forbidden):
                self.assertNotIn(forbidden, imported)

    def test_assessing_twice_gives_the_same_answer(self):
        """Deterministic: no clock, no randomness, no accumulated state."""
        first, second = assess(), assess()
        self.assertEqual(first.decision, second.decision)
        self.assertEqual(first.assessment_id, second.assessment_id)

    def test_the_engine_never_reads_the_candidates_own_quality_claims(self):
        """§30. A manifest saying `precision = 1.0` is metadata, not evidence."""
        import inspect
        from eye_for_an_eye.governance import engine as module
        source = inspect.getsource(module)
        for claim in ('manifest_precision', 'manifest.get', 'declared_precision',
                      'claimed_'):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, source)


if __name__ == '__main__':
    unittest.main()
