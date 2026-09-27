"""P15 §12-§13 and §160-§183: measuring the system honestly, and the traps that hide.

Three groups of tests, in increasing order of how easy they are to get wrong.

**The metrics** (§12, §164-§172). A confusion matrix for the final TEMP_BLOCK
decision rather than for the classifier, block precision, false blocks per 1000
benign sources, and the prevalence sweep that shows what those numbers become
when the positive class is rare. The accuracy trap has its own class, because
§13 describes a specific failure that has an appealing number attached to it.

**The scenarios** (§173-§183). Each one is a situation that a defensive system
gets wrong in a way that costs somebody their access: a degraded model that
flags everything, a legitimate backup job that looks anomalous, a conference NAT
behind a CDN, a management address that scans its own network. The tests assert
the outcome, not the mechanism, so a refactor that preserves the behaviour keeps
them passing and a refactor that loses it does not.

**The data gates** (§174-§175). Model collapse and leakage, asserted against the
dataset surfaces that already enforce them, because a P15 test that invented its
own weaker version of an existing gate would be worse than no test.
"""
import unittest

from eye_for_an_eye.autonomy import evaluation as ev
from eye_for_an_eye.autonomy import record as codes
from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               DecisionInputs)
from eye_for_an_eye.autonomy.breakers import BudgetLimits, BreakerPanel
from eye_for_an_eye.autonomy.record import ALLOW, TEMP_BLOCK
from eye_for_an_eye.decision.math_risk import decay

CONTRIBUTIONS = {'ports_60s': 0.9, 'credentials_60s': 0.8,
                 'anomaly_60s': 0.7, 'persistence_900s': 0.4}

BLOCKABLE = dict(
    source='198.51.100.7', identity_confidence='HIGH', network_enforceable=True,
    enforcement_scope='NETWORK_SOURCE', observations=600, observation_seconds=300.0,
    data_quality=1.0, math_risk=0.99, math_contributions=CONTRIBUTIONS,
    ml_usable=True, model_score=0.97, calibrated=True, calibrated_probability=0.999,
    anomaly_score=0.8, ood_score=0.0, ood_status='IN_DISTRIBUTION',
    drift_status='STABLE', model_health='HEALTHY', policy_guard_action='ALLOW')


def decide(authority=None, **changes):
    authority = authority or AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS)
    return authority.decide(DecisionInputs(**{**BLOCKABLE, **changes}))


def population(*, benign, malicious, blocked_benign=0, blocked_malicious=0, site=''):
    """A labelled evaluation set with exactly the four cells asked for."""
    rows = []
    rows += [ev.Outcome(blocked=True, label=ev.BENIGN, score=0.99, site_id=site)
             for _ in range(blocked_benign)]
    rows += [ev.Outcome(blocked=False, label=ev.BENIGN, score=0.01, site_id=site)
             for _ in range(benign - blocked_benign)]
    rows += [ev.Outcome(blocked=True, label=ev.MALICIOUS_AUTOMATION, score=0.99,
                        site_id=site) for _ in range(blocked_malicious)]
    rows += [ev.Outcome(blocked=False, label=ev.MALICIOUS_AUTOMATION, score=0.02,
                        site_id=site) for _ in range(malicious - blocked_malicious)]
    return rows


# --- §13: the accuracy trap -------------------------------------------------

class TestTheAccuracyTrap(unittest.TestCase):
    """§13. The dataset is 99.9% benign and the classifier says benign to everything.

    Its accuracy is 99.9%. It has protected nobody, and the only thing standing
    between that number and a release is a test that refuses to be impressed by
    it. This class is that test.
    """

    def setUp(self):
        self.rows = population(benign=9990, malicious=10)

    def test_the_accuracy_really_is_excellent(self):
        """Stated explicitly so the next test cannot be read as a rounding issue."""
        metrics = ev.evaluate(self.rows)
        self.assertGreater(metrics.accuracy, 0.998)

    def test_the_system_calls_it_useless_anyway(self):
        metrics = ev.evaluate(self.rows)
        self.assertEqual(ev.usefulness(metrics), ev.USELESS_NO_DETECTION)

    def test_the_release_gate_fails_it(self):
        metrics = ev.evaluate(population(benign=9990, malicious=100))
        self.assertEqual(ev.release_gate(metrics)['verdict'], 'FAIL')

    def test_recall_is_zero_and_that_is_what_matters(self):
        metrics = ev.evaluate(self.rows)
        self.assertEqual(metrics.recall, 0.0)
        self.assertEqual(metrics.block_precision, None)

    def test_blocking_everything_is_also_useless(self):
        """The opposite failure, and the more expensive one."""
        rows = population(benign=1000, malicious=100,
                          blocked_benign=1000, blocked_malicious=100)
        self.assertEqual(ev.usefulness(ev.evaluate(rows)),
                         ev.USELESS_BLOCKS_EVERYTHING)

    def test_the_report_says_accuracy_is_used_for_nothing(self):
        body = ev.evaluate(self.rows).explain()
        self.assertIn('used for nothing', body['accuracy_note'])


# --- §164-§166: the final decision, measured --------------------------------

class TestTheFinalDecisionConfusionMatrix(unittest.TestCase):
    """§164. For the action, not for the classifier."""

    def test_the_four_cells_are_counted_from_the_action(self):
        matrix = ev.confusion(population(benign=100, malicious=10,
                                         blocked_benign=2, blocked_malicious=8))
        self.assertEqual(matrix.true_positive, 8)
        self.assertEqual(matrix.false_negative, 2)
        self.assertEqual(matrix.false_positive, 2)
        self.assertEqual(matrix.true_negative, 98)

    def test_block_precision_is_of_what_was_blocked(self):
        """§165. Of everything autonomously blocked, how much should have been?"""
        metrics = ev.evaluate(population(benign=1000, malicious=100,
                                         blocked_benign=1, blocked_malicious=79))
        self.assertAlmostEqual(metrics.block_precision, 79 / 80)

    def test_false_blocks_per_1000_benign_is_the_release_metric(self):
        """§166."""
        metrics = ev.evaluate(population(benign=2000, malicious=100,
                                         blocked_benign=3, blocked_malicious=90))
        self.assertAlmostEqual(metrics.false_blocks_per_1000_benign, 1.5)

    def test_specificity_and_the_two_error_rates_are_all_reported(self):
        body = ev.evaluate(population(benign=1000, malicious=100,
                                      blocked_benign=10, blocked_malicious=90)).explain()
        for key in ('precision', 'recall', 'specificity', 'false_positive_rate',
                    'false_negative_rate', 'block_precision',
                    'false_blocks_per_1000_benign', 'class_prevalence'):
            with self.subTest(metric=key):
                self.assertIsNotNone(body[key])


class TestUnlabelledTrafficProducesNoAccuracy(unittest.TestCase):
    """§156. The most tempting number in the whole system is the one nobody has."""

    def test_a_production_window_with_no_labels_reports_ground_truth_unavailable(self):
        rows = [ev.Outcome(blocked=bool(index % 97 == 0)) for index in range(5000)]
        body = ev.evaluate(rows).explain()
        self.assertEqual(body['status'], ev.GROUND_TRUTH_UNAVAILABLE)
        self.assertNotIn('precision', body)

    def test_the_report_does_not_invent_a_ranking_either(self):
        rows = [ev.Outcome(blocked=False, score=0.3) for _ in range(100)]
        body = ev.report(rows)
        self.assertEqual(body['ranking']['status'], ev.GROUND_TRUTH_UNAVAILABLE)
        self.assertEqual(body['release_gate']['verdict'], 'INSUFFICIENT_EVIDENCE')

    def test_unlabelled_rows_are_counted_but_never_scored(self):
        rows = population(benign=100, malicious=10, blocked_malicious=9)
        rows += [ev.Outcome(blocked=False) for _ in range(500)]
        matrix = ev.confusion(rows)
        self.assertEqual(matrix.unlabeled, 500)
        self.assertEqual(matrix.labelled, 110)


class TestPrevalence(unittest.TestCase):
    """§168, §169. The number that surprises people."""

    def test_precision_collapses_as_the_positive_class_becomes_rare(self):
        metrics = ev.evaluate(population(benign=1000, malicious=1000,
                                         blocked_benign=10, blocked_malicious=950))
        table = {row['prevalence']: row['precision'] for row in ev.prevalence_sweep(metrics)}
        self.assertGreater(table[0.10], table[0.01])
        self.assertGreater(table[0.01], table[0.001])
        self.assertLess(table[0.0001], 0.15)

    def test_a_balanced_lab_result_is_not_a_production_result(self):
        """The same detector, measured two ways, giving two different pictures."""
        metrics = ev.evaluate(population(benign=1000, malicious=1000,
                                         blocked_benign=10, blocked_malicious=950))
        self.assertGreater(metrics.precision, 0.98)
        rare = [row for row in ev.prevalence_sweep(metrics) if row['prevalence'] == 0.001]
        self.assertLess(rare[0]['precision'], 0.60)

    def test_the_sweep_holds_recall_and_fpr_fixed(self):
        metrics = ev.evaluate(population(benign=1000, malicious=100,
                                         blocked_benign=5, blocked_malicious=80))
        for row in ev.prevalence_sweep(metrics):
            with self.subTest(prevalence=row['prevalence']):
                self.assertAlmostEqual(row['recall'], metrics.recall, places=6)
                self.assertAlmostEqual(row['false_positive_rate'],
                                       metrics.false_positive_rate, places=6)


class TestBootstrapAndSampleSize(unittest.TestCase):
    """§35, §170, §171."""

    def test_an_interval_is_produced_and_named_as_empirical(self):
        rows = population(benign=1000, malicious=100,
                          blocked_benign=5, blocked_malicious=80)
        interval = ev.bootstrap_interval(
            rows, lambda sample: ev.evaluate(sample).block_precision, resamples=200)
        self.assertLessEqual(interval['statistic_low'], interval['statistic_high'])
        self.assertIn('not an exact frequentist confidence interval',
                      interval['interpretation'])

    def test_the_interval_is_reproducible(self):
        rows = population(benign=500, malicious=50,
                          blocked_benign=4, blocked_malicious=40)
        first = ev.bootstrap_interval(
            rows, lambda sample: ev.evaluate(sample).false_positive_rate, resamples=150)
        second = ev.bootstrap_interval(
            rows, lambda sample: ev.evaluate(sample).false_positive_rate, resamples=150)
        self.assertEqual(first, second)

    def test_a_wider_interval_comes_from_a_smaller_sample(self):
        def width(benign, malicious):
            rows = population(benign=benign, malicious=malicious,
                              blocked_benign=max(1, benign // 100),
                              blocked_malicious=max(1, int(malicious * 0.8)))
            interval = ev.bootstrap_interval(
                rows, lambda sample: ev.evaluate(sample).block_precision, resamples=300)
            return interval['statistic_high'] - interval['statistic_low']
        self.assertGreater(width(60, 10), width(6000, 1000))

    def test_a_tiny_evaluation_cannot_pass_the_release_gate(self):
        """§171. "Not enough data" is not a PASS with a caveat."""
        metrics = ev.evaluate(population(benign=12, malicious=3, blocked_malicious=3))
        verdict = ev.release_gate(metrics)
        self.assertEqual(verdict['verdict'], 'INSUFFICIENT_EVIDENCE')
        self.assertTrue(any('trusted benign' in reason for reason in verdict['reasons']))

    def test_the_report_states_the_sample_it_measured(self):
        body = ev.evaluate(population(benign=800, malicious=60,
                                      blocked_malicious=50)).explain()
        self.assertEqual(body['benign_sample'], 800)
        self.assertEqual(body['positive_sample'], 60)


class TestWorstSite(unittest.TestCase):
    """§172. An average across sites hides the site that is broken."""

    def test_the_worst_site_is_reported_rather_than_averaged_away(self):
        rows = population(benign=1000, malicious=100, blocked_benign=0,
                          blocked_malicious=95, site='healthy')
        rows += population(benign=200, malicious=20, blocked_benign=40,
                           blocked_malicious=18, site='broken')
        overall = ev.evaluate(rows)
        worst = ev.worst_site(rows)
        self.assertEqual(worst['site'], 'broken')
        self.assertGreater(worst['metrics']['false_blocks_per_1000_benign'],
                           overall.false_blocks_per_1000_benign)

    def test_every_site_gets_its_own_metrics(self):
        rows = population(benign=100, malicious=10, blocked_malicious=9, site='a')
        rows += population(benign=100, malicious=10, blocked_benign=5, site='b')
        report = ev.per_site(rows)
        self.assertEqual(set(report), {'a', 'b'})
        self.assertEqual(report['a'].false_positive_rate, 0.0)
        self.assertAlmostEqual(report['b'].false_positive_rate, 0.05)


class TestRankingMetrics(unittest.TestCase):

    def test_a_perfect_ranking_scores_one(self):
        rows = [ev.Outcome(blocked=False, label=ev.BENIGN, score=0.1) for _ in range(50)]
        rows += [ev.Outcome(blocked=True, label=ev.MALICIOUS_AUTOMATION, score=0.9)
                 for _ in range(10)]
        self.assertAlmostEqual(ev.roc_auc(rows), 1.0)
        self.assertAlmostEqual(ev.pr_auc(rows), 1.0)

    def test_an_uninformative_score_lands_near_one_half(self):
        rows = [ev.Outcome(blocked=False, label=ev.BENIGN, score=0.5) for _ in range(50)]
        rows += [ev.Outcome(blocked=False, label=ev.MALICIOUS_AUTOMATION, score=0.5)
                 for _ in range(50)]
        self.assertAlmostEqual(ev.roc_auc(rows), 0.5)

    def test_a_missing_class_produces_no_auc_rather_than_a_number(self):
        rows = [ev.Outcome(blocked=False, label=ev.BENIGN, score=0.1) for _ in range(10)]
        self.assertIsNone(ev.roc_auc(rows))
        self.assertIsNone(ev.pr_auc(rows))


# --- §173-§183: the scenarios ----------------------------------------------

class TestScenario173ModelPredictsMaliciousForEverything(unittest.TestCase):
    """§173. The single most dangerous failure this project can have."""

    def test_the_mass_block_breaker_stops_the_catastrophe(self):
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(blocks_per_minute=10_000,
                                          max_active_blocks=10_000,
                                          minimum_sources_for_share=100,
                                          max_block_share=0.02),
                             clock=lambda: clock[0])
        authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS,
                                                panel=panel, clock=lambda: clock[0])
        blocked = allowed = 0
        for index in range(1000):
            record = decide(authority, source=f'198.51.100.{index % 256}',
                            calibrated_probability=1.0, model_score=1.0)
            blocked += record.action == TEMP_BLOCK
            allowed += record.action == ALLOW
        self.assertGreater(allowed, 0, 'nothing stopped a model that flagged everything')
        self.assertLess(blocked, 1000)
        self.assertEqual(panel.state, 'AUTONOMOUS_SAFE_MODE')

    def test_the_reason_is_recorded_rather_than_silent(self):
        panel = BreakerPanel(BudgetLimits(blocks_per_minute=2))
        authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS, panel=panel)
        records = [decide(authority, source=f'203.0.113.{index}') for index in range(6)]
        suppressed = [r for r in records if r.action == ALLOW]
        self.assertTrue(suppressed)
        self.assertIn(codes.BLOCK_BUDGET_EXHAUSTED, suppressed[-1].reason_codes)


class TestScenario176OutOfDistributionWithAHighScore(unittest.TestCase):
    """§176. An extreme score on an input the model has never seen is extrapolation."""

    def test_a_high_model_score_on_an_unfamiliar_sample_does_not_block(self):
        record = decide(ood_status='OUT_OF_DISTRIBUTION', ood_score=0.95,
                        model_score=1.0, calibrated_probability=1.0)
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.HIGH_OOD, record.reason_codes)

    def test_the_classifier_loses_authority_rather_than_the_source_gaining_guilt(self):
        familiar = decide(ood_score=0.0, ood_status='IN_DISTRIBUTION')
        unfamiliar = decide(ood_score=0.9, ood_status='BORDERLINE')
        self.assertLessEqual(unfamiliar.conservative_probability,
                             familiar.conservative_probability)


class TestScenario177LegitimateUnusualWorkload(unittest.TestCase):
    """§177. The nightly backup, the analytics crawler, the monitoring probe.

    High anomaly, high rate, one phenomenon, nothing else. Every one of these
    exists on real servers and every one of them would be blocked by a system
    that treated unusual as malicious.
    """

    def test_a_high_anomaly_score_on_one_family_does_not_block(self):
        record = decide(anomaly_score=0.99,
                        math_contributions={'connections_60s': 0.95,
                                            'connections_10s': 0.9,
                                            'burst_10s': 0.9})
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.INSUFFICIENT_SIGNAL_DIVERSITY, record.reason_codes)

    def test_the_explanation_does_not_accuse_the_backup_job(self):
        record = decide(anomaly_score=0.99,
                        math_contributions={'connections_60s': 0.95})
        text = record.explanation()
        self.assertIn('unusual is not malicious', text)


class TestScenario178OneBadClientBehindASharedProxy(unittest.TestCase):
    """§178. The conference NAT, the mobile carrier, the CDN edge."""

    def test_the_proxy_address_is_never_network_blocked(self):
        record = decide(network_enforceable=False, enforcement_scope='WEB_CLIENT',
                        identity_confidence='HIGH')
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.NOT_NETWORK_ENFORCEABLE, record.reason_codes)

    def test_the_record_says_a_block_would_have_hit_the_wrong_machine(self):
        record = decide(network_enforceable=False, enforcement_scope='WEB_CLIENT')
        self.assertIn('would hit a proxy, not this client', record.explanation())

    def test_a_partial_proxy_chain_is_medium_confidence_and_not_blockable(self):
        from eye_for_an_eye.web.identity import ClientResolver
        identity = ClientResolver(['10.0.0.0/8']).resolve(
            '10.0.0.1', forwarded='192.0.2.9, 198.51.100.4')
        self.assertEqual(identity.confidence, 'MEDIUM')
        self.assertFalse(identity.network_enforceable)


class TestScenario179ManagementSourceThatLooksSuspicious(unittest.TestCase):
    """§179. A monitoring host scanning its own fleet looks exactly like a scanner."""

    def test_a_management_source_is_never_locked_out(self):
        record = decide(management=True, calibrated_probability=1.0,
                        model_score=1.0, anomaly_score=1.0)
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.MANAGEMENT_NETWORK, record.reason_codes)

    def test_the_override_is_recorded_rather_than_silently_applied(self):
        record = decide(management=True)
        self.assertFalse(record.safety_gates['not_protected'])
        self.assertIn('the source is in a configured management network',
                      record.explanation())

    def test_policy_guard_protects_loopback_and_configured_networks(self):
        from eye_for_an_eye.config import Config
        from eye_for_an_eye.decision.policy import PolicyGuard
        config = Config()
        config.enforcement.management_networks = ['192.0.2.0/24']
        guard = PolicyGuard(config)
        self.assertTrue(guard.protected('127.0.0.1'))
        self.assertTrue(guard.protected('192.0.2.50'))
        self.assertFalse(guard.protected('198.51.100.50'))


class TestScenario180And181ExpiryAndEscalation(unittest.TestCase):
    """§180, §181, §188."""

    def test_every_block_expires_and_the_ladder_is_capped(self):
        durations = [decide(offence_count=count).block_ttl_seconds for count in range(8)]
        self.assertTrue(all(value > 0 for value in durations))
        self.assertEqual(durations, sorted(durations))
        self.assertEqual(max(durations), min(43_200, max(durations)))

    def test_the_temporary_block_table_is_per_process_and_deleted_on_close(self):
        """§183. A restart cannot inherit a block, because it cannot inherit the table."""
        source = (__import__('pathlib').Path(__file__).resolve().parents[1] /
                  'eye_for_an_eye' / 'security' / 'temporary_blocks.py'
                  ).read_text(encoding='utf-8')
        self.assertIn("'e4e_decision_' + uuid.uuid4().hex", source)
        self.assertIn('flags timeout', source)
        self.assertIn('timeout {seconds}s', source)
        self.assertIn('delete table inet {self.table}', source)


class TestScenario182RiskDecays(unittest.TestCase):
    """§47, §182, §125. Old behaviour cannot produce permanent suspicion."""

    def test_risk_falls_by_half_over_a_half_life(self):
        self.assertAlmostEqual(decay(0.8, 600, 600), 0.4)
        self.assertAlmostEqual(decay(0.8, 1200, 600), 0.2)

    def test_risk_approaches_zero_over_a_long_quiet_period(self):
        self.assertLess(decay(1.0, 86_400, 600), 1e-40)

    def test_decay_never_increases_a_score(self):
        for elapsed in (0, 1, 60, 3600, 86_400):
            with self.subTest(elapsed=elapsed):
                self.assertLessEqual(decay(0.9, elapsed, 900), 0.9)

    def test_an_offence_count_decays_out_of_the_window(self):
        from eye_for_an_eye.config import Config
        self.assertLessEqual(Config().enforcement.offense_decay_seconds, 86_400)


# --- §174-§175: the data gates ---------------------------------------------

class TestScenario174ModelCollapse(unittest.TestCase):
    """§74, §174. A dataset made of the system's own output.

    The strongest protection here is that the row cannot be constructed: a
    dataset sample whose label came from a decision is refused at the schema,
    before any quality gate is consulted. The gate is the second line.
    """

    def test_a_pseudo_labelled_row_cannot_even_be_built(self):
        from dataset import schema
        for name in ('shadow_decision', 'blocked', 'model_score', 'math_score',
                     'self_labelled', 'previous_model', 'automatically_blocked'):
            with self.subTest(label_source=name):
                self.assertIn(name, schema.FORBIDDEN_LABEL_SOURCES)
                self.assertNotIn(name, schema.ALL_LABEL_SOURCES)

    def test_unreviewed_shadow_rows_carry_no_supervised_label(self):
        from dataset import schema
        self.assertIn(schema.SHADOW_UNLABELED, schema.SHADOW_TYPES)
        self.assertIn('never enters a supervised split',
                      schema.SOURCE_ROLES[schema.SHADOW_UNLABELED])

    def test_a_dataset_dominated_by_one_group_fails_the_quality_gate(self):
        """One source filling a candidate dataset is how a model gets steered."""
        from dataset.candidate import quality_gate

        class Report:
            warnings = ()

        class Row:
            def __init__(self, label, group):
                self.label = label
                self.source_type = 'LAB'
                self.provenance = {'source_group': group}
                self.source_group = group
                self.capture_group = None

        from dataset import schema
        rows = [Row(schema.BENIGN, 'dominant') for _ in range(700)]
        rows += [Row(schema.MALICIOUS, f'other-{index}') for index in range(300)]
        status, reasons = quality_gate(rows, Report())
        self.assertEqual(status, 'FAIL')
        self.assertTrue(any('one group is' in reason for reason in reasons))

    def test_new_observed_rows_are_a_bounded_share_of_a_candidate(self):
        from dataset.candidate import IntakeLimits
        limits = IntakeLimits()
        self.assertLessEqual(limits.max_new_fraction, 0.25)
        self.assertLessEqual(limits.max_single_source_fraction, 0.10)


class TestScenario175Leakage(unittest.TestCase):
    """§70, §175. A feature that encodes the answer."""

    def test_the_final_action_can_never_be_a_model_feature(self):
        from dataset import schema
        for name in ('blocked', 'block_status', 'final_risk', 'math_score', 'ml_score',
                     'previous_risk', 'label'):
            with self.subTest(feature=name):
                self.assertIn(name, schema.NEVER_MODEL_INPUT)
                self.assertNotIn(name, schema.MODEL_FEATURES)

    def test_identity_can_never_be_a_model_feature(self):
        from dataset import schema
        for name in ('src_ip', 'dst_ip', 'asn', 'country', 'source_group'):
            with self.subTest(feature=name):
                self.assertIn(name, schema.NEVER_MODEL_INPUT)

    def test_the_training_contract_and_the_runtime_tensor_are_the_same_list(self):
        """§69. One pipeline, so training and runtime cannot drift apart."""
        from eye_for_an_eye.decision.features import INPUT_ORDER
        from dataset import schema
        self.assertEqual(len(schema.MODEL_FEATURES),
                         len(INPUT_ORDER) - len(schema.EXCLUDED_FROM_MODEL))
        self.assertTrue(set(schema.MODEL_FEATURES).issubset(set(INPUT_ORDER)))


class TestTheReportIsHonestEndToEnd(unittest.TestCase):
    """§155. What `science report` would print, checked as a whole."""

    def test_a_good_evaluation_passes_and_says_what_it_measured(self):
        rows = population(benign=5000, malicious=500,
                          blocked_benign=1, blocked_malicious=480)
        body = ev.report(rows, resamples=100)
        self.assertEqual(body['release_gate']['verdict'], 'PASS')
        self.assertEqual(body['usefulness'], ev.USEFUL)
        self.assertIsNotNone(body['bootstrap']['block_precision'])
        self.assertTrue(body['prevalence_sweep'])

    def test_a_high_false_block_rate_fails_the_gate(self):
        rows = population(benign=5000, malicious=500,
                          blocked_benign=50, blocked_malicious=480)
        body = ev.report(rows, resamples=50)
        self.assertEqual(body['release_gate']['verdict'], 'FAIL')
        self.assertTrue(any('false blocks per' in reason
                            for reason in body['release_gate']['reasons']))

    def test_the_thresholds_are_labelled_as_policy_rather_than_measurement(self):
        body = ev.release_gate(ev.evaluate(population(benign=10, malicious=1)))
        self.assertIn('none of these values is measured', body['thresholds']['note'])


if __name__ == '__main__':
    unittest.main()
