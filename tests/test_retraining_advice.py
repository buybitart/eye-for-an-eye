"""P9 retraining advice.

The point of these tests is what the module refuses to do. It must never start a
job, never treat drift as guilt, and never let a busy machine or thin evidence be
overruled by an impressive-looking signal.
"""
import inspect
import unittest
from pathlib import Path

from eye_for_an_eye.decision import retraining
from eye_for_an_eye.decision.retraining import (COLLECT_MORE, CONSIDER_RETRAINING, NO_ACTION,
                                                RECOMMENDATIONS, RetrainingAdvice, RetrainingError,
                                                RetrainingPolicy, RetrainingSignals, SYSTEM_BUSY,
                                                WAIT_COOLDOWN, evaluate, system_signals)


def ready(**overrides):
    """Signals that satisfy every floor, so a test can remove one at a time."""
    values = {'new_benign_labels': 150, 'new_malicious_labels': 120,
              'new_label_sources': 40, 'days_since_training': 30.0,
              'drift_status': 'STABLE', 'ood_rate': 0.05, 'model_health': 'HEALTHY',
              'load_per_core': 0.10, 'free_disk_mib': 20_000.0}
    values.update(overrides)
    return RetrainingSignals(**values)


class TestItNeverTrains(unittest.TestCase):
    def test_this_module_never_turns_auto_train_on(self):
        """Renamed from `test_there_is_no_auto_train_setting`, which was a lie.

        The setting does exist (`LearningConfig.auto_train`); it is reserved and
        unread. What this test actually checks -- and all it ever checked -- is
        that nothing in this module assigns it.
        """
        text = Path(retraining.__file__).read_text(encoding='utf-8')
        self.assertNotIn('auto_train = True', text)
        self.assertNotIn("auto_train=True", text)

    def test_no_function_here_starts_a_job(self):
        """Checked against the parsed module, not against its prose.

        A substring search would trip over the word "retraining" in a comment.
        What matters is what the code imports and calls.
        """
        import ast
        tree = ast.parse(Path(retraining.__file__).read_text(encoding='utf-8'))
        imported, called = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split('.')[0])
            elif isinstance(node, ast.Call):
                target = node.func
                called.add(target.attr if isinstance(target, ast.Attribute)
                           else getattr(target, 'id', ''))
        for forbidden in ('subprocess', 'multiprocessing', 'threading', 'socket',
                          'urllib', 'http', 'requests'):
            self.assertNotIn(forbidden, imported, forbidden)
        for forbidden in ('system', 'Popen', 'run', 'spawn', 'fork', 'train', 'fit',
                          'promote', 'register_candidate', 'write', 'open'):
            self.assertNotIn(forbidden, called, forbidden)

    def test_advice_reports_that_it_would_not_train(self):
        for signals in (ready(), ready(new_benign_labels=0), ready(load_per_core=8.0)):
            self.assertFalse(evaluate(signals).would_train)

    def test_the_strongest_possible_recommendation_is_still_only_advice(self):
        advice = evaluate(ready())
        self.assertEqual(advice.recommendation, CONSIDER_RETRAINING)
        self.assertIn('separate steps a person runs', ' '.join(advice.reasons))
        self.assertIn('no automatic training', advice.explain()['authority'])

    def test_the_next_step_is_a_command_for_a_person_to_type(self):
        advice = evaluate(ready())
        self.assertTrue(advice.next_step.startswith('eye-for-an-eye '))
        self.assertNotIn('promote', advice.next_step)

    def test_a_recommendation_that_is_not_consider_has_no_next_step(self):
        self.assertEqual(evaluate(ready(new_benign_labels=0)).next_step, '')


class TestSystemFirst(unittest.TestCase):
    def test_a_busy_machine_stops_everything(self):
        advice = evaluate(ready(load_per_core=4.0))
        self.assertEqual(advice.recommendation, SYSTEM_BUSY)
        self.assertIn('defending comes first', ' '.join(advice.reasons))

    def test_a_full_disk_stops_everything(self):
        advice = evaluate(ready(free_disk_mib=100.0))
        self.assertEqual(advice.recommendation, SYSTEM_BUSY)
        self.assertTrue(any('MiB free' in blocker for blocker in advice.blockers))

    def test_plenty_of_new_data_does_not_override_a_busy_machine(self):
        advice = evaluate(ready(new_benign_labels=10_000, new_malicious_labels=10_000,
                                load_per_core=8.0))
        self.assertEqual(advice.recommendation, SYSTEM_BUSY)

    def test_an_unknown_load_is_not_treated_as_idle_or_as_busy(self):
        advice = evaluate(ready(load_per_core=None, free_disk_mib=None))
        self.assertEqual(advice.recommendation, CONSIDER_RETRAINING)
        self.assertIsNone(advice.signals['load_per_core'])


class TestCooldown(unittest.TestCase):
    def test_a_recent_training_run_holds_the_next_one_back(self):
        advice = evaluate(ready(days_since_training=3.0))
        self.assertEqual(advice.recommendation, WAIT_COOLDOWN)
        self.assertTrue(any('cooldown' in reason for reason in advice.reasons))

    def test_the_cooldown_explains_itself(self):
        advice = evaluate(ready(days_since_training=1.0))
        self.assertTrue(any('reproduces its mistakes' in reason for reason in advice.reasons))

    def test_an_unknown_last_training_date_does_not_block(self):
        advice = evaluate(ready(days_since_training=None))
        self.assertEqual(advice.recommendation, CONSIDER_RETRAINING)


class TestEvidenceFloors(unittest.TestCase):
    def test_too_few_labels_means_collect_more(self):
        advice = evaluate(ready(new_benign_labels=5, new_malicious_labels=5))
        self.assertEqual(advice.recommendation, COLLECT_MORE)
        self.assertTrue(any('new reviewed labels' in blocker for blocker in advice.blockers))

    def test_labels_of_only_one_kind_are_not_enough(self):
        advice = evaluate(ready(new_malicious_labels=0))
        self.assertEqual(advice.recommendation, COLLECT_MORE)
        self.assertTrue(any('malicious-automation labels' in b for b in advice.blockers))

    def test_labels_from_too_few_sources_are_not_enough(self):
        advice = evaluate(ready(new_label_sources=2))
        self.assertEqual(advice.recommendation, COLLECT_MORE)
        self.assertTrue(any('sources' in blocker for blocker in advice.blockers))

    def test_uncertain_answers_do_not_count_towards_the_floors(self):
        advice = evaluate(RetrainingSignals(new_benign_labels=10, new_malicious_labels=10,
                                            new_uncertain_labels=5000, new_label_sources=40,
                                            days_since_training=100.0))
        self.assertEqual(advice.recommendation, COLLECT_MORE)
        self.assertTrue(any('excluded from supervised training' in r for r in advice.reasons))


class TestDriftIsNotGuilt(unittest.TestCase):
    def test_drift_alone_never_recommends_retraining(self):
        advice = evaluate(ready(new_benign_labels=0, new_malicious_labels=0,
                                drift_status='DRIFTED'))
        self.assertEqual(advice.recommendation, COLLECT_MORE)

    def test_drift_is_described_as_a_fact_about_the_model(self):
        advice = evaluate(ready(drift_status='DRIFTED'))
        text = ' '.join(advice.reasons)
        self.assertIn('the model knows less', text)
        for word in ('attack', 'attacker', 'malicious', 'hostile', 'suspicious'):
            self.assertNotIn(word, text.lower(), word)

    def test_a_high_ood_rate_is_described_as_unfamiliar_not_hostile(self):
        advice = evaluate(ready(ood_rate=0.55))
        text = ' '.join(advice.reasons)
        self.assertIn('unfamiliar, not hostile', text)

    def test_degraded_health_says_the_mathematical_engine_still_runs(self):
        advice = evaluate(ready(model_health='UNRELIABLE'))
        self.assertTrue(any('mathematical engine' in reason for reason in advice.reasons))

    def test_a_missing_drift_reading_is_said_out_loud(self):
        advice = evaluate(ready(drift_status=''))
        self.assertTrue(any('no drift reading' in reason for reason in advice.reasons))

    def test_nothing_in_the_signals_counts_blocks(self):
        fields = set(RetrainingSignals.__dataclass_fields__)
        for forbidden in ('blocks', 'blocked', 'block_count', 'enforced', 'risk_score'):
            self.assertNotIn(forbidden, fields)


class TestPolicyValidation(unittest.TestCase):
    def test_impossible_policies_are_refused(self):
        for kwargs in ({'min_new_labels': 0}, {'cooldown_days': -1},
                       {'max_load_per_core': 0}, {'min_new_labels': 10, 'min_new_per_label': 50}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(RetrainingError):
                    RetrainingPolicy(**kwargs)

    def test_signals_must_be_the_right_type(self):
        with self.assertRaises(RetrainingError):
            evaluate({'new_benign_labels': 500})

    def test_every_recommendation_is_one_of_the_documented_five(self):
        self.assertEqual(set(RECOMMENDATIONS),
                         {NO_ACTION, COLLECT_MORE, CONSIDER_RETRAINING, WAIT_COOLDOWN, SYSTEM_BUSY})
        for signals in (ready(), ready(load_per_core=9.0), ready(days_since_training=1.0),
                        ready(new_benign_labels=0)):
            self.assertIn(evaluate(signals).recommendation, RECOMMENDATIONS)


class TestPurity(unittest.TestCase):
    def test_evaluate_takes_only_what_it_is_given(self):
        signature = inspect.signature(evaluate)
        self.assertEqual(list(signature.parameters), ['signals', 'policy'])

    def test_system_signals_never_raises(self):
        values = system_signals()
        self.assertEqual(set(values), {'load_per_core', 'free_disk_mib'})

    def test_advice_serialises_without_losing_its_reasons(self):
        advice = evaluate(ready(drift_status='WARNING'))
        document = advice.explain()
        self.assertEqual(document['recommendation'], advice.recommendation)
        self.assertEqual(len(document['reasons']), len(advice.reasons))
        self.assertEqual(document['advice_version'], 1)

    def test_an_advice_object_is_immutable(self):
        advice = RetrainingAdvice(NO_ACTION)
        with self.assertRaises(Exception):
            advice.recommendation = CONSIDER_RETRAINING


if __name__ == '__main__':
    unittest.main()
