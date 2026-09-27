"""P9 candidate shadow inference.

The question every test here asks in a different way: can a candidate model
affect anything? It must not be able to. It scores, it is counted, and a person
reads the result.
"""
import json
import unittest
import tempfile
from pathlib import Path

from eye_for_an_eye.decision import candidate as candidate_module
from eye_for_an_eye.decision.candidate import (CandidateModel, ComparisonLedger,
                                               LARGE_GAP, classify, render, write_report)


class TestClassify(unittest.TestCase):
    def test_two_quiet_agreeing_models_agree(self):
        self.assertEqual(classify(0.10, 0.12, 'OBSERVE', 'OBSERVE').kind, 'agree')

    def test_a_candidate_that_would_block_where_the_active_allows_is_named(self):
        result = classify(0.20, 0.95, 'WATCH', 'TEMP_BLOCK')
        self.assertEqual(result.kind, 'candidate_blocks_active_allows')

    def test_the_reverse_case_is_named_differently(self):
        result = classify(0.95, 0.20, 'TEMP_BLOCK', 'OBSERVE')
        self.assertEqual(result.kind, 'active_blocks_candidate_allows')

    def test_a_candidate_that_rate_limits_where_the_active_does_not_is_named(self):
        self.assertEqual(classify(0.4, 0.75, 'WATCH', 'RATE_LIMIT').kind,
                         'candidate_acts_active_does_not')

    def test_an_active_that_acts_where_the_candidate_does_not_is_named(self):
        self.assertEqual(classify(0.75, 0.4, 'RATE_LIMIT', 'WATCH').kind,
                         'active_acts_candidate_does_not')

    def test_the_same_action_with_very_different_scores_is_still_worth_seeing(self):
        result = classify(0.10, 0.10 + LARGE_GAP, 'WATCH', 'WATCH')
        self.assertEqual(result.kind, 'large_score_gap')

    def test_a_differing_non_acting_decision_is_named(self):
        self.assertEqual(classify(0.3, 0.35, 'OBSERVE', 'WATCH').kind, 'action_differs')

    def test_a_missing_score_does_not_invent_a_gap(self):
        self.assertEqual(classify(None, 0.9, 'OBSERVE', 'OBSERVE').gap, 0.0)
        self.assertEqual(classify(0.9, None, 'OBSERVE', 'OBSERVE').gap, 0.0)


class TestLedger(unittest.TestCase):
    def ledger(self):
        return ComparisonLedger(active_version='risk-logreg-v1',
                                candidate_version='risk-logreg-v2')

    def test_an_empty_ledger_reports_no_agreement_rather_than_a_perfect_score(self):
        data = self.ledger().explain()
        self.assertIsNone(data['agreement'])
        self.assertIsNone(data['mean_score_gap'])
        self.assertEqual(data['feature_vectors'], 0)

    def test_agreement_is_counted(self):
        ledger = self.ledger()
        for _ in range(8):
            ledger.observe(classify(0.1, 0.1, 'OBSERVE', 'OBSERVE'))
        for _ in range(2):
            ledger.observe(classify(0.1, 0.9, 'OBSERVE', 'TEMP_BLOCK'))
        self.assertAlmostEqual(ledger.agreement, 0.8)
        self.assertEqual(ledger.new_blocks, 2)

    def test_only_disagreements_are_kept_as_examples(self):
        ledger = self.ledger()
        for _ in range(50):
            ledger.observe(classify(0.1, 0.1, 'OBSERVE', 'OBSERVE'))
        ledger.observe(classify(0.1, 0.9, 'OBSERVE', 'TEMP_BLOCK'))
        self.assertEqual(len(ledger.examples), 1)

    def test_the_example_list_is_bounded(self):
        ledger = ComparisonLedger(max_examples=5)
        for index in range(200):
            ledger.observe(classify(0.1, 0.9, 'OBSERVE', 'WATCH'))
        self.assertLessEqual(len(ledger.examples), 5)
        self.assertEqual(ledger.feature_vectors, 200)

    def test_a_new_block_displaces_a_less_important_example_when_full(self):
        ledger = ComparisonLedger(max_examples=3)
        for _ in range(3):
            ledger.observe(classify(0.1, 0.5, 'OBSERVE', 'WATCH'))
        ledger.observe(classify(0.1, 0.95, 'OBSERVE', 'TEMP_BLOCK'))
        kinds = [item.kind for item in ledger.examples]
        self.assertIn('candidate_blocks_active_allows', kinds)
        self.assertEqual(len(ledger.examples), 3)

    def test_the_source_set_is_bounded(self):
        ledger = ComparisonLedger(max_sources=10)
        for index in range(100):
            ledger.observe(classify(0.1, 0.1, 'OBSERVE', 'OBSERVE'),
                           source_key=f'src-{index}')
        self.assertLessEqual(len(ledger.sources), 10)

    def test_the_ledger_says_what_the_candidate_did_not_do(self):
        data = self.ledger().explain()
        self.assertIn('never reached the firewall', data['authority'])
        self.assertIn('shadow only', data['authority'])

    def test_the_ledger_holds_no_address_or_payload(self):
        ledger = self.ledger()
        ledger.observe(classify(0.1, 0.9, 'OBSERVE', 'TEMP_BLOCK'), source_key='src-abcdef')
        text = json.dumps(ledger.explain())
        self.assertNotIn('src_ip', text)
        self.assertNotIn('payload', text)
        for example in ledger.explain()['examples']:
            self.assertEqual(set(example) & {'source', 'src_ip', 'source_key'}, set())


class TestCandidateModel(unittest.TestCase):
    def test_a_candidate_is_off_unless_it_is_configured(self):
        self.assertFalse(CandidateModel().enabled)
        self.assertFalse(CandidateModel(enabled=True).enabled)
        self.assertTrue(CandidateModel(enabled=True, model_path='x.onnx').enabled)

    def test_an_unloaded_candidate_scores_nothing(self):
        model = CandidateModel(enabled=True, model_path='x.onnx')
        self.assertFalse(model.loaded)
        self.assertIsNone(model.score([0.0] * 36))
        self.assertFalse(model.should_score())

    def test_repeated_failures_switch_the_candidate_off_and_nothing_else(self):
        class Broken:
            def predict(self, tensor):
                raise RuntimeError('candidate exploded')

        model = CandidateModel(enabled=True, model_path='x.onnx', max_failures=3)
        model.model = Broken()
        for _ in range(3):
            self.assertIsNone(model.score([0.0] * 36))
        self.assertFalse(model.loaded)
        self.assertIn('switched off', model.disabled_reason)

    def test_an_unhealthy_result_counts_as_a_failure(self):
        class Unhealthy:
            def predict(self, tensor):
                class Result:
                    status = 'unavailable'
                return Result()

        model = CandidateModel(enabled=True, model_path='x.onnx', max_failures=2)
        model.model = Unhealthy()
        model.score([0.0] * 36)
        model.score([0.0] * 36)
        self.assertFalse(model.loaded)

    def test_a_load_failure_disables_only_the_candidate(self):
        def explode(model_path, manifest_path):
            raise OSError('no such file')

        model = CandidateModel(enabled=True, model_path='missing.onnx')
        self.assertFalse(model.load(explode))
        self.assertFalse(model.enabled)
        self.assertIn('could not be loaded', model.disabled_reason)

    def test_sampling_lets_an_operator_reduce_candidate_cost(self):
        class Fine:
            def predict(self, tensor):
                class Result:
                    status = 'healthy'
                    risk_score = 0.5
                return Result()

        model = CandidateModel(enabled=True, model_path='x.onnx', sample_every=4)
        model.model = Fine()
        scored = sum(1 for _ in range(40) if model.should_score())
        self.assertEqual(scored, 10)

    def test_a_candidate_uses_its_own_reference_distribution(self):
        model = CandidateModel(enabled=True, model_path='x.onnx',
                               distribution_path='candidate-distribution.json')
        self.assertEqual(model.distribution_path, 'candidate-distribution.json')
        # A candidate has its own slot, separate from the active model's baseline,
        # so the two can never be confused for one another.
        self.assertNotEqual(model.distribution_path, model.manifest_path)


class TestNoEnforcementPath(unittest.TestCase):
    """The structural argument: there is nothing here for the policy to call."""

    def source(self):
        return Path(candidate_module.__file__).read_text(encoding='utf-8')

    def test_the_module_never_imports_the_enforcer_or_the_policy(self):
        import ast
        tree = ast.parse(self.source())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for forbidden in ('firewall', 'enforcement', 'policy', 'subprocess', 'socket'):
            self.assertFalse(any(forbidden in name for name in imported), forbidden)

    def test_no_function_here_returns_an_action_the_policy_could_use(self):
        model = CandidateModel(enabled=True, model_path='x.onnx')
        for name in ('score', 'should_score', 'load', 'disable', 'close'):
            self.assertTrue(hasattr(model, name))
        self.assertFalse(hasattr(model, 'enforce'))
        self.assertFalse(hasattr(model, 'block'))
        self.assertFalse(hasattr(model, 'decide'))

    def test_the_word_canary_here_means_parallel_inference(self):
        text = self.source()
        self.assertIn('parallel inference', text)
        self.assertIn('never parallel enforcement', text)


class TestReport(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def ledger(self):
        ledger = ComparisonLedger(active_version='risk-logreg-v1',
                                  candidate_version='risk-logreg-v2')
        for _ in range(90):
            ledger.observe(classify(0.1, 0.11, 'OBSERVE', 'OBSERVE'))
        for _ in range(10):
            ledger.observe(classify(0.2, 0.95, 'WATCH', 'TEMP_BLOCK'))
        return ledger

    def test_the_report_file_records_the_expensive_disagreement(self):
        target = Path(self.directory.name) / 'shadow.json'
        write_report(self.ledger(), target, duration_hours=48.0,
                     recommendation='KEEP_ACTIVE', reasons=('ten new blocks',))
        document = json.loads(target.read_text(encoding='utf-8'))
        self.assertEqual(document['candidate_blocks_active_allows'], 10)
        self.assertEqual(document['recommendation'], 'KEEP_ACTIVE')
        self.assertEqual(document['duration_hours'], 48.0)

    def test_a_report_without_a_recommendation_defaults_to_needing_more_data(self):
        target = Path(self.directory.name) / 'shadow2.json'
        summary = write_report(ComparisonLedger(), target)
        self.assertEqual(summary['recommendation'], 'NEED_MORE_DATA')

    def test_the_text_report_uses_the_documented_layout(self):
        text = render(self.ledger(), duration_hours=48.0, recommendation='KEEP_ACTIVE')
        for heading in ('CANDIDATE SHADOW REPORT', 'Active:', 'Candidate:', 'Duration:',
                        'FeatureVectors:', 'Agreement:', 'Candidate would-block:',
                        'Active would-block:', 'Recommendation:'):
            self.assertIn(heading, text)

    def test_the_text_report_says_the_candidate_changed_nothing(self):
        self.assertIn('never changed an action', render(ComparisonLedger()))

    def test_an_empty_report_does_not_claim_perfect_agreement(self):
        self.assertIn('not enough data', render(ComparisonLedger()))


if __name__ == '__main__':
    unittest.main()
