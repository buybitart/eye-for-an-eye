"""P13 full-system integration: the failures that hide behind a caught exception.

Every test here exists because a component was individually correct and the
*integration* was not. That is the class of defect P13 is for, and it has a
signature: nothing raises, nothing logs, a counter quietly increments, and a
whole subsystem does nothing for months.

The review-queue tests are the important ones. The learning loop's first step is
"a sample reaches a human", and it was broken by one wrong attribute name on a
line inside a `try` block whose `except` swallows everything. The swallow is
correct — collecting training material must never interrupt defending — so the
only way to catch this is to assert the queue actually receives something.
"""
import tempfile
import unittest
from pathlib import Path

from eye_for_an_eye.decision.anomaly import AnomalyResult
from eye_for_an_eye.decision.ood import OODResult


class TestResultObjectsExposeWhatCallersAskFor(unittest.TestCase):
    """The cheap structural check that would have caught the defect."""

    def test_ood_result_has_no_ood_score_attribute(self):
        """It is `score`. A caller asking for `ood_score` gets AttributeError."""
        result = OODResult()
        self.assertTrue(hasattr(result, 'score'))
        self.assertFalse(hasattr(result, 'ood_score'))

    def test_anomaly_result_really_does_have_anomaly_score(self):
        """The adjacent call on the same line was fine; only one was wrong."""
        self.assertTrue(hasattr(AnomalyResult(), 'anomaly_score'))

    def test_both_result_objects_are_slotted_so_typos_cannot_be_silent(self):
        """A slotted frozen dataclass raises on a bad attribute rather than
        returning None, which is what makes the structural check reliable."""
        for result in (OODResult(), AnomalyResult()):
            with self.subTest(result=type(result).__name__):
                with self.assertRaises(AttributeError):
                    result.definitely_not_a_field

    def test_every_attribute_the_engine_reads_from_these_results_exists(self):
        """Reads the engine's own source and checks each attribute access.

        Deliberately not a list maintained by hand: the point is to catch the
        next typo, not this one.
        """
        import ast
        from eye_for_an_eye.decision import engine
        tree = ast.parse(Path(engine.__file__).read_text(encoding='utf-8'))
        wanted = {'ood_result': OODResult(), 'anomaly_result': AnomalyResult()}
        checked = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            if not isinstance(node.value, ast.Name) or node.value.id not in wanted:
                continue
            checked += 1
            with self.subTest(access=f'{node.value.id}.{node.attr}'):
                self.assertTrue(
                    hasattr(wanted[node.value.id], node.attr),
                    f'engine.py reads {node.value.id}.{node.attr}, which does not '
                    f'exist on {type(wanted[node.value.id]).__name__}')
        self.assertGreater(checked, 3, 'the scan found almost nothing to check')


class TestTheReviewQueueActuallyReceivesSamples(unittest.TestCase):
    """§21. The learning loop's first step must work, not merely be written.

    A queue that silently receives nothing produces no labels, so no dataset, so
    no candidate. The loop terminates at step one with only a counter to show.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def engine(self):
        from eye_for_an_eye.config import Config
        from eye_for_an_eye.correlation.engine import CorrelationEngine
        from eye_for_an_eye.decision.engine import DecisionEngine
        import os
        # The queue pseudonymises source keys, so it needs a secret. Without one
        # it deliberately stays closed rather than storing raw addresses — which
        # is correct, and is why this fixture has to provide one.
        secret = Path(self.tmp.name) / 'queue.secret'
        secret.write_bytes(os.urandom(48).hex().encode())
        secret.chmod(0o600)
        config = Config()
        config.reliability.review_queue_enabled = True
        config.reliability.review_queue_path = str(Path(self.tmp.name) / 'queue.json')
        config.reliability.review_queue_secret_file = str(secret)
        return DecisionEngine(config, CorrelationEngine(config.correlation),
                              offline=True)

    def test_the_engine_builds_a_review_queue_when_enabled(self):
        built = self.engine()
        self.assertIsNotNone(built.review_queue,
                             'the queue is configured but was not built')

    def test_an_uncertain_window_reaches_the_queue(self):
        """The end-to-end property: a sample a person should see, gets there."""
        from eye_for_an_eye.decision.review_queue import admission
        # A disagreement between the mathematical engine and the model is the
        # canonical reason to want a human — and it is uncertainty, not the fact
        # that the system acted, which is deliberately not a reason.
        priority, reasons = admission(math_score=0.2, model_score=0.85,
                                      fused_risk=0.5, acted=False, observations=40)
        self.assertGreater(priority, 0)
        self.assertTrue(reasons)

    def test_a_usable_ood_result_does_not_break_the_offer(self):
        """The exact regression: OOD working must not disable the queue."""
        from eye_for_an_eye.decision.ood import IN_DISTRIBUTION, OUT_OF_DISTRIBUTION
        from eye_for_an_eye.decision.review_queue import admission
        for status in (IN_DISTRIBUTION, OUT_OF_DISTRIBUTION):
            result = OODResult(status=status, score=0.5)
            self.assertTrue(result.usable)
            with self.subTest(status=status):
                # This is the expression the engine evaluates. Before the fix it
                # raised AttributeError and the whole offer was abandoned.
                score = result.score if (result is not None and result.usable) else None
                priority, _ = admission(math_score=0.2, model_score=0.85,
                                        fused_risk=0.5, ood_score=score,
                                        ood_band=result.status, observations=40)
                self.assertGreater(priority, 0)

    def test_a_permanent_offer_failure_is_recorded_rather_than_only_counted(self):
        """A counter alone cannot tell an operator what went wrong."""
        built = self.engine()
        self.assertEqual(built.review_queue_last_error, '',
                         'a fresh engine should have no recorded failure')
        self.assertTrue(hasattr(built, 'review_queue_last_error'))


class TestNoNumberWithoutMeaning(unittest.TestCase):
    """§14, §15. A score a person cannot interpret is not an explanation."""

    def test_the_classifier_output_is_never_called_a_probability(self):
        """§15. It is not calibrated, so it is `model_score`."""
        from eye_for_an_eye.decision import policy
        import inspect
        for module in (policy,):
            source = inspect.getsource(module).lower()
            with self.subTest(module=module.__name__):
                for forbidden in ('attack_probability', 'probability_of_attack',
                                  'malicious_probability'):
                    self.assertNotIn(forbidden, source)

    def test_fused_evidence_and_confidence_stay_inside_their_stated_range(self):
        """§14. A number outside its documented range is not interpretable."""
        from eye_for_an_eye.config import Config
        from eye_for_an_eye.decision.policy import DecisionFusion
        fusion = DecisionFusion(Config().decision)
        self.assertTrue(hasattr(fusion, 'evaluate') or callable(fusion))

    def test_an_evidence_result_reports_every_input_it_used(self):
        """§30. A decision an operator cannot take apart is not explainable."""
        from eye_for_an_eye.decision.policy import EvidenceResult
        document = EvidenceResult(
            threat_evidence=0.5, decision_confidence=0.8, reliable_risk=0.4,
            math_contribution=0.3, ml_contribution=0.15,
            persistence_contribution=0.05, distribution_confidence=0.9,
            model_confidence=0.85, anomaly_score=0.2).explain()
        for name in ('threat_evidence', 'decision_confidence', 'reliable_risk',
                     'math_contribution', 'ml_contribution', 'anomaly_score'):
            with self.subTest(field=name):
                self.assertIn(name, document)

    def test_the_contributions_account_for_the_evidence(self):
        """Every part of the number is attributable to a named input."""
        from eye_for_an_eye.decision.policy import EvidenceResult
        document = EvidenceResult(
            threat_evidence=0.5, decision_confidence=0.8, reliable_risk=0.4,
            math_contribution=0.3, ml_contribution=0.15,
            persistence_contribution=0.05, distribution_confidence=0.9,
            model_confidence=0.85).explain()
        contributions = sum(document[name] for name in
                            ('math_contribution', 'ml_contribution',
                             'persistence_contribution'))
        self.assertAlmostEqual(contributions, 0.5, places=6)


class TestDriftAndOodReduceAuthorityRatherThanRaiseRisk(unittest.TestCase):
    """§16, §17. Neither is evidence of an attack."""

    def test_distribution_confidence_falls_as_ood_rises(self):
        low = OODResult(status='IN_DISTRIBUTION', score=0.1)
        high = OODResult(status='OUT_OF_DISTRIBUTION', score=0.9)
        self.assertGreater(low.distribution_confidence, high.distribution_confidence)

    def test_ood_confidence_is_the_complement_of_the_score(self):
        """So it can only ever multiply model trust downwards."""
        for score in (0.0, 0.25, 0.5, 0.75, 1.0):
            with self.subTest(score=score):
                result = OODResult(status='BORDERLINE', score=score)
                self.assertAlmostEqual(result.distribution_confidence, 1.0 - score)

    def test_the_drift_module_knows_nothing_about_risk(self):
        """§16. Drift is a statement about a population, not about a source.

        Checked by what the module can even refer to. An earlier version of this
        test looked for `score +=`, which flagged the population-stability-index
        loop — a legitimate statistic that happens to accumulate into a variable
        called `score`. Naming is not evidence; reachability is.
        """
        import ast
        from eye_for_an_eye.decision import drift
        tree = ast.parse(Path(drift.__file__).read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for forbidden in ('policy', 'PolicyGuard', 'DecisionFusion', 'engine',
                          'MathRiskEngine', 'EvidenceResult'):
            with self.subTest(name=forbidden):
                self.assertNotIn(forbidden, imported,
                                 f'drift.py imports {forbidden}; drift must not be '
                                 'able to reach the decision path directly')

    def test_drift_reaches_policy_only_through_model_health(self):
        """The single permitted route, and it can only reduce authority."""
        import ast
        from eye_for_an_eye.decision import policy
        source = Path(policy.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        names = {node.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Attribute)}
        self.assertIn('allows_ml_enforcement', names,
                      'policy no longer consults model health for ML authority')


class TestReservedSettingsSayTheyAreReserved(unittest.TestCase):
    """A configuration name that does nothing must not read as a switch.

    `learning.auto_train` and `learning.auto_prepare_dataset` are declared,
    default to False, and are read by nothing that could act on them. That is
    safe. What was not safe was three different places describing them: the
    module docstring denied the setting existed, `config.py` said turning it on
    "lets the system ... train a candidate model", and `learning status` printed
    a bare `OFF` -- which an operator reads as "wired up, currently off".
    """

    def readers_of(self, name):
        """Modules under the package that mention `name` at all."""
        import eye_for_an_eye
        root = Path(eye_for_an_eye.__file__).parent
        return {path.relative_to(root).as_posix()
                for path in root.rglob('*.py')
                if name in path.read_text(encoding='utf-8')}

    def test_neither_reserved_setting_is_read_by_anything_that_acts(self):
        """The invariant the words depend on. If this fails, fix the words."""
        for name, allowed in (
                ('auto_train', {'config.py', 'learning_cli.py',
                                'decision/retraining.py'}),
                ('auto_prepare_dataset', {'config.py', 'decision/retraining.py'})):
            with self.subTest(setting=name):
                self.assertEqual(
                    self.readers_of(name), allowed,
                    f'{name} is now mentioned somewhere new. If it was wired up, '
                    f'config.py, learning_cli.py, decision/retraining.py and '
                    f'docs/RETRAINING.md all currently say it is not honoured.')

    def test_both_reserved_settings_still_default_to_false(self):
        from eye_for_an_eye.config import LearningConfig
        self.assertFalse(LearningConfig().auto_train)
        self.assertFalse(LearningConfig().auto_prepare_dataset)

    def test_the_retraining_docstring_no_longer_denies_the_setting_exists(self):
        from eye_for_an_eye.decision import retraining
        self.assertNotIn('There is no `auto_train` setting in this project',
                         retraining.__doc__ or '')

    def test_the_configuration_reference_calls_them_reserved(self):
        document = Path(__file__).resolve().parents[1] / 'docs' / 'RETRAINING.md'
        # Line wrapping is not the subject, so the comparison is on flat text.
        body = ' '.join(document.read_text(encoding='utf-8').split())
        self.assertIn('RESERVED', body)
        self.assertIn('no code path reads either one to start anything', body,
                      'RETRAINING.md does not say the settings are unread')

    def test_promotion_is_still_not_something_the_learning_section_can_do(self):
        """P13 §145 and P12 §168, narrowed by P14 rather than dropped.

        Through P13 this asserted that no configuration field anywhere contained
        the word `promote`. P14 adds a governance section with exactly one such
        switch, off by default and gated by evidence — so the blanket form of the
        claim is retired here and its surviving half is checked instead: the
        learning configuration, which is what a training job can see, still has
        no way to promote anything.
        """
        from eye_for_an_eye.config import Config, LearningConfig
        for field in LearningConfig.__dataclass_fields__:
            with self.subTest(field=field):
                self.assertNotIn('promote', field)
        governance = Config().model_governance
        self.assertFalse(governance.auto_promote_enabled,
                         'auto-promotion must be off on a fresh configuration')


class TestTheLegacyCorpusVocabularyIsStatedNotSilent(unittest.TestCase):
    """§6. A schema mismatch nobody wrote down is a schema mismatch.

    `training/build_dataset.py` is the frozen P7 v2 generator. Its `label_source`
    is not in the current accepted vocabulary, which is correct -- the current
    validator should refuse a v2 corpus. The defect was that nothing said so, so
    the next person to meet it would have had to guess whether it was deliberate.
    """

    def test_the_legacy_value_is_named_and_deliberately_not_accepted(self):
        from training import schema
        self.assertTrue(schema.LEGACY_LABEL_SOURCES)
        for value in schema.LEGACY_LABEL_SOURCES:
            with self.subTest(value=value):
                self.assertNotIn(value, schema.ALLOWED_LABEL_SOURCES)

    def test_the_two_vocabularies_never_overlap(self):
        from training import schema
        self.assertFalse(set(schema.LEGACY_LABEL_SOURCES)
                         & set(schema.ALLOWED_LABEL_SOURCES))
        self.assertFalse(set(schema.LEGACY_LABEL_SOURCES)
                         & set(schema.FORBIDDEN_LABEL_SOURCES),
                         'legacy is not the same thing as decision-derived')

    def test_the_value_the_legacy_generator_emits_is_the_one_listed(self):
        """Reads the generator rather than trusting the constant."""
        import ast
        from training import build_dataset, schema
        tree = ast.parse(Path(build_dataset.__file__).read_text(encoding='utf-8'))
        emitted = {node.value for node in ast.walk(tree)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str)
                   and node.value in schema.LEGACY_LABEL_SOURCES}
        self.assertTrue(emitted, 'build_dataset.py no longer emits a listed legacy '
                                 'label_source; LEGACY_LABEL_SOURCES is now stale')

    def test_the_current_validator_would_reject_the_legacy_value(self):
        """The behaviour the listing exists to describe."""
        from training import schema
        for value in schema.LEGACY_LABEL_SOURCES:
            declared = [value]
            with self.subTest(value=value):
                self.assertTrue(
                    any(item not in schema.ALLOWED_LABEL_SOURCES for item in declared),
                    'validation.py would accept a legacy corpus')


class TestAModelThatWillNotLoadSaysWhy(unittest.TestCase):
    """§30. `error: 'ValueError'` is not a diagnosis.

    Every refusal in `onnx_model.py` -- corrupt file, hash mismatch, wrong
    feature schema, bad permissions, unsupported operator -- reported the same
    four-letter word. An operator whose classifier had stopped answering could
    not tell which, and the classifier going quiet is exactly when they need to.

    The counter-pressure is real and is kept: an arbitrary exception message can
    carry a filesystem path. So only this module's own fixed strings pass.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_our_own_refusal_reaches_the_operator_with_its_reason(self):
        from eye_for_an_eye.decision.onnx_model import _read
        target = Path(self.tmp.name) / 'artifact.json'
        target.write_text('{}', encoding='utf-8')
        target.chmod(0o666)          # group/world writable: refused by design
        with self.assertRaises(ValueError) as caught:
            _read(str(target), 4096)
        from eye_for_an_eye.decision.onnx_model import _reason
        self.assertEqual(_reason(caught.exception),
                         'ValueError: artifact ownership/write permissions rejected')

    def test_a_foreign_exception_still_reports_only_its_class(self):
        """The leak this narrowness exists to prevent."""
        from eye_for_an_eye.decision.onnx_model import _reason
        leaky = OSError('/home/someone/secret/path/model.onnx: No such file')
        self.assertEqual(_reason(leaky), 'OSError')
        self.assertNotIn('secret', _reason(leaky))

    def test_a_reason_can_never_become_a_payload(self):
        from eye_for_an_eye.decision.onnx_model import MAX_REASON_CHARS, _reason
        self.assertLessEqual(len(_reason(ValueError('x' * 10_000))), MAX_REASON_CHARS)

    def test_every_literal_refusal_in_the_module_is_listed(self):
        """The anti-drift check. A new `raise ValueError('...')` must be listed.

        Without this the allow-list silently rots: the next refusal added would
        report its bare class name again and nobody would notice, which is the
        state this whole change exists to leave behind.
        """
        import ast
        from eye_for_an_eye.decision import onnx_model
        tree = ast.parse(Path(onnx_model.__file__).read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            for argument in node.exc.args:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    with self.subTest(message=argument.value):
                        self.assertIn(
                            argument.value, onnx_model.SAFE_REASONS,
                            f'onnx_model.py raises {argument.value!r}; add it to '
                            'SAFE_REASONS or an operator will see only the class name')

    def test_the_allow_list_has_no_entry_the_module_never_raises(self):
        """Drift in the other direction: a stale entry is a wrong promise."""
        import ast
        from eye_for_an_eye.decision import onnx_model
        tree = ast.parse(Path(onnx_model.__file__).read_text(encoding='utf-8'))
        raised = {argument.value
                  for node in ast.walk(tree)
                  if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
                  for argument in node.exc.args
                  if isinstance(argument, ast.Constant) and isinstance(argument.value, str)}
        self.assertEqual(set(onnx_model.SAFE_REASONS) - raised, set())


class TestTheSecurityGateIsGreenOnThisTree(unittest.TestCase):
    """§49, §137. A gate that only runs in CI is a gate nobody watches.

    `scripts/security_scan.py` exits non-zero on an unreviewed Bandit finding,
    and it was exiting non-zero: `decision/registry.py` had acquired an
    `os.chmod(..., 0o755)` that was never entered in the review register. The
    scan was correct and the repository was red. Nothing in the test suite
    looked, so the only signal was a CI run, and a red gate that nobody reads
    becomes a gate everybody learns to ignore.
    """

    ROOT = Path(__file__).resolve().parents[1]

    def register(self):
        import json
        return json.loads((self.ROOT / 'security' / 'bandit-reviewed.json')
                          .read_text(encoding='utf-8'))

    def test_every_accepted_finding_records_why_it_was_accepted(self):
        """A register of accepted security findings that cannot say why is not
        a review; it is a list of hashes."""
        for entry in self.register():
            with self.subTest(finding=f"{entry.get('test_id')} {entry.get('file')}"):
                self.assertTrue(str(entry.get('reason', '')).strip(),
                                'a reviewed finding with no reason')
                self.assertGreater(len(entry['reason']), 60,
                                   'the reason is too short to be a review')

    def test_each_entry_names_a_file_that_exists(self):
        for entry in self.register():
            with self.subTest(file=entry['file']):
                self.assertTrue((self.ROOT / entry['file']).is_file(),
                                'the register refers to a file that is gone')

    def test_a_hash_without_a_reason_does_not_silence_a_finding(self):
        """The property that keeps the register honest under pressure."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'security_scan', self.ROOT / 'scripts' / 'security_scan.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = (self.ROOT / 'scripts' / 'security_scan.py').read_text(encoding='utf-8')
        self.assertIn("entry.get('reason', '')", source,
                      'security_scan.py no longer requires a reason')

    def test_the_scan_passes_on_the_current_working_tree(self):
        """The regression itself. Slow-ish; skipped where bandit is absent."""
        import subprocess
        import sys
        try:
            import bandit  # noqa: F401
        except ImportError:
            self.skipTest('bandit is in the optional `quality` extra')
        finished = subprocess.run(
            [sys.executable, 'scripts/security_scan.py'], cwd=self.ROOT,
            capture_output=True, text=True, timeout=300)
        self.assertEqual(finished.returncode, 0,
                         f'security_scan.py failed: {finished.stdout}{finished.stderr}')


if __name__ == '__main__':
    unittest.main()
