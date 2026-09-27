"""P9 invariants, asserted against the whole repository rather than one module.

Every test here is a regression test for a property that is easy to break later by
adding one convenient function. They are deliberately blunt: they read the source
tree and the configuration surface and check that certain things do not exist.
"""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'eye_for_an_eye'
TRAINING = ROOT / 'training'
DATASET = ROOT / 'dataset'


def python_files(*roots):
    for root in roots:
        for path in sorted(root.rglob('*.py')):
            if '__pycache__' not in path.parts:
                yield path


class TestNoAutoPromotion(unittest.TestCase):
    """§63, §84, §123. The single most important property in P9.

    **Narrowed in P14, and the narrowing is the point.** Through P13 this class
    asserted that no configuration field anywhere was named `auto_promote`, which
    was a true and useful statement about a system that had no governance engine.
    P14 adds `model_governance.auto_promote_enabled`, so the blanket claim stops
    being true — and deleting the class would throw away the properties that do
    still hold.

    What P14 did not change, and what is checked below: training still cannot
    promote what it trained, promotion still defaults to off, and the one setting
    that exists is gated by evidence the training process cannot manufacture.
    """

    def test_only_the_governance_section_may_mention_promotion(self):
        """Any *other* section growing a promotion switch is the regression."""
        from eye_for_an_eye.config import Config
        config = Config()
        for section_name in vars(config):
            section = getattr(config, section_name)
            for field in getattr(section, '__dataclass_fields__', {}):
                if section_name == 'model_governance':
                    continue
                with self.subTest(section=section_name, field=field):
                    self.assertNotIn('auto_promote', field,
                                     f'{section_name}.{field} would allow automatic '
                                     'promotion outside the governance authority')
                    self.assertNotIn('autopromote', field.replace('_', ''))

    def test_the_governance_switches_are_off_on_a_fresh_configuration(self):
        """§4, §143. Whatever the machinery can do, it starts switched off."""
        from eye_for_an_eye.config import Config
        governance = Config().model_governance
        self.assertFalse(governance.auto_promote_enabled)
        self.assertFalse(governance.auto_promote_global_enabled)
        self.assertEqual(list(governance.auto_promote_sites), [])

    def test_enabling_promotion_without_a_way_back_is_refused(self):
        """The combination that would make automation irreversible."""
        from eye_for_an_eye.config import Config
        for field in ('guarded_activation_enabled', 'auto_rollback_enabled'):
            with self.subTest(setting=field):
                config = Config()
                config.model_governance.auto_promote_enabled = True
                setattr(config.model_governance, field, False)
                with self.assertRaises(ValueError):
                    config.validate()

    def test_the_learning_configuration_has_no_promotion_switch(self):
        from eye_for_an_eye.config import LearningConfig
        fields = set(LearningConfig.__dataclass_fields__)
        self.assertIn('auto_train', fields, 'auto_train is expected to exist and default to False')
        self.assertFalse(LearningConfig().auto_train)
        self.assertFalse(LearningConfig().auto_prepare_dataset)
        self.assertFalse(LearningConfig().enabled)
        for name in fields:
            self.assertNotIn('promote', name)

    def test_promotion_requires_a_passing_gate_at_the_registry_itself(self):
        import tempfile
        from eye_for_an_eye.decision.registry import ModelRegistry, RegistryError
        with tempfile.TemporaryDirectory() as directory:
            registry = ModelRegistry(Path(directory))
            with self.assertRaises(RegistryError):
                registry.promote('anything', gate_passed=False)

    def test_nothing_outside_the_operator_command_calls_promote(self):
        """Who may change which model is ACTIVE.

        Through P13 this was the registry CLI and the registry itself. P14 adds
        exactly one more: `governance/activation.py`, the promotion transaction,
        which accepts only an ELIGIBLE assessment under the current policy and
        which puts the model into a guarded stage rather than into full service.

        Adding it to this list is the narrowing P14 needs; the companion test
        below is the part that still bites, because the property that matters was
        never "one call site" but "not from training".
        """
        allowed = {'reliability_cli.py', 'registry.py', 'promotion.py',
                   'activation.py'}
        offenders = []
        for path in python_files(PACKAGE, TRAINING, DATASET):
            if path.name in allowed:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if not isinstance(target, ast.Attribute):
                    continue
                receiver = getattr(target.value, 'id', '')
                # A rollback call in the firewall rolls back a firewall rule,
                # which is a different thing entirely. Only a call on a registry
                # can change which model is active.
                if target.attr in ('promote', 'rollback') and 'registr' in receiver.lower():
                    offenders.append(f'{path.relative_to(ROOT)}:{node.lineno}')
        self.assertEqual(offenders, [], f'unexpected promotion call sites: {offenders}')

    def test_the_training_and_dataset_packages_cannot_change_the_active_model(self):
        """§109, §142. The boundary P14 did not move, checked where it matters.

        A training job may produce a candidate and may do nothing else. If this
        ever fails, a training subprocess has acquired the ability to put its own
        output into production, which is the single failure this whole
        architecture is arranged to prevent.
        """
        offenders = []
        for path in python_files(TRAINING, DATASET):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('promote', 'rollback'):
                        offenders.append(f'{path.relative_to(ROOT)}:{node.lineno}')
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = {alias.name for alias in node.names}
                    names.add(getattr(node, 'module', '') or '')
                    for name in names:
                        if 'governance' in name or 'registry' in name:
                            offenders.append(
                                f'{path.relative_to(ROOT)}:{node.lineno} imports {name}')
        self.assertEqual(offenders, [],
                         f'training or dataset code can reach promotion: {offenders}')

    def test_the_activator_is_the_only_new_promotion_authority(self):
        """One call site was added in P14. It should stay one."""
        callers = set()
        for path in python_files(PACKAGE):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)):
                    continue
                receiver = getattr(node.func.value, 'id', '')
                if node.func.attr == 'promote' and 'registr' in receiver.lower():
                    callers.add(path.name)
        self.assertEqual(callers - {'registry.py', 'promotion.py'},
                         {'reliability_cli.py', 'activation.py'},
                         'the set of things that can promote a model has changed')

    def test_the_recommendation_vocabulary_contains_no_action(self):
        from eye_for_an_eye.decision.promotion import (KEEP_ACTIVE, NEED_MORE_DATA, PROMOTE,
                                                       REJECT)
        # PROMOTE is the name of an opinion, not of a function that promotes.
        for value in (PROMOTE, KEEP_ACTIVE, REJECT, NEED_MORE_DATA):
            self.assertIsInstance(value, str)
        from eye_for_an_eye.decision import promotion
        self.assertFalse(hasattr(promotion, 'promote'))
        self.assertFalse(hasattr(promotion, 'apply'))


class TestNoSelfLabelling(unittest.TestCase):
    """§5, §125. A decision must never become training data."""

    def test_every_decision_derived_label_source_is_forbidden(self):
        from dataset.schema import FORBIDDEN_LABEL_SOURCES
        for name in ('blocked', 'model_score', 'math_score', 'risk_threshold',
                     'shadow_decision', 'previous_model', 'self_labelled'):
            self.assertIn(name, FORBIDDEN_LABEL_SOURCES, name)

    def test_a_sample_with_a_decision_derived_label_is_refused(self):
        from datetime import datetime, timezone
        from dataset import schema
        from eye_for_an_eye.decision.features import FeatureVector, NAMES
        vector = FeatureVector(values=tuple(0.0 for _ in NAMES), observation_seconds=60.0,
                               sample_count=30, loss_fraction=0.0)
        for source in schema.FORBIDDEN_LABEL_SOURCES:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    schema.DatasetSample(
                        dataset_version='d', feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
                        sample_id='s', timestamp=datetime.now(timezone.utc),
                        source_type=schema.LAB, scenario_group='g', source_group='g',
                        capture_group=None, label=schema.MALICIOUS, label_source=source,
                        label_confidence='HIGH', features=vector)

    def test_unreviewed_shadow_cannot_carry_a_supervised_label(self):
        from datetime import datetime, timezone
        from dataset import schema
        from eye_for_an_eye.decision.features import FeatureVector, NAMES
        vector = FeatureVector(values=tuple(0.0 for _ in NAMES), observation_seconds=60.0,
                               sample_count=30, loss_fraction=0.0)
        with self.assertRaises(ValueError):
            schema.DatasetSample(
                dataset_version='d', feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
                sample_id='s', timestamp=datetime.now(timezone.utc),
                source_type=schema.SHADOW_UNLABELED, scenario_group=None, source_group='g',
                capture_group=None, label=schema.MALICIOUS, label_source='shadow_observation',
                label_confidence='MEDIUM', features=vector)

    def test_the_review_queue_is_the_only_module_that_writes_a_review_state(self):
        from eye_for_an_eye.decision.review_queue import ANSWERS
        offenders = []
        for path in python_files(PACKAGE):
            if path.name in ('review_queue.py', 'review_cli.py'):
                continue
            text = path.read_text(encoding='utf-8')
            for answer in ANSWERS:
                if f"state={answer}" in text or f"'{answer}'" in text and 'record_review' in text:
                    offenders.append(f'{path.relative_to(ROOT)}:{answer}')
        self.assertEqual(offenders, [])


class TestForbiddenFeatures(unittest.TestCase):
    """§20, §90. Identity must never become a model input."""

    #: Short words that mean identity only when they stand alone. Matched as
    #: whole `_`-separated tokens, because as bare substrings they turn up
    #: inside ordinary English — "principals" contains "ip" — so a substring
    #: match here fails correct names while catching nothing a token match
    #: misses.
    IDENTITY_TOKENS = ('ip', 'src', 'dst', 'asn', 'addr', 'address', 'host', 'name')
    #: Distinctive enough that any appearance at all is suspicious.
    IDENTITY_SUBSTRINGS = ('country', 'hash', 'scenario', 'capture', 'block',
                           'principal_id', 'username', 'account_id')

    def test_the_model_feature_list_contains_no_identity(self):
        from dataset.schema import MODEL_FEATURES
        for name in MODEL_FEATURES:
            tokens = set(name.lower().split('_'))
            for forbidden in self.IDENTITY_TOKENS:
                self.assertNotIn(forbidden, tokens, f'{name} looks like identity')
            for forbidden in self.IDENTITY_SUBSTRINGS:
                self.assertNotIn(forbidden, name.lower(), f'{name} looks like identity')

    def test_every_model_feature_is_measured_as_a_quantity(self):
        """The stronger form of the check above, and the one that matters.

        A name is a hint; the declared units are the contract. Every model input
        has to be a count, a fraction, a duration or a score — never a value
        that identifies anybody. `auth_principals_900s` passes because it counts
        distinct pseudonyms; the pseudonym itself is never a feature, and
        `decision/auth.py` is where that is enforced.
        """
        from eye_for_an_eye.decision.features import SPEC
        from dataset.schema import MODEL_FEATURES
        units = {name: unit for name, _, _, unit, _ in SPEC}
        quantities = ('observation', 'port', 'address', 'fraction', 'second',
                      'protocol famil', 'coefficient', 'score', 'refus', 'success',
                      'principal', 'attempt')
        for name in MODEL_FEATURES:
            if name.startswith('available_'):
                # An availability flag is a boolean about a feature, not a
                # measurement of its own. It carries no units and no value.
                self.assertIn(name.removeprefix('available_'), units, f'{name} flags nothing')
                continue
            unit = units.get(name, '')
            self.assertTrue(any(word in unit for word in quantities),
                            f'{name} declares units {unit!r}, which is not a quantity')

    def test_the_model_feature_list_contains_no_previous_decision(self):
        from dataset.schema import MODEL_FEATURES
        for name in MODEL_FEATURES:
            self.assertNotIn('previous', name)
            self.assertNotIn('risk', name)
            self.assertNotIn('score', name)

    def test_a_source_key_is_never_a_feature(self):
        from dataset.schema import MODEL_FEATURES
        from eye_for_an_eye.decision.review_queue import SUMMARY_FEATURES
        for name in ('source_key', 'source_group', 'src', 'pseudonym'):
            self.assertNotIn(name, MODEL_FEATURES)
            self.assertNotIn(name, SUMMARY_FEATURES)


class TestNoNetwork(unittest.TestCase):
    """§ "No cloud AI. No external training API. No remote model registry." """

    LEARNING_MODULES = ('decision/registry.py', 'decision/promotion.py',
                        'decision/retraining.py', 'decision/review_queue.py',
                        'decision/candidate.py')

    def test_no_learning_module_can_reach_a_network(self):
        for relative in self.LEARNING_MODULES:
            with self.subTest(module=relative):
                tree = ast.parse((PACKAGE / relative).read_text(encoding='utf-8'))
                imported = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported.update(alias.name.split('.')[0] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported.add(node.module.split('.')[0])
                for forbidden in ('socket', 'urllib', 'http', 'requests', 'ftplib',
                                  'smtplib', 'ssl', 'asyncio'):
                    self.assertNotIn(forbidden, imported, f'{relative} imports {forbidden}')

    def test_the_training_job_runner_never_opens_a_socket(self):
        tree = ast.parse((TRAINING / 'jobs.py').read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split('.')[0])
        for forbidden in ('socket', 'urllib', 'http', 'requests'):
            self.assertNotIn(forbidden, imported)


class TestNoPickleInProduction(unittest.TestCase):
    """§42. A production classifier is ONNX, never a pickle."""

    def test_the_runtime_package_never_imports_pickle_or_joblib(self):
        offenders = []
        for path in python_files(PACKAGE):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                names = ()
                if isinstance(node, ast.Import):
                    names = tuple(alias.name.split('.')[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = (node.module.split('.')[0],)
                for name in names:
                    if name in ('pickle', 'joblib', 'cPickle', 'dill', 'shelve'):
                        offenders.append(f'{path.relative_to(ROOT)}:{name}')
        self.assertEqual(offenders, [])

    def test_the_registry_only_accepts_onnx_as_the_classifier(self):
        from eye_for_an_eye.decision.registry import ARTIFACTS
        self.assertIn('classifier.onnx', ARTIFACTS)
        for name in ARTIFACTS:
            self.assertFalse(name.endswith(('.pkl', '.joblib', '.pickle')))


class TestSafeDefaults(unittest.TestCase):
    """Everything P9 added is off until an operator asks for it."""

    def test_the_review_queue_is_off_by_default(self):
        from eye_for_an_eye.config import Config
        self.assertFalse(Config().reliability.review_queue_enabled)
        self.assertEqual(Config().reliability.review_queue_path, '')

    def test_learning_is_off_by_default(self):
        from eye_for_an_eye.config import Config
        learning = Config().learning
        self.assertFalse(learning.enabled)
        self.assertFalse(learning.auto_train)
        self.assertFalse(learning.auto_prepare_dataset)

    def test_training_limits_have_real_values_by_default(self):
        from eye_for_an_eye.config import Config
        learning = Config().learning
        self.assertGreater(learning.training_max_duration_seconds, 0)
        self.assertGreater(learning.training_max_memory_mb, 0)
        self.assertEqual(learning.training_max_parallel_jobs, 1)

    def test_the_cooldown_is_measured_in_days_not_minutes(self):
        from eye_for_an_eye.config import Config
        self.assertGreaterEqual(Config().learning.minimum_retraining_interval_days, 1)


if __name__ == '__main__':
    unittest.main()
