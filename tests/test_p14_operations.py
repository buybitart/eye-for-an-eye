"""P14 phase 7: the CLI, the store, the metrics, and default safety.

Two of the tests here are the ones §143 and §144 call mandatory regressions: a
fresh install has auto-promotion off, and an upgrade cannot turn it on. They are
short and they are the most valuable tests in the file, because the failure they
guard against is silent — nobody notices that a setting became true until a model
they did not choose is deciding what to block.

The rest is about the CLI refusing to guess. A governance command that defaulted
to "every site" would make the widest-reaching version of each command the one
that is easiest to type, and the one an operator reaches for at two in the
morning.
"""
import json
import tempfile
import unittest
from pathlib import Path

from eye_for_an_eye.config import Config, load_config
from eye_for_an_eye.governance_cli import governance_command
from eye_for_an_eye.governance.policy import from_config as policy_from_config
from eye_for_an_eye.governance.store import (AUDIT_EVENTS, GovernanceStore,
                                             StoreError)


class TestFreshInstallDefaultsAreOff(unittest.TestCase):
    """§4, §143. Mandatory regression: the switch starts off."""

    def test_a_fresh_configuration_has_auto_promotion_off(self):
        governance = Config().model_governance
        self.assertFalse(governance.auto_promote_enabled)
        self.assertFalse(governance.auto_promote_global_enabled)
        self.assertEqual(list(governance.auto_promote_sites), [])

    def test_the_policy_built_from_a_fresh_configuration_permits_nothing(self):
        policy = policy_from_config(Config())
        for scope in ('GLOBAL', 'SITE:main', 'SITE:anything'):
            with self.subTest(scope=scope):
                allowed, reason = policy.auto_promote.allows(scope)
                self.assertFalse(allowed)
                self.assertIn('disabled', reason)

    def test_a_configuration_with_no_governance_section_behaves_identically(self):
        """§98. "The section is missing" and "the section says no" must be the
        same behaviour, or adding the section during an upgrade is a change."""
        class Older:
            reliability = Config().reliability

        self.assertFalse(policy_from_config(Older()).auto_promote.enabled)
        self.assertEqual(policy_from_config(Older()).auto_promote.sites, ())


class TestUpgradeCannotEnableIt(unittest.TestCase):
    """§98, §144. Mandatory regression: installing P14 changes nothing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, body):
        path = Path(self.tmp.name) / 'eye-for-an-eye.toml'
        path.write_text(body, encoding='utf-8')
        return str(path)

    def test_a_pre_p14_configuration_file_loads_with_promotion_off(self):
        config = load_config(self.write(
            '[storage]\nenabled = true\n\n[learning]\nenabled = true\n'))
        self.assertFalse(config.model_governance.auto_promote_enabled)
        self.assertFalse(config.model_governance.auto_promote_global_enabled)

    def test_an_empty_configuration_file_loads_with_promotion_off(self):
        self.assertFalse(load_config(self.write('')).model_governance.auto_promote_enabled)

    def test_turning_learning_on_does_not_turn_promotion_on(self):
        """§109. Training may be automated. Promotion is a different authority."""
        config = load_config(self.write(
            '[learning]\nenabled = true\nauto_train = true\n'))
        self.assertTrue(config.learning.auto_train)
        self.assertFalse(config.model_governance.auto_promote_enabled)

    def test_the_shipped_example_configurations_all_have_it_off(self):
        root = Path(__file__).resolve().parents[1]
        examples = sorted(root.glob('config.*.toml'))
        self.assertTrue(examples)
        for example in examples:
            with self.subTest(configuration=example.name):
                config = load_config(str(example))
                self.assertFalse(config.model_governance.auto_promote_enabled,
                                 f'{example.name} ships with auto-promotion on')

    def test_enabling_global_alone_is_refused(self):
        """A setting that has no effect is a setting somebody will misread."""
        config = Config()
        config.model_governance.auto_promote_global_enabled = True
        with self.assertRaises(ValueError):
            config.validate()


class TestTheCliRefusesToGuess(unittest.TestCase):
    """§96. No command defaults to every site."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = str(Path(self.tmp.name) / 'e4e.toml')
        Path(self.config).write_text(
            f'[model_governance]\nhistory_path = "{Path(self.tmp.name).as_posix()}/gov"\n',
            encoding='utf-8')

    def run_command(self, *argv):
        return governance_command([*argv, '--config', self.config])

    def test_assess_without_a_scope_is_refused(self):
        self.assertEqual(self.run_command('assess'), 2)

    def test_assess_with_both_scopes_is_refused(self):
        self.assertEqual(self.run_command('assess', '--site', 'main', '--global'), 2)

    def test_assess_with_one_scope_works(self):
        self.assertEqual(self.run_command('assess', '--site', 'main'), 0)

    def test_status_without_a_scope_is_about_the_installation(self):
        """Unambiguous, so it does not need a scope — and says so."""
        self.assertEqual(self.run_command('status'), 0)

    def test_freeze_without_a_reason_is_refused(self):
        self.assertEqual(self.run_command('freeze'), 2)

    def test_freeze_and_unfreeze_round_trip(self):
        self.assertEqual(self.run_command('freeze', '--reason', 'investigating'), 0)
        store = GovernanceStore(Path(self.tmp.name) / 'gov')
        self.assertTrue(store.freeze_state().frozen)
        self.assertEqual(self.run_command('unfreeze'), 0)
        self.assertFalse(store.freeze_state().frozen)

    def test_every_action_produces_json_when_asked(self):
        import contextlib
        import io
        for action in ('status', 'policy', 'history', 'audit'):
            with self.subTest(action=action):
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    self.assertEqual(self.run_command(action, '--json'), 0)
                json.loads(captured.getvalue())

    def test_there_is_no_promote_action(self):
        """Adding a "promote now" verb would become the thing everybody used.

        argparse exits rather than returning for an unknown action, which is the
        right behaviour and is what an operator sees.
        """
        with self.assertRaises(SystemExit) as caught:
            self.run_command('promote')
        self.assertEqual(caught.exception.code, 2)

    def test_there_is_no_activate_or_rollback_action_either(self):
        """Rollback stays where it already was: `eye-for-an-eye model rollback`,
        which requires a person and predates this stage."""
        for action in ('activate', 'rollback', 'enable'):
            with self.subTest(action=action):
                with self.assertRaises(SystemExit):
                    self.run_command(action)


class TestTheStore(unittest.TestCase):
    """§101, §102. Bounded, append-only, and readable when the program is not."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = GovernanceStore(Path(self.tmp.name))

    def test_history_is_bounded(self):
        for index in range(400):
            self.store.record(scope='SITE:main', event='promotion_guarded',
                              version=f'v{index}')
        self.assertLessEqual(len(self.store.history(limit=10_000)), 200)

    def test_history_can_be_filtered_by_scope(self):
        self.store.record(scope='SITE:main', event='promotion_guarded', version='a')
        self.store.record(scope='SITE:api', event='promotion_guarded', version='b')
        main = self.store.history(scope='SITE:main')
        self.assertEqual([entry.version for entry in main], ['a'])

    def test_an_unknown_audit_event_is_refused(self):
        """A log whose vocabulary anybody can extend stops being machine-readable."""
        with self.assertRaises(StoreError):
            self.store.audit('something_i_made_up')

    def test_every_named_audit_event_is_accepted(self):
        for event in AUDIT_EVENTS:
            with self.subTest(event=event):
                self.store.audit(event, scope='SITE:main', detail='test')
        self.assertGreaterEqual(len(self.store.audit_entries(limit=100)),
                                len(AUDIT_EVENTS))

    def test_a_torn_final_audit_line_does_not_lose_the_rest(self):
        """Expected after a crash; not a reason to refuse the whole log."""
        self.store.audit('frozen', detail='one')
        with self.store.audit_path.open('a', encoding='utf-8') as stream:
            stream.write('{"at": "2026-09-11", "eve')
        entries = self.store.audit_entries(limit=10)
        self.assertTrue(any(entry.get('detail') == 'one' for entry in entries))

    def test_unreadable_freeze_state_raises_rather_than_reporting_not_frozen(self):
        """§115. The one reading that could resume promotion after corruption."""
        self.store.freeze_path.parent.mkdir(parents=True, exist_ok=True)
        self.store.freeze_path.write_text('{ not json', encoding='utf-8')
        with self.assertRaises(StoreError):
            self.store.freeze_state()

    def test_the_cli_treats_unreadable_state_as_frozen(self):
        import contextlib
        import io
        self.store.freeze_path.parent.mkdir(parents=True, exist_ok=True)
        self.store.freeze_path.write_text('{ not json', encoding='utf-8')
        config = Path(self.tmp.name) / 'e4e.toml'
        config.write_text(
            f'[model_governance]\nhistory_path = "{Path(self.tmp.name).as_posix()}"\n',
            encoding='utf-8')
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            governance_command(['status', '--json', '--config', str(config)])
        document = json.loads(captured.getvalue())
        self.assertTrue(document['freeze']['frozen'],
                        'unreadable governance state was reported as not frozen')

    def test_repeated_failures_freeze_automatically(self):
        """§55."""
        from eye_for_an_eye.governance.policy import GovernancePolicy
        policy = GovernancePolicy()
        for _ in range(policy.promotion.failures_before_freeze):
            self.store.record_failure(policy=policy, reason='test')
        state = self.store.freeze_state()
        self.assertTrue(state.frozen)
        self.assertTrue(state.automatic)

    def test_unfreezing_clears_the_failure_count(self):
        """Otherwise an operator who looked and fixed it is frozen again at once."""
        from eye_for_an_eye.governance.policy import GovernancePolicy
        policy = GovernancePolicy()
        for _ in range(policy.promotion.failures_before_freeze):
            self.store.record_failure(policy=policy, reason='test')
        self.store.unfreeze()
        self.assertEqual(self.store.freeze_state().consecutive_failures, 0)

    def test_safe_mode_is_recorded_distinctly_from_a_freeze(self):
        """§57, §116. Stronger than a freeze, and an operator must see which."""
        self.store.enter_safe_mode(reason='rollback itself failed')
        state = self.store.freeze_state()
        self.assertTrue(state.frozen)
        self.assertTrue(state.safe_mode)


class TestTheMetricsAreBoundedAndAnonymous(unittest.TestCase):
    """§100. Nothing high-cardinality, and nothing identifying."""

    def test_every_governance_metric_is_registered(self):
        from eye_for_an_eye.observability.metrics import NAMES
        for name in ('model_promotion_assessments_total',
                     'model_promotion_eligible_total', 'model_auto_promotions_total',
                     'model_auto_promotion_failures_total',
                     'model_guarded_activations_total',
                     'model_guarded_stage_advances_total',
                     'model_auto_rollbacks_total', 'model_governance_freeze_total',
                     'model_quarantine_total',
                     'model_post_promotion_disagreement_ratio'):
            with self.subTest(metric=name):
                self.assertIn(name, NAMES)

    def test_the_duration_metric_has_its_sum_and_count(self):
        from eye_for_an_eye.observability.metrics import NAMES
        for suffix in ('sum', 'count'):
            self.assertIn(f'model_promotion_duration_seconds_{suffix}', NAMES)

    def test_no_governance_metric_name_could_carry_an_identifier(self):
        """A model hash, a candidate id or a site domain as a label is how a
        scrape endpoint becomes a memory problem — and a site domain would also
        publish the list of protected websites."""
        from eye_for_an_eye.observability.metrics import NAMES
        for name in (name for name in NAMES if name.startswith('model_')):
            with self.subTest(metric=name):
                for forbidden in ('version', 'hash', 'sha', 'domain', 'site_id',
                                  'candidate_id', 'address'):
                    self.assertNotIn(forbidden, name)

    def test_the_governance_metrics_are_a_bounded_set(self):
        """Twenty-odd fixed names, not a name built from anything observed."""
        from eye_for_an_eye.observability.metrics import NAMES
        governance = [name for name in NAMES if name.startswith('model_')]
        self.assertGreater(len(governance), 15)
        self.assertLess(len(governance), 40)

    def test_no_governance_code_builds_a_metric_name_from_a_value(self):
        """The pattern that turns a fixed list into an unbounded one:
        `metrics['model_' + version]`. Checked across the package."""
        import ast
        from pathlib import Path
        import eye_for_an_eye.governance as package
        for path in sorted(Path(package.__file__).parent.glob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Subscript):
                    continue
                target = node.value
                if not (isinstance(target, ast.Attribute) and target.attr == 'metrics'):
                    continue
                with self.subTest(file=path.name, line=node.lineno):
                    self.assertIsInstance(
                        node.slice, ast.Constant,
                        f'{path.name}:{node.lineno} builds a metric name at runtime')


if __name__ == '__main__':
    unittest.main()
