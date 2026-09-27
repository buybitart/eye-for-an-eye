"""The two production postures, as shipped. P16 §6-§11, §37-§40, §86.

Both run the same runtime. The difference between them is one thing: whether a
decision the authority takes is carried out. That difference has to be legible
in the file an operator reads, and it has to be enforced by the configuration
rather than by a sentence in a document.

So these tests load the shipped templates through the real loader and assert
what they actually configure. Three properties matter more than the rest:

* **Shadow validates as shipped and enforces nothing.** It is the quick-start
  path, so a new operator reaches a running analysis stack without touching a
  firewall rule.
* **Autonomous refuses to validate as shipped.** Not because it is broken, but
  because `enforcement.host_enabled` with an empty `management_networks` is a
  configuration that can lock an administrator out of their own machine. The
  refusal names the setting. That is §9's fail-safe, tested rather than
  described.
* **Neither enables anything that reaches outward.** No active probes, no RDAP,
  no decoy listener, no automatic promotion, no automatic training.
"""
from pathlib import Path
import shutil
import tempfile
import unittest

from eye_for_an_eye.config import load_config
from eye_for_an_eye.configuration import PROFILE_TEMPLATES, SENSOR_PROFILES, initialize

ROOT = Path(__file__).resolve().parents[1]
CALIBRATOR = ROOT / 'models' / 'mathrisk-cal-v4-isotonic.json'


class ProfileCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)

    #: `initialize` refuses to overwrite an existing file — correct for a real
    #: configuration and inconvenient for a test that wants two of them — so
    #: each call gets its own name.
    _written = 0

    def written(self, profile):
        type(self)._written += 1
        path = self.directory / f'{profile}-{type(self)._written}.toml'
        initialize(str(path), profile)
        return path

    def loaded(self, profile, *, edits=()):
        path = self.written(profile)
        text = path.read_text(encoding='utf-8')
        for old, new in edits:
            self.assertIn(old, text, f'{profile} no longer contains {old!r}')
            text = text.replace(old, new, 1)
        path.write_text(text, encoding='utf-8')
        # Loaded without validating, so a test can say which call refuses. The
        # autonomous template is *meant* to refuse as shipped, and a helper that
        # raised during the load would make that indistinguishable from a
        # template that cannot be read at all.
        return load_config(str(path), validate=False)


class TestBothProfilesExist(ProfileCase):
    def test_they_are_registered_setup_profiles(self):
        for profile in ('production-shadow', 'production-autonomous'):
            with self.subTest(profile=profile):
                self.assertIn(profile, PROFILE_TEMPLATES)

    def test_they_are_sensor_deployments(self):
        """One runtime, two postures. Neither is a new deployment mode."""
        for profile in ('production-shadow', 'production-autonomous'):
            with self.subTest(profile=profile):
                self.assertIn(profile, SENSOR_PROFILES)
                result = initialize(str(self.directory / f'{profile}.toml'), profile)
                self.assertEqual(result['deployment_profile'], 'sensor')

    def test_an_unknown_profile_is_refused_and_the_message_lists_the_real_ones(self):
        with self.assertRaises(ValueError) as raised:
            initialize(str(self.directory / 'x.toml'), 'production')
        for profile in PROFILE_TEMPLATES:
            with self.subTest(profile=profile):
                self.assertIn(profile, str(raised.exception))


class TestProductionShadow(ProfileCase):
    """The quick-start path. It must work as shipped and enforce nothing."""

    def setUp(self):
        super().setUp()
        self.config = self.loaded('production-shadow')

    def test_it_validates_as_shipped(self):
        self.config.validate()

    def test_the_whole_authority_runs(self):
        self.assertTrue(self.config.autonomy.enabled)
        self.assertEqual(self.config.autonomy.mode, 'shadow')
        self.assertTrue(self.config.decision.enabled)
        self.assertTrue(self.config.correlation.enabled)
        self.assertTrue(self.config.web.enabled)
        self.assertTrue(self.config.ml.enabled)

    def test_nothing_is_enforced(self):
        """Two settings, and both of them say no."""
        self.assertFalse(self.config.enforcement.host_enabled)
        self.assertFalse(self.config.enforcement.enabled)
        self.assertFalse(self.config.firewall.enabled)

    def test_the_auxiliary_model_is_not_required(self):
        """A broken optional component degrades health; it does not stop the
        deterministic path."""
        self.assertFalse(self.config.ml.required)

    def test_both_evidence_files_are_configured(self):
        """§20, §21: the canonical journal, and the analytic export beside it."""
        self.assertTrue(self.config.autonomy.decision_journal_path)
        self.assertTrue(self.config.autonomy.shadow_export_path)

    def test_the_journal_keeps_no_addresses(self):
        self.assertFalse(self.config.autonomy.journal_include_source)

    def test_the_export_is_marked_as_real_shadow(self):
        self.assertEqual(self.config.autonomy.shadow_export_collection, 'real_shadow')


class TestProductionAutonomous(ProfileCase):
    """The posture that acts. Its prerequisites are refusals, not advice."""

    def test_it_refuses_to_validate_with_no_management_network(self):
        """§9's fail-safe. An empty list is not a statement that you have none."""
        config = self.loaded('production-autonomous')
        with self.assertRaises(ValueError) as raised:
            config.validate()
        message = str(raised.exception)
        self.assertIn('management_networks', message)
        self.assertIn('lock you out', message)

    def test_it_validates_once_the_prerequisites_are_supplied(self):
        shutil.copy(CALIBRATOR, self.directory / CALIBRATOR.name)
        config = self.loaded('production-autonomous', edits=(
            ('management_networks = []', 'management_networks = ["192.0.2.0/24"]'),))
        config.validate()
        self.assertEqual(config.autonomy.mode, 'autonomous')
        self.assertTrue(config.autonomy.enabled)
        self.assertTrue(config.enforcement.host_enabled)

    def test_it_names_a_calibrator(self):
        """A block decided without a calibrated probability is a block decided
        on a number that is not a probability."""
        config = self.loaded('production-autonomous')
        self.assertTrue(config.autonomy.calibrator_path)

    def test_the_calibrator_it_names_is_one_this_repository_ships(self):
        config = self.loaded('production-autonomous')
        self.assertTrue((ROOT / 'models' / Path(config.autonomy.calibrator_path).name).is_file(),
                        'the template names a calibrator file that is not in models/')

    def test_a_block_cannot_be_made_permanent(self):
        """§86. The ceiling is the configuration's own, not a number repeated here."""
        config = self.loaded('production-autonomous')
        ladder = config.enforcement.block_seconds
        self.assertTrue(ladder)
        self.assertEqual(sorted(set(ladder)), ladder, 'the ladder must escalate')
        with self.assertRaises(ValueError):
            over = self.loaded('production-autonomous', edits=(
                ('management_networks = []', 'management_networks = ["192.0.2.0/24"]'),
                (f'block_seconds = {ladder}',
                 f'block_seconds = {ladder[:-1] + [ladder[-1] + 1]}')))
            over.validate()

    def test_the_prerequisites_are_written_at_the_top_of_the_file(self):
        """An operator who reads the first screen has read them."""
        head = self.written('production-autonomous').read_text(encoding='utf-8')[:2400]
        for phrase in ('PENDING', 'management_networks', 'calibrator_path',
                       'doctor', 'readiness'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, head)

    def test_the_file_does_not_claim_real_world_validation(self):
        text = self.written('production-autonomous').read_text(encoding='utf-8').lower()
        for claim in ('production-proven', 'production proven', 'zero false positive',
                      'internet-validated', 'guaranteed'):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, text)


class TestNeitherProfileReachesOutward(ProfileCase):
    """§11, §12, §23. Included is not enabled, and local-first is a setting."""

    def configs(self):
        shutil.copy(CALIBRATOR, self.directory / CALIBRATOR.name)
        return (('production-shadow', self.loaded('production-shadow')),
                ('production-autonomous', self.loaded('production-autonomous', edits=(
                    ('management_networks = []', 'management_networks = ["192.0.2.0/24"]'),))))

    def test_no_active_probing(self):
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertFalse(config.active_probes.enabled)

    def test_no_outbound_enrichment(self):
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertFalse(config.enrichment.rdap_enabled)
                self.assertEqual(config.deployment.egress, 'disabled')

    def test_no_decoy_listener(self):
        """Available, and not appropriate on a host serving real users."""
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertFalse(config.deception.enabled)

    def test_no_lab_experiment(self):
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertFalse(config.lab.enabled)

    def test_no_automatic_training(self):
        """A system decision is never a training label."""
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertFalse(config.learning.auto_train)
                self.assertFalse(config.learning.auto_prepare_dataset)

    def test_no_automatic_promotion_to_active(self):
        """§18: the subsystem is present and its highest-impact transition is gated."""
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertFalse(config.model_governance.auto_promote_enabled)
                self.assertFalse(config.model_governance.auto_promote_global_enabled)

    def test_rollback_and_guarded_activation_stay_available(self):
        """Gating the promotion is not disabling the governance."""
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertTrue(config.model_governance.auto_rollback_enabled)
                self.assertTrue(config.model_governance.guarded_activation_enabled)

    def test_the_api_and_metrics_stay_on_loopback(self):
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertEqual(config.api.bind_address, '127.0.0.1')
                self.assertEqual(config.metrics.bind_address, '127.0.0.1')

    def test_an_unusual_source_does_not_become_a_block_on_its_own(self):
        """§15. OOD and a degraded model reduce trust; they do not create one."""
        for name, config in self.configs():
            with self.subTest(profile=name):
                self.assertTrue(config.reliability.ood_suppresses_block)
                self.assertTrue(config.reliability.degraded_model_suppresses_block)


if __name__ == '__main__':
    unittest.main()
