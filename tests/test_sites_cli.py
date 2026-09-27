"""P12 Phase 9 (§89-§95, §155, §157, §158): what an operator sees.

Two things are being checked beyond "it prints something".

**A single-site owner never meets multi-site.** With `sites.enabled = false`
every command says so plainly and exits 0. Multi-site must not become a thing
you have to understand in order to protect one website (§158).

**The output is honest about scope.** A network block reaches every site on the
machine, a site without a baseline answers INSUFFICIENT_DATA rather than
guessing, and a site on the shared base model is not reported as broken. Each of
those is a place where a comforting summary would mislead.
"""
import contextlib
import io
import json
import unittest
from pathlib import Path
import tempfile

from eye_for_an_eye.cli import COMMANDS
from eye_for_an_eye.config import load_config
from eye_for_an_eye.sites_cli import (DEGRADED, DISABLED, NOT_CONFIGURED,
                                      doctor, sites_command)

MAIN = 'example.org'
API_HOST = 'api.example.org'

CONFIG = '''
[sites]
enabled = true

[sites.profiles.main]
profile = "website"
domains = ["example.org", "www.example.org"]

[sites.profiles.api]
profile = "api"
domains = ["api.example.org"]
'''


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, text=CONFIG):
        path = self.root / 'eye-for-an-eye.toml'
        path.write_text(text, encoding='utf-8')
        return path

    def run_command(self, *argv, text=CONFIG):
        path = self.write(text)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sites_command([*argv, '--config', str(path)])
        return code, out.getvalue(), err.getvalue()


class TestRouting(Base):
    def test_sites_is_a_routed_command(self):
        self.assertIn('sites', COMMANDS)

    def test_the_router_reaches_the_module(self):
        from eye_for_an_eye.cli import main
        with self.assertRaises(SystemExit) as raised:
            main(['sites', '--help'])
        self.assertEqual(raised.exception.code, 0)

    def test_an_unknown_action_is_refused(self):
        with self.assertRaises(SystemExit):
            sites_command(['delete-everything'])


class TestSingleSiteOwnersAreLeftAlone(Base):
    """§158. Multi-site must not become something you have to understand."""

    def test_every_command_says_so_plainly_when_multi_site_is_off(self):
        for action in ('list', 'doctor'):
            with self.subTest(action=action):
                code, printed, _ = self.run_command(action, text='[sites]\nenabled = false\n')
                self.assertEqual(code, 0)
                self.assertIn('Disabled', printed)

    def test_an_absent_sites_section_is_not_an_error(self):
        code, printed, _ = self.run_command('list', text='[web]\nenabled = false\n')
        self.assertEqual(code, 0)
        self.assertIn('Disabled', printed)

    def test_doctor_reports_disabled_rather_than_broken(self):
        config = load_config(str(self.write('[sites]\nenabled = false\n')))
        report = doctor(config, None)
        self.assertEqual(report['sites']['status'], DISABLED)


class TestList(Base):
    """§90. One line per site, with the things an operator compares."""

    def test_every_configured_site_appears(self):
        _, printed, _ = self.run_command('list')
        self.assertIn('main', printed)
        self.assertIn('api', printed)

    def test_the_profile_and_mode_are_shown(self):
        _, printed, _ = self.run_command('list')
        self.assertIn('website', printed)
        self.assertIn('shadow', printed)

    def test_the_unknown_bucket_is_shown_rather_than_hidden(self):
        _, printed, _ = self.run_command('list')
        self.assertIn('unknown-site', printed)

    def test_the_shared_budget_is_shown(self):
        _, printed, _ = self.run_command('list')
        self.assertIn('Shared budget', printed)
        self.assertIn('reserved per site', printed)

    def test_the_note_says_what_is_shared(self):
        _, printed, _ = self.run_command('list')
        self.assertIn('separate per site', printed)
        self.assertIn('shared on purpose', printed)

    def test_json_output_is_the_engine_health_document(self):
        _, printed, _ = self.run_command('list', '--json')
        document = json.loads(printed)
        self.assertEqual(document['sites'], 2)
        self.assertEqual(sorted(document['site_ids']), ['api', 'main'])


class TestShow(Base):
    """§91. One site, in full."""

    def test_a_site_shows_its_domains_thresholds_and_baseline(self):
        _, printed, _ = self.run_command('show', 'main')
        for expected in (MAIN, 'website', 'Thresholds', 'Baseline', 'Active sources'):
            self.assertIn(expected, printed)

    def test_shadow_mode_says_that_nothing_is_enforced(self):
        _, printed, _ = self.run_command('show', 'main')
        self.assertIn('nothing is enforced', printed)

    def test_an_api_site_reports_its_own_higher_expected_rate(self):
        _, main, _ = self.run_command('show', 'main')
        _, api, _ = self.run_command('show', 'api')
        self.assertNotEqual(main, api)
        self.assertIn('Expected rate', api)

    def test_an_api_site_reports_challenges_disabled(self):
        _, printed, _ = self.run_command('show', 'api')
        self.assertIn('Challenge:\ndisabled', printed)

    def test_the_output_says_a_network_block_would_reach_every_site(self):
        """§96. The sentence that stops a bad afternoon."""
        _, printed, _ = self.run_command('show', 'main')
        self.assertIn('stays site-local', printed)
        self.assertIn('would affect all of them', printed)

    def test_an_unknown_site_is_refused_with_a_hint(self):
        code, printed, _ = self.run_command('show', 'nope')
        self.assertEqual(code, 2)
        self.assertIn('sites list', printed)

    def test_show_without_a_site_says_which_argument_is_missing(self):
        code, printed, _ = self.run_command('show')
        self.assertEqual(code, 2)
        self.assertIn('needs a site name', printed)


class TestDoctor(Base):
    """§92. Read-only, and honest about what it found."""

    def test_a_healthy_configuration_exits_zero(self):
        code, _, _ = self.run_command('doctor')
        self.assertEqual(code, 0)

    def test_the_headline_names_the_check_that_produced_it(self):
        code, printed, _ = self.run_command('doctor')
        self.assertIn('Domain mapping', printed)
        self.assertIn('Unknown hosts', printed)

    def test_a_site_with_no_domains_is_flagged(self):
        text = CONFIG + '\n[sites.profiles.orphan]\nprofile = "website"\n'
        _, printed, _ = self.run_command('doctor', text=text)
        self.assertIn('can never match', printed)

    def test_a_default_site_is_flagged_as_widening_exposure(self):
        text = CONFIG.replace('[sites]\nenabled = true',
                              '[sites]\nenabled = true\ndefault_site = "main"')
        _, printed, _ = self.run_command('doctor', text=text)
        self.assertIn("policy is applied to traffic nobody configured", printed)

    def test_a_site_allowed_to_block_the_host_is_flagged(self):
        """Not an error — but an operator should have meant it."""
        text = CONFIG.replace('profile = "website"',
                              'profile = "website"\nallow_host_network_block = true', 1)
        _, printed, _ = self.run_command('doctor', text=text)
        self.assertIn('EVERY site on this server', printed)

    def test_missing_baselines_are_reported_as_not_configured_not_broken(self):
        config = load_config(str(self.write()))
        from eye_for_an_eye.sites.engine import from_config
        report = doctor(config, from_config(config))
        self.assertEqual(report['baselines']['status'], NOT_CONFIGURED)
        self.assertIn('INSUFFICIENT_DATA', report['baselines']['reason'])

    def test_using_the_base_model_is_not_reported_as_degraded(self):
        config = load_config(str(self.write()))
        from eye_for_an_eye.sites.engine import from_config
        report = doctor(config, from_config(config))
        self.assertNotEqual(report['models']['status'], DEGRADED)

    def test_the_report_is_json_serialisable(self):
        config = load_config(str(self.write()))
        from eye_for_an_eye.sites.engine import from_config
        json.dumps(doctor(config, from_config(config)))

    def test_doctor_changes_no_file(self):
        path = self.write()
        before = {item: (item.stat().st_mtime_ns, item.stat().st_size)
                  for item in self.root.rglob('*') if item.is_file()}
        with contextlib.redirect_stdout(io.StringIO()):
            sites_command(['doctor', '--config', str(path)])
        after = {item: (item.stat().st_mtime_ns, item.stat().st_size)
                 for item in self.root.rglob('*') if item.is_file()}
        self.assertEqual(before, after)

    def test_the_module_reaches_no_network_and_runs_no_subprocess(self):
        import ast
        from eye_for_an_eye import sites_cli
        tree = ast.parse(Path(sites_cli.__file__).read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for forbidden in ('socket', 'urllib', 'http', 'requests', 'subprocess',
                          'asyncio'):
            self.assertNotIn(forbidden, imported)


class TestBaselineAndDrift(Base):
    """§89, §149. A site with no baseline says so."""

    def test_a_missing_baseline_is_reported_as_missing(self):
        _, printed, _ = self.run_command('baseline', 'main')
        self.assertIn('MISSING', printed)

    def test_the_baseline_view_refuses_to_call_anything_an_attack(self):
        _, printed, _ = self.run_command('baseline', 'main')
        self.assertIn('not evidence of an attack', printed)

    def test_drift_against_no_baseline_is_insufficient_data(self):
        _, printed, _ = self.run_command('drift', 'main')
        self.assertIn('INSUFFICIENT_DATA', printed)
        self.assertIn('not a failure', printed)

    def test_drift_recommends_staying_in_shadow(self):
        _, printed, _ = self.run_command('drift', 'main')
        self.assertIn('Shadow Mode', printed)

    def test_drift_says_another_sites_traffic_does_not_count(self):
        """§139. The isolation property, stated where an operator reads it."""
        _, printed, _ = self.run_command('drift', 'main')
        self.assertIn('does not make this site drifted', printed)

    def test_drift_json_reports_the_baseline_in_use(self):
        _, printed, _ = self.run_command('drift', 'main', '--json')
        document = json.loads(printed)
        self.assertEqual(document['site_id'], 'main')
        self.assertFalse(document['comparable'])


class TestModels(Base):
    def test_a_site_without_a_registry_is_told_the_maths_decides(self):
        _, printed, _ = self.run_command('models', 'main')
        self.assertIn('mathematical engine', printed)

    def test_the_output_explains_that_sharing_a_model_is_intended(self):
        """§31. Otherwise it reads as a missing feature."""
        _, printed, _ = self.run_command('models', 'main')
        self.assertIn('not a deficiency', printed)


if __name__ == '__main__':
    unittest.main()
