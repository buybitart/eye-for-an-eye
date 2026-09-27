"""Startup evidence, from the runtime rather than from the file. P15S §3, §4, §9, §10.

§4 says it in one line -- *do not rely on configuration text alone* -- and the
reason is the one this whole cycle keeps finding. A configuration that says
`mode = "shadow"` and a pipeline that came up in some other state are different
facts, and traffic meets the second one. P15.5R found exactly that shape twice:
`autonomy status` reported AUTONOMOUS for a shadow configuration because the
runtime read `enabled` and not `mode`, and the first repair was a silent no-op
because two modules spell the same mode in different case.

So the preflight constructs the pipeline and reads it. These tests check that it
reads the pipeline and not the settings, that it says what would happen to a
host enforcer rather than building one to find out (§3), and that it answers the
one question about site mapping nothing else was asking (§10).
"""
import io
import contextlib
import json
from pathlib import Path
import tempfile
import unittest

from eye_for_an_eye.autonomy.scope import resolved_profile_mapping
from eye_for_an_eye.autonomy_cli import (autonomy_command, preflight_document,
                                         render_preflight)
from eye_for_an_eye.config import Config


def shadow_config(directory, **kwargs):
    config = Config()
    config.autonomy.enabled = True
    config.autonomy.mode = 'shadow'
    config.autonomy.decision_journal_path = str(Path(directory) / 'journal.jsonl')
    config.autonomy.shadow_export_path = str(Path(directory) / 'export.jsonl')
    for key, value in kwargs.items():
        setattr(config.autonomy, key, value)
    return config


class PreflightCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)

    def config(self, **kwargs):
        return shadow_config(self.directory, **kwargs)


class TestTheModeComesFromThePipeline(PreflightCase):
    def test_a_shadow_configuration_reports_shadow(self):
        document = preflight_document(self.config())
        self.assertTrue(document['runtime']['shadow'])
        self.assertEqual(document['runtime']['mode'], 'shadow')

    def test_the_mode_is_read_from_the_constructed_pipeline(self):
        """Not from `config.autonomy.mode`, which is the text §4 distrusts."""
        from eye_for_an_eye.autonomy.pipeline import from_config
        config = self.config()
        pipeline = from_config(config, attach_enforcer=False, attach_journal=False)
        self.assertEqual(preflight_document(config)['runtime']['mode'],
                         pipeline.health()['mode'])

    def test_an_autonomous_configuration_is_warned_about(self):
        """§3 requires shadow for the whole period, so this is not a detail."""
        config = self.config()
        config.autonomy.mode = 'autonomous'
        document = preflight_document(config)
        self.assertFalse(document['runtime']['shadow'])
        self.assertFalse(document['ready_for_shadow'])
        self.assertTrue(any('requires SHADOW' in warning
                            for warning in document['warnings']))

    def test_every_component_of_the_decision_path_is_named(self):
        """§4's checklist, answered in §20's four words."""
        components = preflight_document(self.config())['runtime']['components']
        for name in ('decision_authority', 'calibrator', 'cost_policy',
                     'scope_resolver', 'policy_guard', 'enforcement',
                     'decision_journal', 'shadow_export'):
            with self.subTest(component=name):
                self.assertIn(name, components)

    def test_a_configured_journal_and_export_report_as_configured(self):
        components = preflight_document(self.config())['runtime']['components']
        self.assertNotEqual(components['decision_journal'], 'NOT_CONFIGURED')
        self.assertNotEqual(components['shadow_export'], 'NOT_CONFIGURED')

    def test_an_unconfigured_export_is_warned_about(self):
        config = self.config(shadow_export_path='')
        document = preflight_document(config)
        self.assertFalse(document['ready_for_shadow'])
        self.assertTrue(any('no shadow export' in warning
                            for warning in document['warnings']))

    def test_an_unconfigured_journal_is_warned_about(self):
        """Without it there is nothing to reconcile the export against (§42)."""
        document = preflight_document(self.config(decision_journal_path=''))
        self.assertTrue(any('nothing to reconcile' in warning or
                            'canonical record' in warning
                            for warning in document['warnings']))


class TestTheEnforcementInvariant(PreflightCase):
    """§3. Reported, not demonstrated by building one."""

    def test_the_preflight_attaches_no_enforcer(self):
        enforcement = preflight_document(self.config())['enforcement']
        self.assertFalse(enforcement['host_enforcer_attached_by_this_preflight'])

    def test_a_shadow_configuration_would_not_attach_one_either(self):
        enforcement = preflight_document(self.config())['enforcement']
        self.assertFalse(enforcement['this_configuration_would_attach_one'])
        self.assertEqual(enforcement['autonomous_action'], 'DISABLED')

    def test_an_autonomous_host_configuration_says_it_would(self):
        """The answer an operator needs *before* starting, not after."""
        config = self.config()
        config.autonomy.mode = 'autonomous'
        config.enforcement.host_enabled = True
        enforcement = preflight_document(config)['enforcement']
        self.assertTrue(enforcement['this_configuration_would_attach_one'])
        self.assertEqual(enforcement['autonomous_action'], 'ENABLED')

    def test_the_invariant_is_stated_in_words(self):
        enforcement = preflight_document(self.config())['enforcement']
        self.assertIn('actual host TEMP_BLOCK must be 0',
                      enforcement['invariant'])


class TestTheProfileMapping(PreflightCase):
    """§10. Which cutoff each site is actually priced at."""

    def sites(self, mapping):
        config = self.config()
        config.sites.enabled = True
        config.sites.profiles = {name: {'profile': value}
                                 for name, value in mapping.items()}
        return config

    def test_multi_site_off_is_reported_as_one_default_profile(self):
        mapping = resolved_profile_mapping(self.config())
        self.assertFalse(mapping['multi_site'])
        self.assertEqual(mapping['sites'], [])
        self.assertEqual(mapping['default_profile'], 'public_website')

    def test_an_unpriced_site_is_flagged_as_falling_back(self):
        """The finding this exists for: it looks exactly like a priced one."""
        config = self.sites({'main': 'website', 'api': 'api'})
        mapping = resolved_profile_mapping(config)
        self.assertEqual({row['site'] for row in mapping['sites']},
                         {'main', 'api'})
        self.assertTrue(all(row['fell_back_to_default'] for row in mapping['sites']))
        self.assertEqual(sorted(mapping['sites_on_the_default']), ['api', 'main'])

    def test_a_priced_site_resolves_to_its_own_profile(self):
        config = self.sites({'main': 'website', 'api': 'api'})
        config.autonomy.cost_profiles = {'SITE:api': 'api'}
        rows = {row['site']: row for row in resolved_profile_mapping(config)['sites']}
        self.assertEqual(rows['api']['cost_profile'], 'api')
        self.assertFalse(rows['api']['fell_back_to_default'])
        self.assertEqual(rows['main']['cost_profile'], 'public_website')
        self.assertTrue(rows['main']['fell_back_to_default'])

    def test_the_cutoff_that_will_be_applied_is_recorded(self):
        """§36 reports per profile; the cutoff is what makes that mean anything."""
        config = self.sites({'api': 'api'})
        config.autonomy.cost_profiles = {'SITE:api': 'api'}
        row, = resolved_profile_mapping(config)['sites']
        self.assertAlmostEqual(row['threshold'], 0.987654, places=6)

    def test_the_preflight_warns_when_a_site_is_on_the_default(self):
        document = preflight_document(self.sites({'api': 'api'}))
        self.assertTrue(any('resolve to the default cost profile' in warning
                            for warning in document['warnings']))

    def test_the_note_says_why_a_fallback_is_not_a_malfunction(self):
        mapping = resolved_profile_mapping(self.config())
        self.assertIn('indistinguishable from a site somebody meant to price',
                      mapping['note'])

    def test_resolving_changes_nothing(self):
        """It prices nothing and decides nothing; it reports."""
        config = self.sites({'api': 'api'})
        before = dict(config.autonomy.cost_profiles or {})
        resolved_profile_mapping(config)
        self.assertEqual(dict(config.autonomy.cost_profiles or {}), before)


class TestTheStoragePaths(PreflightCase):
    """§9, and an honest account of what the check is."""

    def test_a_writable_directory_passes(self):
        paths = {row['role']: row for row
                 in preflight_document(self.config())['storage']['paths']}
        self.assertEqual(paths['shadow_export']['status'], 'PASS')

    def test_a_directory_that_does_not_exist_fails(self):
        config = self.config(shadow_export_path='/nonexistent-dir-p15s/export.jsonl')
        document = preflight_document(config)
        paths = {row['role']: row for row in document['storage']['paths']}
        self.assertEqual(paths['shadow_export']['status'], 'FAIL')
        self.assertFalse(document['ready_for_shadow'])

    def test_an_unconfigured_path_is_not_a_failure(self):
        paths = {row['role']: row for row in
                 preflight_document(self.config(decision_journal_path=''))
                 ['storage']['paths']}
        self.assertEqual(paths['decision_journal']['status'], 'NOT_CONFIGURED')

    def test_the_check_says_what_it_is_not(self):
        """Attaching the writers proves nothing: they open on first write."""
        note = preflight_document(self.config())['storage']['note']
        self.assertIn('not a write', note)
        self.assertIn('open lazily', note)


class TestTheCommand(PreflightCase):
    def run_command(self, config):
        path = self.directory / 'config.toml'
        path.write_text(
            '[decision]\nenabled = true\n\n'
            '[autonomy]\nenabled = true\nmode = "shadow"\n'
            f'decision_journal_path = "{config.autonomy.decision_journal_path}"\n'
            f'shadow_export_path = "{config.autonomy.shadow_export_path}"\n',
            encoding='utf-8')
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = autonomy_command(['preflight', '--config', str(path), '--json'])
        return status, json.loads(out.getvalue())

    def test_it_runs_from_a_configuration_file_and_exits_zero_when_ready(self):
        status, document = self.run_command(self.config())
        self.assertTrue(document['ready_for_shadow'], document['warnings'])
        self.assertEqual(status, 0)

    def test_the_rendered_page_separates_the_readiness_gate_from_this_answer(self):
        """A NO from the autonomous gate is the expected answer before P15S."""
        rendered = render_preflight(preflight_document(self.config()))
        self.assertIn('Readiness gate (autonomous_ready): NO', rendered)
        self.assertIn('A shadow period does not need it to pass', rendered)
        self.assertIn('Ready to collect shadow evidence: YES', rendered)

    def test_the_document_says_to_keep_it_with_its_segment(self):
        """§46, §47: a configuration or code change starts a new segment."""
        self.assertIn('new evidence segment',
                      preflight_document(self.config())['note'])


if __name__ == '__main__':
    unittest.main()
