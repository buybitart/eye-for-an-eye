"""P12 Phase 2 (§10-§14, §43-§49, §79): site settings and the safety ordering.

Two properties carry most of the weight here.

**A site cannot reach past a global safety limit.** A site override can adjust
that site's own behaviour; it cannot touch memory bounds, protected networks or
firewall ownership. This is enforced structurally — those things are not fields
on a site profile, so there is nothing to override — and the tests check that
the structure really is the enforcement.

**A configuration is validated whole or not at all.** Partly applying a security
configuration is worse than refusing it: some sites protected under new rules,
some under old, and nothing that says which.
"""
import unittest

from eye_for_an_eye.sites.identity import SiteResolverError
from eye_for_an_eye.sites.profile import (ADMIN, API, BOUNDS, CUSTOM, MAX_ROUTE_PREFIXES,
                                          MIXED, OVERRIDABLE, PROFILE_TYPES,
                                          SiteProfileError, SiteSettings, TEMPLATES,
                                          WEBSITE, build_all, build_profile,
                                          build_settings)

MAIN = 'example.org'
API_HOST = 'api.example.org'


class TestTemplates(unittest.TestCase):
    """§43-§47. Starter configurations, and what each one assumes."""

    def test_every_profile_type_has_a_template(self):
        self.assertEqual(set(TEMPLATES), set(PROFILE_TYPES))

    def test_every_template_produces_valid_settings(self):
        for profile_type in PROFILE_TYPES:
            with self.subTest(profile=profile_type):
                build_settings(profile_type)

    def test_an_api_tolerates_a_far_higher_rate_than_an_admin_panel(self):
        """The core claim of this whole stage, as a number."""
        api = build_settings(API)
        admin = build_settings(ADMIN)
        self.assertGreater(api.expected_requests_per_minute,
                           admin.expected_requests_per_minute * 10)

    def test_an_api_does_not_use_browser_challenges(self):
        """§45. A machine client cannot answer one."""
        self.assertFalse(build_settings(API).challenge_enabled)
        self.assertTrue(build_settings(WEBSITE).challenge_enabled)

    def test_an_admin_panel_is_more_sensitive_than_a_public_website(self):
        """§46. Path breadth and auth failures mean more on a quiet site."""
        admin = build_settings(ADMIN)
        website = build_settings(WEBSITE)
        self.assertLess(admin.watch_threshold, website.watch_threshold)
        self.assertLess(admin.expected_unique_paths, website.expected_unique_paths)

    def test_an_api_expects_the_methods_an_api_uses(self):
        self.assertIn('DELETE', build_settings(API).expected_methods)
        self.assertNotIn('DELETE', build_settings(WEBSITE).expected_methods)

    def test_the_custom_template_assumes_nothing(self):
        self.assertEqual(TEMPLATES[CUSTOM], {})
        self.assertEqual(build_settings(CUSTOM), SiteSettings())

    def test_the_mixed_template_is_the_least_opinionated_of_the_shaped_ones(self):
        mixed = build_settings(MIXED)
        admin = build_settings(ADMIN)
        self.assertGreater(mixed.expected_unique_paths, admin.expected_unique_paths)

    def test_no_template_arrives_enforcing(self):
        """§157. A new site is never born blocking anybody."""
        for profile_type in PROFILE_TYPES:
            with self.subTest(profile=profile_type):
                settings = build_settings(profile_type)
                self.assertEqual(settings.mode, 'shadow')
                self.assertFalse(settings.rate_limit_enabled)
                self.assertFalse(settings.allow_host_network_block)

    def test_an_unknown_profile_type_is_refused(self):
        with self.assertRaises(SiteProfileError):
            build_settings('e-commerce-pro')


class TestInheritance(unittest.TestCase):
    """§12. Global defaults, then the template, then the site's own changes."""

    def test_an_override_wins_over_the_template(self):
        settings = build_settings(API, {'expected_requests_per_minute': 50.0})
        self.assertEqual(settings.expected_requests_per_minute, 50.0)

    def test_the_template_wins_over_the_global_default(self):
        self.assertNotEqual(build_settings(API).expected_requests_per_minute,
                            SiteSettings().expected_requests_per_minute)

    def test_a_field_nobody_set_keeps_the_global_default(self):
        self.assertEqual(build_settings(API).minimum_quality,
                         SiteSettings().minimum_quality)

    def test_a_site_may_switch_its_own_challenge_on(self):
        self.assertTrue(build_settings(API, {'challenge_enabled': True}).challenge_enabled)

    def test_a_misspelled_setting_is_refused_rather_than_ignored(self):
        """Silently dropping it leaves an operator believing a site is tightened."""
        for typo in ('watch_treshold', 'block_thresold', 'challenge_enable',
                     'expected_requests_per_min'):
            with self.subTest(typo=typo):
                with self.assertRaises(SiteProfileError):
                    build_settings(WEBSITE, {typo: 0.5})


class TestGlobalSafetyOutranksSitePolicy(unittest.TestCase):
    """§13, §14. The property that keeps one bad site from spoiling the host."""

    def test_a_site_has_no_field_for_any_global_safety_limit(self):
        """Structural enforcement: there is nothing here to override."""
        forbidden = ('max_state_bytes', 'max_sources_global', 'protected_networks',
                     'firewall', 'nftables', 'max_sites', 'memory_limit',
                     'process_limit', 'rlimit', 'run_as_root', 'bind_address',
                     'auto_promote')
        for name in forbidden:
            with self.subTest(field=name):
                self.assertNotIn(name, OVERRIDABLE)

    def test_a_site_cannot_set_a_global_safety_limit_by_naming_it(self):
        for name in ('max_state_bytes', 'protected_networks', 'auto_promote',
                     'max_sources_global', 'firewall_enabled'):
            with self.subTest(field=name):
                with self.assertRaises(SiteProfileError):
                    build_settings(WEBSITE, {name: 999})

    def test_host_wide_network_blocking_is_off_unless_a_site_asks(self):
        """§96-§99. A network block reaches every site on the machine."""
        self.assertFalse(build_settings(WEBSITE).allow_host_network_block)
        asked = build_settings(WEBSITE, {'allow_host_network_block': True})
        self.assertTrue(asked.allow_host_network_block)

    def test_an_allowlist_is_bounded(self):
        with self.assertRaises(SiteProfileError):
            build_settings(WEBSITE, {'allowlist': [f'10.0.0.{n}' for n in range(200)]})


class TestBounds(unittest.TestCase):
    """A setting outside its bounds is refused, not clamped silently."""

    def test_every_bounded_setting_refuses_values_outside_its_range(self):
        for name, (low, high) in BOUNDS.items():
            with self.subTest(setting=name):
                with self.assertRaises(SiteProfileError):
                    build_settings(WEBSITE, {name: low - 1})
                with self.assertRaises(SiteProfileError):
                    build_settings(WEBSITE, {name: high * 10 + 1})

    def test_a_threshold_of_zero_is_refused(self):
        """It would act on every visitor to the site."""
        with self.assertRaises(SiteProfileError):
            build_settings(WEBSITE, {'block_threshold': 0.0})

    def test_retention_cannot_be_unbounded(self):
        with self.assertRaises(SiteProfileError):
            build_settings(WEBSITE, {'retention_days': 100_000})


class TestTheLadderMustBeALadder(unittest.TestCase):
    def test_out_of_order_thresholds_are_refused(self):
        with self.assertRaises(SiteProfileError) as raised:
            build_settings(WEBSITE, {'challenge_threshold': 0.9,
                                     'rate_limit_threshold': 0.7})
        self.assertIn('unreachable', str(raised.exception))

    def test_equal_thresholds_are_refused(self):
        with self.assertRaises(SiteProfileError):
            build_settings(WEBSITE, {'watch_threshold': 0.5,
                                     'challenge_threshold': 0.5})

    def test_every_template_has_an_ordered_ladder(self):
        for profile_type in PROFILE_TYPES:
            with self.subTest(profile=profile_type):
                settings = build_settings(profile_type)
                self.assertLess(settings.watch_threshold, settings.challenge_threshold)
                self.assertLess(settings.challenge_threshold, settings.rate_limit_threshold)
                self.assertLess(settings.rate_limit_threshold, settings.block_threshold)


class TestRouteBounds(unittest.TestCase):
    """§49. A pathological route list is a slow path for every request."""

    def test_too_many_prefixes_are_refused(self):
        many = [f'/route{index}/' for index in range(MAX_ROUTE_PREFIXES + 1)]
        with self.assertRaises(SiteProfileError):
            build_settings(WEBSITE, {'api_path_prefixes': many})

    def test_an_enormous_prefix_is_refused(self):
        with self.assertRaises(SiteProfileError):
            build_settings(WEBSITE, {'api_path_prefixes': ['/' + 'x' * 5000]})

    def test_a_prefix_must_be_a_path(self):
        for bad in ('api/', 'https://evil.test/', '*'):
            with self.subTest(prefix=bad):
                with self.assertRaises(SiteProfileError):
                    build_settings(WEBSITE, {'api_path_prefixes': [bad]})


class TestProfiles(unittest.TestCase):
    def test_a_profile_carries_its_domains_normalised(self):
        profile = build_profile('main', {'profile': WEBSITE,
                                         'domains': [MAIN.upper(), f'{MAIN}:443']})
        self.assertEqual(profile.domains, (MAIN,))

    def test_a_profile_defaults_to_the_global_base_model(self):
        """§29-§31. One validated base model beats several weak site models."""
        self.assertEqual(build_profile('main', {}).model_scope, '')
        self.assertEqual(build_profile('main', {}).explain()['model_scope'], 'global')

    def test_the_challenge_scope_is_the_site_id(self):
        self.assertEqual(build_profile('main', {}).challenge_site_id, 'main')

    def test_a_profile_is_frozen(self):
        profile = build_profile('main', {})
        with self.assertRaises(Exception):
            profile.settings.watch_threshold = 0.9

    def test_a_profile_explains_that_its_type_is_not_a_label(self):
        note = build_profile('main', {}).explain()['note']
        self.assertIn('never a label', note)
        self.assertIn('never a model input', note)

    def test_an_unknown_key_in_a_site_spec_is_refused(self):
        with self.assertRaises(SiteProfileError):
            build_profile('main', {'profile': WEBSITE, 'danger_mode': True})

    def test_a_bad_domain_stops_the_site_being_built(self):
        with self.assertRaises(SiteProfileError):
            build_profile('main', {'domains': ['exa mple.org']})


class TestWholeConfigurationValidation(unittest.TestCase):
    """§79. Whole, or nothing."""

    def test_a_good_configuration_builds(self):
        profiles = build_all({'main': {'profile': WEBSITE, 'domains': [MAIN]},
                              'api': {'profile': API, 'domains': [API_HOST]}})
        self.assertEqual(set(profiles), {'main', 'api'})

    def test_one_bad_site_stops_the_whole_configuration(self):
        with self.assertRaises(SiteProfileError):
            build_all({'main': {'profile': WEBSITE, 'domains': [MAIN]},
                       'broken': {'profile': 'not-a-profile'}})

    def test_nothing_is_returned_when_one_site_is_bad(self):
        """Not "main was built and broken was skipped" — nothing at all."""
        try:
            build_all({'main': {'domains': [MAIN]}, 'broken': {'profile': 'nope'}})
        except SiteProfileError:
            pass
        else:
            self.fail('a bad site should stop the configuration')

    def test_a_duplicate_domain_across_sites_is_rejected(self):
        with self.assertRaises(SiteResolverError):
            build_all({'main': {'domains': [MAIN]}, 'other': {'domains': [MAIN]}})

    def test_a_duplicate_domain_in_a_different_spelling_is_rejected(self):
        with self.assertRaises(SiteResolverError):
            build_all({'main': {'domains': [MAIN]},
                       'other': {'domains': [f'{MAIN.upper()}:443']}})

    def test_too_many_sites_is_rejected_with_the_reason(self):
        many = {f'site{index}': {'domains': [f'{index}.example.test']}
                for index in range(30)}
        with self.assertRaises(SiteProfileError) as raised:
            build_all(many, max_sites=10)
        self.assertIn('bounded', str(raised.exception))

    def test_an_empty_configuration_is_valid(self):
        """A single-site owner configures no sites and nothing breaks."""
        self.assertEqual(build_all({}), {})
        self.assertEqual(build_all(None), {})


if __name__ == '__main__':
    unittest.main()
