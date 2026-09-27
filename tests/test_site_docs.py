"""The multi-site documentation must describe the code that exists.

Same reasoning as the P11 documentation tests: security documentation that
drifts is worse than none, because somebody configures a server from a table of
defaults that stopped being true two releases ago.

These check the specific, checkable claims — numbers, names, defaults, promises
— and deliberately not the prose.
"""
import re
import unittest
from pathlib import Path

from eye_for_an_eye.config import SitesConfig
from eye_for_an_eye.sites.baseline import (MIN_SAMPLES, MIN_SOURCES,
                                           PROVENANCE_CONFIDENCE, STATES)
from eye_for_an_eye.sites.engine import NETWORK_HOST_BLOCK, SITE_WEB_ACTION
from eye_for_an_eye.sites.identity import UNKNOWN_SITE
from eye_for_an_eye.sites.profile import (ADMIN, API, MAX_PREFIX_CHARS,
                                          MAX_ROUTE_PREFIXES, PROFILE_TYPES, WEBSITE,
                                          build_settings)
from eye_for_an_eye.sites.state import (DEFAULT_MAX_PER_SITE,
                                        DEFAULT_RESERVED_PER_SITE, MAX_SOURCES_GLOBAL)

DOCS = Path(__file__).resolve().parents[1] / 'docs'
REQUIRED = ('MULTI_SITE.md', 'SITE_PROFILES.md', 'SITE_BASELINES.md',
            'MULTI_SITE_MODELS.md', 'CROSS_SITE_SECURITY.md', 'MULTI_SITE_NGINX.md',
            'SITE_DATASETS.md')


def read(name):
    return (DOCS / name).read_text(encoding='utf-8')


def flat(name):
    """One document with its line wrapping removed.

    Prose wraps, so "empty by default" is very often "empty by\ndefault" in the
    file. Matching against the raw text makes these tests fail on the position
    of a line break rather than on what the document says.
    """
    return ' '.join(read(name).split())


def everything():
    return ' '.join(flat(name) for name in REQUIRED)


class TestTheDocumentsExist(unittest.TestCase):
    def test_every_required_document_is_present(self):
        for name in REQUIRED:
            with self.subTest(document=name):
                self.assertTrue((DOCS / name).is_file(), name)

    def test_none_of_them_is_a_stub(self):
        for name in REQUIRED:
            with self.subTest(document=name):
                self.assertGreater(len(read(name)), 1500, name)

    def test_every_internal_link_points_at_a_real_file(self):
        for name in REQUIRED:
            for target in re.findall(r'\]\(([A-Za-z0-9_./-]+\.md)\)', read(name)):
                with self.subTest(document=name, link=target):
                    self.assertTrue((DOCS / target).is_file()
                                    or (DOCS.parent / target).is_file(),
                                    f'{name} links to missing {target}')

    def test_the_readme_links_to_the_multi_site_page(self):
        readme = (DOCS.parent / 'README.md').read_text(encoding='utf-8')
        self.assertIn('docs/MULTI_SITE.md', readme)


class TestTheNumbersAreTrue(unittest.TestCase):
    def test_the_documented_profile_defaults_match_the_templates(self):
        text = read('SITE_PROFILES.md')
        for profile in (WEBSITE, API, ADMIN):
            settings = build_settings(profile)
            with self.subTest(profile=profile):
                rate = f'{settings.expected_requests_per_minute:.0f}'
                self.assertIn(rate, text,
                              f'SITE_PROFILES.md does not mention {profile} rate {rate}')

    def test_the_documented_thresholds_match_the_admin_template(self):
        settings = build_settings(ADMIN)
        text = read('SITE_PROFILES.md')
        for value in (settings.watch_threshold, settings.block_threshold):
            with self.subTest(threshold=value):
                self.assertIn(f'{value:.2f}', text)

    def test_every_profile_type_is_documented(self):
        text = read('SITE_PROFILES.md').lower()
        for profile in PROFILE_TYPES:
            with self.subTest(profile=profile):
                self.assertIn(profile, text)

    def test_the_documented_budgets_match_the_defaults(self):
        text = read('MULTI_SITE.md')
        self.assertIn(str(MAX_SOURCES_GLOBAL), text)
        self.assertIn(str(DEFAULT_RESERVED_PER_SITE), text)
        self.assertIn(str(DEFAULT_MAX_PER_SITE), text)

    def test_the_documented_site_limit_matches_the_default(self):
        self.assertEqual(SitesConfig().max_sites, 32)
        self.assertIn('32', read('MULTI_SITE.md'))

    def test_the_documented_route_bounds_match_the_code(self):
        text = read('SITE_PROFILES.md')
        self.assertIn(str(MAX_ROUTE_PREFIXES), text)
        self.assertIn(str(MAX_PREFIX_CHARS), text)

    def test_the_documented_baseline_minimums_match_the_code(self):
        text = read('SITE_BASELINES.md')
        self.assertIn(str(MIN_SAMPLES), text)
        self.assertIn(str(MIN_SOURCES), text)

    def test_every_baseline_state_is_documented(self):
        text = read('SITE_BASELINES.md')
        for state in STATES:
            with self.subTest(state=state):
                self.assertIn(state, text)

    def test_the_documented_provenance_confidences_match_the_code(self):
        text = read('SITE_BASELINES.md')
        for name, score in PROVENANCE_CONFIDENCE.items():
            with self.subTest(provenance=name):
                self.assertIn(name, text)
                self.assertIn(f'{score}', text)

    def test_the_unknown_bucket_is_documented_by_its_real_name(self):
        self.assertIn(UNKNOWN_SITE, everything())

    def test_both_action_scopes_are_documented_by_name(self):
        text = read('CROSS_SITE_SECURITY.md')
        self.assertIn(SITE_WEB_ACTION, text)
        self.assertIn(NETWORK_HOST_BLOCK, text)


class TestThePromisesAreKept(unittest.TestCase):
    def test_multi_site_is_documented_as_off_by_default_and_really_is(self):
        self.assertFalse(SitesConfig().enabled)
        self.assertTrue('off by default' in everything().lower(),
                        'no document says multi-site is off by default')

    def test_the_default_site_is_documented_as_empty_and_really_is(self):
        self.assertEqual(SitesConfig().default_site, '')
        self.assertTrue('empty by default' in flat('MULTI_SITE_NGINX.md'),
                        'MULTI_SITE_NGINX.md does not say the default site is empty')

    def test_new_sites_are_documented_as_shadow_and_really_are(self):
        for profile in PROFILE_TYPES:
            with self.subTest(profile=profile):
                self.assertEqual(build_settings(profile).mode, 'shadow')
        self.assertTrue('shadow mode' in everything().lower(),
                        'no document says new sites start in shadow mode')

    def test_host_wide_blocking_is_documented_as_off_and_really_is(self):
        for profile in PROFILE_TYPES:
            with self.subTest(profile=profile):
                self.assertFalse(build_settings(profile).allow_host_network_block)

    def test_an_api_profile_is_documented_as_not_challenging_and_really_does_not(self):
        self.assertFalse(build_settings(API).challenge_enabled)
        self.assertTrue('cannot be answered' in flat('SITE_PROFILES.md'),
                        'SITE_PROFILES.md does not explain why API sites do not challenge')

    def test_the_documentation_states_the_host_header_rule(self):
        text = everything().lower()
        for phrase in ('never from a request', 'can never create one'):
            with self.subTest(phrase=phrase):
                self.assertTrue(phrase in text, f'no document says {phrase!r}')

    def test_the_documentation_admits_a_network_block_reaches_every_site(self):
        """The limitation that must not be softened."""
        text = flat('CROSS_SITE_SECURITY.md').lower()
        for phrase in ('every site on the machine', 'not preventable',
                       'real and unavoidable'):
            with self.subTest(phrase=phrase):
                self.assertTrue(phrase in text,
                                f'CROSS_SITE_SECURITY.md does not say {phrase!r}')

    def test_the_documentation_does_not_claim_hosting_scale_tenancy(self):
        text = everything().lower()
        for forbidden in ('unlimited tenants', 'any number of sites',
                          'hosting-provider multitenancy', 'fully isolated',
                          'complete isolation'):
            with self.subTest(claim=forbidden):
                self.assertNotIn(forbidden, text)

    def test_the_documentation_says_what_is_not_isolated(self):
        text = flat('CROSS_SITE_SECURITY.md').lower()
        for phrase in ('not a sandbox', 'share a process'):
            with self.subTest(phrase=phrase):
                self.assertTrue(phrase in text,
                                f'CROSS_SITE_SECURITY.md does not say {phrase!r}')

    def test_the_security_document_states_a_remaining_limit_for_every_threat(self):
        text = flat('CROSS_SITE_SECURITY.md').lower()
        self.assertGreaterEqual(text.count('**remaining.**'), 8,
                                'every threat needs its remaining limitation stated')

    def test_site_identity_is_documented_as_never_a_feature(self):
        from dataset.schema import NEVER_MODEL_INPUT
        text = read('SITE_DATASETS.md')
        for field in ('site_group', 'site_id', 'domain', 'host', 'profile_type'):
            with self.subTest(field=field):
                self.assertIn(field, text)
                self.assertIn(field, NEVER_MODEL_INPUT)

    def test_the_documentation_prefers_the_base_model(self):
        text = flat('MULTI_SITE_MODELS.md').lower()
        for phrase in ('not a deficiency', 'twenty labelled examples'):
            with self.subTest(phrase=phrase):
                self.assertTrue(phrase in text,
                                f'MULTI_SITE_MODELS.md does not say {phrase!r}')

    def test_auto_promotion_is_documented_as_off_by_default(self):
        """Narrowed in P14: the setting now exists, and is off.

        The earlier form of this test required the page to say "there is no
        setting that turns it on", which stopped being true when P14 added one.
        Requiring a document to repeat a claim the code has outgrown is how a
        test starts defending a lie, so what is checked now is the claim that is
        both true and worth defending: it is off unless somebody turns it on.
        """
        text = flat('MULTI_SITE_MODELS.md').lower()
        for phrase in ('auto_promote', 'is off', 'separate', 'worst'):
            with self.subTest(phrase=phrase):
                self.assertTrue(phrase in text,
                                f'MULTI_SITE_MODELS.md does not say {phrase!r}')


if __name__ == '__main__':
    unittest.main()
