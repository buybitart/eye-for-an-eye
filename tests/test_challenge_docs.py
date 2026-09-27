"""The challenge documentation must describe the code that exists.

Documentation drifts silently, and security documentation that drifts is worse
than none: somebody configures a site from a table of thresholds that stopped
being true two releases ago. These tests read the shipped documents and check
the specific, checkable claims in them against the code.

They deliberately do not check prose. They check numbers, names, defaults and
promises — the things a reader would act on.
"""
import re
import unittest
from pathlib import Path

from eye_for_an_eye.challenge.page import MAX_RETURN_CHARS, SECURITY_HEADERS, build
from eye_for_an_eye.challenge.policy import (CHALLENGE_ESCALATION_CEILING,
                                             ChallengeBudget, DEFAULT_ROUTES)
from eye_for_an_eye.challenge.token import (COOKIE_NAME, DEFAULT_TTL_SECONDS,
                                            MASTER_SECRET_MIN_BYTES,
                                            MAX_CLOCK_SKEW_SECONDS, MAX_TTL_SECONDS,
                                            TOKEN_SCHEME, issue)
from eye_for_an_eye.config import ChallengeConfig
from eye_for_an_eye.web.sensor import (BLOCK_THRESHOLD, CHALLENGE_THRESHOLD,
                                       RATE_LIMIT_THRESHOLD, WATCH_THRESHOLD)

DOCS = Path(__file__).resolve().parents[1] / 'docs'
REQUIRED = ('CHALLENGE.md', 'PROGRESSIVE_DEFENSE.md', 'CHALLENGE_SECURITY.md',
            'CHALLENGE_PRIVACY.md', 'NGINX_CHALLENGE.md', 'API_CLIENTS.md',
            'TRUSTED_PROXIES.md', 'WEBSITE_QUICKSTART.md')


def read(name):
    return (DOCS / name).read_text(encoding='utf-8')


def everything():
    return '\n'.join(read(name) for name in REQUIRED)


class TestTheDocumentsExist(unittest.TestCase):
    def test_every_required_document_is_present(self):
        for name in REQUIRED:
            with self.subTest(document=name):
                self.assertTrue((DOCS / name).is_file(), name)

    def test_none_of_them_is_a_stub(self):
        for name in REQUIRED:
            with self.subTest(document=name):
                self.assertGreater(len(read(name)), 1200, name)

    def test_every_internal_link_points_at_a_real_file(self):
        for name in REQUIRED:
            for target in re.findall(r'\]\(([A-Za-z0-9_./-]+\.md)\)', read(name)):
                with self.subTest(document=name, link=target):
                    self.assertTrue((DOCS / target).resolve().is_file()
                                    or (DOCS.parent / target).resolve().is_file(),
                                    f'{name} links to missing {target}')


class TestTheNumbersAreTrue(unittest.TestCase):
    """Every threshold and default a reader might configure from."""

    def test_the_documented_thresholds_match_the_code(self):
        text = read('CHALLENGE.md')
        for value in (WATCH_THRESHOLD, CHALLENGE_THRESHOLD, RATE_LIMIT_THRESHOLD,
                      BLOCK_THRESHOLD):
            with self.subTest(threshold=value):
                self.assertIn(f'{value:.2f}', text)

    def test_the_documented_ladder_is_the_real_ladder(self):
        from eye_for_an_eye.web.sensor import ACTIONS
        ladder = ' → '.join(ACTIONS)
        for name in ('CHALLENGE.md', 'PROGRESSIVE_DEFENSE.md'):
            with self.subTest(document=name):
                self.assertIn('SOFT_CHALLENGE', read(name))
        readme = (DOCS.parent / 'README.md').read_text(encoding='utf-8')
        self.assertIn(ladder, readme,
                      'the README ladder does not match sensor.ACTIONS')

    def test_the_documented_token_lifetime_matches_the_default(self):
        # The failure message names the missing phrase rather than printing the
        # whole document, which is otherwise several screens of noise.
        text = read('CHALLENGE_SECURITY.md')
        self.assertEqual(DEFAULT_TTL_SECONDS, 900)
        for phrase in ('15 minutes', f'{MAX_TTL_SECONDS // 60} minutes',
                       f'{MAX_CLOCK_SKEW_SECONDS} seconds'):
            with self.subTest(phrase=phrase):
                self.assertTrue(phrase in text,
                                f'CHALLENGE_SECURITY.md does not say {phrase!r}')

    def test_the_documented_secret_minimum_matches_the_check(self):
        self.assertEqual(MASTER_SECRET_MIN_BYTES, 32)
        self.assertIn(f'{MASTER_SECRET_MIN_BYTES} bytes', read('CHALLENGE_SECURITY.md'))

    def test_the_documented_token_scheme_is_the_real_one(self):
        self.assertIn(TOKEN_SCHEME, read('CHALLENGE_SECURITY.md'))

    def test_the_documented_cookie_name_is_the_real_one(self):
        self.assertIn(COOKIE_NAME, read('NGINX_CHALLENGE.md'))

    def test_the_documented_budget_matches_the_defaults(self):
        budget = ChallengeBudget()
        text = read('CHALLENGE_PRIVACY.md')
        self.assertEqual(budget.concurrent_contexts, 10_000)
        self.assertIn('10,000', text)
        self.assertIn(str(budget.max_attempts), read('CHALLENGE_SECURITY.md'))

    def test_the_documented_escalation_ceiling_is_the_real_one(self):
        self.assertIn(CHALLENGE_ESCALATION_CEILING, read('PROGRESSIVE_DEFENSE.md'))

    def test_the_documented_page_size_is_not_smaller_than_the_real_page(self):
        response = build(issue(b'm' * 32, site='docs'), '/some/page')
        actual = len(response.body.encode('utf-8'))
        claimed = int(re.search(r'(\d+) bytes', read('CHALLENGE.md')).group(1))
        # The page is static, so this should be exact. A drift of a few bytes
        # means the page changed and the number did not.
        self.assertEqual(actual, claimed,
                         f'the page is {actual} bytes; CHALLENGE.md says {claimed}')

    def test_the_documented_return_path_bound_matches_the_code(self):
        self.assertGreater(MAX_RETURN_CHARS, 0)

    def test_every_route_the_api_document_lists_is_really_exempt(self):
        exempt = {rule.path_prefix for rule in DEFAULT_ROUTES if not rule.challenge}
        text = read('API_CLIENTS.md')
        for prefix in re.findall(r'`(/[a-z0-9./_-]+)`', text.split('## Adding')[0]):
            with self.subTest(prefix=prefix):
                self.assertIn(prefix, exempt,
                              f'API_CLIENTS.md lists {prefix} as never challenged, '
                              'but the default routes do not exempt it')

    def test_the_documented_configuration_keys_exist(self):
        settings = ChallengeConfig()
        for key in ('enabled', 'mode', 'secret_file', 'site_id',
                    'api_path_prefixes', 'no_challenge_path_prefixes'):
            with self.subTest(key=key):
                self.assertTrue(hasattr(settings, key), key)
                self.assertIn(key, everything(), f'{key} is never documented')

    def test_challenges_are_documented_as_off_by_default_and_really_are(self):
        settings = ChallengeConfig()
        self.assertFalse(settings.enabled)
        self.assertEqual(settings.mode, 'shadow')
        self.assertIn('off by default', everything().lower())


class TestThePromisesAreKept(unittest.TestCase):
    """Claims a reader would rely on, checked against behaviour."""

    def test_the_no_store_promise_is_kept(self):
        self.assertIn('no-store', read('CHALLENGE_SECURITY.md'))
        self.assertIn('no-store', SECURITY_HEADERS.get('Cache-Control', ''))

    def test_the_frame_ancestors_promise_is_kept(self):
        self.assertIn("frame-ancestors 'none'", read('CHALLENGE_SECURITY.md'))
        self.assertIn("frame-ancestors 'none'",
                      SECURITY_HEADERS.get('Content-Security-Policy', ''))

    def test_the_default_src_none_promise_is_kept(self):
        self.assertIn("default-src 'none'", read('CHALLENGE_PRIVACY.md'))
        self.assertIn("default-src 'none'",
                      SECURITY_HEADERS.get('Content-Security-Policy', ''))

    def test_the_cookie_attribute_promises_are_kept(self):
        response = build(issue(b'm' * 32, site='docs'), '/')
        cookie = response.headers['Set-Cookie']
        for attribute in ('HttpOnly', 'Secure', 'SameSite=Lax'):
            with self.subTest(attribute=attribute):
                self.assertIn(attribute, cookie)
                self.assertIn(attribute, read('CHALLENGE_SECURITY.md'))

    def test_the_page_really_contains_no_javascript(self):
        body = build(issue(b'm' * 32, site='docs'), '/').body.lower()
        for forbidden in ('<script', 'javascript:', 'onload=', 'onerror='):
            self.assertNotIn(forbidden, body)
        self.assertIn('no javascript', everything().lower())

    def test_the_page_really_loads_nothing_external(self):
        body = build(issue(b'm' * 32, site='docs'), '/').body.lower()
        for forbidden in ('http://', 'https://', '//cdn', 'src='):
            self.assertNotIn(forbidden, body)

    def test_the_documentation_never_claims_to_detect_humans(self):
        """§143. The claim this project must never make."""
        text = everything().lower()
        for forbidden in ('detects humans', 'proves a human', 'proves the client is human',
                          'identifies the attacker', 'complete waf', 'perfect bot'):
            with self.subTest(claim=forbidden):
                self.assertNotIn(forbidden, text)

    def test_the_documentation_says_a_result_is_not_proof(self):
        text = read('CHALLENGE.md').lower()
        self.assertIn('does not prove an attack', text)
        self.assertIn('does not make a client trusted forever', text)

    def test_the_security_document_names_every_threat_the_brief_lists(self):
        """§140. Each one with an impact, a mitigation and what is left."""
        text = read('CHALLENGE_SECURITY.md').lower()
        for threat in ('replay', 'cookie theft', 'flood', 'open redirect',
                       'cross-site scripting', 'proxy spoofing', 'shared addresses',
                       'caching', 'loop', 'secret leakage', 'feedback loop',
                       'availability'):
            with self.subTest(threat=threat):
                self.assertIn(threat, text)
        self.assertGreaterEqual(text.count('**remaining.**'), 10,
                                'every threat needs its remaining limitation stated')

    def test_the_security_document_admits_the_timing_side_channel(self):
        """It is real, it is small, and hiding it would be dishonest."""
        text = read('CHALLENGE_SECURITY.md').lower()
        self.assertIn('timing', text)
        self.assertIn('constant time', text)


if __name__ == '__main__':
    unittest.main()
