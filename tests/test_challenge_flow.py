"""P11 challenge web flow: redirect safety, cookie attributes, page injection.

A challenge page is a page the security tool serves on the protected site. If it
can be made to redirect anywhere, it is a phishing tool hosted on the site it
defends. If it echoes a client-controlled value, it is a cross-site scripting
hole in the security layer. Both have happened to real products.
"""
import unittest

from eye_for_an_eye.challenge.page import (MAX_RESPONSE_BYTES, SAFE_METHODS,
                                           SECURITY_HEADERS, build, clear_cookie_header,
                                           cookie_header, encode_location, rate_limited,
                                           render, safe_return_path)
from eye_for_an_eye.challenge.token import COOKIE_NAME, issue

SECRET = b'm' * 32
NOW = 1_800_000_000


class TestOpenRedirect(unittest.TestCase):
    """§23, §102. The challenge must not become an open redirector."""

    def test_a_normal_local_path_survives(self):
        for path in ('/', '/blog', '/a/b/c', '/page?x=1', '/p#frag', '/a-b_c.html'):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path), path)

    def test_an_absolute_url_is_rejected(self):
        for path in ('https://evil.test/', 'http://evil.test/x',
                     'HTTPS://evil.test', 'hTtP://evil.test'):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path), '/')

    def test_a_protocol_relative_url_is_rejected(self):
        """`//evil.test` is a full URL to a browser."""
        for path in ('//evil.test/', '//evil.test', '/\\evil.test', '/\\\\evil.test'):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path), '/')

    def test_a_javascript_url_is_rejected(self):
        for path in ('javascript:alert(1)', 'JavaScript:alert(1)',
                     'java\tscript:alert(1)', ' javascript:alert(1)'):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path), '/')

    def test_a_data_url_is_rejected(self):
        for path in ('data:text/html,<script>alert(1)</script>', 'DATA:text/plain,x',
                     'blob:https://evil.test/x', 'file:///etc/passwd',
                     'vbscript:msgbox(1)', 'mailto:a@b.test'):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path), '/')

    def test_a_relative_path_without_a_leading_slash_is_rejected(self):
        for path in ('evil.test', '../../etc/passwd', 'x'):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path), '/')

    def test_control_characters_cannot_split_a_response(self):
        """A newline in a Location header is response splitting."""
        for path in ('/a\r\nLocation: https://evil.test', '/a\nSet-Cookie: x=1',
                     '/a\x00b', '/a\tb'):
            with self.subTest(path=path):
                cleaned = safe_return_path(path)
                self.assertNotIn('\r', cleaned)
                self.assertNotIn('\n', cleaned)
                self.assertNotIn('\x00', cleaned)

    def test_a_very_long_path_is_bounded(self):
        self.assertLessEqual(len(safe_return_path('/' + 'a' * 100_000)), 512)

    def test_an_empty_or_missing_path_becomes_root(self):
        for path in ('', None, '   '):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path), '/')

    def test_an_encoded_scheme_does_not_slip_through(self):
        for path in ('%2f%2fevil.test', '%6a%61%76%61script:alert(1)'):
            with self.subTest(path=path):
                self.assertEqual(safe_return_path(path)[:1], '/')
                self.assertNotIn('evil.test', encode_location(path).lower()
                                 .replace('%2f', '/').replace('%2e', '.')[:2])

    def test_a_location_header_is_percent_encoded(self):
        self.assertNotIn(' ', encode_location('/a b'))
        self.assertTrue(encode_location('/x').startswith('/'))


class TestPageSafety(unittest.TestCase):
    """§75, §116. Nothing attacker-controlled reaches the HTML unescaped."""

    def test_an_html_injection_attempt_is_escaped(self):
        page = render('/"><script>alert(1)</script>')
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertNotIn('"><script', page)

    def test_an_attribute_break_out_is_escaped(self):
        page = render('/x" onload="alert(1)')
        self.assertNotIn('onload="alert(1)"', page)

    def test_a_rejected_path_lands_on_root(self):
        page = render('javascript:alert(1)')
        self.assertNotIn('javascript:', page)
        self.assertIn('href="/"', page)

    def test_the_page_carries_no_third_party_resource(self):
        page = render('/').lower()
        for forbidden in ('http://', 'https://', 'cdn', 'googleapis', 'captcha',
                          'recaptcha', 'hcaptcha', 'turnstile', 'analytics'):
            self.assertNotIn(forbidden, page)

    def test_the_page_contains_no_javascript(self):
        page = render('/').lower()
        for forbidden in ('<script', 'onclick', 'onload', 'onerror', 'eval(',
                          'javascript:'):
            self.assertNotIn(forbidden, page)

    def test_the_page_is_small(self):
        self.assertLess(len(render('/').encode()), 2048)
        self.assertLess(len(render('/' + 'a' * 500).encode()), MAX_RESPONSE_BYTES)

    def test_the_page_wording_does_not_accuse_the_visitor(self):
        """Checked against the visible words, matched whole.

        A substring search would trip over "body" and "roboto"; what matters is
        what a visitor reads.
        """
        import re
        page = render('/')
        visible = re.sub(r'<style>.*?</style>', ' ', page, flags=re.S)
        visible = re.sub(r'<[^>]+>', ' ', visible).lower()
        words = set(re.findall(r'[a-z]+', visible))
        for word in ('hacker', 'attacker', 'bot', 'suspicious', 'blocked', 'denied',
                     'risk', 'score', 'malicious', 'robot', 'human', 'verify'):
            self.assertNotIn(word, words, f'the page says {word!r} to a visitor')
        self.assertIn('checking this request', visible)

    def test_the_page_does_not_leak_an_internal_score(self):
        page = render('/')
        self.assertNotIn('0.', page.split('<style>')[0])

    def test_the_page_is_accessible_without_javascript(self):
        """A meta refresh and a real link, so a screen reader still gets there."""
        page = render('/target')
        self.assertIn('http-equiv="refresh"', page)
        self.assertIn('<a href="/target">', page)
        self.assertIn('lang="en"', page)


class TestHeaders(unittest.TestCase):
    """§71, §76, §77, §78."""

    def test_the_response_is_never_cached(self):
        self.assertIn('no-store', SECURITY_HEADERS['Cache-Control'])
        self.assertIn('private', SECURITY_HEADERS['Cache-Control'])

    def test_scripts_are_forbidden_by_policy(self):
        policy = SECURITY_HEADERS['Content-Security-Policy']
        self.assertIn("default-src 'none'", policy)
        self.assertNotIn('script-src', policy.replace("form-action 'none'", ''))

    def test_the_page_cannot_be_framed(self):
        self.assertIn("frame-ancestors 'none'", SECURITY_HEADERS['Content-Security-Policy'])
        self.assertEqual(SECURITY_HEADERS['X-Frame-Options'], 'DENY')

    def test_no_referrer_leaks_the_protected_url(self):
        self.assertEqual(SECURITY_HEADERS['Referrer-Policy'], 'no-referrer')

    def test_the_content_type_cannot_be_sniffed(self):
        self.assertEqual(SECURITY_HEADERS['X-Content-Type-Options'], 'nosniff')


class TestCookie(unittest.TestCase):
    """§14, §103."""

    def test_a_cookie_over_https_is_secure_and_httponly(self):
        header = cookie_header('tok', secure=True, max_age=900)
        self.assertIn('Secure', header)
        self.assertIn('HttpOnly', header)
        self.assertIn('SameSite=Lax', header)
        self.assertIn('Max-Age=900', header)
        self.assertIn('Path=/', header)

    def test_a_cookie_over_plain_http_is_not_marked_secure(self):
        self.assertNotIn('Secure', cookie_header('tok', secure=False))

    def test_same_site_none_requires_secure(self):
        with self.assertRaises(ValueError):
            cookie_header('tok', secure=False, same_site='None')

    def test_an_unknown_same_site_value_is_refused(self):
        with self.assertRaises(ValueError):
            cookie_header('tok', same_site='Whatever')

    def test_the_cookie_name_is_project_specific(self):
        self.assertTrue(cookie_header('tok').startswith(COOKIE_NAME + '='))

    def test_a_negative_max_age_becomes_zero(self):
        self.assertIn('Max-Age=0', cookie_header('tok', max_age=-500))

    def test_clearing_the_cookie_expires_it(self):
        header = clear_cookie_header()
        self.assertIn('Max-Age=0', header)
        self.assertIn('HttpOnly', header)


class TestResponse(unittest.TestCase):
    def test_an_active_response_sets_the_cookie_and_serves_the_page(self):
        token = issue(SECRET, site='blog', now=NOW)
        response = build(token, '/target', secure=True, max_age=900)
        self.assertEqual(response.status, 200)
        self.assertIn('Set-Cookie', response.headers)
        self.assertIn(token, response.headers['Set-Cookie'])
        self.assertIn('/target', response.body)
        self.assertFalse(response.shadow)

    def test_a_shadow_response_sends_nothing(self):
        """§122, §123. Measure the impact before anyone is inconvenienced."""
        token = issue(SECRET, site='blog', now=NOW)
        response = build(token, '/target', shadow=True)
        self.assertEqual(response.status, 0)
        self.assertNotIn('Set-Cookie', response.headers)
        self.assertEqual(response.body, '')
        self.assertTrue(response.shadow)
        self.assertIn('nothing was sent', response.reason)

    def test_the_explanation_never_carries_the_token(self):
        """§83, §84. A token in a report is a short-lived bypass."""
        token = issue(SECRET, site='blog', now=NOW)
        document = build(token, '/target').explain()
        self.assertNotIn(token, str(document))
        self.assertEqual(document['headers']['Set-Cookie'], '[set-cookie omitted]')

    def test_a_rate_limited_response_carries_a_bounded_retry_after(self):
        response = rate_limited(retry_after=30)
        self.assertEqual(response.status, 429)
        self.assertEqual(response.headers['Retry-After'], '30')
        for value, expected in ((0, '1'), (-5, '1'), (999_999, '3600')):
            with self.subTest(value=value):
                self.assertEqual(rate_limited(value).headers['Retry-After'], expected)

    def test_every_response_is_small(self):
        token = issue(SECRET, site='blog', now=NOW)
        for response in (build(token, '/x'), rate_limited(), build(token, shadow=True)):
            with self.subTest(status=response.status):
                self.assertLess(response.bytes_sent, MAX_RESPONSE_BYTES)


class TestSafeMethods(unittest.TestCase):
    """§21, §110. A redirect replays the request."""

    def test_only_idempotent_methods_are_listed_as_safe(self):
        self.assertEqual(set(SAFE_METHODS), {'GET', 'HEAD'})
        for unsafe in ('POST', 'PUT', 'PATCH', 'DELETE'):
            self.assertNotIn(unsafe, SAFE_METHODS)


if __name__ == '__main__':
    unittest.main()
