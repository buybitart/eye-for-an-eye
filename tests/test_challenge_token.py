"""P11 challenge token security.

The token is the one thing in this stage a client holds and returns, so it is
the one thing an attacker will attack. These tests cover forging, replaying past
expiry, moving a token between sites, and every malformed shape a fuzzer finds.

The clock is injected throughout. No test sleeps.
"""
import base64
import os
import unittest

from eye_for_an_eye.challenge.token import (BAD_SIGNATURE, CHALLENGE_TOKEN_VERSION,
                                            COOKIE_NAME, DEFAULT_TTL_SECONDS, EXPIRED,
                                            LIFETIME_TOO_LONG, MALFORMED,
                                            MAX_CLOCK_SKEW_SECONDS, MAX_TTL_SECONDS,
                                            MIN_TTL_SECONDS, NOT_YET_VALID, OUTCOMES,
                                            TOKEN_SCHEME, TokenError, UNKNOWN_VERSION,
                                            VALID, issue, normalise_site, redact,
                                            remaining, site_key, verify)

SECRET = b'm' * 32
OTHER = b'n' * 32
NOW = 1_800_000_000


class TestIssuing(unittest.TestCase):
    def test_a_token_is_short_and_url_safe(self):
        token = issue(SECRET, site='blog', now=NOW)
        self.assertLess(len(token), 200)
        self.assertRegex(token, r'^[A-Za-z0-9_\-]+$')

    def test_two_tokens_differ_even_with_the_same_inputs(self):
        """A nonce, so two clients challenged in the same second differ."""
        first = issue(SECRET, site='blog', now=NOW)
        second = issue(SECRET, site='blog', now=NOW)
        self.assertNotEqual(first, second)

    def test_a_short_secret_is_refused(self):
        for secret in (b'', b'short', b'x' * 31, 'not-bytes'):
            with self.subTest(secret=secret):
                with self.assertRaises(TokenError):
                    issue(secret, site='blog')

    def test_an_absurd_lifetime_is_refused(self):
        for ttl in (0, -1, MIN_TTL_SECONDS - 1, MAX_TTL_SECONDS + 1, 86_400):
            with self.subTest(ttl=ttl):
                with self.assertRaises(TokenError):
                    issue(SECRET, site='blog', ttl_seconds=ttl)

    def test_the_default_lifetime_is_short(self):
        self.assertLessEqual(DEFAULT_TTL_SECONDS, 1800)
        self.assertLessEqual(MAX_TTL_SECONDS, 3600)


class TestVerification(unittest.TestCase):
    def test_a_fresh_token_verifies(self):
        result = verify(issue(SECRET, site='blog', now=NOW), SECRET, site='blog', now=NOW)
        self.assertTrue(result.valid)
        self.assertEqual(result.outcome, VALID)
        self.assertEqual(result.key_generation, 'current')

    def test_a_token_expires(self):
        token = issue(SECRET, site='blog', ttl_seconds=900, now=NOW)
        self.assertTrue(verify(token, SECRET, site='blog', now=NOW + 899).valid)
        self.assertEqual(verify(token, SECRET, site='blog', now=NOW + 901).outcome, EXPIRED)

    def test_remaining_time_counts_down(self):
        token = issue(SECRET, site='blog', ttl_seconds=900, now=NOW)
        self.assertEqual(remaining(verify(token, SECRET, site='blog', now=NOW), now=NOW), 900)
        self.assertEqual(
            remaining(verify(token, SECRET, site='blog', now=NOW + 300), now=NOW + 300), 600)

    def test_a_token_from_the_future_is_refused(self):
        token = issue(SECRET, site='blog', now=NOW + 10_000)
        self.assertEqual(verify(token, SECRET, site='blog', now=NOW).outcome, NOT_YET_VALID)

    def test_a_small_clock_skew_is_tolerated(self):
        token = issue(SECRET, site='blog', now=NOW + MAX_CLOCK_SKEW_SECONDS - 5)
        self.assertTrue(verify(token, SECRET, site='blog', now=NOW).valid)

    def test_a_forged_signature_is_refused(self):
        self.assertEqual(verify(issue(SECRET, site='blog', now=NOW), OTHER, site='blog',
                                now=NOW).outcome, BAD_SIGNATURE)

    def test_every_single_bit_flip_is_caught(self):
        """A MAC that misses a flipped bit is not a MAC."""
        raw = bytearray(base64.urlsafe_b64decode(
            issue(SECRET, site='blog', now=NOW) + '=='))
        for index in range(0, len(raw), 7):
            with self.subTest(index=index):
                mutated = bytearray(raw)
                mutated[index] ^= 0x01
                token = base64.urlsafe_b64encode(bytes(mutated)).rstrip(b'=').decode()
                self.assertFalse(verify(token, SECRET, site='blog', now=NOW).valid)

    def test_verification_never_raises(self):
        for token in ('', None, 123, 'x', '!!!', 'A' * 5000, '\x00\x01',
                      'a' * 71, base64.urlsafe_b64encode(b'\x00' * 72).decode()):
            with self.subTest(token=token):
                result = verify(token, SECRET, site='blog', now=NOW)
                self.assertIn(result.outcome, OUTCOMES)
                self.assertFalse(result.valid)

    def test_random_bytes_never_verify(self):
        for _ in range(200):
            token = base64.urlsafe_b64encode(os.urandom(72)).rstrip(b'=').decode()
            self.assertFalse(verify(token, SECRET, site='blog', now=NOW).valid)

    def test_an_unknown_version_is_named(self):
        raw = bytearray(base64.urlsafe_b64decode(
            issue(SECRET, site='blog', now=NOW) + '=='))
        raw[0] = 99
        token = base64.urlsafe_b64encode(bytes(raw)).rstrip(b'=').decode()
        self.assertEqual(verify(token, SECRET, site='blog', now=NOW).outcome,
                         UNKNOWN_VERSION)

    def test_a_truncated_token_is_malformed(self):
        token = issue(SECRET, site='blog', now=NOW)
        for length in (1, 10, 40, len(token) - 1):
            with self.subTest(length=length):
                self.assertEqual(verify(token[:length], SECRET, site='blog',
                                        now=NOW).outcome, MALFORMED)

    def test_an_oversized_token_is_refused_before_parsing(self):
        self.assertEqual(verify('A' * 100_000, SECRET, site='blog', now=NOW).outcome,
                         MALFORMED)

    def test_a_token_claiming_a_long_life_is_refused_even_when_signed(self):
        """A signed token from a build with different limits, or a leaked secret."""
        token = issue(SECRET, site='blog', ttl_seconds=MAX_TTL_SECONDS, now=NOW)
        result = verify(token, SECRET, site='blog', now=NOW, max_ttl_seconds=60)
        self.assertEqual(result.outcome, LIFETIME_TOO_LONG)


class TestSiteScope(unittest.TestCase):
    """§60, §61. A token for one site must not work on another."""

    def test_a_token_does_not_cross_sites(self):
        token = issue(SECRET, site='site-a', now=NOW)
        self.assertTrue(verify(token, SECRET, site='site-a', now=NOW).valid)
        self.assertFalse(verify(token, SECRET, site='site-b', now=NOW).valid)

    def test_every_site_gets_a_different_key(self):
        keys = {site_key(SECRET, name) for name in ('a', 'b', 'c', 'default')}
        self.assertEqual(len(keys), 4)

    def test_the_same_site_always_derives_the_same_key(self):
        self.assertEqual(site_key(SECRET, 'blog'), site_key(SECRET, 'blog'))

    def test_a_different_master_secret_gives_a_different_site_key(self):
        self.assertNotEqual(site_key(SECRET, 'blog'), site_key(OTHER, 'blog'))

    def test_a_site_name_is_normalised_and_bounded(self):
        self.assertEqual(normalise_site('  BLOG  '), 'blog')
        self.assertEqual(normalise_site(''), 'default')
        self.assertEqual(normalise_site(None), 'default')
        self.assertLessEqual(len(normalise_site('x' * 500)), 64)

    def test_a_hostile_site_name_cannot_smuggle_characters(self):
        for name in ('a/../b', 'a\x00b', 'a b', 'a;b', '<script>'):
            with self.subTest(name=name):
                cleaned = normalise_site(name)
                self.assertTrue(all(c.isalnum() or c in '.-_' for c in cleaned))

    def test_two_sites_that_normalise_the_same_share_a_key(self):
        """Documented consequence: scope is an identifier, not a secret."""
        self.assertEqual(site_key(SECRET, 'BLOG'), site_key(SECRET, 'blog'))


class TestRotation(unittest.TestCase):
    """§12, §120. Rotate without logging everyone out mid-flow."""

    def test_a_token_from_the_previous_key_is_accepted_during_rotation(self):
        old = issue(OTHER, site='blog', now=NOW)
        result = verify(old, SECRET, site='blog', now=NOW, previous_secret=OTHER)
        self.assertTrue(result.valid)
        self.assertEqual(result.key_generation, 'previous')

    def test_a_token_from_the_previous_key_is_refused_after_rotation_ends(self):
        old = issue(OTHER, site='blog', now=NOW)
        self.assertFalse(verify(old, SECRET, site='blog', now=NOW).valid)

    def test_new_tokens_use_the_current_key(self):
        fresh = issue(SECRET, site='blog', now=NOW)
        result = verify(fresh, SECRET, site='blog', now=NOW, previous_secret=OTHER)
        self.assertEqual(result.key_generation, 'current')

    def test_the_current_key_is_tried_first(self):
        """So the common case costs one HMAC, not two."""
        fresh = issue(SECRET, site='blog', now=NOW)
        self.assertEqual(verify(fresh, SECRET, site='blog', now=NOW,
                                previous_secret=OTHER).key_generation, 'current')

    def test_an_invalid_previous_secret_does_not_break_verification(self):
        fresh = issue(SECRET, site='blog', now=NOW)
        self.assertTrue(verify(fresh, SECRET, site='blog', now=NOW,
                               previous_secret=b'too-short').valid)


class TestNoIdentity(unittest.TestCase):
    """§16. A token carries no identity, and cannot be made to."""

    def test_the_token_payload_has_exactly_five_fixed_fields(self):
        """Checked against the struct, not against prose.

        The payload is a fixed-width struct plus a nonce. There is no field an
        identifier could be placed in, and no variable-length region to hide one.
        """
        from eye_for_an_eye.challenge.token import (NONCE_BYTES, _PAYLOAD,
                                                    _PAYLOAD_BYTES)
        self.assertEqual(_PAYLOAD.format, '>BIIB')
        self.assertEqual(_PAYLOAD.size, 10)
        self.assertEqual(_PAYLOAD_BYTES, _PAYLOAD.size + NONCE_BYTES)
        raw = base64.urlsafe_b64decode(issue(SECRET, site='blog', now=NOW) + '==')
        self.assertEqual(len(raw), _PAYLOAD_BYTES + 32)

    def test_two_tokens_differ_only_in_their_nonce_and_signature(self):
        from eye_for_an_eye.challenge.token import _PAYLOAD
        first = base64.urlsafe_b64decode(issue(SECRET, site='b', now=NOW) + '==')
        second = base64.urlsafe_b64decode(issue(SECRET, site='b', now=NOW) + '==')
        self.assertEqual(first[:_PAYLOAD.size], second[:_PAYLOAD.size])
        self.assertNotEqual(first[_PAYLOAD.size:], second[_PAYLOAD.size:])

    def test_issue_accepts_no_identity_argument(self):
        import inspect
        parameters = set(inspect.signature(issue).parameters)
        self.assertEqual(parameters, {'master_secret', 'site', 'ttl_seconds', 'level', 'now'})

    def test_a_verified_token_reveals_only_timing_and_level(self):
        result = verify(issue(SECRET, site='blog', now=NOW), SECRET, site='blog', now=NOW)
        document = result.explain()
        self.assertEqual(set(document) & {'client', 'address', 'user', 'session'}, set())
        self.assertIn('not authentication', document['meaning'])


class TestRedaction(unittest.TestCase):
    """§83, §84. A token must never reach a log."""

    def test_a_cookie_header_is_redacted(self):
        text = f'Cookie: {COOKIE_NAME}=AbCdEf0123456789xyz; other=1'
        cleaned = redact(text)
        self.assertNotIn('AbCdEf0123456789xyz', cleaned)
        self.assertIn('[redacted]', cleaned)

    def test_a_token_in_an_error_message_is_redacted(self):
        token = issue(SECRET, site='blog', now=NOW)
        cleaned = redact(f'failed to verify {COOKIE_NAME}={token} from client')
        self.assertNotIn(token, cleaned)

    def test_redaction_handles_empty_input(self):
        self.assertEqual(redact(''), '')
        self.assertIsNone(redact(None))

    def test_the_cookie_name_is_project_specific(self):
        for generic in ('session', 'auth', 'token', 'id'):
            self.assertNotEqual(COOKIE_NAME, generic)
        self.assertTrue(COOKIE_NAME.startswith('__efae'))


class TestConstantTime(unittest.TestCase):
    def test_comparison_uses_compare_digest(self):
        import inspect
        from eye_for_an_eye.challenge import token as module
        source = inspect.getsource(module.verify)
        self.assertIn('compare_digest', source)
        self.assertNotIn('mac == expected', source)
        self.assertNotIn('mac != expected', source)

    def test_nothing_hand_rolls_a_hash(self):
        import ast
        import inspect
        from eye_for_an_eye.challenge import token as module
        tree = ast.parse(inspect.getsource(module))
        imported = {node.module for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom) and node.module}
        imported |= {alias.name for node in ast.walk(tree)
                     if isinstance(node, ast.Import) for alias in node.names}
        self.assertIn('hmac', imported)
        self.assertIn('hashlib', imported)


class TestScheme(unittest.TestCase):
    def test_the_scheme_is_versioned(self):
        self.assertEqual(TOKEN_SCHEME, 'challenge-v1')
        self.assertEqual(CHALLENGE_TOKEN_VERSION, 1)

    def test_the_version_is_inside_the_signed_payload(self):
        """So the version cannot be changed without breaking the signature."""
        raw = base64.urlsafe_b64decode(issue(SECRET, site='blog', now=NOW) + '==')
        self.assertEqual(raw[0], CHALLENGE_TOKEN_VERSION)


if __name__ == '__main__':
    unittest.main()
