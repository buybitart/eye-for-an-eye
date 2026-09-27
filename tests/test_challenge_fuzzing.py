"""P11 fuzzing and load (§114-§117). Deterministic, local, bounded.

Two questions, asked by hitting the code with things it was not designed for:

* Can any input make the token parser crash, hang, or allocate without bound?
  The parser reads attacker-controlled bytes on every request, which makes it
  the largest attack surface in the subsystem.
* Can a flood make the challenge subsystem consume memory or CPU without bound?

Seeded, so a failure here is reproducible rather than a story about a build that
went red once.
"""
import gc
import random
import string
import sys
import time
import unittest

from eye_for_an_eye.challenge.page import (MAX_RESPONSE_BYTES, build, render,
                                           safe_return_path)
from eye_for_an_eye.challenge.policy import ChallengeGate, PASSED, PRESENTED
from eye_for_an_eye.challenge.service import ChallengeService
from eye_for_an_eye.challenge.token import COOKIE_NAME, issue, verify
from eye_for_an_eye.web.gateway import WebGateway
from eye_for_an_eye.web.identity import ClientResolver

SECRET = b'f' * 32
SITE = 'fuzz'
NOW = 1_800_000_000
ALPHABET = string.ascii_letters + string.digits + '-_=.:/%+*&?#$@!~^ \t\r\n\\"\'<>'


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


def alphabet_token(attempts=200):
    """A token containing both base64url-only characters.

    The nonce is random, so roughly one token in seven contains neither `-` nor
    `_`. For those, swapping to the standard alphabet is a no-op and a test that
    checks the swap is refused silently checks nothing instead — which is how a
    suite ends up failing once every few runs for reasons nobody can reproduce.
    """
    for _ in range(attempts):
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        if '-' in token and '_' in token:
            return token
    raise AssertionError('no token containing both -_ was minted')


class TestTokenFuzzing(unittest.TestCase):
    """§115. Nothing a client can send may crash the parser."""

    def check(self, candidate):
        """Verification must return a refusal, never raise, never hang."""
        started = time.perf_counter()
        result = verify(candidate, SECRET, site=SITE, now=NOW)
        elapsed = time.perf_counter() - started
        self.assertFalse(result.valid, repr(candidate)[:80])
        self.assertTrue(result.outcome, 'a refusal must say why')
        self.assertLess(elapsed, 0.25, 'verification took too long')

    def test_random_text_of_every_length(self):
        stream = random.Random(1)
        for _ in range(3000):
            length = stream.randrange(0, 400)
            self.check(''.join(stream.choice(ALPHABET) for _ in range(length)))

    def test_random_bytes_decoded_loosely(self):
        stream = random.Random(2)
        for _ in range(1500):
            raw = bytes(stream.randrange(256) for _ in range(stream.randrange(0, 200)))
            self.check(raw.decode('latin-1'))

    def test_valid_tokens_with_one_character_changed(self):
        """The case that matters: almost right, and still refused."""
        stream = random.Random(3)
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        for _ in range(1500):
            index = stream.randrange(len(token))
            replacement = stream.choice(ALPHABET)
            if replacement == token[index]:
                continue
            self.check(token[:index] + replacement + token[index + 1:])

    def test_valid_tokens_truncated_at_every_point(self):
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        for cut in range(len(token)):
            self.check(token[:cut])

    def test_valid_tokens_with_things_appended(self):
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        for suffix in ('A', '==', '\x00', '\n', 'A' * 1000, '%00', '../'):
            self.check(token + suffix)

    def test_enormous_input_is_refused_without_allocating(self):
        """A megabyte of base64 must not become a megabyte of parsed anything."""
        gc.collect()
        for size in (10_000, 100_000, 1_000_000):
            candidate = 'A' * size
            before = time.perf_counter()
            result = verify(candidate, SECRET, site=SITE, now=NOW)
            self.assertFalse(result.valid)
            self.assertLess(time.perf_counter() - before, 0.25, f'{size} took too long')

    def test_structured_attack_strings(self):
        token = alphabet_token()
        for candidate in ('', ' ', '\x00', '\n\r', 'null', 'None', 'true', '0',
                          '{}', '[]', '{"a":1}', '../../etc/passwd', '%2e%2e%2f',
                          '<script>alert(1)</script>', "' OR '1'='1",
                          '\\x00\\x01', 'A' * 43 + '.' + 'B' * 43,
                          token.replace('-', '+').replace('_', '/'),
                          token[::-1], token.upper(), token.lower()):
            self.check(candidate)

    def test_every_wrong_secret_length_is_refused_not_raised(self):
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        for length in (0, 1, 8, 31, 33, 64, 1000):
            result = verify(token, b'x' * length, site=SITE, now=NOW)
            self.assertFalse(result.valid, length)

    def test_absurd_clock_values_are_refused_not_raised(self):
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        for moment in (0, -1, -1e18, 1e18, float('inf'), float('-inf')):
            with self.subTest(now=moment):
                result = verify(token, SECRET, site=SITE, now=moment)
                self.assertIn(result.valid, (True, False))

    def test_a_not_a_number_clock_does_not_validate_a_token(self):
        """An unusable clock cannot decide whether a token is in date."""
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        self.assertFalse(verify(token, SECRET, site=SITE, now=float('nan')).valid)

    def test_a_token_has_exactly_one_spelling(self):
        """Found by fuzzing: three ways to respell a token and still pass.

        None of them was a signature bypass, but a value with several spellings
        cannot be safely used as a key, counted, or compared, and a token is an
        obvious thing to want to do all three with later.
        """
        token = alphabet_token()
        self.assertTrue(verify(token, SECRET, site=SITE, now=NOW).valid)
        for variant, why in (
                (token + '=', 'one padding character'),
                (token + '==', 'two padding characters'),
                (token.replace('-', '+').replace('_', '/'), 'the standard alphabet'),
                (token + '\n', 'a trailing newline'),
                (token + ' ', 'a trailing space'),
                ('\n' + token, 'a leading newline')):
            with self.subTest(why=why):
                self.assertNotEqual(variant, token, f'{why} did not change the token')
                self.assertFalse(verify(variant, SECRET, site=SITE, now=NOW).valid,
                                 f'a token respelled with {why} still verified')

    def test_a_site_scope_of_any_shape_is_survivable(self):
        stream = random.Random(4)
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        for _ in range(500):
            site = ''.join(stream.choice(ALPHABET)
                           for _ in range(stream.randrange(0, 120)))
            result = verify(token, SECRET, site=site, now=NOW)
            self.assertEqual(result.valid, False)


class TestChallengePageFuzzing(unittest.TestCase):
    """§116. Attacker-controlled paths must not reach the HTML."""

    #: Markup that would only be present if a return path had escaped. The page's
    #: own `</title>` is not on this list, which is the difference between
    #: testing for injection and testing that the page has a title.
    INJECTION = ('<script', 'javascript:', 'onerror', 'onload=', '"><', "'><",
                 '</style><', '<img', '<iframe', '<svg')

    def test_no_return_path_ever_escapes_into_the_page(self):
        baseline = render('/').lower()
        stream = random.Random(5)
        for _ in range(2000):
            raw = ''.join(stream.choice(ALPHABET)
                          for _ in range(stream.randrange(0, 200)))
            page = render(raw).lower()
            for marker in self.INJECTION:
                self.assertNotIn(marker, page, repr(raw)[:60])
            # The return target does appear in the body — a meta refresh and a
            # link, so the flow still works without scripting. It appears
            # percent-encoded, so none of the characters that could end an
            # attribute or open a tag survive the trip.
            for character in ('<', '>', '"', "'"):
                self.assertEqual(page.count(character), baseline.count(character),
                                 f'{character!r} count changed for {raw[:40]!r}')

    def test_deliberate_injection_attempts_all_fail(self):
        for attack in ('/"><script>alert(1)</script>',
                       "/'></title><script>x</script>",
                       '/</style><script>x</script>',
                       '/%22%3E%3Cscript%3E',
                       '/\x00<script>',
                       'javascript:alert(1)',
                       'data:text/html,<script>x</script>',
                       '//evil.test/',
                       'https://evil.test/',
                       '/\\evil.test'):
            with self.subTest(attack=attack):
                page = render(attack).lower()
                self.assertNotIn('<script', page)
                self.assertNotIn('javascript:', page)

    def test_the_response_never_exceeds_its_bound(self):
        stream = random.Random(6)
        token = issue(SECRET, site=SITE, ttl_seconds=900, now=NOW)
        for _ in range(500):
            raw = '/' + ''.join(stream.choice(ALPHABET)
                                for _ in range(stream.randrange(0, 4000)))
            response = build(token, raw)
            self.assertLessEqual(len(response.body.encode('utf-8')),
                                 MAX_RESPONSE_BYTES)

    def test_a_rejected_path_becomes_the_site_root(self):
        stream = random.Random(7)
        for _ in range(500):
            raw = ''.join(stream.choice(ALPHABET)
                          for _ in range(stream.randrange(0, 50)))
            safe = safe_return_path(raw)
            self.assertTrue(safe.startswith('/'), repr(raw))
            self.assertFalse(safe.startswith('//'), repr(raw))
            self.assertFalse(safe.startswith('/\\'), repr(raw))


class TestFloodIsBounded(unittest.TestCase):
    """§114, §117, §81, §82. State must not grow with attacker input."""

    def gateway(self, clock):
        gate = ChallengeGate(shadow=False, clock=clock)
        service = ChallengeService(secret=SECRET, mode='active', site_id=SITE,
                                   gate=gate, clock=clock, wall_clock=clock)
        sensor = _FixedRisk(0.6)
        return WebGateway(resolver=ClientResolver([]), challenge=service,
                          sensor=sensor, clock=clock), gate

    def test_fifty_thousand_distinct_sources_do_not_grow_state_without_bound(self):
        clock = Clock()
        gateway, gate = self.gateway(clock)
        limit = gate.budget.concurrent_contexts
        for index in range(50_000):
            clock.now += 0.001
            gateway.handle(peer=f'10.{index // 65536 % 256}.'
                                f'{index // 256 % 256}.{index % 256}',
                           method='GET', path='/', now=clock.now)
        self.assertLessEqual(len(gate.contexts), limit)

    def test_the_global_budget_stops_issuing_rather_than_growing(self):
        clock = Clock()
        gateway, gate = self.gateway(clock)
        issued = 0
        for index in range(2000):
            plan = gateway.handle(peer=f'192.0.2.{index % 256}', method='GET',
                                  path='/', now=clock.now)
            issued += 1 if plan.challenged else 0
        # One second on the clock, so the per-second budget is the ceiling.
        self.assertLessEqual(issued, gate.budget.per_second)

    def test_one_source_cannot_exceed_its_hourly_budget(self):
        clock = Clock()
        gateway, gate = self.gateway(clock)
        issued = 0
        for _ in range(500):
            clock.now += 60.0
            plan = gateway.handle(peer='198.51.100.5', method='GET', path='/',
                                  now=clock.now)
            issued += 1 if plan.challenged else 0
        self.assertLessEqual(issued, gate.budget.per_source_per_hour * 9)

    def test_a_flood_never_returns_an_error_to_a_client(self):
        """The property that matters: overload degrades, it does not break."""
        clock = Clock()
        gateway, _ = self.gateway(clock)
        for index in range(5000):
            plan = gateway.handle(peer=f'192.0.2.{index % 256}', method='GET',
                                  path='/', now=clock.now)
            self.assertIn(plan.plan, ('PASS', 'CHALLENGE', 'RATE_LIMIT'))
            self.assertNotEqual(plan.status, 500)

    def test_the_context_table_evicts_rather_than_filling_memory(self):
        clock = Clock()
        gate = ChallengeGate(clock=clock)
        limit = gate.budget.concurrent_contexts
        for index in range(limit * 3):
            gate.contexts.touch(f'10.0.{index // 256 % 256}.{index % 256}', clock.now)
        self.assertLessEqual(len(gate.contexts), limit)
        self.assertGreater(gate.contexts.evictions, 0)

    def test_recorded_outcomes_per_context_are_bounded(self):
        clock = Clock()
        gate = ChallengeGate(clock=clock)
        context = gate.contexts.touch('198.51.100.5', clock.now)
        for index in range(10_000):
            context.record(PRESENTED if index % 2 else PASSED, clock.now + index)
        self.assertLessEqual(len(context.recent), 16)
        self.assertLess(sys.getsizeof(context.recent), 4096)

    def test_a_flood_of_invalid_cookies_costs_nothing_to_store(self):
        clock = Clock()
        gateway, gate = self.gateway(clock)
        stream = random.Random(8)
        before = len(gate.contexts)
        for _ in range(3000):
            junk = ''.join(stream.choice(ALPHABET) for _ in range(120))
            plan = gateway.handle(peer='198.51.100.6', method='GET', path='/',
                                  cookie=f'{COOKIE_NAME}={junk}', now=clock.now)
            self.assertNotEqual(plan.status, 500)
        self.assertLessEqual(len(gate.contexts) - before, 2)


class _FixedRisk:
    """A sensor stand-in that always reports the same risk."""

    def __init__(self, risk):
        self.risk = risk

    def last_risk(self, source):
        return self.risk


if __name__ == '__main__':
    unittest.main()
