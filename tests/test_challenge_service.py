"""P11 challenge service: failure behaviour and the full flow.

The most important group here is `TestFailsOpen`. A security tool that returns
500 to every visitor when its own optional component breaks has caused a worse
outage than the attack it was watching for. Every entry point is broken
deliberately and the answer must always be "do not challenge, carry on".
"""
import unittest
import tempfile
from pathlib import Path

from eye_for_an_eye.challenge.policy import FAILED, PASSED, PRESENTED
from eye_for_an_eye.challenge.service import (ACTIVE, ChallengeService,
                                              ChallengeServiceError, DISABLED, SHADOW,
                                              from_config, load_secret)
from eye_for_an_eye.challenge.token import issue
from eye_for_an_eye.config import Config

SECRET = b'm' * 32
OTHER = b'n' * 32
NOW = 1_800_000_000


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def service(**kwargs):
    kwargs.setdefault('secret', SECRET)
    kwargs.setdefault('mode', ACTIVE)
    kwargs.setdefault('site_id', 'blog')
    kwargs.setdefault('wall_clock', lambda: NOW)
    kwargs.setdefault('clock', Clock())
    return ChallengeService(**kwargs)


class TestSecretFile(unittest.TestCase):
    """§11. A weak or exposed secret is refused, loudly."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'challenge.secret'

    def write(self, data, mode=0o600):
        self.path.write_bytes(data)
        self.path.chmod(mode)
        return str(self.path)

    def test_a_good_secret_loads(self):
        self.assertEqual(load_secret(self.write(b'k' * 48)), b'k' * 48)

    def test_a_short_secret_is_refused(self):
        with self.assertRaises(ChallengeServiceError) as caught:
            load_secret(self.write(b'short'))
        self.assertIn('at least 32 bytes', str(caught.exception))

    def test_a_world_readable_secret_is_refused(self):
        with self.assertRaises(ChallengeServiceError) as caught:
            load_secret(self.write(b'k' * 48, mode=0o644))
        self.assertIn('chmod 600', str(caught.exception))

    def test_a_missing_secret_file_is_refused(self):
        with self.assertRaises(ChallengeServiceError):
            load_secret(str(self.path.parent / 'nope'))

    def test_no_path_means_no_secret(self):
        self.assertIsNone(load_secret(''))
        self.assertIsNone(load_secret(None))


class TestConfiguration(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def secret_file(self, name='challenge.secret', data=b'k' * 48, mode=0o600):
        path = Path(self.directory.name) / name
        path.write_bytes(data)
        path.chmod(mode)
        return str(path)

    def test_challenges_are_off_by_default(self):
        built = from_config(Config())
        self.assertFalse(built.enabled)
        self.assertEqual(built.mode, DISABLED)

    def test_enabling_without_a_secret_disables_rather_than_raising(self):
        config = Config()
        config.challenge.enabled = True
        built = from_config(config)
        self.assertFalse(built.enabled)
        self.assertIn('no challenge.secret_file', built.last_error)

    def test_an_unreadable_secret_disables_rather_than_raising(self):
        config = Config()
        config.challenge.enabled = True
        config.challenge.secret_file = self.secret_file(mode=0o644)
        built = from_config(config)
        self.assertFalse(built.enabled)
        self.assertIn('could not be loaded', built.last_error)
        self.assertEqual(built.metrics['challenge_subsystem_errors_total'], 1)

    def test_the_default_mode_is_shadow(self):
        config = Config()
        config.challenge.enabled = True
        config.challenge.secret_file = self.secret_file()
        built = from_config(config)
        self.assertTrue(built.enabled)
        self.assertEqual(built.mode, SHADOW)
        self.assertTrue(built.shadow)

    def test_active_mode_must_be_asked_for(self):
        config = Config()
        config.challenge.enabled = True
        config.challenge.mode = 'active'
        config.challenge.secret_file = self.secret_file()
        self.assertFalse(from_config(config).shadow)

    def test_operator_route_prefixes_are_honoured(self):
        config = Config()
        config.challenge.enabled = True
        config.challenge.secret_file = self.secret_file()
        config.challenge.no_challenge_path_prefixes = ['/embed/']
        built = from_config(config)
        decision = built.consider(risk=0.6, confidence=0.5, method='GET',
                                  path='/embed/widget', source='198.51.100.7')
        self.assertFalse(decision.challenge)

    def test_a_rendered_configuration_never_shows_the_secret_path(self):
        from eye_for_an_eye.config import redacted_config
        config = Config()
        config.challenge.enabled = True
        path = self.secret_file()
        config.challenge.secret_file = path
        rendered = redacted_config(config)
        self.assertEqual(rendered['challenge']['secret_file'], '********')
        self.assertNotIn(path, str(rendered))


class TestFullFlow(unittest.TestCase):
    """§105, §107. The whole loop, end to end."""

    def test_a_suspicious_client_is_challenged_and_can_pass(self):
        built = service()
        decision = built.consider(risk=0.6, confidence=0.5, method='GET', path='/page',
                                  source='198.51.100.7')
        self.assertTrue(decision.challenge)

        response = built.respond('/page')
        self.assertEqual(response.status, 200)
        self.assertIn('Set-Cookie', response.headers)

        cookie = response.headers['Set-Cookie'].split(';')[0].split('=', 1)[1]
        verification = built.verify_cookie(cookie)
        self.assertTrue(verification.valid)

        built.observe_token('198.51.100.7', verification)
        context = built.gate.contexts.get('198.51.100.7')
        self.assertEqual(context.passed, 1)

    def test_passing_does_not_make_a_client_trusted(self):
        """§39. A capable bot handles cookies."""
        built = service()
        built.gate.record_outcome('198.51.100.7', PASSED)
        action, reasons = built.adjust('SOFT_CHALLENGE', '198.51.100.7')
        self.assertEqual(action, 'SOFT_CHALLENGE')
        self.assertEqual(reasons, ())

    def test_a_bot_that_passes_and_keeps_scanning_is_escalated(self):
        """§42, §107. The signal a challenge exists to produce."""
        built = service()
        built.gate.record_outcome('198.51.100.7', PASSED)
        for _ in range(8):
            built.note_activity('198.51.100.7', suspicious=True)
        action, reasons = built.adjust('SOFT_CHALLENGE', '198.51.100.7')
        self.assertEqual(action, 'RATE_LIMIT')
        self.assertTrue(any('continued probing' in reason for reason in reasons))

    def test_a_cookieless_scanner_accumulates_failure_evidence(self):
        """§106. It never keeps the cookie, so it never passes."""
        built = service()
        for _ in range(4):
            built.gate.record_outcome('198.51.100.7', PRESENTED)
            built.gate.record_outcome('198.51.100.7', FAILED)
        values = built.evidence('198.51.100.7')
        self.assertEqual(values['challenge_pass_count'], 0.0)
        self.assertEqual(values['challenge_fail_count'], 4.0)
        self.assertEqual(values['challenge_pass_ratio'], 0.0)

    def test_an_expired_token_reads_as_a_timeout_not_a_failure(self):
        built = service()
        old = issue(SECRET, site='blog', ttl_seconds=60, now=NOW - 600)
        verification = built.verify_cookie(old)
        self.assertFalse(verification.valid)
        built.observe_token('198.51.100.7', verification)
        self.assertEqual(built.gate.contexts.get('198.51.100.7').timed_out, 1)

    def test_a_forged_token_reads_as_a_failure(self):
        built = service()
        forged = issue(OTHER, site='blog', now=NOW)
        verification = built.verify_cookie(forged)
        built.observe_token('198.51.100.7', verification)
        self.assertEqual(built.gate.contexts.get('198.51.100.7').failed, 1)

    def test_a_token_for_another_site_does_not_pass(self):
        built = service(site_id='blog')
        other_site = issue(SECRET, site='shop', now=NOW)
        self.assertFalse(built.verify_cookie(other_site).valid)


class TestShadowMode(unittest.TestCase):
    """§122, §123. Decide, record, send nothing."""

    def test_shadow_mode_sends_no_cookie_and_no_page(self):
        built = service(mode=SHADOW)
        response = built.respond('/page')
        self.assertEqual(response.status, 0)
        self.assertNotIn('Set-Cookie', response.headers)
        self.assertEqual(response.body, '')
        self.assertTrue(response.shadow)

    def test_shadow_mode_still_records_the_decision(self):
        built = service(mode=SHADOW)
        decision = built.consider(risk=0.6, confidence=0.5, method='GET', path='/page',
                                  source='198.51.100.7')
        self.assertTrue(decision.challenge)
        self.assertTrue(decision.shadow)
        self.assertEqual(built.metrics['challenge_shadow_total'], 0)
        built.respond('/page')
        self.assertEqual(built.metrics['challenge_shadow_total'], 1)


class TestFailsOpen(unittest.TestCase):
    """§68, §118. The rule that keeps the website up."""

    def broken(self, attribute):
        built = service()

        class Broken:
            def __getattr__(self, name):
                raise RuntimeError('the challenge subsystem exploded')

        setattr(built, attribute, Broken())
        return built

    def test_a_broken_gate_does_not_challenge_and_does_not_raise(self):
        built = self.broken('gate')
        decision = built.consider(risk=0.9, confidence=0.5, method='GET', path='/x',
                                  source='198.51.100.7')
        self.assertFalse(decision.challenge)
        self.assertEqual(decision.action, 'WATCH')
        self.assertIn('the site was not affected', decision.reason)
        self.assertEqual(built.metrics['challenge_subsystem_errors_total'], 1)

    def test_a_broken_secret_produces_no_response_rather_than_an_error(self):
        built = service(secret=b'too-short-to-sign')
        self.assertIsNone(built.respond('/x'))
        self.assertEqual(built.metrics['challenge_subsystem_errors_total'], 1)

    def test_a_secret_too_short_to_derive_a_key_verifies_nothing(self):
        """No token can pass, and nothing raises.

        The verifier already treats a key it cannot derive as "this does not
        verify", which is the safe reading: an unusable secret must not become an
        unusable website.
        """
        built = service(secret=b'\x00')
        result = built.verify_cookie(issue(SECRET, site='blog', now=NOW))
        self.assertIsNotNone(result)
        self.assertFalse(result.valid)

    def test_a_broken_gate_still_answers_evidence_questions(self):
        built = self.broken('gate')
        values = built.evidence('198.51.100.7')
        self.assertEqual(values['challenge_presented_count'], 0.0)

    def test_a_broken_gate_never_changes_an_action(self):
        built = self.broken('gate')
        action, reasons = built.adjust('WATCH', '198.51.100.7')
        self.assertEqual(action, 'WATCH')
        self.assertEqual(reasons, ())

    def test_a_disabled_service_answers_every_question_safely(self):
        built = ChallengeService(secret=None, mode=DISABLED)
        self.assertFalse(built.consider(risk=0.9, confidence=0.9, method='GET',
                                        path='/x', source='s').challenge)
        self.assertIsNone(built.respond('/x'))
        self.assertIsNone(built.verify_cookie('anything'))
        self.assertIsNone(built.note_activity('s', suspicious=True))
        self.assertEqual(built.adjust('WATCH', 's'), ('WATCH', ()))
        self.assertEqual(built.review_priority('s', 0.9), (0.0, ()))

    def test_every_failure_is_counted_and_named(self):
        built = self.broken('gate')
        built.consider(risk=0.9, confidence=0.5, method='GET', path='/x', source='s')
        self.assertGreaterEqual(built.metrics['challenge_subsystem_errors_total'], 1)
        self.assertTrue(built.last_error)


class TestRotation(unittest.TestCase):
    """§120. Rotate without breaking every live cookie."""

    def test_a_token_from_the_previous_secret_is_accepted(self):
        built = service(secret=SECRET, previous_secret=OTHER)
        old = issue(OTHER, site='blog', now=NOW)
        self.assertTrue(built.verify_cookie(old).valid)

    def test_the_same_token_is_rejected_once_rotation_ends(self):
        built = service(secret=SECRET, previous_secret=None)
        old = issue(OTHER, site='blog', now=NOW)
        self.assertFalse(built.verify_cookie(old).valid)

    def test_health_says_whether_a_rotation_is_in_progress(self):
        self.assertTrue(service(previous_secret=OTHER).health()['rotation_active'])
        self.assertFalse(service().health()['rotation_active'])


class TestRestart(unittest.TestCase):
    """§119. A stateless token survives a restart."""

    def test_a_token_issued_before_a_restart_still_verifies_after_one(self):
        before = service()
        response = before.respond('/page')
        cookie = response.headers['Set-Cookie'].split(';')[0].split('=', 1)[1]
        after = service()          # a fresh process, same secret, no shared state
        self.assertTrue(after.verify_cookie(cookie).valid)

    def test_no_server_side_row_is_needed_to_verify(self):
        built = service()
        cookie = built.respond('/page').headers['Set-Cookie'].split(';')[0].split('=', 1)[1]
        built.gate.contexts._contexts.clear()
        self.assertTrue(built.verify_cookie(cookie).valid)


class TestReviewQueueIntegration(unittest.TestCase):
    """§44. What is worth a person's time."""

    def test_a_source_that_passed_then_kept_probing_is_prioritised(self):
        built = service()
        built.gate.record_outcome('198.51.100.7', PASSED)
        for _ in range(5):
            built.note_activity('198.51.100.7', suspicious=True)
        priority, reasons = built.review_priority('198.51.100.7', 0.8)
        self.assertGreater(priority, 1.0)
        self.assertTrue(any('continued probing' in reason for reason in reasons))

    def test_a_likely_false_positive_is_prioritised(self):
        """An ordinary-looking client challenged again and again."""
        built = service()
        for _ in range(4):
            built.gate.record_outcome('198.51.100.7', PRESENTED)
        priority, reasons = built.review_priority('198.51.100.7', 0.5)
        self.assertGreater(priority, 1.0)
        self.assertTrue(any('false positive' in reason for reason in reasons))

    def test_an_unremarkable_source_is_not_prioritised(self):
        built = service()
        self.assertEqual(built.review_priority('unknown', 0.5), (0.0, ()))


class TestHealth(unittest.TestCase):
    """§133. Status shows everything except the secret."""

    def test_health_never_carries_the_secret(self):
        built = service(secret=b'SUPER-SECRET-VALUE-THAT-IS-LONG-ENOUGH-32')
        text = str(built.health())
        self.assertNotIn('SUPER-SECRET', text)
        self.assertNotIn('secret_file', text)

    def test_health_reports_what_an_operator_needs(self):
        document = service().health()
        for key in ('enabled', 'mode', 'shadow', 'site_id', 'token_ttl_seconds',
                    'token_scheme', 'rotation_active'):
            self.assertIn(key, document)

    def test_health_never_carries_a_token(self):
        built = service()
        response = built.respond('/page')
        cookie = response.headers['Set-Cookie'].split(';')[0].split('=', 1)[1]
        self.assertNotIn(cookie, str(built.health()))


class TestNoPublicSurface(unittest.TestCase):
    """§65, §66, §67. Nothing here opens a port."""

    def test_the_package_never_imports_a_network_module(self):
        import ast
        from pathlib import Path as P
        import eye_for_an_eye.challenge as package
        root = P(package.__file__).parent
        for path in sorted(root.glob('*.py')):
            with self.subTest(module=path.name):
                tree = ast.parse(path.read_text(encoding='utf-8'))
                imported = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported.update(a.name.split('.')[0] for a in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported.add(node.module.split('.')[0])
                # `urllib.parse` is pure string handling and is allowed; the
                # networking modules are not. The distinction is the point.
                for forbidden in ('socket', 'http', 'requests', 'asyncio',
                                  'socketserver', 'subprocess', 'ftplib', 'smtplib'):
                    self.assertNotIn(forbidden, imported)
                text = path.read_text(encoding='utf-8')
                self.assertNotIn('urllib.request', text)
                self.assertNotIn('urlopen', text)

    def test_nothing_reaches_a_firewall(self):
        from pathlib import Path as P
        import eye_for_an_eye.challenge as package
        root = P(package.__file__).parent
        for path in sorted(root.glob('*.py')):
            text = path.read_text(encoding='utf-8').lower()
            with self.subTest(module=path.name):
                for forbidden in ('nftables', 'iptables', 'firewall'):
                    self.assertNotIn(forbidden, text)


if __name__ == '__main__':
    unittest.main()
