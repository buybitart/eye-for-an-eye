"""P10 enforcement safety.

One question, asked from several directions: can suspicious web behaviour get a
reverse proxy or CDN address blocked at the network layer? If it can, one
scanner takes the whole site off the air, and the protection has become the
outage it was meant to prevent.

§66 and §141 call this the critical regression test. It is.
"""
import unittest
from datetime import datetime, timezone

from eye_for_an_eye.web.event import build
from eye_for_an_eye.web.identity import ClientResolver
from eye_for_an_eye.web.sensor import (BLOCK_THRESHOLD, MINIMUM_REQUESTS_FOR_ACTION,
                                       WebSensor, apply_policy, data_quality, incident,
                                       propose)
from eye_for_an_eye.web.state import WebSourceTable

SECRET = b'k' * 32
CDN = '203.0.113.0/24'
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def enumerate_paths(sensor, resolver, *, peer, forwarded=None, count=120, gap=0.5):
    """Unmistakable path enumeration from one client."""
    now = 0.0
    for index in range(count):
        now += gap
        identity = resolver.resolve(peer, forwarded=forwarded)
        event = build(timestamp=START, identity=identity, method='GET',
                      path=('/.env' if index % 11 == 0 else
                            '/wp-login.php' if index % 13 == 0 else f'/g{index}x{index * 3}'),
                      status=404, host='example.test', user_agent='', referer='',
                      secret=SECRET)
        sensor.observe(event, now)
    return now


class TestProxyIsNeverBlocked(unittest.TestCase):
    def sensor(self, **kwargs):
        kwargs.setdefault('shadow', False)
        return WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0, **kwargs)

    def test_a_direct_scanner_can_reach_a_block(self):
        """The control case. Without this the safety test proves nothing."""
        resolver = ClientResolver([CDN])
        sensor = self.sensor()
        now = enumerate_paths(sensor, resolver, peer='198.51.100.7')
        decision = sensor.evaluate('198.51.100.7', now, force=True)
        self.assertGreater(decision.risk, BLOCK_THRESHOLD)
        self.assertEqual(decision.action, 'TEMP_BLOCK')
        self.assertEqual(decision.scope, 'NETWORK_SOURCE')
        self.assertTrue(decision.network_enforceable)

    def test_the_same_scanner_behind_a_cdn_never_reaches_a_block(self):
        """Identical behaviour, one hop away. The action must be capped."""
        resolver = ClientResolver([CDN])
        sensor = self.sensor()
        now = enumerate_paths(sensor, resolver, peer='203.0.113.10',
                              forwarded='198.51.100.7')
        decision = sensor.evaluate('198.51.100.7', now, force=True)
        self.assertGreater(decision.risk, BLOCK_THRESHOLD,
                           'the behaviour is still recognised as bad')
        self.assertEqual(decision.proposed_action, 'TEMP_BLOCK')
        self.assertEqual(decision.action, 'RATE_LIMIT', 'but it must not be blocked')
        self.assertFalse(decision.network_enforceable)
        self.assertTrue(any('every other visitor' in item
                            for item in decision.suppressions))

    def test_the_cdn_address_itself_never_becomes_a_source(self):
        """The proxy is never the thing judged, so it cannot be the thing blocked."""
        resolver = ClientResolver([CDN])
        sensor = self.sensor()
        now = enumerate_paths(sensor, resolver, peer='203.0.113.10',
                              forwarded='198.51.100.7')
        self.assertIsNone(sensor.table.get('203.0.113.10'))
        self.assertIsNotNone(sensor.table.get('198.51.100.7'))
        self.assertIsNone(sensor.evaluate('203.0.113.10', now, force=True))

    def test_one_bad_client_among_a_hundred_does_not_affect_the_others(self):
        """§141. A hundred logical clients behind one proxy address."""
        resolver = ClientResolver([CDN])
        sensor = self.sensor()
        now = 0.0
        for index in range(1, 101):
            for _ in range(6):
                now += 0.1
                identity = resolver.resolve('203.0.113.10',
                                            forwarded=f'198.51.100.{index}')
                sensor.observe(build(timestamp=START, identity=identity, method='GET',
                                     path='/', status=200, secret=SECRET), now)
        now = enumerate_paths(sensor, resolver, peer='203.0.113.10',
                              forwarded='198.51.100.200')
        bad = sensor.evaluate('198.51.100.200', now, force=True)
        self.assertGreater(bad.risk, BLOCK_THRESHOLD)
        self.assertNotEqual(bad.action, 'TEMP_BLOCK')
        for index in (1, 50, 100):
            good = sensor.evaluate(f'198.51.100.{index}', now, force=True)
            self.assertEqual(good.action, 'OBSERVE', f'client {index} was affected')

    def test_a_source_seen_both_directly_and_through_a_proxy_is_not_blockable(self):
        """One proxied request is enough: the address may not be what gets hit."""
        resolver = ClientResolver([CDN])
        sensor = self.sensor()
        now = enumerate_paths(sensor, resolver, peer='198.51.100.7')
        identity = resolver.resolve('203.0.113.10', forwarded='198.51.100.7')
        sensor.observe(build(timestamp=START, identity=identity, method='GET', path='/',
                             status=200, secret=SECRET), now + 1)
        decision = sensor.evaluate('198.51.100.7', now + 2, force=True)
        self.assertFalse(decision.network_enforceable)
        self.assertNotEqual(decision.action, 'TEMP_BLOCK')


class TestPolicyOnlyWeakens(unittest.TestCase):
    """Every path through the policy must reduce the action, never raise it."""

    ORDER = {'OBSERVE': 0, 'WATCH': 1, 'RATE_LIMIT': 2, 'TEMP_BLOCK': 3}

    def test_no_combination_of_inputs_ever_raises_an_action(self):
        for proposed in ('OBSERVE', 'WATCH', 'RATE_LIMIT', 'TEMP_BLOCK'):
            for confidence in ('HIGH', 'MEDIUM', 'LOW'):
                for enforceable in (True, False):
                    for observations in (1, 10, 100):
                        for quality in (0.1, 0.5, 1.0):
                            with self.subTest(proposed=proposed, confidence=confidence,
                                              enforceable=enforceable,
                                              observations=observations, quality=quality):
                                action, _ = apply_policy(
                                    proposed, identity_confidence=confidence,
                                    network_enforceable=enforceable,
                                    observations=observations, quality=quality)
                                self.assertLessEqual(self.ORDER[action],
                                                     self.ORDER[proposed])

    def test_a_low_confidence_identity_can_never_be_acted_on(self):
        for proposed in ('RATE_LIMIT', 'TEMP_BLOCK'):
            action, suppressions = apply_policy(
                proposed, identity_confidence='LOW', network_enforceable=True,
                observations=500, quality=1.0)
            self.assertEqual(action, 'WATCH')
            self.assertTrue(any('not reliable enough' in item for item in suppressions))

    def test_thin_evidence_can_never_be_acted_on(self):
        action, suppressions = apply_policy(
            'TEMP_BLOCK', identity_confidence='HIGH', network_enforceable=True,
            observations=MINIMUM_REQUESTS_FOR_ACTION - 1, quality=1.0)
        self.assertEqual(action, 'WATCH')
        self.assertTrue(any('fewer than' in item for item in suppressions))

    def test_poor_data_quality_can_never_be_acted_on(self):
        action, _ = apply_policy('TEMP_BLOCK', identity_confidence='HIGH',
                                 network_enforceable=True, observations=500, quality=0.2)
        self.assertEqual(action, 'WATCH')

    def test_every_suppression_is_explained(self):
        _, suppressions = apply_policy('TEMP_BLOCK', identity_confidence='LOW',
                                       network_enforceable=False, observations=3,
                                       quality=0.1)
        self.assertGreaterEqual(len(suppressions), 3)
        for item in suppressions:
            self.assertGreater(len(item), 20, 'a suppression must say why')


class TestShadowIsDefault(unittest.TestCase):
    def test_a_sensor_is_in_shadow_mode_unless_told_otherwise(self):
        self.assertTrue(WebSensor(None).shadow)

    def test_shadow_mode_says_nothing_was_enforced(self):
        resolver = ClientResolver([])
        sensor = WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0)
        now = enumerate_paths(sensor, resolver, peer='198.51.100.7')
        decision = sensor.evaluate('198.51.100.7', now, force=True)
        self.assertEqual(decision.proposed_action, 'TEMP_BLOCK')
        self.assertTrue(decision.shadow)
        self.assertFalse(decision.enforced)
        self.assertTrue(any('nothing was enforced' in item
                            for item in decision.suppressions))
        self.assertEqual(sensor.metrics['web_shadow_would_block_total'], 1)

    def test_the_sensor_never_touches_a_firewall(self):
        import ast
        from pathlib import Path
        from eye_for_an_eye.web import sensor as module
        tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for forbidden in ('firewall', 'security', 'nftables', 'subprocess', 'socket'):
            self.assertFalse(any(forbidden in name for name in imported), forbidden)


class TestDataQuality(unittest.TestCase):
    def features(self, observations=100, seconds=120.0, saturated=False):
        from eye_for_an_eye.web.features import WebFeatures
        return WebFeatures(values={}, observations=observations,
                           observation_seconds=seconds, saturated_paths=saturated)

    def test_plenty_of_clean_evidence_is_high_quality(self):
        score, reasons = data_quality(self.features())
        self.assertEqual(score, 1.0)
        self.assertEqual(reasons, ())

    def test_few_requests_lower_quality(self):
        score, reasons = data_quality(self.features(observations=4))
        self.assertLess(score, 0.5)
        self.assertTrue(any('only 4 requests' in reason for reason in reasons))

    def test_a_short_window_lowers_quality(self):
        score, _ = data_quality(self.features(seconds=3.0))
        self.assertLess(score, 1.0)

    def test_lost_log_lines_lower_quality(self):
        from eye_for_an_eye.web.nginx import ReaderStats
        stats = ReaderStats(lines_read=100, parse_errors=40)
        score, reasons = data_quality(self.features(), stats)
        self.assertLess(score, 1.0)
        self.assertTrue(any('could not be read' in reason for reason in reasons))

    def test_an_uncertain_identity_lowers_quality(self):
        high, _ = data_quality(self.features(), None, 'HIGH')
        medium, _ = data_quality(self.features(), None, 'MEDIUM')
        low, _ = data_quality(self.features(), None, 'LOW')
        self.assertGreater(high, medium)
        self.assertGreater(medium, low)

    def test_a_saturated_path_counter_is_said_out_loud(self):
        _, reasons = data_quality(self.features(saturated=True))
        self.assertTrue(any('saturated' in reason for reason in reasons))


class TestIncidentReport(unittest.TestCase):
    def decision(self):
        resolver = ClientResolver([CDN])
        sensor = WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0)
        now = enumerate_paths(sensor, resolver, peer='203.0.113.10',
                              forwarded='198.51.100.7')
        return sensor.evaluate('198.51.100.7', now, force=True)

    def test_the_report_has_the_documented_shape(self):
        text = incident(self.decision())
        for heading in ('WEB INCIDENT', 'Source:', 'Requests:', 'Unique paths:',
                        'Not found:', 'Sensitive probes:', 'Web risk:', 'Decision:'):
            self.assertIn(heading, text)

    def test_the_report_explains_why_the_action_was_reduced(self):
        text = incident(self.decision())
        self.assertIn('Reduced because:', text)
        self.assertIn('every other visitor', text)

    def test_the_report_never_claims_to_identify_a_person(self):
        text = incident(self.decision()).lower()
        for word in ('hacker', 'attacker', 'criminal', 'ai found'):
            self.assertNotIn(word, text)
        self.assertIn('does not identify a person', text)

    def test_the_report_needs_no_model(self):
        import ast
        from pathlib import Path
        from eye_for_an_eye.web import sensor as module
        source = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
        text = ast.unparse(source).lower()
        for forbidden in ('onnx', 'llm', 'openai', 'transformer'):
            self.assertNotIn(forbidden, text)


class TestThresholds(unittest.TestCase):
    def test_the_ladder_matches_the_network_side(self):
        self.assertEqual(propose(0.0), 'OBSERVE')
        self.assertEqual(propose(0.40), 'WATCH')
        self.assertEqual(propose(0.70), 'RATE_LIMIT')
        self.assertEqual(propose(0.88), 'TEMP_BLOCK')
        self.assertEqual(propose(1.0), 'TEMP_BLOCK')


if __name__ == '__main__':
    unittest.main()
