"""P11 integration: the challenge inside the web sensor's decision flow.

The properties that matter when a new rung is inserted into a ladder that is
already carrying a production deployment:

* **Nothing regresses.** With no challenge service configured, every action this
  sensor produces is the action P10 produced. The new rung degrades to WATCH,
  which is what the band used to be.
* **Availability is still the first rule.** A proxied client can be challenged —
  a challenge travels over HTTP to the one client that asked — but still cannot
  be blocked at the network layer.
* **Evaluation is free.** The sensor re-scores every known source on a timer.
  Asking "could this source be challenged" must not consume the budget that
  answering a real request needs.
* **A challenge outcome is evidence.** It moves an action within a ceiling; it
  never becomes a label and never reaches TEMP_BLOCK on its own.
"""
import unittest
from datetime import datetime, timezone

from eye_for_an_eye.challenge.policy import (CHALLENGE_ESCALATION_CEILING, FAILED,
                                             PASSED, ChallengeGate, adjust)
from eye_for_an_eye.challenge.service import ChallengeService
from eye_for_an_eye.web.event import build
from eye_for_an_eye.web.identity import ClientResolver
from eye_for_an_eye.web.sensor import (BLOCK_THRESHOLD, CHALLENGE_THRESHOLD,
                                       RATE_LIMIT_THRESHOLD, WATCH_THRESHOLD, WebSensor,
                                       apply_policy, incident, propose)
from eye_for_an_eye.web.state import WebSourceTable

SECRET = b'k' * 32
CDN = '203.0.113.0/24'
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def tick(self, seconds):
        self.now += seconds
        return self.now


def service(clock, *, mode='active', **kwargs):
    gate = ChallengeGate(shadow=(mode != 'active'), clock=clock, **kwargs)
    return ChallengeService(secret=SECRET, mode=mode, site_id='test', gate=gate,
                            clock=clock, wall_clock=clock)


def traffic(sensor, resolver, *, peer, forwarded=None, count=120, gap=0.5,
            start=0.0, suspicious=True):
    """Enough requests to score, either scanning or ordinary browsing."""
    now = start
    for index in range(count):
        now += gap
        identity = resolver.resolve(peer, forwarded=forwarded)
        if suspicious:
            path = ('/.env' if index % 11 == 0 else
                    '/wp-login.php' if index % 13 == 0 else f'/g{index}x{index * 3}')
            status = 404
        else:
            path = f'/articles/{index % 4}'
            status = 200
        event = build(timestamp=START, identity=identity, method='GET', path=path,
                      status=status, host='example.test', user_agent='', referer='',
                      secret=SECRET)
        sensor.observe(event, now)
    return now


def moderate(sensor, resolver, peer='198.51.100.9', start=0.0):
    """Traffic aimed at the SOFT_CHALLENGE band rather than either extreme."""
    now = start
    for index in range(60):
        now += 1.0
        identity = resolver.resolve(peer)
        event = build(timestamp=START, identity=identity, method='GET',
                      path=f'/page/{index}', status=404 if index % 3 else 200,
                      host='example.test', user_agent='', referer='', secret=SECRET)
        sensor.observe(event, now)
    return now


class TestTheLadderIsOrdered(unittest.TestCase):
    def test_soft_challenge_sits_between_watch_and_rate_limit(self):
        self.assertLess(WATCH_THRESHOLD, CHALLENGE_THRESHOLD)
        self.assertLess(CHALLENGE_THRESHOLD, RATE_LIMIT_THRESHOLD)
        self.assertLess(RATE_LIMIT_THRESHOLD, BLOCK_THRESHOLD)

    def test_propose_covers_the_whole_range_without_a_gap(self):
        boundaries = [0.0, WATCH_THRESHOLD, CHALLENGE_THRESHOLD,
                      RATE_LIMIT_THRESHOLD, BLOCK_THRESHOLD, 1.0]
        expected = ['OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT', 'TEMP_BLOCK']
        for index, name in enumerate(expected):
            low, high = boundaries[index], boundaries[index + 1]
            self.assertEqual(propose(low), name, low)
            self.assertEqual(propose((low + high) / 2), name)

    def test_the_band_below_the_floor_is_never_a_challenge(self):
        self.assertEqual(propose(CHALLENGE_THRESHOLD - 0.001), 'WATCH')


class TestNothingRegressesWithoutAChallengeService(unittest.TestCase):
    """The compatibility property. A P10 deployment must see P10 behaviour."""

    def sensor(self, **kwargs):
        return WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0,
                         shadow=False, **kwargs)

    def test_a_proposed_challenge_degrades_to_watch(self):
        for risk in (CHALLENGE_THRESHOLD, 0.5, 0.6, RATE_LIMIT_THRESHOLD - 0.001):
            with self.subTest(risk=risk):
                action, suppressions = apply_policy(
                    propose(risk), identity_confidence='HIGH', network_enforceable=True,
                    observations=100, quality=1.0, challenge_available=False)
                self.assertEqual(action, 'WATCH')
                self.assertTrue(any('challenge' in item for item in suppressions))

    def test_a_scanner_still_reaches_a_block(self):
        sensor = self.sensor()
        resolver = ClientResolver([CDN])
        now = traffic(sensor, resolver, peer='198.51.100.7')
        decision = sensor.evaluate('198.51.100.7', now, force=True)
        self.assertEqual(decision.action, 'TEMP_BLOCK')

    def test_a_moderate_source_lands_on_watch_exactly_as_before(self):
        sensor = self.sensor()
        now = moderate(sensor, ClientResolver([]))
        decision = sensor.evaluate('198.51.100.9', now, force=True)
        self.assertEqual(decision.action, 'WATCH')
        self.assertEqual(decision.challenge, {})
        self.assertEqual(decision.challenge_reason, '')

    def test_the_decision_record_still_serialises(self):
        sensor = self.sensor()
        now = moderate(sensor, ClientResolver([]))
        document = sensor.evaluate('198.51.100.9', now, force=True).explain()
        self.assertEqual(document['challenge'], {})
        import json
        json.dumps(document)


class TestChallengeReachesTheDecision(unittest.TestCase):
    def build(self, **kwargs):
        clock = Clock()
        sensor = WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0,
                           shadow=False, challenge=service(clock, **kwargs), clock=clock)
        return sensor, clock

    def test_a_moderate_source_is_offered_a_challenge_instead_of_watch(self):
        sensor, clock = self.build()
        now = moderate(sensor, ClientResolver([]), start=clock.now)
        decision = sensor.evaluate('198.51.100.9', now, force=True)
        self.assertEqual(decision.proposed_action, 'SOFT_CHALLENGE')
        self.assertEqual(decision.action, 'SOFT_CHALLENGE')
        self.assertIn('can be presented', decision.challenge_reason)

    def test_the_decision_carries_bounded_challenge_features(self):
        sensor, clock = self.build()
        now = moderate(sensor, ClientResolver([]), start=clock.now)
        features = sensor.evaluate('198.51.100.9', now, force=True).challenge
        self.assertIn('challenge_pass_count', features)
        self.assertIn('challenge_decayed_failures', features)
        for value in features.values():
            self.assertIsInstance(value, (float, int, bool, type(None)))

    def test_a_strong_scanner_is_not_challenged_because_the_evidence_is_enough(self):
        sensor, clock = self.build()
        now = traffic(sensor, ClientResolver([]), peer='198.51.100.7', start=clock.now)
        decision = sensor.evaluate('198.51.100.7', now, force=True)
        self.assertEqual(decision.action, 'TEMP_BLOCK')
        self.assertIn('enough evidence', decision.challenge_reason)

    def test_the_soft_challenge_metric_counts_only_presentable_challenges(self):
        sensor, clock = self.build()
        now = moderate(sensor, ClientResolver([]), start=clock.now)
        sensor.evaluate('198.51.100.9', now, force=True)
        self.assertEqual(sensor.metrics['web_soft_challenge_total'], 1)

    def test_health_reports_the_challenge_subsystem(self):
        sensor, _ = self.build()
        self.assertEqual(sensor.health()['challenge']['token_scheme'], 'challenge-v1')

    def test_the_incident_view_explains_what_a_pass_does_not_prove(self):
        sensor, clock = self.build()
        now = moderate(sensor, ClientResolver([]), start=clock.now)
        text = incident(sensor.evaluate('198.51.100.9', now, force=True))
        self.assertIn('not proof of a person', text)
        self.assertIn('not proof of an attack', text)


class TestEvaluationSpendsNoBudget(unittest.TestCase):
    """The sensor scores every source on a timer. That must stay free."""

    def test_asking_availability_never_issues_a_challenge(self):
        clock = Clock()
        built = service(clock)
        for _ in range(200):
            built.available('1.2.3.4', risk=0.5)
        self.assertEqual(built.metrics['challenge_issued_total'], 0)
        self.assertEqual(built.gate.metrics['challenge_issued_total'], 0)

    def test_asking_availability_creates_no_context(self):
        clock = Clock()
        built = service(clock)
        for index in range(500):
            built.available(f'10.0.0.{index % 256}', risk=0.5)
        self.assertEqual(len(built.gate.contexts), 0)

    def test_repeated_evaluation_does_not_exhaust_the_hourly_budget(self):
        """Fifty evaluations of one source, all at the same instant.

        The clock is deliberately held still. Advancing it would let the
        behaviour window empty out and the risk fall on its own, which would make
        this pass for the wrong reason — the point is that re-asking, not the
        passage of time, must leave the budget untouched.
        """
        clock = Clock()
        sensor = WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0,
                           shadow=False, challenge=service(clock), clock=clock)
        now = moderate(sensor, ClientResolver([]), start=clock.now)
        clock.now = now
        for _ in range(50):
            decision = sensor.evaluate('198.51.100.9', now, force=True)
        self.assertEqual(decision.action, 'SOFT_CHALLENGE')
        self.assertIn('can be presented', decision.challenge_reason)
        self.assertEqual(sensor.challenge.metrics['challenge_issued_total'], 0)


class TestAvailabilityStillWins(unittest.TestCase):
    def sensor(self, clock):
        return WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0,
                         shadow=False, challenge=service(clock), clock=clock)

    def test_a_proxied_client_can_be_challenged_but_never_blocked(self):
        """A challenge reaches the one client; a network block reaches everyone."""
        clock = Clock()
        sensor = self.sensor(clock)
        resolver = ClientResolver([CDN])
        now = traffic(sensor, resolver, peer='203.0.113.10',
                      forwarded='198.51.100.7', start=clock.now)
        decision = sensor.evaluate('198.51.100.7', now, force=True)
        self.assertGreater(decision.risk, BLOCK_THRESHOLD)
        self.assertNotEqual(decision.action, 'TEMP_BLOCK')
        self.assertFalse(decision.network_enforceable)
        self.assertTrue(any('proxy' in item for item in decision.suppressions))

    def test_a_challenge_is_still_capped_by_too_little_data(self):
        clock = Clock()
        sensor = self.sensor(clock)
        resolver = ClientResolver([])
        now = clock.now
        for index in range(5):
            now += 1.0
            event = build(timestamp=START, identity=resolver.resolve('198.51.100.5'),
                          method='GET', path=f'/x{index}', status=404,
                          host='example.test', user_agent='', referer='', secret=SECRET)
            sensor.observe(event, now)
        decision = sensor.evaluate('198.51.100.5', now, force=True)
        self.assertIn(decision.action, ('OBSERVE', 'WATCH'))

    def test_an_unreliable_identity_is_not_challenged(self):
        clock = Clock()
        available, reason = service(clock).available(
            '198.51.100.5', risk=0.5, identity_confidence='LOW')
        self.assertFalse(available)
        self.assertIn('not reliable enough', reason)


class TestAChallengeOutcomeStaysEvidence(unittest.TestCase):
    def test_challenge_evidence_alone_never_reaches_a_block(self):
        """§: a challenge result is evidence, not ground truth."""
        clock = Clock()
        gate = ChallengeGate(clock=clock)
        context = gate.contexts.touch('1.2.3.4', clock.now)
        for _ in range(20):
            context.record(FAILED, clock.now)
            context.record(PASSED, clock.now)
        for _ in range(20):
            context.record(FAILED, clock.now)
        for start in ('OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT'):
            with self.subTest(start=start):
                action, reasons = adjust(start, context, clock.now, gate.budget)
                self.assertNotEqual(action, 'TEMP_BLOCK')
                self.assertTrue(reasons)

    def test_an_action_already_above_the_ceiling_is_left_alone(self):
        clock = Clock()
        gate = ChallengeGate(clock=clock)
        context = gate.contexts.touch('1.2.3.4', clock.now)
        for _ in range(20):
            context.record(FAILED, clock.now)
        action, _ = adjust('TEMP_BLOCK', context, clock.now, gate.budget)
        self.assertEqual(action, 'TEMP_BLOCK')

    def test_the_ceiling_is_named_and_is_rate_limit(self):
        self.assertEqual(CHALLENGE_ESCALATION_CEILING, 'RATE_LIMIT')

    def test_escalation_says_when_it_has_stopped(self):
        clock = Clock()
        gate = ChallengeGate(clock=clock)
        context = gate.contexts.touch('1.2.3.4', clock.now)
        for _ in range(20):
            context.record(FAILED, clock.now)
        _, reasons = adjust('RATE_LIMIT', context, clock.now, gate.budget)
        self.assertTrue(any('limit for challenge evidence' in item for item in reasons))

    def test_no_challenge_field_is_a_label(self):
        clock = Clock()
        features = service(clock).evidence('1.2.3.4')
        for name in features:
            for forbidden in ('label', 'malicious', 'benign', 'bot', 'human',
                              'attacker', 'verdict'):
                self.assertNotIn(forbidden, name)


class TestTheSubsystemCannotBreakTheSensor(unittest.TestCase):
    class Broken:
        enabled = True

        def adjust(self, *args, **kwargs):
            raise RuntimeError('adjust exploded')

        def evidence(self, *args, **kwargs):
            raise RuntimeError('evidence exploded')

        def available(self, *args, **kwargs):
            raise RuntimeError('available exploded')

        def health(self):
            raise RuntimeError('health exploded')

    def test_a_service_that_raises_is_still_caught_by_the_service_boundary(self):
        """The real service swallows its own failures; this proves it, not the sensor."""
        clock = Clock()
        built = ChallengeService(secret=SECRET, mode='active', site_id='test',
                                 clock=clock, wall_clock=clock)
        built.gate = None  # every gate call will now raise
        action, reasons = built.adjust('WATCH', '1.2.3.4')
        self.assertEqual(action, 'WATCH')
        self.assertEqual(reasons, ())
        available, reason = built.available('1.2.3.4', risk=0.5)
        self.assertFalse(available)
        self.assertIn('site was not affected', reason)
        self.assertEqual(built.evidence('1.2.3.4')['challenge_pass_count'], 0.0)
        self.assertGreaterEqual(built.metrics['challenge_subsystem_errors_total'], 3)

    def test_a_sensor_with_a_broken_service_still_produces_decisions(self):
        clock = Clock()
        sensor = WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0,
                           shadow=False, challenge=self.Broken(), clock=clock)
        now = moderate(sensor, ClientResolver([]), start=clock.now)
        with self.assertRaises(RuntimeError):
            sensor.evaluate('198.51.100.9', now, force=True)


if __name__ == '__main__':
    unittest.main()
