"""P11 challenge policy: when to ask, when not to, and what an answer means.

The rules that must hold whatever else changes:

  * passing a challenge does not clear risk
  * failing one does not prove anything
  * neither ever becomes a training label
  * a client cannot be made to loop forever
  * an attacker cannot make the system issue unlimited challenges
"""
import unittest

from eye_for_an_eye.challenge.policy import (ACTIONS, API, AUTH, CHALLENGEABLE_PROFILES,
                                             ChallengeBudget, ChallengeContextTable,
                                             ChallengeGate, ChallengePolicyError,
                                             DEFAULT_ROUTES, FAILED, HEALTH, OUTCOMES,
                                             PASSED, PRESENTED, RouteRule, STRENGTH,
                                             TIMED_OUT, WEBHOOK, WEB_BROWSER, adjust,
                                             evidence, match_route)


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class GateTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()

    def gate(self, **kwargs):
        kwargs.setdefault('clock', self.clock)
        return ChallengeGate(**kwargs)

    def ask(self, gate, **overrides):
        request = {'risk': 0.6, 'confidence': 0.5, 'method': 'GET', 'path': '/page',
                   'network_enforceable': True, 'identity_confidence': 'HIGH',
                   'source': '198.51.100.7'}
        request.update(overrides)
        return gate.decide(**request)


class TestLadder(unittest.TestCase):
    def test_soft_challenge_sits_between_watch_and_rate_limit(self):
        self.assertEqual(ACTIONS,
                         ('OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT', 'TEMP_BLOCK'))
        self.assertLess(STRENGTH['WATCH'], STRENGTH['SOFT_CHALLENGE'])
        self.assertLess(STRENGTH['SOFT_CHALLENGE'], STRENGTH['RATE_LIMIT'])

    def test_no_existing_action_was_removed(self):
        for name in ('OBSERVE', 'WATCH', 'RATE_LIMIT', 'TEMP_BLOCK'):
            self.assertIn(name, ACTIONS)


class TestWhenToChallenge(GateTestCase):
    def test_meaningful_risk_with_middling_confidence_earns_a_challenge(self):
        decision = self.ask(self.gate())
        self.assertTrue(decision.challenge)
        self.assertEqual(decision.action, 'SOFT_CHALLENGE')
        self.assertIn('one more piece', decision.reason)

    def test_low_risk_is_never_challenged(self):
        """§35. A challenge costs the user something."""
        decision = self.ask(self.gate(), risk=0.2)
        self.assertFalse(decision.challenge)
        self.assertIn('below the challenge floor', decision.reason)

    def test_overwhelming_evidence_skips_the_challenge(self):
        """§34. If there is enough to act, a challenge only delays it."""
        decision = self.ask(self.gate(), risk=0.95, confidence=0.9)
        self.assertFalse(decision.challenge)
        self.assertEqual(decision.action, 'RATE_LIMIT')
        self.assertIn('enough evidence to act', decision.reason)

    def test_a_client_holding_a_valid_token_is_not_challenged_again(self):
        decision = self.ask(self.gate(), has_valid_token=True)
        self.assertFalse(decision.challenge)
        self.assertIn('already holds a valid', decision.reason)

    def test_an_unreliable_client_address_is_not_challenged(self):
        decision = self.ask(self.gate(), identity_confidence='LOW')
        self.assertFalse(decision.challenge)
        self.assertIn('not reliable enough', decision.reason)


class TestUnsafeMethods(GateTestCase):
    """§21, §22, §110. A redirect replays the request."""

    def test_a_post_is_never_challenged_with_a_redirect(self):
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            with self.subTest(method=method):
                decision = self.ask(self.gate(), method=method)
                self.assertFalse(decision.challenge)
                self.assertIn('state-changing', decision.reason)
                self.assertEqual(decision.action, 'WATCH')

    def test_get_and_head_may_be_challenged(self):
        for method in ('GET', 'HEAD'):
            with self.subTest(method=method):
                self.assertTrue(self.ask(self.gate(), method=method).challenge)


class TestRoutePolicy(GateTestCase):
    """§49–§54. A challenge that breaks a route proves nothing."""

    def test_an_api_route_is_not_challenged_by_default(self):
        decision = self.ask(self.gate(), path='/api/v1/orders')
        self.assertFalse(decision.challenge)
        self.assertEqual(decision.profile, API)
        self.assertIn('route policy does not use browser challenges', decision.reason)

    def test_an_auth_route_is_not_challenged_by_default(self):
        for path in ('/login', '/oauth/callback', '/auth/token'):
            with self.subTest(path=path):
                decision = self.ask(self.gate(), path=path)
                self.assertFalse(decision.challenge)
                self.assertEqual(decision.profile, AUTH)

    def test_a_webhook_is_not_challenged(self):
        """§53. Machine-to-machine callers cannot complete a cookie flow."""
        decision = self.ask(self.gate(), path='/webhooks/stripe')
        self.assertFalse(decision.challenge)
        self.assertEqual(decision.profile, WEBHOOK)

    def test_a_health_check_is_not_challenged(self):
        decision = self.ask(self.gate(), path='/healthz')
        self.assertFalse(decision.challenge)
        self.assertEqual(decision.profile, HEALTH)

    def test_an_ordinary_page_is_challengeable(self):
        decision = self.ask(self.gate(), path='/blog/post-1')
        self.assertTrue(decision.challenge)
        self.assertEqual(decision.profile, WEB_BROWSER)

    def test_the_longest_matching_prefix_wins(self):
        routes = (RouteRule('/', WEB_BROWSER, True),
                  RouteRule('/api/', API, False),
                  RouteRule('/api/public/', WEB_BROWSER, True))
        self.assertEqual(match_route('/api/private', routes).profile, API)
        self.assertEqual(match_route('/api/public/x', routes).profile, WEB_BROWSER)
        self.assertEqual(match_route('/other', routes).profile, WEB_BROWSER)

    def test_an_operator_can_override_the_defaults(self):
        routes = (RouteRule('/api/', API, challenge=True), RouteRule('/', WEB_BROWSER))
        self.assertTrue(self.ask(self.gate(routes=routes), path='/api/x').challenge)

    def test_an_unknown_path_falls_back_to_not_challenging(self):
        self.assertFalse(match_route('/x', ()).challenge)

    def test_a_bad_route_rule_is_refused(self):
        with self.assertRaises(ChallengePolicyError):
            RouteRule('no-leading-slash')
        with self.assertRaises(ChallengePolicyError):
            RouteRule('/x', 'not-a-profile')

    def test_only_browser_like_profiles_are_challengeable(self):
        self.assertNotIn(API, CHALLENGEABLE_PROFILES)
        self.assertNotIn(AUTH, CHALLENGEABLE_PROFILES)
        self.assertNotIn(WEBHOOK, CHALLENGEABLE_PROFILES)
        self.assertNotIn(HEALTH, CHALLENGEABLE_PROFILES)

    def test_the_defaults_protect_the_routes_that_break(self):
        for path in ('/api/x', '/login', '/oauth/cb', '/webhook', '/healthz'):
            with self.subTest(path=path):
                self.assertFalse(match_route(path, DEFAULT_ROUTES).challenge)


class TestLoopPrevention(GateTestCase):
    """§37. A client that cannot keep a cookie must not cycle forever."""

    def test_a_cookieless_client_stops_being_challenged(self):
        gate = self.gate(budget=ChallengeBudget(max_attempts=3,
                                                minimum_seconds_between=0))
        issued = 0
        for _ in range(20):
            self.clock.advance(30)
            if self.ask(gate).challenge:
                issued += 1
        self.assertLessEqual(issued, 3)
        self.assertGreaterEqual(gate.metrics['challenge_loop_prevented_total'], 1)

    def test_the_loop_stop_hands_back_a_stronger_action(self):
        gate = self.gate(budget=ChallengeBudget(max_attempts=2,
                                                minimum_seconds_between=0))
        for _ in range(3):
            self.clock.advance(30)
            decision = self.ask(gate)
        self.assertFalse(decision.challenge)
        self.assertEqual(decision.action, 'RATE_LIMIT')
        self.assertIn('would loop', decision.reason)

    def test_two_challenges_in_a_row_are_spaced_out(self):
        gate = self.gate(budget=ChallengeBudget(minimum_seconds_between=10))
        self.assertTrue(self.ask(gate).challenge)
        self.clock.advance(2)
        decision = self.ask(gate)
        self.assertFalse(decision.challenge)
        self.assertIn('moments ago', decision.reason)

    def test_passing_resets_the_attempt_counter(self):
        gate = self.gate(budget=ChallengeBudget(max_attempts=3,
                                                minimum_seconds_between=0,
                                                grace_seconds=0))
        for _ in range(2):
            self.clock.advance(30)
            self.ask(gate)
        gate.record_outcome('198.51.100.7', PASSED, now=self.clock())
        self.clock.advance(30)
        self.assertTrue(self.ask(gate).challenge)


class TestBudget(GateTestCase):
    """§36, §81. An attacker can trigger challenges deliberately."""

    def test_one_source_has_an_hourly_limit(self):
        gate = self.gate(budget=ChallengeBudget(per_source_per_hour=3, max_attempts=10,
                                                minimum_seconds_between=0))
        # No PASSED is recorded: a pass would open the grace window, and grace
        # would refuse before the budget check was ever reached. This test is
        # about the budget, so the client simply ignores every challenge.
        issued = 0
        for _ in range(8):
            self.clock.advance(20)
            if self.ask(gate).challenge:
                issued += 1
        self.assertLessEqual(issued, 3)
        self.assertGreaterEqual(gate.metrics['challenge_budget_rejected_total'], 1)

    def test_the_global_rate_is_capped(self):
        gate = self.gate(budget=ChallengeBudget(per_second=5, per_source_per_hour=1000,
                                                max_attempts=10,
                                                minimum_seconds_between=0))
        issued = sum(1 for index in range(100)
                     if self.ask(gate, source=f'198.51.100.{index}').challenge)
        self.assertLessEqual(issued, 5)

    def test_the_global_rate_recovers_after_a_second(self):
        gate = self.gate(budget=ChallengeBudget(per_second=2, per_source_per_hour=1000,
                                                max_attempts=10,
                                                minimum_seconds_between=0))
        for index in range(5):
            self.ask(gate, source=f'198.51.100.{index}')
        self.clock.advance(2.0)
        self.assertTrue(self.ask(gate, source='198.51.100.99').challenge)

    def test_a_flood_of_sources_leaves_context_memory_bounded(self):
        """§82. Distributed sources must not fill the table."""
        gate = self.gate(budget=ChallengeBudget(concurrent_contexts=100,
                                                per_source_per_hour=1000,
                                                per_second=10_000, max_attempts=10,
                                                minimum_seconds_between=0))
        for index in range(20_000):
            self.ask(gate, source=f'198.51.{index // 250}.{index % 250}')
        self.assertLessEqual(len(gate.contexts), 100)
        self.assertGreater(gate.contexts.evictions, 0)

    def test_impossible_budgets_are_refused(self):
        for kwargs in ({'per_source_per_hour': 0}, {'per_second': 0},
                       {'max_attempts': 0}, {'max_attempts': 11},
                       {'concurrent_contexts': 0}, {'failure_decay_seconds': 1}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ChallengePolicyError):
                    ChallengeBudget(**kwargs)

    def test_an_inverted_floor_and_ceiling_is_refused(self):
        with self.assertRaises(ChallengePolicyError):
            ChallengeGate(floor=0.9, ceiling=0.5)


class TestGrace(GateTestCase):
    """§96, §97. A recent pass buys quiet, not immunity."""

    def test_a_recent_pass_prevents_immediate_re_challenge(self):
        gate = self.gate(budget=ChallengeBudget(grace_seconds=300,
                                                minimum_seconds_between=0))
        gate.record_outcome('198.51.100.7', PASSED, now=self.clock())
        self.clock.advance(30)
        decision = self.ask(gate)
        self.assertFalse(decision.challenge)
        self.assertIn('passed a challenge recently', decision.reason)

    def test_strong_new_evidence_cancels_the_grace(self):
        gate = self.gate(budget=ChallengeBudget(grace_seconds=300,
                                                minimum_seconds_between=0))
        gate.record_outcome('198.51.100.7', PASSED, now=self.clock())
        self.clock.advance(30)
        decision = self.ask(gate, risk=0.95, confidence=0.4)
        self.assertTrue(decision.challenge, 'a pass must not buy immunity')

    def test_the_grace_window_expires(self):
        gate = self.gate(budget=ChallengeBudget(grace_seconds=60,
                                                minimum_seconds_between=0))
        gate.record_outcome('198.51.100.7', PASSED, now=self.clock())
        self.clock.advance(120)
        self.assertTrue(self.ask(gate).challenge)


class TestOutcomeIsEvidenceNotTruth(GateTestCase):
    """§39, §41, §42, §43. The heart of P11."""

    def context(self, gate, outcomes):
        for outcome in outcomes:
            gate.record_outcome('198.51.100.7', outcome, now=self.clock())
            self.clock.advance(1)
        return gate.contexts.get('198.51.100.7')

    def test_passing_alone_changes_nothing(self):
        gate = self.gate()
        context = self.context(gate, [PRESENTED, PASSED])
        action, reasons = adjust('SOFT_CHALLENGE', context, self.clock())
        self.assertEqual(action, 'SOFT_CHALLENGE')
        self.assertEqual(reasons, ())

    def test_passing_then_behaving_normally_lowers_the_action(self):
        gate = self.gate()
        context = self.context(gate, [PRESENTED, PASSED])
        for _ in range(6):
            gate.record_activity('198.51.100.7', suspicious=False, now=self.clock())
        action, reasons = adjust('SOFT_CHALLENGE', context, self.clock())
        self.assertEqual(action, 'WATCH')
        self.assertTrue(any('behaved normally since' in reason for reason in reasons))

    def test_passing_then_continuing_to_probe_raises_the_action(self):
        """§42. The most valuable signal a challenge produces."""
        gate = self.gate()
        context = self.context(gate, [PRESENTED, PASSED])
        for _ in range(8):
            gate.record_activity('198.51.100.7', suspicious=True, now=self.clock())
        action, reasons = adjust('SOFT_CHALLENGE', context, self.clock())
        self.assertEqual(action, 'RATE_LIMIT')
        self.assertTrue(any('continued probing' in reason for reason in reasons))

    def test_one_failure_proves_nothing(self):
        gate = self.gate()
        context = self.context(gate, [PRESENTED, FAILED])
        action, _ = adjust('SOFT_CHALLENGE', context, self.clock())
        self.assertEqual(action, 'SOFT_CHALLENGE')

    def test_repeated_failures_raise_the_action_by_one_step_only(self):
        gate = self.gate()
        context = self.context(gate, [FAILED] * 6)
        action, reasons = adjust('SOFT_CHALLENGE', context, self.clock())
        self.assertEqual(action, 'RATE_LIMIT')
        self.assertTrue(any('challenge failures' in reason for reason in reasons))

    def test_failures_decay_with_time(self):
        """§95. A browser that dropped a cookie last week is not evidence now."""
        gate = self.gate()
        budget = ChallengeBudget(failure_decay_seconds=1800)
        context = self.context(gate, [FAILED] * 5)
        fresh = context.decayed_failures(self.clock(), budget)
        self.clock.advance(1700)
        aged = context.decayed_failures(self.clock(), budget)
        self.assertGreater(fresh, aged)
        self.clock.advance(2000)
        self.assertEqual(context.decayed_failures(self.clock(), budget), 0.0)

    def test_no_outcome_ever_reaches_temp_block_on_its_own(self):
        gate = self.gate()
        context = self.context(gate, [FAILED] * 10)
        action, _ = adjust('WATCH', context, self.clock())
        self.assertNotEqual(action, 'TEMP_BLOCK')

    def test_an_unknown_outcome_is_refused(self):
        with self.assertRaises(ChallengePolicyError):
            self.gate().record_outcome('x', 'malicious')

    def test_the_outcome_vocabulary_has_no_verdict_in_it(self):
        for name in OUTCOMES:
            self.assertNotIn('malicious', name)
            self.assertNotIn('benign', name)
            self.assertNotIn('bot', name)


class TestEvidenceFeatures(GateTestCase):
    """§40, §128. Features, and one that is deliberately excluded from models."""

    def test_an_unknown_source_produces_empty_evidence(self):
        values = evidence(None, self.clock())
        self.assertEqual(values['challenge_presented_count'], 0.0)
        self.assertIsNone(values['challenge_pass_ratio'])
        self.assertFalse(values['continued_after_pass'])

    def test_counts_are_recorded(self):
        gate = self.gate()
        for outcome in (PRESENTED, PASSED, PRESENTED, FAILED, PRESENTED, TIMED_OUT):
            gate.record_outcome('198.51.100.7', outcome, now=self.clock())
        values = evidence(gate.contexts.get('198.51.100.7'), self.clock())
        self.assertEqual(values['challenge_presented_count'], 3.0)
        self.assertEqual(values['challenge_pass_count'], 1.0)
        self.assertEqual(values['challenge_fail_count'], 1.0)
        self.assertEqual(values['challenge_timeout_count'], 1.0)

    def test_continuation_after_a_pass_is_a_named_feature(self):
        gate = self.gate()
        gate.record_outcome('198.51.100.7', PASSED, now=self.clock())
        gate.record_activity('198.51.100.7', suspicious=True, now=self.clock())
        values = evidence(gate.contexts.get('198.51.100.7'), self.clock())
        self.assertTrue(values['continued_after_pass'])
        self.assertEqual(values['suspicious_after_pass'], 1.0)

    def test_the_feedback_loop_risk_is_documented_in_the_code(self):
        """§128, §129. `challenge_presented` encodes the system's own decision."""
        import inspect
        from eye_for_an_eye.challenge import policy
        # Normalise wrapping: the phrase is split across lines in the docstring.
        source = ' '.join(inspect.getsource(policy.evidence).split())
        self.assertIn('feedback loop', source)
        self.assertIn('reproduce its own earlier decision', source)

    def test_no_feature_is_a_label(self):
        gate = self.gate()
        gate.record_outcome('198.51.100.7', FAILED, now=self.clock())
        context = gate.contexts.get('198.51.100.7')
        values = evidence(context, self.clock())
        for name in values:
            self.assertNotIn('label', name)
            self.assertNotIn('malicious', name)
            self.assertNotIn('benign', name)
        self.assertIn('never a training label', context.explain()['meaning'])


class TestContextTable(unittest.TestCase):
    def test_contexts_expire(self):
        table = ChallengeContextTable(ttl_seconds=600)
        table.touch('a', 0.0)
        table.touch('b', 10.0)
        self.assertEqual(table.expire(1000.0), 2)
        self.assertEqual(len(table), 0)

    def test_the_table_is_bounded(self):
        table = ChallengeContextTable(budget=ChallengeBudget(concurrent_contexts=50))
        for index in range(5000):
            table.touch(f'source-{index}', float(index))
        self.assertLessEqual(len(table), 50)

    def test_a_context_holds_no_identity(self):
        table = ChallengeContextTable()
        document = table.touch('198.51.100.7', 0.0).explain()
        for forbidden in ('address', 'session', 'user', 'account', 'token'):
            self.assertNotIn(forbidden, document)


if __name__ == '__main__':
    unittest.main()
