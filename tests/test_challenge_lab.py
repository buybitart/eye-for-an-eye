"""P11 LAB scenarios (§104-§113, §121, §142, §143), through the real gateway.

These run the actual challenge flow end to end — token issued, cookie carried,
request repeated, outcome recorded — against thirteen scripted clients. Nothing
here talks to a network and no fixture is a recording of anyone's traffic.

The results worth reading are the uncomfortable ones. `patient_scanner` passes
every challenge it is given; if passing were treated as proof of anything, it
would be the safest client on the list. It is not, and the tests below say so.
"""
import unittest
from datetime import datetime, timezone
from functools import partial

from eye_for_an_eye.challenge import policy
from eye_for_an_eye.challenge.policy import ChallengeGate
from eye_for_an_eye.challenge.service import ChallengeService
from eye_for_an_eye.web import lab
from eye_for_an_eye.web.event import build
from eye_for_an_eye.web.gateway import CHALLENGE, PASS, WebGateway
from eye_for_an_eye.web.identity import ClientResolver
from eye_for_an_eye.web.lab import (AUTOMATED, CLIENTS_BY_NAME, LAB_CLIENTS, ORDINARY,
                                    summarise)
from eye_for_an_eye.web.sensor import WebSensor
from eye_for_an_eye.web.state import WebSourceTable

SECRET = b'k' * 32
CDN = '203.0.113.0/24'
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


def event(*, identity, method, path, status, host, user_agent):
    return build(timestamp=START, identity=identity, method=method, path=path,
                 status=status, host=host, user_agent=user_agent, referer='',
                 secret=SECRET)


class Harness:
    """A site: resolver, sensor, challenge service and gateway, wired as shipped."""

    def __init__(self, *, proxies=(), mode='active', shadow_sensor=False, **budget):
        self.clock = Clock()
        self.resolver = ClientResolver(list(proxies))
        gate = ChallengeGate(shadow=(mode != 'active'), clock=self.clock, **budget)
        self.challenge = ChallengeService(secret=SECRET, mode=mode, site_id='lab',
                                          gate=gate, clock=self.clock,
                                          wall_clock=self.clock)
        self.sensor = WebSensor(None, table=WebSourceTable(), evaluation_interval=0.0,
                                shadow=shadow_sensor, challenge=self.challenge,
                                clock=self.clock)
        self.gateway = WebGateway(resolver=self.resolver, challenge=self.challenge,
                                  sensor=self.sensor, clock=self.clock)

    def play(self, name, *, peer, forwarded=None, start=0.0):
        return lab.run(CLIENTS_BY_NAME[name], gateway=self.gateway, sensor=self.sensor,
                       resolver=self.resolver, event_builder=partial(event),
                       peer=peer, forwarded=forwarded, start=start)


class TestTheFixtureSetIsHonest(unittest.TestCase):
    def test_every_scenario_the_brief_asks_for_exists(self):
        expected = {'normal_browser', 'cookie_enabled_browser', 'privacy_browser',
                    'slow_browser', 'api_client', 'crawler', 'health_checker',
                    'cookieless_scanner', 'cookie_aware_scanner', 'patient_scanner',
                    'challenge_loop_bot', 'distributed_scanner', 'slow_scanner'}
        self.assertEqual(set(CLIENTS_BY_NAME), expected)

    def test_the_ordinary_set_is_not_stacked_with_easy_cases(self):
        """Three ordinary fixtures cannot hold a cookie. That is the point."""
        ordinary = [item for item in LAB_CLIENTS if item.intent == ORDINARY]
        self.assertGreaterEqual(sum(1 for item in ordinary if not item.keeps_cookies), 3)

    def test_one_automated_fixture_completes_every_challenge(self):
        patient = CLIENTS_BY_NAME['patient_scanner']
        self.assertEqual(patient.intent, AUTOMATED)
        self.assertTrue(patient.keeps_cookies and patient.follows_redirects)

    def test_intent_is_labelled_as_a_property_of_the_fixture(self):
        text = lab.__doc__ + (lab.LabResult.explain.__doc__ or '')
        self.assertIn('not a', text.lower())
        note = lab.LabResult('x', ORDINARY).explain()['note']
        self.assertIn('never a training label', note)


class TestOrdinaryClients(unittest.TestCase):
    """§104, §108, §142. What the protection costs someone who did nothing."""

    def setUp(self):
        self.site = Harness()

    def run_ordinary(self):
        results, peer = [], 10
        for client in LAB_CLIENTS:
            if client.intent != ORDINARY:
                continue
            peer += 1
            results.append(self.site.play(client.name, peer=f'198.51.100.{peer}'))
        return results

    def test_an_ordinary_browser_is_never_challenged(self):
        result = self.site.play('normal_browser', peer='198.51.100.11')
        self.assertEqual(result.challenges_seen, 0)
        self.assertEqual(result.final_action, 'OBSERVE')

    def test_a_privacy_browser_that_blocks_cookies_is_not_punished_for_it(self):
        result = self.site.play('privacy_browser', peer='198.51.100.13')
        self.assertEqual(result.challenges_seen, 0)
        self.assertNotEqual(result.final_action, 'TEMP_BLOCK')

    def test_a_slow_browser_is_not_challenged_for_being_slow(self):
        result = self.site.play('slow_browser', peer='198.51.100.14')
        self.assertEqual(result.challenges_seen, 0)

    def test_a_health_checker_hitting_one_path_forever_is_left_alone(self):
        result = self.site.play('health_checker', peer='198.51.100.17')
        self.assertEqual(result.challenges_seen, 0)
        self.assertNotEqual(result.final_action, 'TEMP_BLOCK')

    def test_a_crawler_is_not_challenged_merely_for_being_a_crawler(self):
        result = self.site.play('crawler', peer='198.51.100.16')
        self.assertEqual(result.challenges_seen, 0)

    def test_no_ordinary_fixture_reaches_a_block(self):
        for result in self.run_ordinary():
            with self.subTest(client=result.name):
                self.assertNotEqual(result.final_action, 'TEMP_BLOCK')

    def test_the_summary_reports_no_cost_to_ordinary_clients(self):
        report = summarise(self.run_ordinary())
        self.assertEqual(report['ordinary_challenge_rate'], 0.0)
        self.assertEqual(report['ordinary_extra_requests'], 0)
        self.assertEqual(report['ordinary_reaching_block'], 0.0)

    def test_the_summary_refuses_to_claim_real_world_accuracy(self):
        self.assertIn('not real-world accuracy', summarise(self.run_ordinary())['note'])


class TestApiClients(unittest.TestCase):
    """§49, §50, §109. An API client cannot complete a browser challenge."""

    def test_an_api_route_is_never_sent_an_html_challenge(self):
        site = Harness()
        result = site.play('api_client', peer='198.51.100.15')
        self.assertEqual(result.challenges_seen, 0)

    def test_a_suspicious_api_client_is_still_refused_a_challenge(self):
        site = Harness()
        plan = site.gateway.handle(peer='198.51.100.15', method='GET',
                                   path='/api/v1/items', now=1.0)
        # Force the risk high enough that a browser route would be challenged.
        site.sensor._last_risk['198.51.100.15'] = 0.6
        plan = site.gateway.handle(peer='198.51.100.15', method='GET',
                                   path='/api/v1/items', now=2.0)
        self.assertEqual(plan.plan, PASS)
        self.assertEqual(plan.profile, policy.API)
        self.assertIn('route policy', plan.reason)


class TestUnsafeMethods(unittest.TestCase):
    """§21, §22, §110. A redirect replays the request."""

    def test_a_suspicious_post_is_never_redirected(self):
        site = Harness()
        site.sensor._last_risk['198.51.100.30'] = 0.6
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            with self.subTest(method=method):
                plan = site.gateway.handle(peer='198.51.100.30', method=method,
                                           path='/checkout', now=5.0)
                self.assertEqual(plan.plan, PASS)
                self.assertEqual(plan.status, 0)
                self.assertIn('safe', plan.reason)

    def test_a_get_at_the_same_risk_is_challenged(self):
        """The control. Without it the test above proves only that nothing works."""
        site = Harness()
        site.sensor._last_risk['198.51.100.31'] = 0.6
        plan = site.gateway.handle(peer='198.51.100.31', method='GET',
                                   path='/shop', now=5.0)
        self.assertEqual(plan.plan, CHALLENGE)


class TestScanners(unittest.TestCase):
    """§106, §107, §143."""

    def test_a_cookieless_scanner_is_challenged_and_stops_being_asked(self):
        site = Harness()
        result = site.play('cookieless_scanner', peer='198.51.100.40')
        self.assertGreater(result.challenges_seen, 0)
        self.assertEqual(result.challenges_passed, 0)
        # Bounded: it is not asked once per request forever.
        self.assertLess(result.challenges_seen, result.requests)

    def test_a_challenge_loop_bot_never_loops_without_bound(self):
        """§37. The single most important availability property of the flow."""
        site = Harness()
        result = site.play('challenge_loop_bot', peer='198.51.100.41')
        self.assertLessEqual(result.challenges_seen, 10)
        self.assertGreater(result.requests, 100)

    def test_a_scanner_that_passes_is_not_thereby_benign(self):
        """§39, §42, §107. The fixture that would break a naive design."""
        site = Harness()
        result = site.play('patient_scanner', peer='198.51.100.42')
        self.assertGreater(result.challenges_passed, 0)
        self.assertGreater(result.final_risk, 0.4)
        self.assertNotEqual(result.final_action, 'OBSERVE')

    def test_a_slow_scanner_is_still_seen(self):
        site = Harness()
        result = site.play('slow_scanner', peer='198.51.100.43')
        self.assertNotEqual(result.final_action, 'OBSERVE')

    def test_scanners_are_challenged_far_more_often_than_ordinary_clients(self):
        site = Harness()
        peer = 50
        results = []
        for client in LAB_CLIENTS:
            peer += 1
            results.append(site.play(client.name, peer=f'198.51.100.{peer}'))
        report = summarise(results)
        self.assertGreater(report['automated_challenge_rate'],
                           report['ordinary_challenge_rate'])
        self.assertEqual(report['ordinary_challenge_rate'], 0.0)


class TestProxiesAndCdn(unittest.TestCase):
    """§111, §113. The property that keeps a site online."""

    def test_one_client_behind_a_proxy_never_costs_the_others(self):
        site = Harness(proxies=[CDN])
        scanner = site.play('cookieless_scanner', peer='203.0.113.10',
                            forwarded='198.51.100.90')
        ordinary = site.play('normal_browser', peer='203.0.113.10',
                             forwarded='198.51.100.91', start=1000.0)
        self.assertGreater(scanner.final_risk, ordinary.final_risk)
        self.assertEqual(ordinary.challenges_seen, 0)
        self.assertEqual(ordinary.final_action, 'OBSERVE')

    def test_a_proxied_scanner_is_never_network_enforceable(self):
        site = Harness(proxies=[CDN])
        result = site.play('cookieless_scanner', peer='203.0.113.10',
                           forwarded='198.51.100.90')
        self.assertFalse(result.network_enforceable)
        self.assertNotEqual(result.final_action, 'TEMP_BLOCK')

    def test_a_proxied_client_can_still_be_challenged(self):
        """A challenge reaches one client; a network block reaches everyone."""
        site = Harness(proxies=[CDN])
        result = site.play('cookieless_scanner', peer='203.0.113.10',
                           forwarded='198.51.100.90')
        self.assertGreater(result.challenges_seen, 0)

    def test_a_spoofed_forwarded_header_from_an_untrusted_peer_is_ignored(self):
        """§112. The peer is not a trusted proxy, so it speaks only for itself."""
        site = Harness(proxies=[CDN])
        site.play('cookieless_scanner', peer='198.51.100.99',
                  forwarded='203.0.113.77')
        self.assertEqual(site.sensor.last_risk('203.0.113.77'), 0.0)
        self.assertGreater(site.sensor.last_risk('198.51.100.99'), 0.0)

    def test_many_clients_behind_one_proxy_do_not_share_challenge_state(self):
        site = Harness(proxies=[CDN])
        for index in range(12):
            site.play('normal_browser', peer='203.0.113.10',
                      forwarded=f'198.51.100.{100 + index}', start=index * 500.0)
        self.assertEqual(site.challenge.metrics['challenge_issued_total'], 0)


class TestShadowMode(unittest.TestCase):
    """§122, §123. Measure the impact before anyone is inconvenienced."""

    def test_in_shadow_mode_no_challenge_is_ever_sent(self):
        site = Harness(mode='shadow')
        result = site.play('cookieless_scanner', peer='198.51.100.60')
        self.assertEqual(result.challenges_seen, 0)
        self.assertEqual(result.extra_requests, 0)

    def test_shadow_mode_still_records_what_it_would_have_done(self):
        site = Harness(mode='shadow')
        site.sensor._last_risk['198.51.100.61'] = 0.6
        plan = site.gateway.handle(peer='198.51.100.61', method='GET',
                                   path='/shop', now=5.0)
        self.assertEqual(plan.plan, PASS)
        self.assertEqual(plan.action, 'SOFT_CHALLENGE')
        self.assertIn('would have been challenged', plan.reason)
        self.assertGreater(site.gateway.metrics['challenge_shadow_total'], 0)

    def test_the_same_traffic_scores_the_same_risk_in_either_mode(self):
        """Shadow must measure the real thing, not a different thing."""
        shadow = Harness(mode='shadow').play('cookieless_scanner', peer='198.51.100.62')
        active = Harness(mode='active').play('cookieless_scanner', peer='198.51.100.62')
        self.assertAlmostEqual(shadow.final_risk, active.final_risk, places=6)


class TestTheFlowSurvivesFailure(unittest.TestCase):
    """§68, §118. The subsystem must not become a way to take the site down."""

    def test_a_gateway_with_a_broken_service_still_passes_every_request(self):
        class Exploding:
            enabled = True
            shadow = False

            def __getattr__(self, name):
                def boom(*args, **kwargs):
                    raise RuntimeError(name + ' exploded')
                return boom

        site = Harness()
        site.gateway.challenge = Exploding()
        plan = site.gateway.handle(peer='198.51.100.70', method='GET', path='/',
                                   now=1.0)
        self.assertEqual(plan.plan, PASS)
        self.assertEqual(plan.status, 0)
        self.assertIn('site was not affected', plan.reason)
        self.assertGreater(site.gateway.metrics['challenge_subsystem_errors_total'], 0)

    def test_a_gateway_with_no_challenge_service_passes_everything(self):
        from eye_for_an_eye.web.gateway import WebGateway as Bare
        gateway = Bare(resolver=ClientResolver([]))
        plan = gateway.handle(peer='198.51.100.71', method='GET', path='/', now=1.0)
        self.assertEqual(plan.plan, PASS)
        self.assertEqual(plan.status, 0)

    def test_a_broken_resolver_does_not_reach_the_caller(self):
        class Broken:
            def resolve(self, *args, **kwargs):
                raise RuntimeError('resolver exploded')

        gateway = WebGateway(resolver=Broken())
        plan = gateway.handle(peer='198.51.100.72', method='GET', path='/', now=1.0)
        self.assertEqual(plan.plan, PASS)


class TestNothingSecretLeaves(unittest.TestCase):
    """§83, §84. A token in a log is a live bypass sitting in a file."""

    def test_a_plan_explanation_never_carries_the_cookie(self):
        site = Harness()
        site.sensor._last_risk['198.51.100.80'] = 0.6
        plan = site.gateway.handle(peer='198.51.100.80', method='GET', path='/shop',
                                   now=5.0)
        self.assertEqual(plan.plan, CHALLENGE)
        self.assertIn('Set-Cookie', plan.headers)
        document = plan.explain()
        self.assertNotIn('Set-Cookie', document['headers'])
        token = plan.headers['Set-Cookie']
        self.assertNotIn(token, str(document))

    def test_a_lab_result_carries_counts_and_not_requests(self):
        site = Harness()
        document = site.play('normal_browser', peer='198.51.100.81').explain()
        for value in document.values():
            self.assertNotIn('/articles', str(value))

    def test_gateway_health_never_shows_a_secret(self):
        site = Harness()
        self.assertNotIn(SECRET.decode(), str(site.gateway.health()))


if __name__ == '__main__':
    unittest.main()
