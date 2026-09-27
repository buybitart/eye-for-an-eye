"""P10 web behaviour: what must not be flagged, and what must be.

The hard negatives come first on purpose. A web protection layer that blocks the
monitoring system, the load balancer or a browser loading a page is worse than
no web protection layer, because it takes the site down while claiming to defend
it. Every scenario here is built from real traffic shapes.

Thresholds used: WATCH 0.40, RATE_LIMIT 0.70, TEMP_BLOCK 0.88 — the same ones
the network side uses.
"""
import unittest
from datetime import datetime, timezone

from eye_for_an_eye.web.event import build
from eye_for_an_eye.web.features import extract
from eye_for_an_eye.web.identity import ClientResolver
from eye_for_an_eye.web.risk import WebMathRisk
from eye_for_an_eye.web.state import WebSourceTable

WATCH, RATE_LIMIT, BLOCK = 0.40, 0.70, 0.88
SECRET = b'k' * 32
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


class Scenario:
    """Replays a request sequence through the real state and feature code."""

    def __init__(self, client='198.51.100.7', resolver=None):
        self.resolver = resolver or ClientResolver([])
        self.table = WebSourceTable()
        self.client = client
        self.now = 0.0

    def request(self, path, *, status=200, method='GET', gap=1.0, agent='Mozilla/5.0',
                referer='https://example.test/', host='example.test', auth='',
                peer=None):
        self.now += gap
        identity = self.resolver.resolve(peer or self.client)
        event = build(timestamp=START, identity=identity, method=method, path=path,
                      status=status, host=host, user_agent=agent, referer=referer,
                      auth_outcome=auth, secret=SECRET)
        self.table.observe(event, self.now)
        return event

    def score(self, expected_methods=None):
        state = self.table.get(self.client)
        features = extract(state, self.now,
                           expected_methods=expected_methods or ('GET', 'HEAD', 'POST', 'OPTIONS'))
        return WebMathRisk().evaluate(features), features


class TestHardNegatives(unittest.TestCase):
    """Real traffic that must not be treated as an attack."""

    def test_a_browser_loading_a_page_is_not_a_bot(self):
        """§120. One HTML page pulls thirty assets in a burst. That is a browser."""
        scenario = Scenario()
        scenario.request('/', status=200)
        for name in ('app.css', 'theme.css', 'app.js', 'vendor.js', 'logo.svg',
                     'hero.jpg', 'icon.png', 'font.woff2', 'analytics.js'):
            scenario.request(f'/static/{name}', status=200, gap=0.05)
        for index in range(20):
            scenario.request(f'/static/img/photo-{index}.jpg', status=200, gap=0.03)
        risk, _ = scenario.score()
        self.assertLess(risk.score, WATCH, f'a page load scored {risk.score:.3f}')

    def test_a_health_checker_is_not_a_bot(self):
        """Perfectly regular timing, one path, all 200s. Automation, but wanted."""
        scenario = Scenario(client='10.0.0.9')
        for _ in range(60):
            scenario.request('/healthz', status=200, gap=5.0, agent='kube-probe/1.29',
                             referer='')
        risk, _ = scenario.score()
        self.assertLess(risk.score, WATCH, f'a health checker scored {risk.score:.3f}')

    def test_a_high_rate_api_client_is_not_a_bot(self):
        """§118. Fast, no referer, no assets — and entirely legitimate."""
        scenario = Scenario(client='198.51.100.20')
        for index in range(200):
            scenario.request(f'/api/v1/orders/{index % 8}', status=200, gap=0.25,
                             agent='acme-sdk/2.1', referer='')
        risk, _ = scenario.score()
        self.assertLess(risk.score, RATE_LIMIT, f'an API client scored {risk.score:.3f}')

    def test_a_broken_frontend_requesting_a_missing_asset_is_not_a_scanner(self):
        """§22. Constant 404s, but always the same one. A deployment bug."""
        scenario = Scenario()
        for _ in range(80):
            scenario.request('/static/missing-icon.png', status=404, gap=0.5)
        risk, _ = scenario.score()
        self.assertLess(risk.score, WATCH, f'a broken asset scored {risk.score:.3f}')

    def test_a_legitimate_crawler_is_not_a_scanner(self):
        """§121. Many distinct paths — and it finds them, because they exist."""
        scenario = Scenario(client='198.51.100.30')
        for index in range(120):
            scenario.request(f'/blog/post-{index}', status=200, gap=2.0,
                             agent='Mozilla/5.0 (compatible; SomeBot/2.1)', referer='')
        risk, _ = scenario.score()
        self.assertLess(risk.score, RATE_LIMIT, f'a crawler scored {risk.score:.3f}')

    def test_one_mistyped_password_is_not_an_attack(self):
        """§21. A person gets it wrong, then right."""
        scenario = Scenario()
        scenario.request('/login', status=200)
        scenario.request('/login', method='POST', status=401, gap=8.0, auth='failure')
        scenario.request('/login', method='POST', status=302, gap=12.0, auth='success')
        scenario.request('/dashboard', status=200, gap=2.0)
        risk, _ = scenario.score()
        self.assertLess(risk.score, WATCH, f'one failed login scored {risk.score:.3f}')

    def test_an_administrator_using_the_admin_panel_is_not_a_probe(self):
        """§11. Sensitive paths, repeatedly, successfully. That is the admin."""
        scenario = Scenario(client='10.0.0.5')
        for index in range(40):
            scenario.request(f'/admin/users/{index % 5}', status=200, gap=4.0)
        risk, _ = scenario.score()
        self.assertLess(risk.score, WATCH, f'admin use scored {risk.score:.3f}')

    def test_a_load_balancer_probing_the_root_is_not_a_bot(self):
        scenario = Scenario(client='10.0.0.2')
        for _ in range(100):
            scenario.request('/', method='HEAD', status=200, gap=1.0, agent='', referer='')
        risk, _ = scenario.score()
        self.assertLess(risk.score, WATCH, f'a load balancer scored {risk.score:.3f}')


class TestSuspicious(unittest.TestCase):
    """Behaviour that should raise risk, in proportion to the evidence."""

    def test_path_enumeration_raises_risk(self):
        """§16. Many distinct guesses, almost all missing, on a timer."""
        scenario = Scenario(client='198.51.100.50')
        for index in range(90):
            scenario.request(f'/x{index}a{index * 7}', status=404, gap=0.6,
                             agent='', referer='')
        risk, _ = scenario.score()
        self.assertGreater(risk.score, RATE_LIMIT, f'enumeration scored {risk.score:.3f}')
        self.assertTrue(any('not found' in reason for reason in risk.reasons))

    def test_sensitive_file_probing_across_categories_raises_risk(self):
        scenario = Scenario(client='198.51.100.51')
        for path in ('/.env', '/.git/config', '/wp-login.php', '/phpmyadmin/',
                     '/backup.sql', '/admin/', '/config.php', '/.svn/entries',
                     '/db.sql.gz', '/administrator/index.php'):
            for _ in range(4):
                scenario.request(path, status=404, gap=0.8, agent='', referer='')
        risk, features = scenario.score()
        self.assertGreater(risk.score, WATCH, f'sensitive probing scored {risk.score:.3f}')
        self.assertGreaterEqual(features.values['sensitive_category_count'], 4)

    def test_repeated_authentication_failures_across_accounts_raise_risk(self):
        """§20. Credential-spray shape: many failures, low rate per account."""
        scenario = Scenario(client='198.51.100.52')
        for index in range(30):
            scenario.request(f'/login?u=user{index}', method='POST', status=401,
                             gap=2.0, auth='failure', agent='', referer='')
        risk, _ = scenario.score()
        self.assertGreater(risk.score, WATCH, f'auth spraying scored {risk.score:.3f}')
        self.assertTrue(any('failed sign-in' in reason for reason in risk.reasons))

    def test_a_low_and_slow_probe_is_still_seen(self):
        """§15. One request every five seconds for fifteen minutes."""
        scenario = Scenario(client='198.51.100.53')
        for index in range(120):
            scenario.request(f'/probe-{index}', status=404, gap=5.0, agent='', referer='')
        risk, features = scenario.score()
        self.assertGreater(risk.score, WATCH, f'a slow probe scored {risk.score:.3f}')
        self.assertGreater(features.values['persistence_900s'], 300)

    def test_method_probing_raises_risk(self):
        scenario = Scenario(client='198.51.100.54')
        for method in ('PUT', 'DELETE', 'TRACE', 'PATCH', 'CONNECT', 'PROPFIND'):
            for index in range(6):
                scenario.request(f'/{method.lower()}-{index}', method=method, status=405,
                                 gap=0.7, agent='', referer='')
        risk, features = scenario.score()
        self.assertGreater(features.values['unexpected_method_ratio'], 0.5)
        self.assertGreater(risk.score, WATCH, f'method probing scored {risk.score:.3f}')

    def test_virtual_host_enumeration_raises_risk(self):
        scenario = Scenario(client='198.51.100.55')
        for index in range(40):
            scenario.request('/', status=404, gap=0.5, host=f'host{index}.example.test',
                             agent='', referer='')
        _, features = scenario.score()
        self.assertGreater(features.values['host_diversity'], 4)


class TestProportionality(unittest.TestCase):
    """No single signal may reach a strong action on its own."""

    def test_rate_alone_never_reaches_a_block(self):
        scenario = Scenario(client='198.51.100.60')
        for index in range(300):
            scenario.request(f'/page-{index % 4}', status=200, gap=0.05)
        risk, _ = scenario.score()
        self.assertLess(risk.score, BLOCK, f'rate alone scored {risk.score:.3f}')

    def test_a_single_sensitive_request_is_almost_nothing(self):
        """§11. Never `if path == '/.env': block()`."""
        scenario = Scenario()
        scenario.request('/', status=200)
        scenario.request('/.env', status=404, gap=1.0)
        for _ in range(8):
            scenario.request('/', status=200, gap=3.0)
        risk, _ = scenario.score()
        self.assertLess(risk.score, WATCH, f'one .env request scored {risk.score:.3f}')

    def test_errors_alone_never_reach_a_block(self):
        scenario = Scenario(client='198.51.100.61')
        for _ in range(100):
            scenario.request('/broken', status=500, gap=0.4)
        risk, _ = scenario.score()
        self.assertLess(risk.score, RATE_LIMIT, f'5xx alone scored {risk.score:.3f}')

    def test_too_few_requests_produce_no_score_at_all(self):
        scenario = Scenario()
        scenario.request('/.env', status=404)
        scenario.request('/.git/config', status=404, gap=0.2)
        risk, _ = scenario.score()
        self.assertEqual(risk.score, 0.0)
        self.assertFalse(risk.usable)
        self.assertIn('too few to judge', risk.reasons[0])

    def test_the_strongest_case_is_built_from_many_families(self):
        scenario = Scenario(client='198.51.100.62')
        for index in range(120):
            path = ('/.env' if index % 11 == 0 else
                    '/wp-login.php' if index % 13 == 0 else f'/g{index}x{index * 3}')
            scenario.request(path, status=404, gap=0.5, agent='', referer='')
        risk, _ = scenario.score()
        self.assertGreater(risk.score, RATE_LIMIT)
        self.assertGreaterEqual(risk.families, 3)
        self.assertTrue(any('independent kinds of evidence' in r for r in risk.reasons))


class TestExplanations(unittest.TestCase):
    def test_reasons_carry_real_numbers(self):
        scenario = Scenario(client='198.51.100.70')
        for index in range(80):
            scenario.request(f'/q{index}', status=404, gap=0.5, agent='', referer='')
        risk, _ = scenario.score()
        self.assertTrue(risk.reasons)
        self.assertTrue(any(char.isdigit() for reason in risk.reasons for char in reason))

    def test_no_explanation_claims_to_have_found_a_hacker(self):
        """§57. The wording is part of the contract."""
        scenario = Scenario(client='198.51.100.71')
        for index in range(90):
            scenario.request(f'/z{index}', status=404, gap=0.4, agent='', referer='')
        risk, _ = scenario.score()
        text = ' '.join(risk.reasons).lower() + risk.explain()['meaning'].lower()
        for word in ('hacker', 'attacker', 'criminal', 'malicious user', 'ai found'):
            self.assertNotIn(word, text)
        self.assertIn('not proof of an attack', risk.explain()['meaning'])

    def test_contributions_name_the_families_that_mattered(self):
        scenario = Scenario(client='198.51.100.72')
        for index in range(90):
            scenario.request(f'/y{index}', status=404, gap=0.5, agent='', referer='')
        risk, _ = scenario.score()
        contributions = risk.explain()['contributions']
        self.assertIn('path_enumeration', contributions)
        self.assertGreater(contributions['path_enumeration'], 0)

    def test_the_result_is_deterministic(self):
        def run():
            scenario = Scenario(client='198.51.100.73')
            for index in range(60):
                scenario.request(f'/d{index}', status=404, gap=0.5, agent='', referer='')
            return scenario.score()[0].score
        self.assertEqual(run(), run())


class TestExpectedMethods(unittest.TestCase):
    def test_an_api_that_expects_put_is_not_penalised_for_it(self):
        """§24. What counts as unexpected depends on the application."""
        scenario = Scenario(client='198.51.100.80')
        for index in range(40):
            scenario.request(f'/api/items/{index}', method='PUT', status=200, gap=0.5,
                             agent='sdk/1.0', referer='')
        strict, _ = scenario.score(expected_methods=('GET', 'HEAD', 'POST'))
        relaxed, _ = scenario.score(expected_methods=('GET', 'HEAD', 'POST', 'PUT'))
        self.assertGreater(strict.score, relaxed.score)
        self.assertLess(relaxed.score, WATCH)


if __name__ == '__main__':
    unittest.main()
