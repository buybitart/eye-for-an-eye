"""P12 Phases 6 and 8 (§17-§18, §50-§51, §96-§101, §134, §136, §141): the engine.

Three properties, each of which would be a real incident if it failed.

**Challenge isolation.** A token minted for one site must not verify for
another. P11 derives a per-site key with HKDF, so this should already hold — but
"should already hold" is exactly the kind of claim that stops being true when a
second layer starts choosing which site string to pass in.

**Network blocks are honest about their reach.** An `nftables` block removes a
source from every site on the machine. Representing that as a site-local action
would be a lie with an outage attached.

**Host network evidence is still shared.** Isolating web behaviour must not make
a multi-site deployment worse at detection than a single-site one. A port scan
is about the machine, and both sites may legitimately see it.
"""
import unittest
from datetime import datetime, timezone

from eye_for_an_eye.challenge.policy import ChallengeGate
from eye_for_an_eye.challenge.service import ChallengeService
from eye_for_an_eye.challenge.token import COOKIE_NAME, issue, verify
from eye_for_an_eye.config import Config
from eye_for_an_eye.sites.baseline import missing as missing_baseline
from eye_for_an_eye.sites.engine import (NETWORK_HOST_BLOCK, SITE_WEB_ACTION,
                                         SiteEngine, from_config)
from eye_for_an_eye.sites.identity import UNKNOWN_SITE
from eye_for_an_eye.sites.profile import API, WEBSITE, build_all
from eye_for_an_eye.web.event import build
from eye_for_an_eye.web.identity import ClientResolver

SECRET = b'k' * 32
MASTER = b'm' * 48
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
RESOLVER = ClientResolver([])
MAIN = 'example.org'
API_HOST = 'api.example.org'


def event(peer, path='/', status=200, host=MAIN):
    return build(timestamp=START, identity=RESOLVER.resolve(peer), method='GET',
                 path=path, status=status, host=host, user_agent='', referer='',
                 secret=SECRET)


def engine(**kwargs):
    profiles = build_all({'main': {'profile': WEBSITE, 'domains': [MAIN]},
                          'api': {'profile': API, 'domains': [API_HOST]}})
    return SiteEngine(profiles, **kwargs)


class TestResolution(unittest.TestCase):
    def test_each_domain_reaches_its_own_profile(self):
        built = engine()
        self.assertEqual(built.context(MAIN).profile.profile_type, WEBSITE)
        self.assertEqual(built.context(API_HOST).profile.profile_type, API)

    def test_each_site_keeps_its_own_thresholds(self):
        """§23. The claim the whole stage rests on."""
        built = engine()
        main = built.context(MAIN).settings
        api = built.context(API_HOST).settings
        self.assertGreater(api.expected_requests_per_minute,
                           main.expected_requests_per_minute)

    def test_an_unknown_host_gets_the_most_cautious_profile(self):
        context = engine().context('nothing-configured.test')
        self.assertEqual(context.site_id, UNKNOWN_SITE)
        self.assertFalse(context.known)
        self.assertFalse(context.settings.challenge_enabled)
        self.assertFalse(context.settings.rate_limit_enabled)
        self.assertFalse(context.settings.allow_host_network_block)
        self.assertEqual(context.settings.mode, 'shadow')

    def test_a_disabled_site_does_not_run_its_own_policy(self):
        profiles = build_all({'main': {'domains': [MAIN], 'enabled': False}})
        context = SiteEngine(profiles).context(MAIN)
        self.assertEqual(context.site_id, UNKNOWN_SITE)
        self.assertIn('disabled', context.reason)

    def test_the_context_explains_how_the_site_was_decided(self):
        document = engine().context(MAIN).explain()
        self.assertEqual(document['site_id'], 'main')
        self.assertEqual(document['site_origin'], 'configured')
        self.assertTrue(document['site_reason'])


class TestChallengeIsolation(unittest.TestCase):
    """§50, §51, §103, §136. A token for one site is worthless on another."""

    def factory(self, site):
        gate = ChallengeGate(shadow=False)
        return ChallengeService(secret=MASTER, mode='active', site_id=site, gate=gate)

    def test_each_site_gets_its_own_challenge_service(self):
        built = engine()
        main = built.challenge_for('main', self.factory)
        api = built.challenge_for('api', self.factory)
        self.assertIsNot(main, api)
        self.assertNotEqual(main.site_id, api.site_id)

    def test_a_service_is_cached_per_site(self):
        built = engine()
        self.assertIs(built.challenge_for('main', self.factory),
                      built.challenge_for('main', self.factory))

    def test_a_token_for_one_site_does_not_verify_for_another(self):
        built = engine()
        main = built.challenge_for('main', self.factory)
        api = built.challenge_for('api', self.factory)
        token = main.respond(return_path='/').headers['Set-Cookie']
        value = token.split(';')[0].split('=', 1)[1]

        self.assertTrue(main.verify_cookie(value).valid)
        self.assertFalse(api.verify_cookie(value).valid)

    def test_isolation_holds_for_every_pair_of_configured_sites(self):
        sites = [f'site{index}' for index in range(6)]
        tokens = {site: issue(MASTER, site=site) for site in sites}
        for holder in sites:
            for target in sites:
                with self.subTest(holder=holder, target=target):
                    result = verify(tokens[holder], MASTER, site=target)
                    self.assertEqual(result.valid, holder == target)

    def test_an_unknown_site_token_does_not_open_a_configured_site(self):
        built = engine()
        unknown = built.challenge_for('whatever', self.factory)
        main = built.challenge_for('main', self.factory)
        token = unknown.respond(return_path='/').headers['Set-Cookie']
        value = token.split(';')[0].split('=', 1)[1]
        self.assertFalse(main.verify_cookie(value).valid)

    def test_the_challenge_cookie_is_host_only(self):
        """§104, §105. No Domain attribute means no cross-subdomain trust."""
        built = engine()
        header = built.challenge_for('main', self.factory).respond('/').headers['Set-Cookie']
        self.assertIn(COOKIE_NAME, header)
        self.assertNotIn('Domain', header)
        self.assertNotIn('domain', header)


class TestCrossSiteContamination(unittest.TestCase):
    """§16, §133. Web counters never cross."""

    def test_probing_one_site_leaves_the_others_counters_alone(self):
        built = engine()
        context = built.context(MAIN)
        for index in range(50):
            built.observe(context, event('198.51.100.5', f'/p{index}', 404),
                          float(index), probing=True)
        self.assertIsNotNone(built.state.get('main', '198.51.100.5'))
        self.assertIsNone(built.state.get('api', '198.51.100.5'))

    def test_a_baseline_belongs_to_exactly_one_site(self):
        built = engine()
        with self.assertRaises(ValueError) as raised:
            built.set_baseline('api', missing_baseline('main'))
        self.assertIn('must not be installed elsewhere', str(raised.exception))

    def test_a_baseline_cannot_be_installed_for_an_unconfigured_site(self):
        with self.assertRaises(KeyError):
            engine().set_baseline('nope', missing_baseline('nope'))


class TestCrossSiteEvidence(unittest.TestCase):
    """§17, §18, §100, §101, §134. Shared on purpose, and bounded."""

    def test_a_source_probing_several_sites_is_visible_as_such(self):
        built = engine()
        for host, site in ((MAIN, 'main'), (API_HOST, 'api')):
            context = built.context(host)
            built.observe(context, event('198.51.100.5', '/admin', 404, host),
                          1.0, probing=True, sensitive=True)
        evidence = built.cross_site('198.51.100.5')
        self.assertEqual(evidence.features()['sites_touched'], 2.0)
        self.assertEqual(evidence.features()['sites_with_probing'], 2.0)

    def test_cross_site_evidence_carries_counts_not_site_names(self):
        """It is host-level evidence, not a site identifier in disguise."""
        built = engine()
        context = built.context(MAIN)
        built.observe(context, event('198.51.100.5', '/admin', 404), 1.0,
                      probing=True)
        for name, value in built.cross_site('198.51.100.5').features().items():
            self.assertIsInstance(value, float)
            self.assertNotIn('main', name)
            self.assertNotIn('site_id', name)

    def test_a_source_on_one_site_only_shows_no_cross_site_diversity(self):
        built = engine()
        context = built.context(MAIN)
        for index in range(20):
            built.observe(context, event('198.51.100.6', f'/p{index}', 404),
                          float(index), probing=True)
        self.assertEqual(built.cross_site('198.51.100.6').features()['sites_touched'],
                         1.0)

    def test_an_unseen_source_has_empty_evidence_rather_than_none(self):
        self.assertEqual(engine().cross_site('203.0.113.9').features()['sites_touched'],
                         0.0)

    def test_the_cross_site_table_is_bounded(self):
        built = engine()
        built._max_cross_site = 100
        context = built.context(MAIN)
        for index in range(5000):
            built.observe(context,
                          event(f'10.{index // 65536 % 256}.'
                                f'{index // 256 % 256}.{index % 256}', '/x', 404),
                          float(index), probing=True)
        self.assertLessEqual(len(built._cross_site), 100)
        self.assertGreater(built.metrics['cross_site_evictions_total'], 0)


class TestActionScope(unittest.TestCase):
    """§96-§99, §141. A network block reaches every site on the machine."""

    def test_ordinary_actions_are_site_local(self):
        built = engine()
        context = built.context(MAIN)
        for action in ('OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT'):
            with self.subTest(action=action):
                scope, allowed, _ = built.action_scope(context, action)
                self.assertEqual(scope, SITE_WEB_ACTION)
                self.assertTrue(allowed)

    def test_a_site_cannot_block_the_host_unless_configured_to(self):
        built = engine()
        scope, allowed, reason = built.action_scope(built.context(MAIN), 'TEMP_BLOCK')
        self.assertEqual(scope, SITE_WEB_ACTION)
        self.assertFalse(allowed)
        self.assertIn('every site on this server', reason)

    def test_a_configured_site_may_ask_and_is_told_what_it_reaches(self):
        profiles = build_all({'main': {'domains': [MAIN],
                                       'allow_host_network_block': True}})
        built = SiteEngine(profiles)
        scope, allowed, reason = built.action_scope(built.context(MAIN), 'TEMP_BLOCK')
        self.assertEqual(scope, NETWORK_HOST_BLOCK)
        self.assertTrue(allowed)
        self.assertIn('host-wide', reason)
        self.assertIn('not only this one', reason)

    def test_the_unknown_bucket_can_never_block_the_host(self):
        built = engine()
        scope, allowed, _ = built.action_scope(built.context('invented.test'),
                                               'TEMP_BLOCK')
        self.assertEqual(scope, SITE_WEB_ACTION)
        self.assertFalse(allowed)

    def test_the_two_scopes_are_named_differently(self):
        """§97. Not naming them apart is how the lie gets told."""
        self.assertNotEqual(SITE_WEB_ACTION, NETWORK_HOST_BLOCK)
        self.assertIn('HOST', NETWORK_HOST_BLOCK)


class TestFromConfig(unittest.TestCase):
    def test_multi_site_is_off_by_default(self):
        """§158. A single-site owner never has to know this exists."""
        config = Config()
        self.assertFalse(config.sites.enabled)
        self.assertIsNone(from_config(config))

    def test_an_enabled_configuration_builds_an_engine(self):
        config = Config()
        config.sites.enabled = True
        config.sites.profiles = {'main': {'profile': WEBSITE, 'domains': [MAIN]}}
        built = from_config(config)
        self.assertEqual(built.context(MAIN).site_id, 'main')

    def test_a_bad_site_stops_startup_rather_than_half_applying(self):
        config = Config()
        config.sites.enabled = True
        config.sites.profiles = {'main': {'domains': [MAIN]},
                                 'other': {'domains': [MAIN]}}
        with self.assertRaises(ValueError):
            from_config(config)

    def test_the_site_limit_from_configuration_is_honoured(self):
        config = Config()
        config.sites.enabled = True
        config.sites.max_sites = 2
        config.sites.profiles = {f'site{index}': {'domains': [f'{index}.example.test']}
                                 for index in range(5)}
        with self.assertRaises(ValueError):
            from_config(config)


class TestReporting(unittest.TestCase):
    def test_health_reports_every_site(self):
        document = engine().health()
        self.assertEqual(document['sites'], 2)
        self.assertEqual(document['site_ids'], ['api', 'main'])

    def test_health_says_what_is_shared_and_what_is_not(self):
        note = engine().health()['note']
        self.assertIn('per site', note)
        self.assertIn('host', note)

    def test_site_status_covers_profile_state_and_baseline(self):
        document = engine().site_status('main')
        self.assertTrue(document['configured'])
        for section in ('profile', 'state', 'baseline'):
            self.assertIn(section, document)

    def test_status_for_an_unconfigured_site_says_so(self):
        self.assertFalse(engine().site_status('nope')['configured'])

    def test_health_is_json_serialisable(self):
        import json
        json.dumps(engine().health())


if __name__ == '__main__':
    unittest.main()
