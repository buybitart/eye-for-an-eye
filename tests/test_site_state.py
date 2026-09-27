"""P12 Phase 3 (§15-§22, §107-§110, §133, §143): isolation and fairness.

The headline property is cross-site contamination: a source scanning site A must
leave site B's counters exactly as they were. That one is easy to state and easy
to test.

The harder property is fairness, and it is the reason this file has a whole
class about a busy neighbour. A shared pool with ordinary least-recently-used
eviction is bounded and looks fine in a benchmark, but a busy site's churn
evicts a quiet site's state continuously — and the symptom is not an error, it
is a small site that never accumulates enough evidence to decide anything.
"""
import unittest
from datetime import datetime, timezone

from eye_for_an_eye.sites.identity import UNKNOWN_SITE
from eye_for_an_eye.sites.state import (SiteStateError, SiteStateRegistry)
from eye_for_an_eye.web.event import build
from eye_for_an_eye.web.identity import ClientResolver

SECRET = b'k' * 32
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
RESOLVER = ClientResolver([])


def event(peer, path='/', status=200, host='example.org'):
    return build(timestamp=START, identity=RESOLVER.resolve(peer), method='GET',
                 path=path, status=status, host=host, user_agent='', referer='',
                 secret=SECRET)


def scan(registry, site, peer, *, count=60, now=0.0):
    """Path enumeration from one source against one site."""
    for index in range(count):
        now += 1.0
        registry.observe(site, event(peer, f'/probe-{index}', 404), now)
    return now


class TestCrossSiteContamination(unittest.TestCase):
    """§16, §133. The headline requirement."""

    def setUp(self):
        self.registry = SiteStateRegistry(['main', 'api'])

    def test_scanning_one_site_leaves_the_other_untouched(self):
        scan(self.registry, 'main', '198.51.100.5')
        self.assertIsNotNone(self.registry.get('main', '198.51.100.5'))
        self.assertIsNone(self.registry.get('api', '198.51.100.5'))

    def test_the_same_source_has_separate_counters_on_each_site(self):
        """§15. Normal on site A, suspicious on site B, is a real situation."""
        scan(self.registry, 'main', '198.51.100.5', count=60)
        self.registry.observe('api', event('198.51.100.5', '/v1/items', 200), 100.0)

        main = self.registry.get('main', '198.51.100.5')
        api = self.registry.get('api', '198.51.100.5')
        self.assertGreater(len(main.requests), 50)
        self.assertEqual(len(api.requests), 1)

    def test_path_breadth_does_not_cross_sites(self):
        scan(self.registry, 'main', '198.51.100.5', count=60)
        for index in range(3):
            self.registry.observe('api', event('198.51.100.5', f'/v1/{index}'), 100.0)
        main = self.registry.get('main', '198.51.100.5')
        api = self.registry.get('api', '198.51.100.5')
        self.assertGreater(len(main.paths), 40)
        self.assertLessEqual(len(api.paths), 3)

    def test_a_sites_own_counters_are_unaffected_by_a_busy_neighbour(self):
        before = self.registry.site_stats('api')['sources']
        for index in range(500):
            self.registry.observe('main', event(f'10.0.{index // 256}.{index % 256}'),
                                  float(index))
        self.assertEqual(self.registry.site_stats('api')['sources'], before)


class TestUnknownSiteIsBounded(unittest.TestCase):
    """§109, §110, §146. The Host cardinality attack, at the state layer."""

    def test_an_unrecognised_site_folds_into_one_bucket(self):
        registry = SiteStateRegistry(['main'])
        for index in range(1000):
            self.assertEqual(registry.site_for(f'invented-{index}'), UNKNOWN_SITE)

    def test_traffic_for_invented_sites_creates_no_new_tables(self):
        registry = SiteStateRegistry(['main'])
        before = registry.stats()['sites']
        for index in range(5000):
            registry.observe(f'invented-{index}', event(f'10.0.{index % 256}.1'),
                             float(index))
        self.assertEqual(registry.stats()['sites'], before)

    def test_the_unknown_bucket_respects_the_per_site_limit(self):
        registry = SiteStateRegistry(['main'], max_sources_per_site=100,
                                     max_sources_global=500)
        for index in range(3000):
            registry.observe('whatever', event(f'10.{index // 65536}.'
                                               f'{index // 256 % 256}.{index % 256}'),
                             float(index))
        self.assertLessEqual(registry.site_stats(UNKNOWN_SITE)['sources'], 100)

    def test_unknown_site_exists_before_any_traffic_arrives(self):
        """Lazy creation would mean the first hostile request allocates."""
        self.assertIn(UNKNOWN_SITE, SiteStateRegistry([]))


class TestGlobalBound(unittest.TestCase):
    """§20. Multi-site must not multiply memory by the number of sites."""

    def test_the_total_never_exceeds_the_global_limit(self):
        registry = SiteStateRegistry(['a', 'b', 'c', 'd'], max_sources_global=400,
                                     max_sources_per_site=200, reserved_per_site=20)
        now = 0.0
        for index in range(4000):
            now += 0.01
            site = 'abcd'[index % 4]
            registry.observe(site, event(f'10.{index // 65536 % 256}.'
                                         f'{index // 256 % 256}.{index % 256}'), now)
            self.assertLessEqual(len(registry), 400)

    def test_ten_sites_do_not_hold_ten_times_the_memory(self):
        one = SiteStateRegistry(['a'], max_sources_global=1000, reserved_per_site=10)
        ten = SiteStateRegistry([f's{index}' for index in range(10)],
                                max_sources_global=1000, reserved_per_site=10)
        for registry in (one, ten):
            now = 0.0
            for index in range(5000):
                now += 0.01
                site = registry.sites[index % len(registry.sites)]
                registry.observe(site, event(f'10.{index // 65536 % 256}.'
                                             f'{index // 256 % 256}.{index % 256}'), now)
        self.assertLessEqual(len(ten), 1000)
        self.assertLessEqual(len(one), 1000)

    def test_reservations_that_cannot_fit_are_refused_at_construction(self):
        with self.assertRaises(SiteStateError) as raised:
            SiteStateRegistry([f's{index}' for index in range(50)],
                              max_sources_global=100, reserved_per_site=64)
        self.assertIn('exceeds the global limit', str(raised.exception))


class TestFairness(unittest.TestCase):
    """§21, §107, §143. The busy-neighbour problem."""

    def registry(self):
        return SiteStateRegistry(['busy', 'small', 'idle'],
                                 max_sources_global=300,
                                 max_sources_per_site=280,
                                 reserved_per_site=50)

    def flood(self, registry, site, count, *, start=0.0):
        now = start
        for index in range(count):
            now += 0.01
            registry.observe(site, event(f'10.{index // 65536 % 256}.'
                                         f'{index // 256 % 256}.{index % 256}'), now)
        return now

    def test_a_small_site_keeps_its_state_while_a_neighbour_floods(self):
        """The property a naive global LRU pool silently fails."""
        registry = self.registry()
        for index in range(30):
            registry.observe('small', event(f'192.0.2.{index}'), float(index))
        held = registry.site_stats('small')['sources']

        self.flood(registry, 'busy', 5000, start=100.0)

        self.assertEqual(registry.site_stats('small')['sources'], held)
        self.assertGreaterEqual(held, 30)

    def test_a_small_site_can_still_take_new_sources_during_a_flood(self):
        registry = self.registry()
        self.flood(registry, 'busy', 5000)
        for index in range(40):
            registry.observe('small', event(f'192.0.2.{index}'), 1000.0 + index)
        self.assertGreaterEqual(registry.site_stats('small')['sources'], 40)

    def test_the_flooding_site_pays_for_its_own_growth(self):
        registry = self.registry()
        for index in range(40):
            registry.observe('small', event(f'192.0.2.{index}'), float(index))
        self.flood(registry, 'busy', 5000, start=100.0)
        stats = registry.stats()
        self.assertGreater(stats['per_site']['busy']['evictions'], 0)
        self.assertEqual(stats['per_site']['small']['evictions'], 0)

    def test_an_idle_site_holds_no_memory(self):
        """A floor is a claim, not a reservation sitting empty."""
        registry = self.registry()
        self.flood(registry, 'busy', 1000)
        self.assertEqual(registry.site_stats('idle')['sources'], 0)

    def test_a_site_at_its_floor_is_never_evicted_from(self):
        registry = SiteStateRegistry(['busy', 'small'], max_sources_global=200,
                                     max_sources_per_site=190, reserved_per_site=40)
        for index in range(20):
            registry.observe('small', event(f'192.0.2.{index}'), float(index))
        self.flood(registry, 'busy', 4000, start=100.0)
        self.assertEqual(registry.site_stats('small')['sources'], 20)

    def test_no_site_may_take_more_than_its_hard_cap(self):
        registry = self.registry()
        self.flood(registry, 'busy', 5000)
        self.assertLessEqual(registry.site_stats('busy')['sources'], 280)

    def test_eviction_is_counted_so_an_operator_can_see_pressure(self):
        registry = self.registry()
        for index in range(60):
            registry.observe('small', event(f'192.0.2.{index}'), float(index))
        self.flood(registry, 'busy', 5000, start=100.0)
        self.assertGreater(registry.stats()['cross_site_evictions'], 0)


class TestReporting(unittest.TestCase):
    def test_stats_report_every_site_separately(self):
        registry = SiteStateRegistry(['main', 'api'])
        registry.observe('main', event('198.51.100.5'), 1.0)
        per_site = registry.stats()['per_site']
        self.assertEqual(set(per_site), {'main', 'api', UNKNOWN_SITE})
        self.assertEqual(per_site['main']['sources'], 1)
        self.assertEqual(per_site['api']['sources'], 0)

    def test_stats_are_json_serialisable(self):
        import json
        registry = SiteStateRegistry(['main'])
        registry.observe('main', event('198.51.100.5'), 1.0)
        json.dumps(registry.stats())

    def test_the_registry_says_how_it_stays_bounded(self):
        self.assertIn('fair share', SiteStateRegistry(['a']).stats()['bounded'])


if __name__ == '__main__':
    unittest.main()
