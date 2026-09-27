"""P12 Phase 4 (§24-§28, §85-§88, §115, §139, §149): what normal means per site.

The property this file exists to protect is the one that is easy to get wrong
and impossible to notice afterwards: **a baseline must not be able to learn an
attacker's traffic as normal.** Two mechanisms guard it, and both are tested
here — a baseline never becomes active by the passage of time, and the active
one never quietly absorbs new traffic.

The second theme is honesty about not knowing. A new site has no baseline, and
the answer to "is this unusual?" is `INSUFFICIENT_DATA`. Not "no", which would
be a claim nobody checked, and not "yes", which would make every visitor to a
new site look like an attack.
"""
import unittest

from eye_for_an_eye.sites.baseline import (ABOVE_BASELINE, ACTIVE, BaselineBuilder,
                                           DEGRADED, Distribution, INSUFFICIENT_DATA,
                                           LAB, LEARNING, MISSING, OBSERVED, PROVENANCE,
                                           REVIEWED_SHADOW, STALE, STATES,
                                           SiteBaselineError, TRACKED, VALIDATING,
                                           WITHIN_BASELINE, activate,
                                           compare_baselines, missing)

NOW = 1_800_000_000.0


def builder(site='main', *, provenance=OBSERVED, seed=1):
    return BaselineBuilder(site, provenance=provenance, seed=seed)


def fill(build, *, windows=400, sources=40, rate=100.0, paths=20.0, errors=0.05):
    """Enough ordinary-looking windows to make a candidate viable."""
    for index in range(windows):
        build.observe({'requests_per_minute': rate * (0.8 + 0.4 * (index % 10) / 10),
                       'unique_paths_60s': paths * (0.8 + 0.4 * (index % 7) / 7),
                       'error_ratio': errors,
                       'method_diversity': 2.0,
                       'auth_failure_ratio': 0.0,
                       'interval_regularity': 0.3},
                      source=f'10.0.0.{index % sources}', now=NOW + index)
    return build


class TestColdStart(unittest.TestCase):
    """§27, §28, §149. A new site knows that it does not know."""

    def test_a_new_site_has_a_missing_baseline_not_an_empty_one(self):
        baseline = missing('newsite')
        self.assertEqual(baseline.state, MISSING)
        self.assertFalse(baseline.usable)
        self.assertEqual(baseline.confidence, 0.0)

    def test_a_missing_baseline_answers_insufficient_data(self):
        """Not "normal", which nobody checked, and not "unusual", which would
        make every visitor to a new site look like an attack."""
        verdict, _, reason = missing('newsite').compare('requests_per_minute', 9999.0)
        self.assertEqual(verdict, INSUFFICIENT_DATA)
        self.assertIn('missing', reason)

    def test_an_enormous_value_against_a_missing_baseline_is_still_not_an_alert(self):
        verdict, _, _ = missing('newsite').compare('unique_paths_60s', 1e9)
        self.assertEqual(verdict, INSUFFICIENT_DATA)

    def test_a_thin_candidate_stays_in_learning(self):
        build = fill(builder(), windows=20, sources=3)
        candidate = build.build('v1')
        self.assertEqual(candidate.state, LEARNING)
        self.assertFalse(candidate.usable)

    def test_learning_says_what_is_missing(self):
        candidate = fill(builder(), windows=20, sources=3).build('v1')
        joined = ' '.join(candidate.notes)
        self.assertIn('windows observed', joined)
        self.assertIn('distinct sources', joined)

    def test_many_windows_from_one_client_are_not_a_site_baseline(self):
        """§25. Two hundred windows from one client describe that client."""
        build = builder()
        for index in range(1000):
            build.observe({'requests_per_minute': 100.0}, source='10.0.0.1',
                          now=NOW + index)
        ready, reasons = build.ready()
        self.assertFalse(ready)
        self.assertTrue(any('distinct sources' in reason for reason in reasons))


class TestTimeCannotActivateABaseline(unittest.TestCase):
    """§25, §85. The mechanism that stops an attacker defining normal."""

    def test_a_builder_cannot_produce_an_active_baseline(self):
        with self.assertRaises(SiteBaselineError) as raised:
            fill(builder()).build('v1', state=ACTIVE)
        self.assertIn('explicitly', str(raised.exception))

    def test_a_well_fed_builder_still_only_produces_a_candidate(self):
        candidate = fill(builder(), windows=2000, sources=200).build('v1')
        self.assertEqual(candidate.state, VALIDATING)
        self.assertNotEqual(candidate.state, ACTIVE)

    def test_activation_is_a_separate_deliberate_act(self):
        candidate = fill(builder()).build('v1')
        self.assertEqual(activate(candidate, now=NOW).state, ACTIVE)

    def test_activation_refuses_a_candidate_that_is_too_thin(self):
        candidate = fill(builder(), windows=30, sources=5).build('v1')
        with self.assertRaises(SiteBaselineError):
            activate(candidate)

    def test_activation_refuses_a_candidate_identical_to_the_active_one(self):
        active = activate(fill(builder()).build('v1'), now=NOW)
        same = fill(builder()).build('v2')
        with self.assertRaises(SiteBaselineError) as raised:
            activate(same, previous=active)
        self.assertIn('nothing would change', str(raised.exception))

    def test_the_active_baseline_is_never_mutated_by_new_traffic(self):
        """§85. Continuous absorption is how a baseline gets poisoned."""
        active = activate(fill(builder()).build('v1'), now=NOW)
        before = active.digest
        build = fill(builder(), rate=100_000.0)
        build.build('v2')
        self.assertEqual(active.digest, before)
        for method in dir(active):
            self.assertNotIn(method, ('observe', 'update', 'absorb', 'extend', 'add'))


class TestProvenance(unittest.TestCase):
    """§25, §88. Where the data came from is recorded, never inferred."""

    def test_every_provenance_is_accepted_and_recorded(self):
        for provenance in PROVENANCE:
            with self.subTest(provenance=provenance):
                candidate = fill(builder(provenance=provenance)).build('v1')
                self.assertEqual(candidate.provenance, provenance)

    def test_lab_data_earns_more_confidence_than_observed_traffic(self):
        lab = activate(fill(builder(provenance=LAB)).build('v1'), now=NOW)
        observed = activate(fill(builder(provenance=OBSERVED)).build('v1'), now=NOW)
        self.assertGreater(lab.confidence, observed.confidence)

    def test_observed_traffic_says_that_nobody_checked_it(self):
        """§88. "No alert" is not the same as "benign"."""
        candidate = fill(builder(provenance=OBSERVED)).build('v1')
        self.assertTrue(any('no attacker was present' in note
                            for note in candidate.notes))

    def test_reviewed_shadow_sits_between_lab_and_observed(self):
        scores = {}
        for provenance in (LAB, REVIEWED_SHADOW, OBSERVED):
            scores[provenance] = activate(
                fill(builder(provenance=provenance)).build('v1'), now=NOW).confidence
        self.assertGreater(scores[LAB], scores[REVIEWED_SHADOW])
        self.assertGreater(scores[REVIEWED_SHADOW], scores[OBSERVED])

    def test_an_unknown_provenance_is_refused(self):
        with self.assertRaises(SiteBaselineError):
            BaselineBuilder('main', provenance='trust-me')


class TestComparison(unittest.TestCase):
    def setUp(self):
        self.baseline = activate(fill(builder(), rate=100.0, paths=20.0).build('v1'),
                                 now=NOW)

    def test_an_ordinary_value_is_within_the_baseline(self):
        verdict, _, _ = self.baseline.compare('requests_per_minute', 100.0)
        self.assertEqual(verdict, WITHIN_BASELINE)

    def test_a_far_larger_value_is_above_the_baseline(self):
        verdict, ratio, reason = self.baseline.compare('requests_per_minute', 5000.0)
        self.assertEqual(verdict, ABOVE_BASELINE)
        self.assertGreater(ratio, 10)
        self.assertIn('percentile', reason)

    def test_an_untracked_statistic_says_so_rather_than_guessing(self):
        verdict, _, reason = self.baseline.compare('phase_of_the_moon', 1.0)
        self.assertEqual(verdict, INSUFFICIENT_DATA)
        self.assertIn('not described', reason)

    def test_the_same_value_means_different_things_on_different_sites(self):
        """The claim this whole stage rests on, as a test."""
        blog = activate(fill(builder('blog'), rate=100.0).build('v1'), now=NOW)
        api = activate(fill(builder('api'), rate=5000.0).build('v1'), now=NOW)
        busy = 2000.0
        self.assertEqual(blog.compare('requests_per_minute', busy)[0], ABOVE_BASELINE)
        self.assertEqual(api.compare('requests_per_minute', busy)[0], WITHIN_BASELINE)

    def test_a_baseline_never_calls_anything_an_attack(self):
        meaning = self.baseline.explain()['meaning']
        self.assertIn('not evidence of an attack', meaning)


class TestAgeing(unittest.TestCase):
    def test_a_fresh_baseline_stays_active(self):
        baseline = activate(fill(builder()).build('v1'), now=NOW)
        self.assertEqual(baseline.aged(now=NOW + 60).state, ACTIVE)

    def test_an_old_baseline_becomes_stale(self):
        baseline = activate(fill(builder()).build('v1'), now=NOW)
        aged = baseline.aged(now=NOW + 400 * 24 * 3600)
        self.assertEqual(aged.state, STALE)
        self.assertTrue(any('older than' in note for note in aged.notes))

    def test_a_stale_baseline_is_still_usable_but_trusted_less(self):
        baseline = activate(fill(builder()).build('v1'), now=NOW)
        aged = baseline.aged(now=NOW + 400 * 24 * 3600)
        self.assertTrue(aged.usable)
        self.assertLess(aged.confidence, baseline.confidence)

    def test_ageing_never_mutates_the_original(self):
        baseline = activate(fill(builder()).build('v1'), now=NOW)
        baseline.aged(now=NOW + 400 * 24 * 3600)
        self.assertEqual(baseline.state, ACTIVE)


class TestVersioningAndBounds(unittest.TestCase):
    """§86. Versioned, hashable, and bounded in memory."""

    def test_a_baseline_carries_a_version_and_a_content_digest(self):
        candidate = fill(builder()).build('site-main-baseline-v1')
        self.assertEqual(candidate.version, 'site-main-baseline-v1')
        self.assertEqual(len(candidate.digest), 16)

    def test_the_digest_follows_the_content_not_the_name(self):
        one = fill(builder(seed=1), rate=100.0).build('v1')
        two = fill(builder(seed=1), rate=100.0).build('completely-different-name')
        self.assertEqual(one.digest, two.digest)

    def test_different_traffic_gives_a_different_digest(self):
        one = fill(builder(seed=1), rate=100.0).build('v1')
        two = fill(builder(seed=1), rate=9000.0).build('v1')
        self.assertNotEqual(one.digest, two.digest)

    def test_the_builder_is_bounded_however_much_traffic_arrives(self):
        import sys
        build = builder()
        fill(build, windows=200_000, sources=500)
        held = sum(len(values) for values in build._values.values())
        self.assertLessEqual(held, len(TRACKED) * 4000)
        self.assertLess(sys.getsizeof(build._sources), 300_000)
        self.assertEqual(build.samples, 200_000)

    def test_a_baseline_stores_quantiles_not_every_observation(self):
        candidate = fill(builder(), windows=50_000, sources=200).build('v1')
        document = candidate.explain()
        self.assertLess(len(str(document)), 6000)
        for row in document['distributions'].values():
            self.assertEqual(set(row), {'p50', 'p90', 'p99', 'max', 'mean', 'samples'})

    def test_every_state_is_named(self):
        self.assertEqual(set(STATES),
                         {MISSING, LEARNING, VALIDATING, ACTIVE, STALE, DEGRADED})

    def test_a_baseline_is_json_serialisable(self):
        import json
        json.dumps(activate(fill(builder()).build('v1'), now=NOW).explain())


class TestCandidateComparison(unittest.TestCase):
    """§87. What an operator sees before accepting a new baseline."""

    def test_a_much_wider_candidate_is_flagged(self):
        active = activate(fill(builder(seed=1), rate=100.0).build('v1'), now=NOW)
        candidate = fill(builder(seed=2), rate=1000.0).build('v2')
        report = compare_baselines(active, candidate)
        self.assertTrue(report['comparable'])
        self.assertIn('requests_per_minute', report['widened'])
        self.assertIn('poisoned', report['caution'])

    def test_a_similar_candidate_raises_no_caution(self):
        active = activate(fill(builder(seed=1), rate=100.0).build('v1'), now=NOW)
        candidate = fill(builder(seed=2), rate=105.0).build('v2')
        self.assertEqual(compare_baselines(active, candidate)['caution'], '')

    def test_comparison_says_so_when_there_is_nothing_to_compare(self):
        report = compare_baselines(missing('main'), fill(builder()).build('v1'))
        self.assertFalse(report['comparable'])


class TestDistribution(unittest.TestCase):
    def test_quantiles_of_a_known_series(self):
        distribution = Distribution.from_values(range(101))
        self.assertAlmostEqual(distribution.p50, 50.0)
        self.assertAlmostEqual(distribution.p90, 90.0)
        self.assertAlmostEqual(distribution.maximum, 100.0)

    def test_an_empty_series_is_survivable(self):
        self.assertEqual(Distribution.from_values([]).samples, 0)

    def test_missing_and_not_a_number_values_are_dropped(self):
        distribution = Distribution.from_values([1.0, None, float('nan'), 3.0])
        self.assertEqual(distribution.samples, 2)


if __name__ == '__main__':
    unittest.main()
