"""The release numbers, and the ways they could be made to look better.

P15S §17, §35, §36, §52, §53, §54, §60.

Every test here is about a number that could be improved without anything
failing. Put unreviewed sources in the benign denominator and the false-block
rate falls. Put controlled scans in it and it falls further. Merge deliberate
tests into naturally observed positives and recall rises. Compare the interval
against 500 sources instead of 3,000 and an insufficient window passes.

None of those is a bug that raises. Each is a decision about a denominator, so
each has a test naming it.
"""
import unittest

from eye_for_an_eye.autonomy import shadow_evidence as ev
from eye_for_an_eye.autonomy import shadow_result as sr
from eye_for_an_eye.autonomy.evaluation import ReleaseThresholds


def source(pseudonym, *, blocked=False, collection=ev.REAL_SHADOW,
           profile='public_website', windows=1, degraded=()):
    """One aggregated source, as `shadow_evidence.sources()` would produce it."""
    return ev.Source(pseudonym=pseudonym, collection=collection, windows=windows,
                     would_block_windows=1 if blocked else 0,
                     profiles={profile} if profile else set(),
                     degraded_components=set(degraded))


def population(*, benign=0, false_blocks=0, positives=0, positives_blocked=0,
               unreviewed=0, controlled=0, controlled_blocked=0, profile='public_website'):
    """A whole period, built from counts, with the labels a reviewer wrote."""
    by_source, labels = {}, {}
    for n in range(benign):
        key = f'src-benign-{n}'
        by_source[key] = source(key, blocked=n < false_blocks, profile=profile)
        labels[key] = ev.BENIGN
    for n in range(positives):
        key = f'src-positive-{n}'
        by_source[key] = source(key, blocked=n < positives_blocked, profile=profile)
        labels[key] = ev.MALICIOUS_AUTOMATION
    for n in range(unreviewed):
        key = f'src-unreviewed-{n}'
        by_source[key] = source(key, profile=profile)
    for n in range(controlled):
        key = f'src-controlled-{n}'
        by_source[key] = source(key, blocked=n < controlled_blocked,
                                collection=ev.CONTROLLED_POSITIVE, profile=profile)
        labels[key] = ev.MALICIOUS_AUTOMATION
    return by_source, labels


class TestTheInterval(unittest.TestCase):
    """The arithmetic `docs/SHADOW_VALIDATION_PLAN.md` derives its targets from."""

    def test_a_clean_run_of_2995_sources_supports_one_per_thousand(self):
        """The number the 3,000-source target comes from."""
        self.assertAlmostEqual(sr.upper_bound(0, 2995) * 1000, 1.0, places=2)

    def test_a_clean_run_of_500_sources_does_not(self):
        """§17. Five hundred clean sources are consistent with six times the ceiling."""
        self.assertAlmostEqual(sr.upper_bound(0, 500) * 1000, 5.97, places=2)

    def test_more_evidence_narrows_the_bound(self):
        bounds = [sr.upper_bound(0, n) for n in (500, 1000, 2000, 3000, 5000)]
        self.assertEqual(bounds, sorted(bounds, reverse=True))

    def test_an_observed_error_widens_it(self):
        self.assertGreater(sr.upper_bound(1, 3000), sr.upper_bound(0, 3000))

    def test_a_bound_over_nothing_is_absent_rather_than_wide(self):
        """1.0 would read as a measurement of a terrible system."""
        self.assertIsNone(sr.upper_bound(0, 0))

    def test_everything_failing_bounds_at_one(self):
        self.assertEqual(sr.upper_bound(5, 5), 1.0)

    def test_the_bound_brackets_the_observed_rate(self):
        self.assertGreater(sr.upper_bound(3, 1000), 3 / 1000)

    def test_precision_needs_59_clean_blocks_to_reach_the_floor(self):
        """The other derived sample size, checked at the edge."""
        self.assertLess(sr.lower_bound_precision(0, 58), 0.95)
        self.assertGreaterEqual(sr.lower_bound_precision(0, 59), 0.95)

    def test_the_bound_satisfies_the_definition_it_claims(self):
        """The bisection is checked against what it is bisecting towards.

        The Clopper-Pearson upper bound is *defined* as the p at which observing
        this many events or fewer has probability exactly alpha. Asserting that
        identity catches a bisection that converged on the wrong side, an
        off-by-one in the tail, or a step count too small for the sample --
        none of which would make any of the tests above fail.
        """
        import math
        for events, trials in ((1, 3000), (3, 1000), (20, 3000), (1500, 3000),
                               (59, 60)):
            with self.subTest(events=events, trials=trials):
                bound = sr.upper_bound(events, trials)
                tail = sr._tail(bound, events, trials,
                                log_factorial_trials=math.lgamma(trials + 1))
                self.assertAlmostEqual(tail, 0.05, places=9)

    def test_a_large_sample_does_not_overflow(self):
        """`math.comb(3000, 1500)` is a 900-digit integer.

        The readable form of the binomial tail raises OverflowError on any
        sample big enough to matter, which is why the terms are built in log
        space. This is the test that failed when they were not.
        """
        self.assertIsInstance(sr.upper_bound(1500, 3000), float)
        self.assertIsInstance(sr.upper_bound(2, 100_000), float)

    def test_it_agrees_with_scipy_where_scipy_is_available(self):
        """An independent implementation of the same definition.

        scipy is not a dependency of the sensor -- it arrives with the training
        extra -- so this skips rather than failing where it is absent.
        """
        try:
            from scipy.stats import beta
        except ImportError:                                   # pragma: no cover
            self.skipTest('scipy is not installed')
        for events, trials in ((0, 500), (1, 3000), (3, 1000), (20, 3000)):
            with self.subTest(events=events, trials=trials):
                self.assertAlmostEqual(sr.upper_bound(events, trials),
                                       beta.ppf(0.95, events + 1, trials - events),
                                       places=12)


class TestTheSampleSizesAreNotTheReleaseThresholds(unittest.TestCase):
    """§17, named. `ReleaseThresholds.min_benign_sample` is 500 and is not used."""

    def test_the_benign_target_is_three_thousand(self):
        self.assertEqual(sr.MINIMUM_BENIGN_SOURCES, 3000)

    def test_it_is_deliberately_not_the_release_thresholds_minimum(self):
        self.assertEqual(ReleaseThresholds().min_benign_sample, 500)
        self.assertNotEqual(sr.MINIMUM_BENIGN_SOURCES,
                            ReleaseThresholds().min_benign_sample,
                            'the sample size was aligned with the 500 in '
                            'ReleaseThresholds; 500 clean sources are consistent '
                            'with 5.97 false blocks per 1000, six times the '
                            'ceiling they would be claimed to establish')

    def test_the_blocked_target_clears_the_precision_floor(self):
        self.assertGreaterEqual(
            sr.lower_bound_precision(0, sr.MINIMUM_BLOCKED_SOURCES),
            ReleaseThresholds().min_block_precision)

    def test_the_threshold_values_are_the_operator_policy_not_a_new_pair(self):
        """They have been in `ReleaseThresholds` since the decision authority."""
        by_source, labels = population(benign=3000, positives=60, positives_blocked=60)
        answer = sr.verdict(sr.evaluate(by_source, labels))
        self.assertEqual(answer['thresholds']['max_false_blocks_per_1000_benign'],
                         ReleaseThresholds().max_false_blocks_per_1000_benign)
        self.assertEqual(answer['thresholds']['min_block_precision'],
                         ReleaseThresholds().min_block_precision)


class TestUnreviewedTrafficEntersNoRate(unittest.TestCase):
    """§53. The denominator that would make any system look perfect."""

    def test_the_benign_denominator_is_the_reviewed_sources_only(self):
        by_source, labels = population(benign=3000, unreviewed=100_000)
        result = sr.evaluate(by_source, labels)
        self.assertEqual(result['false_would_blocks']['benign_sources'], 3000)

    def test_the_unreviewed_are_reported_rather_than_dropped(self):
        by_source, labels = population(benign=10, unreviewed=90)
        populations = {p['population']: p for p in
                       sr.evaluate(by_source, labels)['populations']}
        self.assertEqual(populations['unreviewed']['sources'], 90,
                         'a reader cannot judge a rate without knowing how much '
                         'of the period it excluded')

    def test_an_ignored_source_is_excluded_and_counted(self):
        by_source, labels = population(benign=10)
        labels['src-benign-0'] = ev.IGNORE
        result = sr.evaluate(by_source, labels)
        populations = {p['population']: p for p in result['populations']}
        self.assertEqual(result['false_would_blocks']['benign_sources'], 9)
        self.assertEqual(populations['ignored']['sources'], 1)

    def test_an_unreviewed_would_block_enters_neither_precision_column(self):
        """§14. It is not correct and it is not incorrect; nobody looked."""
        by_source = {'src-x': source('src-x', blocked=True)}
        precision = sr.evaluate(by_source, {})['block_precision']
        self.assertEqual(precision['reviewed_would_block_sources'], 0)
        self.assertIsNone(precision['precision'])


class TestControlledPositivesStayOutOfThePopulation(unittest.TestCase):
    """§31, §54. A scan somebody ran on purpose is not traffic that happened."""

    def test_a_controlled_source_is_not_in_the_benign_denominator(self):
        by_source, labels = population(benign=100, controlled=50, controlled_blocked=50)
        self.assertEqual(
            sr.evaluate(by_source, labels)['false_would_blocks']['benign_sources'], 100)

    def test_a_controlled_source_is_not_in_the_precision_numerator(self):
        by_source, labels = population(benign=100, controlled=50, controlled_blocked=50)
        self.assertEqual(
            sr.evaluate(by_source, labels)['block_precision']['reviewed_would_block_sources'],
            0, 'deliberate scans were counted as correct blocks on real traffic')

    def test_the_two_recalls_are_reported_apart(self):
        by_source, labels = population(positives=4, positives_blocked=1,
                                       controlled=10, controlled_blocked=10)
        result = sr.evaluate(by_source, labels)
        self.assertEqual(result['controlled_positive_recall']['recall'], 1.0)
        self.assertEqual(result['natural_positive_recall']['recall'], 0.25)

    def test_the_separation_is_stated_in_the_result(self):
        by_source, labels = population(controlled=1, controlled_blocked=1)
        note = sr.evaluate(by_source, labels)['controlled_positive_recall']['note']
        self.assertIn('never merged with naturally observed', note)


class TestTheRates(unittest.TestCase):
    def test_a_clean_period_reports_zero_and_its_bound(self):
        by_source, labels = population(benign=3000)
        rates = sr.evaluate(by_source, labels)['false_would_blocks']
        self.assertEqual(rates['per_1000_benign'], 0.0)
        self.assertAlmostEqual(rates['upper_bound_95_per_1000'], 0.998, places=2)

    def test_a_false_block_is_counted_once_however_many_windows_it_had(self):
        """§18, through the rate rather than through the aggregation."""
        by_source, labels = population(benign=1000, false_blocks=1)
        by_source['src-benign-0'].would_block_windows = 500
        rates = sr.evaluate(by_source, labels)['false_would_blocks']
        self.assertEqual(rates['false_would_block_sources'], 1)
        self.assertEqual(rates['per_1000_benign'], 1.0)

    def test_precision_is_over_reviewed_blocks_only(self):
        by_source, labels = population(benign=100, false_blocks=2,
                                       positives=18, positives_blocked=18)
        precision = sr.evaluate(by_source, labels)['block_precision']
        self.assertEqual(precision['reviewed_would_block_sources'], 20)
        self.assertEqual(precision['incorrect'], 2)
        self.assertEqual(precision['precision'], 0.9)

    def test_a_period_with_no_reviewed_benign_reports_no_rate(self):
        """None, not zero. Zero would be a measurement."""
        rates = sr.evaluate(*population(unreviewed=50))['false_would_blocks']
        self.assertIsNone(rates['per_1000_benign'])
        self.assertIsNone(rates['upper_bound_95_per_1000'])


class TestPerProfile(unittest.TestCase):
    """§36. A safe website result and a dangerous API result are not averaged."""

    def test_each_profile_gets_its_own_numbers(self):
        website, labels = population(benign=100, false_blocks=0, profile='public_website')
        api, api_labels = population(benign=100, false_blocks=10, profile='api')
        api = {f'api-{k}': v for k, v in api.items()}
        api_labels = {f'api-{k}': v for k, v in api_labels.items()}
        for key, value in api.items():
            value.pseudonym = key
        website.update(api)
        labels.update(api_labels)
        site = sr.evaluate(website, labels, profile='public_website')
        service = sr.evaluate(website, labels, profile='api')
        self.assertEqual(site['false_would_blocks']['per_1000_benign'], 0.0)
        self.assertEqual(service['false_would_blocks']['per_1000_benign'], 100.0)

    def test_an_unknown_profile_selects_nothing_rather_than_everything(self):
        by_source, labels = population(benign=10)
        result = sr.evaluate(by_source, labels, profile='honeypot')
        self.assertEqual(result['false_would_blocks']['benign_sources'], 0)


class TestTheVerdict(unittest.TestCase):
    """§60. Three answers, and two of them are not a pass."""

    def enough(self, **kwargs):
        defaults = {'benign': 3000, 'positives': 60, 'positives_blocked': 60}
        defaults.update(kwargs)
        return population(**defaults)

    def test_a_small_clean_window_is_insufficient_not_failed(self):
        """The trap this ordering exists for.

        With 100 clean benign sources the bound is 29 per 1000 and exceeds the
        ceiling on arithmetic alone. Reporting FAIL there would be a statement
        about the window length dressed up as a finding about the detector.
        """
        by_source, labels = population(benign=100, positives=5, positives_blocked=5)
        answer = sr.verdict(sr.evaluate(by_source, labels))
        self.assertEqual(answer['verdict'], sr.INSUFFICIENT_EVIDENCE)

    def test_insufficiency_names_the_shortfall_and_the_target(self):
        answer = sr.verdict(sr.evaluate(*population(benign=100)))
        reasons = ' '.join(answer['sufficiency']['reasons'])
        self.assertIn('100 reviewed benign sources', reasons)
        self.assertIn('3000 are needed', reasons)

    def test_a_window_that_is_insufficient_still_shows_what_else_failed(self):
        """Quiet is not the same as clean."""
        by_source, labels = population(benign=100, false_blocks=50)
        answer = sr.verdict(sr.evaluate(by_source, labels))
        self.assertEqual(answer['verdict'], sr.INSUFFICIENT_EVIDENCE)
        self.assertTrue(answer['failing_checks'],
                        'a window with a 50% false-block rate reported nothing '
                        'but "not enough data"')

    def test_a_clean_sufficient_window_passes(self):
        answer = sr.verdict(sr.evaluate(*self.enough()))
        self.assertEqual(answer['verdict'], sr.PASS)
        self.assertEqual(answer['failing_checks'], [])

    def test_one_false_block_in_three_thousand_does_not_pass(self):
        """The 3,000 target is the size at which a *clean* window supports the
        ceiling, and nothing more than that.

        One false block in 3,000 is an observed rate of 0.33 per 1000, well
        under the ceiling -- and its 95% upper bound is 4.7 per 1000, which is
        not. Reading the observed rate and calling it a pass is the mistake the
        interval exists to prevent; demonstrating 1.0 per 1000 with one error
        takes roughly 4,700 sources, not 3,000.
        """
        result = sr.evaluate(*self.enough(false_blocks=1))
        self.assertEqual(result['false_would_blocks']['per_1000_benign'], 0.3333)
        self.assertGreater(result['false_would_blocks']['upper_bound_95_per_1000'],
                           ReleaseThresholds().max_false_blocks_per_1000_benign)
        self.assertEqual(sr.verdict(result)['verdict'], sr.FAIL)

    def test_enough_false_blocks_fail_it(self):
        answer = sr.verdict(sr.evaluate(*self.enough(false_blocks=10)))
        self.assertEqual(answer['verdict'], sr.FAIL)
        self.assertTrue(any('upper bound' in reason for reason in answer['failing_checks']))

    def test_poor_precision_fails_it(self):
        by_source, labels = self.enough(benign=3000, false_blocks=20,
                                        positives=60, positives_blocked=60)
        answer = sr.verdict(sr.evaluate(by_source, labels))
        self.assertEqual(answer['verdict'], sr.FAIL)
        self.assertTrue(any('precision' in reason for reason in answer['failing_checks']))

    def test_a_pass_does_not_authorise_enabling_blocking(self):
        """§62, in the output rather than only in the brief."""
        answer = sr.verdict(sr.evaluate(*self.enough()))
        self.assertIn('does not authorise enabling autonomous blocking',
                      answer['note'])


class TestDegeneracy(unittest.TestCase):
    """Two systems that measure beautifully and defend nothing."""

    def test_allowing_everything_does_not_pass(self):
        by_source, labels = population(benign=3000, positives=60, positives_blocked=0)
        answer = sr.verdict(sr.evaluate(by_source, labels))
        self.assertEqual(answer['verdict'], sr.FAIL)
        self.assertTrue(answer['degeneracy']['degenerate'])
        self.assertTrue(any('stopped nothing' in reason
                            for reason in answer['failing_checks']))

    def test_a_perfect_false_block_rate_is_not_enough_on_its_own(self):
        """The allow-all system's numbers, stated as the trap they are."""
        by_source, labels = population(benign=3000, false_blocks=0,
                                       positives=60, positives_blocked=0)
        result = sr.evaluate(by_source, labels)
        self.assertEqual(result['false_would_blocks']['per_1000_benign'], 0.0)
        self.assertEqual(sr.verdict(result)['verdict'], sr.FAIL)

    def test_blocking_every_benign_source_does_not_pass(self):
        by_source, labels = population(benign=3000, false_blocks=3000,
                                       positives=60, positives_blocked=60)
        answer = sr.verdict(sr.evaluate(by_source, labels))
        self.assertEqual(answer['verdict'], sr.FAIL)
        self.assertTrue(any('every reviewed benign source' in reason
                            for reason in answer['failing_checks']))


class TestEvidenceIntegrity(unittest.TestCase):
    def test_a_degraded_component_fails_the_window(self):
        by_source, labels = population(benign=3000, positives=60, positives_blocked=60)
        by_source['src-benign-0'].degraded_components.add('calibrator:UNAVAILABLE')
        answer = sr.verdict(sr.evaluate(by_source, labels))
        self.assertEqual(answer['verdict'], sr.FAIL)
        self.assertTrue(any('DEGRADED or UNAVAILABLE' in reason
                            for reason in answer['failing_checks']))

    def test_excluding_the_degraded_sources_clears_it(self):
        """The plan fails a window where they were *not* excluded."""
        by_source, labels = population(benign=3001, positives=60, positives_blocked=60)
        by_source['src-benign-3000'].degraded_components.add('calibrator:UNAVAILABLE')
        labels['src-benign-3000'] = ev.IGNORE
        kept = {k: v for k, v in by_source.items() if labels.get(k) != ev.IGNORE}
        self.assertEqual(sr.verdict(sr.evaluate(kept, labels))['verdict'], sr.PASS)

    def test_rows_that_could_not_be_read_fail_the_window(self):
        by_source, labels = population(benign=3000, positives=60, positives_blocked=60)
        answer = sr.verdict(sr.evaluate(by_source, labels),
                            skipped={'unparseable_lines': 4,
                                     'unsupported_schema_rows': 0})
        self.assertEqual(answer['verdict'], sr.FAIL)
        self.assertTrue(any('incomplete by an amount nobody can quantify' in reason
                            for reason in answer['failing_checks']))

    def test_a_window_that_lost_nothing_is_not_penalised(self):
        by_source, labels = population(benign=3000, positives=60, positives_blocked=60)
        answer = sr.verdict(sr.evaluate(by_source, labels),
                            skipped={'unparseable_lines': 0,
                                     'unsupported_schema_rows': 0})
        self.assertEqual(answer['verdict'], sr.PASS)


class TestTheWholeReport(unittest.TestCase):
    """§52. Committed code against frozen files, not a notebook."""

    def setUp(self):
        import tempfile
        from eye_for_an_eye.autonomy.shadow_export import ShadowExport
        from tests.test_p15s_shadow_evidence import Outcome
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        from pathlib import Path
        self.path = Path(self._workspace.name) / 'export.jsonl'
        export = ShadowExport(self.path)
        try:
            for n in range(20):
                export.write(Outcome(pseudonym=f'src-{n}', blocked=n < 3))
        finally:
            export.close()
        self.labels = {f'src-{n}': (ev.MALICIOUS_AUTOMATION if n < 3 else ev.BENIGN)
                       for n in range(20)}

    def test_it_runs_end_to_end_from_files(self):
        document = sr.report(self.path, self.labels)
        self.assertEqual(document['rows_read'], 20)
        self.assertEqual(document['overall']['false_would_blocks']['benign_sources'], 17)
        self.assertEqual(document['shadow_result_schema_version'],
                         sr.SHADOW_RESULT_SCHEMA_VERSION)

    def test_a_twenty_source_window_is_insufficient(self):
        self.assertEqual(sr.report(self.path, self.labels)['verdict']['verdict'],
                         sr.INSUFFICIENT_EVIDENCE)

    def test_the_assumptions_are_printed_with_the_numbers(self):
        assumptions = ' '.join(sr.report(self.path, self.labels)['assumptions'])
        self.assertIn('independent', assumptions)
        self.assertIn('widens the true uncertainty', assumptions)

    def test_the_per_profile_overlap_is_stated(self):
        """Per-profile rows do not sum to the overall row, and say so."""
        assumptions = ' '.join(sr.report(self.path, self.labels)['assumptions'])
        self.assertIn('do not sum to the overall row', assumptions)

    def test_the_profiles_present_are_broken_out_without_being_asked(self):
        document = sr.report(self.path, self.labels)
        self.assertEqual([entry['profile'] for entry in document['per_profile']],
                         ['public_website'])

    def test_labels_read_from_a_pack_reach_the_report(self):
        """The loop §15 asks for: blinded pack out, labels in, numbers from both."""
        import json
        from pathlib import Path
        pack = Path(self._workspace.name) / 'labels.jsonl'
        pack.write_text(''.join(json.dumps({'source_pseudonym': key, 'label': value})
                                + '\n' for key, value in self.labels.items()),
                        encoding='utf-8')
        labels, report = ev.read_labels(pack)
        self.assertEqual(report['sources_labelled'], 20)
        document = sr.report(self.path, labels)
        self.assertEqual(document['overall']['false_would_blocks']['benign_sources'], 17)


if __name__ == '__main__':
    unittest.main()
