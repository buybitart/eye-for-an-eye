"""Reading an evidence period without flattering it. P15S §18, §45, §50, §51, §53.

Three mistakes would each produce a beautiful false-block rate from the same
files, and none of them would raise anything:

* counting **windows** instead of sources, so one busy monitoring host becomes a
  thousand independent pieces of evidence (§18);
* counting **unreviewed** traffic as benign, which is most of a shadow period
  and would make the denominator enormous (§53);
* counting a **controlled positive** test against an owned asset as ordinary
  traffic, putting a deliberate scan in the benign population (§31).

So the tests below are mostly about denominators. They are written against rows
produced by the real `ShadowExport`, not against hand-built dictionaries,
because the recurring finding of this whole cycle is that a reader and a writer
can each be correct about a schema neither of them shares.
"""
import json
from pathlib import Path
import tempfile
import unittest

from eye_for_an_eye.autonomy import shadow_evidence as ev
from eye_for_an_eye.autonomy.shadow_export import (
    CONTROLLED_POSITIVE, REAL_SHADOW, ShadowExport)

from tests.test_p15_5r_journal import FakeOutcome, FakeProfile, FakeResolution


class Profile(FakeProfile):
    def __init__(self, name):
        self.name = name


class Resolution(FakeResolution):
    def __init__(self, profile='public_website', scope='GLOBAL'):
        self.profile = Profile(profile)
        self.scope = scope
        self.site_id = ''


class Outcome(FakeOutcome):
    """One decision, with the four things a test needs to vary."""

    def __init__(self, *, pseudonym='src-0000000000000000', blocked=False,
                 profile='public_website', scope='GLOBAL',
                 timestamp='2026-09-19T00:00:00+00:00'):
        super().__init__(blocked=blocked)
        self.record.source_pseudonym = pseudonym
        self.record._extra = {'timestamp': timestamp}
        self.resolution = Resolution(profile, scope)


class EvidenceCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)

    def write(self, outcomes, *, name='export.jsonl', collection=REAL_SHADOW,
              segment_id='', component_health=None):
        """Real export rows, written by the real writer."""
        path = self.directory / name
        export = ShadowExport(path, collection=collection, segment_id=segment_id)
        try:
            for outcome in outcomes:
                self.assertTrue(export.write(outcome, component_health=component_health),
                                'the fixture failed to write, so the test below '
                                'would have passed on an empty file')
        finally:
            export.close()
        return path


class TestTheUnitIsASource(EvidenceCase):
    """§18. A thousand windows from one host is one piece of evidence."""

    def test_many_windows_from_one_source_are_one_source(self):
        path = self.write(Outcome(pseudonym='src-aaaa', timestamp=f'2026-09-19T{h:02d}:00:00+00:00')
                          for h in range(24))
        rows, _ = ev.read_rows(path)
        found = ev.sources(rows)
        self.assertEqual(len(rows), 24)
        self.assertEqual(len(found), 1)
        self.assertEqual(found['src-aaaa'].windows, 24)

    def test_windows_and_sources_are_reported_as_separate_numbers(self):
        path = self.write([Outcome(pseudonym='src-a'), Outcome(pseudonym='src-a'),
                           Outcome(pseudonym='src-b')])
        summary = ev.summarise(path)
        self.assertEqual(summary['sources'], 2)
        self.assertEqual(summary['windows'], 3)

    def test_one_blocked_window_makes_the_source_would_blocked(self):
        """What would have happened to it, which is the counterfactual asked."""
        path = self.write([Outcome(pseudonym='src-a', blocked=False),
                           Outcome(pseudonym='src-a', blocked=True),
                           Outcome(pseudonym='src-a', blocked=False)])
        source = ev.sources(ev.read_rows(path)[0])['src-a']
        self.assertTrue(source.would_blocked)
        self.assertEqual(source.would_block_windows, 1)
        self.assertEqual(source.windows, 3)

    def test_a_source_that_was_never_blocked_is_not_would_blocked(self):
        path = self.write([Outcome(pseudonym='src-a', blocked=False)])
        self.assertFalse(ev.sources(ev.read_rows(path)[0])['src-a'].would_blocked)

    def test_the_hour_buckets_a_source_appeared_in_are_counted(self):
        path = self.write(Outcome(pseudonym='src-a',
                                  timestamp=f'2026-09-19T{h:02d}:30:00+00:00')
                          for h in range(5))
        self.assertEqual(ev.sources(ev.read_rows(path)[0])['src-a'].explain()['hour_buckets'], 5)


class TestUnreviewedTrafficIsNotBenign(EvidenceCase):
    """§53, the rule most easily broken by accident."""

    def test_an_unlabelled_source_is_counted_as_unlabelled(self):
        path = self.write([Outcome(pseudonym=f'src-{n}') for n in range(10)])
        summary = ev.summarise(path)
        self.assertEqual(summary['label_states'][ev.UNLABELED], 10)
        self.assertEqual(summary['label_states'][ev.BENIGN], 0)

    def test_a_label_is_never_derived_from_the_decision(self):
        """§9, §14. Blocked is not malicious and allowed is not benign."""
        path = self.write([Outcome(pseudonym='src-blocked', blocked=True),
                           Outcome(pseudonym='src-allowed', blocked=False)])
        summary = ev.summarise(path)
        self.assertEqual(summary['label_states'][ev.UNLABELED], 2)
        self.assertEqual(summary['label_states'][ev.MALICIOUS_AUTOMATION], 0)
        self.assertEqual(summary['label_states'][ev.BENIGN], 0)

    def test_the_summary_says_so_in_words(self):
        """A reader should not have to reverse-engineer it from the counts."""
        note = ev.summarise(self.write([Outcome()]))['note']
        self.assertIn('not benign because nobody looked at it', note)

    def test_an_ignored_source_is_counted_out_loud(self):
        """IGNORE is the obvious way to make a result disappear, so it is visible."""
        path = self.write([Outcome(pseudonym='src-health'), Outcome(pseudonym='src-x')])
        summary = ev.summarise(path, labels={'src-health': ev.IGNORE})
        self.assertEqual(summary['label_states'][ev.IGNORE], 1)


class TestTheCollectionsStaySeparate(EvidenceCase):
    """§31. A scan somebody ran on purpose is not ordinary traffic."""

    def test_each_source_carries_the_collection_it_was_written_under(self):
        real = self.write([Outcome(pseudonym='src-visitor')], name='real.jsonl',
                          collection=REAL_SHADOW)
        test = self.write([Outcome(pseudonym='src-scanner', blocked=True)],
                          name='test.jsonl', collection=CONTROLLED_POSITIVE)
        found = ev.sources(ev.read_rows([real, test])[0])
        self.assertEqual(found['src-visitor'].collection, REAL_SHADOW)
        self.assertEqual(found['src-scanner'].collection, CONTROLLED_POSITIVE)

    def test_the_summary_breaks_the_period_down_by_collection(self):
        real = self.write([Outcome(pseudonym='src-v')], name='real.jsonl')
        test = self.write([Outcome(pseudonym='src-s', blocked=True)],
                          name='test.jsonl', collection=CONTROLLED_POSITIVE)
        collections = ev.summarise([real, test])['collections']
        self.assertEqual(collections[REAL_SHADOW]['sources'], 1)
        self.assertEqual(collections[CONTROLLED_POSITIVE]['would_block_sources'], 1)

    def test_one_source_in_two_collections_is_recorded_rather_than_resolved(self):
        """It cannot happen inside one writer, so it means two were merged."""
        real = self.write([Outcome(pseudonym='src-same')], name='real.jsonl')
        test = self.write([Outcome(pseudonym='src-same')], name='test.jsonl',
                          collection=CONTROLLED_POSITIVE)
        found = ev.sources(ev.read_rows([real, test])[0])
        self.assertEqual(found['src-same'].collection, 'MIXED')

    def test_the_segment_travels_to_the_source(self):
        path = self.write([Outcome(pseudonym='src-a')], segment_id='seg-1')
        self.assertEqual(ev.sources(ev.read_rows(path)[0])['src-a'].segments, {'seg-1'})


class TestReadingWhatIsThere(EvidenceCase):
    """A bad line is skipped and counted, never guessed at."""

    def test_a_truncated_last_line_does_not_lose_the_file(self):
        """What a full disk leaves behind."""
        path = self.write([Outcome(pseudonym=f'src-{n}') for n in range(5)])
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write('{"source_pseudonym": "src-tru')
        rows, skipped = ev.read_rows(path)
        self.assertEqual(len(rows), 5)
        self.assertEqual(skipped['unparseable_lines'], 1)

    def test_a_row_from_an_unreadable_schema_is_refused_not_guessed(self):
        """A version 1 row has no provenance, so it cannot be placed."""
        path = self.directory / 'old.jsonl'
        path.write_text(json.dumps({'shadow_export_schema_version': 1,
                                    'source_pseudonym': 'src-old',
                                    'would_action': 'TEMP_BLOCK'}) + '\n',
                        encoding='utf-8')
        rows, skipped = ev.read_rows(path)
        self.assertEqual(rows, [])
        self.assertEqual(skipped['unsupported_schema_rows'], 1)
        self.assertEqual(skipped['unparseable_lines'], 0,
                         'a row this build cannot read is a different problem '
                         'from a row nobody can parse')

    def test_the_two_kinds_of_skip_are_counted_apart(self):
        path = self.write([Outcome(pseudonym='src-a')])
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps({'shadow_export_schema_version': 99}) + '\n')
            stream.write('not json\n')
        rows, skipped = ev.read_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(skipped, {'unparseable_lines': 1, 'unsupported_schema_rows': 1})

    def test_several_files_read_as_one_period(self):
        first = self.write([Outcome(pseudonym='src-a')], name='a.jsonl')
        second = self.write([Outcome(pseudonym='src-b')], name='b.jsonl')
        self.assertEqual(ev.summarise([first, second])['sources'], 2)


class TestDegradedComponentsAreVisible(EvidenceCase):
    """A decision taken on a degraded system is evidence about a degraded system."""

    def test_a_degraded_component_marks_the_source(self):
        path = self.write([Outcome(pseudonym='src-a')],
                          component_health={'classifier': 'DEGRADED'})
        source = ev.sources(ev.read_rows(path)[0])['src-a']
        self.assertTrue(source.degraded)
        self.assertEqual(source.explain()['degraded_components'], ['classifier:DEGRADED'])

    def test_a_healthy_or_unconfigured_component_does_not(self):
        path = self.write([Outcome(pseudonym='src-a')],
                          component_health={'classifier': 'NOT_CONFIGURED',
                                            'calibrator': 'HEALTHY'})
        self.assertFalse(ev.sources(ev.read_rows(path)[0])['src-a'].degraded)

    def test_the_summary_counts_degraded_sources(self):
        healthy = self.write([Outcome(pseudonym='src-a')], name='healthy.jsonl')
        broken = self.write([Outcome(pseudonym='src-b')], name='broken.jsonl',
                            component_health={'calibrator': 'UNAVAILABLE'})
        self.assertEqual(ev.summarise([healthy, broken])['degraded_sources'], 1)


class TestReadingLabelsBack(EvidenceCase):
    """§15. The loop from a review pack to a number, closed."""

    def pack(self, rows, *, name='labels.jsonl'):
        path = self.directory / name
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows),
                        encoding='utf-8')
        return path

    def test_a_blinded_review_row_carries_its_label_at_the_top_level(self):
        """The shape `autonomy/review.py` hands a reviewer."""
        path = self.pack([{'source_pseudonym': 'src-a', 'label': 'BENIGN'}])
        labels, report = ev.read_labels(path)
        self.assertEqual(labels, {'src-a': ev.BENIGN})
        self.assertEqual(report['sources_labelled'], 1)

    def test_an_export_row_carries_its_label_in_the_review_block(self):
        """The other real shape, and both are read rather than one being right."""
        path = self.pack([{'shadow_export_schema_version': 2,
                           'source_pseudonym': 'src-a',
                           'review': {'label': 'MALICIOUS_AUTOMATION'}}])
        labels, _ = ev.read_labels(path)
        self.assertEqual(labels, {'src-a': ev.MALICIOUS_AUTOMATION})

    def test_ignore_wins_over_any_other_label_for_the_same_source(self):
        """It is a statement about what the source is, not about one window."""
        path = self.pack([{'source_pseudonym': 'src-a', 'label': 'BENIGN'},
                          {'source_pseudonym': 'src-a', 'label': 'IGNORE'}])
        labels, _ = ev.read_labels(path)
        self.assertEqual(labels['src-a'], ev.IGNORE)

    def test_a_disagreement_is_reported_rather_than_resolved(self):
        """Choosing either side would move the false-block rate on purpose."""
        path = self.pack([{'source_pseudonym': 'src-a', 'label': 'BENIGN'},
                          {'source_pseudonym': 'src-a', 'label': 'MALICIOUS_AUTOMATION'}])
        labels, report = ev.read_labels(path)
        self.assertNotIn('src-a', labels)
        self.assertEqual(report['conflicting_sources'], ['src-a'])

    def test_a_conflict_is_not_counted_as_an_unreviewed_source(self):
        """A review that disagreed with itself is not a review nobody did."""
        path = self.pack([{'source_pseudonym': 'src-a', 'label': 'BENIGN'},
                          {'source_pseudonym': 'src-a', 'label': 'MALICIOUS_AUTOMATION'}])
        _, report = ev.read_labels(path)
        self.assertEqual(report['rows_without_a_label'], 0)
        self.assertEqual(len(report['conflicting_sources']), 1)

    def test_a_pack_mixing_both_shapes_loses_neither(self):
        """The reason labels are read plainly rather than through `read_rows`.

        A schema check there would refuse the blinded half of this file and
        report a smaller review than the reviewer did, without failing.
        """
        path = self.pack([{'source_pseudonym': 'src-a', 'label': 'BENIGN'},
                          {'shadow_export_schema_version': 2,
                           'source_pseudonym': 'src-b',
                           'review': {'label': 'BENIGN'}}])
        labels, report = ev.read_labels(path)
        self.assertEqual(labels, {'src-a': ev.BENIGN, 'src-b': ev.BENIGN})
        self.assertEqual(report['sources_labelled'], 2)

    def test_an_unparseable_line_in_a_pack_is_counted(self):
        path = self.pack([{'source_pseudonym': 'src-a', 'label': 'BENIGN'}])
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write('{"source_pseudonym": "src-tru\n')
        labels, report = ev.read_labels(path)
        self.assertEqual(labels, {'src-a': ev.BENIGN})
        self.assertEqual(report['skipped']['unparseable_lines'], 1)

    def test_a_label_outside_the_vocabulary_is_not_guessed_at(self):
        path = self.pack([{'source_pseudonym': 'src-a', 'label': 'probably fine'}])
        labels, report = ev.read_labels(path)
        self.assertEqual(labels, {})
        self.assertEqual(report['unusable_labels'], {'PROBABLY FINE': 1})

    def test_an_unlabelled_row_produces_no_label(self):
        path = self.pack([{'source_pseudonym': 'src-a', 'label': None},
                          {'source_pseudonym': 'src-b', 'label': 'UNLABELED'}])
        labels, report = ev.read_labels(path)
        self.assertEqual(labels, {})
        self.assertEqual(report['rows_without_a_label'], 2)

    def test_the_decision_is_never_read_as_a_label(self):
        """§14. A would-block in the pack does not become MALICIOUS_AUTOMATION."""
        path = self.write([Outcome(pseudonym='src-blocked', blocked=True)])
        labels, _ = ev.read_labels(path)
        self.assertEqual(labels, {},
                         'a label was produced from a file in which no person '
                         'wrote one, which can only have come from the decision')

    def test_labels_read_back_reach_the_summary(self):
        export = self.write([Outcome(pseudonym='src-a'), Outcome(pseudonym='src-b')])
        pack = self.pack([{'source_pseudonym': 'src-a', 'label': 'BENIGN'}])
        labels, _ = ev.read_labels(pack)
        summary = ev.summarise(export, labels=labels)
        self.assertEqual(summary['label_states'][ev.BENIGN], 1)
        self.assertEqual(summary['label_states'][ev.UNLABELED], 1)


class TestTheDistributions(EvidenceCase):
    """§26, §27. What the decisions were made of, in window counts.

    Every number here is over windows. That is stated in the output because the
    rest of this module is deliberately at the source unit, and a reader who
    divided a family count by a source count would be computing nothing.
    """

    def test_the_histogram_bins_are_the_cost_cutoffs(self):
        """Even deciles would put every decision in one bin."""
        from eye_for_an_eye.autonomy.cost import PROFILES
        edges = ev.probability_edges()
        for profile in PROFILES.values():
            with self.subTest(profile=profile.name):
                self.assertIn(round(profile.threshold, 6),
                              [round(edge, 6) for edge in edges])
        self.assertEqual(edges[0], 0.0)
        self.assertEqual(edges[-1], 1.0)

    def test_a_value_falls_in_the_bin_below_the_edge_it_reaches(self):
        edges = (0.0, 0.5, 1.0)
        self.assertEqual([bin['count'] for bin in
                          ev.histogram([0.0, 0.4999, 0.5, 0.9, 1.0], edges)],
                         [2, 3])

    def test_the_top_bin_is_closed_so_a_probability_of_one_is_counted(self):
        self.assertEqual(ev.histogram([1.0], (0.0, 0.5, 1.0))[-1]['count'], 1)

    def test_a_missing_value_is_skipped_rather_than_counted_as_zero(self):
        self.assertEqual(sum(bin['count'] for bin in
                             ev.histogram([None, 'high', 0.2], (0.0, 0.5, 1.0))), 1)

    def test_the_families_of_a_would_block_are_counted(self):
        path = self.write([Outcome(pseudonym='src-a', blocked=True)])
        found = ev.distributions(ev.read_rows(path)[0])
        names = {entry['name'] for entry in found['evidence_families']}
        self.assertTrue(names, 'no family was counted for a blocked window')
        self.assertTrue(all(name.startswith('FAMILY_NUMBER_') for name in names))

    def test_an_allowed_window_contributes_no_families_or_codes(self):
        """§27 measures the would-block distribution, not every window's."""
        path = self.write([Outcome(pseudonym='src-a', blocked=False)])
        found = ev.distributions(ev.read_rows(path)[0])
        self.assertEqual(found['evidence_families'], [])
        self.assertEqual(found['reason_codes'], [])
        self.assertEqual(found['would_block_windows'], 0)

    def test_the_probability_distribution_covers_every_window(self):
        path = self.write([Outcome(pseudonym=f'src-{n}', blocked=n < 2)
                           for n in range(5)])
        found = ev.distributions(ev.read_rows(path)[0])
        self.assertEqual(sum(bin['count'] for bin in
                             found['conservative_probability']), 5)

    def test_the_unit_is_stated_in_the_output(self):
        path = self.write([Outcome(pseudonym='src-a')])
        self.assertIn('not sources', ev.distributions(ev.read_rows(path)[0])['unit'])

    def test_the_summary_carries_the_distributions(self):
        path = self.write([Outcome(pseudonym='src-a', blocked=True)])
        self.assertIn('distributions', ev.summarise(path))


class TestSuppression(EvidenceCase):
    """§26. A strong decision that no block came of, and which gate refused."""

    def suppressed(self, *, gates, assumptions=()):
        """A window whose bound cleared its threshold and was not blocked."""
        outcome = Outcome(pseudonym='src-a', blocked=False)
        outcome.record._extra = {
            'timestamp': '2026-09-19T00:00:00+00:00',
            'gates': gates,
            'assumptions': {'failed': list(assumptions), 'failed_subsystems': []},
            'cost': {'profile': 'public_website', 'policy_version': 'cost-policy-v1',
                     'policy_digest': 'd' * 64, 'threshold': 0.9,
                     'decision_margin': 0.25, 'probability': 0.99,
                     'conservative_probability': 0.95,
                     'loss_allow': 0.9, 'loss_block': 0.02}}
        return outcome

    def test_a_strong_window_that_was_not_blocked_counts_as_suppressed(self):
        path = self.write([self.suppressed(gates={'observation_count': False,
                                                  'clock_sane': True})])
        found = ev.distributions(ev.read_rows(path)[0])['suppression']
        self.assertEqual(found['suppressed_windows'], 1)
        self.assertEqual(found['failed_gates'],
                         [{'name': 'observation_count', 'windows': 1}])

    def weak(self):
        """A window the arithmetic never asked to block.

        Built explicitly, because the shared fixture's default bound is 0.9948
        against a 0.9756 cutoff -- an allowed window whose arithmetic *did*
        prefer a block, which is suppression. The first version of this test
        used it and asserted the opposite of what it had built.
        """
        outcome = Outcome(pseudonym='src-weak', blocked=False)
        outcome.record._extra = {
            'timestamp': '2026-09-19T00:00:00+00:00',
            'cost': {'profile': 'public_website', 'policy_version': 'cost-policy-v1',
                     'policy_digest': 'd' * 64, 'threshold': 0.97561,
                     'decision_margin': 0.25, 'probability': 0.2,
                     'conservative_probability': 0.05,
                     'loss_allow': 0.05, 'loss_block': 0.9}}
        return outcome

    def test_a_weak_window_that_was_not_blocked_is_not_suppression(self):
        """Nothing was refused; the arithmetic simply did not ask for a block."""
        path = self.write([self.weak()])
        self.assertEqual(
            ev.distributions(ev.read_rows(path)[0])['suppression']['suppressed_windows'],
            0)

    def test_a_blocked_window_is_not_suppression_either(self):
        path = self.write([Outcome(pseudonym='src-a', blocked=True)])
        self.assertEqual(
            ev.distributions(ev.read_rows(path)[0])['suppression']['suppressed_windows'],
            0)

    def test_one_gate_refusing_most_of_them_is_surfaced_as_a_share(self):
        """The alarm §26 asks to be watched, as a number rather than a hunch."""
        path = self.write([self.suppressed(gates={'observation_count': False,
                                                  'clock_sane': True})
                           for _ in range(9)]
                          + [self.suppressed(gates={'data_quality': False,
                                                    'clock_sane': True})])
        found = ev.distributions(ev.read_rows(path)[0])['suppression']
        self.assertEqual(found['suppressed_windows'], 10)
        self.assertEqual(found['leading_gate_share'], 0.9)
        self.assertEqual(found['failed_gates'][0]['name'], 'observation_count')

    def test_the_failed_assumptions_are_counted_too(self):
        path = self.write([self.suppressed(gates={'clock_sane': True},
                                           assumptions=['feature_schema_supported'])])
        found = ev.distributions(ev.read_rows(path)[0])['suppression']
        self.assertEqual(found['failed_assumptions'],
                         [{'name': 'feature_schema_supported', 'windows': 1}])

    def test_the_note_forbids_the_obvious_wrong_repair(self):
        path = self.write([self.suppressed(gates={'observation_count': False})])
        note = ev.distributions(ev.read_rows(path)[0])['suppression']['note']
        self.assertIn('never a reason to weaken the gate', note)

    def test_no_suppression_reports_no_share_rather_than_zero(self):
        """A share over nothing is absent, not 0.0."""
        path = self.write([self.weak()])
        self.assertIsNone(
            ev.distributions(ev.read_rows(path)[0])['suppression']['leading_gate_share'])


class TestReadingAWholeRotatedPeriod(EvidenceCase):
    """The export is a ring, and reading the live file reads a quarter of it.

    `autonomy/bounded_jsonl.py` keeps four files by default and deletes the
    oldest. A reader that opens only `export.jsonl` gets the newest file, counts
    fewer sources than were collected, and nothing about the result looks wrong.
    """

    def rotated(self, index, sources):
        path = self.write([Outcome(pseudonym=key) for key in sources],
                          name=f'export.jsonl.{index}' if index else 'export.jsonl')
        return path

    def test_the_rotations_are_read_oldest_first(self):
        self.rotated(0, ['src-newest'])
        self.rotated(1, ['src-middle'])
        self.rotated(2, ['src-oldest'])
        files = ev.period_files(self.directory / 'export.jsonl')
        self.assertEqual([path.name for path in files],
                         ['export.jsonl.2', 'export.jsonl.1', 'export.jsonl'])

    def test_the_whole_period_is_counted_not_the_last_file(self):
        self.rotated(0, ['src-a'])
        self.rotated(1, ['src-b'])
        self.rotated(2, ['src-c'])
        whole = ev.summarise(ev.period_files(self.directory / 'export.jsonl'))
        live = ev.summarise(self.directory / 'export.jsonl')
        self.assertEqual(whole['sources'], 3)
        self.assertEqual(live['sources'], 1,
                         'the live file alone is the newest part of the window, '
                         'which is the reading this helper exists to replace')

    def test_a_file_that_merely_looks_like_a_rotation_is_not_read(self):
        self.rotated(0, ['src-a'])
        (self.directory / 'export.jsonl.backup').write_text('{}\n', encoding='utf-8')
        files = ev.period_files(self.directory / 'export.jsonl')
        self.assertEqual([path.name for path in files], ['export.jsonl'])

    def test_a_path_that_is_not_there_yields_nothing(self):
        self.assertEqual(ev.period_files(self.directory / 'absent.jsonl'), [])


class TestRetention(EvidenceCase):
    """Did the window lose its own beginning? The count would not say so."""

    def summary(self, first_bucket):
        return {'time_coverage': {'first_bucket': first_bucket}}

    def test_a_window_whose_oldest_row_is_later_than_its_start_is_incomplete(self):
        answer = ev.retention(self.summary('2026-09-19T06:00:00+00:00'),
                              started_at=ev._epoch('2026-09-19T00:00:00+00:00'))
        self.assertFalse(answer['complete'])
        self.assertAlmostEqual(answer['seconds_missing_at_the_start'], 6 * 3600)

    def test_a_window_that_starts_where_it_says_is_complete(self):
        answer = ev.retention(self.summary('2026-09-19T00:00:00+00:00'),
                              started_at=ev._epoch('2026-09-19T00:00:00+00:00'))
        self.assertTrue(answer['complete'])

    def test_the_hour_bucket_does_not_count_as_a_gap(self):
        """A window beginning mid-hour would otherwise always look truncated."""
        answer = ev.retention(self.summary('2026-09-19T00:00:00+00:00'),
                              started_at=ev._epoch('2026-09-18T23:20:00+00:00'))
        self.assertTrue(answer['complete'])

    def test_the_writers_own_deletion_counter_is_believed(self):
        answer = ev.retention(self.summary(None),
                              counters={'retention_deleted': 2})
        self.assertFalse(answer['complete'])
        self.assertTrue(any('retention ceiling' in reason
                            for reason in answer['reasons']))

    def test_rows_that_failed_to_write_are_a_gap_too(self):
        """§25 backpressure drops the export first, and it is evidence lost."""
        answer = ev.retention(self.summary(None), counters={'failed': 17})
        self.assertFalse(answer['complete'])
        self.assertTrue(any('17 rows failed to write' in reason
                            for reason in answer['reasons']))

    def test_no_start_and_no_counters_claims_nothing(self):
        """Absence of a signal is not evidence of completeness, but it is not a
        finding either; it reports complete and says what it checked."""
        answer = ev.retention(self.summary('2026-09-19T00:00:00+00:00'))
        self.assertTrue(answer['complete'])
        self.assertIsNone(answer['seconds_missing_at_the_start'])

    def test_a_freeze_carries_the_answer(self):
        path = self.write([Outcome(pseudonym='src-a',
                                   timestamp='2026-09-19T06:00:00+00:00')])
        document = ev.freeze(export_paths=[path],
                             started_at=ev._epoch('2026-09-19T00:00:00+00:00'))
        self.assertFalse(document['retention']['complete'])

    def test_a_freeze_records_the_writers_counters(self):
        path = self.write([Outcome(pseudonym='src-a')])
        document = ev.freeze(export_paths=[path],
                             counters={'written': 1, 'failed': 0,
                                       'retention_deleted': 0})
        self.assertEqual(document['writer_counters']['written'], 1)
        self.assertTrue(document['retention']['complete'])


class TestTheManifest(EvidenceCase):
    """§45. What the numbers were computed from, so a reader can check."""

    def test_it_hashes_every_file_it_names(self):
        path = self.write([Outcome(pseudonym='src-a')])
        document = ev.manifest(export_paths=[path])
        entry, = document['files']
        self.assertEqual(entry['role'], 'shadow_export')
        self.assertEqual(entry['bytes'], path.stat().st_size)
        self.assertEqual(len(entry['sha256']), 64)

    def test_it_records_the_build_and_the_configuration(self):
        path = self.write([Outcome(pseudonym='src-a')])
        document = ev.manifest(export_paths=[path], runtime_version='1.2.3',
                               git_commit='4c0d6b9', config_digest='abc123',
                               segment_id='seg-1')
        self.assertEqual(document['runtime_version'], '1.2.3')
        self.assertEqual(document['git_commit'], '4c0d6b9')
        self.assertEqual(document['config_digest'], 'abc123')
        self.assertEqual(document['segment_id'], 'seg-1')

    def test_the_profile_mapping_is_hashed_as_well_as_recorded(self):
        """Which site was treated as which cost profile is part of the result."""
        path = self.write([Outcome(pseudonym='src-a')])
        mapping = {'site-a': 'public_website', 'site-b': 'api'}
        first = ev.manifest(export_paths=[path], profile_mapping=mapping)
        second = ev.manifest(export_paths=[path],
                             profile_mapping={'site-b': 'api', 'site-a': 'public_website'})
        self.assertEqual(first['profile_mapping_sha256'],
                         second['profile_mapping_sha256'],
                         'the digest depends on the order the mapping was written in')
        changed = ev.manifest(export_paths=[path],
                              profile_mapping={'site-a': 'honeypot'})
        self.assertNotEqual(first['profile_mapping_sha256'],
                            changed['profile_mapping_sha256'])

    def test_a_journal_is_named_by_its_role(self):
        export = self.write([Outcome(pseudonym='src-a')], name='export.jsonl')
        journal = self.directory / 'journal.jsonl'
        journal.write_text('{}\n', encoding='utf-8')
        roles = {entry['role'] for entry in
                 ev.manifest(export_paths=[export], journal_paths=[journal])['files']}
        self.assertEqual(roles, {'shadow_export', 'decision_journal'})

    def test_a_file_that_is_not_there_is_not_hashed_into_existence(self):
        document = ev.manifest(export_paths=[self.directory / 'absent.jsonl'])
        self.assertEqual(document['files'], [])


class TestFreezingAndVerifying(EvidenceCase):
    """§47, §51. A frozen dataset that quietly grew is not a frozen dataset."""

    def frozen(self, **kwargs):
        path = self.write([Outcome(pseudonym=f'src-{n}') for n in range(4)])
        return path, ev.freeze(export_paths=[path], **kwargs)

    def test_a_freeze_carries_the_counts_it_was_taken_at(self):
        _, document = self.frozen()
        self.assertTrue(document['frozen'])
        self.assertEqual(document['summary']['sources'], 4)

    def test_an_untouched_dataset_verifies(self):
        _, document = self.frozen()
        self.assertEqual(ev.verify(document)['status'], 'MATCH')

    def test_an_appended_file_does_not_verify(self):
        path, document = self.frozen()
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps({'shadow_export_schema_version': 2,
                                     'source_pseudonym': 'src-late'}) + '\n')
        result = ev.verify(document)
        self.assertEqual(result['status'], 'CHANGED')
        self.assertEqual(result['files'][0]['status'], 'CHANGED')

    def test_a_missing_file_says_missing_rather_than_changed(self):
        path, document = self.frozen()
        path.unlink()
        self.assertEqual(ev.verify(document)['files'][0]['status'], 'MISSING')

    def test_a_manifest_naming_nothing_verifies_as_empty(self):
        """Not MATCH. Nothing matched, because nothing was checked."""
        self.assertEqual(ev.verify({'files': []})['status'], 'EMPTY')

    def test_evidence_moved_to_another_machine_still_verifies(self):
        """The join that silently does nothing.

        A manifest records absolute paths, and `Path('/evidence') /
        '/var/lib/e4e/export.jsonl'` is the second path: the root is discarded
        without a word. Before this was fixed, an operator who copied the
        evidence somewhere to analyse it was told it had CHANGED.
        """
        path, document = self.frozen()
        elsewhere = self.directory / 'elsewhere'
        elsewhere.mkdir()
        path.replace(elsewhere / path.name)
        self.assertEqual(ev.verify(document)['status'], 'MISSING')
        self.assertEqual(ev.verify(document, root=elsewhere)['status'], 'MATCH')

    def test_rebasing_an_absolute_path_uses_the_root(self):
        self.assertEqual(ev.rebase('/var/lib/e4e/export.jsonl', '/evidence'),
                         Path('/evidence/export.jsonl'))

    def test_rebasing_a_relative_path_keeps_its_shape(self):
        self.assertEqual(ev.rebase('period/export.jsonl', '/evidence'),
                         Path('/evidence/period/export.jsonl'))

    def test_no_root_leaves_the_path_alone(self):
        self.assertEqual(ev.rebase('/var/lib/e4e/export.jsonl', None),
                         Path('/var/lib/e4e/export.jsonl'))

    def test_the_note_says_an_append_invalidates_rather_than_extends(self):
        _, document = self.frozen()
        self.assertIn('invalidates the result rather than extending it',
                      document['note'])


class TestTheLabelVocabularyIsShared(unittest.TestCase):
    """One spelling of BENIGN. A second would halve a dataset silently."""

    def test_the_labels_are_the_evaluation_module_s_own(self):
        from eye_for_an_eye.autonomy import evaluation
        self.assertIs(ev.BENIGN, evaluation.BENIGN)
        self.assertIs(ev.MALICIOUS_AUTOMATION, evaluation.MALICIOUS_AUTOMATION)
        self.assertIs(ev.UNLABELED, evaluation.UNLABELED)

    def test_ignore_is_the_only_state_this_module_adds(self):
        from eye_for_an_eye.autonomy import evaluation
        self.assertEqual(set(ev.LABELS) - set(evaluation.LABELS), {ev.IGNORE})

    def test_conflict_is_not_a_label(self):
        """It is a description of a review, and must not reach a rate."""
        self.assertNotIn(ev.CONFLICT, ev.LABELS)


if __name__ == '__main__':
    unittest.main()
