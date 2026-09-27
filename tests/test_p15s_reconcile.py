"""The journal and the export, checked against each other. P15S §41, §42, §43.

Both files are written from one `PipelineOutcome`, in one call, by one bounded
writer. They cannot disagree -- which is the reason to check, because that
sentence was equally true of every component P15.5 found had been disagreeing
for four phases.

So the central test here writes the *same* outcome through the *real*
`DecisionJournal` and the *real* `ShadowExport` and reconciles the two files. A
test that compared two hand-built dictionaries would assert the shape of the
fixture, which is the failure mode this whole cycle exists to catch.
"""
import json
from pathlib import Path
import tempfile
import unittest

from eye_for_an_eye.autonomy import shadow_reconcile as rc
from eye_for_an_eye.autonomy.journal import DecisionJournal
from eye_for_an_eye.autonomy.pipeline import PipelineOutcome
from eye_for_an_eye.autonomy.shadow_export import (
    EXPORT_REASON_CODE_LIMIT, ShadowExport)

from tests.test_p15_5r_journal import FakeRecord, FakeResolution


class ReconcileCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)
        self.journal_path = self.directory / 'journal.jsonl'
        self.export_path = self.directory / 'export.jsonl'

    #: Deliberately not on the hour. The fixture's own timestamp is midnight
    #: exactly, where bucketing is the identity -- so a reconciliation that
    #: compared a raw timestamp against a bucket would pass every test in this
    #: file. The first version of the bucketing test did exactly that and
    #: asserted nothing.
    TIMESTAMP = '2026-09-19T13:47:31+00:00'

    def outcome(self, *, decision_id, blocked=False, pseudonym=None,
                timestamp=TIMESTAMP):
        """A real `PipelineOutcome`, as `decide()` builds one in shadow."""
        record = FakeRecord(blocked=blocked)
        record.decision_id = decision_id
        if pseudonym:
            record.source_pseudonym = pseudonym
        record._extra = {'decision_id': decision_id,
                         'source_pseudonym': record.source_pseudonym,
                         'timestamp': timestamp}
        return PipelineOutcome(record=record, resolution=FakeResolution(),
                               calibrated=True)

    def write(self, outcomes):
        """One outcome through both writers, as the pipeline does."""
        journal = DecisionJournal(self.journal_path)
        export = ShadowExport(self.export_path)
        try:
            for outcome in outcomes:
                self.assertTrue(journal.write(outcome), 'the journal fixture failed')
                self.assertTrue(export.write(outcome), 'the export fixture failed')
        finally:
            journal.close()
            export.close()

    def lines(self, path):
        return [json.loads(line) for line in
                path.read_text(encoding='utf-8').splitlines() if line.strip()]

    def rewrite(self, path, rows):
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows),
                        encoding='utf-8')

    def reconcile(self, **kwargs):
        return rc.reconcile(self.journal_path, self.export_path, **kwargs)


class TestTheTwoFilesAgree(ReconcileCase):
    """The test that matters. Real writers, one outcome, both files."""

    def test_the_same_decisions_written_both_ways_reconcile(self):
        self.write([self.outcome(decision_id=f'dec-{n:016x}',
                                 pseudonym=f'src-{n}', blocked=n < 3)
                    for n in range(10)])
        answer = self.reconcile()
        self.assertEqual(answer['status'], rc.AGREE, answer['problems'])
        self.assertEqual(answer['disagreements'], [])
        self.assertEqual(answer['counts']['joined'], 10)

    def test_the_would_block_counts_agree(self):
        self.write([self.outcome(decision_id=f'dec-{n:016x}', blocked=n < 4)
                    for n in range(10)])
        counts = self.reconcile()['counts']
        self.assertEqual(counts['journal_would_block'], 4)
        self.assertEqual(counts['export_would_block'], 4)

    def test_shadow_took_no_actual_block(self):
        """§3's invariant, read off the evidence rather than the code."""
        self.write([self.outcome(decision_id=f'dec-{n:016x}', blocked=True)
                    for n in range(5)])
        counts = self.reconcile()['counts']
        self.assertEqual(counts['export_would_block'], 5)
        self.assertEqual(counts['export_actual_block'], 0)

    def test_the_shorter_reason_code_list_is_the_bound_not_a_disagreement(self):
        """The export keeps 16 of this record's 24, and that is correct."""
        self.write([self.outcome(decision_id='dec-a', blocked=True)])
        journal_codes = self.lines(self.journal_path)[0]['entry']['decision']['reason_codes']
        export_codes = self.lines(self.export_path)[0]['reason_codes']
        self.assertEqual(len(journal_codes), 24)
        self.assertEqual(len(export_codes), EXPORT_REASON_CODE_LIMIT)
        self.assertEqual(self.reconcile()['status'], rc.AGREE)

    def test_the_hour_bucket_is_applied_before_comparing_the_time(self):
        """The export coarsens; comparing a bucket to a timestamp would fail all."""
        self.write([self.outcome(decision_id='dec-a')])
        row = self.lines(self.export_path)[0]
        entry = self.lines(self.journal_path)[0]['entry']
        self.assertNotEqual(entry['decision']['timestamp'], row['timestamp_bucket'])
        self.assertEqual(self.reconcile()['status'], rc.AGREE)


class TestADisagreementIsReportedAndNotRepaired(ReconcileCase):
    def setUp(self):
        super().setUp()
        self.write([self.outcome(decision_id=f'dec-{n}', blocked=n < 2)
                    for n in range(5)])

    def test_a_changed_profile_is_caught_and_named(self):
        rows = self.lines(self.export_path)
        rows[0]['profile_type'] = 'api'
        self.rewrite(self.export_path, rows)
        answer = self.reconcile()
        self.assertEqual(answer['status'], rc.DISAGREE)
        difference, = answer['disagreements']
        self.assertEqual(difference['differences']['cost_profile'],
                         {'journal': 'public_website', 'export': 'api'})

    def test_a_changed_action_is_caught(self):
        rows = self.lines(self.export_path)
        rows[4]['would_action'] = 'TEMP_BLOCK'
        self.rewrite(self.export_path, rows)
        answer = self.reconcile()
        self.assertEqual(answer['status'], rc.DISAGREE)
        self.assertTrue(any('would-block counts differ' in problem
                            for problem in answer['problems']))

    def test_a_changed_bound_is_caught_despite_the_float_tolerance(self):
        rows = self.lines(self.export_path)
        rows[0]['conservative_probability'] = 0.5
        self.rewrite(self.export_path, rows)
        self.assertIn('conservative_probability',
                      self.reconcile()['disagreements'][0]['differences'])

    def test_a_bound_differing_in_the_sixteenth_decimal_is_not_a_disagreement(self):
        rows = self.lines(self.export_path)
        rows[0]['conservative_probability'] += 1e-15
        self.rewrite(self.export_path, rows)
        self.assertEqual(self.reconcile()['status'], rc.AGREE)

    def test_a_reordered_reason_code_list_is_a_disagreement(self):
        """Prefix comparison, not set comparison: order is part of the record."""
        rows = self.lines(self.export_path)
        rows[0]['reason_codes'] = list(reversed(rows[0]['reason_codes']))
        self.rewrite(self.export_path, rows)
        self.assertIn('reason_codes',
                      self.reconcile()['disagreements'][0]['differences'])

    def test_a_truncated_reason_code_list_is_a_disagreement(self):
        """Shorter than the bound, with more available, is not the bound."""
        rows = self.lines(self.export_path)
        rows[0]['reason_codes'] = rows[0]['reason_codes'][:3]
        self.rewrite(self.export_path, rows)
        self.assertIn('reason_codes',
                      self.reconcile()['disagreements'][0]['differences'])

    def test_nothing_is_repaired(self):
        """Choosing a winner would destroy the only signal that anything is wrong."""
        rows = self.lines(self.export_path)
        rows[0]['profile_type'] = 'api'
        self.rewrite(self.export_path, rows)
        self.reconcile()
        self.assertEqual(self.lines(self.export_path)[0]['profile_type'], 'api')
        self.assertIn('reports and does not repair', rc.__doc__)


class TestDecisionsMissingFromOneSide(ReconcileCase):
    def setUp(self):
        super().setUp()
        self.write([self.outcome(decision_id=f'dec-{n}') for n in range(6)])

    def test_an_export_that_dropped_rows_is_counted(self):
        """The failure that matters most to a window: silent loss."""
        rows = self.lines(self.export_path)
        self.rewrite(self.export_path, rows[:4])
        answer = self.reconcile()
        self.assertEqual(answer['status'], rc.DISAGREE)
        self.assertEqual(answer['counts']['journal_only'], 2)
        self.assertTrue(any('dropped them' in problem
                            for problem in answer['problems']))

    def test_a_decision_only_in_the_export_says_it_should_be_unreachable(self):
        rows = self.lines(self.journal_path)
        self.rewrite(self.journal_path, rows[:4])
        answer = self.reconcile()
        self.assertEqual(answer['counts']['export_only'], 2)
        self.assertTrue(any('should not be reachable' in problem
                            for problem in answer['problems']))

    def test_the_missing_ids_are_named_so_they_can_be_looked_up(self):
        rows = self.lines(self.export_path)
        self.rewrite(self.export_path, rows[:4])
        self.assertEqual(self.reconcile()['journal_only_ids'], ['dec-4', 'dec-5'])


class TestTheAmendedEntry(ReconcileCase):
    """One decision, two journal entries. Structural, not a duplicate."""

    def test_the_second_entry_is_an_amendment_and_not_a_second_decision(self):
        outcome = self.outcome(decision_id='dec-a', blocked=True)
        journal = DecisionJournal(self.journal_path)
        export = ShadowExport(self.export_path)
        try:
            journal.write(outcome)          # before the enforcement attempt
            journal.write(outcome)          # the amendment carrying the result
            export.write(outcome)
        finally:
            journal.close()
            export.close()
        answer = self.reconcile()
        self.assertEqual(answer['counts']['journal_lines'], 2)
        self.assertEqual(answer['counts']['journal_decisions'], 1)
        self.assertEqual(answer['counts']['journal_amendments'], 1)
        self.assertEqual(answer['status'], rc.AGREE,
                         'an amended block was reported as an inconsistency')

    def test_the_later_entry_is_the_one_compared(self):
        """The amendment carries what happened; the first entry does not."""
        entries = [
            {'journal_schema_version': 1, 'entry': {
                'decision': {'decision_id': 'dec-a'}, 'actual_action': 'NONE'}},
            {'journal_schema_version': 1, 'entry': {
                'decision': {'decision_id': 'dec-a'}, 'actual_action': 'TEMP_BLOCK'}},
        ]
        found, amendments = rc.journal_decisions(entries)
        self.assertEqual(found['dec-a']['actual_action'], 'TEMP_BLOCK')
        self.assertEqual(amendments['dec-a'], 1)


class TestReadingWhatIsThere(ReconcileCase):
    def test_a_journal_line_from_an_unreadable_schema_is_skipped_and_counted(self):
        self.write([self.outcome(decision_id='dec-a')])
        with open(self.journal_path, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps({'journal_schema_version': 99,
                                     'entry': {'decision':
                                               {'decision_id': 'dec-b'}}}) + '\n')
        answer = self.reconcile()
        self.assertEqual(answer['skipped']['journal']['unsupported_schema_rows'], 1)
        self.assertEqual(answer['counts']['journal_decisions'], 1)

    def test_a_truncated_line_is_skipped_and_counted(self):
        self.write([self.outcome(decision_id='dec-a')])
        with open(self.journal_path, 'a', encoding='utf-8') as stream:
            stream.write('{"journal_schema_version": 1, "entry')
        self.assertEqual(
            self.reconcile()['skipped']['journal']['unparseable_lines'], 1)

    def test_two_empty_files_reconcile_as_empty_rather_than_agreeing(self):
        """Nothing agreed, because nothing was compared."""
        self.journal_path.write_text('', encoding='utf-8')
        self.export_path.write_text('', encoding='utf-8')
        self.assertEqual(self.reconcile()['status'], rc.EMPTY)


class TestSampling(ReconcileCase):
    """A periodic check during a long window, which must say it was one."""

    def setUp(self):
        super().setUp()
        self.write([self.outcome(decision_id=f'dec-{n:04d}') for n in range(50)])

    def test_a_sample_examines_only_part_and_says_so(self):
        answer = self.reconcile(sample=10)
        self.assertEqual(answer['counts']['examined'], 10)
        self.assertEqual(answer['counts']['joined'], 50)
        self.assertTrue(answer['counts']['sampled'])

    def test_a_sample_larger_than_the_window_is_not_a_sample(self):
        self.assertFalse(self.reconcile(sample=500)['counts']['sampled'])

    def test_no_sample_examines_everything(self):
        answer = self.reconcile()
        self.assertEqual(answer['counts']['examined'], 50)
        self.assertFalse(answer['counts']['sampled'])


class TestTheKnownDifferencesAreStated(ReconcileCase):
    def test_each_structural_difference_is_written_down(self):
        self.write([self.outcome(decision_id='dec-a')])
        stated = ' '.join(self.reconcile()['known_differences'])
        self.assertIn('two journal entries', stated)
        self.assertIn('reason codes', stated)
        self.assertIn('coarsens its timestamp', stated)

    def test_the_operational_log_is_named_as_not_evidence(self):
        """§43, in the output rather than only in a docstring."""
        self.write([self.outcome(decision_id='dec-a')])
        stated = ' '.join(self.reconcile()['known_differences'])
        self.assertIn('operational log is not read here', stated)


if __name__ == '__main__':
    unittest.main()
