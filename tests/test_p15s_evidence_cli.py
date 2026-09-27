"""The three commands an operator runs during a shadow window. P15S §50, §51, §52.

The arithmetic is tested in `test_p15s_shadow_evidence.py` and
`test_p15s_shadow_result.py`. What is checked here is the part that only exists
at the command line and can therefore only be wrong there:

* `evidence` prints no rate, however tempting one would be;
* `freeze` writes down what the result will be checked against;
* `result` refuses a file that is not a freeze, re-hashes what the freeze named,
  and leaves a non-zero exit status behind anything that is not a PASS.

That last one matters more than it looks. A command that prints
INSUFFICIENT_EVIDENCE and exits zero is a command a deployment script walks
straight past.
"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from eye_for_an_eye.autonomy import shadow_evidence as ev
from eye_for_an_eye.autonomy.shadow_export import ShadowExport
from eye_for_an_eye.autonomy_cli import autonomy_command

from tests.test_p15s_shadow_evidence import Outcome


class CommandCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)
        self.export = self.directory / 'export.jsonl'
        writer = ShadowExport(self.export, segment_id='seg-1')
        try:
            for n in range(20):
                writer.write(Outcome(pseudonym=f'src-{n}', blocked=n < 4,
                                     timestamp=f'2026-09-19T{n % 6:02d}:00:00+00:00'))
        finally:
            writer.close()
        self.labels = self.directory / 'labels.jsonl'
        self.labels.write_text(
            ''.join(json.dumps({'source_pseudonym': f'src-{n}',
                                'label': 'MALICIOUS_AUTOMATION' if n < 4 else 'BENIGN'})
                    + '\n' for n in range(20)), encoding='utf-8')

    def run_command(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = autonomy_command(argv)
        return status, out.getvalue(), err.getvalue()

    def document(self, argv):
        status, out, _err = self.run_command(argv + ['--json'])
        return status, json.loads(out)


class TestEvidence(CommandCase):
    def test_it_reports_the_period(self):
        status, document = self.document(['evidence', str(self.export)])
        self.assertEqual(status, 0)
        self.assertEqual(document['sources'], 20)
        self.assertEqual(document['rows_read'], 20)

    def test_it_prints_no_rate(self):
        """§50. A rate over a growing window invites somebody to stop at a
        number they like, and the printed text is where that temptation lands."""
        _status, out, _err = self.run_command(['evidence', str(self.export)])
        self.assertNotIn('per 1000', out)
        self.assertIn('No rate is printed here on purpose', out)

    def test_it_reads_the_whole_rotated_period(self):
        rotated = self.directory / 'export.jsonl.1'
        writer = ShadowExport(rotated)
        try:
            writer.write(Outcome(pseudonym='src-older'))
        finally:
            writer.close()
        _status, document = self.document(['evidence', str(self.export)])
        self.assertEqual(document['sources'], 21)
        self.assertEqual([Path(name).name for name in document['files']],
                         ['export.jsonl.1', 'export.jsonl'])

    def test_labels_are_applied_when_given(self):
        _status, document = self.document(['evidence', str(self.export),
                                           '--labels', str(self.labels)])
        self.assertEqual(document['label_states'][ev.BENIGN], 16)
        self.assertEqual(document['label_states'][ev.MALICIOUS_AUTOMATION], 4)

    def test_without_labels_nothing_is_reviewed(self):
        _status, document = self.document(['evidence', str(self.export)])
        self.assertEqual(document['label_states'][ev.UNLABELED], 20)
        self.assertEqual(document['review']['sources_labelled'], 0)

    def test_the_suppression_alarm_is_printed_when_there_is_one(self):
        """§26. A number an operator watches, not one they have to go looking for."""
        _status, out, _err = self.run_command(['evidence', str(self.export)])
        self.assertIn('Suppressed:', out)
        self.assertIn('never a reason to weaken the gate', out)

    def test_the_histogram_bins_are_explained_where_they_are_printed(self):
        _status, out, _err = self.run_command(['evidence', str(self.export)])
        self.assertIn('the bin edges are the cost profile cutoffs', out)

    def test_a_missing_export_is_an_error_not_an_empty_period(self):
        status, _out, err = self.run_command(['evidence',
                                              str(self.directory / 'nope.jsonl')])
        self.assertNotEqual(status, 0)
        self.assertIn('no export file of that name', err)


class TestFreeze(CommandCase):
    def test_it_hashes_what_the_result_will_be_checked_against(self):
        _status, document = self.document(['freeze', str(self.export)])
        self.assertTrue(document['frozen'])
        entry, = document['files']
        self.assertEqual(entry['sha256'], ev._digest(self.export))

    def test_it_records_the_build_and_the_segment(self):
        _status, document = self.document(['freeze', str(self.export),
                                           '--segment', 'seg-1',
                                           '--commit', '4c0d6b9',
                                           '--runtime-version', '15.5'])
        self.assertEqual(document['segment_id'], 'seg-1')
        self.assertEqual(document['git_commit'], '4c0d6b9')
        self.assertEqual(document['runtime_version'], '15.5')

    def test_it_names_a_journal_given_one(self):
        journal = self.directory / 'journal.jsonl'
        journal.write_text('{}\n', encoding='utf-8')
        _status, document = self.document(['freeze', str(self.export),
                                           '--journal', str(journal)])
        self.assertEqual({entry['role'] for entry in document['files']},
                         {'shadow_export', 'decision_journal'})

    def test_a_window_that_lost_its_start_says_so(self):
        _status, document = self.document(
            ['freeze', str(self.export),
             '--started-at', str(ev._epoch('2026-09-18T00:00:00+00:00'))])
        self.assertFalse(document['retention']['complete'])

    def test_the_printed_freeze_states_an_incomplete_window_before_the_counts(self):
        """An operator who reads the source count first has already believed it."""
        _status, out, _err = self.run_command(
            ['freeze', str(self.export),
             '--started-at', str(ev._epoch('2026-09-18T00:00:00+00:00'))])
        self.assertIn('EVIDENCE IS INCOMPLETE', out)


class TestResult(CommandCase):
    def freeze(self, **kwargs):
        from eye_for_an_eye.autonomy_cli import freeze_document
        document = freeze_document(str(self.export), **kwargs)
        path = self.directory / 'freeze.json'
        path.write_text(json.dumps(document), encoding='utf-8')
        return path

    def test_it_computes_from_the_frozen_files(self):
        path = self.freeze()
        status, document = self.document(['result', str(path),
                                          '--labels', str(self.labels)])
        self.assertEqual(document['evidence']['status'], 'MATCH')
        self.assertEqual(document['overall']['false_would_blocks']['benign_sources'], 16)
        self.assertNotEqual(status, 0, 'a 20-source window is not a PASS')

    def test_a_short_window_is_insufficient_rather_than_failed(self):
        path = self.freeze()
        _status, document = self.document(['result', str(path),
                                           '--labels', str(self.labels)])
        self.assertEqual(document['verdict']['verdict'], 'INSUFFICIENT_EVIDENCE')

    def test_anything_that_is_not_a_pass_leaves_a_non_zero_status(self):
        """The property a deployment script actually reads."""
        path = self.freeze()
        status, _out, _err = self.run_command(['result', str(path),
                                               '--labels', str(self.labels)])
        self.assertEqual(status, 1)

    def test_evidence_appended_after_the_freeze_fails_the_window(self):
        """§47. The reason the hashes are in the manifest at all."""
        path = self.freeze()
        with open(self.export, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps({'shadow_export_schema_version': 2,
                                     'source_pseudonym': 'src-late'}) + '\n')
        _status, document = self.document(['result', str(path),
                                           '--labels', str(self.labels)])
        self.assertEqual(document['evidence']['status'], 'CHANGED')
        self.assertEqual(document['verdict']['verdict'], 'FAIL')
        self.assertTrue(any('does not verify' in reason
                            for reason in document['verdict']['failing_checks']))

    def test_evidence_that_is_gone_produces_no_numbers_at_all(self):
        """Counting what is left would answer a question about another period."""
        path = self.freeze()
        self.export.unlink()
        _status, document = self.document(['result', str(path),
                                           '--labels', str(self.labels)])
        self.assertEqual(document['verdict']['verdict'], 'FAIL')
        self.assertNotIn('overall', document)

    def test_an_export_is_not_a_freeze_manifest(self):
        """The mistake this refusal exists for: running a result on live files."""
        status, _out, err = self.run_command(['result', str(self.export),
                                              '--labels', str(self.labels)])
        self.assertNotEqual(status, 0)
        self.assertIn('not a freeze manifest', err)

    def test_a_relocated_period_is_read_from_the_root_given(self):
        """Evidence is analysed somewhere other than where it was written."""
        path = self.freeze()
        moved = self.directory / 'moved'
        moved.mkdir()
        self.export.replace(moved / self.export.name)
        _status, document = self.document(['result', str(path),
                                           '--labels', str(self.labels),
                                           '--root', str(moved)])
        self.assertEqual(document['evidence']['status'], 'MATCH')

    def test_the_verdict_note_travels_with_the_numbers(self):
        """§62, at the place somebody reads the result."""
        path = self.freeze()
        _status, out, _err = self.run_command(['result', str(path),
                                               '--labels', str(self.labels)])
        self.assertIn('does not authorise enabling autonomous blocking', out)


class TestCrosscheck(CommandCase):
    """§41, §42 at the command line. The arithmetic is tested in
    `test_p15s_reconcile.py`; what is checked here is that the command reaches
    it, reads whole rotated sets, and leaves a status a script can read."""

    def setUp(self):
        super().setUp()
        from eye_for_an_eye.autonomy.journal import DecisionJournal
        from eye_for_an_eye.autonomy.pipeline import PipelineOutcome
        from tests.test_p15_5r_journal import FakeRecord, FakeResolution
        self.journal = self.directory / 'journal.jsonl'
        self.export2 = self.directory / 'paired.jsonl'
        journal = DecisionJournal(self.journal)
        export = ShadowExport(self.export2)
        try:
            for n in range(8):
                record = FakeRecord(blocked=n < 2)
                record.decision_id = f'dec-{n}'
                record._extra = {'decision_id': f'dec-{n}',
                                 'timestamp': '2026-09-19T13:47:31+00:00'}
                outcome = PipelineOutcome(record=record,
                                          resolution=FakeResolution(),
                                          calibrated=True)
                journal.write(outcome)
                export.write(outcome)
        finally:
            journal.close()
            export.close()

    def test_matching_files_agree_and_exit_zero(self):
        status, document = self.document(['crosscheck', str(self.journal),
                                          '--export', str(self.export2)])
        self.assertEqual(document['status'], 'AGREE', document['problems'])
        self.assertEqual(status, 0)

    def test_a_dropped_export_row_disagrees_and_exits_non_zero(self):
        rows = [json.loads(line) for line in
                self.export2.read_text(encoding='utf-8').splitlines() if line.strip()]
        self.export2.write_text(''.join(json.dumps(row) + '\n' for row in rows[:5]),
                                encoding='utf-8')
        status, document = self.document(['crosscheck', str(self.journal),
                                          '--export', str(self.export2)])
        self.assertEqual(document['status'], 'DISAGREE')
        self.assertEqual(document['counts']['journal_only'], 3)
        self.assertEqual(status, 1)

    def test_it_needs_both_files(self):
        status, _out, err = self.run_command(['crosscheck', str(self.journal)])
        self.assertNotEqual(status, 0)
        self.assertIn('--export', err)

    def test_a_sample_is_reported_as_one(self):
        _status, document = self.document(['crosscheck', str(self.journal),
                                           '--export', str(self.export2),
                                           '--sample', '3'])
        self.assertTrue(document['counts']['sampled'])
        self.assertEqual(document['counts']['examined'], 3)

    def test_the_printed_output_names_the_actual_host_blocks(self):
        """§3's invariant is what a reader of this command is checking."""
        _status, out, _err = self.run_command(['crosscheck', str(self.journal),
                                               '--export', str(self.export2)])
        self.assertIn('actual host blocks: 0', out)


class TestTheCommandsAreDocumented(unittest.TestCase):
    def test_each_one_appears_in_the_module_header(self):
        from eye_for_an_eye import autonomy_cli
        for action in ('evidence', 'freeze', 'result', 'crosscheck'):
            with self.subTest(action=action):
                self.assertIn(f'eye-for-an-eye autonomy {action}',
                              autonomy_cli.__doc__)


if __name__ == '__main__':
    unittest.main()
