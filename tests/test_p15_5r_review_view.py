"""The reviewer must not be shown the answer first. P15.5R §9, §31-§39.

`docs/SHADOW_VALIDATION_PLAN.md` rests on one source of ground truth that scales
to real traffic: a person reading the evidence and writing a label. Everything
the plan computes -- the false-block rate, the block precision, the intervals --
is only as independent as that label is.

A reviewer shown `would_action = TEMP_BLOCK` before deciding produces a label
that is partly the system's decision. The resulting rate is biased towards
agreeing with the system, which is the one direction that matters, and the bias
is invisible in the result. §9 forbids deriving a label from a decision; a label
taken from a primed reviewer is the same thing with a person in the middle.

So these tests are about absence. Most of them assert that something is *not*
in the view, which is a weak shape for a test in general and the right one here,
because the failure being prevented is a field arriving where nobody looked.
"""
import json
from pathlib import Path
import tempfile
import unittest

from eye_for_an_eye.autonomy.review import (
    KEEP, KEEP_FEATURES, LABELS, REVIEW_VIEW_VERSION, WITHHELD,
    blinded, project, read_export, review_document)
from eye_for_an_eye.autonomy.shadow_export import ShadowExport

from tests.test_p15_5r_journal import FakeOutcome


def _row(**kwargs):
    export = ShadowExport('/dev/null')
    try:
        return export.row(FakeOutcome(**kwargs),
                          component_health={'auxiliary_ml': 'HEALTHY'})
    finally:
        export.close()


class ReviewCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)

    def export_file(self, rows):
        path = self.directory / 'export.jsonl'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows),
                        encoding='utf-8')
        return path


class TestTheDecisionIsWithheld(ReviewCase):
    """The whole point, asserted field by field."""

    def test_no_withheld_field_survives_the_projection(self):
        view = blinded(_row(blocked=True))
        for field in WITHHELD:
            with self.subTest(field=field):
                self.assertNotIn(field, view)

    def test_a_block_and_an_allow_are_indistinguishable_in_the_view(self):
        """If the reviewer can tell, the blinding did not happen."""
        blocked = blinded(_row(blocked=True))
        allowed = blinded(_row(blocked=False))
        self.assertEqual(sorted(blocked), sorted(allowed))
        differing = [key for key in blocked
                     if key not in ('decision_id',) and blocked[key] != allowed[key]]
        self.assertEqual(differing, [],
                         f'{differing} differ between a block and an allow, so the '
                         f'reviewer can read the decision off the view')

    def test_the_word_block_appears_nowhere_in_a_rendered_view(self):
        text = json.dumps(blinded(_row(blocked=True))).lower()
        for word in ('temp_block', 'blocked', 'enforce', 'withheld'):
            with self.subTest(word=word):
                self.assertNotIn(word, text)

    def test_no_probability_or_cost_field_reaches_the_reviewer(self):
        """A calibrated probability is the decision in one number."""
        view = blinded(_row(blocked=True))
        text = json.dumps(view).lower()
        for word in ('probability', 'threshold', 'loss_', 'margin', 'risk'):
            with self.subTest(word=word):
                self.assertNotIn(word, text)

    def test_the_keep_list_and_the_withheld_list_do_not_overlap(self):
        self.assertEqual(set(KEEP) & set(WITHHELD), set())
        self.assertEqual(set(KEEP_FEATURES) & set(WITHHELD), set())


class TestAnUnknownFieldIsDroppedRatherThanLeaked(ReviewCase):
    """A keep-list, because a remove-list is wrong by default.

    The failure this prevents is entirely ordinary: somebody adds a field to the
    export row and nobody remembers this file exists. With a remove-list the new
    field reaches the reviewer silently and looks exactly like a field that was
    meant to be there.
    """

    def test_a_field_added_to_the_export_does_not_appear_automatically(self):
        row = _row(blocked=True)
        row['some_future_field'] = 'TEMP_BLOCK, obviously'
        view = blinded(row)
        self.assertNotIn('some_future_field', view)
        self.assertNotIn('obviously', json.dumps(view))

    def test_a_feature_added_to_the_export_does_not_appear_automatically(self):
        row = _row(blocked=True)
        row['features']['some_future_feature'] = 0.99
        view = blinded(row)
        self.assertNotIn('some_future_feature', view['features'])

    def test_every_kept_field_that_exists_in_the_row_is_actually_carried(self):
        """The other half: blinding that dropped the evidence would be useless."""
        row = _row(blocked=True)
        view = blinded(row)
        for key in KEEP:
            if key in row:
                with self.subTest(field=key):
                    self.assertEqual(view[key], row[key])
        for key in KEEP_FEATURES:
            if key in row['features']:
                with self.subTest(feature=key):
                    self.assertEqual(view['features'][key], row['features'][key])


class TestTheViewCarriesWhatAReviewerNeeds(ReviewCase):
    """Blinding the conclusion, not the evidence."""

    def test_the_behaviour_is_described_well_enough_to_judge(self):
        view = blinded(_row(blocked=True))
        self.assertIn('contributions', view['features'])
        self.assertTrue(view['features']['contributions'])
        self.assertIn('observations', view['features'])
        self.assertIn('observation_seconds', view['features'])
        self.assertIn('data_quality', view['features'])
        self.assertIn('evidence_families', view)

    def test_the_label_fields_are_present_and_empty(self):
        view = blinded(_row())
        self.assertIsNone(view['label'])
        self.assertIsNone(view['label_confidence'])
        self.assertEqual(view['label_source'], 'reviewed_evaluation')

    def test_unlabeled_is_offered_as_an_answer(self):
        self.assertIn('UNLABELED', LABELS)
        self.assertIn('UNLABELED', blinded(_row())['instructions'])

    def test_the_decision_id_survives_so_a_label_can_be_joined_back(self):
        row = _row()
        self.assertEqual(blinded(row)['decision_id'], row['decision_id'])

    def test_the_view_declares_its_own_version(self):
        self.assertEqual(blinded(_row())['review_view_version'], REVIEW_VIEW_VERSION)


class TestTheOrderCarriesNothing(ReviewCase):
    """Consecutive rows from one burst get labelled more alike than they should."""

    def test_the_rows_are_shuffled(self):
        rows = [dict(_row(), decision_id=f'dec-{index:018x}') for index in range(40)]
        order = [view['decision_id'] for view in project(rows, seed=7)]
        self.assertNotEqual(order, [row['decision_id'] for row in rows])
        self.assertEqual(sorted(order), sorted(row['decision_id'] for row in rows),
                         'shuffling lost or duplicated a row')

    def test_a_seed_makes_a_review_reproducible(self):
        rows = [dict(_row(), decision_id=f'dec-{index:018x}') for index in range(40)]
        self.assertEqual([v['decision_id'] for v in project(rows, seed=3)],
                         [v['decision_id'] for v in project(rows, seed=3)])


class TestReadingAnExport(ReviewCase):
    def test_a_truncated_last_line_is_skipped_rather_than_aborting_the_review(self):
        """What a full disk leaves behind. See docs/BACKPRESSURE.md."""
        path = self.export_file([_row() for _ in range(3)])
        with path.open('a', encoding='utf-8') as handle:
            handle.write('{"decision_id": "dec-00000000000000')
        rows, skipped = read_export(path)
        self.assertEqual(len(rows), 3)
        self.assertEqual(skipped, 1)

    def test_the_document_reports_what_it_skipped_rather_than_hiding_it(self):
        path = self.export_file([_row() for _ in range(2)])
        with path.open('a', encoding='utf-8') as handle:
            handle.write('not json\n')
        document = review_document(path, seed=1)
        self.assertEqual(document['rows'], 2)
        self.assertEqual(document['unparseable_lines_skipped'], 1)

    def test_the_limit_bounds_how_much_is_read(self):
        path = self.export_file([_row() for _ in range(10)])
        self.assertEqual(review_document(path, limit=4)['rows'], 4)

    def test_the_pack_names_what_it_withheld(self):
        path = self.export_file([_row()])
        document = review_document(path)
        self.assertEqual(document['withheld_fields'], list(WITHHELD))
        self.assertIn('not independent ground truth', document['note'])

    def test_no_withheld_field_reaches_the_rendered_pack(self):
        """The end-to-end version, through the renderer an operator actually runs."""
        from eye_for_an_eye.autonomy_cli import render_review
        path = self.export_file([_row(blocked=True), _row(blocked=False)])
        document = review_document(path, seed=5)
        rendered = '\n'.join(json.dumps(row) for row in document['view'])
        for field in WITHHELD:
            with self.subTest(field=field):
                self.assertNotIn(f'"{field}"', rendered)
        # The header names them; the rows must not contain them.
        self.assertIn('Withheld on purpose', render_review(document))


class TestTheCommandRuns(ReviewCase):
    def test_the_cli_refuses_without_a_file_rather_than_inventing_one(self):
        """And refuses the same way `explain` does, rather than a new way."""
        from eye_for_an_eye.autonomy_cli import autonomy_command
        review = autonomy_command(['review'], debug=False)
        self.assertNotEqual(review, 0)
        self.assertEqual(review, autonomy_command(['explain'], debug=False))

    def test_the_cli_emits_json_a_reviewer_tool_can_read(self):
        import contextlib
        import io
        from eye_for_an_eye.autonomy_cli import autonomy_command
        path = self.export_file([_row(blocked=True)])
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = autonomy_command(['review', str(path), '--json'], debug=False)
        self.assertEqual(code, 0)
        document = json.loads(stream.getvalue())
        self.assertEqual(document['rows'], 1)
        self.assertNotIn('would_action', json.dumps(document['view']))


if __name__ == '__main__':
    unittest.main()
