"""The measurement harness that produced P15.1's central finding.

`training/decision_replay.py` is how this project learned that its autonomous
authority blocks nothing. A harness with that much authority over a conclusion
needs tests of its own, and they are a specific kind: not "does it compute an
AUC" — arithmetic is already covered in `tests/test_p15_science.py` — but "can
it be made to report a number it has not earned".

Three ways that could happen, and each has tests below:

* **Labels that are not ground truth.** §5 lists what may never become a label:
  the system's own block, its own allow, a model score, a challenge outcome. The
  harness must drop a row it cannot trust rather than score it.
* **Rows where ground truth does not exist.** The same bounded window can come
  from a quiet reader and from a slow scan. Scoring those moves a metric without
  measuring anything.
* **An aggregation chosen after seeing the answer.** Per-source numbers depend
  entirely on how a source's windows combine, and the harness must combine them
  the way the *system* does, not the way that reads best.
"""
import unittest

from eye_for_an_eye.autonomy import evaluation as ev
from training.decision_replay import (LABELS, TRUSTED_LABEL_SOURCES,
                                      ambiguous_vectors, ranking_breakdown,
                                      source_outcomes, trusted, window_outcomes)

from p15_1_replay_fixtures import sample, window


class TestOnlyTrustedLabelsAreScored(unittest.TestCase):

    def test_the_trusted_sources_are_the_three_named_in_the_brief(self):
        self.assertEqual(set(TRUSTED_LABEL_SOURCES),
                         {'controlled_scenario', 'manual_review', 'trusted_fixture'})

    def test_a_generated_label_is_valid_in_the_corpus_and_still_not_scored(self):
        """`synthetic_generator` is the case that matters, because it is legal.

        The schema accepts it — a generator's own idea of what it produced is a
        real label source and fine for training. It is not evidence about the
        deployed decision, so the measurement declines it. The drop is counted,
        because a harness that silently discarded part of the corpus would
        report a clean number about a corpus nobody could see.
        """
        rows = ([sample(f'trusted-{index}') for index in range(3)]
                + [sample('generated', label_source='synthetic_generator',
                          port_breadth=9.0)])
        kept, dropped = trusted(rows)
        self.assertEqual([row.sample_id for row in kept],
                         ['trusted-0', 'trusted-1', 'trusted-2'])
        self.assertEqual(dropped, {'label_source=synthetic_generator': 1})

    def test_the_corpus_format_cannot_even_hold_a_self_made_label(self):
        """§5's forbidden substitutions never reach the harness at all.

        Two layers, and this pins the lower one: a row whose label came from
        this system's own block, allow, model score or math score cannot be
        constructed, so no corpus can carry one to be filtered later. A filter
        can be bypassed by a new code path; a constructor cannot.
        """
        for source in ('model_score', 'math_score', 'blocked', 'firewall',
                       'shadow_decision', 'automatically_blocked', 'self_labelled',
                       'risk_threshold', 'previous_model'):
            with self.subTest(label_source=source):
                with self.assertRaises(ValueError):
                    sample('rejected', label_source=source)

    def test_an_unlabelled_row_is_dropped_rather_than_assumed_benign(self):
        """The quiet failure this prevents: silence read as innocence.

        An UNLABELED row is the common case in production and the tempting one
        to count as benign, which would inflate the benign sample and deflate
        every false-positive rate computed from it.
        """
        kept, dropped = trusted([sample('unlabelled', label='unlabeled',
                                        label_source='shadow_observation',
                                        confidence='LOW'),
                                 sample('known', label='benign_like')])
        self.assertEqual([row.sample_id for row in kept], ['known'])
        self.assertEqual(dropped, {'label=unlabeled': 1})

    def test_the_label_map_covers_exactly_two_classes(self):
        self.assertEqual(LABELS, {'benign_like': ev.BENIGN,
                                  'malicious_automation_like': ev.MALICIOUS_AUTOMATION})


class TestRowsWithoutGroundTruthAreExcluded(unittest.TestCase):

    def test_one_vector_under_two_labels_is_dropped_from_both_sides(self):
        rows = [sample('benign', label='benign_like', port_breadth=4.0),
                sample('malicious', label='malicious_automation_like', port_breadth=4.0),
                sample('separable', label='malicious_automation_like', port_breadth=40.0)]
        self.assertEqual(len(ambiguous_vectors(rows)), 1)
        kept, dropped = trusted(rows)
        self.assertEqual([row.sample_id for row in kept], ['separable'])
        self.assertEqual(dropped, {'identical_vector_under_both_labels': 2})

    def test_the_same_vector_under_one_label_is_kept(self):
        """Duplicates are not ambiguity. Only disagreement is."""
        rows = [sample('one', label='benign_like', port_breadth=4.0),
                sample('two', label='benign_like', port_breadth=4.0)]
        kept, dropped = trusted(rows)
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, {})

    def test_observation_length_is_part_of_the_vector_identity(self):
        """Same feature values, different window length: not the same evidence."""
        rows = [sample('short', label='benign_like', port_breadth=4.0, seconds=30.0),
                sample('long', label='malicious_automation_like',
                       port_breadth=4.0, seconds=600.0)]
        self.assertEqual(ambiguous_vectors(rows), set())
        kept, _ = trusted(rows)
        self.assertEqual(len(kept), 2)


class TestASourceIsScoredTheWayItIsBlocked(unittest.TestCase):

    def test_one_blocked_window_blocks_the_source(self):
        decisions = [window('s1', blocked=False), window('s1', blocked=True),
                     window('s1', blocked=False)]
        outcomes, conflicts = source_outcomes(decisions)
        self.assertEqual(conflicts, [])
        self.assertEqual(len(outcomes), 1)
        self.assertTrue(outcomes[0].blocked)

    def test_a_source_with_no_blocked_window_is_allowed(self):
        outcomes, _ = source_outcomes([window('s1'), window('s1')])
        self.assertFalse(outcomes[0].blocked)

    def test_the_source_score_is_the_strongest_window_not_the_average(self):
        """The strongest window is the one a block would have rested on.

        Averaging would report a source the system nearly blocked as a quiet
        one, which is the wrong direction for a false-positive measurement.
        """
        outcomes, _ = source_outcomes([window('s1', probability=0.1),
                                       window('s1', probability=0.9),
                                       window('s1', probability=0.2)])
        self.assertEqual(outcomes[0].score, 0.9)

    def test_a_source_whose_windows_disagree_about_the_label_is_refused(self):
        """Picking a side here would be inventing ground truth.

        It should not happen in a group-consistent corpus. If it ever does, the
        harness must say so rather than score it — a silent majority vote is how
        a labelling bug becomes a published metric.
        """
        decisions = [window('mixed', label='benign_like'),
                     window('mixed', label='malicious_automation_like'),
                     window('clean', label='benign_like')]
        outcomes, conflicts = source_outcomes(decisions)
        self.assertEqual(conflicts, ['mixed'])
        self.assertEqual(len(outcomes), 1)

    def test_windows_are_scored_one_row_each(self):
        decisions = [window('s1'), window('s1'), window('s2')]
        self.assertEqual(len(window_outcomes(decisions)), 3)
        self.assertEqual(len(source_outcomes(decisions)[0]), 2)


class TestTheRankingBreakdownIsHonestAboutMissingScores(unittest.TestCase):

    def test_a_stage_that_did_not_answer_is_excluded_not_zeroed(self):
        """A classifier that failed has no opinion. Zero is an opinion.

        Substituting 0.0 for an absent score would make the classifier look
        like it confidently called those rows benign, which is how an outage
        turns into a detection claim.
        """
        decisions = [window('s1', label='benign_like', model_score=None),
                     window('s2', label='malicious_automation_like', model_score=0.9),
                     window('s3', label='benign_like', model_score=0.1)]
        rows = ranking_breakdown(decisions)
        self.assertEqual(rows['classifier model_score']['scored_windows'], 2)
        self.assertEqual(rows['MathRisk (raw)']['scored_windows'], 3)

    def test_a_stage_with_only_one_class_reports_none_rather_than_a_number(self):
        decisions = [window('s1', label='benign_like'), window('s2', label='benign_like')]
        rows = ranking_breakdown(decisions)
        self.assertIsNone(rows['MathRisk (raw)']['per_window_roc_auc'])
        self.assertIsNone(rows['MathRisk (raw)']['per_source_roc_auc'])

    def test_a_perfect_separator_scores_one_and_a_reversed_one_scores_zero(self):
        """Wiring check. An AUC that cannot reach either extreme is misconnected."""
        decisions = [window(f'b{index}', label='benign_like', math_risk=0.1 * index)
                     for index in range(5)]
        decisions += [window(f'm{index}', label='malicious_automation_like',
                             math_risk=0.6 + 0.05 * index) for index in range(5)]
        self.assertEqual(ranking_breakdown(decisions)['MathRisk (raw)']['per_window_roc_auc'],
                         1.0)
        flipped = [window(d.source_group, label=d.label, math_risk=1.0 - d.math_risk)
                   for d in decisions]
        self.assertEqual(ranking_breakdown(flipped)['MathRisk (raw)']['per_window_roc_auc'],
                         0.0)

    def test_sources_aggregate_with_max_so_one_strong_window_counts(self):
        """The documented aggregation, pinned.

        Each malicious source here has one strong window and several weak ones.
        Under max it separates perfectly; under a mean it would not. This test
        fails if somebody quietly changes the aggregation, which would change
        every per-source number in the report without changing the report.
        """
        decisions = []
        for index in range(4):
            decisions.append(window(f'm{index}', label='malicious_automation_like',
                                    math_risk=0.95))
            decisions += [window(f'm{index}', label='malicious_automation_like',
                                 math_risk=0.01) for _ in range(9)]
            decisions += [window(f'b{index}', label='benign_like', math_risk=0.3)
                          for _ in range(10)]
        rows = ranking_breakdown(decisions)['MathRisk (raw)']
        self.assertEqual(rows['scored_sources'], 8)
        self.assertEqual(rows['per_source_roc_auc'], 1.0)
        self.assertLess(rows['per_window_roc_auc'], 0.5)

    def test_a_source_with_conflicting_labels_is_left_out_of_the_ranking_too(self):
        decisions = [window('mixed', label='benign_like', math_risk=0.2),
                     window('mixed', label='malicious_automation_like', math_risk=0.8),
                     window('clean', label='benign_like', math_risk=0.1),
                     window('bad', label='malicious_automation_like', math_risk=0.9)]
        rows = ranking_breakdown(decisions)['MathRisk (raw)']
        self.assertEqual(rows['scored_windows'], 4)
        self.assertEqual(rows['scored_sources'], 2)

    def test_every_stage_in_the_report_table_is_present(self):
        decisions = [window('s1', label='benign_like'),
                     window('s2', label='malicious_automation_like')]
        self.assertEqual(list(ranking_breakdown(decisions)), [
            'classifier model_score', 'anomaly score', 'signal diversity',
            'MathRisk (raw)', 'conservative probability (what decides)',
            'behavioural diversity'])


if __name__ == '__main__':
    unittest.main()
