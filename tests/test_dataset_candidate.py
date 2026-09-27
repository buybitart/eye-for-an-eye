"""P9 candidate dataset: lineage and resistance to poisoning.

The threat these tests describe is simple. Reviewed rows come from observed
traffic, and observed traffic is chosen by whoever sends it. So the questions are:
how much of a new dataset can one source be, how much can one day be, and can a
flood of near-identical windows change what the next model learns.
"""
from datetime import datetime, timedelta, timezone
import json
import unittest
import tempfile
from pathlib import Path

from dataset import schema
from dataset.candidate import (CandidateError, IntakeLimits, LABEL_FROM_REVIEW, admit, build,
                               quality_gate, read_review_export, write_report)
from eye_for_an_eye.decision.features import FeatureVector, NAMES
from eye_for_an_eye.decision.review_queue import vector_payload

START = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def vector(seed=0.1):
    values = {name: 0.0 for name in NAMES}
    values.update({'connections_10s': 1.0 + seed, 'connections_60s': 4.0 + seed,
                   'connections_900s': 12.0 + seed, 'ports_60s': 2.0 + seed,
                   'ports_900s': 3.0 + seed, 'destinations_60s': 1.0,
                   'families_60s': 1.0, 'interarrival_mean_60s': 8.0 + seed,
                   'persistence_900s': 20.0 + seed})
    return FeatureVector(values=tuple(values[name] for name in NAMES),
                         observation_seconds=90.0, sample_count=30, loss_fraction=0.0)


def review_row(index, *, label='benign_like', group=None, day=0, seed=None):
    seed = index * 0.011 if seed is None else seed
    return {'entry_id': f'entry-{index:05d}', 'signature': f'sig{index}',
            'source_group': group or f'src-{index:04x}',
            'label': label, 'label_source': 'manual_review', 'label_confidence': 'MEDIUM',
            'observed_at': (START + timedelta(days=day, minutes=index)).isoformat().replace('+00:00', 'Z'),
            'reviewed_at': (START + timedelta(days=day, hours=2)).isoformat().replace('+00:00', 'Z'),
            'reviewer_note': 'test', 'behaviour': {}, 'evidence': {'observations': 30},
            'features': vector_payload(vector(seed))}


def parent_sample(index, label=schema.BENIGN):
    return schema.DatasetSample(
        dataset_version='parent-v1', feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
        sample_id=f'parent-{index:05d}', timestamp=START - timedelta(days=30),
        source_type=schema.LAB, scenario_group=f'scenario-{index % 40}',
        source_group=f'group-{index % 40}', capture_group=None, label=label,
        label_source='controlled_scenario', label_confidence='HIGH',
        features=vector(1000 + index * 0.013),
        provenance={'source_type': schema.LAB, 'source_role': schema.SOURCE_ROLES[schema.LAB],
                    'ingestion': 'synthetic_event', 'label_authority': 'controlled scenario'})


def parent(rows=600):
    return [parent_sample(index, schema.BENIGN if index % 2 else schema.MALICIOUS)
            for index in range(rows)]


class TestLabelOrigin(unittest.TestCase):
    def test_only_a_manual_review_can_label_an_observed_row(self):
        row = review_row(1)
        row['label_source'] = 'shadow_decision'
        samples, report = admit([row], dataset_version='c-v1', sensor_placement='lab')
        self.assertEqual(samples, [])
        self.assertEqual(report.dropped['unusable_row'], 1)

    def test_a_model_score_is_never_a_label_source(self):
        for forbidden in ('model_score', 'math_score', 'risk_threshold', 'blocked'):
            with self.subTest(source=forbidden):
                row = review_row(1)
                row['label_source'] = forbidden
                samples, _ = admit([row], dataset_version='c-v1', sensor_placement='lab')
                self.assertEqual(samples, [])

    def test_an_unknown_label_is_refused(self):
        row = review_row(1)
        row['label'] = 'malicious'
        samples, report = admit([row], dataset_version='c-v1', sensor_placement='lab')
        self.assertEqual(samples, [])
        self.assertEqual(report.dropped['unusable_row'], 1)

    def test_uncertain_never_enters_supervised_data(self):
        rows = [review_row(index, label='uncertain') for index in range(10)]
        samples, report = admit(rows, dataset_version='c-v1', sensor_placement='lab')
        self.assertEqual(samples, [])
        self.assertEqual(report.dropped['uncertain_not_supervised'], 10)

    def test_the_review_label_names_map_to_the_dataset_names(self):
        self.assertEqual(LABEL_FROM_REVIEW['benign_like'], schema.BENIGN)
        self.assertEqual(LABEL_FROM_REVIEW['malicious_automation_like'], schema.MALICIOUS)
        self.assertNotIn('ignore', LABEL_FROM_REVIEW)

    def test_a_reviewed_row_is_never_high_confidence(self):
        row = review_row(1)
        row['label_confidence'] = 'HIGH'
        samples, _ = admit([row], dataset_version='c-v1', sensor_placement='lab')
        self.assertEqual(samples[0].label_confidence, 'MEDIUM')


class TestPoisoningLimits(unittest.TestCase):
    def test_one_source_cannot_contribute_more_than_its_cap(self):
        rows = [review_row(index, group='src-attacker') for index in range(200)]
        samples, report = admit(rows, dataset_version='c-v1', sensor_placement='lab',
                                limits=IntakeLimits(per_source=10, max_single_source_fraction=1.0))
        self.assertEqual(len(samples), 10)
        self.assertEqual(report.dropped['per_source_limit'], 190)

    def test_one_source_cannot_be_most_of_the_new_rows(self):
        rows = ([review_row(index, group='src-attacker') for index in range(100)]
                + [review_row(500 + index) for index in range(20)])
        samples, report = admit(rows, dataset_version='c-v1', sensor_placement='lab',
                                limits=IntakeLimits(per_source=100, max_single_source_fraction=0.10))
        by_group = {}
        for sample in samples:
            by_group[sample.source_group] = by_group.get(sample.source_group, 0) + 1
        self.assertLessEqual(by_group.get('src-attacker', 0), max(1, int(len(samples) * 0.5)))
        self.assertGreater(report.dropped['single_source_share'], 0)

    def test_one_day_cannot_contribute_more_than_its_cap(self):
        rows = [review_row(index, day=0) for index in range(100)]
        samples, report = admit(rows, dataset_version='c-v1', sensor_placement='lab',
                                limits=IntakeLimits(per_day=15, max_single_source_fraction=1.0))
        self.assertEqual(len(samples), 15)
        self.assertEqual(report.dropped['per_day_limit'], 85)

    def test_identical_behaviour_is_counted_once(self):
        rows = [review_row(index, seed=0.5) for index in range(50)]
        samples, report = admit(rows, dataset_version='c-v1', sensor_placement='lab')
        self.assertEqual(len(samples), 1)
        self.assertEqual(report.dropped['duplicate_behaviour'], 49)

    def test_a_row_already_in_the_parent_dataset_is_not_added_again(self):
        parent_rows = parent(10)
        row = review_row(1, seed=1000.0)
        row['features'] = vector_payload(parent_rows[0].features)
        result = build(parent_samples=parent_rows, parent_dataset='parent-v1',
                       review_rows=[row], dataset_version='c-v1', sensor_placement='lab')
        self.assertEqual(result['intake'].dropped['duplicate_behaviour'], 1)

    def test_the_whole_batch_is_capped(self):
        rows = [review_row(index) for index in range(5000)]
        samples, report = admit(rows, dataset_version='c-v1', sensor_placement='lab',
                                limits=IntakeLimits(max_new_rows=100,
                                                    max_single_source_fraction=1.0))
        self.assertEqual(len(samples), 100)
        self.assertGreater(report.dropped['batch_limit'], 0)

    def test_a_narrow_batch_is_reported_as_a_warning(self):
        rows = [review_row(index, group='src-one') for index in range(30)]
        _, report = admit(rows, dataset_version='c-v1', sensor_placement='lab',
                          limits=IntakeLimits(per_source=30, max_single_source_fraction=1.0,
                                              min_distinct_sources=10))
        self.assertTrue(any('sources' in warning for warning in report.warnings))

    def test_new_rows_may_not_dominate_the_candidate_dataset(self):
        rows = [review_row(index) for index in range(400)]
        _, report = admit(rows, dataset_version='c-v1', sensor_placement='lab', parent_rows=100,
                          limits=IntakeLimits(max_new_fraction=0.25,
                                              max_single_source_fraction=1.0))
        self.assertTrue(any('above the' in warning for warning in report.warnings))

    def test_impossible_limits_are_refused(self):
        for kwargs in ({'per_source': 0}, {'max_new_fraction': 0}, {'max_new_fraction': 2.0},
                       {'max_new_rows': 0}, {'min_distinct_sources': 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(CandidateError):
                    IntakeLimits(**kwargs)


class TestLineage(unittest.TestCase):
    def test_a_candidate_records_its_parent(self):
        result = build(parent_samples=parent(600), parent_dataset='parent-v1',
                       review_rows=[review_row(index, label='malicious_automation_like')
                                    for index in range(30)],
                       dataset_version='candidate-v2', sensor_placement='lab')
        lineage = result['lineage'].explain()
        self.assertEqual(lineage['parent_dataset'], 'parent-v1')
        self.assertEqual(lineage['parent_rows'], 600)
        self.assertEqual(lineage['new_malicious_samples'], result['intake'].accepted)
        self.assertTrue(lineage['parent_digest'])
        self.assertIn('answering a review entry', lineage['label_origin'])

    def test_a_candidate_cannot_reuse_the_parent_version(self):
        with self.assertRaises(CandidateError):
            build(parent_samples=parent(10), parent_dataset='parent-v1', review_rows=[],
                  dataset_version='parent-v1', sensor_placement='lab')

    def test_a_candidate_needs_a_version(self):
        with self.assertRaises(CandidateError):
            build(parent_samples=parent(10), parent_dataset='parent-v1', review_rows=[],
                  dataset_version='', sensor_placement='lab')

    def test_the_parent_rows_are_carried_through_unchanged(self):
        parent_rows = parent(50)
        result = build(parent_samples=parent_rows, parent_dataset='parent-v1',
                       review_rows=[review_row(1)], dataset_version='c-v2',
                       sensor_placement='lab')
        self.assertEqual(result['samples'][:50], parent_rows)
        for sample in result['samples'][:50]:
            self.assertEqual(sample.label_source, 'controlled_scenario')


class TestQualityGate(unittest.TestCase):
    def test_a_small_dataset_fails(self):
        status, reasons = quality_gate(parent(50), _empty_report(), minimum_rows=500)
        self.assertEqual(status, 'FAIL')
        self.assertTrue(any('supervised rows' in reason for reason in reasons))

    def test_a_dataset_with_one_class_fails(self):
        samples = [parent_sample(index, schema.BENIGN) for index in range(600)]
        status, reasons = quality_gate(samples, _empty_report())
        self.assertEqual(status, 'FAIL')
        self.assertTrue(any('no malicious' in reason for reason in reasons))

    def test_a_badly_imbalanced_dataset_fails(self):
        samples = ([parent_sample(index, schema.BENIGN) for index in range(600)]
                   + [parent_sample(1000 + index, schema.MALICIOUS) for index in range(20)])
        status, reasons = quality_gate(samples, _empty_report())
        self.assertEqual(status, 'FAIL')
        self.assertTrue(any('smaller class' in reason for reason in reasons))

    def test_a_dataset_dominated_by_one_group_fails(self):
        samples = []
        for index in range(600):
            sample = parent_sample(index, schema.BENIGN if index % 2 else schema.MALICIOUS)
            sample.source_group = 'group-one' if index < 400 else f'group-{index}'
            samples.append(sample)
        status, reasons = quality_gate(samples, _empty_report())
        self.assertEqual(status, 'FAIL')
        self.assertTrue(any('one group is' in reason for reason in reasons))

    def test_a_reasonable_dataset_passes_with_a_note_about_its_one_source_kind(self):
        status, reasons = quality_gate(parent(600), _empty_report())
        self.assertEqual(status, 'PASS_WITH_WARNINGS')
        self.assertTrue(any('one kind of source' in reason for reason in reasons))

    def test_intake_warnings_reach_the_gate(self):
        report = _empty_report()
        report.warnings.append('new rows come from 2 sources, 10 needed')
        _, reasons = quality_gate(parent(600), report)
        self.assertIn('new rows come from 2 sources, 10 needed', reasons)


class TestReportFile(unittest.TestCase):
    def test_the_report_says_it_cannot_train_or_promote(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        result = build(parent_samples=parent(600), parent_dataset='parent-v1',
                       review_rows=[review_row(index) for index in range(30)],
                       dataset_version='c-v2', sensor_placement='lab')
        target = Path(directory.name) / 'candidate.json'
        write_report(result, target)
        document = json.loads(target.read_text(encoding='utf-8'))
        self.assertIn('does not train a model', document['authority'])
        self.assertIn(document['quality_gate'], ('PASS', 'PASS_WITH_WARNINGS', 'FAIL'))
        self.assertEqual(document['lineage']['parent_dataset'], 'parent-v1')

    def test_a_file_that_is_not_a_review_export_is_refused(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        target = Path(directory.name) / 'other.json'
        target.write_text(json.dumps({'samples': []}), encoding='utf-8')
        with self.assertRaises(CandidateError):
            read_review_export(target)


def _empty_report():
    from dataset.candidate import IntakeReport
    return IntakeReport()


if __name__ == '__main__':
    unittest.main()
