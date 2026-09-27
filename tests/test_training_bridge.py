"""The bridge between this repository's two dataset formats.

The bridge exists so a P9 candidate dataset can reach the existing trainer. The
risk it introduces is that a conversion quietly changes what a row means, so
these tests are mostly about what must survive the crossing unchanged, and what
must not cross at all.
"""
from datetime import datetime, timedelta, timezone
import json
import unittest
import tempfile
from pathlib import Path

from dataset import schema
from eye_for_an_eye.decision.features import FeatureVector, NAMES
from training.bridge import BridgeError, DROPPED_COLUMNS, convert, materialise, training_row

START = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def vector(seed=0.1):
    values = {name: 0.0 for name in NAMES}
    values.update({'connections_10s': 1.0 + seed, 'connections_60s': 4.0 + seed,
                   'connections_900s': 12.0 + seed, 'ports_60s': 2.0 + seed,
                   'ports_900s': 3.0 + seed, 'destinations_60s': 1.0, 'families_60s': 1.0,
                   'interarrival_mean_60s': 8.0 + seed, 'persistence_900s': 20.0 + seed})
    return FeatureVector(values=tuple(values[name] for name in NAMES),
                         observation_seconds=90.0, sample_count=30, loss_fraction=0.0)


def sample(index=0, *, label=schema.BENIGN, split='train', source_type=schema.LAB,
           label_source='controlled_scenario', confidence='HIGH'):
    kwargs = {'scenario_group': f'scenario-{index % 7}', 'source_group': f'group-{index % 7}',
              'capture_group': None}
    if source_type in schema.SHADOW_TYPES:
        kwargs = {'scenario_group': None, 'source_group': f'src-{index % 7}',
                  'capture_group': None}
        provenance = {'source_type': source_type,
                      'source_role': schema.SOURCE_ROLES[source_type],
                      'ingestion': 'shadow_export', 'label_authority': 'manual review'}
    else:
        provenance = {'source_type': source_type,
                      'source_role': schema.SOURCE_ROLES[source_type],
                      'ingestion': 'synthetic_event', 'label_authority': 'controlled scenario'}
    return schema.DatasetSample(
        dataset_version='dataset-v2-candidate',
        feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
        sample_id=f'sample-{index:05d}', timestamp=START + timedelta(minutes=index),
        source_type=source_type, label=label, label_source=label_source,
        label_confidence=confidence, features=vector(index * 0.017),
        provenance=provenance, split=split, **kwargs)


class TestWhatCrosses(unittest.TestCase):
    def test_a_supervised_row_crosses_with_its_label_converted_not_derived(self):
        row = training_row(sample(1, label=schema.MALICIOUS))
        self.assertEqual(row['label'], 1)
        self.assertEqual(training_row(sample(2, label=schema.BENIGN))['label'], 0)

    def test_the_feature_values_survive_unchanged(self):
        source = sample(3)
        row = training_row(source)
        for name, value in zip(NAMES, source.features.values, strict=True):
            stored = row['raw_' + name]
            self.assertEqual(stored if stored == '' else float(stored),
                             '' if value is None else round(float(value), 9))

    def test_the_evidence_survives(self):
        source = sample(4)
        row = training_row(source)
        self.assertEqual(row['sample_count'], source.features.sample_count)
        self.assertEqual(row['loss_fraction'], source.features.loss_fraction)

    def test_an_uncertain_row_never_crosses(self):
        rows, dropped = convert([sample(5, label=schema.UNCERTAIN, confidence='LOW',
                                        label_source='manual_review',
                                        source_type=schema.SHADOW_REVIEWED)])
        self.assertEqual(rows, [])
        self.assertEqual(dropped['not_supervised_uncertain'], 1)

    def test_an_unlabelled_row_never_crosses(self):
        rows, dropped = convert([sample(6, label=schema.UNLABELED, confidence='LOW',
                                        label_source='shadow_observation',
                                        source_type=schema.SHADOW_UNLABELED)])
        self.assertEqual(rows, [])
        self.assertEqual(dropped['not_supervised_unlabeled'], 1)

    def test_a_reviewed_shadow_row_crosses_and_keeps_its_source(self):
        row = training_row(sample(7, label=schema.MALICIOUS, label_source='manual_review',
                                  source_type=schema.SHADOW_REVIEWED, confidence='MEDIUM'))
        self.assertEqual(row['label_source'], 'manual_review')
        self.assertTrue(row['scenario_group'], 'a shadow row still needs a grouping key')

    def test_a_shadow_row_gets_a_grouping_key_so_the_split_stays_group_aware(self):
        row = training_row(sample(8, label=schema.BENIGN, label_source='manual_review',
                                  source_type=schema.SHADOW_REVIEWED, confidence='MEDIUM'))
        self.assertEqual(row['scenario_group'], row['source_group'])

    def test_the_dropped_columns_are_named_rather_than_silently_lost(self):
        for column in ('provenance', 'label_confidence', 'source_type'):
            self.assertIn(column, DROPPED_COLUMNS)


class TestMaterialise(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def corpus(self):
        """A corpus whose splits follow its groups.

        The split is chosen by the row's group, never by its position, because a
        group that crosses a split is exactly the leakage the trainer's validator
        is there to catch.
        """
        rows = []
        for index in range(120):
            group = index % 7
            split = 'train' if group < 4 else ('validation' if group < 6 else 'test')
            label = schema.BENIGN if index % 2 else schema.MALICIOUS
            rows.append(sample(index, label=label, split=split))
        return rows

    def test_the_manifest_does_not_claim_to_be_the_synthetic_corpus(self):
        manifest = materialise(self.corpus(), self.root / 'out',
                               dataset_version='dataset-v2-candidate',
                               parent_dataset='dataset-v1')
        self.assertEqual(manifest['dataset_version'], 'dataset-v2-candidate')
        self.assertEqual(manifest['parent_dataset'], 'dataset-v1')
        self.assertIn('converted', manifest['generator'])
        self.assertIn('converted view', manifest['source'])

    def test_the_manifest_names_every_label_source_it_actually_contains(self):
        rows = self.corpus()
        rows.append(sample(999, label=schema.MALICIOUS, label_source='manual_review',
                           source_type=schema.SHADOW_REVIEWED, confidence='MEDIUM',
                           split='train'))
        manifest = materialise(rows, self.root / 'out2', dataset_version='d-v2')
        self.assertIn('manual_review', manifest['label_sources'])
        self.assertIn('controlled_scenario', manifest['label_sources'])
        self.assertEqual(manifest['label_source'], manifest['label_sources'])

    def test_a_single_source_stays_a_plain_string(self):
        manifest = materialise(self.corpus(), self.root / 'out3', dataset_version='d-v2')
        self.assertEqual(manifest['label_source'], 'controlled_scenario')

    def test_the_manifest_says_what_did_not_cross(self):
        rows = self.corpus() + [sample(500, label=schema.UNCERTAIN, confidence='LOW',
                                       label_source='manual_review',
                                       source_type=schema.SHADOW_REVIEWED)]
        manifest = materialise(rows, self.root / 'out4', dataset_version='d-v2')
        self.assertEqual(manifest['dropped_rows']['not_supervised_uncertain'], 1)
        self.assertIn('never derived', manifest['conversion_note'])

    def test_the_written_directory_loads_with_the_trainer(self):
        from training.dataset import load
        materialise(self.corpus(), self.root / 'out5', dataset_version='d-v2')
        manifest, rows = load(self.root / 'out5')
        self.assertEqual(len(rows), 120)
        self.assertEqual({row['label'] for row in rows}, {0, 1})

    def test_it_passes_the_trainers_own_dataset_validation(self):
        from training.dataset import load
        from training.validation import validate_dataset
        materialise(self.corpus(), self.root / 'out6', dataset_version='d-v2')
        manifest, rows = load(self.root / 'out6')
        report = validate_dataset(manifest, rows)
        self.assertEqual(report['critical'], [], report['critical'])

    def test_a_dataset_with_no_supervised_rows_is_refused(self):
        rows = [sample(index, label=schema.UNLABELED, confidence='LOW',
                       label_source='shadow_observation',
                       source_type=schema.SHADOW_UNLABELED) for index in range(5)]
        with self.assertRaises(BridgeError):
            materialise(rows, self.root / 'out7', dataset_version='d-v2')

    def test_a_row_without_a_split_is_refused_rather_than_guessed_at(self):
        rows = self.corpus() + [sample(700, split=None)]
        with self.assertRaises(BridgeError):
            materialise(rows, self.root / 'out8', dataset_version='d-v2')

    def test_the_written_manifest_is_readable_json(self):
        target = self.root / 'out9'
        materialise(self.corpus(), target, dataset_version='d-v2')
        document = json.loads((target / 'dataset_manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(document['dataset_version'], 'd-v2')


class TestLabelSourceValidation(unittest.TestCase):
    """The validator was widened to accept a list. It must not have been loosened.

    Each case runs against a real, otherwise-valid dataset, so the only thing
    that changes between them is the declared label source.
    """

    MESSAGE = 'label_source is not an accepted independent source'

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        rows = []
        for index in range(120):
            group = index % 7
            split = 'train' if group < 4 else ('validation' if group < 6 else 'test')
            rows.append(sample(index, label=schema.BENIGN if index % 2 else schema.MALICIOUS,
                               split=split))
        target = Path(self.directory.name) / 'ds'
        materialise(rows, target, dataset_version='d-v2')
        from training.dataset import load
        self.manifest, self.rows = load(target)

    def report_for(self, label_source):
        from training.validation import validate_dataset
        manifest = dict(self.manifest)
        manifest['label_source'] = label_source
        return validate_dataset(manifest, self.rows)

    def test_a_forbidden_source_still_fails_on_its_own(self):
        self.assertIn(self.MESSAGE, self.report_for('blocked')['critical'])

    def test_one_forbidden_source_in_a_list_fails_the_whole_dataset(self):
        report = self.report_for(['controlled_scenario', 'ml_score'])
        self.assertIn(self.MESSAGE, report['critical'])

    def test_an_empty_list_fails(self):
        self.assertIn(self.MESSAGE, self.report_for([])['critical'])

    def test_a_missing_source_fails(self):
        self.assertIn(self.MESSAGE, self.report_for(None)['critical'])

    def test_a_list_of_trusted_sources_is_accepted(self):
        report = self.report_for(['controlled_scenario', 'manual_review'])
        self.assertNotIn(self.MESSAGE, report['critical'])

    def test_a_single_trusted_source_is_still_accepted(self):
        self.assertNotIn(self.MESSAGE, self.report_for('controlled_scenario')['critical'])


if __name__ == '__main__':
    unittest.main()
