"""P12 Phase 7 (§54-§57, §63-§66, §113, §140): site metadata, and the leakage it invites.

A site identifier is the sharpest leakage available to this project. Hand a
model `site_group` and it learns "traffic to the admin site is malicious" —
which is a fact about one deployment's shape, scores beautifully on the data it
was trained on, and is worthless on the first site it has not seen.

So `site_group` exists as metadata, for filtering, splitting and per-site
evaluation, and is registered as never-model-input alongside the source and
scenario identifiers that were already there for the same reason.

The other half is compatibility. Adding a column is a schema change, and a
corpus written before P12 must still load — including the one the shipped model
was trained on.
"""
import unittest

from dataset import schema
from dataset.schema import (COLUMNS, COLUMNS_V1, DATASET_SCHEMA_VERSION,
                            METADATA_COLUMNS, NEVER_MODEL_INPUT,
                            READABLE_SCHEMA_VERSIONS, accepted_columns)
from eye_for_an_eye.decision.features import INPUT_ORDER


class TestSiteIsMetadataNeverAFeature(unittest.TestCase):
    """§55, §64, §140. The rule, and the ways round it that are closed."""

    def test_site_group_is_registered_as_never_model_input(self):
        self.assertIn('site_group', NEVER_MODEL_INPUT)
        self.assertIn('site', NEVER_MODEL_INPUT['site_group'])

    def test_every_way_of_naming_a_site_is_excluded(self):
        """§64. Domain, host and profile are the same leak wearing other names."""
        for name in ('site_group', 'site_id', 'domain', 'host', 'profile_type'):
            with self.subTest(field=name):
                self.assertIn(name, NEVER_MODEL_INPUT)

    def test_each_exclusion_records_why(self):
        """So it survives a future contributor asking "why not?"."""
        for name in ('site_group', 'site_id', 'domain', 'host', 'profile_type'):
            with self.subTest(field=name):
                self.assertGreater(len(NEVER_MODEL_INPUT[name]), 20)

    def test_no_site_field_is_in_the_model_input_order(self):
        for name in ('site_group', 'site_id', 'domain', 'host', 'profile_type',
                     'site', 'server_name', 'vhost'):
            with self.subTest(field=name):
                self.assertNotIn(name, INPUT_ORDER)

    def test_the_feature_vector_carries_nothing_site_shaped(self):
        joined = ' '.join(INPUT_ORDER).lower()
        for fragment in ('site', 'domain', 'host', 'vhost', 'server_name', 'tenant'):
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, joined)

    def test_site_group_is_metadata_not_evidence(self):
        self.assertIn('site_group', METADATA_COLUMNS)

    def test_a_profile_type_is_never_a_label(self):
        """§113. "admin site" is not a synonym for "dangerous"."""
        from dataset.schema import ALL_LABELS
        for name in ('website', 'api', 'admin', 'mixed', 'custom'):
            with self.subTest(profile=name):
                self.assertNotIn(name, ALL_LABELS)
        # And no label is named after a kind of site either.
        for label in ALL_LABELS:
            self.assertNotIn('site', label)


class TestSampleCarriesSite(unittest.TestCase):
    def sample(self, **kwargs):
        from datetime import datetime, timezone
        from eye_for_an_eye.decision.features import FeatureVector
        vector = FeatureVector(tuple(0.0 for _ in schema.NAMES), 60.0, 30, False, 0.0)
        base = {'dataset_version': 'v1',
                'feature_schema_version': vector.schema_version,
                'sample_id': 'sample-1',
                'timestamp': datetime(2026, 9, 10, tzinfo=timezone.utc),
                'source_type': 'LAB', 'scenario_group': 'g1',
                'source_group': 's1', 'capture_group': None,
                'label': 'benign_like', 'label_source': 'controlled_scenario',
                'label_confidence': 'HIGH', 'features': vector}
        base.update(kwargs)
        return schema.DatasetSample(**base)

    def test_a_sample_can_record_which_site_it_came_from(self):
        self.assertEqual(self.sample(site_group='site-main').site_group, 'site-main')

    def test_site_group_is_optional(self):
        """Rows written before P12 have no site, and that is not an error."""
        self.assertIsNone(self.sample().site_group)

    def test_the_site_reaches_the_row_and_comes_back(self):
        row = self.sample(site_group='site-api').to_row()
        self.assertEqual(row['site_group'], 'site-api')
        restored = schema.sample_from_row(row, {})
        self.assertEqual(restored.site_group, 'site-api')

    def test_a_row_without_the_column_still_loads(self):
        row = self.sample(site_group='site-api').to_row()
        del row['site_group']
        self.assertIsNone(schema.sample_from_row(row, {}).site_group)

    def test_a_control_character_in_a_site_group_is_refused(self):
        """The shape of CSV and log injection, in a field the system generates."""
        for awkward in ('site\nmain', 'site\rmain', 'site\x00main', 'site\x7f'):
            with self.subTest(value=repr(awkward)):
                with self.assertRaises(ValueError):
                    self.sample(site_group=awkward)

    def test_the_same_rule_applies_to_every_group_key(self):
        """Found while adding site_group; the others had the same gap."""
        for field in ('scenario_group', 'source_group', 'sample_id'):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.sample(**{field: 'value\nwith-newline'})

    def test_an_ordinary_site_group_is_accepted(self):
        for good in ('site-main', 'site_api', 'main.example', 'a' * 200):
            with self.subTest(value=good[:20]):
                self.assertEqual(self.sample(site_group=good).site_group, good)


class TestSchemaCompatibility(unittest.TestCase):
    """§56. A corpus written before P12 must still load."""

    def test_the_schema_version_moved(self):
        self.assertEqual(DATASET_SCHEMA_VERSION, 2)

    def test_both_layouts_are_recognised(self):
        self.assertIs(accepted_columns(COLUMNS), COLUMNS)
        self.assertIs(accepted_columns(COLUMNS_V1), COLUMNS_V1)

    def test_the_two_layouts_differ_by_exactly_the_site_column(self):
        self.assertEqual(set(COLUMNS) - set(COLUMNS_V1), {'site_group'})

    def test_an_unknown_layout_is_still_refused(self):
        self.assertIsNone(accepted_columns(('a', 'b', 'c')))
        self.assertIsNone(accepted_columns(()))
        self.assertIsNone(accepted_columns(COLUMNS[:-1]))

    def test_both_schema_versions_are_readable(self):
        self.assertEqual(set(READABLE_SCHEMA_VERSIONS), {1, 2})

    def test_a_version_one_corpus_passes_validation(self):
        """The corpus the shipped model was trained on is version 1."""
        from dataset.validator import validate
        from datetime import datetime, timezone
        from eye_for_an_eye.decision.features import FeatureVector
        vector = FeatureVector(tuple(0.0 for _ in schema.NAMES), 60.0, 30, False, 0.0)
        samples = [schema.DatasetSample(
            dataset_version='v1', feature_schema_version=vector.schema_version,
            sample_id=f'sample-{index}',
            timestamp=datetime(2026, 9, 10, tzinfo=timezone.utc),
            source_type='LAB', scenario_group=f'g{index % 5}',
            source_group=f's{index % 7}', capture_group=None,
            label='benign_like' if index % 2 else 'malicious_automation_like',
            label_source='controlled_scenario', label_confidence='HIGH', features=vector,
            dataset_schema_version=1) for index in range(40)]
        report = validate(samples)
        self.assertNotIn('dataset schema version mismatch', report['critical'])


class TestSiteViews(unittest.TestCase):
    """§56, §71. One corpus, filtered — not one copy per site."""

    def samples(self):
        from datetime import datetime, timezone
        from eye_for_an_eye.decision.features import FeatureVector
        vector = FeatureVector(tuple(0.0 for _ in schema.NAMES), 60.0, 30, False, 0.0)
        return [schema.DatasetSample(
            dataset_version='v1', feature_schema_version=vector.schema_version,
            sample_id=f'sample-{index}',
            timestamp=datetime(2026, 9, 10, tzinfo=timezone.utc),
            source_type='LAB', scenario_group=f'g{index}',
            source_group=f's{index}', capture_group=None, label='benign_like',
            label_source='controlled_scenario', label_confidence='HIGH', features=vector,
            site_group=f'site-{"main" if index % 3 else "api"}')
            for index in range(30)]

    def test_a_site_view_is_a_filter_over_one_corpus(self):
        rows = self.samples()
        main = [row for row in rows if row.site_group == 'site-main']
        api = [row for row in rows if row.site_group == 'site-api']
        self.assertEqual(len(main) + len(api), len(rows))
        self.assertGreater(len(main), 0)
        self.assertGreater(len(api), 0)

    def test_per_site_contributions_are_countable(self):
        """§71. One large site must not silently dominate a global model."""
        from collections import Counter
        counts = Counter(row.site_group for row in self.samples())
        self.assertEqual(sum(counts.values()), 30)
        self.assertEqual(set(counts), {'site-main', 'site-api'})


if __name__ == '__main__':
    unittest.main()
