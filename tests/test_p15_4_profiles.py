"""Site and profile metadata: present for evaluation, absent from every model. §41, §42.

P15.1, P15.2 and P15.3 each reported "per-profile metrics could not be produced"
because `site_group` was `None` on every row of every corpus. That is not a
small gap: a false-block rate averaged over a whole benchmark can hide a profile
where the system is badly wrong, and "the worst site" is exactly the number the
average is supposed to be read against.

Fixing it introduces the risk that makes §42 a hard invariant. Site identity is
a superb predictor of the label in a synthetic corpus — a scenario family and a
site are correlated by construction — so a model that saw `site_group` would
learn which site the traffic came from and score beautifully while having
learned nothing about behaviour at all. That is the purest form of the leakage
`NEVER_MODEL_INPUT` exists to prevent.

So this module checks the same thing from four directions: the exclusion list,
the feature schema, the tensor itself, and the CSV column layout.
"""
import unittest

from dataset import schema
from dataset.scenarios import PROFILE_TYPES, load, plans
from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES


class TestTheMetadataIsExcludedFromEveryModel(unittest.TestCase):
    """§42, four independent ways. One of them is a comment; three are not."""

    METADATA = ('site_group', 'profile_type')

    def test_both_are_named_in_the_exclusion_list_with_a_reason(self):
        for name in self.METADATA:
            with self.subTest(name=name):
                self.assertIn(name, schema.NEVER_MODEL_INPUT)
                self.assertTrue(schema.NEVER_MODEL_INPUT[name].strip(),
                                'an exclusion without a reason does not survive a refactor')

    def test_neither_is_a_feature_in_any_schema(self):
        for name in self.METADATA:
            with self.subTest(name=name):
                self.assertNotIn(name, NAMES)
                self.assertNotIn(name, INPUT_ORDER)
                self.assertNotIn('available_' + name, INPUT_ORDER)

    def test_neither_is_a_model_input_in_any_schema_version(self):
        for version in (1, schema.FEATURE_SCHEMA_VERSION):
            for name in self.METADATA:
                with self.subTest(schema=version, name=name):
                    self.assertNotIn(name, schema.model_features_for(version))

    def test_the_tensor_has_no_room_for_them(self):
        """The structural argument: the tensor is exactly two columns per
        feature, so there is nowhere a metadata column could hide."""
        self.assertEqual(len(INPUT_ORDER), 2 * len(NAMES))

    def test_site_group_is_a_csv_column_and_not_a_feature_column(self):
        self.assertIn('site_group', schema.COLUMNS)
        self.assertNotIn('raw_site_group', schema.COLUMNS)
        self.assertNotIn('profile_type', schema.COLUMNS,
                         'profile_type travels in provenance, not as its own column')


class TestTheProfileVocabularyMatchesTheCostPolicy(unittest.TestCase):
    """A per-profile result is only meaningful if it groups traffic the way the
    cost policy prices it. Two vocabularies that drift apart produce a report
    whose rows mean something different from the thresholds they are judged by."""

    def test_every_declarable_profile_has_a_cost_profile(self):
        for name in PROFILE_TYPES:
            with self.subTest(profile=name):
                self.assertIn(name, PROFILES)

    def test_every_cost_profile_can_be_declared_by_a_scenario(self):
        for name in PROFILES:
            with self.subTest(profile=name):
                self.assertIn(name, PROFILE_TYPES)


class TestTheMatrixCarriesItThrough(unittest.TestCase):

    def test_an_unknown_profile_type_is_refused_rather_than_ignored(self):
        matrix = {'matrix_version': '1.0', 'dataset_version': 'x', 'scenario': [
            {'id': 'a', 'group': 'g', 'generator': 'benign.web_client', 'runs': 1,
             'profile_type': 'not-a-profile'}]}
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'm.toml'
            path.write_text(
                'matrix_version = "1.0"\ndataset_version = "x"\n'
                'snapshot_interval_seconds = 2.0\nmax_samples_per_source = 4\n'
                'max_samples_per_scenario = 4\n\n[[scenario]]\nid = "a"\ngroup = "g"\n'
                'generator = "benign.web_client"\nruns = 1\n'
                'profile_type = "not-a-profile"\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                load(path)
        _ = matrix

    def test_a_declared_site_reaches_the_plan(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'm.toml'
            path.write_text(
                'matrix_version = "1.0"\ndataset_version = "x"\n'
                'snapshot_interval_seconds = 2.0\nmax_samples_per_source = 4\n'
                'max_samples_per_scenario = 4\n\n[[scenario]]\nid = "a"\ngroup = "g"\n'
                'generator = "benign.web_client"\nruns = 1\n'
                'site_group = "site-public-1"\nprofile_type = "public_website"\n',
                encoding='utf-8')
            built = list(plans(load(path)))
        self.assertTrue(built)
        for plan in built:
            self.assertEqual(plan.site_group, 'site-public-1')
            self.assertEqual(plan.profile_type, 'public_website')

    def test_a_scenario_without_a_site_says_nothing_rather_than_guessing(self):
        """Silence, not a default. Putting traffic in a bucket nobody chose and
        then reporting a number about that bucket is worse than reporting none."""
        built = list(plans(load()))
        self.assertTrue(built)
        for plan in built[:20]:
            self.assertEqual(plan.site_group, '')
            self.assertEqual(plan.profile_type, '')


if __name__ == '__main__':
    unittest.main()
