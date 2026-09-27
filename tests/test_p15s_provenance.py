"""A row has to say where it came from. P15S §12, §13, §31.

Version 1 of the shadow export could not distinguish a row produced by a real
deployment from one produced by a controlled test against an owned asset. Both
are real runtime evidence and only one of them is *benign population* evidence,
so mixing them does not merely blur a result -- it puts a deliberate scan into
the denominator of the false-block rate, which is the number the whole release
decision rests on.

Reconstructing the split afterwards from timestamps is not an answer. It
depends on somebody recording the test window accurately, in another file, and
it fails silently when they do not.

### Two vocabularies, one of them not importable

`dataset/schema.py` already names these ideas: `SHADOW_UNLABELED`,
`shadow_export`, and an exclusion list that keeps provenance out of the model.
The export restates those constants rather than importing them, because
`dataset/` is a development tree and is **not installed with the package** -- a
sensor on a real deployment has no `dataset` module to import, and a test run
from the repository root would never notice.

So the constants are duplicated on purpose, and these tests are the reason that
is safe: they compare the two, and a drift fails here rather than producing
evidence the dataset tooling silently refuses to ingest.
"""
import json
from pathlib import Path
import tempfile
import unittest

from eye_for_an_eye.autonomy.shadow_export import (
    COLLECTIONS, CONTROLLED_POSITIVE, INGESTION, LABEL_AUTHORITY,
    PROVENANCE_KEYS, REAL_SHADOW, SHADOW_EXPORT_SCHEMA_VERSION, SOURCE_TYPE,
    ShadowExport)
from eye_for_an_eye.config import Config

from tests.test_p15_5r_journal import FakeOutcome


class ExportCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)

    def export(self, **kwargs):
        export = ShadowExport(self.directory / 'export.jsonl', **kwargs)
        self.addCleanup(export.close)
        return export

    def rows(self, path=None):
        target = Path(path or (self.directory / 'export.jsonl'))
        return [json.loads(line) for line in
                target.read_text(encoding='utf-8').splitlines() if line.strip()]


class TestTheVocabularyMatchesTheDatasetSchema(unittest.TestCase):
    """The duplication is deliberate; the drift would not be.

    `dataset` is importable from the repository root, which is where these tests
    run. It is not importable from an installed sensor, which is why the export
    does not import it.
    """

    def setUp(self):
        try:
            from dataset import schema
        except ImportError:                                   # pragma: no cover
            self.skipTest('the dataset tree is not on the path')
        self.schema = schema

    def test_the_source_type_is_one_the_dataset_schema_knows(self):
        self.assertIn(SOURCE_TYPE, self.schema.SOURCE_TYPES)
        self.assertEqual(SOURCE_TYPE, self.schema.SHADOW_UNLABELED,
                         'the sensor never reviews anything, so every row it '
                         'writes is unlabelled shadow')

    def test_the_ingestion_mode_is_one_the_dataset_schema_knows(self):
        self.assertIn(INGESTION, self.schema.INGESTION_MODES)

    def test_the_sensor_never_writes_the_reviewed_source_type(self):
        """§9, §14. A label arrives from a person, never from this software.

        Asserted on what the export *writes*, not on whether the module
        mentions the constant. The first version of this test scanned the source
        for the string and failed on the comment explaining why the sensor never
        emits it -- a test whose easiest fix is deleting the clearest sentence in
        the file, which is the shape `tests/denial.py` exists to warn about.
        """
        self.assertNotEqual(SOURCE_TYPE, self.schema.SHADOW_REVIEWED)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reviewed.jsonl'
            export = ShadowExport(path)
            try:
                for collection in COLLECTIONS:
                    other = ShadowExport(Path(directory) / f'{collection}.jsonl',
                                         collection=collection)
                    try:
                        other.write(FakeOutcome())
                        rows = [json.loads(line) for line in
                                other.path.read_text(encoding='utf-8').splitlines()
                                if line.strip()]
                    finally:
                        other.close()
                    for row in rows:
                        with self.subTest(collection=collection):
                            self.assertNotEqual(row['provenance']['source_type'],
                                                self.schema.SHADOW_REVIEWED)
                            self.assertIsNone(row['review']['label'])
            finally:
                export.close()

    def test_no_provenance_key_may_become_a_model_feature(self):
        """§13, checked against the contract that enforces it.

        `NEVER_MODEL_INPUT` is the dataset's own exclusion list and
        `dataset/schema.py` refuses at import time if it intersects
        `MODEL_FEATURES`. What this asserts is the other direction: that nothing
        the export puts in `provenance` is a model feature.
        """
        features = set(self.schema.MODEL_FEATURES)
        for key in PROVENANCE_KEYS:
            with self.subTest(key=key):
                self.assertNotIn(key, features,
                                 f'{key} travels as provenance and is a model '
                                 f'feature; one of the two is wrong')


class TestEveryRowCarriesItsProvenance(ExportCase):
    def test_a_row_names_its_source_type_ingestion_and_label_authority(self):
        export = self.export()
        export.write(FakeOutcome())
        provenance = self.rows()[0]['provenance']
        self.assertEqual(provenance['source_type'], SOURCE_TYPE)
        self.assertEqual(provenance['ingestion'], INGESTION)
        self.assertEqual(provenance['label_authority'], LABEL_AUTHORITY)
        self.assertEqual(provenance['scenario_kind'], 'observed')

    def test_the_default_collection_is_real_shadow(self):
        export = self.export()
        export.write(FakeOutcome())
        self.assertEqual(self.rows()[0]['provenance']['collection'], REAL_SHADOW)

    def test_a_controlled_positive_row_says_so(self):
        export = self.export(collection=CONTROLLED_POSITIVE)
        export.write(FakeOutcome())
        self.assertEqual(self.rows()[0]['provenance']['collection'],
                         CONTROLLED_POSITIVE)

    def test_the_two_collections_are_distinguishable_in_the_file(self):
        """The whole point, stated as the question an evaluator asks."""
        real = ShadowExport(self.directory / 'real.jsonl', collection=REAL_SHADOW)
        test = ShadowExport(self.directory / 'test.jsonl',
                            collection=CONTROLLED_POSITIVE)
        self.addCleanup(real.close)
        self.addCleanup(test.close)
        real.write(FakeOutcome())
        test.write(FakeOutcome())
        collections = {self.rows(self.directory / name)[0]['provenance']['collection']
                       for name in ('real.jsonl', 'test.jsonl')}
        self.assertEqual(collections, {REAL_SHADOW, CONTROLLED_POSITIVE})

    def test_the_placement_and_segment_travel_with_the_row(self):
        export = self.export(sensor_placement='edge nginx, site A',
                             segment_id='shadow-real-v1-seg1')
        export.write(FakeOutcome())
        provenance = self.rows()[0]['provenance']
        self.assertEqual(provenance['sensor_placement'], 'edge nginx, site A')
        self.assertEqual(provenance['segment_id'], 'shadow-real-v1-seg1')

    def test_the_provenance_block_holds_nothing_else(self):
        """A bounded block, so a future field cannot arrive unnoticed."""
        export = self.export()
        export.write(FakeOutcome())
        self.assertEqual(sorted(self.rows()[0]['provenance']),
                         sorted(PROVENANCE_KEYS))

    def test_provenance_carries_no_address_or_content(self):
        """§11. The same rule the rest of the row obeys."""
        export = self.export(sensor_placement='198.51.100.7 edge',
                             segment_id='seg1')
        export.write(FakeOutcome())
        provenance = self.rows()[0]['provenance']
        # Placement is operator free text and this software cannot stop an
        # operator typing an address into it. What it can do is keep it out of
        # every field that is derived rather than typed, and say so.
        for key in ('source_type', 'ingestion', 'label_authority',
                    'collection', 'scenario_kind'):
            with self.subTest(key=key):
                self.assertNotIn('198.51.100.7', provenance[key])

    def test_the_collection_is_fixed_for_the_life_of_the_writer(self):
        """§46: changing it needs a restart, which starts a new segment."""
        export = self.export()
        self.assertFalse(hasattr(ShadowExport, 'set_collection'))
        export.write(FakeOutcome())
        export.write(FakeOutcome())
        self.assertEqual({row['provenance']['collection'] for row in self.rows()},
                         {REAL_SHADOW})


class TestAnUnknownCollectionIsRefused(ExportCase):
    """Refused, not defaulted. A default here is a silent contamination."""

    def test_the_writer_refuses_a_collection_it_does_not_know(self):
        with self.assertRaises(ValueError) as raised:
            ShadowExport(self.directory / 'x.jsonl', collection='benign')
        self.assertIn('unknown collection', str(raised.exception))

    def test_the_configuration_refuses_one_too(self):
        config = Config()
        config.autonomy.shadow_export_collection = 'REAL_SHADOW'
        with self.assertRaises(ValueError) as raised:
            config.validate()
        self.assertIn('shadow_export_collection', str(raised.exception))

    def test_the_shipped_default_validates(self):
        self.assertEqual(Config().autonomy.shadow_export_collection, REAL_SHADOW)
        Config().validate()

    def test_both_collections_are_accepted_by_configuration(self):
        for collection in COLLECTIONS:
            with self.subTest(collection=collection):
                config = Config()
                config.autonomy.shadow_export_collection = collection
                config.validate()


class TestFromConfig(ExportCase):
    def test_the_configured_provenance_reaches_the_row(self):
        from eye_for_an_eye.autonomy.shadow_export import from_config
        config = Config()
        config.autonomy.shadow_export_path = str(self.directory / 'configured.jsonl')
        config.autonomy.shadow_export_collection = CONTROLLED_POSITIVE
        config.autonomy.shadow_export_placement = 'lab host'
        config.autonomy.shadow_export_segment = 'seg-7'
        export = from_config(config)
        self.addCleanup(export.close)
        export.write(FakeOutcome())
        provenance = self.rows(self.directory / 'configured.jsonl')[0]['provenance']
        self.assertEqual(provenance['collection'], CONTROLLED_POSITIVE)
        self.assertEqual(provenance['sensor_placement'], 'lab host')
        self.assertEqual(provenance['segment_id'], 'seg-7')


class TestTheSchemaVersionWasBumped(ExportCase):
    """A version 1 row has no provenance, and must not be read as if it had.

    An additive change would have left a reader unable to tell "this row came
    from a deployment" from "this row predates the field", and the safe reading
    of the second is not the first.
    """

    def test_the_version_is_two(self):
        self.assertEqual(SHADOW_EXPORT_SCHEMA_VERSION, 2)

    def test_every_row_declares_it(self):
        export = self.export()
        export.write(FakeOutcome())
        self.assertEqual(self.rows()[0]['shadow_export_schema_version'], 2)

    def test_the_bump_is_documented(self):
        page = (Path(__file__).resolve().parents[1] / 'docs'
                / 'SCHEMA_COMPATIBILITY.md').read_text(encoding='utf-8')
        self.assertIn('autonomy.shadow_export.SHADOW_EXPORT_SCHEMA_VERSION', page)
        self.assertIn('| 2 |', page,
                      'the compatibility page still shows version 1 for the export')


if __name__ == '__main__':
    unittest.main()
