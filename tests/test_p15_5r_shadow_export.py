"""Evidence somebody else can evaluate. P15.5R §8, §9, §10, §11.

### The assertion that matters most

§9 forbids the export from labelling itself. Every row carries `label`,
`label_source` and `label_confidence`, and all three stay null. That is not a
formality. An export that filled them in from `would_action` would produce a
training set whose labels *are* the thing being measured — a model that learns to
agree with itself, and a benchmark that cannot disagree with it.

So `TestTheExportNeverLabelsItself` runs the two opposite cases through the real
row builder and checks that a blocked decision and an allowed one are
indistinguishable in their label fields. If somebody later adds a convenience
that fills them in, that test is where it stops.

### Why this reads rows rather than files

Most of the file bounds — rotation, retention, the entry ceiling, permissions —
belong to `BoundedJsonlWriter` and are tested in `test_p15_5r_journal.py` against
the journal that shares it. Repeating them here would test the same code twice
and say nothing new. What is specific to the export is the *row*: what it
carries, what it refuses to carry, and how it behaves when it falls behind.
"""
import json
from pathlib import Path
import tempfile
import unittest

from eye_for_an_eye.autonomy.bounded_jsonl import WriterLimits
from eye_for_an_eye.autonomy.shadow_export import (EXPORT_SLOW_WRITE_SECONDS,
                                                   SHADOW_EXPORT_SCHEMA_VERSION,
                                                   ShadowExport, UNLABELLED, bucket)
from eye_for_an_eye.autonomy.shadow_export import from_config as export_from_config
from eye_for_an_eye.config import Config

from test_p15_5r_journal import FakeOutcome, FakeRecord

REPOSITORY = Path(__file__).resolve().parents[1]
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'


class ExportCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.path = Path(self._workspace.name) / 'shadow.jsonl'

    def export(self, **kwargs):
        export = ShadowExport(self.path, **kwargs)
        self.addCleanup(export.close)
        return export

    def rows(self):
        if not self.path.exists():
            return []
        return [json.loads(line) for line in
                self.path.read_text(encoding='utf-8').splitlines() if line.strip()]


class TestTheExportNeverLabelsItself(ExportCase):
    """§9. The one that must never be relaxed."""

    def test_the_label_fields_are_empty_on_a_blocked_decision(self):
        export = self.export()
        export.write(FakeOutcome(blocked=True))
        row = self.rows()[0]
        self.assertEqual(row['review'], UNLABELLED)
        self.assertIsNone(row['review']['label'])

    def test_the_label_fields_are_empty_on_an_allowed_decision(self):
        export = self.export()
        export.write(FakeOutcome(blocked=False))
        self.assertEqual(self.rows()[0]['review'], UNLABELLED)

    def test_a_block_and_an_allow_are_indistinguishable_in_their_labels(self):
        """The property stated directly: the decision does not leak into the
        label by any route, including a helpful default."""
        export = self.export()
        export.write(FakeOutcome(blocked=True))
        export.write(FakeOutcome(blocked=False))
        blocked, allowed = self.rows()
        self.assertEqual(blocked['review'], allowed['review'])
        self.assertNotEqual(blocked['would_action'], allowed['would_action'])

    def test_no_row_contains_the_words_malicious_or_benign(self):
        """A label by another name is still a label."""
        export = self.export()
        export.write(FakeOutcome(blocked=True))
        text = self.path.read_text(encoding='utf-8').lower()
        for word in ('"malicious"', '"benign"', '"attack"', '"legitimate"'):
            with self.subTest(word=word):
                self.assertNotIn(word, text)

    def test_the_row_says_out_loud_that_it_is_unlabelled(self):
        export = self.export()
        export.write(FakeOutcome())
        policy = self.rows()[0]['label_policy']
        self.assertIn('never ground truth', policy)


class TestTheRowIsDerivedFromTheDecision(ExportCase):
    """§8. Everything present, nothing recomputed."""

    def test_the_conceptual_fields_are_all_present(self):
        export = self.export()
        export.write(FakeOutcome(), component_health={'calibrator': 'HEALTHY'})
        row = self.rows()[0]
        for key in ('shadow_export_schema_version', 'decision_id',
                    'timestamp_bucket', 'source_pseudonym', 'site_pseudonym',
                    'profile_type', 'features', 'math_risk',
                    'calibrated_probability', 'conservative_probability',
                    'ood_status', 'evidence_families', 'maturity',
                    'expected_loss', 'policy_guard', 'would_action',
                    'actual_action', 'component_health', 'review'):
            with self.subTest(field=key):
                self.assertIn(key, row)
        self.assertEqual(row['shadow_export_schema_version'],
                         SHADOW_EXPORT_SCHEMA_VERSION)

    def test_the_values_come_from_the_decision_rather_than_being_recomputed(self):
        outcome = FakeOutcome()
        decision = outcome.record.explain()
        export = self.export()
        export.write(outcome)
        row = self.rows()[0]
        self.assertEqual(row['decision_id'], outcome.record.decision_id)
        self.assertEqual(row['math_risk'], decision['math']['risk'])
        self.assertEqual(row['conservative_probability'],
                         decision['cost']['conservative_probability'])
        self.assertEqual(row['evidence_families'],
                         decision['evidence']['signal_families'])
        self.assertEqual(row['expected_loss']['threshold'],
                         decision['cost']['threshold'])

    def test_would_and_actual_are_separate_fields(self):
        """In shadow they differ, and the difference is the point."""
        export = self.export()
        export.write(FakeOutcome(blocked=True))
        row = self.rows()[0]
        self.assertEqual(row['would_action'], 'TEMP_BLOCK')
        self.assertEqual(row['actual_action'], 'NONE')
        self.assertTrue(row['shadow'])
        self.assertEqual(row['enforcement_withheld'], 'shadow_mode')

    def test_the_component_health_of_the_moment_is_carried(self):
        export = self.export()
        export.write(FakeOutcome(),
                     component_health={'auxiliary_ml': 'UNAVAILABLE',
                                       'calibrator': 'HEALTHY'})
        self.assertEqual(self.rows()[0]['component_health'],
                         {'auxiliary_ml': 'UNAVAILABLE', 'calibrator': 'HEALTHY'})


class TestExportPrivacy(ExportCase):
    """§8's "privacy-safe", checked rather than asserted in prose."""

    def test_the_raw_address_is_never_present_at_any_setting(self):
        """Unlike the journal, which has an opt-in. There is no setting that
        puts an address in an analytic row meant to be aggregated and shipped."""
        export = self.export()
        export.write(FakeOutcome())
        text = self.path.read_text(encoding='utf-8')
        self.assertNotIn('198.51.100.23', text)
        self.assertNotIn('"source"', text)
        self.assertIn('src-4f2a9c18bb3e77d0', text)

    def test_the_timestamp_is_coarsened(self):
        export = self.export()
        export.write(FakeOutcome())
        row = self.rows()[0]
        self.assertEqual(row['timestamp_bucket'], '2026-09-19T00:00:00+00:00')
        self.assertEqual(row['bucket_seconds'], 3600)

    def test_a_precise_timestamp_never_reaches_the_row(self):
        record = FakeRecord()
        outcome = FakeOutcome(record=record)
        export = self.export()
        row = export.row(outcome)
        self.assertNotIn('timestamp', row)
        self.assertNotIn('2026-09-19T00:00:00+00:00'[:19] + '.', json.dumps(row))

    def test_bucketing_is_an_hour_by_default_and_configurable(self):
        self.assertEqual(bucket('2026-09-19T13:47:31+00:00'),
                         '2026-09-19T13:00:00+00:00')
        self.assertEqual(bucket('2026-09-19T13:47:31+00:00', size=86400),
                         '2026-09-19T00:00:00+00:00')

    def test_bucketing_refuses_nonsense_rather_than_inventing_a_time(self):
        self.assertIsNone(bucket('not a timestamp'))
        self.assertIsNone(bucket(None))

    def test_a_site_is_carried_as_a_pseudonym(self):
        outcome = FakeOutcome()
        outcome.resolution.site_id = 'customer-one'
        export = self.export(secret=b'a' * 32)
        row = export.row(outcome)
        self.assertTrue(row['site_pseudonym'].startswith('src-'))
        self.assertNotIn('customer-one', json.dumps(row))

    def test_no_site_means_no_pseudonym_rather_than_a_fabricated_one(self):
        export = self.export()
        self.assertIsNone(export.row(FakeOutcome())['site_pseudonym'])


class TestExportBackpressure(ExportCase):
    """§11. If the export falls behind, the runtime wins."""

    def test_a_slow_write_trips_a_bounded_cooling_off_period(self):
        clock = [0.0]

        def monotonic():
            return clock[0]

        export = self.export(limits=WriterLimits(slow_write_seconds=0.001,
                                                 cooldown_seconds=30.0))
        export.writer.monotonic = monotonic
        # The first write "takes" a second, because the clock moves under it.
        real_write = export.writer._write

        def slow(document):
            clock[0] += 1.0
            return real_write(document)

        export.writer._write = slow
        self.assertTrue(export.write(FakeOutcome()))
        self.assertEqual(export.counters['slow_writes'], 1)
        self.assertTrue(export.writer.cooling)

        export.writer._write = real_write
        self.assertFalse(export.write(FakeOutcome()),
                         'a write landed during the cooling-off period')
        self.assertEqual(export.counters['dropped_backpressure'], 1)

        clock[0] += 31.0
        self.assertFalse(export.writer.cooling)
        self.assertTrue(export.write(FakeOutcome()))

    def test_dropping_is_counted_and_visible_rather_than_silent(self):
        export = self.export(limits=WriterLimits(slow_write_seconds=0.001,
                                                 cooldown_seconds=30.0))
        export.writer._cooling_until = export.writer.monotonic() + 30
        export.write(FakeOutcome())
        status = export.status()
        self.assertTrue(status['cooling_off'])
        self.assertEqual(status['status'], 'DEGRADED')
        self.assertEqual(status['counters']['dropped_backpressure'], 1)
        self.assertEqual(export.metrics()['shadow_export_dropped_total'], 1)

    def test_the_export_is_less_patient_than_the_journal(self):
        """§25's priority order, expressed as two budgets rather than a comment."""
        from eye_for_an_eye.autonomy.journal import JOURNAL_SLOW_WRITE_SECONDS
        self.assertLess(EXPORT_SLOW_WRITE_SECONDS, JOURNAL_SLOW_WRITE_SECONDS)

    def test_an_unwritable_path_fails_without_raising(self):
        export = ShadowExport(Path('/proc/version/shadow.jsonl'))
        self.addCleanup(export.close)
        self.assertFalse(export.write(FakeOutcome()))
        self.assertEqual(export.counters['failed'], 1)
        self.assertEqual(export.status()['status'], 'DEGRADED')


class TestExportFormat(ExportCase):
    """§10. Easy to inspect, hash, validate and import."""

    def test_every_row_is_one_independently_parseable_json_line(self):
        export = self.export()
        for _ in range(5):
            export.write(FakeOutcome())
        raw = self.path.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(raw), 5)
        for line in raw:
            with self.subTest():
                self.assertIn('shadow_export_schema_version', json.loads(line))

    def test_the_file_hashes_stably(self):
        import hashlib
        export = self.export()
        for _ in range(3):
            export.write(FakeOutcome())
        first = hashlib.sha256(self.path.read_bytes()).hexdigest()
        second = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(first, second)

    def test_every_row_declares_its_schema_version(self):
        export = self.export()
        export.write(FakeOutcome())
        self.assertEqual(self.rows()[0]['shadow_export_schema_version'],
                         SHADOW_EXPORT_SCHEMA_VERSION)

    def test_the_file_is_not_readable_by_the_group(self):
        import os
        export = self.export()
        export.write(FakeOutcome())
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)


class TestExportFromConfig(ExportCase):
    def test_off_by_default(self):
        self.assertIsNone(export_from_config(Config()))

    def test_the_configured_path_and_bounds_are_used(self):
        config = Config()
        config.autonomy.shadow_export_path = str(self.path)
        config.autonomy.shadow_export_max_files = 3
        config.autonomy.shadow_export_bucket_seconds = 86400
        export = export_from_config(config)
        self.addCleanup(export.close)
        self.assertEqual(str(export.path), str(self.path))
        self.assertEqual(export.writer.limits.max_files, 3)
        self.assertEqual(export.timestamp_bucket, 86400)


class TestTheExportIsNotASecondDataPath(unittest.TestCase):
    """§8, structurally. One decision, two sinks — never two decisions."""

    def test_the_export_is_written_from_the_same_outcome_as_the_journal(self):
        import ast
        import inspect
        from eye_for_an_eye.autonomy import pipeline

        source = inspect.getsource(pipeline.AutonomousDecisionPipeline.decide)
        tree = ast.parse(source.lstrip())
        calls = {node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertIn('_journal', calls)
        self.assertIn('_export', calls)
        # And only one authority call, so both sinks describe the same decision.
        decisions = [node for node in ast.walk(tree)
                     if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute)
                     and node.func.attr == 'decide']
        self.assertEqual(len(decisions), 1,
                         'the pipeline decides more than once per window; the '
                         'journal and the export could describe different things')

    def test_the_export_module_recomputes_nothing(self):
        """It may read the record. It may not run an engine."""
        import ast
        from pathlib import Path as _Path
        source = (_Path(__file__).resolve().parents[1] / 'eye_for_an_eye' /
                  'autonomy' / 'shadow_export.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or '')
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for forbidden in ('math_risk', 'families', 'composition', 'calibration',
                          'authority', 'uncertainty', 'maturity'):
            with self.subTest(module=forbidden):
                self.assertFalse(any(forbidden in name for name in imported),
                                 f'the export imports {forbidden}; it would be '
                                 f'a second opinion rather than a record of the '
                                 f'first')


if __name__ == '__main__':
    unittest.main()
