"""The canonical decision record, and the line it no longer has to fit in.

P15.5R §1-§7.

### The defect this file exists to keep fixed

`serialize_event` refuses any log record over 4096 bytes and replaces its
observations with `{'record_truncated': True}` — the whole record, not the
verbose parts. A full `AutonomousDecisionRecord` serialises to roughly 3.5 KB
before it is wrapped in an event, so the richest decisions were exactly the ones
that lost everything: the action, the address, the reasons, all of it, replaced
by a flag saying something had been there.

So the two jobs were separated. `TestTheOperationalLogStaysBounded` asserts the
line is small. `TestTheJournalIsCanonical` asserts the full record survives.
Neither is interesting alone: the log was already bounded before this cycle, by
throwing the evidence away.

### What is asserted about privacy, and why that shape

Not "today's record contains no secrets" — that is true and would pass forever
without testing anything. What is asserted is that the *sanitiser* refuses a
sensitive field name wherever it appears, at any depth, so the day somebody adds
one to the record the journal does not quietly persist it.
"""
import json
from pathlib import Path
import os
import tempfile
import unittest

from eye_for_an_eye.autonomy.journal import (DecisionJournal, FORBIDDEN_MARKER,
                                             JOURNAL_SCHEMA_VERSION, JournalLimits,
                                             MAX_ENTRY_BYTES, sanitise)
from eye_for_an_eye.autonomy.journal import from_config as journal_from_config
from eye_for_an_eye.autonomy.pipeline import from_config as pipeline_from_config
from eye_for_an_eye.config import Config
from eye_for_an_eye.logging import serialize_event

REPOSITORY = Path(__file__).resolve().parents[1]
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'

#: `serialize_event`'s own ceiling, named here so a change to it fails this file
#: rather than silently changing what "bounded" means.
LOG_LINE_LIMIT = 4096


class FakeProfile:
    name = 'public_website'
    threshold = 0.975610
    network_block_permitted = True


class FakeResolution:
    scope = 'GLOBAL'
    site_id = ''
    profile = FakeProfile()

    def explain(self):
        return {'scope': self.scope, 'cost_profile': self.profile.name,
                'threshold': self.profile.threshold}


class FakeRecord:
    """A decision record shaped like the real one, sized like the worst one.

    Built rather than captured so the size is deliberate: `families` and
    `reason_codes` here are at the bounds the real record allows, which is what
    "a very complex decision" means in §7.
    """

    def __init__(self, *, extra=None, blocked=True):
        self.decision_id = 'dec-0123456789abcdef01'
        self.action = 'TEMP_BLOCK' if blocked else 'ALLOW'
        self.blocked = blocked
        self.shadow = True
        self.enforced = False
        self.block_ttl_seconds = 43_200
        self.reason_codes = tuple(f'REASON_CODE_NUMBER_{n:02d}' for n in range(24))
        self.failed_assumptions = ('feature_schema_supported', 'clock_sane')
        self.calibrated_probability = 0.999886
        self.conservative_probability = 0.994779
        self.signal_diversity = 6
        self.behavioural_diversity = 4
        self.evidence_band = 'STRONG'
        self.source = '198.51.100.23'
        self.source_pseudonym = 'src-4f2a9c18bb3e77d0'
        self._extra = dict(extra or {})

    def explain(self):
        body = {
            'record_version': 1,
            'decision_id': self.decision_id,
            'timestamp': '2026-09-19T00:00:00+00:00',
            'mode': 'shadow', 'shadow': True, 'enforced': False,
            'scope': 'GLOBAL', 'site_id': '',
            'source': self.source, 'source_pseudonym': self.source_pseudonym,
            'identity': {'confidence': 'HIGH', 'origin': 'direct_peer',
                         'network_enforceable': True,
                         'enforcement_scope': 'NETWORK_SOURCE'},
            'features': {'schema_version': 2, 'observations': 240,
                         'observation_seconds': 612.5, 'data_quality': 0.91},
            'math': {'risk': 0.998578, 'version': 'math-risk-v4',
                     'contributions': {f'feature_number_{n:02d}': round(0.01 * n, 5)
                                       for n in range(23)},
                     'web_risk': None, 'persistence': 0.874},
            'model': {'version': 'none', 'status': 'not_loaded', 'score': None,
                      'calibrated': True,
                      'calibrated_probability': self.calibrated_probability,
                      'calibration_version': 'mathrisk-cal-v4-isotonic',
                      'anomaly_score': None, 'ood_score': None,
                      'ood_status': 'INSUFFICIENT_REFERENCE',
                      'drift_status': 'STABLE', 'health': 'UNKNOWN'},
            'evidence': {'signal_families': {f'FAMILY_NUMBER_{n:02d}': round(0.05 * n, 4)
                                             for n in range(10)},
                         'signal_diversity': self.signal_diversity,
                         'behavioural_diversity': self.behavioural_diversity,
                         'band': self.evidence_band},
            'uncertainty': {f'component_{n:02d}': round(0.03 * n, 5) for n in range(8)},
            'cost': {'profile': 'public_website', 'policy_version': 'cost-policy-v1',
                     'policy_digest': 'b0b45ea9a51b08c7' * 4, 'threshold': 0.97561,
                     'decision_margin': 0.25, 'probability': 0.999886,
                     'conservative_probability': self.conservative_probability,
                     'loss_allow': 0.994779, 'loss_block': 0.020884},
            'gates': {f'gate_number_{n:02d}': True for n in range(14)},
            'assumptions': {'failed': list(self.failed_assumptions),
                            'failed_subsystems': ['calibration']},
            'policy_guard': {'action': 'ALLOW',
                             'reasons': [f'guard_reason_{n:02d}' for n in range(8)]},
            'action': self.action,
            'block_ttl_seconds': self.block_ttl_seconds,
            'offence_count': 2,
            'reason_codes': list(self.reason_codes),
            'limitations': ['behaviour is not identity',
                            'an address is not a person',
                            'a block is never a training label',
                            'autonomy is an operational property, not an accuracy claim'],
        }
        body.update(self._extra)
        return body


class FakeOutcome:
    def __init__(self, record=None, **kwargs):
        self.record = record or FakeRecord(**kwargs)
        self.resolution = FakeResolution()
        self.calibrated = True
        self.execution = None
        self.enforcement_withheld = 'shadow_mode'

    @property
    def blocked(self):
        return self.record.blocked

    @property
    def enforced(self):
        return False

    def explain(self):
        return {'pipeline_version': 'autonomous-decision-pipeline-v1',
                'decision': self.record.explain(),
                'cost_scope': self.resolution.explain(),
                'calibrated': self.calibrated,
                'enforcement_withheld': self.enforcement_withheld,
                'policy_guard_version': 'policy-guard-v1'}

    def summary(self):
        from eye_for_an_eye.autonomy.pipeline import PipelineOutcome
        return PipelineOutcome.summary(self)


class JournalCase(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.path = Path(self._workspace.name) / 'decisions.jsonl'

    def journal(self, **kwargs):
        journal = DecisionJournal(self.path, **kwargs)
        self.addCleanup(journal.close)
        return journal

    def lines(self, path=None):
        target = Path(path or self.path)
        if not target.exists():
            return []
        return [json.loads(line) for line in
                target.read_text(encoding='utf-8').splitlines() if line.strip()]


class TestTheJournalIsCanonical(JournalCase):
    """§2, §3."""

    def test_a_complete_record_is_written_as_one_json_line(self):
        journal = self.journal()
        self.assertTrue(journal.write(FakeOutcome()))
        lines = self.lines()
        self.assertEqual(len(lines), 1)
        entry = lines[0]
        self.assertEqual(entry['journal_schema_version'], JOURNAL_SCHEMA_VERSION)
        decision = entry['entry']['decision']
        for section in ('identity', 'features', 'math', 'model', 'evidence',
                        'uncertainty', 'cost', 'gates', 'assumptions',
                        'policy_guard'):
            with self.subTest(section=section):
                self.assertIn(section, decision)
        self.assertEqual(len(decision['reason_codes']), 24)
        self.assertEqual(len(decision['math']['contributions']), 23)

    def test_entries_append_rather_than_replace(self):
        journal = self.journal()
        for _ in range(5):
            journal.write(FakeOutcome())
        self.assertEqual(len(self.lines()), 5)

    def test_every_line_parses_independently(self):
        """JSONL's whole value: a reader can skip a damaged line rather than
        losing the file."""
        journal = self.journal()
        for _ in range(3):
            journal.write(FakeOutcome())
        raw = self.path.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(raw), 3)
        for line in raw:
            with self.subTest():
                json.loads(line)

    def test_the_file_is_not_readable_by_the_group(self):
        journal = self.journal()
        journal.write(FakeOutcome())
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode, 0o600, f'journal mode is {oct(mode)}')


class TestTheOperationalLogStaysBounded(JournalCase):
    """§1, §7. The regression test the brief asks for, both halves."""

    def _decision_event(self, outcome):
        from eye_for_an_eye.event_types import EventType
        from eye_for_an_eye.events import NetworkEvent
        return NetworkEvent(
            '198.51.100.23', event_type=EventType.DECISION,
            observations={'decision_version': 1, 'feature_schema_version': 2,
                          'action': 'TEMP_BLOCK', 'proposed_action': 'TEMP_BLOCK',
                          'risk': 0.91, 'math_score': 0.998578,
                          'math_version': 'math-risk-v4',
                          'sample_count': 240, 'observation_seconds': 612.5,
                          'would_enforce': True, 'enforced': False,
                          'block_seconds': 0,
                          'policy_reasons': ['insufficient_data_quality'],
                          'disagreement': 'none',
                          'autonomous': outcome.summary()})

    def test_a_very_complex_decision_survives_in_full_in_the_journal(self):
        journal = self.journal()
        outcome = FakeOutcome()
        self.assertTrue(journal.write(outcome))
        decision = self.lines()[0]['entry']['decision']
        self.assertEqual(decision['decision_id'], outcome.record.decision_id)
        self.assertEqual(decision['action'], 'TEMP_BLOCK')
        self.assertEqual(sorted(decision['reason_codes']),
                         sorted(outcome.record.reason_codes))

    def test_the_same_decision_fits_one_operational_log_line(self):
        line = serialize_event(self._decision_event(FakeOutcome()))
        self.assertLessEqual(len(line), LOG_LINE_LIMIT,
                             f'the summary is {len(line)} bytes')
        body = json.loads(line)
        self.assertNotIn('record_truncated', body['observations'])

    def test_the_summary_still_answers_why_this_was_blocked(self):
        """Bounded is easy. Bounded *and* accountable is the requirement."""
        body = json.loads(serialize_event(self._decision_event(FakeOutcome())))
        summary = body['observations']['autonomous']
        self.assertEqual(summary['action'], 'TEMP_BLOCK')
        self.assertTrue(summary['decision_id'])
        self.assertEqual(summary['cost_profile'], 'public_website')
        self.assertEqual(summary['threshold'], 0.97561)
        self.assertEqual(summary['conservative_probability'], 0.994779)
        self.assertTrue(summary['reason_codes'])
        self.assertIn('full_record', summary)

    def test_the_full_record_in_the_event_is_still_truncated(self):
        """The defect itself, demonstrated through the real serialiser.

        The claim is not that a decision record is larger than 4096 bytes on
        its own — it is close to that line and would drift across it. The claim
        is that a DECISION *event* carrying one does not fit.

        And the ceiling turns out to be lower in the stack than the logger.
        `NetworkEvent.to_json` has the same 4096-byte budget and the same
        answer, so an oversized decision event is truncated **on the way into
        the queue**, before any logger or store sees it. That is not a logging
        limitation to be raised: it is the event frame budget the whole pipeline
        is accounted against. A decision that cannot travel as an event cannot
        be a decision the runtime emits, which is why the summary is the design
        rather than a workaround.

        Asserted rather than remembered, so "the summary is necessary" stays a
        property this suite checks instead of a paragraph somebody wrote once.
        """
        outcome = FakeOutcome()
        event = self._decision_event(outcome)
        event.observations['autonomous'] = outcome.explain()
        body = json.loads(serialize_event(event))
        self.assertEqual(body['observations'], {'record_truncated': True},
                         'the full record now fits, and the separation between '
                         'the log summary and the journal should be re-argued '
                         'on that evidence rather than assumed')
        self.assertIn('record_limit', body['limitations'])

    def test_the_truncation_happens_in_the_event_not_only_in_the_logger(self):
        """Where the ceiling actually is, because it changes what the fix is."""
        outcome = FakeOutcome()
        event = self._decision_event(outcome)
        event.observations['autonomous'] = outcome.explain()
        encoded = json.loads(event.to_json())
        self.assertEqual(encoded['observations'], {'record_truncated': True})
        self.assertEqual(encoded['limitations'], ['record_limit'])

    def test_the_summarised_event_travels_intact(self):
        encoded = json.loads(self._decision_event(FakeOutcome()).to_json())
        self.assertNotIn('record_truncated', encoded['observations'])
        self.assertEqual(encoded['observations']['autonomous']['action'],
                         'TEMP_BLOCK')


class TestTheEntryExplainsItselfWithoutTheExport(JournalCase):
    """P15S §7. A canonical record that needs a second file is not canonical.

    Until this was fixed the journal entry for a shadow TEMP_BLOCK carried
    `enforcement_withheld = ""`. The reason was computed -- `_enforce` returns
    `shadow_mode` -- but the entry is written *before* the enforcement decision
    and was only amended afterwards when an attempt had actually happened. In
    shadow no attempt happens, so the amendment never came and the canonical
    forensic record could not say why a block it had decided on did nothing.

    The information was recoverable by joining the export row on `decision_id`,
    which is why this was a gap rather than a loss. It was still the wrong
    place for it: the journal is the file this project calls canonical, in the
    mode every shadow deployment runs in.

    The repair is a recording change. `_withheld_before_attempt` answers the
    three cases where the answer is already known, and `_enforce` still decides,
    still counts, and still returns the same reason.
    """

    def outcome(self, *, blocked=True, shadow=True, enforcer=None):
        """A real `PipelineOutcome` through a real pipeline, not a fixture.

        The claim is about what `decide()` puts in the journal, so a fabricated
        outcome would assert the shape of the fixture rather than the behaviour
        of the pipeline.
        """
        from tests.test_p15_5r_journal import FakeRecord, FakeResolution
        from eye_for_an_eye.autonomy.pipeline import PipelineOutcome
        return PipelineOutcome(record=FakeRecord(blocked=blocked),
                               resolution=FakeResolution(), calibrated=True)

    def test_a_shadow_block_entry_names_shadow_mode_on_its_own(self):
        from eye_for_an_eye.autonomy.authority import SHADOW
        from eye_for_an_eye.autonomy.pipeline import from_config
        from eye_for_an_eye.config import Config
        config = Config()
        config.autonomy.enabled = True
        config.autonomy.mode = SHADOW
        config.autonomy.decision_journal_path = str(self.path)
        pipeline = from_config(config, attach_enforcer=False)
        self.addCleanup(pipeline.journal.close)
        self.assertTrue(pipeline.shadow)
        self.assertEqual(pipeline._withheld_before_attempt(_Blocked()), 'shadow_mode')

    def test_the_entry_carries_would_action_and_actual_action(self):
        journal = self.journal()
        journal.write(self.outcome(blocked=True))
        entry = self.lines()[0]['entry']
        self.assertEqual(entry['would_action'], 'TEMP_BLOCK')
        self.assertEqual(entry['actual_action'], 'NONE')

    def test_an_allowed_decision_says_so_too(self):
        journal = self.journal()
        journal.write(self.outcome(blocked=False))
        entry = self.lines()[0]['entry']
        self.assertEqual(entry['would_action'], 'ALLOW')
        self.assertEqual(entry['actual_action'], 'NONE')
        self.assertEqual(entry['enforcement_withheld'], '',
                         'an ALLOW withheld nothing because there was nothing to '
                         'withhold, and a reason here would be an invented one')

    def test_no_reason_is_invented_when_an_attempt_will_be_made(self):
        """The entry written before a real enforcement attempt stays bare.

        Guessing there would put a claim in the forensic record that the
        enforcer had not yet had a chance to contradict.
        """
        pipeline = _pipeline_that_will_enforce()
        self.assertEqual(pipeline._withheld_before_attempt(_Blocked()), '')

    def test_an_allow_withholds_nothing_because_there_was_nothing_to_withhold(self):
        pipeline = _pipeline_that_will_enforce()
        self.assertEqual(pipeline._withheld_before_attempt(_Allowed()), '')

    def test_a_missing_enforcer_is_named_rather_than_left_blank(self):
        from eye_for_an_eye.autonomy.authority import AUTONOMOUS
        from eye_for_an_eye.autonomy.pipeline import from_config
        from eye_for_an_eye.config import Config
        config = Config()
        config.autonomy.enabled = True
        config.autonomy.mode = AUTONOMOUS
        pipeline = from_config(config, attach_enforcer=False, attach_journal=False)
        self.assertFalse(pipeline.shadow)
        self.assertIsNone(pipeline.enforcer)
        self.assertEqual(pipeline._withheld_before_attempt(_Blocked()),
                         'no_host_enforcer_configured')

    def test_the_decision_itself_is_untouched(self):
        """P15S §7: recording only. Nothing about the decision may move."""
        journal = self.journal()
        journal.write(self.outcome(blocked=True))
        decision = self.lines()[0]['entry']['decision']
        self.assertEqual(decision['action'], 'TEMP_BLOCK')
        self.assertEqual(decision['math']['risk'], 0.998578)
        self.assertEqual(decision['model']['calibrated_probability'], 0.999886)
        self.assertEqual(decision['cost']['conservative_probability'], 0.994779)
        self.assertEqual(decision['cost']['threshold'], 0.97561)


class _Blocked:
    blocked = True
    action = 'TEMP_BLOCK'


class _Allowed:
    blocked = False
    action = 'ALLOW'


def _pipeline_that_will_enforce():
    """Autonomous, with an enforcer attached, so an attempt really would happen."""
    from eye_for_an_eye.autonomy.authority import AUTONOMOUS
    from eye_for_an_eye.autonomy.pipeline import from_config
    from eye_for_an_eye.config import Config

    class _Enforcer:
        has_firewall_privilege = False
        counters = {}

    config = Config()
    config.autonomy.enabled = True
    config.autonomy.mode = AUTONOMOUS
    pipeline = from_config(config, enforcer=_Enforcer(), attach_journal=False)
    assert pipeline.enforcer is not None
    return pipeline


class TestJournalPrivacy(JournalCase):
    """§4."""

    def test_the_raw_address_is_dropped_by_default(self):
        journal = self.journal()
        journal.write(FakeOutcome())
        decision = self.lines()[0]['entry']['decision']
        self.assertNotIn('source', decision)
        self.assertEqual(decision['source_pseudonym'], 'src-4f2a9c18bb3e77d0')

    def test_the_raw_address_is_kept_when_the_operator_asks(self):
        journal = self.journal(include_source=True)
        journal.write(FakeOutcome())
        decision = self.lines()[0]['entry']['decision']
        self.assertEqual(decision['source'], '198.51.100.23')

    def test_a_sensitive_field_name_is_refused_wherever_it_appears(self):
        """The guard against the day the record grows a field it should not."""
        for name in ('password', 'authorization', 'cookie', 'raw_token',
                     'credential_body', 'session_secret', 'api_key', 'payload'):
            with self.subTest(field=name):
                document = {'a': {'b': [{name: 'hunter2'}]}}
                self.assertEqual(sanitise(document)['a']['b'][0][name],
                                 FORBIDDEN_MARKER)

    def test_a_sensitive_field_never_reaches_the_file(self):
        journal = self.journal()
        journal.write(FakeOutcome(extra={'authorization': 'Bearer abcdef'}))
        text = self.path.read_text(encoding='utf-8')
        self.assertNotIn('Bearer', text)
        self.assertIn(FORBIDDEN_MARKER, text)

    def test_ordinary_derived_fields_are_untouched(self):
        journal = self.journal()
        journal.write(FakeOutcome())
        decision = self.lines()[0]['entry']['decision']
        self.assertEqual(decision['math']['version'], 'math-risk-v4')
        self.assertEqual(decision['cost']['conservative_probability'], 0.994779)
        self.assertEqual(decision['evidence']['signal_diversity'], 6)


class TestJournalBounds(JournalCase):
    """§5."""

    def test_a_full_file_rotates_rather_than_growing(self):
        journal = self.journal(limits=JournalLimits(max_file_bytes=8192, max_files=3,
                                                    max_total_bytes=65_536))
        for _ in range(12):
            journal.write(FakeOutcome())
        self.assertGreater(journal.counters['rotated'], 0)
        self.assertLessEqual(self.path.stat().st_size, 8192 + MAX_ENTRY_BYTES)
        self.assertTrue(self.path.with_name(self.path.name + '.1').exists())

    def test_the_file_count_is_capped(self):
        journal = self.journal(limits=JournalLimits(max_file_bytes=4096, max_files=2,
                                                    max_total_bytes=65_536))
        for _ in range(30):
            journal.write(FakeOutcome())
        present = [p for p in Path(self._workspace.name).iterdir()]
        self.assertLessEqual(len(present), 2, [p.name for p in present])

    def test_the_total_byte_budget_holds_whatever_the_others_are(self):
        journal = self.journal(limits=JournalLimits(max_file_bytes=4096, max_files=8,
                                                    max_total_bytes=12_288))
        for _ in range(60):
            journal.write(FakeOutcome())
        total = sum(p.stat().st_size for p in Path(self._workspace.name).iterdir())
        self.assertLessEqual(total, 12_288 + MAX_ENTRY_BYTES, total)

    def test_the_record_count_rotates_too(self):
        journal = self.journal(limits=JournalLimits(max_records=3))
        for _ in range(7):
            journal.write(FakeOutcome())
        self.assertGreater(journal.counters['rotated'], 0)
        self.assertLessEqual(len(self.lines()), 3)

    def test_an_absurdly_large_entry_is_refused_not_written(self):
        journal = self.journal()
        huge = FakeOutcome(extra={'blob': 'x' * (MAX_ENTRY_BYTES + 1)})
        self.assertFalse(journal.write(huge))
        self.assertEqual(journal.counters['refused_too_large'], 1)
        self.assertEqual(self.lines(), [])

    def test_impossible_limits_are_refused_at_construction(self):
        for kwargs in ({'max_file_bytes': 10}, {'max_files': 0},
                       {'max_total_bytes': 1}, {'max_records': 0}):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    JournalLimits(**kwargs)


class TestJournalFailure(JournalCase):
    """§6. A journal problem is never a firewall problem."""

    def test_a_write_to_an_unwritable_path_fails_without_raising(self):
        journal = DecisionJournal(Path('/proc/version/decisions.jsonl'))
        self.addCleanup(journal.close)
        self.assertFalse(journal.write(FakeOutcome()))
        self.assertEqual(journal.counters['failed'], 1)
        self.assertTrue(journal.last_error)
        self.assertEqual(journal.status()['status'], 'DEGRADED')

    def test_repeated_failure_does_not_raise_or_grow_unbounded_state(self):
        journal = DecisionJournal(Path('/proc/version/decisions.jsonl'))
        self.addCleanup(journal.close)
        for _ in range(50):
            journal.write(FakeOutcome())
        self.assertEqual(journal.counters['failed'], 50)
        self.assertLessEqual(len(journal.last_error), 200)

    def test_by_default_a_failed_journal_does_not_stop_enforcement(self):
        """The documented choice, asserted so it cannot drift silently.

        The accountable minimum survives in the operational log either way, and
        nothing in this project's policy makes durable auditability a
        precondition for acting.
        """
        config = self._config(journal_path='/proc/version/decisions.jsonl')
        pipeline = pipeline_from_config(config)
        self.addCleanup(pipeline.close)
        self.assertFalse(pipeline._journal_gates_action())

    def test_an_operator_can_require_the_journal_before_enforcing(self):
        config = self._config(journal_path='/proc/version/decisions.jsonl')
        config.autonomy.journal_required_for_action = True
        pipeline = pipeline_from_config(config)
        self.addCleanup(pipeline.close)
        self.assertTrue(pipeline._journal_gates_action())

    def test_no_journal_configured_is_not_a_failure(self):
        pipeline = pipeline_from_config(self._config(journal_path=''))
        self.addCleanup(pipeline.close)
        self.assertIsNone(pipeline.journal)
        self.assertFalse(pipeline._journal_gates_action())
        self.assertEqual(pipeline.health()['components']['decision_journal'],
                         'NOT_CONFIGURED')

    def _config(self, *, journal_path):
        config = Config()
        config.decision.enabled = True
        config.autonomy.enabled = True
        config.autonomy.mode = 'shadow'
        config.autonomy.calibrator_path = str(CALIBRATOR)
        config.autonomy.decision_journal_path = journal_path
        return config


class TestTheSelfCheckDoesNotJournal(JournalCase):
    """Its two fixtures are not decisions about anybody."""

    def test_doctor_leaves_no_synthetic_entries_behind(self):
        from eye_for_an_eye.autonomy import selfcheck
        config = Config()
        config.decision.enabled = True
        config.autonomy.enabled = True
        config.autonomy.mode = 'shadow'
        config.autonomy.calibrator_path = str(CALIBRATOR)
        config.autonomy.decision_journal_path = str(self.path)
        document = selfcheck.run(config=config)
        self.assertEqual(document['verdict'], selfcheck.WIRED, document['failures'])
        self.assertFalse(self.path.exists(),
                         'the self-check wrote synthetic fixtures into the '
                         'forensic journal')


class TestJournalFromConfig(JournalCase):
    def test_the_configured_path_and_bounds_are_used(self):
        config = Config()
        config.autonomy.decision_journal_path = str(self.path)
        config.autonomy.journal_max_files = 2
        config.autonomy.journal_max_file_bytes = 4096
        config.autonomy.journal_max_total_bytes = 8192
        config.autonomy.decision_journal_max_entries = 7
        journal = journal_from_config(config)
        self.addCleanup(journal.close)
        self.assertEqual(str(journal.path), str(self.path))
        self.assertEqual(journal.limits.max_files, 2)
        self.assertEqual(journal.limits.max_records, 7)

    def test_no_path_means_no_journal(self):
        config = Config()
        self.assertIsNone(journal_from_config(config))


if __name__ == '__main__':
    unittest.main()
