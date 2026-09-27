"""A full disk is a storage problem, not a defence outage. P15.5R §24-§26.

`tests/test_p15_5r_journal.py` and `tests/test_p15_5r_shadow_export.py` already
prove the *writer* behaves: it rotates, it refuses an oversized entry, it counts
a failure instead of raising, it stops writing when a write is slow. Those are
component claims about a component.

This file makes the system claim the components cannot make. §6 names four
things a journal write failure must not cause -- a random block, a service
outage, firewall corruption, a silently weaker policy -- and none of them is
visible from inside `BoundedJsonlWriter`, because none of them is about the
writer. They are about what the *sensor* does while the writer is failing.

### The failure is real, not mocked

`/dev/full` is a character device that accepts `open`, reports a size, and
returns `ENOSPC` from every `write`. Pointing the journal at it produces the
exact errno a full filesystem produces, from the kernel, in a test that needs no
privilege and patches nothing. Nothing here monkeypatches `os.write`: a test
that injects its own `OSError` proves that the code handles the exception the
test wrote, which is a weaker statement than it looks.

`/dev/full` fails from the first write, so it cannot show that the records
written *before* the disk filled survived. A real filesystem that fills up
partway through a run can, and `TestARealFilesystemFillingUpMidRun` does that on
a small tmpfs when the tests run as root.

### The bound

§24: bounded means bounded. The shedding policy here is a write deadline and a
cooling-off period, not a queue -- so the claim to prove is not "the queue has a
maximum" but "there is no queue", together with the disk ceiling holding under
sustained writing. Both are below.
"""
import collections
import errno
import json
import os
from pathlib import Path
import queue
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from eye_for_an_eye.autonomy.bounded_jsonl import BoundedJsonlWriter, WriterLimits
from eye_for_an_eye.autonomy.journal import DecisionJournal
from eye_for_an_eye.autonomy.shadow_export import ShadowExport
from eye_for_an_eye.event_types import EventType

from tests.test_p15_5r_journal import FakeOutcome

#: The kernel's own ENOSPC, with no privilege and no patching.
FULL_DEVICE = '/dev/full'

requires_full_device = unittest.skipUnless(
    sys.platform.startswith('linux') and os.path.exists(FULL_DEVICE),
    'the storage-full injection uses /dev/full, which is a Linux device')


def _scapy():
    try:
        import scapy.layers.inet  # noqa: F401
        return True
    except ImportError:
        return False


requires_packets = unittest.skipUnless(_scapy(), 'the traffic needs scapy to render')


# ---------------------------------------------------------------------------
# §24. There is no queue, and the disk has a ceiling.
# ---------------------------------------------------------------------------


class TestTheDecisionPathHoldsNoQueue(unittest.TestCase):
    """§24: bounded means bounded, and the strongest bound is absence.

    A bounded queue plus a writer thread would also satisfy §11, and would add
    a thread, a shutdown ordering problem and a new way to lose records without
    counting them. The design chose a deadline instead, so what there is to
    assert is that no queue and no thread appeared anyway.
    """

    UNBOUNDED = (queue.Queue, queue.SimpleQueue, collections.deque, threading.Thread)

    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)

    def _no_queues_in(self, obj, label):
        for name, value in vars(obj).items():
            with self.subTest(attribute=f'{label}.{name}'):
                self.assertNotIsInstance(
                    value, self.UNBOUNDED,
                    f'{label}.{name} is a {type(value).__name__}; the shedding '
                    f'policy here is a deadline, not a queue')

    def test_the_writer_the_journal_and_the_export_hold_no_queue(self):
        writer = BoundedJsonlWriter(self.directory / 'w.jsonl')
        journal = DecisionJournal(self.directory / 'j.jsonl')
        export = ShadowExport(self.directory / 'e.jsonl')
        self.addCleanup(writer.close)
        self.addCleanup(journal.close)
        self.addCleanup(export.close)
        for obj, label in ((writer, 'writer'), (journal, 'journal'),
                           (export, 'export'), (journal.writer, 'journal.writer'),
                           (export.writer, 'export.writer')):
            self._no_queues_in(obj, label)

    def test_building_a_journal_and_an_export_starts_no_thread(self):
        before = threading.active_count()
        journal = DecisionJournal(self.directory / 'j.jsonl')
        export = ShadowExport(self.directory / 'e.jsonl')
        self.addCleanup(journal.close)
        self.addCleanup(export.close)
        journal.write(FakeOutcome())
        export.write(FakeOutcome())
        self.assertEqual(threading.active_count(), before,
                         'a writer thread appeared; §24 asks for no queue and '
                         'this design has no thread to hold one')

    def test_sustained_writing_never_exceeds_the_disk_budget(self):
        limits = WriterLimits(max_file_bytes=4096, max_files=3,
                              max_total_bytes=12288, max_records=8)
        writer = BoundedJsonlWriter(self.directory / 'bounded.jsonl', limits=limits)
        self.addCleanup(writer.close)
        peak = 0
        for index in range(4000):
            writer.write({'index': index, 'padding': 'x' * 200})
            if index % 97 == 0:
                peak = max(peak, writer.total_bytes)
                self.assertLessEqual(writer.total_bytes, limits.max_total_bytes)
                self.assertLessEqual(len(writer.existing()), limits.max_files)
        self.assertGreater(writer.counters['rotated'], 100,
                           'nothing rotated, so the ceiling was never tested')
        self.assertLessEqual(writer.total_bytes, limits.max_total_bytes)
        self.assertGreater(peak, 0)

    @requires_full_device
    def test_the_writer_does_not_change_the_mode_of_something_it_did_not_create(self):
        """Found by running this file as root, which is how it should be found.

        `/dev/full` is 0666 on every Linux system and the writer narrowed it to
        0600, because it chmods whatever path it is given. Every later run of
        these tests as an ordinary user then failed with EACCES, and so would
        anything else on the machine that expected the device to work.

        The same code path applies to a fifo or a socket an operator pointed the
        journal at. A regular file is tightened on purpose -- it is a file of
        behaviour and should not belong to the group -- and nothing else is
        touched.
        """
        before = os.stat(FULL_DEVICE).st_mode
        writer = BoundedJsonlWriter(FULL_DEVICE)
        self.addCleanup(writer.close)
        writer.write({'index': 0})
        self.assertEqual(os.stat(FULL_DEVICE).st_mode, before,
                         'the writer changed the mode of a device node')

    def test_a_regular_file_is_still_tightened(self):
        """The other half: §4's privacy rule must not be lost to the guard."""
        path = self.directory / 'modes.jsonl'
        writer = BoundedJsonlWriter(path)
        self.addCleanup(writer.close)
        self.assertTrue(writer.write({'index': 0}))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    @requires_full_device
    def test_sustained_failure_never_grows_the_in_memory_state(self):
        """A disk that is full for an hour must not become a memory problem."""
        writer = BoundedJsonlWriter(FULL_DEVICE)
        self.addCleanup(writer.close)
        keys = set(writer.counters)
        for index in range(5000):
            self.assertFalse(writer.write({'index': index}))
        self.assertEqual(set(writer.counters), keys,
                         'the counter set grew, so something is accumulating a key')
        self.assertLessEqual(len(writer.last_error), 200)
        self.assertEqual(writer.counters['failed'], 5000)
        self.assertEqual(writer.counters['written'], 0)


class TestDoctorRefusesAnUnwritableEvidencePath(unittest.TestCase):
    """§24, §25: the configuration mistake, caught before the first decision.

    A journal pointed at a directory that does not exist behaves exactly like a
    full disk — every record counted as a failure — except that it is entirely
    preventable and the operator has no reason to suspect it. `doctor` is where
    that belongs, beside the other five autonomy checks.
    """

    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.directory = Path(self._workspace.name)

    def checks(self, **autonomy):
        from eye_for_an_eye.config import Config
        from eye_for_an_eye.operations import _autonomy_checks
        config = Config()
        config.autonomy.enabled = True
        config.autonomy.mode = 'shadow'
        for name, value in autonomy.items():
            setattr(config.autonomy, name, value)
        return _autonomy_checks(config)['checks']['evidence_files']

    def test_no_evidence_file_configured_is_healthy_not_a_fault(self):
        check = self.checks()
        self.assertEqual(check['status'], 'HEALTHY')
        self.assertIn('default', check['detail'])

    def test_a_writable_directory_is_healthy(self):
        check = self.checks(
            decision_journal_path=str(self.directory / 'decisions.jsonl'),
            shadow_export_path=str(self.directory / 'export.jsonl'))
        self.assertEqual(check['status'], 'HEALTHY')
        self.assertIn('advisory', check['detail'],
                      'a permission check that does not say it is one reads as a '
                      'guarantee that the write will succeed')

    def test_a_missing_directory_is_named_and_degrades(self):
        check = self.checks(
            decision_journal_path=str(self.directory / 'nowhere' / 'decisions.jsonl'))
        self.assertEqual(check['status'], 'DEGRADED')
        self.assertIn('journal', check['detail'])

    def test_each_unwritable_file_is_named_separately(self):
        check = self.checks(
            decision_journal_path=str(self.directory / 'nowhere' / 'decisions.jsonl'),
            shadow_export_path=str(self.directory / 'elsewhere' / 'export.jsonl'))
        self.assertEqual(check['status'], 'DEGRADED')
        self.assertIn('journal', check['detail'])
        self.assertIn('shadow export', check['detail'])

    def test_a_broken_export_does_not_condemn_a_working_journal_by_name(self):
        check = self.checks(
            decision_journal_path=str(self.directory / 'decisions.jsonl'),
            shadow_export_path=str(self.directory / 'elsewhere' / 'export.jsonl'))
        self.assertEqual(check['status'], 'DEGRADED')
        self.assertIn('shadow export', check['detail'])
        self.assertNotIn('journal:', check['detail'])


# ---------------------------------------------------------------------------
# §11, §24. Slow storage sheds; it does not make the caller wait.
# ---------------------------------------------------------------------------


class SlowWriter(BoundedJsonlWriter):
    """A writer whose backend is slow. The policy under test is in `write`.

    `_write` is the storage step and `write` is the deadline and the cooling-off
    around it, so overriding the former is how the latter gets exercised without
    needing a filesystem that can be made slow on demand.
    """

    def __init__(self, *args, delay=0.3, **kwargs):
        super().__init__(*args, **kwargs)
        self.delay = delay
        self.attempts = 0

    def _write(self, document):
        self.attempts += 1
        time.sleep(self.delay)
        return super()._write(document)


class TestSlowStorageShedsInsteadOfWaiting(unittest.TestCase):
    """§11: runtime availability wins. §24: the cost is bounded, per cooldown."""

    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        self.path = Path(self._workspace.name) / 'slow.jsonl'

    def writer(self, *, delay=0.3, cooldown=30.0):
        writer = SlowWriter(self.path, delay=delay,
                            limits=WriterLimits(slow_write_seconds=0.05,
                                                cooldown_seconds=cooldown))
        self.addCleanup(writer.close)
        return writer

    def test_one_slow_write_per_cooldown_rather_than_one_per_record(self):
        writer = self.writer(delay=0.3)
        started = time.monotonic()
        for index in range(50):
            writer.write({'index': index})
        elapsed = time.monotonic() - started

        self.assertEqual(writer.attempts, 1,
                         'the slow storage was touched more than once inside one '
                         'cooling-off period')
        self.assertEqual(writer.counters['slow_writes'], 1)
        self.assertEqual(writer.counters['dropped_backpressure'], 49)
        # 50 records at 0.3s each would be 15 seconds. The policy is one slow
        # write, so the bound is a small multiple of one -- generous, because
        # this asserts a policy and not this machine's speed.
        self.assertLess(elapsed, 3.0,
                        f'the decision path waited {elapsed:.2f}s on slow storage')

    def test_the_cooling_off_ends_and_the_writer_tries_again(self):
        writer = self.writer(delay=0.3, cooldown=0.4)
        writer.write({'index': 0})
        self.assertTrue(writer.cooling)
        for index in range(20):
            writer.write({'index': index})
        self.assertEqual(writer.attempts, 1, 'it retried inside the cooling-off period')
        time.sleep(0.45)
        self.assertFalse(writer.cooling)
        writer.write({'index': 99})
        self.assertEqual(writer.attempts, 2,
                         'the cooling-off period never ended, so slow storage '
                         'became a permanently silent journal')

    def test_the_shedding_is_counted_and_reported_rather_than_silent(self):
        writer = self.writer(delay=0.3)
        for index in range(10):
            writer.write({'index': index})
        status = writer.status()
        self.assertEqual(status['status'], 'DEGRADED')
        self.assertTrue(status['cooling_off'])
        self.assertIn('over the', status['last_error'])
        self.assertEqual(status['counters']['dropped_backpressure'], 9)


# ---------------------------------------------------------------------------
# §6, §26. The sensor, while the disk is full.
# ---------------------------------------------------------------------------


@requires_packets
@requires_full_device
class FullDiskRuntimeCase(unittest.TestCase):
    """A running sensor whose journal is a device that is permanently full.

    The traffic is rendered once for the class, because rendering a capture and
    parsing it back is the slowest thing here and it is identical between runs.
    That it is identical is also what makes the comparison in
    `TestAFullDiskDoesNotChangeTheDecision` mean anything.
    """

    @classmethod
    def setUpClass(cls):
        cls._workspace = tempfile.TemporaryDirectory()
        cls.events = cls._render()

    @classmethod
    def _render(cls):
        """A block-eligible behaviour, through the production parser.

        Written here rather than reused from
        `tests/test_p15_5r_runtime_end_to_end.py` for one reason:
        `TestARealFilesystemFillingUpMidRun` needs root to mount a filesystem,
        and `ensure_analysis_user` — a P0 invariant, and a correct one — refuses
        to parse a capture under root. So the *fixture's reader* is excused when
        this file runs privileged, and nothing else is. The limitation that
        creates is the same one `tests/test_p15_5r_runtime_enforcement.py`
        states: a privileged run of this file does not exercise the privilege
        boundary, only the storage behaviour it is about.
        """
        from dataset.collectors.pcap import events as pcap_events
        from dataset.generators import scanner
        from dataset.generators.packets import render, write_pcap
        from eye_for_an_eye.config import Config

        plan = scanner.sequential_scan('p15-5r-backpressure', 'backpressure',
                                       'p15.5r-runtime', port_count=90, period=0.9)
        rows, _budget = render(plan)
        capture = Path(cls._workspace.name) / 'backpressure.pcap'
        write_pcap(capture, rows)
        parser_config = Config()
        parser_config.storage.enabled = False
        if os.geteuid() == 0:
            parser_config.runtime.enforce_unprivileged = False
        events, stats = pcap_events(capture, parser_config)
        assert stats['parse_errors'] == 0, stats
        assert events, 'the controlled traffic produced no events'
        return events

    @classmethod
    def tearDownClass(cls):
        cls._workspace.cleanup()

    def run_with_journal(self, journal_path, *, required=False, export_path=''):
        from tests.test_p15_5r_runtime_end_to_end import drive, runtime_config
        config = runtime_config(autonomy=True, mode='shadow',
                                workspace=self._workspace.name)
        config.autonomy.decision_journal_path = str(journal_path)
        config.autonomy.journal_required_for_action = bool(required)
        config.autonomy.shadow_export_path = str(export_path)
        records, snapshot, health, counters = drive(config.validate(), self.events)
        return {'records': records, 'snapshot': snapshot, 'health': health,
                'counters': counters,
                'summaries': [record['observations']['autonomous']
                              for record in records
                              if 'autonomous' in record['observations']]}

    @staticmethod
    def comparable(summaries):
        """Everything a decision says about itself except its identity.

        `decision_id` is minted per decision and is meant to differ between two
        runs; every other field is a property of the evidence and the policy and
        must not move because a file could not be written.
        """
        return [{key: value for key, value in summary.items()
                 if key not in ('decision_id', 'journal_path')}
                for summary in summaries]


class TestAFullDiskDoesNotChangeTheDecision(FullDiskRuntimeCase):
    """§6: no random block, no service outage, no silently weaker policy."""

    def setUp(self):
        self.healthy_journal = Path(self._workspace.name) / 'healthy.jsonl'
        self.healthy_journal.unlink(missing_ok=True)

    def test_the_sensor_reaches_the_same_decisions_on_a_full_disk(self):
        healthy = self.run_with_journal(self.healthy_journal)
        full = self.run_with_journal(FULL_DEVICE)

        self.assertTrue(healthy['summaries'], 'the healthy run decided nothing')
        self.assertEqual(len(full['summaries']), len(healthy['summaries']),
                         'a full disk changed how many decisions the sensor took')
        self.assertEqual(self.comparable(full['summaries']),
                         self.comparable(healthy['summaries']),
                         'a full disk changed what the sensor decided')

    def test_no_block_appears_that_the_healthy_run_did_not_take(self):
        """§6's first named failure, stated as its own assertion."""
        healthy = self.run_with_journal(self.healthy_journal)
        full = self.run_with_journal(FULL_DEVICE)
        self.assertEqual(full['counters']['blocks'], healthy['counters']['blocks'])
        self.assertEqual(full['counters']['enforced'], 0)
        self.assertEqual(healthy['counters']['enforced'], 0)

    def test_the_failure_is_counted_rather_than_raised(self):
        full = self.run_with_journal(FULL_DEVICE)
        self.assertEqual(full['counters']['journalled'], 0)
        self.assertEqual(full['counters']['journal_failures'],
                         full['counters']['decisions'])
        self.assertEqual(
            full['snapshot']['decision'].get('autonomous_pipeline_failures_total', 0), 0,
            'the storage failure became an exception on the decision path')

    def test_the_health_surface_says_degraded_rather_than_not_configured(self):
        """§20's rule, on the component this cycle added.

        A configured journal that cannot write is not the same fact as a
        deployment that asked for no journal, and reporting both as
        NOT_CONFIGURED is how P15.4 made a broken classifier invisible.
        """
        full = self.run_with_journal(FULL_DEVICE)
        self.assertEqual(full['health']['components']['decision_journal'], 'DEGRADED')
        self.assertEqual(full['health']['journal']['status'], 'DEGRADED')
        self.assertIn(str(errno.ENOSPC), full['health']['journal']['last_error'])

    def test_the_sensor_keeps_serving_and_shuts_down_cleanly(self):
        """§6's second named failure: no service outage."""
        full = self.run_with_journal(FULL_DEVICE)
        self.assertTrue(full['records'], 'the sensor stopped producing decisions')
        status = full['snapshot']
        self.assertEqual(status['health']['components'].get('queue', 'healthy'), 'healthy')
        self.assertEqual(status['metrics']['events_dropped_total'], 0)

    def test_a_full_export_does_not_disturb_the_journal_or_the_decision(self):
        """§11: the export is the first thing that may fall behind, and only it."""
        healthy = self.run_with_journal(self.healthy_journal)
        both = self.run_with_journal(self.healthy_journal, export_path=FULL_DEVICE)
        self.assertEqual(self.comparable(both['summaries']),
                         self.comparable(healthy['summaries']))
        self.assertEqual(both['counters']['exported'], 0)
        self.assertEqual(both['counters']['export_failures'],
                         both['counters']['decisions'])
        self.assertEqual(both['counters']['journalled'], both['counters']['decisions'])
        self.assertEqual(both['health']['components']['decision_journal'], 'HEALTHY')


class TestTheStricterReadingWithholdsRatherThanActs(FullDiskRuntimeCase):
    """§6: `journal_required_for_action` turns a full disk into caution, not action.

    The default is the other way round, and both are defensible. What is not
    defensible is a full disk producing a block whose record nobody has -- so
    when an operator asks for the stricter reading, the observable result has to
    be a *withheld* action with a named reason, not a quieter one.
    """

    def test_a_block_that_could_not_be_journalled_is_withheld_by_name(self):
        full = self.run_with_journal(FULL_DEVICE, required=True)
        blocks = [s for s in full['summaries'] if s['action'] == 'TEMP_BLOCK']
        self.assertTrue(blocks,
                        'no window reached a block decision, so this says nothing '
                        'about withholding one')
        for summary in blocks:
            with self.subTest():
                self.assertEqual(summary['enforcement_withheld'],
                                 'decision_not_journalled')
                self.assertFalse(summary['enforced'])
        self.assertEqual(full['counters']['enforced'], 0)
        self.assertGreaterEqual(full['counters']['enforcement_withheld'], len(blocks))

    def test_the_default_reading_does_not_withhold_for_the_same_reason(self):
        """Both readings exist on purpose; neither is the silent one."""
        full = self.run_with_journal(FULL_DEVICE, required=False)
        blocks = [s for s in full['summaries'] if s['action'] == 'TEMP_BLOCK']
        self.assertTrue(blocks)
        for summary in blocks:
            with self.subTest():
                self.assertEqual(summary['enforcement_withheld'], 'shadow_mode')


# ---------------------------------------------------------------------------
# §26. A filesystem that fills up partway through, which /dev/full cannot show.
# ---------------------------------------------------------------------------


def _tmpfs_available():
    return (sys.platform.startswith('linux') and os.geteuid() == 0
            and shutil.which('mount') is not None)


@unittest.skipUnless(
    _tmpfs_available() and os.environ.get('E4E_RUN_HOST_FIREWALL', '1') != '0',
    'a real filesystem filling up needs root on a machine you can lose; '
    'set E4E_RUN_HOST_FIREWALL=0 to skip deliberately')
@requires_packets
class TestARealFilesystemFillingUpMidRun(FullDiskRuntimeCase):
    """The shape `/dev/full` cannot produce: some records land, then none do.

    A 128 KiB tmpfs, mounted and unmounted by this test and holding nothing
    else. The journal fills it partway through the run, so the assertions can
    be about the transition rather than about a device that was never writable.
    """

    SIZE = '128k'

    def setUp(self):
        self.mountpoint = Path(tempfile.mkdtemp(prefix='e4e-p155r-full-'))
        self.addCleanup(self._unmount)
        subprocess.run(['mount', '-t', 'tmpfs', '-o', f'size={self.SIZE}',
                        'e4e-p155r-full', str(self.mountpoint)],
                       check=True, capture_output=True, text=True, timeout=20)

    def _unmount(self):
        subprocess.run(['umount', str(self.mountpoint)],
                       check=False, capture_output=True, text=True, timeout=20)
        shutil.rmtree(self.mountpoint, ignore_errors=True)

    def test_records_land_until_the_filesystem_is_full_and_the_sensor_carries_on(self):
        journal = self.mountpoint / 'decisions.jsonl'
        # Leave the journal barely any room, so the fill happens inside the run
        # rather than after it. The filler is a separate file so that the
        # journal's own rotation is not what frees the space.
        filler = self.mountpoint / 'filler'
        with filler.open('wb') as handle:
            try:
                handle.write(b'\0' * 110_000)
            except OSError:
                pass
        result = self.run_with_journal(journal)

        counters = result['counters']
        self.assertGreater(counters['decisions'], 0)
        self.assertGreater(counters['journalled'], 0,
                           'nothing was written before the disk filled, so this '
                           'test is only repeating the /dev/full case')
        self.assertGreater(counters['journal_failures'], 0,
                           'the filesystem never filled, so nothing was injected')
        self.assertEqual(counters['journalled'] + counters['journal_failures'],
                         counters['decisions'])

        # The sensor kept deciding after the disk filled, and every line that
        # did land is still a complete, parseable record.
        lines = [line for line in journal.read_text(encoding='utf-8').splitlines()
                 if line.strip()]
        parsed = []
        for line in lines:
            try:
                parsed.append(json.loads(line))
            except ValueError:
                # A short write leaves a truncated last line. The writer counts
                # that as a failure; a reader skips it. Both are correct, and a
                # test that demanded every byte parse would be demanding
                # something ENOSPC cannot give.
                continue
        self.assertTrue(parsed)
        self.assertTrue(all(entry['journal_schema_version'] == 1 for entry in parsed))

        self.assertEqual(result['health']['components']['decision_journal'], 'DEGRADED')
        self.assertTrue(result['records'], 'the sensor stopped producing decisions')
        self.assertEqual(result['snapshot']['metrics']['events_dropped_total'], 0)

    def test_the_journal_never_exceeds_the_filesystem_it_lives_on(self):
        """The ceiling and the disk are different limits; neither may be breached."""
        journal = self.mountpoint / 'decisions.jsonl'
        self.run_with_journal(journal)
        used = sum(path.stat().st_size for path in self.mountpoint.iterdir()
                   if path.is_file())
        statvfs = os.statvfs(self.mountpoint)
        self.assertLessEqual(used, statvfs.f_blocks * statvfs.f_frsize)


if __name__ == '__main__':
    unittest.main()
