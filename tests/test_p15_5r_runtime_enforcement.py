"""A packet in, a dropped packet out — and the test touches neither end.

P15.5R §12-§17. Release-critical.

### What makes this different from the P15.1 enforcement tests

`tests/test_p15_1_enforcement.py` already proves that a block stops traffic: a
veth pair, a listener, a real TCP connection, reachable-blocked-reachable. It
proves it by building an `EnforcementRequest` and handing it to the backend.

That was the right test for P15.1, and it is exactly the test that could not
have caught what P15.5 found. The components worked. Nothing assembled them.
`reports/P15_5R_RUNTIME_BEFORE.md` traced a running sensor and found twelve
modules on its decision path, none of them in `autonomy/` and none in
`security/`: the authority was imported and never instantiated, and
`HostEnforcer` was never even imported.

So the rule here is §12's, and it is the whole point of the file: **this test
does not call `AutonomousDecisionAuthority`, `HostEnforcer` or `TemporaryBlocks`.**
It writes a configuration, starts `EventRuntime`, hands it parsed packets through
`emit()` — the call the network listeners make — and then asks the kernel whether
a TCP connection still completes. Everything between those two points has to
happen by itself or the test fails.

### The isolation, and why the source address is what it is

§13: real enforcement only in a disposable environment. A veth pair into a
throw-away network namespace, a listener bound to this side, and traffic from the
other. The namespace exists to give the traffic a source address that is not this
host's, because a protected address cannot be blocked — that is what the
protection is for, and it would make the test vacuous.

The generated capture is rendered with that peer address as its source, so the
address the parser reads, the address the correlation engine keys on, the address
the authority decides about and the address in the firewall are all one address
that a real TCP connection is arriving from. Nothing is remapped after parsing.

Everything created here is named and removed in `tearDownClass`.

### What this test does not prove, stated because it matters

It runs the sensor as root. It has to: building a network namespace and writing
an nftables table both require it, and `ensure_analysis_user` — a P0 invariant,
and a correct one — refuses to parse a capture under root, so even the fixture's
reader has to be excused explicitly.

In production the split is the other way round: the sensor is unprivileged and
only the firewall helper is not. So this file proves that the path runs end to
end and that the kernel effect is real; it does **not** exercise the privilege
boundary between the two. That boundary is tested separately and structurally in
`tests/test_p15_1_enforcement.py` — `HostEnforcer.has_firewall_privilege` is
`False`, the module imports nothing that can reach `nft`, and the helper refuses
a request it cannot validate. Two tests, two claims, neither standing in for the
other.
"""
from dataclasses import replace
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from eye_for_an_eye.config import load_config
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime

REPOSITORY = Path(__file__).resolve().parents[1]
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'
SNAPSHOT_INTERVAL = 2.0


def kernel_available():
    return (sys.platform.startswith('linux') and shutil.which('nft') is not None
            and os.geteuid() == 0)


def packets_available():
    try:
        import scapy.layers.inet  # noqa: F401
        return True
    except ImportError:
        return False


requires_kernel = unittest.skipUnless(
    kernel_available() and os.environ.get('E4E_RUN_HOST_FIREWALL', '1') != '0',
    'runtime enforcement needs Linux, nft and root on a machine you can lose; '
    'set E4E_RUN_HOST_FIREWALL=0 to skip deliberately')

requires_veth = unittest.skipUnless(
    shutil.which('ip') is not None,
    'the reachability proof needs iproute2 to build a throw-away veth pair')

requires_packets = unittest.skipUnless(
    packets_available(), 'the controlled traffic needs scapy to render')


class CollectingLogger(EventLogger):
    """The production logger, writing to a list. Observation, not substitution."""

    def __init__(self, config):
        self.lines = []
        super().__init__(config, writer=self.lines.append)

    def decisions(self):
        import json
        out = []
        for line in list(self.lines):
            try:
                body = json.loads(line)
            except ValueError:
                continue
            if body.get('event_type') == EventType.DECISION:
                out.append(body)
        return out


@requires_kernel
@requires_veth
@requires_packets
class RuntimeEnforcementCase(unittest.TestCase):
    """The isolated environment, shared by the shadow and autonomous cases."""

    #: Each class builds its own lab on its own port. Sharing one would mean a
    #: class that fails in `setUpClass` can take the next one down with it, and
    #: a cascade of identical errors hides which one actually broke.
    LAB = 0
    HOST_ADDRESS = '198.51.100.1'
    PEER_ADDRESS = '198.51.100.2'
    #: Nothing the traffic touches, and nothing this host administers from.
    MANAGEMENT = '192.0.2.0/24'
    BASE_PORT = 59231

    @classmethod
    def _names(cls):
        return (f'e4e_p155r_ns{cls.LAB}', f'e4ep155r{cls.LAB}a',
                f'e4ep155r{cls.LAB}b', cls.BASE_PORT + cls.LAB)

    # -- the lab -------------------------------------------------------------

    @classmethod
    def _ip(cls, *arguments, check=True):
        return subprocess.run([shutil.which('ip'), *arguments], check=check,
                              capture_output=True, text=True, timeout=20)

    @classmethod
    def setUpClass(cls):
        cls.NS, cls.HOST_SIDE, cls.PEER_SIDE, cls.PORT = cls._names()
        cls.listener = None
        cls.serving = False
        cls._workspace = tempfile.TemporaryDirectory()
        cls._ip('netns', 'del', cls.NS, check=False)
        cls._ip('link', 'del', cls.HOST_SIDE, check=False)
        cls._ip('netns', 'add', cls.NS)
        try:
            cls._ip('link', 'add', cls.HOST_SIDE, 'type', 'veth',
                    'peer', 'name', cls.PEER_SIDE)
            cls._ip('link', 'set', cls.PEER_SIDE, 'netns', cls.NS)
            cls._ip('addr', 'add', f'{cls.HOST_ADDRESS}/24', 'dev', cls.HOST_SIDE)
            cls._ip('link', 'set', cls.HOST_SIDE, 'up')
            cls._ip('netns', 'exec', cls.NS, 'ip', 'addr', 'add',
                    f'{cls.PEER_ADDRESS}/24', 'dev', cls.PEER_SIDE)
            cls._ip('netns', 'exec', cls.NS, 'ip', 'link', 'set', cls.PEER_SIDE, 'up')
            cls.listener = socket.socket()
            cls.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            cls.listener.bind((cls.HOST_ADDRESS, cls.PORT))
            cls.listener.listen(16)
            cls.serving = True
            threading.Thread(target=cls._serve, daemon=True).start()
            cls.events = cls._controlled_traffic()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def _serve(cls):
        while cls.serving:
            try:
                connection, _ = cls.listener.accept()
            except OSError:
                return
            try:
                connection.sendall(b'ok')
            finally:
                connection.close()

    @classmethod
    def tearDownClass(cls):
        cls.serving = False
        if getattr(cls, 'listener', None) is not None:
            cls.listener.close()
        cls._ip('link', 'del', cls.HOST_SIDE, check=False)
        cls._ip('netns', 'del', cls.NS, check=False)
        if getattr(cls, '_workspace', None) is not None:
            cls._workspace.cleanup()

    @classmethod
    def _controlled_traffic(cls):
        """A block-eligible behaviour, rendered from the peer address.

        The source is set on the plan before rendering, so the address in the
        capture, the address the parser reads, the address the authority decides
        about and the address in the firewall are one address — the one a real
        TCP connection is arriving from in this namespace. Nothing is rewritten
        after parsing.
        """
        from dataset.collectors.pcap import events as pcap_events
        from dataset.generators import scanner
        from dataset.generators.packets import render, write_pcap
        from eye_for_an_eye.config import Config

        plan = scanner.sequential_scan('p15-5r-kernel', 'scanner-recon',
                                       'p15.5r-kernel', port_count=90, period=0.9)
        plan = replace(plan, source=cls.PEER_ADDRESS)
        rows, _budget = render(plan)
        capture = Path(cls._workspace.name) / 'controlled.pcap'
        write_pcap(capture, rows)
        parser_config = Config()
        parser_config.storage.enabled = False
        # `analyze_pcap` refuses to run as root — `ensure_analysis_user` is a
        # P0 invariant and a correct one: the analysis runtime is unprivileged
        # and only the firewall helper is not. This file has to be root for
        # `nft` and the network namespace, so the *fixture's* reader is excused
        # and nothing else is. The limitation this creates is stated in the
        # class docstring and is not hidden by it.
        parser_config.runtime.enforce_unprivileged = False
        events, stats = pcap_events(capture, parser_config)
        assert stats['parse_errors'] == 0, stats
        assert events, 'the controlled traffic produced no events'
        # The capture contains both directions, so the destinations appear as
        # sources on the replies. What matters is that the only *client* in it
        # is the namespace peer: the decision under test has to be about the
        # address a real TCP connection is arriving from.
        destinations = {contact.destination for contact in plan.contacts}
        sources = {event.src_ip for event in events}
        unexpected = sources - destinations - {cls.PEER_ADDRESS}
        assert not unexpected, f'unexpected client addresses in the capture: {unexpected}'
        assert cls.PEER_ADDRESS in sources, \
            'the controlled traffic is not attributed to the namespace peer'
        return events

    # -- reachability --------------------------------------------------------

    def reachable(self):
        """Does a TCP connection from the peer address complete?

        Run inside the namespace with a short timeout. A DROP produces no
        refusal, so an unreachable host is a timeout rather than a connection
        error — and telling those apart is what distinguishes a firewall drop
        from a listener that died.
        """
        probe = ('import socket, sys\n'
                 's = socket.socket()\n'
                 's.settimeout(3)\n'
                 'try:\n'
                 f'    s.connect(({self.HOST_ADDRESS!r}, {self.PORT}))\n'
                 '    sys.stdout.write(s.recv(2).decode())\n'
                 'except OSError:\n'
                 "    sys.stdout.write('unreachable')\n")
        result = subprocess.run(
            [shutil.which('ip'), 'netns', 'exec', self.NS, sys.executable, '-c', probe],
            capture_output=True, text=True, timeout=30)
        return result.stdout.strip() == 'ok'

    # -- the runtime under test ----------------------------------------------

    def write_config(self, *, mode, host_enabled):
        """A real configuration file, because the privileged helper needs one.

        `HostEnforcer` starts the helper as `--config <path>`, and the helper
        reads its own protected networks from that file rather than being told
        them. So this is not a convenience: a programmatically built
        configuration has no path and `from_config` correctly refuses to attach
        an enforcer to it.
        """
        directory = Path(self._workspace.name)
        journal = directory / f'decisions-{mode}.jsonl'
        path = directory / f'eye-for-an-eye-{mode}.toml'
        path.write_text(f'''
config_version = 1

[deployment]
profile = "sensor"

[decision]
enabled = true
mode = "enforce"
interval_ms = {int(SNAPSHOT_INTERVAL * 1000)}

[correlation]
enabled = true

[storage]
enabled = false

[api]
enabled = false

[metrics]
enabled = false

[logging]
events_per_second = 100000.0
per_source_per_second = 100000.0
per_event_type_per_second = 100000.0
queue_size = 8192

[enforcement]
enabled = false
host_enabled = {str(bool(host_enabled)).lower()}
management_networks = ["{self.MANAGEMENT}"]

[autonomy]
enabled = true
mode = "{mode}"
calibrator_path = "{CALIBRATOR}"
default_cost_profile = "public_website"
decision_journal_path = "{journal}"
''', encoding='utf-8')
        return path, journal

    def drive(self, config):
        """Start the real runtime, feed it, and let it decide by itself.

        `emit` is the sensor's intake. Nothing below it is called from here.
        """
        logger = CollectingLogger(config.logging)
        runtime = EventRuntime(config, logger=logger, mode='sensor')
        runtime.start()
        try:
            for event in self.events:
                runtime.emit(event)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if runtime.queue.empty() and not runtime.analysis.decisions.pending:
                    break
                time.sleep(0.05)
            pipeline = runtime.analysis.decisions.autonomy
            observed = {
                'decisions': logger.decisions(),
                'counters': dict(pipeline.counters) if pipeline else {},
                'enforcer_counters': (dict(pipeline.enforcer.counters)
                                      if pipeline and pipeline.enforcer else None),
                'health': pipeline.health() if pipeline else None,
            }
        finally:
            runtime.close(timeout=15)
        return observed

    @staticmethod
    def summaries(observed):
        return [record['observations']['autonomous']
                for record in observed['decisions']
                if 'autonomous' in record['observations']]

    # -- cleaning up after the runtime ---------------------------------------

    def release_blocks(self, path):
        """Release whatever the *runtime's own* installation owns.

        Through `HostEnforcer` and the privileged helper, with the same
        configuration file the runtime was given — because the owned table's
        name is derived from that configuration (`runtime.sensor_id`, falling
        back to `deployment.profile`), and a test that spells the installation
        out itself spells it wrongly the moment that derivation changes.

        That mistake is silent, which is why it is worth this paragraph:
        `cleanup` on a table that is not ours returns `no table` and does not
        raise, so a wrongly named backend reports a tidy no-op while the block
        it was supposed to release stays in the kernel — and the next test
        starts from a host that cannot reach its own lab.
        """
        from eye_for_an_eye.security.host_enforcer import HostEnforcer
        return HostEnforcer(str(path)).cleanup()

    def owned_entries(self, path):
        """What the kernel is enforcing for this installation, asked of the kernel."""
        from eye_for_an_eye.security.host_enforcer import HostEnforcer
        return HostEnforcer(str(path)).status()['helper'].get('entries') or []

    def start_from_an_unblocked_lab(self, path):
        """Every test in this file begins from the same known state.

        Registered as a cleanup as well as run here, so a test that fails
        half-way through an enforcement does not hand the next one a blocked
        host, and so the file does not depend on the order its tests run in.
        """
        self.release_blocks(path)
        self.addCleanup(self.release_blocks, path)
        self.assertTrue(self.reachable(), 'the lab was unreachable before the run')


class TestShadowModeDoesNotEnforce(RuntimeEnforcementCase):
    """§15. The complete path runs; the kernel is never touched."""

    LAB = 1

    def setUp(self):
        self.path, self.journal = self.write_config(mode='shadow', host_enabled=False)
        self.start_from_an_unblocked_lab(self.path)

    def test_the_runtime_would_block_and_the_connection_survives(self):
        path = self.path
        observed = self.drive(load_config(path))

        summaries = self.summaries(observed)
        self.assertTrue(summaries, 'the runtime produced no autonomous decision')
        would = [s for s in summaries if s['action'] == 'TEMP_BLOCK']
        self.assertTrue(would, 'no window reached a block decision, so this test '
                               'says nothing about shadow withholding one')
        for summary in would:
            with self.subTest():
                self.assertFalse(summary['enforced'])
                self.assertEqual(summary['enforcement_withheld'], 'shadow_mode')

        self.assertEqual(observed['counters']['enforced'], 0)
        self.assertIsNone(observed['enforcer_counters'],
                          'a shadow runtime built a host enforcer')
        self.assertEqual(self.owned_entries(path), [],
                         'a shadow runtime put an element in the kernel')
        self.assertTrue(self.reachable(),
                        'the connection stopped working in shadow mode')


class TestAutonomousModeEnforcesFromTheRuntime(RuntimeEnforcementCase):
    """§12, §14, §16. The one that had to be written last."""

    LAB = 2

    def setUp(self):
        self.path, self.journal = self.write_config(mode='autonomous', host_enabled=True)
        # One journal per test, so what a test reads is what its own run wrote.
        self.journal.unlink(missing_ok=True)
        # Only ever to clean up after the runtime, never to create anything:
        # the block under test is placed by the runtime or it is not placed.
        self.start_from_an_unblocked_lab(self.path)

    def test_the_runtime_blocks_a_real_connection_and_releasing_restores_it(self):
        path = self.path
        observed = self.drive(load_config(path))

        # -- the runtime decided, and it decided by itself --------------------
        summaries = self.summaries(observed)
        self.assertTrue(summaries, 'the runtime produced no autonomous decision')
        enforced = [s for s in summaries if s['enforced']]
        self.assertTrue(enforced,
                        f'no decision reached the kernel; withheld reasons were '
                        f'{sorted({s["enforcement_withheld"] for s in summaries})}')

        # -- the request carried the runtime's own decision id (§14) ----------
        for summary in enforced:
            with self.subTest():
                self.assertTrue(summary['decision_id'].startswith('dec-'))
                self.assertEqual(summary['action'], 'TEMP_BLOCK')
        self.assertGreaterEqual(observed['enforcer_counters']['succeeded'], 1)
        self.assertEqual(observed['counters']['enforced'],
                         observed['enforcer_counters']['succeeded'])

        # -- and the packet actually stops ------------------------------------
        self.assertFalse(self.reachable(),
                         'the runtime reported an enforced block and the '
                         'connection still completes')

        # -- an explicit safe release restores it (§14) ------------------------
        #
        # The shortest rung of the TTL ladder is five minutes, which is the
        # right number for a defender and the wrong one for a test. §14 allows
        # either expiry or an explicit unblock; this is the explicit unblock,
        # and it is the same cleanup path an operator has.
        released = self.release_blocks(path)
        self.assertTrue(released['helper'].get('deleted'),
                        f'the release did not remove the owned table: {released}')
        self.assertTrue(self.reachable(),
                        'the connection did not recover after the block was released')

    def test_the_element_the_kernel_holds_expires_on_its_own(self):
        """§46: automatic expiry and the twelve-hour ceiling, asked of the kernel.

        `tests/test_p15_invariants.py` proves no code path produces a permanent
        ban and that the configured ladder cannot exceed the ceiling. Both are
        properties of the source. This is the element itself: whatever the
        record said, the thing in the firewall is counting down, and it is
        counting down from no more than twelve hours.

        A block with no timeout would survive a reboot of nothing and an
        operator's attention span, and it is the one failure that turns a
        temporary defensive measure into somebody permanently unable to reach a
        service nobody remembers blocking them from.
        """
        from eye_for_an_eye.security.enforcement import MAX_TTL_SECONDS
        path = self.path
        observed = self.drive(load_config(path))
        self.assertTrue([s for s in self.summaries(observed) if s['enforced']],
                        'nothing was enforced, so there is no element to inspect')
        entries = self.owned_entries(path)
        self.assertTrue(entries, 'the runtime reported a block and the kernel has none')
        for entry in entries:
            with self.subTest(address=entry['address']):
                self.assertIsInstance(entry['timeout'], int,
                                      'the element carries no kernel timeout')
                self.assertGreater(entry['timeout'], 0)
                self.assertLessEqual(entry['timeout'], MAX_TTL_SECONDS)

    def test_the_journal_records_the_block_that_was_actually_placed(self):
        """§2 and §14 together: the forensic record of a real enforcement."""
        import json
        path, journal = self.path, self.journal
        observed = self.drive(load_config(path))

        entries = [json.loads(line)['entry'] for line in
                   journal.read_text(encoding='utf-8').splitlines() if line.strip()]
        self.assertTrue(entries, 'nothing was journalled')
        blocked = [entry for entry in entries
                   if entry['decision']['action'] == 'TEMP_BLOCK']
        self.assertTrue(blocked)
        enforcement = [entry for entry in blocked if 'enforcement' in entry]
        self.assertTrue(enforcement,
                        'no journal entry records what the enforcer did')
        for entry in enforcement:
            with self.subTest():
                self.assertEqual(entry['enforcement']['decision_id'],
                                 entry['decision']['decision_id'],
                                 'the request does not carry the decision id of '
                                 'the decision that authorised it')

        ids = {s['decision_id'] for s in self.summaries(observed) if s['enforced']}
        self.assertTrue(ids & {entry['decision']['decision_id']
                               for entry in enforcement},
                        'the log summary and the journal disagree about which '
                        'decision was enforced')


class TestTheLegacyPathCannotEnforce(RuntimeEnforcementCase):
    """§17. Asserted against a running autonomous runtime, not only statically."""

    LAB = 3

    def setUp(self):
        self.path, self.journal = self.write_config(mode='autonomous', host_enabled=True)
        self.start_from_an_unblocked_lab(self.path)

    def test_the_legacy_enforcer_is_absent_from_an_autonomous_runtime(self):
        config = load_config(self.path)
        logger = CollectingLogger(config.logging)
        runtime = EventRuntime(config, logger=logger, mode='sensor')
        runtime.start()
        try:
            engine = runtime.analysis.decisions
            self.assertIsNone(engine.enforcer,
                              'the legacy namespace enforcer exists alongside '
                              'the P15 authority in a live runtime')
            self.assertTrue(engine.autonomous_authority)
            self.assertIsNotNone(engine.autonomy.enforcer)
        finally:
            runtime.close(timeout=15)

    def test_no_owned_table_exists_before_the_runtime_places_one(self):
        """So a block observed later is this runtime's doing, not a leftover.

        Asked through the helper with the runtime's own configuration, which is
        the only way to be sure the table being inspected is the table the
        runtime would write to. An independently named backend answers about a
        table nobody uses, and `[]` from that is not evidence of anything.
        """
        self.assertEqual(self.owned_entries(self.path), [])


if __name__ == '__main__':
    unittest.main()
