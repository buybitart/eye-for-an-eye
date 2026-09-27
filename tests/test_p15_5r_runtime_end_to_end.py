"""The running sensor, from a packet to a decision record. P15.5R §25-§30.

### The rule that shapes every test here

§25: *do not manually call `DecisionAuthority` in the test; the application must
reach it naturally.* So nothing below constructs an authority, a pipeline, a
`DecisionInputs` or a `FeatureVector`. Each test builds a configuration, starts
an `EventRuntime`, hands generated packets to `emit()` — the same call
`EventPipeline` and the network listeners make — and reads what comes out of the
logger the runtime writes to.

That distinction is the whole cycle in miniature. P15.5's smoke test assembled
the decision path itself and proved the components compose; it said so plainly in
its own docstring, and it was right to. This proves the *sensor* composes them,
which is a different claim and the one that was false.

### Where the traffic comes from

`dataset/generators` renders a behaviour to real packets, `generators.packets`
writes a PCAP, and `collectors.pcap` reads it back with the production parser.
Writing the capture to disk and reading it back is not ceremony: the PCAP writer
had a microsecond-carry defect in P15.4 that made a capture unreadable, and a
test that passed rows straight to the collector would not have met it.

### What is deliberately not asserted

Accuracy. §41's rule applies to every number in this file: these six behaviours
are a wiring check and not a measurement, the corpus is far too small to support
a claim about detection, and a reader who takes "the scanner was blocked" here as
evidence about scanners has read it wrong. What is being asserted is that the
authority was *reached*, that it was given real evidence rather than defaults,
and that shadow mode stopped the last step.
"""
from pathlib import Path
import json
import tempfile
import time
import unittest

from eye_for_an_eye.config import Config
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime

REPOSITORY = Path(__file__).resolve().parents[1]
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'

#: The cadence every P15 corpus is built at. A longer interval makes a
#: twelve-second behaviour emit one window holding its first two events, every
#: family reads zero, and the result is a harness misconfiguration wearing the
#: costume of a wiring failure. The first run of P15.5's smoke test did exactly
#: that.
SNAPSHOT_INTERVAL = 2.0

#: The five schema-2 authentication columns. `None` in all five for a source that
#: authenticated means the ledger is not wired, whatever the final action says.
AUTH_COLUMNS = ('auth_failures_60s', 'auth_successes_60s', 'auth_failure_ratio',
                'auth_principals_900s', 'auth_failure_span_900s')


def _available():
    try:
        import scapy.layers.inet  # noqa: F401
        return True
    except ImportError:
        return False


class CollectingLogger(EventLogger):
    """The production logger, writing to a list instead of a file.

    Subclassed rather than mocked so that the rate limiter, the repeated-event
    suppression and the bounded queue are all still on the path — a test that
    bypassed them would not be reading what the sensor emits.
    """

    def __init__(self, config):
        self.lines = []
        super().__init__(config, writer=self.lines.append)

    def records(self, event_type):
        out = []
        for line in list(self.lines):
            try:
                body = json.loads(line)
            except ValueError:
                continue
            if body.get('event_type') == event_type:
                out.append(body)
        return out


def runtime_config(*, autonomy, mode='shadow', workspace, cost_profiles=None,
                   default_profile='public_website'):
    config = Config()
    config.decision.enabled = True
    config.decision.mode = 'enforce'
    config.decision.interval_ms = int(SNAPSHOT_INTERVAL * 1000)
    config.enforcement.enabled = False
    config.autonomy.enabled = autonomy
    config.autonomy.mode = mode
    config.autonomy.calibrator_path = str(CALIBRATOR) if autonomy else ''
    config.autonomy.default_cost_profile = default_profile
    config.autonomy.cost_profiles = dict(cost_profiles or {})
    config.storage.enabled = False
    config.api.enabled = False
    config.metrics.enabled = False
    # Generous, because the logger's job here is to be read rather than to
    # protect a disk, and a rate limiter silently dropping decisions would make
    # every assertion below meaningless.
    config.logging.file = ''
    config.logging.events_per_second = 100000.0
    config.logging.per_source_per_second = 100000.0
    config.logging.per_event_type_per_second = 100000.0
    config.logging.queue_size = 8192
    config.runtime.queue_events = 8192
    config.runtime.status_file = str(Path(workspace) / 'status.json')
    return config.validate()


def packets_for(builder_module, builder, name, workspace, **parameters):
    """A behaviour, rendered to a capture and read back by the production parser."""
    from dataset.collectors.pcap import events as pcap_events
    from dataset.generators.packets import render, write_pcap

    plan = getattr(builder_module, builder)(f'p15-5r-{name}', name, 'p15.5r-runtime',
                                            **parameters)
    rows, _budget = render(plan)
    capture = Path(workspace) / f'{plan.scenario_id}.pcap'
    write_pcap(capture, rows)
    parser_config = Config()
    parser_config.storage.enabled = False
    events, stats = pcap_events(capture, parser_config)
    # The destination ports this behaviour actually touches. Read from the plan
    # rather than assumed: the seed decides where a sequential scan starts, so a
    # test that hard-coded port 22 would be asserting a property of one seed and
    # would quietly stop exercising the service scope when the seed changed.
    ports = tuple(dict.fromkeys(contact.port for contact in plan.contacts
                                if contact.port is not None))
    return events, stats, ports


def drive(config, events, *, timeout=60.0):
    """Start the real runtime, feed it, and read what it wrote.

    `emit` is the sensor's intake — the same call the listeners and the capture
    pipeline make. Everything after it is the runtime's own thread.
    """
    logger = CollectingLogger(config.logging)
    runtime = EventRuntime(config, logger=logger, mode='sensor')
    runtime.start()
    try:
        for event in events:
            runtime.emit(event)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if runtime.queue.empty() and not runtime.analysis.decisions.pending:
                break
            time.sleep(0.02)
        snapshot = runtime.control_snapshot() or runtime.snapshot()
        autonomy = runtime.analysis.decisions.autonomy
        health = autonomy.health() if autonomy is not None else None
        counters = dict(autonomy.counters) if autonomy is not None else {}
    finally:
        runtime.close(timeout=10)
    return logger.records(EventType.DECISION), snapshot, health, counters


@unittest.skipUnless(_available(), 'packet rendering needs scapy')
class RuntimeCase(unittest.TestCase):
    """Shared fixture: the traffic is rendered once for the whole class."""

    SCENARIOS = ()

    @classmethod
    def setUpClass(cls):
        from dataset.generators import benign, profiles, scanner
        cls._workspace = tempfile.TemporaryDirectory()
        modules = {'web_client': benign, 'authenticated_batch': profiles,
                   'admin_login_mistakes': profiles, 'api_credential_spray': profiles,
                   'admin_brute_force': profiles, 'sequential_scan': scanner}
        cls.traffic = {}
        for name, builder, parameters in cls.SCENARIOS:
            cls.traffic[name] = packets_for(modules[builder], builder, name,
                                            cls._workspace.name, **parameters)

    def ports_for(self, name):
        return self.traffic[name][2]

    @classmethod
    def tearDownClass(cls):
        cls._workspace.cleanup()

    def run_scenario(self, name, **config_kwargs):
        events, stats, _ports = self.traffic[name]
        self.assertEqual(stats['parse_errors'], 0,
                         'the production parser could not read the generated capture')
        config = runtime_config(workspace=self._workspace.name, **config_kwargs)
        return drive(config, events)


class TestTheSensorReachesTheAuthority(RuntimeCase):
    """§25, §26, §29."""

    SCENARIOS = (
        ('normal-browser', 'web_client', {}),
        ('scanner-recon', 'sequential_scan', {'port_count': 90, 'period': 0.9}),
    )

    def test_a_browser_produces_a_decision_record_and_no_block_request(self):
        """§26. Every stage answered, and the answer was to do nothing."""
        decisions, snapshot, health, counters = self.run_scenario(
            'normal-browser', autonomy=True)
        self.assertTrue(decisions, 'the runtime produced no decision at all')
        self.assertEqual(counters['decisions'], len(decisions),
                         'the authority was not consulted for every window')
        for record in decisions:
            with self.subTest(window=record['observations']['sample_count']):
                self.assertFalse(record['observations']['would_enforce'])
                self.assertFalse(record['observations']['enforced'])
        self.assertEqual(counters['blocks'], 0)
        self.assertEqual(counters['enforced'], 0)
        self.assertEqual(health['components']['calibrator'], 'HEALTHY')

    def test_the_decision_record_carries_what_a_reader_needs(self):
        """§34, over the record the *runtime* emitted rather than one a test built."""
        decisions, _snapshot, _health, _counters = self.run_scenario(
            'scanner-recon', autonomy=True)
        self.assertTrue(decisions)
        autonomous = decisions[-1]['observations']['autonomous']
        self.assertEqual(decisions[-1]['observations']['feature_schema_version'], 2)
        # The bounded form the log can carry. `serialize_event` discards the
        # observations of any record over 4096 bytes, so the event holds what a
        # person reads first and the journal holds everything.
        for key in ('decision_id', 'action', 'blocked', 'shadow', 'reason_codes',
                    'scope', 'cost_profile', 'threshold', 'network_block_permitted',
                    'calibrated', 'conservative_probability', 'signal_diversity',
                    'behavioural_diversity', 'evidence_band',
                    'enforcement_withheld', 'enforced', 'policy_guard_version'):
            with self.subTest(key=key):
                self.assertIn(key, autonomous)
        self.assertEqual(decisions[-1]['observations']['math_version'], 'math-risk-v4')
        self.assertTrue(autonomous['decision_id'])

    def test_the_decision_record_survives_the_log_line_limit(self):
        """The finding that made the bounded form necessary.

        A record over 4096 bytes loses *everything* — `serialize_event` replaces
        its observations with `{'record_truncated': True}`, not just the verbose
        parts. A decision record that answers "why was this blocked" only when
        it happens to be short is not one an operator can rely on.
        """
        decisions, _snapshot, _health, _counters = self.run_scenario(
            'scanner-recon', autonomy=True)
        self.assertTrue(decisions)
        for record in decisions:
            with self.subTest():
                self.assertNotIn('record_truncated', record['observations'])
                self.assertIn('autonomous', record['observations'])

    def test_the_authority_is_reached_through_the_application_not_the_test(self):
        """The negative form of §25: with autonomy off the same traffic produces
        decisions and the authority is never constructed, so a test that had been
        calling it directly would still pass and this one would not."""
        decisions, _snapshot, health, counters = self.run_scenario(
            'scanner-recon', autonomy=False)
        self.assertTrue(decisions)
        self.assertIsNone(health)
        self.assertEqual(counters, {})
        for record in decisions:
            with self.subTest():
                self.assertNotIn('autonomous', record['observations'])

    def test_the_status_snapshot_reports_the_decision_path(self):
        """§49."""
        _decisions, snapshot, _health, _counters = self.run_scenario(
            'scanner-recon', autonomy=True)
        decision = snapshot['decision']
        self.assertEqual(decision['feature_schema_version'], 2)
        self.assertEqual(decision['math_version'], 'math-risk-v4')
        self.assertEqual(decision['components']['calibrator']['status'], 'HEALTHY')
        self.assertEqual(decision['autonomous']['mode'], 'shadow')
        self.assertIn('autonomous_decisions_total', snapshot['metrics'])


class TestAuthenticationReachesTheAuthority(RuntimeCase):
    """§18, §27, §28. The ledger, through the sensor rather than beside it."""

    SCENARIOS = (
        ('authenticated-batch-api', 'authenticated_batch', {}),
        ('admin-brute-force', 'admin_brute_force', {}),
    )

    def _auth_values(self, decisions):
        seen = {name: [] for name in AUTH_COLUMNS}
        for record in decisions:
            families = (record['observations'].get('autonomous', {})
                        .get('decision', {}).get('evidence', {})
                        .get('signal_families', {}))
            seen.setdefault('families', []).append(families)
        return seen

    def test_a_successful_batch_api_is_not_blocked_for_authenticating(self):
        """§27, §31 of P15.5's standing list: authenticated success is not
        evidence of abuse, however much of it there is."""
        decisions, _snapshot, _health, counters = self.run_scenario(
            'authenticated-batch-api', autonomy=True)
        self.assertTrue(decisions)
        self.assertEqual(counters['blocks'], 0,
                         'successful authenticated batch traffic reached a block')
        for record in decisions:
            with self.subTest():
                self.assertFalse(record['observations']['enforced'])

    def test_credential_abuse_reaches_the_authority_with_auth_evidence(self):
        """§28. Not "was it blocked" — whether `AUTH_BEHAVIOR` arrived at all.

        A brute force that reaches ALLOW with `AUTH_BEHAVIOR` at zero has a
        broken ledger, and the action alone cannot tell you so. That is the
        P15.4 lesson restated: asserting the final action is exactly what would
        have passed while the product blocked nothing.
        """
        decisions, _snapshot, health, counters = self.run_scenario(
            'admin-brute-force', autonomy=True)
        self.assertTrue(decisions)
        self.assertEqual(counters['decisions'], len(decisions))
        strongest = 0.0
        for record in decisions:
            summary = record['observations']['autonomous']
            # `signal_families` is in the full record rather than the bounded
            # summary, so the bounded evidence band and diversity count are what
            # a log reader gets. AUTH_BEHAVIOR's presence is asserted through the
            # families the *composition* reported, which the fused evidence
            # block in the same record carries.
            contributions = record['observations'].get('math_contributions', {})
            strongest = max(strongest, float(contributions.get('AUTH_BEHAVIOR', 0.0) or 0.0))
            self.assertGreaterEqual(summary['signal_diversity'], 0)
        self.assertGreater(strongest, 0.0,
                           'the authentication ledger produced no AUTH_BEHAVIOR '
                           'evidence for a brute force; the five schema-2 columns '
                           'are not reaching the feature vector through the runtime')
        self.assertEqual(health['components']['calibrator'], 'HEALTHY')


class TestShadowModeStopsAtTheLastStep(RuntimeCase):
    """§5, §30. The complete path runs; nothing is enforced."""

    SCENARIOS = (('scanner-recon', 'sequential_scan',
                  {'port_count': 90, 'period': 0.9}),)

    def test_a_block_decision_is_taken_and_withheld(self):
        decisions, _snapshot, health, counters = self.run_scenario(
            'scanner-recon', autonomy=True, mode='shadow')
        self.assertGreater(counters['blocks'], 0,
                           'no window reached a block decision, so this test says '
                           'nothing about whether shadow withholds one')
        self.assertEqual(counters['enforced'], 0)
        self.assertEqual(counters['shadow_blocks'], counters['blocks'])
        withheld = {record['observations']['autonomous']['enforcement_withheld']
                    for record in decisions
                    if record['observations']['autonomous']['action'] == 'TEMP_BLOCK'}
        self.assertEqual(withheld, {'shadow_mode'})
        self.assertTrue(health['shadow'])

    def test_no_firewall_action_was_taken_by_any_path(self):
        decisions, snapshot, _health, _counters = self.run_scenario(
            'scanner-recon', autonomy=True, mode='shadow')
        self.assertEqual(snapshot['metrics'].get('autonomous_enforced_total', 0), 0)
        self.assertEqual(snapshot['metrics'].get('enforced_block_total', 0), 0)
        for record in decisions:
            with self.subTest():
                self.assertFalse(record['observations']['enforced'])
                self.assertEqual(record['observations']['block_seconds'], 0)


class TestTheCostProfileReachesTheRuntimeDecision(RuntimeCase):
    """§13, §15. Asserted on the ExpectedLoss input, not on a grouped table."""

    SCENARIOS = (('scanner-recon', 'sequential_scan',
                  {'port_count': 90, 'period': 0.9}),)

    def _profiles(self, decisions):
        return {record['observations']['autonomous']['cost_profile']
                for record in decisions}

    def test_the_default_profile_prices_a_deployment_with_no_scope_mapping(self):
        decisions, _s, _h, _c = self.run_scenario('scanner-recon', autonomy=True)
        self.assertEqual(self._profiles(decisions), {'public_website'})
        thresholds = {record['observations']['autonomous']['threshold']
                      for record in decisions}
        self.assertEqual(thresholds, {0.97561})

    def test_declaring_the_deployment_an_api_changes_the_cutoff_it_is_priced_at(self):
        decisions, _s, _h, _c = self.run_scenario(
            'scanner-recon', autonomy=True, default_profile='api')
        self.assertEqual(self._profiles(decisions), {'api'})
        thresholds = {record['observations']['autonomous']['threshold']
                      for record in decisions}
        self.assertEqual(thresholds, {0.987654})

    def test_a_service_scope_prices_the_service_it_names(self):
        """A mapped destination port prices the windows that touch it.

        The port comes from the generated plan, not from this file: the seed
        decides where a sequential scan starts, and an assertion about port 22
        would be an assertion about one seed. `api` wins over the deployment
        default because it is the more protective of the two candidates, not
        because it is the more specific one.
        """
        port = self.ports_for('scanner-recon')[0]
        scope = f'SERVICE:{port}/tcp'
        decisions, _s, _h, _c = self.run_scenario(
            'scanner-recon', autonomy=True, cost_profiles={scope: 'api'})
        self.assertIn('api', self._profiles(decisions))
        priced = [record for record in decisions
                  if record['observations']['autonomous']['scope'] == scope]
        self.assertTrue(priced, f'no window was priced at {scope}')

    def test_a_mapped_service_takes_precedence_over_the_deployment_default(self):
        """`GLOBAL` is the fallback, not a competitor.

        An operator who maps a service has said something more specific than
        "this machine is an API". A rule that let the default win whenever it
        was the more protective would make every profile cheaper than the
        default unreachable from `[autonomy.cost_profiles]` — configuration that
        appears to work and does not.

        The adversarial property is unaffected and is asserted in
        `tests/test_p15_5r_scope_adversarial.py`: a source cannot evict a scope,
        and every service it adds can only move the answer towards the most
        protective of the ones that apply.
        """
        port = self.ports_for('scanner-recon')[0]
        decisions, _s, _h, _c = self.run_scenario(
            'scanner-recon', autonomy=True, default_profile='api',
            cost_profiles={f'SERVICE:{port}/tcp': 'honeypot'})
        self.assertEqual(self._profiles(decisions), {'honeypot'})

    def test_payment_webhook_refuses_a_network_block_at_any_probability(self):
        """§14. Not a high cutoff — a profile that forbids the action."""
        decisions, _s, _h, counters = self.run_scenario(
            'scanner-recon', autonomy=True, default_profile='payment_webhook')
        self.assertEqual(self._profiles(decisions), {'payment_webhook'})
        self.assertEqual(counters['blocks'], 0,
                         'a payment_webhook deployment reached a network block')
        codes = set()
        for record in decisions:
            codes.update(record['observations']['autonomous']['reason_codes'])
        self.assertIn('NETWORK_BLOCK_NOT_PERMITTED', codes)


if __name__ == '__main__':
    unittest.main()
