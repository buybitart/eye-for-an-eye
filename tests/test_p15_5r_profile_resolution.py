"""Does the cost profile actually reach the arithmetic? P15.5R §20, §21, §22.

### Why this file exists and why it reads the journal

P15.5 found that every locked benchmark since P15.1 had priced every decision at
`public_website`, because the replay harness passed a literal scope. The
per-profile tables in those reports were outcomes *grouped* by profile, not
outcomes *decided* per profile — and nothing in the reports could have shown the
difference, because a grouped table looks identical either way.

So §20 says: do not infer this from grouped output. This file does not.

The same generated traffic is run through the real runtime five times, changing
nothing but the cost profile, and the assertion is made on the **inputs to
ExpectedLoss** as the decision journal records them:

    loss_allow  = conservative_probability * profile.false_allow
    loss_block  = (1 - conservative_probability) * profile.false_block

The conservative probability is a property of the evidence and must be identical
across all five runs. The losses are that number multiplied by the profile's own
costs, which differ by a factor of 250 between `honeypot` and `payment_webhook`.
Identical evidence and five different losses is a fact a grouped table cannot
fake.

This is also the first test that reads the decision journal as a consumer would,
which makes it a check on §2 as well: the record it needs has to actually be
there.
"""
import json
from pathlib import Path
import tempfile
import time
import unittest

from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.config import Config
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime

REPOSITORY = Path(__file__).resolve().parents[1]
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'
SNAPSHOT_INTERVAL = 2.0


def _available():
    try:
        import scapy.layers.inet  # noqa: F401
        return True
    except ImportError:
        return False


class SilentLogger(EventLogger):
    """The real logger, writing nowhere. The evidence here is the journal."""

    def __init__(self, config):
        self.lines = []
        super().__init__(config, writer=self.lines.append)

    def decisions(self):
        out = []
        for line in list(self.lines):
            try:
                body = json.loads(line)
            except ValueError:
                continue
            if body.get('event_type') == EventType.DECISION:
                out.append(body)
        return out


@unittest.skipUnless(_available(), 'packet rendering needs scapy')
class ProfileRuntimeCase(unittest.TestCase):
    """Shared fixture. The traffic is generated once for every class below, so
    "one identical evidence pattern" is a fact about the bytes rather than about
    two generator calls that happen to use the same seed."""

    @classmethod
    def setUpClass(cls):
        from dataset.collectors.pcap import events as pcap_events
        from dataset.generators import scanner
        from dataset.generators.packets import render, write_pcap

        cls._workspace = tempfile.TemporaryDirectory()
        workspace = Path(cls._workspace.name)
        plan = scanner.sequential_scan('p15-5r-profiles', 'scanner-recon',
                                       'p15.5r-profiles', port_count=90, period=0.9)
        rows, _budget = render(plan)
        capture = workspace / 'profiles.pcap'
        write_pcap(capture, rows)
        parser_config = Config()
        parser_config.storage.enabled = False
        cls.events, cls.stats = pcap_events(capture, parser_config)
        cls.port = plan.contacts[0].port

    @classmethod
    def tearDownClass(cls):
        cls._workspace.cleanup()

    def _config(self, *, default_profile, journal, cost_profiles=None):
        config = Config()
        config.decision.enabled = True
        config.decision.mode = 'enforce'
        config.decision.interval_ms = int(SNAPSHOT_INTERVAL * 1000)
        config.enforcement.enabled = False
        config.autonomy.enabled = True
        config.autonomy.mode = 'shadow'
        config.autonomy.calibrator_path = str(CALIBRATOR)
        config.autonomy.default_cost_profile = default_profile
        config.autonomy.cost_profiles = dict(cost_profiles or {})
        config.autonomy.decision_journal_path = str(journal)
        config.storage.enabled = False
        config.api.enabled = False
        config.metrics.enabled = False
        config.logging.file = ''
        config.logging.events_per_second = 100000.0
        config.logging.per_source_per_second = 100000.0
        config.logging.per_event_type_per_second = 100000.0
        config.logging.queue_size = 8192
        config.runtime.queue_events = 8192
        return config.validate()

    def run_under(self, profile_name, *, cost_profiles=None):
        """One run of the identical traffic, returning its journal entries."""
        with tempfile.TemporaryDirectory() as run_space:
            journal = Path(run_space) / 'decisions.jsonl'
            config = self._config(default_profile=profile_name, journal=journal,
                                  cost_profiles=cost_profiles)
            logger = SilentLogger(config.logging)
            runtime = EventRuntime(config, logger=logger, mode='sensor')
            runtime.start()
            try:
                for event in self.events:
                    runtime.emit(event)
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if runtime.queue.empty() and not runtime.analysis.decisions.pending:
                        break
                    time.sleep(0.02)
            finally:
                runtime.close(timeout=10)
            entries = [json.loads(line)['entry']['decision']
                       for line in journal.read_text(encoding='utf-8').splitlines()
                       if line.strip()]
        return entries


@unittest.skipUnless(_available(), 'packet rendering needs scapy')
class TestTheCostProfileReachesExpectedLoss(ProfileRuntimeCase):
    """§20. One evidence pattern, five prices."""

    def test_each_profile_prices_the_same_evidence_with_its_own_costs(self):
        """§20, the whole of it.

        `conservative_probability` is a property of the evidence. `loss_allow`
        and `loss_block` are that number multiplied by the profile's own costs.
        If the profile did not reach the arithmetic, the losses would be equal
        across the five runs; they differ by the ratio of the costs.
        """
        evidence = {}
        for name, profile in sorted(PROFILES.items()):
            with self.subTest(profile=name):
                entries = self.run_under(name)
                self.assertTrue(entries, f'{name} produced no journal entries')
                bounds = set()
                for decision in entries:
                    cost = decision['cost']
                    self.assertEqual(cost['profile'], name)
                    self.assertAlmostEqual(cost['threshold'], profile.threshold,
                                           places=6)
                    conservative = cost['conservative_probability']
                    bounds.add(round(conservative, 9))
                    # `explain()` rounds both the bound and the losses to six
                    # places, so recomputing from the rounded bound carries an
                    # error proportional to the cost. The tolerance is that
                    # rounding and nothing more: at `payment_webhook` it is
                    # 5e-4 against a loss of about 240.
                    self.assertAlmostEqual(
                        cost['loss_allow'], conservative * profile.false_allow,
                        delta=profile.false_allow * 1e-6 + 1e-9,
                        msg='loss_allow does not use this profile\'s false_allow')
                    self.assertAlmostEqual(
                        cost['loss_block'],
                        (1.0 - conservative) * profile.false_block,
                        delta=profile.false_block * 1e-6 + 1e-9,
                        msg='loss_block does not use this profile\'s false_block')
                evidence[name] = bounds

        # The evidence is identical across every run: the same packets, the same
        # parser, the same formula, the same calibrator. Only the price changed.
        distinct = {frozenset(bounds) for bounds in evidence.values()}
        self.assertEqual(len(distinct), 1,
                         'the five runs saw different evidence, so a difference '
                         'in their losses would prove nothing about pricing')

    def test_the_losses_differ_between_the_cheapest_and_the_dearest_profile(self):
        """Stated as one number so the claim is legible: 2 against 500."""
        honeypot = self.run_under('honeypot')
        webhook = self.run_under('payment_webhook')
        cheap = max(d['cost']['loss_block'] for d in honeypot)
        dear = max(d['cost']['loss_block'] for d in webhook)
        self.assertGreater(dear, cheap * 100,
                           f'loss_block was {cheap} at honeypot and {dear} at '
                           f'payment_webhook; the profile is not reaching the '
                           f'arithmetic')

    def test_an_unmapped_deployment_falls_back_to_the_documented_default(self):
        """§12. Not a guess and not the cheapest — the configured fallback."""
        entries = self.run_under('public_website')
        scopes = {d['scope'] for d in entries}
        self.assertEqual(scopes, {'GLOBAL'})
        self.assertEqual({d['cost']['profile'] for d in entries}, {'public_website'})


@unittest.skipUnless(_available(), 'packet rendering needs scapy')
class TestPaymentWebhookRefusesToBlock(ProfileRuntimeCase):
    """§21. Not a high cutoff — a profile that forbids the action."""

    def test_no_window_reaches_a_network_block(self):
        entries = self.run_under('payment_webhook')
        self.assertTrue(entries)
        actions = {decision['action'] for decision in entries}
        self.assertEqual(actions, {'ALLOW'},
                         'a payment_webhook deployment produced a network block')

    def test_the_record_says_why_rather_than_merely_allowing(self):
        entries = self.run_under('payment_webhook')
        codes = set()
        for decision in entries:
            codes.update(decision['reason_codes'])
        self.assertIn('NETWORK_BLOCK_NOT_PERMITTED', codes)

    def test_the_same_evidence_does_reach_a_block_elsewhere(self):
        """So the refusal above is the profile's doing, not the evidence's."""
        entries = self.run_under('public_website')
        self.assertIn('TEMP_BLOCK', {decision['action'] for decision in entries})


@unittest.skipUnless(_available(), 'packet rendering needs scapy')
class TestTheApiCutoffIsTheOneThatApplies(ProfileRuntimeCase):
    """§22. The cutoff eight calibration corpora were fitted to reach."""

    API_CUTOFF = 0.987654
    PUBLIC_WEBSITE_CUTOFF = 0.975610

    def test_an_api_deployment_is_judged_at_the_api_cutoff(self):
        entries = self.run_under('api')
        thresholds = {round(d['cost']['threshold'], 6) for d in entries}
        self.assertEqual(thresholds, {self.API_CUTOFF})
        self.assertNotIn(self.PUBLIC_WEBSITE_CUTOFF, thresholds)

    def test_a_mapped_api_service_is_judged_at_the_api_cutoff(self):
        """The per-service route to the same answer, so the claim does not rest
        on the deployment being declared an API as a whole."""
        scope = f'SERVICE:{self.port}/tcp'
        entries = self.run_under('public_website', cost_profiles={scope: 'api'})
        priced = [d for d in entries if d['scope'] == scope]
        self.assertTrue(priced, f'no window was priced at {scope}')
        for decision in priced:
            with self.subTest():
                self.assertAlmostEqual(decision['cost']['threshold'],
                                       self.API_CUTOFF, places=6)

    def test_the_conservative_bound_the_calibration_work_produced_is_present(self):
        """P15.5 refitted the calibrator so the API cutoff became reachable at
        all. This asserts the runtime carries that bound, not that the bound
        clears the cutoff on this traffic — which would be a detection claim
        about six behaviours and is not one this file makes."""
        entries = self.run_under('api')
        bounds = [d['cost']['conservative_probability'] for d in entries]
        self.assertTrue(bounds)
        self.assertGreater(max(bounds), self.PUBLIC_WEBSITE_CUTOFF)
        for decision in entries:
            with self.subTest():
                self.assertEqual(decision['model']['calibration_version'],
                                 'mathrisk-cal-v4-isotonic')


if __name__ == '__main__':
    unittest.main()
