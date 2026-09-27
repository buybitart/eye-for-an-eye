"""The whole product, once, from a packet to a firewall request. P15.5 §5-§7.

This is the test P15.4 did not have. That cycle ran 2283 unit tests, every one of
them passing, against a build whose autonomous decision path refused all 889
qualifying windows because two components disagreed about an integer. Nothing
smaller than an end-to-end run could have caught it, and nothing smaller has been
added since — so it is added here, and it is a release blocker rather than a
nice-to-have.

`training/p15_5_smoke.py` does the work; this file states what must be true of it.
The split is deliberate: the harness has to produce a document the final report
can quote, and a test that computed its own numbers privately would leave the
report quoting something nobody checked.

**What passing means, and what it does not.** §41 is explicit and it is worth
repeating where somebody will read it: this exercises wiring. Six behaviours is
not a benchmark, the expectations encode *which components must participate*
rather than which answers are correct, and no number produced here may be quoted
as detection evidence. The locked corpus is what measures detection.

The run takes some seconds — it renders six captures, parses them with the
production PCAP reader and takes every window through the full decision path — so
it happens once for the whole module rather than once per assertion.
"""
import unittest

from training.p15_5_smoke import MUST_BLOCK, NO_BLOCK, SCENARIOS, STRONG_EVIDENCE, run

DOCUMENT = None


def setUpModule():
    global DOCUMENT
    DOCUMENT = run()


class TestTheWholeChainIsConnected(unittest.TestCase):
    """§5. Every stage between a packet and an EnforcementRequest, in one run."""

    def test_the_smoke_run_passes(self):
        failures = {name: result['reasons']
                    for name, result in DOCUMENT['scenarios'].items()
                    if result['verdict'] != 'PASS'}
        self.assertEqual(DOCUMENT['verdict'], 'PASS', f'scenario failures: {failures}')

    def test_every_stage_verdict_passes(self):
        for stage, verdict in sorted(DOCUMENT['stage_verdicts'].items()):
            with self.subTest(stage=stage):
                self.assertEqual(verdict, 'PASS')

    def test_the_production_parser_read_every_capture(self):
        """A parse error here is a defect in the capture writer or the reader,
        and P15.4 shipped one: a microsecond rounding to exactly 1000000 made a
        capture unreadable. Writing the PCAP to disk and reading it back is what
        puts that pair under test."""
        for name, result in sorted(DOCUMENT['scenarios'].items()):
            with self.subTest(scenario=name):
                self.assertEqual(result['ingest']['parse_errors'], 0)
                self.assertGreater(result['ingest']['events'], 0)

    def test_every_scenario_produced_windows_to_decide_on(self):
        for name, result in sorted(DOCUMENT['scenarios'].items()):
            with self.subTest(scenario=name):
                self.assertGreater(result['windows'], 0,
                                   'a behaviour that produces no window tests nothing')


class TestRequiredSignalsArePresent(unittest.TestCase):
    """§7. Not the final action — what each stage actually produced.

    ALLOW is a valid final action and it was the *only* action P15.4 could
    produce. Asserting the action alone would have passed that build.
    """

    def test_an_authentication_outcome_reached_the_correlation_engine(self):
        for scenario in SCENARIOS:
            if not scenario.authenticates:
                continue
            with self.subTest(scenario=scenario.name):
                self.assertGreater(
                    DOCUMENT['scenarios'][scenario.name]['ingest']['auth_outcomes'], 0,
                    'the parser saw no authentication outcome; `AuthLedger.features` '
                    'had zero callers for the whole of P15.4 and this is the '
                    'assertion that would have said so')

    def test_the_auth_ledger_populated_the_schema_2_columns(self):
        for scenario in SCENARIOS:
            if not scenario.authenticates:
                continue
            windows = DOCUMENT['scenarios'][scenario.name]
            with self.subTest(scenario=scenario.name):
                self.assertIsNotNone(windows['max_auth_behavior'],
                                     'AUTH_BEHAVIOR was None in every window, which '
                                     'means no authentication column was populated')

    def test_auth_behavior_rises_on_an_authentication_attack(self):
        for scenario in SCENARIOS:
            if scenario.expect != STRONG_EVIDENCE:
                continue
            with self.subTest(scenario=scenario.name):
                self.assertGreater(DOCUMENT['scenarios'][scenario.name]['max_auth_behavior'], 0)

    def test_a_family_score_entered_the_composition(self):
        for name, result in sorted(DOCUMENT['scenarios'].items()):
            with self.subTest(scenario=name):
                self.assertTrue(result['families_ever_observed'])

    def test_every_window_was_scored_by_the_formula_in_force(self):
        for name, result in sorted(DOCUMENT['scenarios'].items()):
            with self.subTest(scenario=name):
                self.assertEqual(result['worst_window']['math_version'], 'math-risk-v4')

    def test_the_calibrator_was_invoked_and_returned_a_finite_probability(self):
        for name, result in sorted(DOCUMENT['scenarios'].items()):
            with self.subTest(scenario=name):
                self.assertIsNotNone(result['max_probability'])
                self.assertTrue(result['worst_window']['probability_finite'])
                self.assertTrue(result['worst_window']['calibrator_version'])

    def test_maturity_was_evaluated_for_every_window(self):
        for name, result in sorted(DOCUMENT['scenarios'].items()):
            with self.subTest(scenario=name):
                self.assertTrue(result['maturity_modes'])
                self.assertTrue(result['worst_window']['maturity_evaluated'])


class TestBenignBehavioursAreNotBlocked(unittest.TestCase):
    """§6, §31. The half that matters more, because it is the half with a cost."""

    def test_no_benign_behaviour_reached_temp_block(self):
        for scenario in SCENARIOS:
            if scenario.expect != NO_BLOCK:
                continue
            with self.subTest(scenario=scenario.name):
                self.assertEqual(DOCUMENT['scenarios'][scenario.name]['blocked_windows'], 0)

    def test_the_authenticated_batch_client_authenticated_and_was_not_blocked(self):
        """§31, permanently. This client's only unusual property is that it
        authenticates successfully on every request, and under `math-risk-v3` a
        weight-3.0 credential-*presence* term blocked 21 of its 22 sources. The
        two assertions have to hold together: not blocked is trivial to achieve
        by not looking, so the test also requires that the outcome was seen."""
        result = DOCUMENT['scenarios']['authenticated-batch-api']
        self.assertGreater(result['ingest']['auth_outcomes'], 0)
        self.assertEqual(result['blocked_windows'], 0)


class TestTheLastTwoStages(unittest.TestCase):
    """authority -> PolicyGuard -> validated EnforcementRequest.

    The chain's end, and the part with a firewall rule behind it.
    """

    def test_a_block_eligible_scanner_reaches_temp_block(self):
        for scenario in SCENARIOS:
            if scenario.expect != MUST_BLOCK:
                continue
            with self.subTest(scenario=scenario.name):
                self.assertGreater(DOCUMENT['scenarios'][scenario.name]['blocked_windows'], 0)

    def test_the_block_becomes_a_validated_enforcement_request(self):
        request = DOCUMENT['scenarios']['scanner-recon']['enforcement_request']
        self.assertTrue(request and request['built'])
        self.assertTrue(request['names_its_decision'],
                        'a request that cannot name its decision cannot be audited')
        self.assertGreater(request['ttl_seconds'], 0)

    def test_the_request_that_crosses_the_privilege_boundary_carries_no_command(self):
        """The privileged helper parses this value and nothing else. Checked on
        the serialised request rather than on the dataclass, because what the
        helper receives is the JSON."""
        request = DOCUMENT['scenarios']['scanner-recon']['enforcement_request']
        self.assertTrue(request['carries_no_command_field'])

    def test_no_benign_scenario_produced_an_enforcement_request(self):
        for scenario in SCENARIOS:
            if scenario.expect != NO_BLOCK:
                continue
            with self.subTest(scenario=scenario.name):
                self.assertIsNone(DOCUMENT['scenarios'][scenario.name]['enforcement_request'])


if __name__ == '__main__':
    unittest.main()
