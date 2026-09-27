"""The §46 properties, asserted on what a running sensor actually wrote.

P15.5R §46. The safety list is eleven properties: no hack-back, no remote active
retaliation, no uncontrolled probing, temporary block only, twelve-hour maximum,
management protection, CDN/proxy protection, owned nftables objects only, a
mass-block breaker, automatic expiry, and no raw secret persistence.

Ten of them are proved structurally in `tests/test_p15_invariants.py`, and
rightly: "no module in this package imports anything that can write a rule" is a
property of the source and is best checked against the source. This file exists
for the ones whose structural proof is not the whole claim.

**No raw secret persistence** is the clearest case. The journal and export tests
prove the *sanitiser* refuses a sensitive field wherever it appears, using
fabricated records built to contain one. That is the right test for a sanitiser
and it cannot answer the question an operator has, which is about the file on
their disk: after a sensor has run, is there anything in it that should not be?
So the check here is on the artifact -- every key name in every line a real
runtime wrote, and every literal address anywhere in it.

**Management protection** is the second. `PolicyGuard` refuses a protected
source and the privileged helper refuses again at the side-effect boundary, and
both are tested. What neither answers is whether the assembled runtime routes a
protected source through them at all, which is exactly the class of question
P15.5 found the wrong answer to.

This file drives `EventRuntime` and reads what came out. It calls no authority,
no enforcer and no writer directly.
"""
import json
from pathlib import Path
import re
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]

#: Field-name fragments that must never name a key in a persisted record. The
#: same vocabulary `security/redaction.sensitive_key` refuses, plus the shapes a
#: future field might arrive in: a raw payload or request body is not a secret by
#: name and is one by content.
FORBIDDEN_KEY_FRAGMENTS = (
    'password', 'passwd', 'authorization', 'cookie', 'token', 'secret',
    'credential', 'api_key', 'apikey', 'bearer', 'session_id', 'private',
    'payload', 'request_body', 'body', 'header', 'query_string', 'user_agent')

#: A literal dotted quad anywhere in a file, in any field, however nested.
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


def _scapy():
    try:
        import scapy.layers.inet  # noqa: F401
        return True
    except ImportError:
        return False


requires_packets = unittest.skipUnless(_scapy(), 'the traffic needs scapy to render')


def keys_in(document, found=None):
    """Every key name anywhere in a document, however deep."""
    found = set() if found is None else found
    if isinstance(document, dict):
        for key, value in document.items():
            found.add(key)
            keys_in(value, found)
    elif isinstance(document, list):
        for value in document:
            keys_in(value, found)
    return found


@requires_packets
class RunningSensorCase(unittest.TestCase):
    """One rendered behaviour, driven through the real runtime per test."""

    @classmethod
    def setUpClass(cls):
        cls._workspace = tempfile.TemporaryDirectory()
        cls.events, cls.source = cls._render()

    @classmethod
    def tearDownClass(cls):
        cls._workspace.cleanup()

    @classmethod
    def _render(cls):
        import os
        from dataset.collectors.pcap import events as pcap_events
        from dataset.generators import scanner
        from dataset.generators.packets import render, write_pcap
        from eye_for_an_eye.config import Config

        # The same plan `tests/test_p15_5r_backpressure.py` renders, and
        # deliberately so. The seed is derived from these three strings, so a
        # different scenario id is different traffic — and the first version of
        # this file used one whose traffic never reached a block, which the
        # control test below caught. A protection test on a behaviour that
        # cannot be blocked proves nothing, so the fixture has to be one that
        # can, and the control is what keeps that honest.
        plan = scanner.sequential_scan('p15-5r-backpressure', 'backpressure',
                                       'p15.5r-runtime', port_count=90, period=0.9)
        rows, _budget = render(plan)
        capture = Path(cls._workspace.name) / 'audit.pcap'
        write_pcap(capture, rows)
        parser_config = Config()
        parser_config.storage.enabled = False
        if os.geteuid() == 0:
            # Same excuse, same reason, same limitation as
            # `tests/test_p15_5r_runtime_enforcement.py`: the fixture's reader
            # only, so the file still runs when the suite is run privileged.
            parser_config.runtime.enforce_unprivileged = False
        events, stats = pcap_events(capture, parser_config)
        assert stats['parse_errors'] == 0, stats
        assert events, 'the controlled traffic produced no events'
        return events, plan.source

    #: A network that does not contain the generated source, checked rather
    #: than assumed. The first version of this file used `192.0.2.0/24` as the
    #: *unprotected* control and the generator's source is `192.0.2.231`, so the
    #: control protected the attacker and both tests ran the same experiment.
    #: The control test caught it, which is what a control is for.
    UNRELATED_NETWORK = '203.0.113.0/24'

    def protecting_network(self):
        """The /24 the generated source is actually in."""
        import ipaddress
        network = ipaddress.ip_network(f'{self.source}/24', strict=False)
        assert ipaddress.ip_address(self.source) in network
        return str(network)

    def unrelated_network(self):
        import ipaddress
        network = ipaddress.ip_network(self.UNRELATED_NETWORK)
        assert ipaddress.ip_address(self.source) not in network, (
            f'{self.UNRELATED_NETWORK} now contains the generated source '
            f'{self.source}, so the control protects it and proves nothing')
        return str(network)

    def drive(self, *, include_source=False, management=None):
        from tests.test_p15_5r_runtime_end_to_end import drive, runtime_config
        management = (self.UNRELATED_NETWORK,) if management is None else management
        directory = Path(self._workspace.name)
        stamp = f'{include_source}-{"-".join(management).replace("/", "_")}'
        journal = directory / f'journal-{stamp}.jsonl'
        export = directory / f'export-{stamp}.jsonl'
        for path in (journal, export):
            path.unlink(missing_ok=True)
        config = runtime_config(autonomy=True, mode='shadow',
                                workspace=self._workspace.name)
        config.enforcement.management_networks = list(management)
        config.autonomy.decision_journal_path = str(journal)
        config.autonomy.shadow_export_path = str(export)
        config.autonomy.journal_include_source = bool(include_source)
        records, snapshot, health, counters = drive(config.validate(), self.events)
        return {'records': records, 'health': health, 'counters': counters,
                'journal': journal, 'export': export,
                'summaries': [record['observations']['autonomous']
                              for record in records
                              if 'autonomous' in record['observations']]}

    @staticmethod
    def lines(path):
        return [json.loads(line) for line in
                path.read_text(encoding='utf-8').splitlines() if line.strip()]


class TestNoRawSecretIsPersisted(RunningSensorCase):
    """§46, on the files rather than on the sanitiser."""

    def assert_no_forbidden_key(self, documents, label):
        names = set()
        for document in documents:
            names |= keys_in(document)
        self.assertTrue(names, f'{label} was empty, so this test checked nothing')
        offenders = sorted(name for name in names
                           if any(fragment in name.lower()
                                  for fragment in FORBIDDEN_KEY_FRAGMENTS))
        self.assertEqual(offenders, [],
                         f'{label} contains {offenders}, which is a field name a '
                         f'raw secret arrives under')

    def test_the_journal_a_real_run_wrote_names_no_sensitive_field(self):
        result = self.drive()
        self.assertGreater(result['counters']['journalled'], 0)
        self.assert_no_forbidden_key(self.lines(result['journal']), 'the journal')

    def test_the_export_a_real_run_wrote_names_no_sensitive_field(self):
        result = self.drive()
        self.assertGreater(result['counters']['exported'], 0)
        self.assert_no_forbidden_key(self.lines(result['export']), 'the export')

    def test_the_export_carries_no_literal_address_at_any_setting(self):
        """Including the setting that puts the address back in the journal.

        `journal_include_source` is the operator's choice about their own
        forensic file. It is not a choice about the export, which is the file
        meant to be aggregated and moved, and a setting that quietly widened
        both would be the kind of coupling nobody discovers until the data has
        left the machine.
        """
        for include_source in (False, True):
            with self.subTest(journal_include_source=include_source):
                result = self.drive(include_source=include_source)
                text = result['export'].read_text(encoding='utf-8')
                self.assertEqual(sorted(set(IPV4.findall(text))), [],
                                 'a literal address reached the shadow export')

    def test_the_journal_keeps_the_address_only_when_the_operator_asked(self):
        """The other half: a privacy default that nothing can turn off is a bug too."""
        without = self.drive(include_source=False)
        self.assertNotIn(self.source,
                         without['journal'].read_text(encoding='utf-8'))
        with_source = self.drive(include_source=True)
        self.assertIn(self.source,
                      with_source['journal'].read_text(encoding='utf-8'),
                      'the operator asked for the address and did not get it')

    def test_every_persisted_record_identifies_its_source_pseudonymously(self):
        """A record nobody can correlate is not a forensic record."""
        result = self.drive()
        for label, path in (('journal', result['journal']),
                            ('export', result['export'])):
            for document in self.lines(path):
                with self.subTest(file=label):
                    self.assertIn('source_pseudonym', keys_in(document))


class TestTheJournalExplainsAShadowBlockOnItsOwn(RunningSensorCase):
    """P15S §7, on a running sensor rather than on a fixture.

    The unit tests in `tests/test_p15_5r_journal.py` prove the outcome carries
    the reason. This proves the sensor writes it -- which is the claim that
    failed before, because the value was computed correctly and recorded in the
    wrong place.
    """

    def test_a_shadow_block_entry_answers_why_nothing_happened(self):
        result = self.drive()
        entries = self.lines(result['journal'])
        blocks = [e['entry'] for e in entries
                  if e['entry']['decision']['action'] == 'TEMP_BLOCK']
        self.assertTrue(blocks, 'no window reached a block, so this proves nothing')
        for entry in blocks:
            with self.subTest(decision=entry['decision']['decision_id']):
                self.assertEqual(entry['would_action'], 'TEMP_BLOCK')
                self.assertEqual(entry['actual_action'], 'NONE')
                self.assertEqual(entry['enforcement_withheld'], 'shadow_mode')

    def test_the_journal_and_the_export_agree_without_being_joined(self):
        """§42 cross-surface consistency, on the three fields §7 names."""
        result = self.drive()
        journal = {e['entry']['decision']['decision_id']: e['entry']
                   for e in self.lines(result['journal'])}
        export = {row['decision_id']: row for row in self.lines(result['export'])}
        self.assertTrue(journal and export)
        self.assertEqual(set(journal), set(export),
                         'the journal and the export disagree about which '
                         'decisions happened')
        for decision_id, entry in journal.items():
            with self.subTest(decision=decision_id):
                row = export[decision_id]
                self.assertEqual(entry['would_action'], row['would_action'])
                self.assertEqual(entry['actual_action'], row['actual_action'])
                self.assertEqual(entry['enforcement_withheld'],
                                 row['enforcement_withheld'])

    def test_an_allow_is_not_given_a_reason_it_did_not_have(self):
        result = self.drive()
        allows = [e['entry'] for e in self.lines(result['journal'])
                  if e['entry']['decision']['action'] == 'ALLOW']
        self.assertTrue(allows)
        for entry in allows:
            with self.subTest(decision=entry['decision']['decision_id']):
                self.assertEqual(entry['actual_action'], 'NONE')
                self.assertEqual(entry['enforcement_withheld'], '')


class TestManagementProtectionSurvivesTheAssembly(RunningSensorCase):
    """§46, asserted on the runtime rather than on the guard.

    `PolicyGuard` refuses a protected source and the privileged helper refuses
    again at the side-effect boundary. Both are tested. Neither answers whether
    the assembled runtime routes a protected source through them, which is the
    question P15.5 found the wrong answer to about a different component.
    """

    def test_a_source_inside_a_management_network_is_never_block_eligible(self):
        protected = self.drive(management=(self.protecting_network(),))
        self.assertTrue(protected['summaries'],
                        'the runtime produced no autonomous decision')
        blocked = [s for s in protected['summaries'] if s['action'] == 'TEMP_BLOCK']
        self.assertEqual(blocked, [],
                         'the source was inside a configured management network '
                         'and still reached a block decision')

    def test_the_same_traffic_does_reach_a_block_when_it_is_not_protected(self):
        """The control. Without it the test above passes on a broken detector.

        And it earned its place: it failed twice before this file was right,
        once on a behaviour that never reached a block and once on a control
        network that contained the source.
        """
        unprotected = self.drive(management=(self.unrelated_network(),))
        blocked = [s for s in unprotected['summaries']
                   if s['action'] == 'TEMP_BLOCK']
        self.assertTrue(blocked,
                        'this behaviour no longer reaches a block at all, so the '
                        'protection test above proves nothing')

    def test_the_protected_refusal_is_recorded_rather_than_silent(self):
        protected = self.drive(management=(self.protecting_network(),))
        reasons = set()
        for summary in protected['summaries']:
            reasons |= set(summary['reason_codes'])
        self.assertTrue(
            any('PROTECT' in code or 'POLICY' in code or 'REFUS' in code
                for code in reasons),
            f'nothing in the reason codes says why this source was spared: {sorted(reasons)}')


if __name__ == '__main__':
    unittest.main()
