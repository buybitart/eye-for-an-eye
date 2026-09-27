"""The P15 documentation must describe the code that exists, and nothing more.

Same reasoning as the P11, P12 and P14 documentation tests, with one addition:
§1 and §201 name the sentences this feature must never be described with. They
are the sentences that make an autonomous defender sound like something it is
not, and a security tool that oversells its autonomy gets deployed by people who
think they no longer have to look.

Checks are on specific, checkable claims — numbers, names, defaults, promises —
and deliberately not on the prose. Forbidden claims are checked with
`denial.asserted` rather than a plain substring search, because several of these
pages quote a wrong idea in order to reject it, and a test whose easiest fix is
deleting the clearest sentence on the page is a badly designed test.
"""
import re
import unittest
from pathlib import Path

from denial import asserted
from eye_for_an_eye.autonomy.authority import DecisionGates
from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.autonomy.record import MAX_BLOCK_TTL_SECONDS
from eye_for_an_eye.config import Config

DOCS = Path(__file__).resolve().parents[1] / 'docs'
ROOT = DOCS.parent
REQUIRED = ('AUTONOMOUS_MODE.md', 'AUTONOMOUS_DECISION.md',
            'COST_SENSITIVE_POLICY.md', 'DECISION_UNCERTAINTY.md',
            'SCIENTIFIC_BASIS.md', 'MODULE_GRADUATION.md',
            'AUTONOMOUS_FAILURE_RECOVERY.md', 'AUTONOMOUS_SAFETY_INVARIANTS.md',
            'AUTONOMOUS_DATA_CURATION.md')


def read(name):
    return (DOCS / name).read_text(encoding='utf-8')


def flat(name):
    return ' '.join(read(name).split())


def everything():
    return ' '.join(flat(name) for name in REQUIRED).lower()


class TestTheDocumentsExist(unittest.TestCase):

    def test_every_required_document_is_present(self):
        for name in REQUIRED:
            with self.subTest(document=name):
                self.assertTrue((DOCS / name).is_file(), name)

    def test_none_of_them_is_a_stub(self):
        for name in REQUIRED:
            with self.subTest(document=name):
                self.assertGreater(len(read(name)), 1500, name)

    def test_every_internal_link_points_at_a_real_file(self):
        for name in REQUIRED:
            for target in re.findall(r'\]\(([A-Za-z0-9_./-]+\.md)\)', read(name)):
                with self.subTest(document=name, link=target):
                    self.assertTrue((DOCS / target).is_file()
                                    or (ROOT / target).is_file(),
                                    f'{name} links to missing {target}')

    def test_the_readme_links_to_the_autonomous_mode_page(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertIn('docs/AUTONOMOUS_MODE.md', readme)
        self.assertIn('docs/SCIENTIFIC_BASIS.md', readme)


class TestTheForbiddenClaims(unittest.TestCase):
    """§1, §201. The sentences that would make this sound like something else."""

    FORBIDDEN = ('100% detection', '100% accurate', '100% protection',
                 'zero false positives', 'no false positives',
                 'perfect protection', 'perfect attacker detection',
                 'stops every hacker', 'blocks every attack',
                 'guaranteed protection', 'complete protection',
                 'always correct', 'never wrong')

    def test_no_document_makes_a_forbidden_claim(self):
        body = everything()
        for phrase in self.FORBIDDEN:
            with self.subTest(phrase=phrase):
                self.assertFalse(asserted(body, phrase),
                                 f'a P15 document claims {phrase!r}')

    def test_the_readme_makes_none_of_them_either(self):
        body = ' '.join((ROOT / 'README.md').read_text(encoding='utf-8').split()).lower()
        for phrase in self.FORBIDDEN:
            with self.subTest(phrase=phrase):
                self.assertFalse(asserted(body, phrase))

    def test_autonomy_and_accuracy_are_kept_apart(self):
        body = flat('AUTONOMOUS_MODE.md')
        self.assertIn('Autonomy is an operational property', body)
        self.assertIn('Accuracy is an empirical property', body)

    def test_the_pages_say_autonomy_does_not_remove_safety_controls(self):
        body = everything()
        self.assertIn('the safety controls run automatically too', body)


class TestTheDocumentedNumbersMatchTheCode(unittest.TestCase):
    """Numbers in a table rot faster than anything else in a document."""

    def test_every_cost_profile_and_cutoff_is_documented_correctly(self):
        body = flat('COST_SENSITIVE_POLICY.md')
        for name, profile in PROFILES.items():
            with self.subTest(profile=name):
                self.assertIn(name, body)
                self.assertIn(f'{profile.threshold:.4f}', body)

    def test_the_payment_profile_is_documented_as_never_network_blocking(self):
        self.assertFalse(PROFILES['payment_webhook'].network_block_permitted)
        self.assertIn('never', flat('COST_SENSITIVE_POLICY.md'))

    def test_the_block_ladder_matches_the_gates(self):
        body = flat('AUTONOMOUS_DECISION.md')
        ladder = ', '.join(f'{value}s' for value in DecisionGates().block_ttl_ladder)
        self.assertIn(ladder, body)
        self.assertIn(str(MAX_BLOCK_TTL_SECONDS), body)

    def test_the_evidence_gates_match_the_defaults(self):
        gates = DecisionGates()
        body = flat('AUTONOMOUS_DECISION.md')
        self.assertIn(f'at least {gates.minimum_signal_diversity} distinct families',
                      body)
        self.assertIn(f'at least {gates.minimum_behavioural_diversity} must be', body)

    def test_the_ten_signal_families_are_all_named(self):
        from eye_for_an_eye.autonomy.evidence import FAMILIES
        body = flat('AUTONOMOUS_DECISION.md')
        for family in FAMILIES:
            with self.subTest(family=family):
                self.assertIn(family, body)

    def test_every_capitalised_token_the_decision_page_names_is_real(self):
        """A page naming a reason code that no longer exists is worse than silent."""
        from eye_for_an_eye.autonomy.evidence import FAMILIES
        from eye_for_an_eye.autonomy.record import REASON_CODES
        known = set(REASON_CODES) | set(FAMILIES) | {
            'ALLOW', 'TEMP_BLOCK', 'OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT'}
        for token in re.findall(r'`([A-Z][A-Z_]{4,})`', flat('AUTONOMOUS_DECISION.md')):
            with self.subTest(token=token):
                self.assertIn(token, known)

    def test_the_technical_faults_are_all_documented(self):
        from eye_for_an_eye.autonomy.breakers import TECHNICAL_FAULTS
        body = flat('AUTONOMOUS_FAILURE_RECOVERY.md')
        for fault in TECHNICAL_FAULTS:
            with self.subTest(fault=fault):
                self.assertIn(fault, body)

    def test_the_trusted_outcome_sources_are_all_documented(self):
        body = flat('AUTONOMOUS_FAILURE_RECOVERY.md').lower()
        for phrase in ('controlled lab scenario', 'signed pcap sidecar',
                       'deterministic harness', 'reviewed evaluation'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, body)

    def test_the_budget_defaults_match_the_code(self):
        from eye_for_an_eye.autonomy.breakers import BudgetLimits
        limits = BudgetLimits()
        body = flat('AUTONOMOUS_FAILURE_RECOVERY.md')
        self.assertIn(f'({limits.blocks_per_minute})', body)
        self.assertIn(f'({limits.max_active_blocks})', body)
        self.assertIn(f'{limits.max_block_share:.0%}', body)

    def test_the_readiness_checks_are_all_listed(self):
        from eye_for_an_eye.autonomy.runtime import evaluate_readiness
        body = flat('AUTONOMOUS_MODE.md')
        for check in evaluate_readiness(Config()).checks:
            with self.subTest(check=check.name):
                self.assertIn(check.name, body)


class TestTheDefaultsAreDocumentedHonestly(unittest.TestCase):

    def test_the_pages_say_autonomy_is_off_until_an_administrator_enables_it(self):
        self.assertFalse(Config().autonomy.enabled)
        self.assertEqual(Config().autonomy.mode, 'shadow')
        body = flat('AUTONOMOUS_MODE.md')
        self.assertIn('the default', body)
        self.assertIn('after an administrator enables it', body)
        readme = ' '.join((ROOT / 'README.md').read_text(encoding='utf-8').split())
        self.assertIn('It is off until you do.', readme)

    def test_the_autonomous_mode_page_keeps_the_two_blocking_paths_apart(self):
        """The same repair `test_the_readme_keeps_the_two_blocking_paths_apart`
        made to the README, made here five phases late.

        This test used to assert the sentence *"there is no code path in this
        project that blocks a source on a real host, and no setting that creates
        one"*. That was true when it was written and stopped being true when
        `enforcement.host_enabled` was built in P15.1. The README was repaired
        then and this page was not, and this test is the reason: it held the
        false sentence in place, so the page could not be corrected without a
        failing test to explain.

        A documentation test that pins a claim pins it whether or not it is
        still true, which makes it worth stating what such a test may pin: a
        property of the code, checked against the code where possible, and never
        a sentence for its own sake. What is pinned below is that both paths are
        described, that the lab gate is still described as a gate, and that the
        page does not promise the code cannot reach a real firewall.
        """
        body = flat('AUTONOMOUS_MODE.md')
        self.assertIn('/proc/1/ns/net', body)
        self.assertIn('enforcement.host_enabled', body)
        self.assertIn('HOST_ENFORCEMENT.md', body)
        self.assertIn('off on a fresh installation', body)
        self.assertFalse(
            asserted(body.lower(),
                     'there is no code path in this project that blocks a source '
                     'on a real host'),
            'AUTONOMOUS_MODE.md still promises the code cannot reach a real host')
        # Checked against the code, not against the page: both switches exist
        # and both are off, which is the property the prose describes.
        self.assertFalse(Config().enforcement.enabled)
        self.assertFalse(Config().enforcement.host_enabled)

    def test_the_documented_way_to_stop_it_is_one_that_exists(self):
        """A kill switch that does not exist is worse than no kill switch.

        Both pages documented `eye-for-an-eye autonomy disable` as the kill
        switch -- "local, immediate" -- and the command has never existed. An
        operator following it in an emergency would have got an argparse usage
        message.
        """
        from eye_for_an_eye.autonomy_cli import autonomy_command  # noqa: F401
        for name in ('AUTONOMOUS_MODE.md', 'AUTONOMOUS_FAILURE_RECOVERY.md'):
            with self.subTest(document=name):
                body = flat(name)
                self.assertFalse(
                    asserted(body.lower(), 'eye-for-an-eye autonomy disable'),
                    f'{name} documents a command that does not exist')
                self.assertIn('enabled = false', body)

    def test_every_documented_subcommand_is_one_the_cli_accepts(self):
        """The durable form of the defect above.

        Every `eye-for-an-eye autonomy <action>` anywhere in the documentation
        is checked against the parser's own choices, so the next invented
        subcommand fails here instead of failing an operator.

        Two of these pages now name the command that never existed *in order to
        say it never existed*, so a plain scan would fail on the sentence that
        fixes the defect -- the badly designed test this module's header warns
        about. `denial.asserted` is the usual instrument for that and it is the
        wrong one here: a command inside a fenced code block has no prose around
        it, so the window picks up whatever sentence preceded the block and an
        unrelated "not" two sentences earlier hides a real command. It hid
        `autonomy enable`, which is the most important one on the page.

        So the rule is the structural one instead. A command in a code block is
        an instruction and is always checked; a command in prose is checked only
        when it is not being denied.
        """
        import contextlib
        import io
        from eye_for_an_eye.autonomy_cli import autonomy_command
        pattern = re.compile(r'eye-for-an-eye autonomy ([a-z][a-z-]*)')
        found = set()
        for path in sorted(DOCS.glob('*.md')) + [ROOT / 'README.md']:
            raw = path.read_text(encoding='utf-8')
            fenced = '\n'.join(re.findall(r'^```.*?^```', raw,
                                          re.MULTILINE | re.DOTALL)).lower()
            prose = ' '.join(re.sub(r'^```.*?^```', ' ', raw,
                                    flags=re.MULTILINE | re.DOTALL).split()).lower()
            found |= {(path.name, action) for action in pattern.findall(fenced)}
            found |= {(path.name, action) for action in pattern.findall(prose)
                      if asserted(prose, f'eye-for-an-eye autonomy {action}')}
        self.assertTrue(found, 'no autonomy commands found; the pattern broke')
        self.assertIn(('AUTONOMOUS_MODE.md', 'enable'), found,
                      'the scan lost a command that is plainly documented')
        for name, action in sorted(found):
            with self.subTest(document=name, action=action):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        autonomy_command([action, '--help'])
                # `--help` exits 0 for a real action and 2 for an unknown one.
                self.assertEqual(raised.exception.code, 0,
                                 f'{name} documents `autonomy {action}`, which the '
                                 f'CLI rejects: {stderr.getvalue().strip()[:200]}')

    def test_the_readme_keeps_the_two_blocking_paths_apart(self):
        """P15.1 added a real-host path. The lab claim was true and is now half true.

        This replaces a P15 test that pinned the sentence *"Automatic blocking
        still runs only in a lab namespace"*. That sentence stopped being true
        when `enforcement.host_enabled` was written, and the honest repair is a
        test that pins what is true now — not a README reverted to match a test.

        What is pinned: the namespace path is still described as lab-only, the
        host path is named and described as off and unproven, and the README no
        longer makes the old blanket promise that this software cannot reach a
        real firewall. That promise is the one a reader would act on.
        """
        body = ' '.join((ROOT / 'README.md').read_text(encoding='utf-8').split())
        self.assertIn('lab-only', body)
        self.assertIn('docs/HOST_ENFORCEMENT.md', body)
        self.assertIn('`enforcement.host_enabled`', body)
        self.assertIn('off on a fresh installation', body)
        self.assertIn('a package upgrade cannot turn it on', body)
        self.assertIn('**not in production**', body)
        self.assertFalse(
            asserted(body.lower(), 'refuses to touch your real host firewall'),
            'the README still promises the code cannot reach a real firewall')

    def test_the_readme_states_the_current_measurement_rather_than_an_old_one(self):
        """§45: an evidence problem is not solved by writing around it.

        And a *stale* evidence claim is the same failure pointing the other way.
        This test used to pin "blocks nothing at all" against P15.1's result,
        which P15.5 replaced: 120 blocks of 203 positives, none of them against
        any of 546 benign sources, and zero detection in six behaviour families
        the system claims to cover. The first half of that is better news than
        the sentence it replaced and the second half is the reason the release
        gate still fails, so the front page has to carry both.
        """
        body = ' '.join((ROOT / 'README.md').read_text(encoding='utf-8').split())
        self.assertIn('reports/P15_5_FINAL_RELEASE_VALIDATION.md', body)
        self.assertIn('no false blocks', body)
        self.assertIn('six of the behaviour families', body)
        self.assertIn('nothing at all', body,
                      'the zero-detection families must still be on the front page')
        self.assertFalse(
            asserted(body.lower(), 'it is safe and it does not yet detect'),
            'the README still states P15.1\'s result as the current one')

    def test_the_readme_does_not_read_a_synthetic_result_as_a_real_one(self):
        """`GENERALIZATION_POLICY.md` forbids it, so the front page must not do it."""
        body = ' '.join((ROOT / 'README.md').read_text(encoding='utf-8').split())
        self.assertIn('generated test data', body)
        self.assertIn('Neither is evidence about real traffic', body)
        self.assertIn('docs/SHADOW_VALIDATION_PLAN.md', body)

    def test_the_uncertainty_page_refuses_the_confidence_interval_name(self):
        """The P15 caveat, still true of the quantity it was written about.

        P15.2 added a second bound that *is* a Wilson score interval, so the
        page now describes two quantities. The caveat did not stop applying to
        the first one; it stopped applying to everything on the page. Both
        halves are pinned below, because a page that dropped either would be
        overclaiming in one direction or underclaiming in the other.
        """
        body = flat('DECISION_UNCERTAINTY.md')
        self.assertIn('a credible interval', body)
        self.assertIn('empirical lower estimate', body)
        self.assertIn('borrowing authority the implementation has not earned', body)

    def test_the_uncertainty_page_says_which_bound_is_a_real_interval(self):
        """§90, §91. Two bounds, and the page must not blur them together."""
        body = flat('DECISION_UNCERTAINTY.md')
        self.assertIn('Wilson score interval on a binomial proportion', body)
        self.assertIn('bounds is sampling error in the calibration data', body)
        # The correction applied to the wrong sample size, named as such.
        self.assertIn('number of packets in the window', body)
        self.assertIn('two orders of magnitude too wide', body)
        # And which bound a decision may act on.
        self.assertIn('An artifact with no conservative knots produces no autonomous '
                      'block', body)

    def test_the_uncertainty_page_keeps_the_shrinkage_rather_than_deleting_it(self):
        """§45's rule, checked on the page as well as in the code.

        The shrinkage still governs every uncalibrated decision. A page that
        quietly stopped describing it would make the repair look like a removal.
        """
        body = flat('DECISION_UNCERTAINTY.md')
        self.assertIn('p_shrunk = (1 - u) * p + u * prior', body)
        self.assertIn('The shrinkage was not removed', body)


class TestTheScientificBasisIsStructured(unittest.TestCase):
    """§0 asks for four specific lines per principle. This checks they are there."""

    def test_every_entry_has_all_four_sections(self):
        body = read('SCIENTIFIC_BASIS.md')
        entries = [block for block in body.split('\n---\n') if '**Source concept.**' in block]
        self.assertGreaterEqual(len(entries), 15)
        for entry in entries:
            heading = entry.strip().splitlines()[0]
            with self.subTest(entry=heading):
                for section in ('**Source concept.**', '**Project interpretation.**',
                                '**Implemented component.**', '**Limitation.**'):
                    self.assertIn(section, entry)

    def test_the_required_concepts_are_all_covered(self):
        body = flat('SCIENTIFIC_BASIS.md').lower()
        for concept in ('rare-class', 'confusion matrix', 'precision', 'recall',
                        'specificity', 'class imbalance', 'cost-sensitive',
                        'cross-validation', 'bootstrap', 'uncertainty',
                        'type i and type ii', 'robust statistics',
                        'isolation forest', 'out-of-distribution', 'drift',
                        'leakage', 'model collapse', 'calibration',
                        'continuous monitoring', 'model governance',
                        'adaptive security'):
            with self.subTest(concept=concept):
                self.assertIn(concept, body)

    def test_it_does_not_claim_the_decisions_are_correct(self):
        body = flat('SCIENTIFIC_BASIS.md')
        self.assertIn('Nothing here is evidence that the system’s decisions are '
                      'correct', body.replace("'", '’'))


if __name__ == '__main__':
    unittest.main()
