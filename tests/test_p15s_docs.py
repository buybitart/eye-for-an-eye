"""The pages an operator reads before a Shadow deployment must describe this build.

P15S §1, §5, §6, §57.

§1 names seven documents as the source of truth and adds: *do not trust this
prompt over the repository*. That instruction cuts both ways. A page that has
gone stale is the prompt, not the repository, and reading it is how an operator
arrives at a deployment with a wrong idea of what the software does.

`docs/LIMITATIONS.md` had gone stale in exactly that way. It carried, as the
largest limitation on the page, the P15.5 finding that the autonomous decision
path was not wired into the running sensor -- `DecisionInputs` and `HostEnforcer`
constructed nowhere, `decision/engine.py` not importing `autonomy` at all, no
configuration setting for the calibrator. P15.5R closed all of it and
`reports/P15_5R_RUNTIME_INTEGRATION.md` recorded the closure; the limitations
page was never updated. Its last sentence told a reader that *"a shadow
deployment of the current runtime would produce no evidence about the decision
path at all"* -- which, read before P15S, says the whole exercise is pointless.

So these tests check documentation claims against the code, mechanically. Each
one establishes the code fact first and only then looks at the page, because a
test that compares two sentences pins whichever was written first.

`denial.asserted` rather than a substring search, for the reason that module's
header gives: the corrected page quotes the old finding in order to say it is
closed, and a plain scan would fail on the paragraph that does the correcting.
"""
import ast
from pathlib import Path
import re
import unittest

from denial import asserted

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'


def flat(path):
    return ' '.join(path.read_text(encoding='utf-8').split()).lower()


def constructs(module, name):
    """Does this module contain a call to `name(...)`? Parsed, not grepped."""
    tree = ast.parse((ROOT / module).read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == name:
            return True
    return False


class TestTheDecisionPathIsDescribedAsItIs(unittest.TestCase):
    """The claim that changed, and the four facts that changed it."""

    def setUp(self):
        self.page = flat(DOCS / 'LIMITATIONS.md')

    def test_the_pipeline_constructs_the_inputs_and_the_enforcer(self):
        self.assertTrue(constructs('eye_for_an_eye/autonomy/pipeline.py',
                                   'DecisionInputs'))
        self.assertTrue(constructs('eye_for_an_eye/autonomy/pipeline.py',
                                   'HostEnforcer'))

    def test_the_engine_reaches_the_autonomous_pipeline(self):
        body = (ROOT / 'eye_for_an_eye/decision/engine.py').read_text(encoding='utf-8')
        self.assertIn('from ..autonomy.pipeline import', body,
                      'the engine no longer builds the autonomous pipeline; if '
                      'that is deliberate, LIMITATIONS.md has to say so again')

    def test_there_is_a_configuration_setting_for_the_calibrator(self):
        from eye_for_an_eye.config import Config
        self.assertTrue(hasattr(Config().autonomy, 'calibrator_path'))

    def test_the_page_does_not_still_claim_the_path_is_unwired(self):
        """Checked only after the three facts above, and through `denial`.

        The page states the old finding on purpose, in the past tense, and says
        it is closed. What must not survive is the claim made as a claim.
        """
        for phrase in ('constructed nowhere',
                       'does not import `autonomy` at all',
                       'no configuration setting for the calibrator path'):
            with self.subTest(phrase=phrase):
                self.assertFalse(
                    asserted(self.page, phrase.lower()),
                    f'LIMITATIONS.md asserts {phrase!r}, which P15.5R closed')

    def test_the_page_does_not_tell_a_reader_shadow_is_pointless(self):
        """The sentence that would have stopped P15S before it started."""
        self.assertFalse(
            asserted(self.page, 'would produce no evidence about the decision path'),
            'the page still says a shadow deployment of this runtime would '
            'produce no evidence about the decision path')

    def test_the_page_still_says_the_numbers_are_synthetic(self):
        """The limitation that did *not* go away when the wiring was fixed.

        A wired path is not a measured one. Dropping this sentence along with the
        stale one would turn a correction into an overclaim.
        """
        self.assertIn('synthetic', self.page)
        # Plain containment, not `denial.asserted`. That helper answers "is this
        # phrase claimed rather than only denied", which is the question for a
        # sentence that must be *absent*. Here the sentence must be *present* --
        # and it begins with "no", which `asserted` reads as a denial of itself,
        # so the first version of this test failed on the sentence it was
        # written to protect. The helper is for prohibitions.
        self.assertIn('no such deployment has run', self.page,
                      'the page no longer says this repository holds no real '
                      'traffic evidence, which is still true')


class TestTheLicenceClaimMatchesTheTree(unittest.TestCase):
    def test_a_missing_licence_is_not_claimed_while_one_is_present(self):
        page = flat(DOCS / 'LIMITATIONS.md')
        if (ROOT / 'LICENSE').is_file():
            self.assertFalse(asserted(page, 'still missing: a license file'),
                             'LIMITATIONS.md says the license file is missing '
                             'and LICENSE is in the tree')


class TestTheStopProcedureNamesMechanismsThatExist(unittest.TestCase):
    """§5, §6, §57. Every switch the stop procedure offers must be real.

    The specific failure this guards against has already happened once on this
    page: it documented `eye-for-an-eye autonomy disable`, which has never
    existed. An operator following a stop procedure is, by definition, in a
    hurry and not in a mood to discover that the command is imaginary.
    """

    def setUp(self):
        self.raw = (DOCS / 'AUTONOMOUS_MODE.md').read_text(encoding='utf-8')
        self.page = flat(DOCS / 'AUTONOMOUS_MODE.md')

    def test_the_two_configuration_switches_exist(self):
        from eye_for_an_eye.config import Config
        config = Config()
        self.assertTrue(hasattr(config.autonomy, 'enabled'))
        self.assertTrue(hasattr(config.enforcement, 'host_enabled'))
        self.assertIn('[autonomy] enabled = false', self.raw)
        self.assertIn('host_enabled = false', self.raw)

    def test_the_helper_verb_the_page_prints_is_one_the_helper_accepts(self):
        from eye_for_an_eye.security.firewall_helper import VERBS
        printed = re.findall(r'firewall_helper[^\n]*--config [^\n]*?(\w[\w-]*)\s*$',
                             self.raw, re.MULTILINE)
        self.assertTrue(printed, 'the stop procedure no longer prints a helper '
                                 'command; the pattern or the page changed')
        for verb in printed:
            with self.subTest(verb=verb):
                self.assertIn(verb, VERBS)

    def test_no_page_documents_a_disable_command(self):
        """§5 and §57, across every page rather than this one."""
        for path in sorted(DOCS.glob('*.md')) + [ROOT / 'README.md']:
            with self.subTest(document=path.name):
                self.assertFalse(
                    asserted(flat(path), 'eye-for-an-eye autonomy disable'),
                    f'{path.name} documents a command that does not exist')

    def test_the_absence_of_a_running_kill_switch_is_stated(self):
        """§57 asks for this to stay visible rather than be smoothed over."""
        self.assertIn('no command that disarms a sensor already running',
                      self.page)


if __name__ == '__main__':
    unittest.main()
