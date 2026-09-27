"""The P14 documentation must describe the code that exists, and nothing more.

Same reasoning as the P11 and P12 documentation tests, with one addition that
matters more here than anywhere else in the project: §155 lists sentences this
feature must never be described with. They are the sentences that make automatic
model promotion sound like something it is not, and a security tool that oversells
its autonomy gets deployed by people who think they no longer have to look.

The checks are on specific, checkable claims — numbers, names, defaults,
promises — and deliberately not on the prose.
"""
import re
import unittest
from pathlib import Path

from denial import asserted
from eye_for_an_eye.config import Config
from eye_for_an_eye.governance.policy import ACTION_LADDER, GovernancePolicy

DOCS = Path(__file__).resolve().parents[1] / 'docs'
ROOT = DOCS.parent
REQUIRED = ('AUTO_PROMOTION.md', 'MODEL_GOVERNANCE.md', 'GUARDED_ACTIVATION.md',
            'AUTO_ROLLBACK.md', 'MODEL_SAFE_MODE.md', 'PROMOTION_POLICY.md')


def read(name):
    return (DOCS / name).read_text(encoding='utf-8')


def flat(name):
    """One document with its line wrapping removed."""
    return ' '.join(read(name).split())


def everything():
    return ' '.join(flat(name) for name in REQUIRED)


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

    def test_the_readme_links_to_the_auto_promotion_page(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertIn('docs/AUTO_PROMOTION.md', readme)


class TestTheForbiddenSentences(unittest.TestCase):
    """§155. The claims that would make this sound like something else.

    Checked with `denial.asserted` rather than a plain substring search, because
    `AUTO_PROMOTION.md` quotes every one of these sentences in order to reject
    it — and a test that failed on the page for saying *"it is not 'the AI
    replaces itself with a better AI'"* would be a test whose easiest fix is
    deleting the most useful paragraph in the documentation set.
    """

    def documents(self):
        for path in sorted(DOCS.glob('*.md')) + [ROOT / 'README.md']:
            yield path, ' '.join(path.read_text(encoding='utf-8').split()).lower()

    def assertNotClaimed(self, body, phrase, document):
        self.assertFalse(asserted(body, phrase),
                         f'{document} appears to claim {phrase!r} rather than deny it')

    def test_nothing_says_the_ai_replaces_itself(self):
        for path, body in self.documents():
            for forbidden in ('replaces itself', 'better ai', 'ai replaces',
                              'improves itself automatically'):
                with self.subTest(document=path.name, claim=forbidden):
                    self.assertNotClaimed(body, forbidden, path.name)

    def test_nothing_claims_the_best_model_is_chosen(self):
        for path, body in self.documents():
            for forbidden in ('best model is always', 'always selects the best',
                              'chooses the best model', 'optimal model'):
                with self.subTest(document=path.name, claim=forbidden):
                    self.assertNotClaimed(body, forbidden, path.name)

    def test_nothing_claims_review_is_no_longer_needed(self):
        """The most damaging possible sentence in this documentation set."""
        for path, body in self.documents():
            for forbidden in ('removes the need for human review',
                              'no human review', 'without human oversight',
                              'no longer need to review'):
                with self.subTest(document=path.name, claim=forbidden):
                    self.assertNotClaimed(body, forbidden, path.name)

    def test_the_helper_can_tell_a_claim_from_a_denial(self):
        """If this fails, the three tests above are passing for the wrong reason."""
        self.assertTrue(asserted('the ai replaces itself with a better ai',
                                 'replaces itself'))
        self.assertFalse(asserted(
            'it is not "the ai replaces itself with a better ai"', 'replaces itself'))

    def test_the_auto_promotion_page_says_what_this_is_not(self):
        """Denying the claim explicitly is better than merely not making it."""
        body = flat('AUTO_PROMOTION.md').lower()
        for phrase in ('it is not', 'does not remove the need for a person'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, body)

    def test_the_approved_vocabulary_is_used(self):
        body = everything().lower()
        for phrase in ('guarded activation', 'automatic rollback',
                       'model governance'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, body)


class TestTheNumbersAreTrue(unittest.TestCase):
    """A table of thresholds that has drifted is worse than no table."""

    def setUp(self):
        self.policy = GovernancePolicy()

    def test_the_documented_shadow_minimums_match_the_policy(self):
        text = read('PROMOTION_POLICY.md')
        shadow = self.policy.shadow
        self.assertIn(f'{shadow.minimum_feature_vectors:,}'.replace(',', ' '), text)
        self.assertIn(str(shadow.minimum_trusted_outcomes), text)

    def test_the_documented_stage_ceilings_match_the_policy(self):
        text = read('GUARDED_ACTIVATION.md')
        for stage in self.policy.stages:
            with self.subTest(stage=stage.name):
                self.assertIn(stage.name, text)
                self.assertIn(stage.action_ceiling, text)

    def test_no_guarded_stage_is_documented_as_reaching_temp_block(self):
        """§37. The claim, and the code, must agree that it cannot block."""
        for stage in self.policy.stages:
            with self.subTest(stage=stage.name):
                self.assertLess(ACTION_LADDER.index(stage.action_ceiling),
                                ACTION_LADDER.index('TEMP_BLOCK'))
        self.assertIn('cannot block anybody', flat('GUARDED_ACTIVATION.md'))

    def test_the_documented_rollback_thresholds_match_the_policy(self):
        text = read('AUTO_ROLLBACK.md')
        limits = self.policy.rollback
        self.assertIn(str(limits.max_consecutive_inference_failures), text)
        self.assertIn(str(limits.minimum_reviewed_outcomes_for_quality_rollback), text)

    def test_the_documented_promotion_budgets_match_the_policy(self):
        text = read('PROMOTION_POLICY.md')
        budgets = self.policy.promotion
        self.assertIn(str(budgets.max_promotions_per_day), text)
        self.assertIn(str(budgets.failures_before_freeze), text)


class TestThePromisesAreKept(unittest.TestCase):
    """Claims the code must actually honour."""

    def test_it_is_documented_as_off_by_default_and_really_is(self):
        governance = Config().model_governance
        self.assertFalse(governance.auto_promote_enabled)
        body = everything().lower()
        self.assertTrue('off when you install' in body or 'is off' in body)

    def test_global_is_documented_as_separate_and_really_is(self):
        self.assertIn('separate', flat('AUTO_PROMOTION.md').lower())
        policy = GovernancePolicy()
        allowed, _ = policy.auto_promote.allows('GLOBAL')
        self.assertFalse(allowed)

    def test_the_documentation_states_that_promotion_touches_no_firewall_rule(self):
        """§86. The claim an operator most needs to be able to rely on."""
        body = everything().lower()
        self.assertIn('never adds a firewall rule', body)

    def test_the_documentation_states_that_rollback_deletes_nothing(self):
        body = flat('AUTO_ROLLBACK.md').lower()
        for phrase in ('delete a dataset', 'stays on disk'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, body)

    def test_the_documentation_admits_nobody_has_run_this_in_production(self):
        """The limitation that must not be softened."""
        body = everything().lower()
        self.assertIn('never run', body)
        readme = ' '.join((ROOT / 'README.md').read_text(encoding='utf-8').split()).lower()
        self.assertIn('nobody has run this over production traffic', readme)

    def test_the_policy_page_says_the_numbers_are_not_measured(self):
        """§19. A threshold that looks authoritative stops being questioned."""
        body = flat('PROMOTION_POLICY.md').lower()
        for phrase in ('none of these numbers is measured', 'operator policy'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, body)

    def test_the_documentation_says_ood_and_drift_are_not_rollback_triggers(self):
        """§49, §50."""
        body = flat('AUTO_ROLLBACK.md').lower()
        self.assertIn('not** trigger a rollback', body)
        for phrase in ('seen even less', 'not a fault in the model'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, body)

    def test_safe_mode_is_documented_as_leaving_the_site_defended(self):
        """The fear this page exists to answer."""
        body = flat('MODEL_SAFE_MODE.md').lower()
        self.assertIn('undefended', body)
        self.assertIn('never depended on a model', body)

    def test_the_example_configuration_ships_with_it_off(self):
        text = (ROOT / 'config.example.toml').read_text(encoding='utf-8')
        self.assertIn('[model_governance]', text)
        self.assertIn('auto_promote_enabled = false', text)
        self.assertIn('auto_promote_global_enabled = false', text)


if __name__ == '__main__':
    unittest.main()
