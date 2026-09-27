"""The ablation's machinery, and the findings it must keep producing. §65, §66, §67.

Two different jobs here, kept apart on purpose.

The first is the arithmetic. An ablation whose AUC is wrong reports a confident
number about nothing, and since every conclusion this cycle draws about which
part of P15.4 earns its place comes out of that function, it is checked against
cases whose answer is known by hand rather than against the corpus.

The second is the findings. Three of them are load-bearing enough that a future
change quietly reversing one would matter more than most test failures, and each
is stated here as a property of the *code* rather than as a number copied from a
report — because a number copied from a report is a number nobody re-derives.

The corpus itself is not required. Every test below either constructs its own
inputs or asserts something about a scorer, so this file passes in a clean clone
with no datasets on disk.
"""
import unittest

from eye_for_an_eye.decision import composition as composition_module
from eye_for_an_eye.decision import families as families_module
from eye_for_an_eye.decision.features import NAMES
from training import p15_4_ablation as ablation


def values(**overrides):
    """A feature dict with everything unobserved except what is named."""
    base = dict.fromkeys(NAMES)
    base.update(overrides)
    return base


class TestTheMeasurementIsCorrect(unittest.TestCase):
    """Hand-checkable cases, because everything else here depends on this."""

    def test_perfect_separation_is_one(self):
        self.assertEqual(ablation.auc([3.0, 4.0, 5.0], [0.0, 1.0, 2.0]), 1.0)

    def test_perfect_inversion_is_zero(self):
        self.assertEqual(ablation.auc([0.0, 1.0], [2.0, 3.0]), 0.0)

    def test_a_scorer_that_says_one_thing_about_everything_is_a_coin(self):
        """The case that matters: a family scoring every source identically must
        report 0.5, not something flattering from a tie-breaking accident."""
        self.assertEqual(ablation.auc([1.0] * 5, [1.0] * 5), 0.5)

    def test_one_tie_against_a_clean_split(self):
        # positives {1, 2}, negatives {0, 1}: one pair tied, one pair won.
        self.assertEqual(ablation.auc([1.0, 2.0], [0.0, 1.0]), 0.875)

    def test_an_empty_class_has_no_answer_rather_than_a_default(self):
        self.assertIsNone(ablation.auc([], [1.0]))
        self.assertIsNone(ablation.auc([1.0], []))


class TestTheShippedVariantIsTheShippedCode(unittest.TestCase):
    """An ablation whose control is a reimplementation measures a fiction."""

    def test_the_shipped_variant_calls_the_real_scorer(self):
        sample = values(auth_failures_60s=9, auth_principals_900s=5,
                        auth_failure_ratio=0.9, auth_failure_span_900s=400)
        self.assertEqual(ablation.auth_score(sample, 'shipped'),
                         families_module.auth_behavior(sample))

    def test_every_declared_variant_is_runnable_and_described(self):
        sample = values(auth_failures_60s=9, auth_principals_900s=5,
                        auth_failure_ratio=0.9, auth_failure_span_900s=400,
                        credentials_60s=20)
        for variant in ablation.AUTH_VARIANTS:
            with self.subTest(variant=variant):
                self.assertIn(variant, ablation.AUTH_VARIANT_NOTES)
                score = ablation.auth_score(sample, variant)
                self.assertIsNotNone(score)
                self.assertTrue(0.0 <= score <= 1.0)


class TestTheFindingsThatMustNotReverse(unittest.TestCase):
    """Three properties the ablation measured, stated as mechanism.

    Each was a number in `reports/P15_4_COMPOSITION_ABLATION.json` first. A
    number in a report protects nothing, so each is re-expressed here as
    something about the code that a change would have to break on purpose.
    """

    STUCK_CLIENT = values(auth_failures_60s=2, auth_principals_900s=1,
                          auth_failure_ratio=1.0, auth_failure_span_900s=316.0)
    ACCOUNT_WALK = values(auth_failures_60s=2, auth_principals_900s=12,
                          auth_failure_ratio=1.0, auth_failure_span_900s=430.0)

    def test_a_long_failure_span_from_one_account_says_nothing(self):
        """§65's finding. Ungated, this exact input scored a benign source 0.784
        — higher than any other benign source in the development corpus, and
        almost exactly what credential *presence* scored before P15.4 replaced
        it. The over-correction reproduced the defect it was correcting."""
        self.assertEqual(families_module.auth_behavior(self.STUCK_CLIENT) or 0.0, 0.0)
        self.assertGreater(ablation.auth_score(self.STUCK_CLIENT,
                                               'failures_and_span_ungated'), 0.9)

    def test_the_same_span_across_many_accounts_says_a_great_deal(self):
        """The gate has to cost nothing on the behaviour the term was written
        for, or it is not a gate, it is a deletion."""
        self.assertGreater(families_module.auth_behavior(self.ACCOUNT_WALK), 0.9)

    def test_credential_presence_is_not_authentication_evidence(self):
        """§15. A source carrying credentials constantly and refused never."""
        busy_and_welcome = values(auth_failures_60s=0, auth_successes_60s=160,
                                  auth_failure_ratio=0.0, auth_principals_900s=0,
                                  auth_failure_span_900s=0.0, credentials_60s=160)
        self.assertEqual(families_module.auth_behavior(busy_and_welcome) or 0.0, 0.0)
        self.assertGreater(ablation.auth_score(busy_and_welcome, 'presence'), 0.9)

    def test_a_corroborating_family_cannot_carry_a_composition_alone(self):
        """§66's finding rests on this: what separated v3 from v4 was the family
        layer — a floor, reliability caps, and the carrying/corroborating split —
        rather than the choice of composition rule, which barely moved the
        numbers. So the split is the thing worth guarding."""
        engine = composition_module.EvidenceCompositionEngine()
        for family in families_module.CORROBORATING_ONLY:
            with self.subTest(family=family):
                score, _ = engine.evaluate({family: 1.0})
                self.assertEqual(score, 0.0)

    def test_every_composition_method_named_in_the_report_still_runs(self):
        """The comparison is only a measurement while the alternatives remain
        runnable. A method quietly deleted turns §25's benchmark back into a
        preference."""
        effective = {families_module.PORT_BREADTH: 0.5,
                     families_module.AUTH_BEHAVIOR: 0.4,
                     families_module.NETWORK_RATE: 0.3}
        for variant, _ in ablation.COMPOSITION_VARIANTS:
            if variant == 'weighted_sum_v3':
                continue
            with self.subTest(variant=variant):
                method = ('noisy_or' if variant == 'noisy_or_without_interactions'
                          else variant)
                self.assertIn(method, composition_module.METHODS)
                engine = composition_module.EvidenceCompositionEngine(
                    method, interactions=variant != 'noisy_or_without_interactions')
                score, _ = engine.evaluate(effective)
                self.assertTrue(0.0 <= score <= 1.0)

    def test_the_previous_formula_is_still_runnable_for_comparison(self):
        """§66 compares against `math-risk-v3`. A comparison whose baseline has
        been deleted is an assertion."""
        from eye_for_an_eye.decision.math_risk import MathRiskEngine, VERSION_V3
        self.assertEqual(VERSION_V3, 'math-risk-v3')
        self.assertTrue(hasattr(MathRiskEngine(), 'evaluate_v3'))


if __name__ == '__main__':
    unittest.main()
