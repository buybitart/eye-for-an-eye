"""The units contract, and the bug it exists to make unrepeatable.

P15 compared a cost-sensitive cutoff — a probability — against `MathRisk`, an
uncalibrated heuristic score. Both are floats in [0, 1]. Both look like a
probability at a call site. The comparison was meaningless, it survived three
review cycles, and it produced a defender that blocked nothing at all.

§92 asks for a test that makes it structurally impossible rather than merely
noticed again. These are those tests. They check the type system, not the
arithmetic: `require_probability` refuses a bare float as firmly as it refuses a
`RiskScore`, because the P15.1 bug was not somebody passing the wrong wrapper —
it was a float arriving from a fallback branch with nothing at all to mark it.
"""
import math
import unittest

from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision.scores import (AnomalyScore, CalibratedProbability,
                                            NOT_PROBABILITIES, RiskScore, ScoreError,
                                            contract, require_probability)


def probability(value=0.99, **changes):
    body = {'value': value, 'source': 'math_risk', 'calibrator_version': 'test-v1'}
    body.update(changes)
    return CalibratedProbability(**body)


class TestOnlyAProbabilityMayEnterExpectedLoss(unittest.TestCase):
    """§11, §12, §13, §92, §93."""

    def test_math_risk_cannot_be_used_as_a_probability(self):
        """The exact P15.1 substitution, refused by type."""
        with self.assertRaises(ScoreError) as caught:
            require_probability(RiskScore(0.99))
        self.assertIn('CalibratedProbability', str(caught.exception))
        self.assertIn('not a probability', str(caught.exception))

    def test_no_uncalibrated_score_may_be_used_as_a_probability(self):
        for kind in NOT_PROBABILITIES:
            with self.subTest(score=kind.__name__):
                self.assertFalse(kind.is_probability)
                with self.assertRaises(ScoreError):
                    require_probability(kind(0.95))

    def test_a_bare_float_is_refused_too(self):
        """The failure mode that actually happened.

        Nobody passed an `AnomalyScore` where a probability belonged. A float
        arrived from a fallback branch carrying no information about what it
        was. A check that only rejected the wrong wrapper would have caught
        nothing at all.
        """
        for value in (0.0, 0.5, 0.9756, 1.0):
            with self.subTest(value=value):
                with self.assertRaises(ScoreError):
                    require_probability(value)

    def test_a_calibrated_probability_is_accepted_and_returns_its_value(self):
        self.assertEqual(require_probability(probability(0.9756)), 0.9756)

    def test_the_refusal_says_what_the_number_actually_is(self):
        """A refusal that does not name the quantity teaches nobody anything."""
        with self.assertRaises(ScoreError) as caught:
            require_probability(AnomalyScore(0.99))
        self.assertIn('unusual', str(caught.exception))


class TestTheScoreVocabularyHoldsItsBounds(unittest.TestCase):

    def test_every_score_refuses_values_outside_the_unit_interval(self):
        for kind in (*NOT_PROBABILITIES, ):
            for value in (-0.0001, 1.0001, 2.0, -1.0):
                with self.subTest(score=kind.__name__, value=value):
                    with self.assertRaises(ScoreError):
                        kind(value)

    def test_every_score_refuses_nan_and_infinity(self):
        """§82. A NaN that reaches a comparison silently answers False."""
        for kind in NOT_PROBABILITIES:
            for value in (float('nan'), float('inf'), float('-inf')):
                with self.subTest(score=kind.__name__, value=value):
                    with self.assertRaises(ScoreError):
                        kind(value)
        for value in (float('nan'), float('inf')):
            with self.subTest(value=value):
                with self.assertRaises(ScoreError):
                    probability(value)

    def test_a_score_still_behaves_like_a_number(self):
        """The wrappers must not be painful, or they get worked around."""
        self.assertEqual(float(RiskScore(0.25)), 0.25)
        self.assertTrue(RiskScore(0.9) > RiskScore(0.2))
        self.assertTrue(probability(0.99) >= 0.9756)

    def test_the_contract_names_exactly_one_probability(self):
        entries = contract()['scores']
        probabilities = [e for e in entries if e['is_probability']]
        self.assertEqual([e['name'] for e in probabilities], ['CalibratedProbability'])
        for entry in entries:
            with self.subTest(score=entry['name']):
                self.assertEqual(entry['range'], [0.0, 1.0])
                self.assertEqual(entry['may_enter_expected_loss'], entry['is_probability'])
                self.assertTrue(entry['semantics'])


class TestAProbabilityCarriesItsProvenance(unittest.TestCase):
    """§84, §94. A probability nobody can trace is a probability nobody can check."""

    def test_it_must_say_what_was_calibrated_and_by_what(self):
        with self.assertRaises(ScoreError):
            CalibratedProbability(value=0.9, source='', calibrator_version='v1')
        with self.assertRaises(ScoreError):
            CalibratedProbability(value=0.9, source='math_risk', calibrator_version='')

    def test_a_calibrator_bound_to_one_model_refuses_another(self):
        estimate = probability(model_version='risk-logreg-v1')
        self.assertTrue(estimate.compatible_with('risk-logreg-v1'))
        self.assertFalse(estimate.compatible_with('risk-logreg-v2'))
        self.assertFalse(estimate.compatible_with(''))

    def test_an_unbound_calibrator_applies_anywhere_and_says_so(self):
        """An empty binding means nobody bound it, not that reuse is safe.

        P15.2 wrote this test believing `MathRisk` needed no binding, because a
        formula with no learned weights cannot drift underneath its calibrator.
        P15.3 changed the `MathRisk` formula and the belief did not survive:
        what a calibrator depends on is whether its input can change *meaning*,
        and every quantity can. The mechanism below is unchanged and still
        correct — an unbound artifact answers for anything — but it is a fact
        about artifacts nobody bound rather than a licence. `training/calibrate`
        binds the `MathRisk` artifact now, and
        `tests/test_p15_3_generalization.py` holds it bound.
        """
        estimate = probability(model_version='')
        self.assertTrue(estimate.compatible_with('anything-at-all'))

    def test_a_lower_bound_above_the_estimate_is_refused(self):
        with self.assertRaises(ScoreError):
            probability(0.5, lower=0.6)

    def test_the_conservative_value_is_the_bound_when_there_is_one(self):
        self.assertEqual(probability(0.99, lower=0.91).conservative, 0.91)
        self.assertEqual(probability(0.99).conservative, 0.99)
        self.assertFalse(probability(0.99).bounded)
        self.assertTrue(probability(0.99, lower=0.9).bounded)


class TestTheCalibratorArtifactIsSafeToLoad(unittest.TestCase):
    """§79. A calibrator is a thing production reads from disk."""

    def setUp(self):
        self.scores = [index / 400 for index in range(400)]
        self.labels = [1 if index > 260 else 0 for index in range(400)]

    def test_an_unknown_field_is_refused_rather_than_ignored(self):
        with self.assertRaises(cal.CalibrationError):
            cal.from_document({'method': 'sigmoid', 'version': 'v', 'source': 's',
                               'a': 1.0, 'b': 0.0, 'unexpected': True})

    def test_a_tampered_artifact_is_refused(self):
        artifact = cal.fit_sigmoid(self.scores, self.labels, version='v', source='math_risk')
        body = dict(artifact.document(), sha256=artifact.digest)
        body['b'] = body['b'] + 1.0
        with self.assertRaises(cal.CalibrationError):
            cal.from_document(body)

    def test_non_monotone_knots_are_refused(self):
        with self.assertRaises(cal.CalibrationError):
            cal.Calibrator(method=cal.ISOTONIC, version='v', source='s',
                           knots=((0.1, 0.9), (0.2, 0.3)))

    def test_knots_out_of_range_are_refused(self):
        with self.assertRaises(cal.CalibrationError):
            cal.Calibrator(method=cal.ISOTONIC, version='v', source='s',
                           knots=((0.1, 0.5), (0.2, 1.5)))

    def test_an_unknown_method_is_refused(self):
        with self.assertRaises(cal.CalibrationError):
            cal.Calibrator(method='neural', version='v', source='s')

    def test_a_calibrator_round_trips_through_json(self):
        for fit in (cal.fit_sigmoid, cal.fit_isotonic):
            with self.subTest(method=fit.__name__):
                artifact = fit(self.scores, self.labels, version='v', source='math_risk')
                restored = cal.from_document(dict(artifact.document(),
                                                  sha256=artifact.digest))
                self.assertEqual(restored, artifact)


class TestCalibrationIsMonotone(unittest.TestCase):
    """§100, §26. More evidence of maliciousness may never mean less probability."""

    def setUp(self):
        self.scores = [index / 500 for index in range(500)]
        self.labels = [1 if (index * 7919) % 11 > 7 else 0 for index in range(500)]

    def test_both_methods_are_non_decreasing_across_the_whole_range(self):
        grid = [index / 1000 for index in range(1001)]
        for fit in (cal.fit_sigmoid, cal.fit_isotonic):
            artifact = fit(self.scores, self.labels, version='v', source='math_risk')
            mapped = [artifact.probability(value) for value in grid]
            with self.subTest(method=artifact.method):
                for lower, higher in zip(mapped, mapped[1:], strict=False):
                    self.assertGreaterEqual(higher, lower - 1e-12)

    def test_the_conservative_bound_is_monotone_too(self):
        grid = [index / 1000 for index in range(1001)]
        artifact = cal.fit_isotonic(self.scores, self.labels, version='v', source='math_risk')
        bounds = [artifact.lower(value) for value in grid]
        for lower, higher in zip(bounds, bounds[1:], strict=False):
            self.assertGreaterEqual(higher, lower - 1e-12)

    def test_the_bound_never_exceeds_the_estimate_it_bounds(self):
        artifact = cal.fit_isotonic(self.scores, self.labels, version='v', source='math_risk')
        for value in (index / 100 for index in range(101)):
            estimate = artifact.calibrate(value)
            with self.subTest(score=value):
                self.assertLessEqual(estimate.lower, estimate.value + 1e-12)


class TestTheWilsonBoundUsesTheRightSampleSize(unittest.TestCase):
    """The P15 mistake, stated as arithmetic.

    A Wilson interval bounds a proportion estimated from `n` observations. The
    proportion is P(malicious | score); its sample size is the number of
    *calibration examples* near that score. P15 used the number of packets in
    the observation window — typically tens against thousands — so the interval
    was two orders of magnitude too wide and the estimate collapsed to zero.
    """

    def test_more_examples_give_a_tighter_bound(self):
        wide = cal.wilson_lower(30, 30)
        tight = cal.wilson_lower(3000, 3000)
        self.assertLess(wide, tight)
        self.assertLess(tight, 1.0)

    def test_no_examples_supports_no_claim(self):
        self.assertEqual(cal.wilson_lower(0, 0), 0.0)

    def test_the_bound_is_never_above_the_observed_proportion(self):
        for positives, total in ((1, 10), (5, 10), (9, 10), (50, 100), (999, 1000)):
            with self.subTest(positives=positives, total=total):
                self.assertLessEqual(cal.wilson_lower(positives, total), positives / total)

    def test_a_perfect_band_still_admits_doubt(self):
        """20 out of 20 does not license a claim of certainty."""
        self.assertLess(cal.wilson_lower(20, 20), 1.0)
        self.assertGreater(cal.wilson_lower(20, 20), 0.0)

    def test_a_calibrator_without_a_bound_offers_none(self):
        """§79: a point estimate is not a reason to deny somebody a service."""
        artifact = cal.fit_sigmoid([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1],
                                   version='v', source='math_risk', conservative=False)
        self.assertFalse(artifact.conservative)
        self.assertIsNone(artifact.lower(0.9))
        self.assertIsNone(artifact.calibrate(0.9).lower)


class TestNumericSafety(unittest.TestCase):
    """§82. Nothing invalid may become a probability."""

    def test_a_calibrator_refuses_a_non_finite_score(self):
        artifact = cal.fit_isotonic([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1],
                                    version='v', source='math_risk')
        for value in (float('nan'), float('inf'), float('-inf')):
            with self.subTest(value=value):
                self.assertIsNone(artifact.calibrate(value))

    def test_a_calibrator_clamps_a_score_outside_the_unit_interval(self):
        artifact = cal.fit_isotonic([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1],
                                    version='v', source='math_risk')
        for value in (-5.0, 5.0):
            with self.subTest(value=value):
                estimate = artifact.calibrate(value)
                self.assertIsNotNone(estimate)
                self.assertTrue(0.0 <= estimate.value <= 1.0)

    def test_an_extreme_sigmoid_fit_cannot_overflow(self):
        artifact = cal.Calibrator(method=cal.SIGMOID, version='v', source='math_risk',
                                  a=-1e6, b=1e6)
        for value in (0.0, 0.5, 1.0):
            with self.subTest(value=value):
                result = artifact.probability(value)
                self.assertTrue(math.isfinite(result))
                self.assertTrue(0.0 <= result <= 1.0)


if __name__ == '__main__':
    unittest.main()
