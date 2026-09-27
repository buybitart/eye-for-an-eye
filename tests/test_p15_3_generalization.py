"""What P15.3 established, pinned so a later cycle cannot quietly undo it.

Three kinds of thing are held here.

**The v3 arithmetic rules.** v3 is not a set of tuned numbers; it is two rules
applied uniformly — an evidence family carries the same weight in both of its
windows, and a normalisation ceiling is a statement about how much of something
is a lot rather than a storage bound. Tests assert the *rules*, not the numbers
that currently satisfy them, so a future re-weighting is free to move a value and
is not free to reintroduce a patience discount.

**The calibrator binding.** A calibrator fitted on one formula's scores is
meaningless applied to another's, and until P15.3 nothing refused the
substitution. The binding is now load-bearing and is asserted here.

**The order of the cycle.** The observability classification and the acceptance
policy were committed before the benchmark was generated. That ordering is the
only reason either document means anything, and a test is a cheaper guard on it
than a promise.

What is deliberately **not** tested here is any measured outcome — no recall, no
per-family detection. Those live in `reports/P15_3_LOCKED_TEST.json`, were
measured once, and a test that asserted them would turn a result into a target.
"""
import hashlib
import json
from pathlib import Path
import unittest

from dataset import split as split_module
from eye_for_an_eye.autonomy.authority import DecisionGates
from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.decision import math_risk
from eye_for_an_eye.decision.features import SPEC
from training import observability, test_policy

REPORTS = Path(__file__).resolve().parent.parent / 'reports'
CEILINGS = {name: ceiling for name, ceiling, *_ in SPEC}


class TestTheWindowParityRule(unittest.TestCase):
    """The same evidence, measured over a longer window, is worth the same."""

    PAIRS = (('ports_60s', 'ports_900s'), ('connections_60s', 'connections_900s'))

    def test_every_two_window_family_is_weighted_equally(self):
        for short, long in self.PAIRS:
            with self.subTest(family=short):
                self.assertEqual(math_risk.WEIGHTS[short], math_risk.WEIGHTS[long],
                                 f'{long} is weighted differently from {short}, '
                                 'which charges a source less for being patient')

    def test_the_long_window_is_anchored_to_the_same_count(self):
        """A re-anchor exists wherever the feature ceilings differ."""
        ratio = CEILINGS['ports_900s'] / CEILINGS['ports_60s']
        self.assertGreater(ratio, 1, 'this test assumes the long window has the '
                                     'wider feature ceiling')
        # A saturating short-window value must saturate in the long window too,
        # for the same raw count.
        self.assertEqual(math_risk.long_window_ports(1 / ratio), 1.0)
        self.assertAlmostEqual(math_risk.long_window_ports(0.5 / ratio), 0.5)

    def test_connection_rate_needs_no_re_anchor(self):
        self.assertEqual(CEILINGS['connections_60s'], CEILINGS['connections_900s'])

    def test_v3_did_not_make_anything_louder(self):
        """Each family's total weight is unchanged from v2. Only the split moved."""
        for short, long in self.PAIRS:
            with self.subTest(family=short):
                before = math_risk.WEIGHTS_V2.get(short, 0) + math_risk.WEIGHTS_V2.get(long, 0)
                after = math_risk.WEIGHTS[short] + math_risk.WEIGHTS[long]
                self.assertEqual(before, after)

    def test_the_total_weight_is_unchanged(self):
        self.assertEqual(sum(math_risk.WEIGHTS_V2.values()),
                         sum(math_risk.WEIGHTS.values()))


class TestNormalisationAnchors(unittest.TestCase):
    """A ceiling says how much is a lot. It is not a storage bound."""

    def test_destination_breadth_can_reach_the_top_of_its_range(self):
        """v2's ceiling was above the number of addresses a host has.

        Touching every address the sensor protects scored 0.5, so the feature
        could not express full breadth however wide the sweep.
        """
        from dataset.generators.base import SENSOR_ADDRESSES
        raw = len(SENSOR_ADDRESSES)
        normalised = raw / CEILINGS['destinations_60s']
        self.assertEqual(math_risk.destination_breadth(normalised), 1.0,
                         'a source touching every address of the protected host '
                         'must score full destination breadth')

    def test_the_ceiling_is_expressed_as_a_multiple_of_the_floor(self):
        self.assertEqual(math_risk.DESTINATION_CEILING, 2 * math_risk.DESTINATION_FLOOR)

    def test_below_the_floor_is_not_breadth(self):
        below = (math_risk.DESTINATION_FLOOR - 1) / CEILINGS['destinations_60s']
        self.assertEqual(math_risk.destination_breadth(below), 0.0)

    def test_a_decoy_brush_past_is_still_not_an_enumeration(self):
        below = (math_risk.DECEPTION_FLOOR - 1) / CEILINGS['deception_60s']
        self.assertEqual(math_risk.deception_interaction(below), 0.0)


class TestSafetyWasNotTraded(unittest.TestCase):
    """P15.3 changed evidence. It did not touch a gate, a cutoff or a cost."""

    def test_the_cost_policy_is_unchanged(self):
        policy = CostPolicy()
        self.assertEqual(policy.profiles['public_website'].false_block, 40.0)
        self.assertEqual(policy.profiles['api'].false_block, 80.0)
        self.assertEqual(policy.profiles['admin'].false_block, 8.0)
        self.assertEqual(policy.profiles['honeypot'].false_block, 2.0)

    def test_a_payment_webhook_still_never_network_blocks(self):
        self.assertFalse(CostPolicy().profiles['payment_webhook'].network_block_permitted)

    def test_the_decision_gates_are_unchanged(self):
        gates = DecisionGates()
        self.assertEqual(gates.minimum_observations, 20)
        self.assertEqual(gates.minimum_signal_diversity, 3)
        self.assertEqual(gates.minimum_behavioural_diversity, 2)
        self.assertEqual(gates.minimum_data_quality, 0.55)
        self.assertEqual(gates.maximum_uncertainty, 0.60)

    def test_no_automatic_block_outlives_twelve_hours(self):
        from eye_for_an_eye.security.enforcement import MAX_TTL_SECONDS
        self.assertEqual(MAX_TTL_SECONDS, 43_200)
        self.assertLessEqual(max(DecisionGates().block_ttl_ladder), MAX_TTL_SECONDS)


class TestTheCalibratorIsBoundToTheFormula(unittest.TestCase):
    """A mapping fitted on one formula's scores may not answer for another's."""

    def test_the_shipped_math_risk_calibrator_names_the_formula_it_maps(self):
        path = Path(__file__).resolve().parent.parent / 'models'
        artifacts = sorted(path.glob('mathrisk-cal-*.json'))
        self.assertTrue(artifacts, 'no MathRisk calibrator is shipped')
        current = [json.loads(a.read_text(encoding='utf-8')) for a in artifacts]
        self.assertTrue(
            any(body.get('model_version') == math_risk.VERSION for body in current),
            'no shipped MathRisk calibrator is bound to the formula in force')

    def test_the_replay_checks_the_version_of_the_quantity_it_calibrates(self):
        """Not whichever version happened to be to hand — that was the bug."""
        from training.decision_replay import MATH_RISK_VERSION, _calibrated

        class Artifact:
            source = 'math_risk'

            def calibrate(self, score, *, model_version=''):
                return ('calibrated', model_version)

        _, version = _calibrated(Artifact(), math_risk=0.5, model_score=0.9,
                                 ml_model_version='risk-logreg-v1')
        self.assertEqual(version, MATH_RISK_VERSION)
        self.assertEqual(version, math_risk.VERSION)


class TestTheCycleHappenedInTheRightOrder(unittest.TestCase):
    """Classification and acceptance were committed before the benchmark existed."""

    def test_every_composite_family_was_classified(self):
        for family in split_module.HOLDOUT:
            with self.subTest(family=family):
                self.assertIn(family, observability.FAMILIES,
                              'a withheld family with no committed classification '
                              'could be explained away after the test')

    def test_no_family_is_out_of_scope(self):
        """§50. Nothing may become out of scope because it proved hard."""
        self.assertEqual(observability.by_class()[observability.OUT_OF_SCOPE], [])
        self.assertEqual(observability.by_class()[observability.INVALID_TEST_SCENARIO], [])

    def test_the_committed_policy_is_internally_intact(self):
        """The P15.3 policy still hashes to the digest it was published with.

        This compared the file against *live* constants until P15.4, which was
        right for exactly one cycle: while P15.3 was the current cycle, "the
        policy on disk disagrees with the code" meant somebody had moved a value
        after committing the standard. Once a later cycle legitimately changes
        the formula, that comparison would report a drift that is not one, and a
        permanently red integrity check is a check nobody reads.

        What stays true forever is the file's own consistency: a published
        acceptance standard must still hash to the digest it was published with,
        or it has been edited since the result was scored against it. P15.4
        commits its own live-code check in `test_p15_4_invariants.py`.
        """
        committed = json.loads(
            (REPORTS / 'P15_3_TEST_POLICY.json').read_text(encoding='utf-8'))
        stored = committed.pop('digest')
        recomputed = hashlib.sha256(
            json.dumps(committed, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(stored, recomputed,
                         'the P15.3 acceptance policy has been edited since the '
                         'locked test was scored against it')

    def test_the_policy_generator_still_produces_a_self_consistent_document(self):
        """And the generator that wrote it has not lost the ability to."""
        live = test_policy.document()
        stored = dict(live)
        digest = stored.pop('digest')
        self.assertEqual(digest, hashlib.sha256(
            json.dumps(stored, sort_keys=True, separators=(',', ':')).encode()).hexdigest())

    def test_the_policy_states_no_recall_target(self):
        """§10. A number invented after a result is not a criterion, and nor is
        one invented before it to be quietly met."""
        committed = json.loads(
            (REPORTS / 'P15_3_TEST_POLICY.json').read_text(encoding='utf-8'))
        self.assertIsNone(committed['gate_c']['recall_target'])

    def test_the_generalization_corpus_is_not_a_fitting_corpus(self):
        from training import evaluation_design as design
        self.assertNotIn(design.GENERALIZATION_TEST, design.CALIBRATION_ROLES)
        self.assertNotEqual(design.CORPORA[design.GENERALIZATION_TEST][2], '')


if __name__ == '__main__':
    unittest.main()
