"""The P15.4 safety baseline, enforced rather than promised. §1.

Four cycles have now been told not to weaken a gate in order to obtain a pass,
and four cycles have kept that promise by intending to. Intention does not
survive a refactor, and it is not something a reviewer can check.

`reports/P15_4_BASELINE.json` is generated from the constants actually loaded and
carries a digest over all of them. This module compares that record against the
code on every run, so a weakened gate fails the build in the same breath as it is
written — and the failure names the value that moved.

A number here may still change if the owner decides it should. What it may not
do is change quietly, or as a side effect of making a result look better.
"""
import json
from pathlib import Path
import unittest

from eye_for_an_eye.autonomy.authority import DecisionGates, MAX_BLOCK_TTL_SECONDS
from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.security.enforcement import MAX_TTL_SECONDS
from training import invariants

BASELINE = Path(__file__).resolve().parent.parent / 'reports' / 'P15_4_BASELINE.json'


def recorded():
    return json.loads(BASELINE.read_text(encoding='utf-8'))


class TestTheBaselineIsIntact(unittest.TestCase):

    def test_the_record_exists(self):
        self.assertTrue(BASELINE.is_file(),
                        'the P15.4 baseline record is missing, so nothing is pinned')

    def test_nothing_in_the_baseline_has_moved(self):
        """One digest over every protected value. The failure names what changed."""
        stored, live = recorded(), invariants.document()
        if stored['digest'] == live['digest']:
            return
        moved = []
        for section in sorted(set(stored) | set(live)):
            if section == 'digest':
                continue
            if stored.get(section) != live.get(section):
                moved.append(section)
        self.fail('P15.4 baseline values changed in: ' + ', '.join(moved) +
                  '. If this was deliberate and owner-approved, regenerate '
                  'reports/P15_4_BASELINE.json in its own commit and say so in '
                  'the report. If it was not, it is the thing P15.4 was told not '
                  'to do.')


class TestTheGatesThemselves(unittest.TestCase):
    """Named individually, so a diff shows which protection a change touches."""

    def test_cost_profiles_are_unchanged(self):
        policy = CostPolicy()
        self.assertEqual(policy.profiles['public_website'].false_block, 40.0)
        self.assertEqual(policy.profiles['api'].false_block, 80.0)
        self.assertEqual(policy.profiles['payment_webhook'].false_block, 500.0)
        self.assertEqual(policy.profiles['admin'].false_block, 8.0)
        self.assertEqual(policy.profiles['honeypot'].false_block, 2.0)

    def test_the_public_website_cutoff_was_not_lowered(self):
        """§62. The cutoff follows from the costs; this asserts the arithmetic."""
        self.assertAlmostEqual(CostPolicy().profiles['public_website'].threshold,
                               0.975610, places=6)

    def test_a_payment_webhook_still_never_network_blocks(self):
        self.assertFalse(CostPolicy().profiles['payment_webhook'].network_block_permitted)

    def test_the_evidence_diversity_requirement_was_not_reduced(self):
        """Called out twice in the brief, so asserted on its own."""
        gates = DecisionGates()
        self.assertGreaterEqual(gates.minimum_signal_diversity, 3)
        self.assertGreaterEqual(gates.minimum_behavioural_diversity, 2)

    def test_data_quality_and_uncertainty_were_not_relaxed(self):
        gates = DecisionGates()
        self.assertGreaterEqual(gates.minimum_data_quality, 0.55)
        self.assertLessEqual(gates.maximum_uncertainty, 0.60)

    def test_no_automatic_block_can_outlive_twelve_hours(self):
        self.assertEqual(MAX_TTL_SECONDS, 43_200)
        self.assertEqual(MAX_BLOCK_TTL_SECONDS, 43_200)
        self.assertLessEqual(max(DecisionGates().block_ttl_ladder), MAX_TTL_SECONDS)

    def test_every_block_duration_is_finite_and_escalating(self):
        ladder = DecisionGates().block_ttl_ladder
        self.assertTrue(all(0 < value <= MAX_BLOCK_TTL_SECONDS for value in ladder))
        self.assertEqual(list(ladder), sorted(ladder))


class TestTheObservationFloorIsNotSimplyLowered(unittest.TestCase):
    """§31. The number that refused `scan-slow` may not be edited to admit it.

    P15.4 is allowed to replace the universal floor with a maturity system that
    reasons about several kinds of evidence. It is not allowed to change 20 to 15
    because a known test revealed 15, and the difference between those two things
    is the whole point of the section.
    """

    def test_the_standard_observation_floor_is_unchanged(self):
        self.assertEqual(DecisionGates().minimum_observations, 20)

    def test_the_standard_observation_time_floor_is_unchanged(self):
        self.assertEqual(DecisionGates().minimum_observation_seconds, 10.0)


if __name__ == '__main__':
    unittest.main()
