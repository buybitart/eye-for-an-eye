"""EvidenceMaturity: enough observation to act, never how malicious. §31 to §40.

The scenarios in §40 are written out one per test, because each of them is a
thing that went wrong, or could have, and a name in a test report is the
cheapest place to record which.
"""
import unittest

from eye_for_an_eye.autonomy.authority import DecisionGates
from eye_for_an_eye.autonomy.maturity import (IMMATURE, LONG_DURATION, MODES, STANDARD,
                                              STRONG_MULTI_SIGNAL, MaturityPolicy, evaluate)


def mature(**overrides):
    body = dict(observations=40, observation_seconds=120.0, data_quality=0.85,
                families=('PORT_BREADTH',))
    body.update(overrides)
    return evaluate(**body)


class TestTheStandardRoadIsUnchanged(unittest.TestCase):
    """§31, §35. The number that refused `scan-slow` is still exactly 20."""

    def test_the_standard_road_reproduces_the_decision_gates(self):
        policy, gates = MaturityPolicy(), DecisionGates()
        self.assertEqual(policy.minimum_observations, gates.minimum_observations)
        self.assertEqual(policy.minimum_observation_seconds,
                         gates.minimum_observation_seconds)
        self.assertEqual(policy.minimum_data_quality, gates.minimum_data_quality)

    def test_what_matured_before_still_matures_the_same_way(self):
        self.assertEqual(mature().mode, STANDARD)

    def test_nineteen_observations_still_does_not_reach_the_standard_road(self):
        """The specific number P15.3 revealed. It was not edited to admit it."""
        result = mature(observations=19, observation_seconds=30.0)
        self.assertFalse(result.roads[STANDARD]['open'])


class TestTheScenariosTheBriefNames(unittest.TestCase):
    """§40, one test per listed case."""

    def test_a_short_benign_burst_is_immature(self):
        result = evaluate(observations=25, observation_seconds=6.0, data_quality=0.9,
                          families=('NETWORK_RATE',))
        self.assertFalse(result.mature)
        self.assertEqual(result.mode, IMMATURE)

    def test_a_long_running_normal_api_client_is_mature(self):
        """Mature and benign are not in tension: this module has no opinion on
        guilt, and a well-observed harmless client is well observed."""
        result = evaluate(observations=300, observation_seconds=800.0, data_quality=0.95,
                          families=('NETWORK_RATE', 'TIMING'))
        self.assertTrue(result.mature)

    def test_a_slow_scan_with_persistence_matures_by_duration(self):
        """The P15.3 miss: 0.9904 conservative probability, fifteen observations.

        It does not mature by having the floor lowered — 15 is still below 20 —
        but by having been watched for eleven minutes while several independent
        families agreed.
        """
        result = evaluate(observations=15, observation_seconds=700.0, data_quality=0.8,
                          families=('PORT_BREADTH', 'PERSISTENCE', 'TIMING'))
        self.assertTrue(result.mature)
        self.assertEqual(result.mode, LONG_DURATION)
        self.assertFalse(result.roads[STANDARD]['open'], 'the standard floor still refuses it')

    def test_one_extreme_event_is_not_automatically_mature(self):
        """§34. However anomalous a single packet is, it is a single packet."""
        result = evaluate(observations=2, observation_seconds=1.0, data_quality=0.95,
                          families=('PROTOCOL_BEHAVIOR', 'ANOMALY', 'ML_CLASSIFIER'))
        self.assertFalse(result.mature)

    def test_several_independent_strong_signals_may_mature_early(self):
        result = evaluate(observations=14, observation_seconds=45.0, data_quality=0.85,
                          families=('PORT_BREADTH', 'AUTH_BEHAVIOR', 'PROTOCOL_BEHAVIOR',
                                    'PERSISTENCE'))
        self.assertTrue(result.mature)
        self.assertEqual(result.mode, STRONG_MULTI_SIGNAL)


class TestWhatMayNotCreateMaturity(unittest.TestCase):

    def test_a_model_cannot_shorten_the_observation_period(self):
        """§38. Confidence about one window is not evidence that a window exists."""
        result = evaluate(observations=14, observation_seconds=45.0, data_quality=0.95,
                          families=('ML_CLASSIFIER', 'ANOMALY', 'NETWORK_RATE', 'TIMING'))
        self.assertFalse(result.mature)

    def test_model_families_are_excluded_from_every_count(self):
        behavioural = evaluate(observations=14, observation_seconds=45.0, data_quality=0.85,
                               families=('PORT_BREADTH', 'AUTH_BEHAVIOR',
                                         'PROTOCOL_BEHAVIOR', 'PERSISTENCE'))
        padded = evaluate(observations=14, observation_seconds=45.0, data_quality=0.85,
                          families=('PORT_BREADTH', 'AUTH_BEHAVIOR', 'PROTOCOL_BEHAVIOR',
                                    'ML_CLASSIFIER', 'ANOMALY'))
        self.assertTrue(behavioural.mature)
        self.assertFalse(padded.mature, 'two model opinions padded the family count')

    def test_probability_is_not_an_input_at_all(self):
        """§33. Not merely unused — there is nowhere to put it."""
        import inspect
        parameters = set(inspect.signature(evaluate).parameters)
        for forbidden in ('probability', 'calibrated', 'risk', 'score', 'malicious'):
            self.assertNotIn(forbidden, parameters)

    def test_poor_data_quality_cannot_be_compensated_for(self):
        for families in (('PORT_BREADTH', 'AUTH_BEHAVIOR', 'PROTOCOL_BEHAVIOR', 'PERSISTENCE'),
                         ('PORT_BREADTH', 'PERSISTENCE', 'TIMING')):
            with self.subTest(families=families):
                self.assertFalse(evaluate(observations=40, observation_seconds=800.0,
                                          data_quality=0.2, families=families).mature)


class TestThePolicyRefusesToWeakenItself(unittest.TestCase):
    """The constructor rejects a configuration that makes a fast road cheap."""

    def test_the_fast_road_may_not_fall_below_half_the_standard_count(self):
        with self.assertRaises(ValueError):
            MaturityPolicy(strong_observations=4)

    def test_the_long_road_must_ask_for_more_time_than_the_standard_one(self):
        with self.assertRaises(ValueError):
            MaturityPolicy(long_duration_seconds=5.0)

    def test_no_road_may_accept_worse_data_than_the_standard_one(self):
        with self.assertRaises(ValueError):
            MaturityPolicy(strong_data_quality=0.1)
        with self.assertRaises(ValueError):
            MaturityPolicy(long_duration_data_quality=0.1)

    def test_every_road_is_reported_whether_or_not_it_opened(self):
        """§39 and plain usefulness: "why not yet" needs the whole answer."""
        result = mature(observations=5, observation_seconds=2.0)
        self.assertEqual(set(result.roads), set(MODES))
        for road in MODES:
            self.assertIn('open', result.roads[road])


if __name__ == '__main__':
    unittest.main()
