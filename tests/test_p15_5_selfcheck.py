"""A decision still reaches the end of the pipeline. P15.5 §40, §41.

The P15.4 defect was present from the moment schema 2 landed. It was detectable
in under a second by pushing one vector through the chain and noticing that
nothing could ever block. Nothing asked, so it was found by a benchmark that took
days to build and returned zero.

`eye_for_an_eye/autonomy/selfcheck.py` asks. This file states what asking must
mean, and most of these tests exist to stop the check degrading into a
formality — a self-check that passes unconditionally is worse than none, because
it converts an unknown into a false assurance.

§41 draws the line this file keeps on the right side of: the check tests wiring.
Two synthetic vectors say whether the pipeline is connected and nothing at all
about whether its answers are right, and `run()` returns `WIRED` / `BROKEN`
rather than any number that could be quoted as a detection result.
"""
from pathlib import Path
import unittest

from eye_for_an_eye.autonomy import selfcheck
from eye_for_an_eye.autonomy.authority import AutonomousDecisionAuthority
from eye_for_an_eye.config import Config

ARTIFACT = Path(__file__).resolve().parents[1] / 'models' / 'mathrisk-cal-v4-isotonic.json'


class TestTheCheckActuallyExercisesTheChain(unittest.TestCase):

    def setUp(self):
        self.document = selfcheck.run(ARTIFACT)

    def test_it_passes_on_this_build(self):
        self.assertEqual(self.document['verdict'], selfcheck.WIRED,
                         self.document['failures'])

    def test_every_stage_answered(self):
        for stage, body in sorted(self.document['stages'].items()):
            with self.subTest(stage=stage):
                self.assertEqual(body['status'], selfcheck.WIRED)

    def test_the_formula_and_the_calibrator_agree_about_the_formula(self):
        """The mismatch that produces a probability nobody can account for."""
        self.assertEqual(self.document['stages']['calibrator']['bound_to'],
                         self.document['stages']['math_risk']['version'])

    def test_the_quiet_fixture_is_allowed_and_the_loud_one_is_eligible(self):
        """Both halves. A check that only asserted the block would pass a build
        that blocked everything, which is the opposite failure and just as bad."""
        authority = self.document['stages']['authority']
        self.assertEqual(authority['quiet_action'], 'ALLOW')
        self.assertTrue(authority['loud_temp_block_eligible'])

    def test_nothing_was_enforced(self):
        authority = self.document['stages']['authority']
        self.assertFalse(authority['enforced'])
        self.assertFalse(self.document['touched_enforcement'])
        self.assertFalse(AutonomousDecisionAuthority.has_enforcement_privilege)


class TestTheCheckCanFail(unittest.TestCase):
    """A guard nobody has seen fire is a guard nobody can trust."""

    def test_a_calibrator_bound_to_another_formula_is_reported_broken(self):
        """The v3 artifact is still on disk. It maps a formula this build does
        not run, no score it is given produces a probability, and the check has
        to notice — that is exactly the class of mismatch it exists for.

        P15.5R moved *where* it is noticed. The check used to call `calibrate`
        itself and see `None` come back; it now asks
        `autonomy/calibrator.load_for`, which refuses the artifact one step
        earlier and says which of the three build-compatibility questions it
        failed. The assertion below names both formula versions rather than a
        phrase, so it tests the finding rather than the sentence.
        """
        stale = ARTIFACT.parent / 'mathrisk-cal-v3-isotonic.json'
        if not stale.is_file():
            self.skipTest('the v3 calibrator is not present in this checkout')
        document = selfcheck.run(stale)
        self.assertEqual(document['verdict'], selfcheck.BROKEN)
        reported = ' '.join(document['failures'])
        self.assertIn('math-risk-v3', reported, document['failures'])
        self.assertIn('math-risk-v4', reported, document['failures'])

    def test_an_unreadable_artifact_is_reported_broken_rather_than_ignored(self):
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
            handle.write('{"schema_version": 1, "method": "isotonic"}')
            path = handle.name
        document = selfcheck.run(path)
        self.assertEqual(document['stages']['calibrator']['status'], selfcheck.BROKEN)
        self.assertEqual(document['verdict'], selfcheck.BROKEN)

    def test_the_fixtures_are_genuinely_separated_by_the_formula(self):
        """If both fixtures scored the same the check would be vacuous, and
        every assertion above would pass for the wrong reason."""
        stages = selfcheck.run(ARTIFACT)['stages']
        self.assertGreater(stages['math_risk']['loud'], stages['math_risk']['quiet'])
        self.assertGreater(stages['calibrator']['loud'], stages['calibrator']['quiet'])


class TestWithoutACalibratorItWithholdsRatherThanFails(unittest.TestCase):
    """No calibrator means no autonomous block at any score, by design.

    That is the documented degraded posture — `CALIBRATION_UNAVAILABLE` — and
    reporting it as a wiring fault would train an operator to ignore the check.
    There is currently no configuration setting for the calibrator path at all,
    so this is the state a default installation is in.
    """

    def test_the_chain_still_runs(self):
        document = selfcheck.run(None)
        self.assertEqual(document['stages']['math_risk']['status'], selfcheck.WIRED)
        self.assertEqual(document['stages']['authority']['status'], selfcheck.WIRED)
        self.assertEqual(document['stages']['calibrator']['status'], selfcheck.SKIPPED)

    def test_eligibility_is_withheld_not_asserted(self):
        authority = selfcheck.run(None)['stages']['authority']
        self.assertFalse(authority['loud_temp_block_eligible'])
        self.assertIn('eligibility_withheld', authority)

    def test_the_verdict_is_not_broken(self):
        self.assertEqual(selfcheck.run(None)['verdict'], selfcheck.WIRED)

    def test_the_default_configuration_has_nowhere_to_put_a_calibrator(self):
        """Recorded as a test because it is a finding, not a preference: the
        artifact a block's conservative bound depends on has no configuration
        setting, so a running sensor could not load one if it wanted to."""
        reliability = Config().reliability
        self.assertFalse([name for name in dir(reliability)
                          if 'calibrat' in name.lower()])


class TestTheFixturesAreSyntheticAndVersioned(unittest.TestCase):
    """§40: no hardcoded attack signature; a versioned internal fixture."""

    def test_the_fixtures_are_described_and_versioned(self):
        fixtures = selfcheck.fixtures()
        self.assertEqual(fixtures['fixture_version'], selfcheck.SELFCHECK_FIXTURE_VERSION)
        self.assertEqual(fixtures['features'], fixtures['features'])
        for name in ('quiet', 'loud'):
            with self.subTest(fixture=name):
                self.assertIn('fraction_of_ceiling', fixtures[name])
                self.assertTrue(fixtures[name]['means'])

    def test_the_fixtures_are_flat_and_therefore_not_a_behaviour(self):
        """Every column at the same fraction of its own ceiling. No source
        produces that, which is what stops the fixture becoming something the
        system is tuned to recognise."""
        from eye_for_an_eye.decision.features import SPEC
        vector = selfcheck._vector(selfcheck.LOUD_FRACTION,  # noqa: SLF001
                                   observations=120, seconds=420.0)
        fractions = {round(value / ceiling, 6)
                     for value, (_, ceiling, *_) in zip(vector.values, SPEC, strict=True)}
        self.assertEqual(fractions, {selfcheck.LOUD_FRACTION})

    def test_the_fixtures_follow_the_schema_rather_than_a_frozen_column_list(self):
        from eye_for_an_eye.decision.features import NAMES
        vector = selfcheck._vector(0.5, observations=24, seconds=60.0)  # noqa: SLF001
        self.assertEqual(len(vector.values), len(NAMES))


class TestItIsReachableFromTheOperatorSurfaces(unittest.TestCase):
    """A check nothing calls is the defect it was written to prevent."""

    def test_doctor_runs_it(self):
        from eye_for_an_eye.operations import doctor
        report = doctor(Config())
        self.assertIn('decision_pipeline', report)
        self.assertIn(report['decision_pipeline']['status'],
                      ('HEALTHY', 'UNAVAILABLE'))

    def test_the_readiness_gate_runs_it_and_treats_it_as_critical(self):
        from eye_for_an_eye.autonomy.runtime import evaluate_readiness
        checks = {check.name: check for check in evaluate_readiness(Config()).checks}
        self.assertIn('decision_pipeline', checks)
        self.assertTrue(checks['decision_pipeline'].critical)

    def test_doctor_reports_the_feature_schema_this_build_actually_has(self):
        """It said 1 from P15.4 onward while the schema in force was 2 — an
        operator-facing field stating something false about its own build."""
        from eye_for_an_eye.compatibility import FEATURE_SCHEMA
        from eye_for_an_eye.operations import doctor
        self.assertEqual(doctor(Config())['ml']['feature_schema_version'],
                         FEATURE_SCHEMA.current)

    def test_the_result_is_labelled_as_wiring_only(self):
        """§41, kept where somebody copying a number out will see it."""
        self.assertIn('wiring_only_not_a_detection_measurement',
                      selfcheck.check(Config())['limitations'])


if __name__ == '__main__':
    unittest.main()
