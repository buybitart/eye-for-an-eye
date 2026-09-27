"""What the runtime says about itself. P15.5R §20-§24, §37, §49, §50.

### The distinction this file exists to defend

"Nobody asked for it" and "it is broken" are opposite facts, and until P15.5R the
health surface reported both as an absence. That is not a cosmetic complaint. It
is what P15.4 looked like from the outside: a classifier was configured, every
prediction failed on a column-count mismatch, and the only visible symptom was
that no model score appeared anywhere — which is exactly what a deployment
without a classifier looks like.

So the tests below are mostly of the form "configure something, break it, and
check the word that comes back is not `NOT_CONFIGURED`". Each one would have
passed before this cycle by reporting the wrong word, and each one is the
difference between an operator investigating and an operator shrugging.

### Why doctor gets its own section

§50 lists six conditions `doctor` must refuse. Five of them are configuration
mistakes an operator can make in an afternoon. The third — a calibrator fitted on
another formula — is the one that produces a deployment which is *correct in
every visible way* and cannot place a single block, and it is the only one of the
six that a person could not reasonably be expected to notice unaided.
"""
import json
from pathlib import Path
import unittest

from eye_for_an_eye.autonomy import calibrator as calibration_loader
from eye_for_an_eye.autonomy import selfcheck
from eye_for_an_eye.config import Config
from eye_for_an_eye.correlation.engine import CorrelationEngine
from eye_for_an_eye.decision.engine import (DEGRADED, DecisionEngine, HEALTHY,
                                            NOT_CONFIGURED, UNAVAILABLE)
from eye_for_an_eye.operations import _autonomy_checks

REPOSITORY = Path(__file__).resolve().parents[1]
MODELS = REPOSITORY / 'models'
CALIBRATOR = MODELS / 'mathrisk-cal-v4-isotonic.json'
#: Fitted on the P15.3 formula. A perfectly well-formed artifact that maps a
#: quantity this build no longer computes — the case `decision/calibration.py`
#: cannot detect, because nothing about the file is wrong.
STALE_CALIBRATOR = MODELS / 'mathrisk-cal-v3-isotonic.json'
#: Fitted on `model_score`. Also well-formed, also not this.
WRONG_QUANTITY = MODELS / 'classifier-cal-v1-isotonic.json'


def settings(**overrides):
    config = Config()
    config.decision.enabled = True
    config.storage.enabled = False
    config.api.enabled = False
    config.metrics.enabled = False
    config.logging.path = ''
    for dotted, value in overrides.items():
        section, _, key = dotted.partition('__')
        setattr(getattr(config, section), key, value)
    return config


def engine_for(config):
    return DecisionEngine(config, CorrelationEngine(config.correlation))


class TestConfiguredAndBrokenIsNotTheSameAsAbsent(unittest.TestCase):
    """§20, §37."""

    def test_an_unconfigured_deployment_says_so_for_every_component(self):
        health = engine_for(settings()).component_health()
        for name in ('auxiliary_ml', 'anomaly', 'ood', 'drift', 'calibrator'):
            with self.subTest(component=name):
                self.assertEqual(health[name]['status'], NOT_CONFIGURED)

    def test_a_configured_classifier_that_did_not_start_is_unavailable(self):
        config = settings(ml__enabled=True, ml__model_path=str(MODELS / 'risk-logreg-v1.onnx'),
                          ml__manifest_path=str(MODELS / 'risk-logreg-v1.json'))
        engine = engine_for(config)
        # Not started, so no worker: the operator asked for a classifier and
        # there is not one.
        self.assertEqual(engine.component_health()['auxiliary_ml']['status'], UNAVAILABLE)

    def test_a_configured_anomaly_artifact_that_will_not_load_is_unavailable(self):
        config = settings(reliability__anomaly_enabled=True,
                          reliability__anomaly_model_path=str(MODELS / 'no-such-model.onnx'),
                          reliability__anomaly_manifest_path=str(MODELS / 'no-such-manifest.json'))
        engine = engine_for(config)
        engine.anomaly.load()
        self.assertEqual(engine.component_health()['anomaly']['status'], UNAVAILABLE)

    def test_anomaly_enabled_with_no_artifact_is_not_configured_rather_than_broken(self):
        """`anomaly_enabled` ships true with empty paths, so "enabled" alone is
        the absence of a refusal rather than a request. Calling a default
        installation UNAVAILABLE would make the word worthless."""
        config = settings(reliability__anomaly_enabled=True)
        self.assertEqual(engine_for(config).component_health()['anomaly']['status'],
                         NOT_CONFIGURED)

    def test_a_configured_reference_distribution_that_will_not_load_is_unavailable(self):
        config = settings(reliability__ood_enabled=True, reliability__drift_enabled=True,
                          reliability__distribution_path=str(MODELS / 'no-such-distribution.json'))
        health = engine_for(config).component_health()
        for name in ('ood', 'drift'):
            with self.subTest(component=name):
                self.assertEqual(health[name]['status'], UNAVAILABLE)

    def test_a_loadable_reference_distribution_is_healthy(self):
        config = settings(reliability__ood_enabled=True, reliability__drift_enabled=True,
                          reliability__distribution_path=str(MODELS / 'risk-logreg-v1-distribution.json'))
        health = engine_for(config).component_health()
        for name in ('ood', 'drift'):
            with self.subTest(component=name):
                self.assertEqual(health[name]['status'], HEALTHY)

    def test_the_authentication_ledger_is_reported(self):
        self.assertEqual(engine_for(settings()).component_health()['auth_context']['status'],
                         HEALTHY)

    def test_every_status_is_one_of_the_four_words(self):
        health = engine_for(settings()).component_health()
        for name, entry in health.items():
            with self.subTest(component=name):
                self.assertIn(entry['status'],
                              (NOT_CONFIGURED, HEALTHY, DEGRADED, UNAVAILABLE))
                self.assertLessEqual(len(entry['detail']), 200)


class TestTheCalibratorLoaderSeparatesWellFormedFromThisBuilds(unittest.TestCase):
    """§9, §10, and the finding §50 is built around."""

    def test_the_shipped_v4_artifact_is_healthy(self):
        state = calibration_loader.load_for(settings(
            autonomy__calibrator_path=str(CALIBRATOR)))
        self.assertEqual(state.status, calibration_loader.HEALTHY)
        self.assertTrue(state.supports_autonomous_block)

    def test_an_artifact_from_the_previous_formula_is_refused(self):
        state = calibration_loader.load_for(settings(
            autonomy__calibrator_path=str(STALE_CALIBRATOR)))
        self.assertEqual(state.status, calibration_loader.UNAVAILABLE)
        self.assertIn('math-risk-v3', state.reason)
        self.assertFalse(state.supports_autonomous_block)

    def test_an_artifact_for_another_quantity_is_refused(self):
        state = calibration_loader.load_for(settings(
            autonomy__calibrator_path=str(WRONG_QUANTITY)))
        self.assertEqual(state.status, calibration_loader.UNAVAILABLE)
        self.assertIn('model_score', state.reason)

    def test_a_refused_artifact_produces_no_probability_at_all(self):
        """§10 in one assertion: no fallback, and specifically not the raw score."""
        for artifact in (STALE_CALIBRATOR, WRONG_QUANTITY):
            with self.subTest(artifact=artifact.name):
                state = calibration_loader.load_for(settings(
                    autonomy__calibrator_path=str(artifact)))
                self.assertIsNone(calibration_loader.calibrated_probability(
                    state, math_risk=0.99))

    def test_an_unconfigured_calibrator_produces_no_probability(self):
        state = calibration_loader.load_for(settings())
        self.assertEqual(state.status, calibration_loader.NOT_CONFIGURED)
        self.assertIsNone(calibration_loader.calibrated_probability(state, math_risk=0.99))

    def test_the_loader_never_raises_on_a_missing_file(self):
        config = settings()
        config.autonomy.calibrator_path = str(MODELS / 'no-such-calibrator.json')
        state = calibration_loader.load_for(config)
        self.assertEqual(state.status, calibration_loader.UNAVAILABLE)


class TestDoctorRefusesWhatItMust(unittest.TestCase):
    """§50, condition by condition."""

    def test_autonomy_off_is_disabled_rather_than_unhealthy(self):
        self.assertEqual(_autonomy_checks(settings())['status'], 'DISABLED')

    def test_a_correct_shadow_deployment_is_healthy(self):
        report = _autonomy_checks(settings(
            autonomy__enabled=True, autonomy__mode='shadow',
            autonomy__calibrator_path=str(CALIBRATOR)))
        self.assertEqual(report['status'], 'HEALTHY')

    def test_a_missing_calibrator_degrades_shadow_and_stops_autonomous(self):
        shadow = _autonomy_checks(settings(autonomy__enabled=True, autonomy__mode='shadow'))
        self.assertEqual(shadow['checks']['calibrator']['status'], 'DEGRADED')
        autonomous = _autonomy_checks(settings(autonomy__enabled=True,
                                               autonomy__mode='autonomous'))
        self.assertEqual(autonomous['checks']['calibrator']['status'], 'UNAVAILABLE')

    def test_a_calibrator_from_another_formula_is_unavailable(self):
        report = _autonomy_checks(settings(
            autonomy__enabled=True, autonomy__mode='shadow',
            autonomy__calibrator_path=str(STALE_CALIBRATOR)))
        self.assertEqual(report['checks']['calibrator']['status'], 'UNAVAILABLE')
        self.assertEqual(report['status'], 'UNAVAILABLE')

    def test_a_broken_scope_mapping_is_unavailable(self):
        config = settings(autonomy__enabled=True, autonomy__mode='shadow',
                          autonomy__calibrator_path=str(CALIBRATOR))
        # Past `validate`, which refuses this — the check has to hold for a
        # configuration mutated after loading, because something eventually will.
        config.autonomy.cost_profiles = {'SITE:example': 'no-such-profile'}
        report = _autonomy_checks(config)
        self.assertEqual(report['checks']['cost_policy']['status'], 'UNAVAILABLE')

    def test_autonomous_without_host_enforcement_degrades(self):
        report = _autonomy_checks(settings(
            autonomy__enabled=True, autonomy__mode='autonomous',
            autonomy__calibrator_path=str(CALIBRATOR)))
        self.assertEqual(report['checks']['enforcement']['status'], 'DEGRADED')

    def test_autonomous_host_enforcement_without_a_config_file_is_unavailable(self):
        """The privileged helper is started as `--config <path>`. A
        programmatically built configuration has no path, so there is nothing to
        hand it — and saying so is better than pointing the helper at whatever it
        would find on its own."""
        config = settings(autonomy__enabled=True, autonomy__mode='autonomous',
                          autonomy__calibrator_path=str(CALIBRATOR),
                          enforcement__host_enabled=True,
                          enforcement__management_networks=['192.0.2.0/24'])
        report = _autonomy_checks(config)
        self.assertEqual(report['checks']['enforcement']['status'], 'UNAVAILABLE')

    def test_the_feature_schema_check_is_asked_of_the_contract(self):
        report = _autonomy_checks(settings(
            autonomy__enabled=True, autonomy__mode='shadow',
            autonomy__calibrator_path=str(CALIBRATOR)))
        self.assertEqual(report['checks']['feature_schema']['status'], 'HEALTHY')
        self.assertIn('current 2', report['checks']['feature_schema']['detail'])


class TestTheSelfCheckUsesTheRealFactory(unittest.TestCase):
    """§23, §24, §41."""

    def test_it_runs_against_the_configured_calibrator(self):
        document = selfcheck.run(config=settings(
            autonomy__enabled=True, autonomy__mode='shadow',
            autonomy__calibrator_path=str(CALIBRATOR)))
        self.assertEqual(document['verdict'], selfcheck.WIRED, document['failures'])
        self.assertEqual(document['stages']['calibrator']['loader_status'], 'HEALTHY')
        self.assertTrue(document['stages']['authority']['loud_temp_block_eligible'])

    def test_it_reports_the_contracts_it_checked(self):
        stage = selfcheck.run(config=settings(
            autonomy__calibrator_path=str(CALIBRATOR)))['stages']['contracts']
        for key in ('feature_schema_supported', 'math_version', 'cost_policy',
                    'scope_resolver', 'policy_guard_version', 'authority_version',
                    'pipeline_version'):
            with self.subTest(key=key):
                self.assertIn(key, stage)
        self.assertTrue(stage['feature_schema_supported'])

    def test_it_never_reaches_an_enforcer_even_on_an_autonomous_host_config(self):
        """The check forces its throwaway authority into autonomous mode, so the
        factory would otherwise attach a real `HostEnforcer` on a deployment that
        has one — and `doctor` would block 192.0.2.1 every time it ran."""
        config = settings(autonomy__enabled=True, autonomy__mode='autonomous',
                          autonomy__calibrator_path=str(CALIBRATOR),
                          enforcement__host_enabled=True,
                          enforcement__management_networks=['192.0.2.0/24'])
        config.runtime.config_path = '/nonexistent/eye-for-an-eye.toml'
        document = selfcheck.run(config=config)
        self.assertEqual(document['verdict'], selfcheck.WIRED, document['failures'])
        self.assertFalse(document['touched_enforcement'])
        self.assertFalse(document['stages']['authority']['enforced'])
        self.assertEqual(document['stages']['authority']['enforcement_withheld'],
                         'no_host_enforcer_configured')

    def test_a_calibrator_from_another_formula_makes_the_check_fail(self):
        document = selfcheck.run(config=settings(
            autonomy__calibrator_path=str(STALE_CALIBRATOR)))
        self.assertEqual(document['verdict'], selfcheck.BROKEN)
        self.assertTrue(document['failures'])

    def test_no_calibrator_withholds_rather_than_fails(self):
        document = selfcheck.run(config=settings())
        self.assertEqual(document['verdict'], selfcheck.WIRED, document['failures'])
        self.assertEqual(document['stages']['calibrator']['status'], selfcheck.SKIPPED)
        self.assertIn('eligibility_withheld', document['stages']['authority'])

    def test_it_reports_nothing_that_could_be_read_as_a_detection_score(self):
        """§41. The fixtures are synthetic by construction and the verdict is
        WIRED or BROKEN; a number from here in a report about accuracy would be
        a measurement of two vectors nobody has ever sent."""
        document = selfcheck.run(config=settings(
            autonomy__calibrator_path=str(CALIBRATOR)))
        self.assertIn(document['verdict'], (selfcheck.WIRED, selfcheck.BROKEN))
        self.assertIn('not', document['what_this_is_not'])
        text = json.dumps(document)
        for forbidden in ('recall', 'precision', 'accuracy', 'f1'):
            with self.subTest(word=forbidden):
                self.assertNotIn(forbidden, text.lower())


class TestTheMassSuppressionAlarmSurvives(unittest.TestCase):
    """§22. The P15.5 signal, still reachable from the pipeline it now sits in."""

    def test_the_pipeline_reports_assumption_health(self):
        from eye_for_an_eye.autonomy.pipeline import from_config as pipeline_from_config
        pipeline = pipeline_from_config(settings(
            autonomy__enabled=True, autonomy__mode='shadow',
            autonomy__calibrator_path=str(CALIBRATOR)))
        health = pipeline.health()
        self.assertIn('assumptions', health)
        self.assertEqual(health['assumptions']['state'], 'OK')
        self.assertIn('autonomous_assumption_health_degraded', pipeline.metrics())

    def test_a_dominant_assumption_degrades_the_pipeline_health(self):
        from eye_for_an_eye.autonomy.pipeline import from_config as pipeline_from_config
        pipeline = pipeline_from_config(settings(
            autonomy__enabled=True, autonomy__mode='shadow',
            autonomy__calibrator_path=str(CALIBRATOR)))
        authority = pipeline.authority
        authority.counters['suppressed'] = 40
        authority.suppressed_by['feature_schema_supported'] = 40
        self.assertEqual(authority.assumption_health()['state'], 'DEGRADED')
        self.assertEqual(pipeline.metrics()['autonomous_assumption_health_degraded'], 1)


if __name__ == '__main__':
    unittest.main()
