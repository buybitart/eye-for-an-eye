"""P8 reliability: reference distribution, OOD, drift, model health and fusion v2.

The rule these tests defend: unknown is not malicious. Anomalous input and a
drifted population must reduce trust, never raise risk.
"""
import json
from pathlib import Path
import pytest

from eye_for_an_eye.config import Config
from eye_for_an_eye.decision import drift as drift_module
from eye_for_an_eye.decision.distribution import (DistributionError, RollingDistribution, WindowedHistogram,
                                                  load_reference, transformed_values)
from eye_for_an_eye.decision.drift import DriftEngine, model_health, psi, quantile_shift
from eye_for_an_eye.decision.features import FeatureVector, NAMES
from eye_for_an_eye.decision.math_risk import MathRiskResult
from eye_for_an_eye.decision.onnx_model import MLResult
from eye_for_an_eye.decision.ood import OODEngine, OODResult
from eye_for_an_eye.decision.policy import DecisionFusion, PolicyGuard

ROOT = Path(__file__).resolve().parents[1]
DISTRIBUTION = ROOT / 'models' / 'risk-logreg-v1-distribution.json'

pytestmark = pytest.mark.skipif(not DISTRIBUTION.is_file(),
                                reason='reference distribution artifact is not present')


@pytest.fixture(scope='module')
def reference():
    return load_reference(DISTRIBUTION, expected_model_version='risk-logreg-v1')


def vector(**overrides):
    values = {name: 0.0 for name in NAMES}
    values.update({'connections_10s': 2.0, 'connections_60s': 6.0, 'connections_900s': 20.0,
                   'ports_60s': 2.0, 'ports_900s': 3.0, 'destinations_60s': 1.0, 'families_60s': 1.0,
                   'interarrival_mean_60s': 10.0, 'persistence_900s': 30.0})
    values.update(overrides)
    return FeatureVector(values=tuple(values[name] for name in NAMES),
                         observation_seconds=overrides.pop('_seconds', 60.0),
                         sample_count=overrides.pop('_samples', 30))


# --- reference distribution ------------------------------------------------

def test_reference_distribution_is_model_scoped_and_validated(reference):
    assert reference.model_version == 'risk-logreg-v1'
    assert reference.feature_schema_version == 1
    assert reference.value_space == 'transformed'
    assert reference.sample_count > 0 and reference.features


def test_a_distribution_from_another_model_is_refused(reference):
    with pytest.raises(DistributionError, match='belongs to'):
        load_reference(DISTRIBUTION, expected_model_version='some-other-model-v9')


def test_malformed_distributions_are_refused(tmp_path):
    base = json.loads(DISTRIBUTION.read_text(encoding='utf-8'))
    for mutate, match in (
        (lambda d: d.update(distribution_version=99), 'distribution_version'),
        (lambda d: d.update(feature_schema_version=99), 'feature schema'),
        (lambda d: d.update(value_space='raw'), 'transformed'),
        (lambda d: d.update(sample_count=0), 'sample_count'),
        (lambda d: d.update(features={'not_a_feature': {}}), 'unknown features'),
    ):
        payload = json.loads(json.dumps(base))
        mutate(payload)
        target = tmp_path / 'bad.json'
        target.write_bytes(json.dumps(payload).encode())
        target.chmod(0o644)
        with pytest.raises(DistributionError, match=match):
            load_reference(target)


# --- OOD (spec section 85) -------------------------------------------------

def test_a_training_like_observation_is_in_distribution(reference):
    engine = OODEngine(reference)
    result = engine.evaluate(transformed_values(vector()))
    assert result.status == 'IN_DISTRIBUTION'
    assert result.score < engine.borderline_threshold
    assert result.distribution_confidence > 0.7


def test_an_observation_far_outside_training_is_out_of_distribution(reference):
    engine = OODEngine(reference)
    extreme = vector(connections_10s=500.0, connections_60s=500.0, connections_900s=500.0,
                     ports_60s=64.0, ports_900s=128.0, anomaly_60s=1.0, credentials_60s=20.0)
    result = engine.evaluate(transformed_values(extreme))
    assert result.status == 'OUT_OF_DISTRIBUTION'
    assert result.score >= engine.high_threshold
    assert result.distribution_confidence < 0.5
    assert result.top_outlier_features, 'an OOD verdict must name its contributors'
    for deviation in result.top_outlier_features:
        assert deviation.explain()['training_p99'] is not None


def test_ood_is_ordered_between_typical_and_extreme(reference):
    engine = OODEngine(reference)
    typical = engine.evaluate(transformed_values(vector())).score
    extreme = engine.evaluate(transformed_values(
        vector(connections_10s=500.0, ports_60s=64.0, anomaly_60s=1.0))).score
    assert typical < extreme


def test_missing_reference_never_pretends_to_know():
    result = OODEngine(None).evaluate({'connections_60s': 0.5})
    assert result.status == 'INSUFFICIENT_REFERENCE'
    assert result.distribution_confidence == 1.0, 'absence of evidence must not discount the model'


def test_too_few_comparable_features_is_insufficient_not_confident(reference):
    result = OODEngine(reference, minimum_features=100).evaluate(transformed_values(vector()))
    assert result.status == 'INSUFFICIENT_REFERENCE'


def test_non_finite_values_are_skipped_not_scored(reference):
    values = transformed_values(vector())
    values['connections_60s'] = float('nan')
    result = OODEngine(reference).evaluate(values)
    assert result.missing_features >= 1
    assert 0.0 <= result.score <= 1.0


# --- drift (spec section 84) ----------------------------------------------

def test_psi_is_zero_for_an_identical_distribution():
    fractions = [0.25, 0.25, 0.25, 0.25]
    assert psi(fractions, [250, 250, 250, 250]) == pytest.approx(0.0, abs=1e-9)


def test_psi_handles_empty_bins_without_dividing_by_zero():
    value = psi([0.25, 0.25, 0.25, 0.25], [1000, 0, 0, 0])
    assert value is not None and value > 0 and value == value  # finite, not NaN


def test_psi_returns_none_for_an_empty_window():
    assert psi([0.5, 0.5], [0, 0]) is None


def test_psi_grows_with_the_size_of_the_shift():
    fractions = [0.25, 0.25, 0.25, 0.25]
    small = psi(fractions, [260, 250, 245, 245])
    large = psi(fractions, [700, 200, 60, 40])
    assert small < large


def test_quantile_shift_detects_a_moved_median():
    class Ref:
        bin_fractions = (0.25, 0.25, 0.25, 0.25)
    assert quantile_shift(Ref, [250, 250, 250, 250]) == pytest.approx(0.0)
    assert quantile_shift(Ref, [0, 0, 0, 1000]) > 0.5


def population_matching(reference, count):
    """Synthesise observations whose distribution reproduces the reference exactly."""
    samples = []
    for index in range(count):
        position = (index + 0.5) / count
        values = {}
        for name, ref in reference.features.items():
            cumulative, chosen = 0.0, len(ref.bin_fractions) - 1
            for bin_index, fraction in enumerate(ref.bin_fractions):
                cumulative += fraction
                if position <= cumulative:
                    chosen = bin_index
                    break
            low, high = ref.bin_edges[chosen], ref.bin_edges[chosen + 1]
            values[name] = (low + high) / 2
        samples.append(values)
    return samples


def test_identical_population_is_stable(reference):
    engine = DriftEngine(reference, minimum_samples=50)
    clock = [1000.0]
    rolling = RollingDistribution(reference, clock=lambda: clock[0])
    for values in population_matching(reference, 400):
        rolling.observe(values)
        clock[0] += 1.0
    result = engine.evaluate(rolling.snapshot('24h'))
    assert result.status == 'STABLE'
    assert result.drifted_features == 0


def test_one_repeated_observation_is_itself_a_drifted_population(reference):
    """A population collapsed onto a single point is genuinely not the reference."""
    engine = DriftEngine(reference, minimum_samples=50)
    clock = [1000.0]
    rolling = RollingDistribution(reference, clock=lambda: clock[0])
    for _ in range(200):
        rolling.observe(transformed_values(vector()))
        clock[0] += 1.0
    assert engine.evaluate(rolling.snapshot('24h')).status == 'DRIFTED'


def test_a_shifted_population_is_detected(reference):
    engine = DriftEngine(reference, minimum_samples=50)
    clock = [1000.0]
    rolling = RollingDistribution(reference, clock=lambda: clock[0])
    for _ in range(300):
        rolling.observe(transformed_values(
            vector(connections_10s=400.0, connections_60s=480.0, ports_60s=60.0,
                   ports_900s=120.0, anomaly_60s=0.95, credentials_60s=18.0)))
        clock[0] += 1.0
    result = engine.evaluate(rolling.snapshot('24h'))
    assert result.status == 'DRIFTED'
    assert result.drifted_features > 0
    assert any(f.psi and f.psi > 0 for f in result.per_feature), 'per-feature drift is required'


def test_an_empty_window_is_insufficient_data_not_stable(reference):
    engine = DriftEngine(reference, minimum_samples=200)
    rolling = RollingDistribution(reference, clock=lambda: 1000.0)
    result = engine.evaluate(rolling.snapshot('1h'))
    assert result.status == 'INSUFFICIENT_DATA'
    assert 'samples' in result.reason


def test_drift_without_a_reference_is_insufficient_data():
    result = DriftEngine(None).evaluate({'window': '24h', 'sample_count': 10_000})
    assert result.status == 'INSUFFICIENT_DATA'


def test_drift_reports_every_feature_not_only_a_global_number(reference):
    engine = DriftEngine(reference, minimum_samples=50)
    clock = [1000.0]
    rolling = RollingDistribution(reference, clock=lambda: clock[0])
    for _ in range(200):
        rolling.observe(transformed_values(vector()))
        clock[0] += 1.0
    explained = engine.evaluate(rolling.snapshot('24h')).explain()
    assert explained['features'] and {'feature', 'status', 'psi'} <= set(explained['features'][0])


# --- bounded production statistics (spec section 8) -----------------------

def test_rolling_distribution_memory_is_bounded(reference):
    rolling = RollingDistribution(reference, clock=lambda: 1000.0)
    described = rolling.describe()
    assert described['bounded_cells'] < 100_000
    assert set(described['windows']) == {'1h', '24h', '7d'}


def test_old_samples_leave_the_window(reference):
    clock = [1000.0]
    rolling = RollingDistribution(reference, windows=(('1h', 300.0, 12),), clock=lambda: clock[0])
    for _ in range(100):
        rolling.observe(transformed_values(vector()))
    assert rolling.snapshot('1h')['sample_count'] > 0
    clock[0] += 10_000.0
    assert rolling.snapshot('1h')['sample_count'] == 0, 'the window must forget old traffic'


def test_windowed_histogram_rejects_impossible_geometry():
    with pytest.raises(ValueError):
        WindowedHistogram(bins=0, slice_seconds=60.0, slices=1)
    with pytest.raises(ValueError):
        WindowedHistogram(bins=4, slice_seconds=0, slices=1)


# --- model health (spec sections 37, 39) ----------------------------------

def test_model_health_reports_unavailable_without_a_model():
    health = model_health(loaded=False)
    assert health.state == 'UNAVAILABLE' and not health.allows_ml_enforcement


def test_drift_degrades_the_model_but_never_the_maths_engine(reference):
    drifted = drift_module.DriftResult(status='DRIFTED', overall_score=0.9, window='24h', sample_count=5000)
    health = model_health(loaded=True, model_version='risk-logreg-v1', drift=drifted)
    assert health.state == 'DEGRADED'
    assert not health.allows_ml_enforcement
    assert 'mathematical engine stays active' in health.explain()['note']


def test_a_high_population_ood_rate_marks_the_model_unreliable():
    assert model_health(loaded=True, ood_rate=0.05).state == 'HEALTHY'
    assert model_health(loaded=True, ood_rate=0.35).state == 'DEGRADED'
    assert model_health(loaded=True, ood_rate=0.70).state == 'UNRELIABLE'


def test_inference_failures_degrade_health():
    assert model_health(loaded=True, inference_failure_rate=0.5).state in ('DEGRADED', 'UNRELIABLE')


# --- fusion v2 (spec sections 33, 88) -------------------------------------

def fusion():
    return DecisionFusion(Config().decision)


def test_threat_evidence_and_decision_confidence_are_separate():
    strong = MLResult('healthy', 0.95, 'malicious-automation-like', 0.9)
    result = fusion().evaluate(MathRiskResult(0.9, {}), strong, 0.5, distribution_confidence=0.2)
    assert result.threat_evidence > 0.6, 'the evidence is still strong'
    assert result.decision_confidence < 0.3, 'but it cannot be trusted'
    assert result.reliable_risk < result.threat_evidence


def test_high_ood_lowers_the_classifier_share_and_never_raises_risk():
    strong = MLResult('healthy', 0.99, 'malicious-automation-like', 0.95)
    engine = fusion()
    trusted = engine.evaluate(MathRiskResult(0.5, {}), strong, 0.0, distribution_confidence=1.0)
    doubted = engine.evaluate(MathRiskResult(0.5, {}), strong, 0.0, distribution_confidence=0.1)
    assert doubted.ml_contribution < trusted.ml_contribution
    assert doubted.reliable_risk <= trusted.reliable_risk


def test_fusion_matches_p7_when_no_distribution_signal_exists():
    strong = MLResult('healthy', 0.8, 'malicious-automation-like', 0.75)
    engine = fusion()
    assert engine.combine(MathRiskResult(0.6, {}), strong, 0.2) == pytest.approx(
        engine.evaluate(MathRiskResult(0.6, {}), strong, 0.2).threat_evidence)


def test_an_unavailable_classifier_does_not_lower_confidence():
    result = fusion().evaluate(MathRiskResult(0.9, {}), MLResult('unavailable'), 0.1,
                               distribution_confidence=0.1)
    assert result.decision_confidence == 1.0, 'the maths engine must not be punished for a missing model'
    assert result.reliable_risk == pytest.approx(result.threat_evidence)


# --- policy (spec sections 5, 20, 89) -------------------------------------

def guard():
    config = Config()
    config.enforcement.management_networks = ['10.9.0.0/16']
    return PolicyGuard(config), config


def strong_vector():
    return vector(ports_60s=40.0, anomaly_60s=0.6, credentials_60s=9.0, continuation_60s=0.4,
                  persistence_900s=200.0, _samples=200, _seconds=600.0)


def test_out_of_distribution_reduces_a_block_to_watch():
    policy, _ = guard()
    ml = MLResult('healthy', 0.97, 'malicious-automation-like', 0.93)
    ood = OODResult(status='OUT_OF_DISTRIBUTION', score=0.85, reference_version='risk-logreg-v1')
    action, reasons, _ = policy.apply('TEMP_BLOCK', strong_vector(), MathRiskResult(0.9, {}), ml,
                                      source='198.51.100.7', ood=ood)
    assert action == 'WATCH'
    assert 'out_of_distribution' in reasons


def test_an_in_distribution_observation_is_not_suppressed_by_ood():
    policy, _ = guard()
    ml = MLResult('healthy', 0.97, 'malicious-automation-like', 0.93)
    ood = OODResult(status='IN_DISTRIBUTION', score=0.05, reference_version='risk-logreg-v1')
    _, reasons, _ = policy.apply('TEMP_BLOCK', strong_vector(), MathRiskResult(0.9, {}), ml,
                                 source='198.51.100.7', ood=ood)
    assert 'out_of_distribution' not in reasons


def test_a_degraded_model_cannot_drive_a_block_on_its_own():
    policy, _ = guard()
    ml = MLResult('healthy', 0.97, 'malicious-automation-like', 0.93)
    health = model_health(loaded=True, ood_rate=0.70)
    action, reasons, _ = policy.apply('TEMP_BLOCK', strong_vector(), MathRiskResult(0.4, {}), ml,
                                      source='198.51.100.7', model_health=health)
    assert action == 'WATCH'
    assert any(r.startswith('model_health_') for r in reasons)


def test_a_degraded_model_does_not_veto_the_maths_engine():
    policy, _ = guard()
    ml = MLResult('healthy', 0.97, 'malicious-automation-like', 0.93)
    health = model_health(loaded=True, ood_rate=0.70)
    _, reasons, _ = policy.apply('TEMP_BLOCK', strong_vector(), MathRiskResult(0.95, {}), ml,
                                 source='198.51.100.7', model_health=health)
    assert not any(r.startswith('model_health_') for r in reasons), \
        'a confident deterministic result stands on its own'


def test_low_data_quality_still_prevents_a_block():
    policy, _ = guard()
    thin = vector(_samples=2, _seconds=1.0)
    action, reasons, quality = policy.apply('TEMP_BLOCK', thin, MathRiskResult(0.95, {}),
                                            MLResult('unavailable'), source='198.51.100.7')
    assert action == 'WATCH'
    assert 'minimum_samples' in reasons and quality.score < 0.7


def test_protected_sources_are_never_blocked_whatever_the_evidence():
    policy, _ = guard()
    ood = OODResult(status='IN_DISTRIBUTION', score=0.0)
    for source in ('127.0.0.1', '10.9.4.5'):
        action, reasons, _ = policy.apply('TEMP_BLOCK', strong_vector(), MathRiskResult(1.0, {}),
                                          MLResult('healthy', 1.0, 'malicious-automation-like', 1.0),
                                          source=source, ood=ood)
        assert action == 'OBSERVE' and reasons == ['protected_source']


def test_anomalous_but_unremarkable_traffic_does_not_reach_a_block():
    """High OOD with weak threat evidence must land on WATCH, never TEMP_BLOCK."""
    policy, _ = guard()
    engine = fusion()
    ml = MLResult('unavailable')
    result = engine.evaluate(MathRiskResult(0.15, {}), ml, 0.0, distribution_confidence=0.2)
    proposed = engine.state(result.reliable_risk)
    assert proposed in ('OBSERVE', 'WATCH')
    action, _, _ = policy.apply(proposed, vector(), MathRiskResult(0.15, {}), ml,
                                source='198.51.100.7',
                                ood=OODResult(status='OUT_OF_DISTRIBUTION', score=0.8))
    assert action in ('OBSERVE', 'WATCH')


# --- the wired decision engine (spec sections 34, 35, 65) -----------------

def engine_config(tmp_path, *, distribution=True):
    config = Config()
    config.decision.enabled = True
    config.storage.enabled = False
    if distribution:
        target = tmp_path / 'reference.json'
        target.write_bytes(DISTRIBUTION.read_bytes())
        target.chmod(0o644)
        config.reliability.distribution_path = str(target)
    return config


def decisions_for(config, source, samples, *, ports=2.0, connections=6.0, anomaly=0.0):
    from datetime import datetime, timezone
    from eye_for_an_eye.correlation.engine import CorrelationEngine
    from eye_for_an_eye.decision.engine import DecisionEngine
    from eye_for_an_eye.events import NetworkEvent
    engine = DecisionEngine(config, CorrelationEngine(config.correlation), offline=True)
    engine.start()
    records = []
    for index in range(samples):
        vec = vector(ports_60s=ports, connections_60s=connections, anomaly_60s=anomaly,
                     _samples=40, _seconds=120.0)
        base = NetworkEvent(source, timestamp=datetime.now(timezone.utc))
        record = engine._record(base, vec, MLResult('unavailable'))
        if record is not None:
            records.append(record)
    return engine, records


def test_the_engine_runs_without_a_reference_distribution(tmp_path):
    engine, records = decisions_for(engine_config(tmp_path, distribution=False), '198.51.100.10', 1)
    assert engine.reference is None
    assert records and records[0].observations['ood']['status'] == 'INSUFFICIENT_REFERENCE'
    assert records[0].observations['evidence']['decision_confidence'] == 1.0


def test_the_engine_reports_the_full_p8_evidence_breakdown(tmp_path):
    _, records = decisions_for(engine_config(tmp_path), '198.51.100.11', 1)
    observed = records[0].observations
    for key in ('evidence', 'ood', 'model_health'):
        assert key in observed, key
    evidence = observed['evidence']
    assert evidence['fusion_version'] == 'decision-fusion-v2'
    for key in ('threat_evidence', 'decision_confidence', 'reliable_risk',
                'math_contribution', 'ml_contribution', 'distribution_confidence'):
        assert key in evidence, key
    assert observed['ood']['status'] in ('IN_DISTRIBUTION', 'BORDERLINE',
                                         'OUT_OF_DISTRIBUTION', 'INSUFFICIENT_REFERENCE')


def test_the_engine_tracks_a_population_ood_rate(tmp_path):
    engine, _ = decisions_for(engine_config(tmp_path), '198.51.100.12', 5)
    assert engine.ood_observations >= 1
    assert engine.ood_rate is not None and 0.0 <= engine.ood_rate <= 1.0
    assert engine.metrics['ood_evaluations_total'] >= 1


def test_drift_is_periodic_and_starts_as_insufficient_data(tmp_path):
    engine, _ = decisions_for(engine_config(tmp_path), '198.51.100.13', 3)
    result = engine.evaluate_drift('24h')
    assert result is not None
    assert result.status == 'INSUFFICIENT_DATA', 'a short run must not be called stable'
    assert engine.metrics['drift_evaluations_total'] == 1


def test_a_missing_distribution_file_is_survivable(tmp_path):
    config = Config()
    config.reliability.distribution_path = str(tmp_path / 'does-not-exist.json')
    from eye_for_an_eye.correlation.engine import CorrelationEngine
    from eye_for_an_eye.decision.engine import DecisionEngine
    engine = DecisionEngine(config, CorrelationEngine(config.correlation), offline=True)
    assert engine.reference is None
    assert engine.metrics['distribution_load_failures_total'] == 1
    assert engine.model_health().state in ('UNAVAILABLE', 'HEALTHY', 'DEGRADED')
