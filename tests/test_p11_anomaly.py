"""P8 anomaly detection: unusual is not malicious.

The properties defended here are structural, not advisory: an anomaly score can
never reach a blocking decision on its own, and a broken anomaly model can never
stop the sensor.
"""
import json
from pathlib import Path
import pytest

from eye_for_an_eye.config import Config
from eye_for_an_eye.decision.anomaly import (AnomalyContractError, AnomalyModel, AnomalyResult,
                                             normalise, read_manifest)
from eye_for_an_eye.decision.features import FeatureTransformer, FeatureVector, INPUT_ORDER, NAMES
from eye_for_an_eye.decision.math_risk import MathRiskResult
from eye_for_an_eye.decision.onnx_model import MLResult
from eye_for_an_eye.decision.policy import DecisionFusion

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'models' / 'isolation-v1.onnx'
MANIFEST = ROOT / 'models' / 'isolation-v1.json'

pytestmark = pytest.mark.skipif(not (MODEL.is_file() and MANIFEST.is_file()),
                                reason='anomaly artifact is not distributed in the source archive')


def vector(**overrides):
    values = {name: 0.0 for name in NAMES}
    values.update({'connections_10s': 2.0, 'connections_60s': 6.0, 'connections_900s': 20.0,
                   'ports_60s': 2.0, 'ports_900s': 3.0, 'destinations_60s': 1.0,
                   'families_60s': 1.0, 'interarrival_mean_60s': 10.0, 'persistence_900s': 30.0})
    values.update(overrides)
    return FeatureVector(values=tuple(values[name] for name in NAMES),
                         observation_seconds=60.0, sample_count=30)


@pytest.fixture(scope='module')
def model():
    loaded = AnomalyModel(manifest_path=str(MANIFEST), model_path=str(MODEL))
    assert loaded.load()
    return loaded


# --- artifact contract (spec sections 30, 67, 87) -------------------------

def test_the_anomaly_artifact_loads_and_reports_health(model):
    health = model.health()
    assert health['status'] == 'healthy'
    assert health['model_version'] == 'isolation-v1'
    assert health['loaded'] is True


def test_the_manifest_records_its_own_score_normalisation():
    manifest, _ = read_manifest(str(MANIFEST), str(MODEL))
    spec = manifest['normalization']
    assert spec['method'] and spec['high'] > spec['low']
    assert manifest['model_family'] == 'isolation_forest'
    assert manifest['training_population']['mode'] == 'trusted_benign'
    assert manifest['recommended_mode'] == 'shadow'
    assert manifest['feature_schema_version'] == 1


def test_the_anomaly_feature_set_is_behaviour_only():
    manifest, _ = read_manifest(str(MANIFEST), str(MODEL))
    for name in manifest['feature_names']:
        assert name in INPUT_ORDER
    banned = ('src_ip', 'asn', 'country', 'provider', 'hostname', 'previous_risk', 'action', 'risk')
    assert not any(any(word in name for word in banned) for name in manifest['feature_names'])


def test_a_tampered_model_is_refused(tmp_path):
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    target = tmp_path / 'model.onnx'
    target.write_bytes(MODEL.read_bytes() + b'tampered')
    target.chmod(0o644)
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest), encoding='utf-8')
    path.chmod(0o644)
    with pytest.raises(AnomalyContractError, match='SHA256'):
        read_manifest(str(path), str(target))


def test_a_schema_mismatch_is_refused(tmp_path):
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    manifest['feature_schema_version'] = 99
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest), encoding='utf-8')
    path.chmod(0o644)
    with pytest.raises(AnomalyContractError, match='feature schema'):
        read_manifest(str(path), str(MODEL))


def test_a_wrong_feature_count_is_refused(tmp_path):
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    manifest['input_shape'] = [1, 3]
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest), encoding='utf-8')
    path.chmod(0o644)
    with pytest.raises(AnomalyContractError, match='input shape'):
        read_manifest(str(path), str(MODEL))


# --- scoring (spec sections 29, 87) ---------------------------------------

def test_scores_are_bounded_and_carry_documented_semantics(model):
    result = model.score(FeatureTransformer.transform(vector()))
    assert result.status == 'healthy' and result.usable
    assert 0.0 <= result.anomaly_score <= 1.0
    assert '0 = common' in result.explain()['semantics']
    assert 'not evidence of an attack' in result.explain()['note']


def test_an_extreme_observation_scores_higher_than_a_typical_one(model):
    typical = model.score(FeatureTransformer.transform(vector())).anomaly_score
    extreme = model.score(FeatureTransformer.transform(
        vector(connections_10s=480.0, connections_60s=500.0, ports_60s=62.0,
               ports_900s=126.0, anomaly_60s=0.95, credentials_60s=19.0))).anomaly_score
    assert extreme > typical


def test_the_raw_score_is_reported_separately_from_the_normalised_one(model):
    result = model.score(FeatureTransformer.transform(vector()))
    assert result.raw_score is not None
    assert result.raw_score != result.anomaly_score, 'a raw forest score is not an anomaly score'


def test_normalisation_is_clamped_and_monotone():
    spec = {'high': 0.2, 'low': -0.1}
    assert normalise(spec, 0.9) == 0.0
    assert normalise(spec, -9.0) == 1.0
    assert normalise(spec, 0.05) > normalise(spec, 0.15)


def test_top_signals_name_behaviour_not_availability_flags(model):
    result = model.score(FeatureTransformer.transform(
        vector(ports_60s=50.0, credentials_60s=15.0)))
    assert all(not name.startswith('available_') for name in result.top_signals)


# --- failure behaviour (spec sections 31, 78) -----------------------------

def test_a_missing_artifact_is_a_supported_state_not_a_crash():
    absent = AnomalyModel(manifest_path='/nonexistent/manifest.json', model_path='/nonexistent/model.onnx')
    assert absent.load() is False
    result = absent.score([0.0] * len(INPUT_ORDER))
    assert result.status == 'ANOMALY_MODEL_UNAVAILABLE'
    assert not result.usable
    assert result.anomaly_score is None


def test_a_disabled_model_reports_disabled():
    result = AnomalyModel(enabled=False).score([0.0] * len(INPUT_ORDER))
    assert result.status == 'disabled' and not result.usable


def test_non_finite_input_is_refused_not_scored(model):
    tensor = list(FeatureTransformer.transform(vector()))
    tensor[0] = float('nan')
    result = model.score(tensor)
    assert not result.usable
    assert result.error == 'non-finite feature value'


def test_repeated_failures_open_the_circuit_breaker(model):
    broken = AnomalyModel(manifest_path=str(MANIFEST), model_path=str(MODEL), max_failures=2)
    broken.load()
    broken.session = object()  # force inference to fail
    for _ in range(3):
        broken.score(FeatureTransformer.transform(vector()))
    result = broken.score(FeatureTransformer.transform(vector()))
    assert 'repeated inference failures' in (result.error or '')


# --- fusion (spec sections 4, 33, 88) -------------------------------------

def fusion():
    return DecisionFusion(Config().decision)


def anomaly(score):
    return AnomalyResult(status='healthy', anomaly_score=score, raw_score=0.0,
                         model_version='isolation-v1')


def test_anomaly_alone_can_never_reach_a_block():
    """The structural guarantee: maximum anomaly with no other evidence is not a block."""
    engine = fusion()
    result = engine.evaluate(MathRiskResult(0.01, {}), MLResult('unavailable'), 0.0,
                             anomaly=anomaly(1.0))
    assert result.threat_evidence < Config().decision.block_threshold
    assert engine.state(result.reliable_risk) in ('OBSERVE', 'WATCH')


def test_high_anomaly_with_low_evidence_stays_low():
    engine = fusion()
    quiet = engine.evaluate(MathRiskResult(0.05, {}), MLResult('unavailable'), 0.0, anomaly=anomaly(0.0))
    odd = engine.evaluate(MathRiskResult(0.05, {}), MLResult('unavailable'), 0.0, anomaly=anomaly(0.95))
    assert odd.threat_evidence > quiet.threat_evidence, 'anomaly is evidence'
    assert engine.state(odd.reliable_risk) in ('OBSERVE', 'WATCH'), 'but not enough to act on'


def test_fusion_is_unchanged_when_no_anomaly_model_is_loaded():
    engine = fusion()
    ml = MLResult('healthy', 0.9, 'malicious-automation-like', 0.85)
    without = engine.evaluate(MathRiskResult(0.7, {}), ml, 0.3)
    unusable = engine.evaluate(MathRiskResult(0.7, {}), ml, 0.3,
                               anomaly=AnomalyResult(status='ANOMALY_MODEL_UNAVAILABLE'))
    assert without.threat_evidence == pytest.approx(unusable.threat_evidence)
    assert without.anomaly_contribution == 0.0


def test_the_anomaly_share_is_bounded_by_its_configured_weight():
    config = Config()
    engine = DecisionFusion(config.decision)
    result = engine.evaluate(MathRiskResult(0.5, {}), MLResult('unavailable'), 0.0, anomaly=anomaly(1.0))
    assert result.anomaly_contribution <= config.decision.anomaly_weight + 1e-9


def test_the_decision_record_explains_the_anomaly(model):
    result = model.score(FeatureTransformer.transform(vector()))
    explained = fusion().evaluate(MathRiskResult(0.5, {}), MLResult('unavailable'), 0.0,
                                  anomaly=result).explain()
    assert 'anomaly_score' in explained and 'anomaly_contribution' in explained
