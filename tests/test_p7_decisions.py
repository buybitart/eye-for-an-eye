from dataclasses import replace
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import time
import pytest
from eye_for_an_eye.analysis import EventAnalysis
from eye_for_an_eye.config import Config
from eye_for_an_eye.decision.features import FeatureVector, NAMES
from eye_for_an_eye.decision.math_risk import MathRiskResult
from eye_for_an_eye.decision.onnx_model import MLResult
from eye_for_an_eye.decision.policy import DecisionFusion, PolicyGuard
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.event_types import EventType


def evidence(**kwargs):
    values = dict.fromkeys(NAMES, 0.0)
    values.update(ports_60s=64, ports_900s=96, credentials_60s=20, anomaly_60s=1,
                  continuation_60s=.9, persistence_900s=300, families_60s=4)
    return FeatureVector(tuple(values.values()), kwargs.pop('observation_seconds', 300), kwargs.pop('sample_count', 100),
        loss_fraction=kwargs.pop('loss_fraction', 0.0), **kwargs)


def test_fusion_fallback_confidence_and_hysteresis():
    cfg = Config()
    fusion = DecisionFusion(cfg.decision)
    math = MathRiskResult(.9, {})
    assert fusion.combine(math, MLResult(), .5) == pytest.approx(.86)
    assert fusion.combine(math, MLResult('healthy', .1, confidence=.5), .5) == pytest.approx(.86)
    assert fusion.combine(math, MLResult('healthy', float('nan'), confidence=1), .5) == pytest.approx(.86)
    assert fusion.state(.38, 'WATCH') == 'WATCH'
    assert fusion.state(.29, 'WATCH') == 'OBSERVE'
    assert fusion.state(.71) == 'RATE_LIMIT'
    assert fusion.state(.89) == 'TEMP_BLOCK'


@pytest.mark.parametrize('source', ['127.0.0.1', '::1', '::ffff:127.0.0.1', '10.1.0.4', '192.0.2.9', '2001:db8::5', '10.2.0.1'])
def test_all_protected_source_categories(source):
    cfg = Config()
    cfg.enforcement.management_networks = ['10.1.0.0/24']
    cfg.enforcement.allowlist = ['192.0.2.9/32']
    cfg.enforcement.trusted_proxies = ['2001:db8::/64']
    guard = PolicyGuard(cfg)
    action, reasons, _ = guard.apply('TEMP_BLOCK', evidence(), MathRiskResult(.99, {}), MLResult(),
        source=source, local_addresses=['10.2.0.1'])
    assert action == 'OBSERVE' and reasons == ['protected_source']


@pytest.mark.parametrize('row,healthy', [(evidence(sample_count=1), True), (evidence(observation_seconds=1), True),
    (evidence(capped=True), True), (evidence(loss_fraction=None), True), (evidence(), False)])
def test_guard_prevents_strong_action_with_insufficient_evidence(row, healthy):
    action, reasons, _ = PolicyGuard(Config()).apply('TEMP_BLOCK', row, MathRiskResult(.99, {}), MLResult(), source='192.0.2.8', healthy=healthy)
    assert action == 'WATCH' and reasons


def test_shadow_enforcement_disabled_and_policy_failure(monkeypatch):
    cfg = Config()
    engine = EventAnalysis(cfg).decisions
    event = NetworkEvent('192.0.2.4')
    record = engine._record(event, evidence(), MLResult('healthy', .99, confidence=.99))
    assert record.observations['would_enforce'] and not record.observations['enforced']
    assert 'shadow_mode' in record.observations['policy_reasons']
    assert NetworkEvent.from_json(record.to_json()).observations['ml']['risk_score'] == .99
    cfg.decision.mode = 'enforce'
    record = engine._record(event, evidence(), MLResult())
    assert 'enforcement_disabled' in record.observations['policy_reasons']
    monkeypatch.setattr(engine.guard, 'apply', lambda *a, **kw: (_ for _ in ()).throw(ValueError()))
    record = engine._record(event, evidence(), MLResult())
    assert record.observations['action'] == 'OBSERVE' and not record.observations['enforced']


def test_pipeline_local_onnx_and_not_per_packet():
    pytest.importorskip('onnxruntime')
    cfg = Config()
    fixture = Path(__file__).parent / 'fixtures' / 'p7'
    cfg.ml.model_path, cfg.ml.manifest_path = str(fixture / 'tiny-v1.onnx'), str(fixture / 'tiny-v1.json')
    analysis = EventAnalysis(cfg, offline=True)
    analysis.start()
    records = []
    try:
        for index in range(60):
            event = NetworkEvent('192.0.2.2', dst_ip='198.51.100.2', dst_port=1000+index, event_type='connection',
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index / 10),
                observations={'protocol_anomaly': True, 'payload_length': 20, 'protocol_family': 'http'})
            records.extend(analysis.process(event))
        decisions = [r for r in records if r.event_type == EventType.DECISION]
        assert len(decisions) == 3
        assert all(r.observations['ml']['status'] == 'healthy' for r in decisions)
        assert all(not r.observations['enforced'] for r in decisions)
        assert analysis.decisions.metrics['ml_inference_total'] == 3
    finally:
        analysis.close()


def test_optional_and_required_missing_model():
    cfg = Config()
    cfg.ml.model_path = cfg.ml.manifest_path = 'missing-file'
    analysis = EventAnalysis(cfg, offline=True)
    analysis.start()
    assert analysis.decisions.health()['status'] == 'unavailable'
    assert analysis.decisions.metrics['model_load_failure_total'] == 1
    analysis.decisions.health()
    assert analysis.decisions.metrics['model_load_failure_total'] == 1
    analysis.close()
    cfg.ml.required = True
    with pytest.raises(RuntimeError, match='required ML'):
        analysis.start()
    analysis.close()


def test_legacy_disabled_correlation_does_not_enable_decisions(tmp_path):
    from eye_for_an_eye.config import load_config
    path = tmp_path/'legacy.toml'
    path.write_text('[correlation]\nenabled=false\n')
    assert not load_config(path).decision.enabled


def test_bounded_worker_queue_cache_and_shutdown():
    from eye_for_an_eye.decision.worker import InferenceWorker
    cfg = Config().ml
    cfg.max_pending = 2
    worker = InferenceWorker(cfg)
    worker.ready.set()
    worker.model.state.update(loaded=True, status='healthy')
    assert worker.submit('one', evidence()) and worker.submit('two', evidence())
    assert not worker.submit('three', evidence())
    start = time.monotonic()
    assert worker.close() and time.monotonic() - start < 1.5
    assert not worker.submit('four', evidence())


def test_dataset_has_no_identity_and_context_is_not_label():
    from training.build_dataset import build
    rows = build(trials=6)
    groups = {}
    for row in rows:
        groups.setdefault(row['source_group'], set()).add(row['split'])
        assert not any(term in NAMES for term in ('source_group', 'scenario_id', 'label', 'src_ip', 'asn', 'country'))
    assert all(len(v) == 1 for v in groups.values())
    # Both classes observe deception and non-deception, avoiding the rejected v1 shortcut.
    for label in (0, 1):
        contexts = {row['features']['values'][NAMES.index('deception_60s')] > 0 for row in rows if row['label'] == label}
        assert contexts == {False, True}


def test_explain_retained_decision(tmp_path, capsys):
    from eye_for_an_eye.storage.sqlite import SQLiteStore
    from eye_for_an_eye.cli import main
    cfg = Config()
    cfg.storage.path = str(tmp_path / 'events.sqlite3')
    event = EventAnalysis(cfg).decisions._record(NetworkEvent('192.0.2.4'), evidence(), MLResult())
    store = SQLiteStore(cfg.storage)
    store.open()
    assert store.write(event)
    store.close()
    assert main(['decision', 'explain', event.event_id, '--storage-path', cfg.storage.path, '--json']) == 0
    assert json.loads(capsys.readouterr().out)['decision_id'] == event.event_id


def test_enforcement_failure_and_offense_decay():
    cfg = Config()
    cfg.decision.mode, cfg.enforcement.enabled = 'enforce', True
    cfg.enforcement.offense_decay_seconds = 1000
    class FakeEnforcer:
        def __init__(self):
            self.calls = []
        def block(self, source, duration):
            self.calls.append(duration)
            return True
    engine = EventAnalysis(cfg).decisions
    engine.enforcer = FakeEnforcer()
    event = NetworkEvent('192.0.2.5')
    for shift in (0, 301, 3000):
        engine._record(replace(event, timestamp=event.timestamp + timedelta(seconds=shift)), evidence(), MLResult())
    assert engine.enforcer.calls == [300, 1800, 300]


def test_async_model_result_does_not_fuse_with_its_own_pending_score():
    engine = EventAnalysis(Config()).decisions
    event = NetworkEvent('192.0.2.5')
    pending = engine._record(event, evidence(), MLResult('pending'))
    complete = engine._record(event, evidence(), MLResult('healthy', .3, confidence=.9))
    assert complete.observations['risk'] < pending.observations['risk']


def test_live_async_completion_and_startup_shutdown():
    pytest.importorskip('onnxruntime')
    cfg = Config()
    fixture = Path(__file__).parent/'fixtures'/'p7'
    cfg.ml.model_path, cfg.ml.manifest_path = str(fixture/'tiny-v1.onnx'), str(fixture/'tiny-v1.json')
    analysis = EventAnalysis(cfg)
    analysis.start()
    try:
        assert analysis.decisions.worker.ready.wait(10)
        event = NetworkEvent('192.0.2.5', dst_ip='198.51.100.5', dst_port=1234, event_type='connection')
        records = list(analysis.process(event))
        assert any(r.observations.get('ml', {}).get('status') == 'pending' for r in records)
        end = time.monotonic() + 2
        while time.monotonic() < end:
            records.extend(analysis.poll())
            if any(r.observations.get('ml', {}).get('status') == 'healthy' for r in records):
                break
            time.sleep(.01)
        assert any(r.observations.get('ml', {}).get('status') == 'healthy' for r in records)
    finally:
        analysis.close()
    assert not analysis.decisions.worker.thread.is_alive()
