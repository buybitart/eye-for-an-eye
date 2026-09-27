import json
import hashlib
from pathlib import Path
import pytest
from eye_for_an_eye.config import MLConfig
from eye_for_an_eye.decision.features import MODEL_SCHEMAS
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel, IsolatedModel, read_artifacts

FIXTURE = Path(__file__).parent / 'fixtures' / 'p7'

#: The fixture model declares feature schema 1, and this suite exercises the
#: artifact contract rather than whichever schema the build currently has.
#: Widths and orders therefore come from the schema the artifact itself names —
#: that is the whole point of the contract, and pinning the build's own schema
#: would make these tests fail every time a column is appended.
FIXTURE_SCHEMA = 1
INPUT_ORDER = MODEL_SCHEMAS[FIXTURE_SCHEMA]


def config():
    return MLConfig(model_path=str(FIXTURE / 'tiny-v1.onnx'), manifest_path=str(FIXTURE / 'tiny-v1.json'))


def test_manifest_and_hash_without_optional_dependencies(tmp_path):
    cfg = config()
    manifest, data = read_artifacts(cfg)
    assert data and manifest['feature_order'] == list(INPUT_ORDER)
    for field, bad in [('feature_order', list(reversed(INPUT_ORDER))), ('sha256', '0'*64),
                       ('input_shape', [1, 24]), ('input_dtype', 'string'), ('feature_schema_version', 99),
                       ('feature_schema_version', True), ('input_shape', [True, len(INPUT_ORDER)])]:
        modified = dict(manifest, **{field: bad})
        path = tmp_path / 'manifest.json'
        path.write_text(json.dumps(modified))
        cfg.manifest_path = str(path)
        with pytest.raises(ValueError):
            read_artifacts(cfg)


def test_cpu_fixture_and_invalid_input():
    pytest.importorskip('onnxruntime')
    model = OnnxRiskModel()
    assert model.load(config())['status'] == 'healthy'
    result = model.predict([0.0]*len(INPUT_ORDER))
    assert result.status == 'healthy' and result.risk_score < .03
    row = [0.0]*len(INPUT_ORDER)
    row[3] = 1.0
    assert model.predict(row).risk_score > .99
    assert model.predict(row[:-1]).status == 'degraded'
    row[0] = float('nan')
    assert model.predict(row).risk_score is None


def test_invalid_model_and_nan_warmup(tmp_path):
    pytest.importorskip('onnxruntime')
    from training.export_onnx import tiny_fixture
    model, manifest = tiny_fixture(tmp_path, nan=True)
    assert OnnxRiskModel().load(MLConfig(model_path=str(model), manifest_path=str(manifest)))['status'] == 'unavailable'
    cfg = config()
    cfg.model_path = str(tmp_path / 'missing.onnx')
    assert OnnxRiskModel().load(cfg)['status'] == 'unavailable'


def test_isolated_roundtrip_and_close():
    pytest.importorskip('onnxruntime')
    model = IsolatedModel(config())
    try:
        assert model.load()['status'] == 'healthy'
        assert model.predict([0.0]*len(INPUT_ORDER)).status == 'healthy'
    finally:
        model.close()
    assert not model.process.is_alive()


def test_hard_deadline_kills_worker(monkeypatch):
    pytest.importorskip('onnxruntime')
    model = IsolatedModel(config())
    assert model.load()['status'] == 'healthy'
    monkeypatch.setattr(model.connection, 'poll', lambda timeout: False)
    result = model.predict([0.0]*len(INPUT_ORDER))
    # The reason travels with the class now. `inference deadline` is one of this
    # module's own fixed strings, so it is allowed through; the adjacent test
    # below keeps a foreign exception reporting its class name alone.
    assert result.error == 'TimeoutError: inference deadline' and not model.process.is_alive()
    model.close()


def test_corrupt_graph_with_matching_hash_and_inference_exception(tmp_path):
    pytest.importorskip('onnxruntime')
    cfg = config()
    manifest = json.loads(Path(cfg.manifest_path).read_text())
    data = b'not-an-onnx-graph'
    manifest['sha256'] = hashlib.sha256(data).hexdigest()
    model_path, manifest_path = tmp_path/'bad.onnx', tmp_path/'bad.json'
    model_path.write_bytes(data)
    manifest_path.write_text(json.dumps(manifest))
    assert OnnxRiskModel().load(MLConfig(model_path=str(model_path), manifest_path=str(manifest_path)))['status'] == 'unavailable'
    model = OnnxRiskModel()
    assert model.load(config())['status'] == 'healthy'
    class BrokenSession:
        def run(self, *args):
            raise RuntimeError('fixture inference failure')
    model.session = BrokenSession()
    assert model.predict([0.0]*len(INPUT_ORDER)).error == 'RuntimeError'


def test_serialized_session_concurrency():
    pytest.importorskip('onnxruntime')
    from concurrent.futures import ThreadPoolExecutor
    model = OnnxRiskModel()
    assert model.load(config())['status'] == 'healthy'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(model.predict, [[0.0]*len(INPUT_ORDER)]*20))
    assert all(r.status == 'healthy' for r in results)


def test_posix_writable_model_rejected(tmp_path):
    import os
    if os.name != 'posix':
        pytest.skip('POSIX write permissions; Windows ACL provisioning is operator controlled')
    cfg = config()
    path = tmp_path/'unsafe.onnx'
    path.write_bytes(Path(cfg.model_path).read_bytes())
    path.chmod(0o666)
    cfg.model_path = str(path)
    with pytest.raises(ValueError, match='permissions'):
        read_artifacts(cfg)
