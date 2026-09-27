"""Exported graph equals the fitted model, rejects bad input and needs no training library."""
import math
from pathlib import Path
import subprocess
import sys
import pytest
from eye_for_an_eye.config import MLConfig
from eye_for_an_eye.decision.features import FeatureTransformer, INPUT_ORDER
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel
from training import schema
from training.dataset import DATASET_VERSION, load
from training.export_onnx import coefficients_from_onnx

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / 'models'
DATASET = ROOT / 'datasets' / DATASET_VERSION
VERSION = schema.MODEL_VERSION
TOLERANCE = 1e-5

pytestmark = pytest.mark.skipif(not (MODELS / (VERSION + '.onnx')).is_file() or
                                not (DATASET / 'dataset_manifest.json').is_file(),
                                reason='research artifacts are not distributed in the source archive')

NO_TRAINING_LIBRARY = """
import sys
BLOCKED = ('sklearn', 'skl2onnx', 'scipy', 'pandas')
class Guard:
    def find_spec(self, name, path=None, target=None):
        if name.split('.')[0] in BLOCKED:
            raise AssertionError('inference must not import ' + name)
        return None
sys.meta_path.insert(0, Guard())
sys.path.insert(0, {root!r})
from eye_for_an_eye.config import MLConfig
from eye_for_an_eye.decision.features import INPUT_ORDER
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel
model = OnnxRiskModel()
state = model.load(MLConfig(model_path={model!r}, manifest_path={manifest!r}))
assert state['status'] == 'healthy', state
row = [0.0] * len(INPUT_ORDER)
result = model.predict(row)
assert result.status == 'healthy' and 0 <= result.risk_score <= 1, result
assert result.model_version == {version!r}
assert result.predicted_class in ('benign-like', 'malicious-automation-like')
assert 'sklearn' not in sys.modules and 'skl2onnx' not in sys.modules
print('ok', result.risk_score)
"""


def config():
    return MLConfig(model_path=str(MODELS / (VERSION + '.onnx')), manifest_path=str(MODELS / (VERSION + '.json')))


@pytest.fixture(scope='module')
def adapter():
    pytest.importorskip('onnxruntime')
    model = OnnxRiskModel()
    assert model.load(config())['status'] == 'healthy'
    return model


@pytest.fixture(scope='module')
def test_rows():
    return [row for row in load(DATASET)[1] if row['split'] == 'test']


def test_exported_graph_matches_a_float64_recomputation(adapter, test_rows):
    weights, intercept = coefficients_from_onnx(MODELS / (VERSION + '.onnx'))
    assert list(weights) == list(INPUT_ORDER)
    ordered = [weights[name] for name in INPUT_ORDER]
    worst = 0.0
    for row in test_rows[::7]:
        tensor = FeatureTransformer.transform(row['vector'])
        result = adapter.predict(list(tensor))
        assert result.status == 'healthy'
        expected = 1 / (1 + math.exp(-(sum(c * v for c, v in zip(ordered, tensor, strict=True)) + intercept)))
        worst = max(worst, abs(expected - result.risk_score))
    assert worst <= TOLERANCE, worst


def test_excluded_columns_have_zero_weight_and_no_effect(adapter):
    weights, _ = coefficients_from_onnx(MODELS / (VERSION + '.onnx'))
    assert all(weights[name] == 0.0 for name in schema.EXCLUDED_FEATURES)
    row = [0.3] * len(INPUT_ORDER)
    baseline = adapter.predict(list(row)).risk_score
    for index in schema.EXCLUDED_INDEX:
        changed = list(row)
        changed[index] = 1.0
        assert adapter.predict(changed).risk_score == baseline


def test_round_trip_export_parity(tmp_path):
    pytest.importorskip('skl2onnx')
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from training.export_onnx import export, widen
    rng = np.random.default_rng(11)
    x = rng.random((160, len(schema.MODEL_FEATURES))).astype(np.float32)
    y = (x[:, 0] + x[:, 3] > 1.0).astype(np.int64)
    model = LogisticRegression(C=1.0, l1_ratio=0, max_iter=2000, random_state=7).fit(x, y)
    full = widen(model)
    assert full.coef_.shape == (1, len(INPUT_ORDER))
    model_path, manifest_path = export(full, tmp_path, 'parity-test-v1', 'unit-fixture-v1')
    runtime = OnnxRiskModel()
    assert runtime.load(MLConfig(model_path=str(model_path), manifest_path=str(manifest_path)))['status'] == 'healthy'
    expected = model.predict_proba(x)[:, 1]
    differences = []
    for row, reference in zip(x, expected, strict=True):
        result = runtime.predict(schema.expand(row.tolist()))
        assert result.status == 'healthy'
        differences.append(abs(result.risk_score - reference))
    assert max(differences) <= TOLERANCE
    with pytest.raises(FileExistsError):
        export(full, tmp_path, 'parity-test-v1', 'unit-fixture-v1')


def test_invalid_input_is_rejected(adapter):
    size = len(INPUT_ORDER)
    good = [0.0] * size
    assert adapter.predict(good).status == 'healthy'
    for bad in (good[:-1], good + [0.0], [float('nan')] + good[1:], [float('inf')] + good[1:],
                [2.0] + good[1:], [-0.5] + good[1:], ['0.0'] + good[1:], [None] + good[1:]):
        result = adapter.predict(bad)
        assert result.status == 'degraded' and result.risk_score is None
    assert adapter.predict(good).status == 'healthy'


def test_inference_without_any_training_library():
    pytest.importorskip('onnxruntime')
    code = NO_TRAINING_LIBRARY.format(root=str(ROOT), model=str(MODELS / (VERSION + '.onnx')),
                                      manifest=str(MODELS / (VERSION + '.json')), version=VERSION)
    finished = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=180)
    assert finished.returncode == 0, finished.stderr
    assert finished.stdout.startswith('ok ')


def test_training_is_deterministic_for_a_fixed_seed():
    pytest.importorskip('sklearn')
    import numpy as np
    from training.train_logreg import fit
    rng = np.random.default_rng(3)
    x = rng.random((240, len(schema.MODEL_FEATURES))).astype(np.float32)
    y = (x[:, 2] + x[:, 5] > 1.0).astype(np.int64)
    first, second = fit(x, y, 1.0, 'balanced'), fit(x, y, 1.0, 'balanced')
    assert np.array_equal(first.coef_, second.coef_)
    assert np.array_equal(first.intercept_, second.intercept_)
    assert not np.array_equal(first.coef_, fit(x, y, 0.01, 'balanced').coef_)


def test_labelled_pcap_replays_through_features_into_the_model(tmp_path):
    pytest.importorskip('scapy')
    pytest.importorskip('onnxruntime')
    from training.pcap_evaluate import evaluate
    corpus = ROOT / 'tests' / 'fixtures' / 'p2' / 'corpus.json'
    result = evaluate(corpus, MODELS, VERSION)
    assert result['transmitted_packets'] == 0
    samples = {sample['id']: sample for sample in result['samples']}
    assert set(samples) == {'scan', 'noise'}
    for sample in samples.values():
        for info in sample['decisions_by_source'].values():
            assert info['model_status'] == 'healthy'
            assert 0.0 <= info['model_score'] <= 1.0
            assert not info['would_enforce']
    assert samples['scan']['decisions_by_source']['192.0.2.1']['model_score'] > \
        samples['noise']['decisions_by_source']['192.0.2.1']['model_score']


def test_export_is_byte_reproducible(tmp_path):
    pytest.importorskip('skl2onnx')
    import hashlib
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from training.export_onnx import export, widen
    rng = np.random.default_rng(5)
    x = rng.random((120, len(schema.MODEL_FEATURES))).astype(np.float32)
    y = (x[:, 1] > 0.5).astype(np.int64)
    model = widen(LogisticRegression(C=1.0, l1_ratio=0, max_iter=2000, random_state=7).fit(x, y))
    digests = []
    for name in ('first', 'second'):
        path, _ = export(model, tmp_path / name, 'reproducible-v1', 'unit-fixture-v1', deterministic_name=True)
        digests.append(hashlib.sha256(path.read_bytes()).hexdigest())
    assert digests[0] == digests[1]
    loose, _ = export(model, tmp_path / 'loose', 'reproducible-v1', 'unit-fixture-v1')
    assert hashlib.sha256(loose.read_bytes()).hexdigest() != digests[0]
