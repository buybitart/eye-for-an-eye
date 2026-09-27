"""Manifest contract, hash binding, frozen feature list and shadow-only defaults."""
import hashlib
import json
from pathlib import Path
import pytest
from eye_for_an_eye.config import MLConfig
from eye_for_an_eye.decision.features import MODEL_SCHEMAS, INPUT_ORDER
from eye_for_an_eye.decision.onnx_model import CLASSES, read_artifacts
from training import schema
from training.dataset import DATASET_VERSION
from training.export_onnx import finalize_manifest

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / 'models'
VERSION = schema.MODEL_VERSION
MODEL = MODELS / (VERSION + '.onnx')
MANIFEST = MODELS / (VERSION + '.json')

pytestmark = pytest.mark.skipif(not MODEL.is_file() or not MANIFEST.is_file(),
                                reason='research artifacts are not distributed in the source archive')


@pytest.fixture(scope='module')
def manifest():
    return json.loads(MANIFEST.read_text(encoding='utf-8'))


def test_manifest_hash_binds_the_artifact(manifest):
    assert manifest['sha256'] == hashlib.sha256(MODEL.read_bytes()).hexdigest()
    assert len(MANIFEST.read_bytes()) <= 32768
    parsed, data = read_artifacts(MLConfig(model_path=str(MODEL), manifest_path=str(MANIFEST)))
    assert parsed['model_version'] == VERSION and len(data) == MODEL.stat().st_size


def test_manifest_declares_the_production_contract(manifest):
    assert manifest['manifest_version'] == 1
    # The shipped artifact declares the schema it was fitted on; this build
    # serves it through FeatureTransformer.project. Requiring equality here
    # would fail every time a column is appended, which is not a defect.
    assert manifest['feature_schema_version'] in MODEL_SCHEMAS
    order = MODEL_SCHEMAS[manifest['feature_schema_version']]
    assert manifest['feature_order'] == list(order)
    assert manifest['input_name'] == 'features'
    assert manifest['input_shape'] == [1, len(order)]
    assert manifest['input_dtype'] == 'float32'
    assert manifest['output_names'] == ['label', 'probabilities']
    assert manifest['classes'] == CLASSES
    assert manifest['score_semantics'] == 'uncalibrated_model_score'
    assert manifest['training_dataset_version'] == DATASET_VERSION


def test_manifest_documents_shadow_only_and_the_frozen_feature_list(manifest):
    assert manifest['recommended_mode'] == 'shadow'
    assert manifest['recommended_shadow_only'] is True
    assert manifest['quality_gate_passed'] is False
    assert manifest['quality_gate_status'] == 'PROVISIONAL'
    assert manifest['positive_class'] == schema.POSITIVE_CLASS
    assert manifest['model_family'] == 'logistic_regression'
    assert manifest['training_synthetic_only'] is True
    assert manifest['model_feature_names'] == list(
        schema.model_features_for(manifest['feature_schema_version']))
    assert set(manifest['zero_weight_columns']) == set(schema.EXCLUDED_FEATURES)
    assert not set(manifest['model_feature_names']) & schema.FORBIDDEN_FEATURES
    assert manifest['onnx_parity']['passed'] is True
    assert manifest['onnx_parity']['max_absolute_difference'] <= manifest['onnx_parity']['tolerance']
    assert 'DecisionFusion' in manifest['threshold_authority']
    assert set(manifest['library_versions']) >= {'python', 'numpy', 'scikit-learn', 'onnx', 'skl2onnx'}


def test_manifest_rejects_contract_drift(tmp_path, manifest):
    config = MLConfig(model_path=str(MODEL), manifest_path=str(tmp_path / 'manifest.json'))
    for field, bad in (('feature_order', list(reversed(INPUT_ORDER))), ('sha256', '0' * 64),
                       ('input_shape', [1, len(INPUT_ORDER) - 1]), ('input_dtype', 'float64'),
                       ('feature_schema_version', 99), ('input_name', 'x'),
                       ('classes', list(reversed(CLASSES))), ('score_semantics', 'probability'),
                       ('model_version', 'bad version!'), ('manifest_version', 2)):
        Path(config.manifest_path).write_text(json.dumps(dict(manifest, **{field: bad})), encoding='utf-8')
        with pytest.raises(ValueError):
            read_artifacts(config)


def test_finalize_manifest_cannot_rewrite_the_contract(tmp_path, manifest):
    model_copy, manifest_copy = tmp_path / 'copy.onnx', tmp_path / 'copy.json'
    model_copy.write_bytes(MODEL.read_bytes())
    manifest_copy.write_text(json.dumps(manifest), encoding='utf-8')
    updated = finalize_manifest(manifest_copy, {'note': 'documentation only'})
    assert updated['note'] == 'documentation only' and updated['sha256'] == manifest['sha256']
    for field in ('feature_order', 'sha256', 'input_shape', 'model_version', 'created_at'):
        with pytest.raises(ValueError, match='immutable'):
            finalize_manifest(manifest_copy, {field: 'tampered'})
    with pytest.raises(ValueError, match='reader limit'):
        finalize_manifest(manifest_copy, {'padding': 'x' * 40000})


def test_model_and_documentation_artifacts_exist():
    assert MODEL.stat().st_size < 65536
    for name in (VERSION + '-training.json', VERSION + '-evaluation.json', VERSION + '-shadow.json',
                 VERSION + '-pcap.json', 'MODEL_CARD_' + VERSION + '.md'):
        assert (MODELS / name).exists(), name
    report = (ROOT / 'reports' / ('model-' + VERSION + '.md')).read_text(encoding='utf-8')
    assert 'ENGINEERING BASELINE ONLY' in report and 'SHADOW ONLY' in report
    card = (MODELS / ('MODEL_CARD_' + VERSION + '.md')).read_text(encoding='utf-8')
    assert 'SHADOW MODE' in card and 'does **not**' in card
    shadow = json.loads((MODELS / (VERSION + '-shadow.json')).read_text(encoding='utf-8'))
    assert shadow['release_recommendation'] == 'SHADOW ONLY'
    assert shadow['enforcement'].startswith('disabled')
