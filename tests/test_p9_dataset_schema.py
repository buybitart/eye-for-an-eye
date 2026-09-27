"""dataset-v1.0 schema, labels, manifest and the model feature contract."""
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES, FeatureVector
from dataset import manifest as manifest_module, schema
from dataset.store import read, write

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / 'datasets' / 'processed' / 'dataset-v1'
MANIFESTS = ROOT / 'datasets' / 'manifests'

pytestmark = pytest.mark.skipif(not (PROCESSED / 'samples.csv').is_file(),
                                reason='generated dataset is not distributed in the source archive')


def vector(**overrides):
    values = list(overrides.pop('values', [1.0] * len(NAMES)))
    return FeatureVector(tuple(values), overrides.pop('observation_seconds', 30.0),
                         overrides.pop('sample_count', 12), overrides.pop('capped', False),
                         overrides.pop('loss_fraction', 0.0))


def sample(**overrides):
    fields = {'dataset_version': 'unit-v1', 'feature_schema_version': schema.FEATURE_SCHEMA_VERSION,
              'sample_id': 'unit#0001', 'timestamp': datetime(2026, 1, 1, tzinfo=timezone.utc),
              'source_type': schema.LAB, 'scenario_id': 'unit/scenario', 'scenario_group': 'unit',
              'source_group': 'unit#00', 'capture_group': None,
              'label': schema.BENIGN, 'label_source': 'controlled_scenario', 'label_confidence': 'HIGH',
              'features': vector(), 'provenance': {}}
    fields.update(overrides)
    return schema.DatasetSample(**fields)


def test_model_feature_contract_excludes_identity_and_decisions():
    assert len(schema.MODEL_FEATURES) == len(INPUT_ORDER) - len(schema.EXCLUDED_FROM_MODEL)
    assert not set(schema.MODEL_FEATURES) & set(schema.NEVER_MODEL_INPUT)
    for name in ('src_ip', 'dst_ip', 'asn', 'country', 'source_group', 'scenario_id', 'label',
                 'previous_risk', 'math_score', 'ml_score', 'blocked', 'block_status', 'final_risk'):
        assert name in schema.NEVER_MODEL_INPUT, name
        assert name not in schema.MODEL_FEATURES
    document = schema.model_feature_document()
    assert [item['name'] for item in document['model_features']] == list(
        schema.model_features_for(document['feature_schema_version']))
    assert {item['name'] for item in document['excluded_from_model']} == set(schema.EXCLUDED_FROM_MODEL)
    assert all(item['reason'] for item in document['never_model_input'])
    assert document['tensor_contract']['order'] == list(INPUT_ORDER)


def test_label_and_confidence_validation():
    assert sample().label == schema.BENIGN
    with pytest.raises(ValueError):
        sample(label='hacker')
    with pytest.raises(ValueError):
        sample(label_source='shadow_decision')
    with pytest.raises(ValueError):
        sample(label_source='blocked')
    with pytest.raises(ValueError):
        sample(label_confidence='CERTAIN')
    with pytest.raises(ValueError, match='HIGH confidence'):
        sample(label=schema.UNCERTAIN, label_confidence='HIGH')
    with pytest.raises(ValueError, match='unlabelled pool'):
        sample(label=schema.BENIGN, label_source='shadow_observation')
    assert sample(label=schema.UNLABELED, label_source='shadow_observation',
                  label_confidence='LOW').label == schema.UNLABELED
    assert sample(label=schema.UNCERTAIN, label_confidence='LOW').label == schema.UNCERTAIN


def test_provenance_cannot_carry_identity_or_payload():
    for key in ('src_ip', 'dst_ip', 'username', 'password', 'payload', 'cookie'):
        with pytest.raises(ValueError, match='identity or payload'):
            sample(provenance={key: 'x'})
    assert sample(provenance={'source_type': schema.LAB}).provenance['source_type']


def test_row_round_trip_and_missing_values(tmp_path):
    values = [None] + [0.5] * (len(NAMES) - 1)
    original = sample(features=vector(values=values), provenance={'source_type': schema.LAB},
                      split='train')
    write(tmp_path / 'rows.csv', [original])
    restored = read(tmp_path / 'rows.csv')[0]
    assert restored.features.values[0] is None
    assert restored.features.values[1] == 0.5
    assert restored.sample_id == original.sample_id and restored.label == original.label
    assert restored.split == 'train' and restored.source_type == schema.LAB
    text = (tmp_path / 'rows.csv').read_text(encoding='utf-8')
    assert 'src_ip' not in text and '192.0.2.' not in text and '198.51.100.' not in text


def test_generated_dataset_columns_carry_no_address():
    text = (PROCESSED / 'samples.csv').read_text(encoding='utf-8')
    assert '192.0.2.' not in text and '198.51.100.' not in text and '203.0.113.' not in text
    header = text.splitlines()[0].split(',')
    # Either the current layout or the version 1 one. The shipped corpus
    # predates `site_group`, and reading it must keep working.
    assert schema.accepted_columns(header) is not None, header
    assert not set(header) & {'src_ip', 'dst_ip', 'asn', 'country', 'port', 'dst_port'}


def test_dataset_manifest_is_complete_and_verifiable():
    manifest = manifest_module.read(MANIFESTS / 'dataset-v1.json')
    for field in ('dataset_version', 'feature_schema_version', 'created_at', 'record_count', 'labels',
                  'sources', 'feature_names', 'generator_version', 'sha256', 'reproduce', 'scenarios',
                  'seeds', 'files', 'truncated', 'safety'):
        assert field in manifest, field
    # Against the schema the manifest declares: it describes the dataset it was
    # written for, and a column appended later does not make it wrong.
    declared = manifest['feature_schema_version']
    assert manifest['feature_names'] == list(schema.feature_names_for(declared))
    assert manifest['model_feature_names'] == list(schema.model_features_for(declared))
    assert manifest['labels'][schema.BENIGN] > 0 and manifest['labels'][schema.MALICIOUS] > 0
    assert manifest['truncated'] is False
    assert manifest_module.verify_files(manifest, PROCESSED) == []
    assert 'python -m dataset build' in manifest['reproduce']
    document = json.loads((ROOT / 'datasets' / 'model_features_v1.json').read_text(encoding='utf-8'))
    assert [item['name'] for item in document['model_features']] == list(
        schema.model_features_for(document['feature_schema_version']))
    stats = json.loads((ROOT / 'datasets' / 'stats_v1.json').read_text(encoding='utf-8'))
    assert set(stats['features']) == set(
        schema.model_features_for(stats['feature_schema_version']))
    assert stats['rows'] == manifest['record_count']
