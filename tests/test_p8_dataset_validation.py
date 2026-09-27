"""Dataset contract, range, label, duplicate and leakage validation for risk-logreg-v1."""
import csv
import json
from pathlib import Path
import pytest
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES, SCHEMA_VERSION, FeatureVector
from training import schema
from training.dataset import COLUMNS, DATASET_VERSION, load
from training.validation import distribution_report, duplicate_report, tensors, validate_dataset

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / 'datasets' / DATASET_VERSION

pytestmark = pytest.mark.skipif(not (DATASET / 'dataset_manifest.json').is_file(),
                                reason='research dataset is not distributed in the source archive')


@pytest.fixture(scope='module')
def corpus():
    return load(DATASET)


def test_model_feature_contract_excludes_identity_and_decision_columns():
    assert len(schema.MODEL_FEATURES) == len(INPUT_ORDER) - 2
    assert not set(schema.MODEL_FEATURES) & schema.FORBIDDEN_FEATURES
    assert set(schema.EXCLUDED_FEATURES) == {'previous_risk', 'available_previous_risk'}
    assert schema.MODEL_FEATURES == tuple(n for n in INPUT_ORDER if n not in schema.EXCLUDED_FEATURES)
    assert schema.select(list(range(len(INPUT_ORDER)))) == [float(i) for i in schema.MODEL_INDEX]
    widened = schema.expand(schema.select([1.0] * len(INPUT_ORDER)))
    assert [widened[i] for i in schema.EXCLUDED_INDEX] == [0.0, 0.0]
    assert schema.FINGERPRINT_DERIVED == ()


def test_shipped_dataset_passes_validation(corpus):
    manifest, rows = corpus
    report = validate_dataset(manifest, rows)
    assert report['critical'] == []
    assert manifest['feature_schema_version'] == SCHEMA_VERSION
    assert manifest['model_feature_names'] == list(schema.MODEL_FEATURES)
    assert manifest['label_source'] in schema.ALLOWED_LABEL_SOURCES
    for split, info in report['class_distribution'].items():
        assert info['rows'] > 0 and min(info['counts'].values()) > 0, split
        assert abs(sum(info['percent'].values()) - 100) < 1e-6


def test_ranges_masks_and_missing_semantics(corpus):
    _, rows = corpus
    matrix = tensors(rows)
    assert all(0.0 <= value <= 1.0 for tensor in matrix for value in tensor)
    for row, tensor in zip(rows[:200], matrix[:200], strict=True):
        for index, name in enumerate(NAMES):
            observed = row['vector'].values[index] is not None
            assert tensor[INPUT_ORDER.index('available_' + name)] == float(observed)
            if not observed:
                assert tensor[index] == 0.0
    report = distribution_report(rows)
    assert set(report) == set(schema.MODEL_FEATURES)
    assert all(0.0 <= info['min'] <= info['max'] <= 1.0 for info in report.values())


def test_out_of_range_values_are_critical_not_clipped(corpus, monkeypatch):
    manifest, rows = corpus
    subset = rows[:50]
    monkeypatch.setattr('training.validation.tensors',
                        lambda data: [[1.5] * len(INPUT_ORDER) for _ in data])
    report = validate_dataset(manifest, subset)
    assert any('outside the declared [0,1] contract' in item for item in report['critical'])


def test_non_finite_feature_values_are_rejected():
    values = [0.0] * len(NAMES)
    values[0] = float('nan')
    with pytest.raises(ValueError):
        FeatureVector(tuple(values), 10.0, 8)
    values[0] = float('inf')
    with pytest.raises(ValueError):
        FeatureVector(tuple(values), 10.0, 8)


def test_invalid_labels_and_decision_derived_sources_are_critical(corpus):
    manifest, rows = corpus
    broken = [dict(rows[0], label=2)] + rows[1:20]
    assert 'label outside the binary schema' in validate_dataset(manifest, broken)['critical']
    derived = [dict(rows[0], label_source='blocked')] + rows[1:20]
    assert 'decision-derived label found in rows' in validate_dataset(manifest, derived)['critical']
    forbidden = dict(manifest, model_feature_names=list(schema.MODEL_FEATURES) + ['src_ip'])
    assert any('forbidden' in item for item in validate_dataset(forbidden, rows[:20])['critical'])
    reordered = dict(manifest, model_feature_names=list(reversed(schema.MODEL_FEATURES)))
    assert any('feature order' in item for item in validate_dataset(reordered, rows[:20])['critical'])


def test_duplicate_detection_reports_cross_split_vectors(corpus):
    manifest, rows = corpus
    report = duplicate_report(rows)
    assert report['exact_vectors_crossing_train_boundary'] == 0
    assert report['distinct_exact_vectors'] == report['rows']
    train = next(row for row in rows if row['split'] == 'train')
    injected = [train, dict(train, split='test', sample_id=train['sample_id'] + ':copy')]
    assert duplicate_report(injected)['exact_vectors_crossing_train_boundary'] == 1
    assert 'identical feature vectors appear in train and a held-out split' in \
        validate_dataset(manifest, injected)['critical']


def test_loader_rejects_tampered_files(tmp_path, corpus):
    manifest, _ = corpus
    for name in ('train.csv', 'validation.csv', 'test.csv'):
        (tmp_path / name).write_bytes((DATASET / name).read_bytes())
    (tmp_path / 'dataset_manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    assert load(tmp_path)[1]
    rows = list(csv.DictReader((tmp_path / 'test.csv').read_text(encoding='utf-8').splitlines()))
    rows[0]['label'] = '1' if rows[0]['label'] == '0' else '0'
    with (tmp_path / 'test.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS, lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(ValueError, match='hash mismatch'):
        load(tmp_path)
    (tmp_path / 'dataset_manifest.json').write_text(
        json.dumps(dict(manifest, feature_schema_version=SCHEMA_VERSION + 1)), encoding='utf-8')
    with pytest.raises(ValueError, match='feature schema'):
        load(tmp_path)
    (tmp_path / 'dataset_manifest.json').write_text(
        json.dumps(dict(manifest, label_source='automatically_blocked')), encoding='utf-8')
    with pytest.raises(ValueError, match='decision-derived'):
        load(tmp_path)
