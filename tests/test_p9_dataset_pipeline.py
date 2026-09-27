"""End to end: scenario -> sensor pipeline -> FeatureVectors -> rows -> validator -> split."""
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from eye_for_an_eye.decision.features import FeatureTransformer, INPUT_ORDER, NAMES, from_samples
from dataset import leakage, manifest as manifest_module, schema, split as split_module
from dataset.builder import collect, generate_raw, plan_context
from dataset.collectors.pcap import events as pcap_events, offline_config
from dataset.deduplicate import analyse
from dataset.generators import benign, scanner
from dataset.statistics import balance_report
from dataset.store import read
from dataset.validator import validate

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / 'datasets' / 'processed' / 'dataset-v1'
MANIFESTS = ROOT / 'datasets' / 'manifests'
RAW_INDEX = ROOT / 'datasets' / 'raw' / 'lab' / 'dataset-v1' / 'raw_index.json'
# The raw index is generated output and stays out of the repository; rebuild with
# `python -m dataset.cli build`. This test skips on a clean checkout.
needs_raw_index = pytest.mark.skipif(not RAW_INDEX.is_file(),
                                     reason='generated raw index is not distributed in the source archive')
# Processed split files are generated output too; rebuild with `python -m dataset.cli build`.
needs_processed = pytest.mark.skipif(not (PROCESSED / 'test.csv').is_file(),
                                     reason='generated dataset split is not distributed in the source archive')


def _clone(sample, **overrides):
    from dataclasses import fields
    values = {item.name: getattr(sample, item.name) for item in fields(sample)}
    values['provenance'] = dict(values['provenance'])
    values.update(overrides)
    return schema.DatasetSample(**values)


@pytest.fixture(scope='module')
def corpus():
    if not (PROCESSED / 'samples.csv').is_file():
        pytest.skip('generated dataset is not distributed in the source archive')
    return read(PROCESSED / 'samples.csv')


def test_integration_benign_client_and_scanner_reach_the_validator(tmp_path):
    pytest.importorskip('scapy')
    plans = [benign.web_client('unit/benign', 'unit-benign', 'unit/benign:0', requests=14, period=1.0),
             scanner.sequential_scan('unit/scan', 'unit-scan', 'unit/scan:0', port_count=40, period=.5)]
    index = generate_raw(plans, tmp_path / 'raw', dataset_version='unit-v1', matrix_version='unit')
    assert index['runs'] == 2 and index['packets'] > 0
    config = offline_config()
    samples = []
    for entry, plan in zip(index['captures'], plans, strict=True):
        parsed, stats = pcap_events(tmp_path / 'raw' / entry['capture'], config)
        assert stats['transmitted_packets'] == 0 and stats['parse_errors'] == 0
        produced, _ = collect(config, parsed, plan_context(plan, 'unit-v1'), interval=2.0,
                              max_samples_per_source=20)
        assert produced, plan.scenario_id
        samples.extend(produced)
    assert {sample.label for sample in samples} == {schema.BENIGN, schema.MALICIOUS}
    for sample in samples:
        assert sample.features.schema_version == schema.FEATURE_SCHEMA_VERSION
        assert len(sample.features.values) == len(NAMES)
    assignment = split_module.assign(samples, holdout={})
    split_module.apply(samples, assignment)
    report = validate(samples)
    assert report['critical'] == []
    # A two-scenario LAB-only slice is engineering material: the gate wants a PCAP contribution
    # and a leakage report before it will call anything ready.
    assert report['readiness'] == 'ENGINEERING_ONLY'
    assert any('PCAP' in reason for reason in report['readiness_reasons'])


def test_features_come_from_the_production_extractor(tmp_path):
    pytest.importorskip('scapy')
    plan = scanner.sequential_scan('unit/parity', 'unit-parity', 'unit/parity:0', port_count=30, period=.4)
    index = generate_raw([plan], tmp_path / 'raw', dataset_version='unit-v1', matrix_version='unit')
    config = offline_config()
    parsed, _ = pcap_events(tmp_path / 'raw' / index['captures'][0]['capture'], config)
    produced, _ = collect(config, parsed, plan_context(plan, 'unit-v1'), interval=2.0)
    # Rebuild the same vector straight from the production correlation state and compare.
    from eye_for_an_eye.correlation.engine import CorrelationEngine
    correlator = CorrelationEngine(config.correlation)
    checked = 0
    for event in parsed:
        correlator.observe(event)
        state = correlator.cache.get((event.sensor_id, event.src_ip))
        if not state:
            continue
        stamp = event.timestamp.timestamp()
        match = [s for s in produced if abs(s.timestamp.timestamp() - stamp) < 1e-6]
        if not match:
            continue
        expected = from_samples(state['samples'], now=stamp, horizon=max(config.correlation.windows),
                                previous_risk=0.0, capped=state['capped'], loss_fraction=0.0)
        assert match[0].features.values == expected.values
        assert FeatureTransformer.transform(match[0].features) == FeatureTransformer.transform(expected)
        checked += 1
    assert checked >= 3


def test_duplicate_and_conflicting_label_detection(corpus):
    report = analyse(corpus)
    assert report['duplicate_sample_ids'] == []
    assert report['conflicting_label_vectors'] == 0
    first = corpus[0]
    conflicting = [first, _clone(first, sample_id=first.sample_id + ':copy',
                                 label=schema.MALICIOUS if first.label == schema.BENIGN
                                 else schema.BENIGN)]
    conflict_report = analyse(conflicting)
    assert conflict_report['conflicting_label_vectors'] == 1
    assert 'conflicting labels' in ' '.join(validate(conflicting)['critical'])
    duplicated = [first, first]
    assert 'duplicate sample ids' in ' '.join(validate(duplicated)['critical'])


def test_ranges_masks_and_unlabelled_handling(corpus):
    report = validate(corpus, leakage_report=True)
    assert report['critical'] == []
    assert report['values']['out_of_range_count'] == 0
    assert report['values']['non_finite'] == 0
    assert report['values']['mask_errors'] == 0
    full = validate(corpus, leakage_report=True)
    assert full['readiness'] == 'READY_FOR_BASELINE_TRAINING'
    assert full['automatic_enforcement_ready'] is False
    unlabelled = schema.DatasetSample(
        dataset_version=corpus[0].dataset_version,
        feature_schema_version=corpus[0].feature_schema_version, sample_id='shadow#0001',
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), source_type=schema.SHADOW_UNLABELED,
        scenario_group=None, source_group='shadow-abc', capture_group=None,
        label=schema.UNLABELED, label_source='shadow_observation', label_confidence='LOW',
        features=corpus[0].features)
    mixed = validate(corpus[:50] + [unlabelled])
    assert mixed['critical'] == []
    assert any('unlabelled or uncertain' in warning for warning in mixed['warnings'])


def test_split_is_group_based_and_holds_out_whole_families(corpus):
    assignment = split_module.assign(corpus)
    split_module.apply(corpus, assignment)
    assert split_module.assert_no_leakage(corpus)
    parts = split_module.partition(corpus)
    assert all(parts[name] for name in split_module.SPLITS)
    for family, (target, _) in split_module.HOLDOUT.items():
        present = {sample.split for sample in corpus
                   if sample.scenario_group == family and sample.split}
        assert present in ({target}, set()), family
    for name, rows in parts.items():
        labels = {sample.label for sample in rows}
        assert labels == set(schema.SUPERVISED_LABELS), name
    labelled = next(sample for sample in corpus if sample.split)
    leaked = [labelled, _clone(labelled, sample_id=labelled.sample_id + ':x',
                               split='test' if labelled.split != 'test' else 'train')]
    with pytest.raises(split_module.LeakageError):
        split_module.assert_no_leakage(leaked)


@needs_processed
def test_test_set_immutability_is_verifiable():
    split_record = manifest_module.read(MANIFESTS / 'dataset-v1-split.json')
    assert split_record['splits']['test']['samples'] > 0
    assert 'frozen' in split_record['immutability']
    assert manifest_module.verify_files(split_record, PROCESSED) == []
    tampered = dict(split_record, files=dict(split_record['files'],
                                             test=dict(split_record['files']['test'], sha256='0' * 64)))
    assert manifest_module.verify_files(tampered, PROCESSED)


@needs_raw_index
def test_leakage_analysis_runs_and_finds_no_single_feature_shortcut(corpus):
    raw_index = json.loads(RAW_INDEX.read_text(encoding='utf-8'))
    report = leakage.report(corpus, raw_index['captures'])
    assert report['feature_separation']['suspicious'] == []
    assert report['generator_fingerprint']['contact_shapes_exclusive_to_one_label'] == []
    assert report['port_leakage']['best_single_port_rule_accuracy'] < .9
    assert report['timing_leakage']['mean_interarrival_range_overlap'] > .3
    assert leakage.auc([0, 1, 2, 3], [0, 0, 1, 1]) == 1.0
    assert leakage.auc([0, 0, 0], [0, 0, 0]) is None
    balance = balance_report(corpus)
    assert balance['largest_scenario_share_percent'] < 25
    assert balance['hard_negative_scenarios'] >= 3 and balance['hard_positive_scenarios'] >= 3


def test_shadow_export_is_redacted_pseudonymous_and_unlabelled(tmp_path):
    from dataset.collectors.shadow import dropped_fields, export, sanitize, source_group as shadow_group
    events_path = tmp_path / 'shadow.jsonl'
    rows = []
    for index in range(4):
        rows.append(json.dumps({
            'src_ip': f'198.51.100.{index + 1}', 'sensor_id': 'sensor-a',
            'timestamp': '2026-01-01T00:00:0%d+00:00' % index,
            'features': {'values': [0.5] * len(NAMES), 'observation_seconds': 30.0,
                         'sample_count': 12, 'capped': False, 'loss_fraction': 0.0},
            'observations': {'payload_length': 12, 'raw_payload': 'GET /admin', 'authorization': 'Bearer x',
                             'cookie': 'session=1', 'probe_digest': 'ab' * 32, 'protocol_family': 'http',
                             'credential_like_attempt': True},
            'analysis': {'math_score': .8, 'model_score': .9, 'action': 'WATCH'}}))
    events_path.write_text('\n'.join(rows) + '\n', encoding='utf-8')
    result = export(events_path, tmp_path / 'unlabeled', max_samples=10)
    assert result['rows'] == 4 and result['label'] == schema.UNLABELED
    assert set(result['redacted_input_fields']) >= {'raw_payload', 'authorization', 'cookie', 'probe_digest'}
    text = (tmp_path / 'unlabeled' / 'shadow_unlabeled.csv').read_text(encoding='utf-8')
    for secret in ('GET /admin', 'Bearer', 'session=1', 'ab' * 32, '198.51.100.'):
        assert secret not in text
    samples = read(tmp_path / 'unlabeled' / 'shadow_unlabeled.csv')
    assert all(sample.label == schema.UNLABELED for sample in samples)
    assert all(sample.label_source == 'shadow_observation' for sample in samples)
    assert all(sample.source_group.startswith('shadow-') for sample in samples)
    analysis = samples[0].provenance['analysis_only']
    assert analysis['math_score'] == .8 and analysis['model_score'] == .9
    assert not set(samples[0].provenance['sensor_observations']) & {'math_score', 'model_score', 'action'}
    assert sanitize({'raw_payload': 'x'}) == {}
    assert 'raw_payload' in dropped_fields({'raw_payload': 'x'})
    assert shadow_group(b'k' * 32, 's', '1.2.3.4') != shadow_group(b'j' * 32, 's', '1.2.3.4')
    report = validate(samples)
    assert report['critical'] == []
    assert report['readiness'] != 'READY_FOR_BASELINE_TRAINING'


def test_no_model_feature_is_an_identity_or_decision_column(corpus):
    manifest = manifest_module.read(MANIFESTS / 'dataset-v1.json')
    # Read against the schema the manifest declares, not the one this build has.
    # A manifest describes its own dataset, so a later appended column does not
    # make a historical one wrong — and this alarm has to keep meaning "the
    # manifest disagrees with the code" rather than "the schema moved on".
    assert manifest['model_feature_names'] == list(
        schema.model_features_for(manifest['feature_schema_version']))
    assert not set(manifest['model_feature_names']) & set(schema.NEVER_MODEL_INPUT)
    tensor = FeatureTransformer.transform(corpus[0].features)
    assert len(tensor) == len(INPUT_ORDER)
    assert [tensor[index] for index in schema.EXCLUDED_INDEX] == [0.0, 1.0]
    assert all(sample.features.values[NAMES.index('previous_risk')] == 0.0 for sample in corpus[:200])
    assert all(sample.provenance.get('source_type') in schema.SOURCE_TYPES or not sample.provenance
               for sample in corpus[:50])
