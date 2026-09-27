"""dataset-v1: three sources, three label authorities, one feature pipeline."""
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from dataset import manifest as manifest_module, provenance, schema, split as split_module
from dataset.collectors import live, pcap as pcap_collector, shadow as shadow_collector
from dataset.deduplicate import cross_source
from dataset.safety import UnsafeTarget
from dataset.store import read
from dataset.validator import validate

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / 'datasets' / 'processed' / 'dataset-v1'
MANIFESTS = ROOT / 'datasets' / 'manifests'
RAW = ROOT / 'datasets' / 'raw'

pytestmark = pytest.mark.skipif(not (PROCESSED / 'samples.csv').is_file(),
                                reason='generated dataset is not distributed in the source archive')
# Raw captures are generated output and stay out of the repository; rebuild with
# `python -m dataset.cli build`. Tests that read them skip on a clean checkout.
needs_raw = pytest.mark.skipif(not (RAW / 'pcap' / 'dataset-v1' / 'captures.json').is_file(),
                               reason='generated raw captures are not distributed in the source archive')


@pytest.fixture(scope='module')
def corpus():
    return read(PROCESSED / 'samples.csv')


def test_every_source_is_present_and_keeps_its_own_label_authority(corpus):
    counts = {source: sum(1 for sample in corpus if sample.source_type == source)
              for source in schema.SOURCE_TYPES}
    assert counts[schema.LAB] and counts[schema.PCAP] and counts[schema.SHADOW_UNLABELED]
    for sample in corpus:
        authority = sample.provenance.get('label_authority', '')
        if sample.source_type == schema.LAB:
            assert sample.label in schema.SUPERVISED_LABELS and 'controlled scenario' in authority
        elif sample.source_type == schema.PCAP:
            assert 'sidecar' in authority or 'unlabelled' in authority
        else:
            assert sample.label == schema.UNLABELED and 'none' in authority


def test_source_type_and_grouping_keys_are_never_model_features(corpus):
    for name in ('source_type', 'capture_group', 'source_group', 'scenario_group', 'sensor_id',
                 'src_ip', 'dst_ip', 'asn', 'country', 'generator_version', 'seed', 'run_id',
                 'capture_id', 'pcap_filename', 'previous_risk', 'ml_score', 'math_score',
                 'block_status', 'would_block', 'final_score'):
        assert name in schema.NEVER_MODEL_INPUT, name
        assert name not in schema.MODEL_FEATURES
    text = (PROCESSED / 'samples.csv').read_text(encoding='utf-8')
    for address in ('192.0.2.', '198.51.100.', '203.0.113.', '2001:db8', '127.0.0.1'):
        assert address not in text
    document = json.loads((ROOT / 'datasets' / 'model_features_v1.json').read_text(encoding='utf-8'))
    excluded = {item['name'] for item in document['never_model_input']}
    assert {'src_ip', 'country', 'asn', 'source_group', 'capture_group', 'source_type'} <= excluded


def test_unreviewed_shadow_is_unlabelled_and_never_in_a_supervised_split(corpus):
    pool = [sample for sample in corpus if sample.source_type == schema.SHADOW_UNLABELED]
    assert pool
    for sample in pool:
        assert sample.label == schema.UNLABELED
        assert sample.label_source == 'shadow_observation'
        assert sample.label_confidence == 'LOW'
        assert sample.supervised is False
        assert sample.split is None
    assert split_module.assert_no_leakage(corpus)
    with pytest.raises(split_module.LeakageError, match='unreviewed shadow'):
        leaked = list(corpus)
        pool[0].split = 'train'
        try:
            split_module.assert_no_leakage(leaked)
        finally:
            pool[0].split = None


def test_shadow_keeps_decisions_as_analysis_only(corpus):
    sample = next(s for s in corpus if s.source_type == schema.SHADOW_UNLABELED)
    analysis = sample.provenance['analysis_only']
    assert {'math_score', 'final_score', 'action', 'would_block'} <= set(analysis)
    assert not set(analysis) & set(schema.MODEL_FEATURES)
    assert sample.provenance['label_authority'].startswith('none')
    observations = sample.provenance.get('sensor_observations', {})
    assert set(observations) <= shadow_collector.SAFE_OBSERVATION_KEYS


@needs_raw
def test_pcap_captures_are_grouped_and_labelled_by_their_sidecar(corpus):
    manifest, entries = pcap_collector.load_corpus(RAW / 'pcap' / 'dataset-v1' / 'captures.json')
    assert manifest['transmitted_packets'] == 0
    assert any(entry['label'] == schema.UNLABELED for entry, _ in entries), 'no unlabelled capture'
    assert any(entry['label_source'] == 'trusted_fixture' for entry, _ in entries)
    assert 'file name never decides' in manifest['labelling']
    rows = [sample for sample in corpus if sample.source_type == schema.PCAP]
    assert rows
    for sample in rows:
        assert sample.capture_group and sample.group == sample.capture_group
        assert sample.scenario_group is None
    # A capture never straddles a split: every window of one capture shares one side.
    for group in {sample.capture_group for sample in rows}:
        splits = {sample.split for sample in rows if sample.capture_group == group and sample.split}
        assert len(splits) <= 1, group


@needs_raw
def test_lab_live_runs_come_from_the_production_sensor():
    index_path = RAW / 'lab-live' / 'dataset-v1' / 'live_index.json'
    index = json.loads(index_path.read_text(encoding='utf-8'))
    assert index['runs']
    for entry in index['runs']:
        assert entry['transmitted_packets'] == 0
        assert 'loopback' in entry['target_policy']
        assert entry['events'] > 0
    assert 'loopback only' in index['safety']


def test_lab_config_refuses_anything_that_is_not_loopback():
    with pytest.raises(UnsafeTarget):
        live.lab_config([9001], bind='0.0.0.0')
    with pytest.raises(UnsafeTarget):
        live.lab_config([9001], bind='8.8.8.8')
    config = live.lab_config([live.free_port(), live.free_port()])
    assert config.deception.mode == 'lab'
    assert config.network.bind_address == '127.0.0.1'
    assert config.deception.source_allowlist == ['127.0.0.1/32', '::1/128']


def test_cross_source_duplicate_detection(corpus):
    report = cross_source(corpus)
    assert report['with_conflicting_labels'] == 0
    lab = next(sample for sample in corpus if sample.source_type == schema.LAB and sample.supervised)
    from dataclasses import fields
    values = {item.name: getattr(lab, item.name) for item in fields(lab)}
    values.update(sample_id=lab.sample_id + ':copy', source_type=schema.PCAP,
                  capture_group='pcap-copy', scenario_group=None,
                  label=schema.MALICIOUS if lab.label == schema.BENIGN else schema.BENIGN,
                  provenance=dict(lab.provenance))
    injected = cross_source([lab, schema.DatasetSample(**values)])
    assert injected['vectors_in_multiple_sources'] == 1
    assert injected['with_conflicting_labels'] == 1
    assert 'LAB + PCAP' in injected['source_pairs']


def test_readiness_gate_requires_a_pcap_contribution_and_a_leakage_report(corpus):
    full = validate(corpus, leakage_report=True)
    assert full['critical'] == []
    assert full['readiness'] == 'READY_FOR_BASELINE_TRAINING'
    assert full['automatic_enforcement_ready'] is False
    lab_only = [sample for sample in corpus if sample.source_type == schema.LAB]
    partial = validate(lab_only, leakage_report=True)
    assert partial['readiness'] == 'ENGINEERING_ONLY'
    assert any('PCAP' in reason for reason in partial['readiness_reasons'])
    without_report = validate(corpus, leakage_report=False)
    assert without_report['readiness'] == 'ENGINEERING_ONLY'
    assert any('leakage report' in reason for reason in without_report['readiness_reasons'])


def test_manual_review_allows_uncertain_and_records_its_annotation():
    from dataset.review import DECISIONS, queue, review_record
    assert schema.UNCERTAIN in DECISIONS
    sample = schema.DatasetSample(
        dataset_version='unit-v1', feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
        sample_id='shadow-unit#0001', timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source_type=schema.SHADOW_UNLABELED, scenario_group=None, source_group='shadow-unit',
        capture_group=None, label=schema.UNLABELED, label_source='shadow_observation',
        label_confidence='LOW',
        features=read(PROCESSED / 'samples.csv')[0].features,
        provenance=provenance.shadow(sensor_placement='unit', collected_at='2026-01-01T00:00:00Z',
                                     analysis_only={'math_score': .1, 'model_score': .9}))
    assert queue([sample])[0]['reasons'] == ['math and model disagree by 0.80']
    record = review_record({'decision': schema.UNCERTAIN, 'reviewer_note': 'not enough evidence'})
    assert record['confidence'] == 'LOW' and record['reviewed_at'] and record['reason']
    assert 'reviewer' not in json.dumps(record).replace('reviewer_note', '')


def test_manual_review_promotes_a_shadow_row_and_never_forces_a_binary_label(tmp_path):
    from dataset.review import apply_decisions, export
    samples = [sample for sample in read(PROCESSED / 'samples.csv')
               if sample.source_type == schema.SHADOW_UNLABELED][:3]
    path = tmp_path / 'review.json'
    export(samples, path)
    payload = json.loads(path.read_text(encoding='utf-8'))
    assert payload['allowed_decisions'] == [schema.BENIGN, schema.MALICIOUS, schema.UNCERTAIN]
    assert 'uncertain' in payload['guidance']
    text = json.dumps(payload)
    for secret in ('192.0.2.', '198.51.100.', '203.0.113.', 'raw_payload', 'cookie',
                   'authorization', 'password'):
        assert secret not in text
    # The reviewer does see what the system thought - that is the point of a review.
    assert payload['samples'][0]['system_opinion']['math_score'] is not None
    payload['samples'][0]['decision'] = schema.MALICIOUS
    payload['samples'][0]['reviewer_note'] = 'sustained probing across many ports'
    payload['samples'][1]['decision'] = schema.UNCERTAIN
    path.write_text(json.dumps(payload), encoding='utf-8')
    result = apply_decisions(samples, path)
    assert result['applied'] == 2
    assert samples[0].source_type == schema.SHADOW_REVIEWED
    assert samples[0].label == schema.MALICIOUS and samples[0].label_source == 'manual_review'
    assert samples[0].label_confidence in ('MEDIUM', 'LOW')
    assert samples[0].supervised is True
    assert samples[1].label == schema.UNCERTAIN and samples[1].supervised is False
    assert samples[0].provenance['review']['reason'].startswith('sustained')


def test_manifest_records_every_source_and_verifies(corpus):
    manifest = manifest_module.read(MANIFESTS / 'dataset-v1.json')
    assert manifest['dataset_version'] == 'dataset-v1'
    assert set(manifest['source_type_counts']) >= {schema.LAB, schema.PCAP, schema.SHADOW_UNLABELED}
    assert manifest['supervised_eligible'] + manifest['unlabelled_pool'] == manifest['record_count']
    # Against the schema the manifest declares — see the note in
    # test_p9_dataset_pipeline for why a historical manifest is read that way.
    assert manifest['generator_version'] and manifest['feature_names'] == list(
        schema.feature_names_for(manifest['feature_schema_version']))
    assert manifest_module.verify_files(manifest, PROCESSED) == []
    split_record = manifest_module.read(MANIFESTS / 'dataset-v1-split.json')
    assert split_record['dataset_sha256'] == manifest['sha256']
    assert split_record['frozen'] is True
    assert split_record['grouping_rules'][schema.PCAP] == 'capture_group'
    assert manifest_module.verify_files(split_record, PROCESSED) == []
    leakage = json.loads((MANIFESTS / 'dataset-v1-leakage.json').read_text(encoding='utf-8'))
    assert leakage['source_type_leakage']['sources']
    assert leakage['feature_separation']['suspicious'] == []
    distribution = json.loads((MANIFESTS / 'dataset-v1-distribution.json').read_text(encoding='utf-8'))
    assert 'LAB_vs_PCAP' in distribution['shift']['pairs']
    assert distribution['out_of_distribution']['pool_rows'] > 0


def test_end_to_end_lab_pcap_and_shadow(tmp_path):
    """LAB benign + LAB scanner + a labelled PCAP fixture + a shadow pool, all the way to a split."""
    pytest.importorskip('scapy')
    from dataset.builder import collect, generate_raw, plan_context
    from dataset.collectors.pcap import events as pcap_events, offline_config
    from dataset.generators import benign, scanner
    from dataset.statistics import source_report
    config = offline_config()
    samples = []

    plans = [benign.web_client('e2e/benign', 'e2e-benign', 'e2e/benign:0', requests=12, period=1.0),
             scanner.sequential_scan('e2e/scan', 'e2e-scan', 'e2e/scan:0', port_count=36, period=.5)]
    index = generate_raw(plans, tmp_path / 'raw' / 'lab', dataset_version='e2e-v1', matrix_version='e2e')
    for entry, plan in zip(index['captures'], plans, strict=True):
        parsed, stats = pcap_events(tmp_path / 'raw' / 'lab' / entry['capture'], config)
        assert stats['transmitted_packets'] == 0
        produced, _ = collect(config, parsed, plan_context(plan, 'e2e-v1'), interval=2.0,
                              max_samples_per_source=16)
        samples.extend(produced)
    assert {sample.source_type for sample in samples} == {schema.LAB}

    fixture = ROOT / 'tests' / 'fixtures' / 'p2' / 'scan.pcap'
    entry = {'capture_id': 'e2e-fixture-scan', 'group': 'e2e-capture-scan',
             'label': schema.MALICIOUS, 'label_source': 'trusted_fixture', 'confidence': 'MEDIUM',
             'family': 'fixture-scan', 'kind': 'malicious_automation',
             'origin': 'pre-existing project fixture'}
    pcap_samples, pcap_stats = pcap_collector.ingest(entry, fixture, config, dataset_version='e2e-v1',
                                                     interval=2.0, max_samples_per_source=16,
                                                     max_samples_per_capture=32)
    assert pcap_samples and pcap_stats['transmitted_packets'] == 0
    samples.extend(pcap_samples)

    shadow_samples, shadow_manifest = shadow_collector.generate_pool(
        tmp_path / 'raw' / 'shadow', tmp_path / 'unlabeled', config, dataset_version='e2e-v1',
        seed='e2e', max_samples_per_source=6, overwrite=True)
    assert shadow_manifest['rows'] and shadow_manifest['label'] == schema.UNLABELED
    samples.extend(shadow_samples[:40])

    assignment = split_module.assign(samples, holdout={}, capture_holdout={})
    split_module.apply(samples, assignment)
    assert split_module.assert_no_leakage(samples)
    parts = split_module.partition(samples)
    assert parts['train']
    for rows in parts.values():
        assert all(sample.source_type != schema.SHADOW_UNLABELED for sample in rows)
        assert all(sample.supervised for sample in rows)

    report = validate(samples, leakage_report=True)
    assert report['critical'] == []
    assert report['unlabelled_pool'] == sum(1 for s in samples if not s.supervised)
    assert set(report['sources']) == {schema.LAB, schema.PCAP, schema.SHADOW_UNLABELED}
    assert report['automatic_enforcement_ready'] is False
    sources = source_report(samples)
    assert sources[schema.SHADOW_UNLABELED]['supervised_eligible'] == 0
    assert sources[schema.LAB]['supervised_eligible'] == sources[schema.LAB]['rows']

    files = {'samples': {'file': 'samples.csv', 'rows': len(samples), 'bytes': 0, 'sha256': '0' * 64}}
    manifest = manifest_module.build('e2e-v1', samples, files=files, reproduce='unit test',
                                     scenarios=[], seeds=['e2e'],
                                     sources={name: info['rows'] for name, info in sources.items()})
    assert manifest['record_count'] == len(samples)
    assert manifest['unlabelled_pool'] == report['unlabelled_pool']
    assert manifest['source_type_counts'][schema.SHADOW_UNLABELED] > 0
