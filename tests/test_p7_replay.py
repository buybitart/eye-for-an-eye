import json
from pathlib import Path
import struct
import pytest
from eye_for_an_eye.cli import main


def test_simulate_pcap_no_network_or_firewall(tmp_path):
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP, TCP
    fixture = tmp_path / 'synthetic.pcap'
    with fixture.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for i in range(32):
            frame = bytes(IP(src='192.0.2.20', dst='198.51.100.20') / TCP(sport=40000+i, dport=2000+i, flags='S'))
            stream.write(struct.pack('<IIII', 1788825600+i, 0, len(frame), len(frame)) + frame)
    events, report = tmp_path / 'events.jsonl', tmp_path / 'report.json'
    assert main(['simulate', str(fixture), '--output', str(events), '--report', str(report)]) == 0
    rows = [json.loads(line) for line in events.read_text().splitlines()]
    decisions = [r for r in rows if r['event_type'] == 'decision_record']
    assert decisions and all(not r['observations']['enforced'] for r in decisions)
    assert json.loads(report.read_text())['shadow']['total_sources_retained'] == 1


def test_fixed_model_regression_and_promotion_gate():
    pytest.importorskip('sklearn')
    from training.evaluate import regression_gate
    assert not regression_gate({'false_positive_rate': .02}, {'false_positive_rate': .01})['eligible_for_manual_review']
    assert not regression_gate({'false_positive_rate': 0}, {'false_positive_rate': 0})['automatic_promotion']
    assert (Path(__file__).parent / 'fixtures' / 'p7' / 'tiny-v1.onnx').stat().st_size < 2048
    from eye_for_an_eye.config import MLConfig
    from eye_for_an_eye.decision.features import (SCHEMA_VERSION, FeatureTransformer,
                                                  FeatureVector, upgrade)
    from eye_for_an_eye.decision.onnx_model import OnnxRiskModel
    root = Path(__file__).parent / 'fixtures' / 'p7'
    rows = json.loads((root/'regression-v2.json').read_text())
    for name in ('logistic', 'gradient_boosting'):
        model = OnnxRiskModel()
        assert model.load(MLConfig(model_path=str(root/(name+'-research-v1.onnx')),
            manifest_path=str(root/(name+'-research-v1.json'))))['status'] == 'healthy'
        false_positives = 0
        for row in rows:
            # The fixture predates feature schema 2. `upgrade` reads it with the
            # newer columns explicitly unknown, and `project` hands the model
            # back exactly the columns it was fitted on.
            features = {**row['features'], 'values': upgrade(tuple(row['features']['values'])),
                        'schema_version': SCHEMA_VERSION}
            vector = FeatureVector(**features)
            prediction = model.predict(FeatureTransformer.project(
                vector, model.health()['feature_schema_version']))
            assert prediction.status == 'healthy'
            false_positives += row['label'] == 0 and prediction.risk_score >= .5
        assert false_positives == 0
