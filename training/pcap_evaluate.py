"""Offline PCAP -> features -> model evaluation using the existing labelled lab corpus.

Captures are read from disk and never retransmitted. Enrichment, active probes, firewall
and enforcement are refused by `analyze_pcap` itself, and decisions stay in shadow mode.
The corpus labels belong to the correlation label space ('scanner', 'noise'), which is not
the model label space, so they are reported beside the decisions and never compared as if
they were the same thing.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
from eye_for_an_eye.calibration import load_corpus
from eye_for_an_eye.config import Config
from eye_for_an_eye.offline import analyze_pcap
from . import schema


def _config(model_dir, version):
    config = Config()
    config.storage.enabled = False
    config.enrichment.enabled = config.enrichment.rdap_enabled = False
    config.active_probes.enabled = False
    config.firewall.enabled = config.enforcement.enabled = False
    config.decision.mode = 'shadow'
    if model_dir is not None:
        config.ml.enabled = True
        config.ml.model_path = str(Path(model_dir) / (version + '.onnx'))
        config.ml.manifest_path = str(Path(model_dir) / (version + '.json'))
    else:
        config.ml.enabled = False
    return config


def evaluate(corpus_path, model_dir, version=schema.MODEL_VERSION):
    result = {'corpus': str(corpus_path), 'model_version': version if model_dir else None,
              'transmitted_packets': 0, 'enforcement': 'refused by offline analysis', 'samples': []}
    config = _config(model_dir, version)
    for sample, capture in load_corpus(corpus_path):
        decisions = defaultdict(list)
        classifications = {}

        def collect(line):
            event = json.loads(line)
            data = event.get('observations') or {}
            if 'decision_version' in data:
                decisions[event['src_ip']].append(data)

        def final(sensor, source, correlation):
            classifications[source, correlation.window_seconds] = correlation.classification

        stats = analyze_pcap(capture, config, writer=collect, on_final=final)
        sources = {}
        for source, records in sorted(decisions.items()):
            strongest = max(records, key=lambda item: item['risk'])
            sources[source] = {
                'decisions': len(records), 'highest_risk': strongest['risk'],
                'action_at_highest_risk': strongest['action'],
                'math_score': strongest['math_score'],
                'model_score': (strongest['ml'] or {}).get('risk_score'),
                'model_status': (strongest['ml'] or {}).get('status'),
                'would_enforce': any(item['would_enforce'] for item in records),
                'policy_reasons': strongest['policy_reasons'],
                'disagreements': sorted({item['disagreement'] for item in records} - {'none'}),
            }
        result['samples'].append({
            'id': sample['id'], 'sha256': sample['sha256'], 'provenance': sample['source'],
            'packets': stats['packets'], 'parse_errors': stats['parse_errors'],
            'expected_correlation_labels': sample['expected_labels'],
            'observed_correlation_labels': {f'{ip}@{window}s': label
                                            for (ip, window), label in sorted(classifications.items())},
            'decisions_by_source': sources})
    result['limitations'] = [
        'the shipped lab corpus is two tiny deterministic synthetic captures, not accuracy evidence',
        'correlation labels are not model labels and are reported side by side, never scored together',
        'no traffic is transmitted and no firewall rule is created or evaluated',
    ]
    return result


def main():
    parser = argparse.ArgumentParser(description='Replay labelled lab PCAPs through features and the model.')
    parser.add_argument('--corpus', required=True, type=Path, help='labelled corpus manifest')
    parser.add_argument('--model-dir', type=Path, help='omit to measure the mathematical baseline alone')
    parser.add_argument('--model-version', default=schema.MODEL_VERSION)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = evaluate(args.corpus, args.model_dir, args.model_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    print(json.dumps({'samples': [{'id': s['id'], 'packets': s['packets'],
                                   'observed_correlation_labels': s['observed_correlation_labels'],
                                   'decisions_by_source': s['decisions_by_source']}
                                  for s in result['samples']]}, indent=2))


if __name__ == '__main__':
    main()
