"""Offline labeled-corpus contract. Synthetic evaluation is not rule calibration."""
from .event_types import CLASSIFICATIONS
from dataclasses import asdict
import hashlib
import ipaddress
import json
from pathlib import Path
from .config import Config
from .offline import analyze_pcap

LABELS = CLASSIFICATIONS | {'unobserved'}


def evaluate_labels(expected, predicted):
    if len(expected) != len(predicted) or any(value not in LABELS for value in [*expected, *predicted]):
        raise ValueError('invalid evaluation labels')
    labels = sorted(set(expected) | set(predicted))
    matrix = {label: dict.fromkeys(labels, 0) for label in labels}
    for truth, guess in zip(expected, predicted):
        matrix[truth][guess] += 1
    metrics = {}
    def ratio(a, b):
        return a / b if b else None
    for label in labels:
        tp = matrix[label][label]
        fp = sum(matrix[other][label] for other in labels if other != label)
        fn = sum(matrix[label][other] for other in labels if other != label)
        tn = len(expected) - tp - fp - fn
        metrics[label] = {'precision': ratio(tp, tp + fp), 'recall': ratio(tp, tp + fn),
                         'false_positive_rate': ratio(fp, fp + tn), 'false_negative_rate': ratio(fn, fn + tp),
                         'support': tp + fn}
    return {'samples': len(expected), 'confusion_matrix': matrix, 'per_class': metrics,
            'undefined_denominator': None, 'calibrated': False}


def load_corpus(filename):
    path = Path(filename).resolve()
    if path.stat().st_size > 1048576:
        raise ValueError('corpus manifest exceeds 1 MiB')
    data = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(data, dict) or type(data.get('schema_version')) is not int or data['schema_version'] != 1
            or not isinstance(data.get('samples'), list) or not 1 <= len(data['samples']) <= 256):
        raise ValueError('unsupported corpus schema')
    ids = set()
    for sample in data['samples']:
        if not isinstance(sample, dict) or set(sample) != {'id', 'pcap', 'sha256', 'expected_labels', 'metadata', 'source'}:
            raise ValueError('invalid corpus sample')
        if not isinstance(sample['id'], str) or not 1 <= len(sample['id']) <= 128 or sample['id'] in ids:
            raise ValueError('invalid or duplicate sample id')
        ids.add(sample['id'])
        capture = (path.parent / sample['pcap']).resolve()
        if not capture.is_relative_to(path.parent) or not capture.is_file() or capture.stat().st_size > 536870912:
            raise ValueError('corpus capture must be a bounded local file inside corpus directory')
        digest = hashlib.sha256()
        with capture.open('rb') as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
        if digest.hexdigest() != sample['sha256']:
            raise ValueError('corpus input hash mismatch')
        if not isinstance(sample['metadata'], dict) or not isinstance(sample['source'], dict):
            raise ValueError('corpus provenance required')
        labels = sample['expected_labels']
        if not isinstance(labels, list) or not 1 <= len(labels) <= 10000:
            raise ValueError('invalid expected label count')
        keys = set()
        for label in labels:
            if (not isinstance(label, dict) or set(label) != {'src_ip', 'window_seconds', 'label'}
                    or label['label'] not in LABELS - {'distributed_scan_pattern', 'unobserved'}):
                raise ValueError('invalid expected label')
            ipaddress.ip_address(label['src_ip'])
            if type(label['window_seconds']) is not int or not 1 <= label['window_seconds'] <= 3600:
                raise ValueError('invalid expected window')
            key = (label['src_ip'], label['window_seconds'])
            if key in keys:
                raise ValueError('duplicate expected source/window')
            keys.add(key)
        yield sample, capture


def evaluate_corpus(filename, config=None):
    config = config or Config()
    if config.storage.enabled:
        raise ValueError('calibration forbids production storage writes')
    expected, predicted, details = [], [], []
    for sample, capture in load_corpus(filename):
        wanted = {(row['src_ip'], row['window_seconds']): row['label'] for row in sample['expected_labels']}
        if any(window not in config.correlation.windows for _, window in wanted):
            raise ValueError('expected window not configured')
        seen = {}
        def final(sensor, source, result):
            key = (source, result.window_seconds)
            if key in wanted:
                seen[key] = result.classification
        stats = analyze_pcap(capture, config, writer=lambda line: None, on_final=final)
        if stats['packet_limit_reached'] or stats.get('output_dropped'):
            raise ValueError('corpus exceeded analysis budget')
        for key, label in wanted.items():
            expected.append(label)
            predicted.append(seen.get(key, 'unobserved'))
        details.append({'id': sample['id'], 'sha256': sample['sha256'], 'source': sample['source'], 'packets': stats['packets'],
                        'parse_errors': stats['parse_errors']})
    return {**evaluate_labels(expected, predicted), 'inputs': details, 'rule_config': asdict(config.correlation),
            'limitations': ['fixtures_are_not_representative_accuracy_evidence', 'labels_apply_to_final_active_source_windows',
                            'distributed_group_labels_require_a_future_corpus_schema', 'no_automatic_download_or_weight_fitting']}
