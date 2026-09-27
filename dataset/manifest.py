"""Dataset and split manifests: what was produced, from what, and how to reproduce it."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES
from . import schema

GENERATOR_VERSION = 'dataset-generator-1.0'
MANIFEST_SCHEMA_VERSION = 1
READINESS = ('NOT_READY', 'ENGINEERING_ONLY', 'READY_FOR_BASELINE_TRAINING')


def git_commit(root='.'):
    """Best effort. A missing repository is recorded honestly, never faked."""
    try:
        finished = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True, text=True,
                                  timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    value = finished.stdout.strip()
    return value if finished.returncode == 0 and len(value) == 40 else None


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def build(dataset_version, samples, *, files, reproduce, scenarios, seeds, sources, truncated=False,
          stats_file=None, notes=()):
    labels = {name: sum(1 for s in samples if s.label == name) for name in schema.ALL_LABELS}
    confidences = {name: sum(1 for s in samples if s.label_confidence == name) for name in schema.CONFIDENCES}
    label_sources = {}
    for sample in samples:
        label_sources[sample.label_source] = label_sources.get(sample.label_source, 0) + 1
    duration = {}
    for sample in samples:
        duration[sample.label] = duration.get(sample.label, 0.0) + sample.features.observation_seconds
    source_counts = {}
    for sample in samples:
        source_counts[sample.source_type] = source_counts.get(sample.source_type, 0) + 1
    return {
        'manifest_schema_version': MANIFEST_SCHEMA_VERSION,
        'dataset_version': dataset_version,
        'dataset_schema_version': schema.DATASET_SCHEMA_VERSION,
        'feature_schema_version': schema.FEATURE_SCHEMA_VERSION,
        'model_feature_list_version': schema.MODEL_FEATURE_LIST_VERSION,
        'created_at': now(),
        'record_count': len(samples),
        'labels': labels,
        'label_confidence': confidences,
        'label_sources': label_sources,
        'label_meaning': schema.LABEL_MEANING,
        'sources': sources,
        'source_type_counts': source_counts,
        'supervised_eligible': sum(1 for s in samples if s.supervised),
        'unlabelled_pool': sum(1 for s in samples if not s.supervised),
        'scenario_count': len({s.scenario_id for s in samples if s.scenario_id}),
        'scenario_group_count': len({s.scenario_group for s in samples if s.scenario_group}),
        'capture_group_count': len({s.capture_group for s in samples if s.capture_group}),
        'source_group_count': len({s.source_group for s in samples if s.source_group}),
        'group_count': len({(s.source_type, s.group) for s in samples}),
        'observed_seconds_by_label': {k: round(v, 3) for k, v in sorted(duration.items())},
        'feature_names': list(NAMES),
        'tensor_order': list(INPUT_ORDER),
        'model_feature_names': list(schema.MODEL_FEATURES),
        'excluded_from_model': schema.EXCLUDED_FROM_MODEL,
        'transform': 'eye_for_an_eye.decision.features.FeatureTransformer (shared with production)',
        'scenarios': scenarios,
        'seeds': seeds,
        'generator_version': GENERATOR_VERSION,
        'git_commit': git_commit(),
        'python': platform.python_version(),
        'platform': platform.platform(),
        'reproduce': reproduce,
        'files': files,
        'truncated': truncated,
        'statistics_file': stats_file,
        'safety': ['generation is offline: no Internet target, no public address, no exploitation, '
                   'no destructive payload and no captured packet is retransmitted',
                   'every scenario runs against loopback, an isolated lab address or a synthetic '
                   'event timeline, enforced by ipaddress checks, not by config strings'],
        'notes': list(notes),
        'sha256': hashlib.sha256(''.join(sorted(info['sha256'] for info in files.values())).encode()).hexdigest(),
    }


def write(path, manifest):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    return target


def read(path):
    manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(manifest, dict) or manifest.get('manifest_schema_version') != MANIFEST_SCHEMA_VERSION:
        raise ValueError('unsupported manifest schema')
    return manifest


def verify_files(manifest, directory):
    """Every listed file must still hash to what the manifest recorded."""
    root = Path(directory)
    problems = []
    for name, info in manifest['files'].items():
        path = root / info['file']
        if not path.is_file():
            problems.append(f'{name}: missing {info["file"]}')
        elif file_digest(path) != info['sha256']:
            problems.append(f'{name}: sha256 mismatch for {info["file"]}')
    return problems


def split_manifest(dataset_version, parts, *, policy, holdout, files, seed=None):
    """Proves which rows were evaluated: a hash per split file, frozen with the dataset."""
    return {
        'manifest_schema_version': MANIFEST_SCHEMA_VERSION,
        'dataset_version': dataset_version,
        'created_at': now(),
        'split_policy': policy,
        'holdout': holdout,
        'seed': seed,
        'splits': {name: {'samples': len(rows),
                          'sources': {source: sum(1 for s in rows if s.source_type == source)
                                      for source in sorted({s.source_type for s in rows})},
                          'families': sorted({s.scenario_group or s.capture_group or s.source_type
                                              for s in rows}),
                          'group_count': len({(s.source_type, s.group) for s in rows}),
                          'labels': {label: sum(1 for s in rows if s.label == label)
                                     for label in schema.SUPERVISED_LABELS}}
                   for name, rows in parts.items()},
        'files': files,
        'immutability': ('once this split manifest is committed the test hash is frozen; tuning against '
                         'this test set requires a new dataset version, not an edit'),
        'sha256': hashlib.sha256(''.join(sorted(info['sha256'] for info in files.values())).encode()).hexdigest(),
    }
