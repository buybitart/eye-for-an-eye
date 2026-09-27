"""SOURCE C: sanitised Shadow Mode export into the unlabelled pool.

Three rules hold here without exception.

* A decision this system made is never a label. Shadow rows enter the unlabelled pool and
  stay out of every supervised split until a person reviews them.
* The math score, the model score and the action are kept for analysis only, in metadata.
  They are not features and the model feature contract refuses them by name.
* No payload, header, credential, cookie, token or command text is exported. Only the
  numeric FeatureVector and bounded metadata leave the sensor.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from eye_for_an_eye.decision.features import NAMES, FeatureVector
from .. import schema

# Default deny. Only these bounded numbers, flags and short enumerations survive an export;
# anything else - including a keyed payload digest - is dropped rather than filtered.
SAFE_OBSERVATION_KEYS = frozenset((
    'payload_length', 'request_length', 'response_length', 'duration', 'tcp_flags',
    'syn_observed', 'completed_handshake', 'response_continuation', 'retry_observed',
    'credential_like_attempt', 'protocol_anomaly', 'inspection_limited', 'malformed',
    'capture_truncated', 'protocol_family', 'service_family', 'command_class', 'load_mode'))
SAFE_ENUM_KEYS = frozenset(('protocol_family', 'service_family', 'command_class', 'load_mode'))
CONTENT_MARKERS = ('payload', 'request', 'response', 'body', 'password', 'passwd', 'credential',
                   'cookie', 'token', 'authorization', 'auth', 'command', 'user', 'query',
                   'header', 'digest', 'probe', 'text', 'banner', 'host')
ANALYSIS_ONLY_KEYS = ('math_score', 'model_score', 'ml_score', 'risk', 'action', 'would_enforce',
                      'disagreement', 'confidence')
MAX_INPUT_BYTES = 268_435_456
MAX_LINE_CHARS = 8192


def load_secret(path=None):
    """Keyed pseudonymisation. The secret stays local and is never committed.

    Without a secret one is generated for this run only, which still groups a source within
    the export while making the mapping unrecoverable afterwards.
    """
    if path:
        target = Path(path)
        data = target.read_bytes().strip()
        if len(data) < 32:
            raise ValueError('dataset pseudonymisation secret must be at least 32 bytes')
        return data
    env = os.environ.get('E4E_DATASET_SECRET')
    if env:
        if len(env.encode()) < 32:
            raise ValueError('E4E_DATASET_SECRET must be at least 32 bytes')
        return env.encode()
    return secrets.token_bytes(32)


def source_group(secret, sensor_id, source):
    """HMAC, truncated. Enough to see the same source twice, not enough to recover it."""
    digest = hmac.new(secret, f'{sensor_id}|{source}'.encode(), hashlib.sha256).hexdigest()
    return 'shadow-' + digest[:16]


def sanitize(observations):
    """Default deny: an observation is kept only if it is on the allowlist and bounded."""
    clean = {}
    for key, value in (observations or {}).items():
        if key not in SAFE_OBSERVATION_KEYS or key in ANALYSIS_ONLY_KEYS:
            continue
        if isinstance(value, bool):
            clean[key] = value
        elif isinstance(value, (int, float)) and -1e12 < value < 1e12:
            clean[key] = value
        elif key in SAFE_ENUM_KEYS and isinstance(value, str) and len(value) <= 32 and value.isascii():
            clean[key] = value
    return clean


def dropped_fields(observations):
    """What an export refused to carry, so a reviewer can see the redaction actually happened."""
    return sorted(key for key in (observations or {}) if key not in SAFE_OBSERVATION_KEYS)


def analysis_of(config, vector, source):
    """Run the production mathematical baseline, fusion and policy for analysis only.

    These numbers are kept beside the row so a reviewer can see what the system thought. They
    are never a label and never a feature; `dataset.schema.NEVER_MODEL_INPUT` names each one.
    """
    from eye_for_an_eye.decision.math_risk import MathRiskEngine
    from eye_for_an_eye.decision.onnx_model import MLResult
    from eye_for_an_eye.decision.policy import DecisionFusion, PolicyGuard
    from eye_for_an_eye.decision.features import NAMES as FEATURE_NAMES
    math_result = MathRiskEngine().evaluate(vector)
    ml = MLResult()
    values = dict(zip(FEATURE_NAMES, vector.values, strict=True))
    persistence = min(1, (values['persistence_900s'] or 0) / 300)
    fusion = DecisionFusion(config.decision)
    risk = fusion.combine(math_result, ml, persistence)
    proposed = fusion.state(risk)
    action, reasons, quality = PolicyGuard(config).apply(proposed, vector, math_result, ml, source=source)
    return {'math_score': round(math_result.score, 6), 'model_score': None,
            'final_score': round(risk, 6), 'action': action,
            'would_block': action == 'TEMP_BLOCK',
            'policy_reasons': reasons[:6],
            'data_quality': round(quality.score, 4) if quality else None,
            'math_version': math_result.model_version}


def pseudonym(source, *, secret=None, salt=None):
    """Group one source across time without keeping its address.

    A real export needs a local secret. The synthetic pool has no real address in it, so a
    fixed salt is used instead and that is stated in the manifest rather than hidden.
    """
    if secret is not None:
        return 'shadow-' + hmac.new(secret, source.encode(), hashlib.sha256).hexdigest()[:16]
    return 'shadow-' + hashlib.sha256(f'{salt}|{source}'.encode()).hexdigest()[:16]


class Collector:
    """Bounded shadow collection. Nothing here grows without a limit stopping it."""

    def __init__(self, *, max_samples=5000, max_output_bytes=33_554_432, flush_every=250,
                 retention_days=30):
        if not 1 <= max_samples <= 1_000_000 or not 4096 <= max_output_bytes <= 1_073_741_824:
            raise ValueError('invalid shadow collection bounds')
        self.max_samples = max_samples
        self.max_output_bytes = max_output_bytes
        self.flush_every = flush_every
        self.retention_days = retention_days
        self.samples = []
        self.bytes = 0
        self.dropped = 0
        self.truncated = False

    def add(self, sample, estimated_bytes=1024):
        if len(self.samples) >= self.max_samples or self.bytes + estimated_bytes > self.max_output_bytes:
            self.truncated = True
            self.dropped += 1
            return False
        self.samples.append(sample)
        self.bytes += estimated_bytes
        return True

    def snapshot(self):
        return {'samples': len(self.samples), 'bytes': self.bytes, 'dropped': self.dropped,
                'truncated': self.truncated, 'max_samples': self.max_samples,
                'max_output_bytes': self.max_output_bytes, 'flush_every': self.flush_every,
                'raw_retention_days': self.retention_days,
                'retention_note': 'raw telemetry is discarded on this schedule; the sanitised '
                                  'FeatureVector pool may be kept longer because it carries no content'}


def observe(config, events, *, dataset_version, sensor_placement, collector=None, salt=None,
            secret=None, interval=2.0, max_samples_per_source=40, collected_at=None):
    """Events observed by a sensor -> unlabelled, sanitised shadow samples."""
    from datetime import datetime, timezone
    from ..builder import FeatureCollector
    from .. import provenance as provenance_module
    collector = collector or Collector()
    feature_collector = FeatureCollector(config, interval=interval,
                                         max_samples_per_source=max_samples_per_source)
    stamp = collected_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        '+00:00', 'Z')
    servers = {event.dst_ip for event in events if event.dst_ip and event.observations.get('syn_observed')}
    produced = []
    for event in events:
        if event.src_ip in servers:
            continue
        group = pseudonym(f'{event.sensor_id}|{event.src_ip}', secret=secret, salt=salt)
        context = {
            'dataset_version': dataset_version, 'source_type': schema.SHADOW_UNLABELED,
            'scenario_id': None, 'scenario_group': None, 'capture_group': None,
            'source_group': group, 'group': group,
            'label': schema.UNLABELED, 'label_source': 'shadow_observation', 'label_confidence': 'LOW',
            'provenance': provenance_module.shadow(sensor_placement=sensor_placement,
                                                   collected_at=stamp),
        }
        sample = feature_collector.observe(event, context)
        if sample is None:
            continue
        sample.provenance = dict(
            sample.provenance,
            analysis_only=analysis_of(config, sample.features, event.src_ip),
            sensor_observations=sanitize(event.observations))
        if not collector.add(sample):
            break
        produced.append(sample)
    return produced, collector


def write_pool(directory, samples, collector, *, dataset_version, sensor_placement, pseudonymisation):
    """Write the unlabelled pool and its manifest. Never mixed with a supervised split."""
    from ..store import write
    root = Path(directory)
    info = write(root / 'shadow_unlabeled.csv', samples)
    manifest = {
        'pool': 'unlabeled', 'dataset_version': dataset_version,
        'source_type': schema.SHADOW_UNLABELED, 'rows': len(samples),
        'label': schema.UNLABELED, 'label_source': 'shadow_observation',
        'sensor_placement': sensor_placement,
        'groups': len({sample.source_group for sample in samples}),
        'collection': collector.snapshot(),
        'pseudonymisation': pseudonymisation,
        'redaction': {'policy': 'default deny', 'allowlist': sorted(SAFE_OBSERVATION_KEYS),
                      'never_exported': ['payload', 'headers', 'credentials', 'cookies', 'tokens',
                                         'authorization', 'command text', 'keyed payload digests',
                                         'source address']},
        'analysis_fields_kept_out_of_features': list(ANALYSIS_ONLY_KEYS),
        'usage': ('no ground truth: excluded from every supervised split. Available for manual '
                  'review, out-of-distribution analysis and distribution comparison only.'),
        'file': info,
    }
    (root / 'shadow_unlabeled_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n',
                                                         encoding='utf-8')
    return manifest


def export(events_path, output_dir, *, secret_path=None, max_samples=20000,
           dataset_version='shadow-unlabeled-v1', sensor_placement='unspecified'):
    """Import a sanitised shadow feature export produced by a running sensor.

    Bounded, offline, default-deny. This is the path a real deployment uses; the synthetic pool
    in `dataset-v1` is produced by `generate_pool` instead and is labelled as such.
    """
    from datetime import datetime, timezone
    from .. import provenance as provenance_module
    source = Path(events_path)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError('shadow export exceeds the ingestion budget')
    secret = load_secret(secret_path)
    collector = Collector(max_samples=max_samples)
    samples, skipped, redacted = [], 0, set()
    with source.open(encoding='utf-8') as stream:
        for line in stream:
            if len(line) > MAX_LINE_CHARS:
                raise ValueError('shadow export line exceeds the frame budget')
            record = json.loads(line)
            features = record.get('features')
            if not isinstance(features, dict) or 'values' not in features:
                skipped += 1
                continue
            values = features['values']
            if not isinstance(values, list) or len(values) != len(NAMES):
                raise ValueError('shadow export feature count does not match the schema')
            vector = FeatureVector(tuple(values), float(features.get('observation_seconds', 0.0)),
                                   int(features.get('sample_count', 0)),
                                   bool(features.get('capped', False)), features.get('loss_fraction'))
            observations = record.get('observations') or {}
            redacted |= set(dropped_fields(observations))
            group = pseudonym(f"{record.get('sensor_id', 'local')}|{record.get('src_ip', 'unknown')}",
                              secret=secret)
            stamp = record.get('timestamp')
            moment = (datetime.fromisoformat(stamp.replace('Z', '+00:00')) if isinstance(stamp, str)
                      else datetime.now(timezone.utc))
            analysis = {key: (record.get('analysis') or {}).get(key) for key in ANALYSIS_ONLY_KEYS
                        if (record.get('analysis') or {}).get(key) is not None}
            sample = schema.DatasetSample(
                dataset_version=dataset_version, feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
                sample_id=f'{group}#{len(samples):06d}', timestamp=moment,
                source_type=schema.SHADOW_UNLABELED, scenario_group=None, source_group=group,
                capture_group=None, label=schema.UNLABELED, label_source='shadow_observation',
                label_confidence='LOW', features=vector,
                provenance=provenance_module.shadow(
                    sensor_placement=sensor_placement,
                    collected_at=moment.isoformat().replace('+00:00', 'Z'),
                    analysis_only=analysis or None, sensor_observations=sanitize(observations)))
            if not collector.add(sample):
                break
            samples.append(sample)
    manifest = write_pool(output_dir, samples, collector, dataset_version=dataset_version,
                          sensor_placement=sensor_placement,
                          pseudonymisation='HMAC-SHA256 over sensor and source under a local secret; '
                                           'the secret is never written here and never committed')
    manifest['skipped_records'] = skipped
    manifest['redacted_input_fields'] = sorted(redacted)
    (Path(output_dir) / 'shadow_unlabeled_manifest.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


SHADOW_WORKLOAD_VERSION = '1.0'
SHADOW_PLACEMENT = ('synthetic stand-in for a sensor placed in front of a small service estate; '
                    'no real deployment has produced telemetry for this project yet')


def _observation_flows(seed):
    """A mixed workload with no declared intent. Deliberately not the labelled corpus.

    Real shadow telemetry is whatever arrives. This stands in for that: a blend of ordinary
    clients, operational tooling and probing, at ranges the labelled generator does not always
    reach, so the distribution comparison has something to say.
    """
    from ..generators.base import REQUESTS, rng
    from ..generators.capture import Flow, sources, stack, targets
    stream = rng(f'{seed}:shadow-workload')
    clients = sources(stream, 14, '203.0.113')
    destinations = targets(stream, 4)
    bodies = ('http_get', 'http_head', 'http_status', 'http_api', 'ssh_banner', 'ftp_feat',
              'redis_probe', 'binary_probe', 'generic_probe', 'http_broken')
    shapes = ('session', 'exchange', 'request', 'syn_only', 'syn_reset', 'handshake',
              'retry_then_request')
    flows, moment = [], 0.0
    for index in range(320):
        client = clients[index % len(clients)]
        signature = stack(rng(f'{seed}:{client}'))
        # A wider port and rate range than the labelled generator uses on purpose.
        port = stream.choice((21, 22, 25, 80, 443, 445, 587, 993, 3306, 5432, 6379, 8080, 8443,
                              9090, 9200, 11211, stream.randrange(1024, 65535)))
        flows.append(Flow(moment, client, stream.choice(destinations), port,
                          stream.choice(shapes), REQUESTS[stream.choice(bodies)],
                          retransmit=stream.random() < .12, reorder=stream.random() < .08,
                          segments=stream.choice((1, 2, 3)), **signature))
        moment += max(.01, stream.expovariate(2.2))
    return flows


def generate_pool(raw_dir, output_dir, config, *, dataset_version, seed='dataset-v1',
                  interval=2.0, max_samples_per_source=30, collector=None, overwrite=False):
    """Produce the synthetic shadow pool: a capture, observed by the sensor, sanitised, unlabelled."""
    from ..generators.capture import write as write_capture
    from ..manifest import file_digest, now
    from .pcap import events as pcap_events
    root = Path(raw_dir)
    capture = root / 'shadow-observation.pcap'
    if capture.exists() and not overwrite:
        raise FileExistsError('raw shadow telemetry is immutable; write a new version instead')
    rows, budget = write_capture(capture, _observation_flows(seed), seed=f'{seed}:shadow')
    parsed, stats = pcap_events(capture, config)
    samples, collector = observe(config, parsed, dataset_version=dataset_version,
                                 sensor_placement=SHADOW_PLACEMENT,
                                 collector=collector, salt=f'{seed}-shadow-fixture',
                                 interval=interval, max_samples_per_source=max_samples_per_source,
                                 collected_at=now())
    manifest = write_pool(output_dir, samples, collector, dataset_version=dataset_version,
                          sensor_placement=SHADOW_PLACEMENT,
                          pseudonymisation=('fixed salt, because this pool contains no real address; '
                                            'a real export uses HMAC under a local secret that is '
                                            'never committed'))
    manifest.update(workload_version=SHADOW_WORKLOAD_VERSION, capture=capture.name,
                    capture_sha256=file_digest(capture), packets=len(rows), budget=budget,
                    packets_parsed=stats['packets'], transmitted_packets=0,
                    synthetic=True,
                    honesty=('this pool is a synthetic stand-in. It exercises the shadow path and '
                             'gives a distribution to compare against; it is not evidence about '
                             'real traffic.'))
    (Path(output_dir) / 'shadow_unlabeled_manifest.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return samples, manifest
