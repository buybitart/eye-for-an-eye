"""SOURCE B: offline PCAP ingestion through the production packet parser.

A capture is read from disk and never retransmitted. Enrichment, active probes, firewall
and enforcement are refused by `analyze_pcap` itself, so the ingestion path is deterministic
and offline by construction.
"""
from dataclasses import dataclass
import json
from pathlib import Path
from eye_for_an_eye.config import Config
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.offline import analyze_pcap
from .. import schema
from ..manifest import file_digest, now

CORRELATION_INPUT = (EventType.CONNECTION_ACCEPTED, EventType.SERVICE_PROBE, EventType.PACKET_OBSERVED,
                     EventType.DECEPTION_CONNECTION, EventType.PROTOCOL_COMMAND)
SIDECAR_SCHEMA_VERSION = 1


def offline_config(base=None):
    """Deterministic offline analysis: no enrichment, no probes, no firewall, no storage."""
    config = base or Config()
    config.storage.enabled = False
    config.enrichment.enabled = config.enrichment.rdap_enabled = False
    config.active_probes.enabled = False
    config.firewall.enabled = config.enforcement.enabled = False
    config.ml.enabled = False
    config.decision.enabled = False
    return config


@dataclass(frozen=True, slots=True)
class Sidecar:
    """Explicit metadata beside a capture. A file name never decides a label."""
    capture: str
    sha256: str
    scenario_id: str
    scenario_group: str
    label: str
    label_source: str
    label_confidence: str
    notes: str = ''
    source_kind: str = 'controlled_lab'
    external_capture: bool = False

    def __post_init__(self):
        if self.label not in schema.ALL_LABELS or self.label_source not in schema.LABEL_SOURCES:
            raise ValueError('sidecar label or label source is not accepted')
        if self.label_source in schema.FORBIDDEN_LABEL_SOURCES:
            raise ValueError('a decision made by this system is not ground truth')
        if self.label_confidence not in schema.CONFIDENCES:
            raise ValueError('sidecar label confidence is not accepted')
        if self.source_kind not in schema.SOURCE_KINDS:
            raise ValueError('unknown source kind')


def load_sidecars(path):
    """Read a sidecar manifest and verify every capture hash before anything is ingested."""
    manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    if manifest.get('sidecar_schema_version') != SIDECAR_SCHEMA_VERSION:
        raise ValueError('unsupported sidecar schema')
    root = Path(path).parent
    entries = []
    for item in manifest['captures']:
        sidecar = Sidecar(**item)
        capture = (root / sidecar.capture).resolve()
        if not capture.is_relative_to(root.resolve()) or not capture.is_file():
            raise ValueError('capture must be a local file beside its sidecar')
        if file_digest(capture) != sidecar.sha256:
            raise ValueError(f'capture hash mismatch for {sidecar.capture}')
        entries.append((sidecar, capture))
    return entries


def events(capture, config=None, *, max_packets=100000):
    """PCAP -> production parser -> NetworkEvents that the correlation engine accepts."""
    collected = []

    def writer(line):
        record = json.loads(line)
        if record['event_type'] in CORRELATION_INPUT:
            collected.append(NetworkEvent.from_json(line))

    stats = analyze_pcap(str(capture), offline_config(config), writer=writer, max_packets=max_packets)
    if stats['packet_limit_reached'] or stats.get('output_dropped'):
        raise ValueError('capture exceeded the ingestion budget; split the fixture instead')
    collected.sort(key=lambda event: (event.timestamp, event.event_id))
    return collected, {'packets': stats['packets'], 'parse_errors': stats['parse_errors'],
                       'events': len(collected), 'transmitted_packets': 0}


def build_corpus(root, *, overwrite=False):
    """Write the generated captures and the sidecar manifest that labels them."""
    import json as _json
    from ..scenarios.captures import EXISTING_FIXTURES, build as build_captures
    target = Path(root)
    target.mkdir(parents=True, exist_ok=True)
    generated = build_captures(target, overwrite=overwrite)
    entries = list(generated['generated'])
    repository = Path(__file__).resolve().parents[2]
    for fixture in EXISTING_FIXTURES:
        path = (repository / fixture['path']).resolve()
        if not path.is_file():
            continue
        entries.append({**{k: v for k, v in fixture.items() if k != 'path'},
                        'capture': fixture['path'], 'external_path': True,
                        'sha256': file_digest(path), 'packets': None, 'flows': None,
                        'bytes': path.stat().st_size, 'ipv6': False, 'snaplen': 65535})
    manifest = {'sidecar_schema_version': SIDECAR_SCHEMA_VERSION,
                'capture_corpus_version': generated['capture_corpus_version'],
                'created_at': now(), 'captures': entries,
                'transmitted_packets': 0,
                'labelling': 'every label comes from this sidecar; a file name never decides a label',
                'privacy': 'synthetic, project-owned captures only; no production capture is committed'}
    (target / 'captures.json').write_text(_json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def load_corpus(path):
    """Read the capture sidecar manifest and verify every capture hash before ingestion."""
    manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    if manifest.get('sidecar_schema_version') != SIDECAR_SCHEMA_VERSION:
        raise ValueError('unsupported sidecar schema')
    root = Path(path).parent
    repository = Path(__file__).resolve().parents[2]
    entries = []
    for entry in manifest['captures']:
        capture = ((repository / entry['capture']) if entry.get('external_path')
                   else (root / entry['capture'])).resolve()
        if not capture.is_file():
            raise ValueError(f'missing capture {entry["capture"]}')
        if file_digest(capture) != entry['sha256']:
            raise ValueError(f'capture hash mismatch for {entry["capture"]}')
        if entry['label'] not in schema.ALL_LABELS:
            raise ValueError('capture sidecar label is not accepted')
        if entry['label'] in schema.SUPERVISED_LABELS and entry['label_source'] not in schema.LABEL_SOURCES:
            raise ValueError('a labelled capture needs an accepted label source')
        if entry['label_confidence' if 'label_confidence' in entry else 'confidence'] not in schema.CONFIDENCES:
            raise ValueError('capture sidecar confidence is not accepted')
        entries.append((entry, capture))
    return manifest, entries


def ingest(entry, capture, config, *, dataset_version, interval, max_samples_per_source,
           max_samples_per_capture):
    """One capture -> DatasetSamples. Every window from a capture shares its capture_group."""
    from ..builder import collect
    from .. import provenance as provenance_module
    parsed, stats = events(capture, config)
    # A SYN points at a server. Everything a SYN was aimed at is a destination, and a
    # destination is never a client - which matters because a truncated capture cannot mark
    # response packets and would otherwise turn the sensor's own addresses into sources.
    destinations = {event.dst_ip for event in parsed
                    if event.dst_ip and event.observations.get('syn_observed')}
    context = {
        'dataset_version': dataset_version, 'source_type': schema.PCAP,
        'scenario_id': entry.get('family'), 'scenario_group': None,
        'capture_group': entry['group'], 'group': entry['group'], 'per_source_groups': True,
        'excluded_sources': destinations,
        'label': entry['label'],
        'label_source': entry.get('label_source') or 'unlabelled_capture',
        'label_confidence': entry.get('confidence', entry.get('label_confidence')),
        'provenance': provenance_module.pcap(
            capture_id=entry['capture_id'], capture_origin=entry['origin'],
            scenario_family=entry.get('family'), scenario_kind=entry.get('kind'),
            label_authority=('explicit capture sidecar' if entry['label'] in schema.SUPERVISED_LABELS
                             else 'none: capture kept unlabelled')),
    }
    produced, collected = collect(config, parsed, context, interval=interval,
                                  max_samples_per_source=max_samples_per_source)
    return produced[:max_samples_per_capture], {**stats, 'capture_id': entry['capture_id'],
                                                'capture_group': entry['group'],
                                                'samples': len(produced[:max_samples_per_capture]),
                                                'clients': collected['correlation'].get('sources', 0)}
