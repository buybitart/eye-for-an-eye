"""RAW -> NORMALIZED -> FEATURES -> LABELED.

The middle of this pipeline is production code: `CorrelationEngine` does the windowing and
aggregation, and `from_samples` builds the FeatureVector, exactly as `DecisionEngine` does at
runtime. There is no second feature extractor to keep in step with the first.
"""
from collections import Counter
from datetime import datetime, timezone
from eye_for_an_eye.correlation.engine import CorrelationEngine
from eye_for_an_eye.decision.features import from_samples
from . import schema
from .safety import Budget, DiskBudget, SafetyLimits

from .manifest import GENERATOR_VERSION

SNAPSHOT_INTERVAL_SECONDS = 2.0
MIN_SAMPLES_FOR_SNAPSHOT = 2


class FeatureCollector:
    """Events in, DatasetSamples out. One source and one window per row.

    The vector is built the same way `DecisionEngine.observe` builds it, from the same
    correlation state, with one deliberate difference: `previous_risk` is always 0.0, because
    a dataset must not carry this system's own earlier decisions into its own training data.
    """

    def __init__(self, config, *, interval=SNAPSHOT_INTERVAL_SECONDS, max_samples_per_source=64,
                 min_samples=MIN_SAMPLES_FOR_SNAPSHOT, limits=None):
        self.config = config
        self.correlator = CorrelationEngine(config.correlation)
        self.horizon = max(config.correlation.windows)
        self.interval = float(interval)
        self.max_samples_per_source = int(max_samples_per_source)
        self.min_samples = int(min_samples)
        self.budget = Budget(limits or SafetyLimits())
        self.emitted = {}
        self.counts = {}
        self.source_index = {}
        self.skipped = 0

    def observe(self, event, plan_context):
        """Feed one production event and return zero or one DatasetSample."""
        self.correlator.observe(event)
        # A truncated capture cannot tell a request from a response, so the sensor's own
        # addresses can appear as sources. Correlation still sees every event, but only the
        # client this scenario describes may produce labelled rows.
        expected = plan_context.get('expected_source')
        if expected and event.src_ip != expected:
            return None
        if event.src_ip in (plan_context.get('excluded_sources') or ()):
            return None
        key = (event.sensor_id, event.src_ip)
        stamp = event.timestamp.timestamp()
        state = self.correlator.cache.get(key)
        if not state or not any(item.event_id == event.event_id for item in state['samples']):
            return None
        if len(state['samples']) < self.min_samples:
            return None
        if stamp - self.emitted.get(key, float('-inf')) < self.interval:
            return None
        if self.counts.get(key, 0) >= self.max_samples_per_source:
            self.skipped += 1
            return None
        try:
            vector = from_samples(state['samples'], now=stamp, horizon=self.horizon,
                                  previous_risk=0.0, capped=state['capped'], loss_fraction=0.0,
                                  # P15.4, and it must be the same argument
                                  # `DecisionEngine.observe` passes. A corpus
                                  # built without the ledger would carry empty
                                  # authentication columns, so a model fitted on
                                  # it could not use them and an evaluation run
                                  # on it would report that the new evidence
                                  # does nothing — a false negative about the
                                  # system rather than about the traffic.
                                  auth=self.correlator.auth.features(key, now=stamp))
        except ValueError:
            return None
        self.emitted[key] = stamp
        self.counts[key] = self.counts.get(key, 0) + 1
        self.budget.sample()
        index = self.counts[key]
        group = plan_context['group']
        source_group = plan_context.get('source_group')
        if plan_context.get('per_source_groups'):
            # One pseudonymous group per client seen in this capture, numbered by first
            # appearance. The address itself never reaches the row.
            position = self.source_index.setdefault(event.src_ip, len(self.source_index) + 1)
            source_group = f"{plan_context['capture_group']}#src{position:02d}"
            group = plan_context['capture_group']
        return schema.DatasetSample(
            dataset_version=plan_context['dataset_version'],
            feature_schema_version=schema.FEATURE_SCHEMA_VERSION,
            sample_id=f'{source_group or group}#{index:04d}',
            timestamp=datetime.fromtimestamp(stamp, timezone.utc),
            source_type=plan_context['source_type'],
            scenario_group=plan_context.get('scenario_group'),
            source_group=source_group,
            capture_group=plan_context.get('capture_group'),
            # §41. Which site this traffic belongs to, where the scenario says
            # so. Evaluation metadata only: `schema.NEVER_MODEL_INPUT` lists it
            # and `tests/test_p15_4_profiles.py` proves it never reaches a
            # feature vector. P15.3 could not report a single per-profile number
            # because this was `None` on every row of every corpus.
            site_group=plan_context.get('site_group'),
            label=plan_context['label'],
            label_source=plan_context['label_source'],
            label_confidence=plan_context['label_confidence'],
            features=vector,
            provenance=dict(plan_context['provenance'],
                            window_horizon_seconds=self.horizon, snapshot_index=index),
            scenario_id=plan_context.get('scenario_id'))


def collect(config, events, plan_context, **options):
    """Run one source's event stream through the collector."""
    collector = FeatureCollector(config, **options)
    samples = [sample for sample in (collector.observe(event, plan_context) for event in events) if sample]
    return samples, {'events': len(events), 'samples': len(samples), 'skipped_over_cap': collector.skipped,
                     'correlation': collector.correlator.snapshot()}


class BuildBudget:
    """Bounded collection: a build stops cleanly instead of filling the disk."""

    def __init__(self, max_output_bytes=134_217_728, max_samples=200_000):
        self.disk = DiskBudget(max_output_bytes)
        self.max_samples = int(max_samples)
        self.samples = 0

    def accept(self, estimated_bytes):
        if self.samples >= self.max_samples or not self.disk.add(estimated_bytes):
            self.disk.truncated = True
            return False
        self.samples += 1
        return True

    @property
    def truncated(self):
        return self.disk.truncated


# --- pipeline stages ---------------------------------------------------------
# RAW is written once and never edited. NORMALIZED and FEATURES are always rebuilt from it,
# so a change to the transformation produces a new processed version, not a mutated one.
RAW_INDEX_SCHEMA_VERSION = 1


def source_group(plan):
    """Deterministic run identity. Derived from the scenario and run index, never an address."""
    return f"{plan.scenario_id}#{plan.parameters.get('run', 0):02d}"


def behaviour_summary(plan):
    """Environment attributes kept in RAW for leakage analysis. None of them is a feature."""
    times = sorted(contact.time for contact in plan.contacts)
    gaps = [round(later - earlier, 6) for earlier, later in zip(times, times[1:])]
    mean = sum(gaps) / len(gaps) if gaps else None
    variance = sum((gap - mean) ** 2 for gap in gaps) / len(gaps) if gaps and mean is not None else None
    sending = [contact for contact in plan.contacts
               if contact.shape not in ('syn_only', 'syn_reset', 'handshake')]
    return {'ports': sorted({contact.port for contact in plan.contacts}),
            'destinations': sorted({contact.destination for contact in plan.contacts}),
            'request_lengths': sorted({len(contact.request) for contact in sending}),
            'shapes': dict(Counter(contact.shape for contact in plan.contacts)),
            'source_port_range': 'ephemeral',
            'interarrival_mean': mean,
            'interarrival_stdev': variance ** .5 if variance is not None else None,
            'interarrival_min': min(gaps) if gaps else None,
            'interarrival_max': max(gaps) if gaps else None}


def plan_context(plan, dataset_version):
    from . import provenance as provenance_module
    group = source_group(plan)
    ingestion = 'synthetic_event' if plan.ingestion == 'event' else 'synthetic_capture'
    return {'dataset_version': dataset_version, 'scenario_id': plan.scenario_id,
            'scenario_group': plan.scenario_group, 'source_group': group, 'capture_group': None,
            'group': group, 'source_type': schema.LAB, 'expected_source': plan.source,
            'label': plan.label, 'label_source': plan.label_source,
            'label_confidence': plan.label_confidence,
            'provenance': provenance_module.lab(
                scenario_family=plan.scenario_group, scenario_variant=plan.scenario_id,
                run_id=group, seed=plan.seed, generator_version=GENERATOR_VERSION,
                ingestion=ingestion, duration_seconds=round(plan.duration, 3),
                scenario_kind=plan.kind, profile_type=plan.profile_type or None)}


def generate_raw(plans_iterable, raw_dir, *, dataset_version, matrix_version, overwrite=False):
    """Stage RAW: render every plan into an immutable local capture. Nothing is transmitted."""
    import json
    from pathlib import Path
    from .collectors.lab import events as lab_events
    from .generators.packets import render, write_pcap
    from .manifest import file_digest, now
    root = Path(raw_dir)
    index_path = root / 'raw_index.json'
    if index_path.exists() and not overwrite:
        raise FileExistsError('raw data is immutable; write a new raw version instead of editing this one')
    entries, total_packets, total_bytes = [], 0, 0
    for plan in plans_iterable:
        stem = source_group(plan).replace('/', '_').replace('#', '-')
        if plan.ingestion == 'event':
            produced, budget_stats = lab_events(plan)
            capture = root / 'captures' / (stem + '.events.json')
            capture.parent.mkdir(parents=True, exist_ok=True)
            capture.write_text('\n'.join(event.to_json() for event in produced) + '\n', encoding='utf-8')
            rows, budget = produced, budget_stats
        else:
            rows, budget = render(plan)
            capture = root / 'captures' / (stem + '.pcap')
            write_pcap(capture, rows, snaplen=int(plan.parameters.get('snaplen') or 65535))
        total_packets += len(rows)
        total_bytes += capture.stat().st_size
        entries.append({'scenario_id': plan.scenario_id, 'scenario_group': plan.scenario_group,
                        # §41. Carried from the matrix through the raw index so
                        # a per-profile result can be reported. Never a feature.
                        'site_group': plan.site_group, 'profile_type': plan.profile_type,
                        'source_group': source_group(plan), 'seed': plan.seed, 'label': plan.label,
                        'label_source': plan.label_source, 'label_confidence': plan.label_confidence,
                        'kind': plan.kind, 'ingestion': plan.ingestion, 'source_kind': 'controlled_lab',
                        'capture': str(capture.relative_to(root)), 'sha256': file_digest(capture),
                        'packets': len(rows), 'contacts': len(plan.contacts),
                        'duration_seconds': round(plan.duration, 3), 'budget': budget,
                        'parameters': {k: v for k, v in plan.parameters.items() if k != 'budget'},
                        'source': plan.source, **behaviour_summary(plan)})
    index = {'raw_index_schema_version': RAW_INDEX_SCHEMA_VERSION, 'dataset_version': dataset_version,
             'matrix_version': matrix_version, 'created_at': now(), 'runs': len(entries),
             'packets': total_packets, 'capture_bytes': total_bytes,
             'immutability': 'captures and this index are inputs; regenerate under a new path, never edit',
             'safety': 'synthetic captures written to disk; no packet was transmitted and no public '
                       'address appears in any capture',
             'captures': entries}
    root.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(index, indent=2) + '\n', encoding='utf-8')
    return index


def build_features(raw_index, raw_dir, config, *, dataset_version, interval, max_samples_per_source,
                   max_samples_per_scenario, build_budget=None):
    """Stages NORMALIZED and FEATURES: captures -> production parser -> correlation -> vectors."""
    from pathlib import Path
    from eye_for_an_eye.events import NetworkEvent
    from . import provenance as provenance_module
    from .collectors.pcap import events as pcap_events
    from .manifest import file_digest

    def event_trace(path):
        produced = [NetworkEvent.from_json(line) for line in
                    Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]
        produced.sort(key=lambda event: (event.timestamp, event.event_id))
        return produced, {'packets': 0, 'parse_errors': 0, 'events': len(produced), 'transmitted_packets': 0}

    root = Path(raw_dir)
    budget = build_budget or BuildBudget()
    samples, runs, per_scenario = [], [], {}
    for entry in raw_index['captures']:
        capture = root / entry['capture']
        if file_digest(capture) != entry['sha256']:
            raise ValueError(f'raw capture changed since ingestion: {entry["capture"]}')
        if entry['ingestion'] == 'event':
            parsed, stats = event_trace(capture)
        else:
            parsed, stats = pcap_events(capture, config)
        context = {'dataset_version': dataset_version, 'scenario_id': entry['scenario_id'],
                   'scenario_group': entry['scenario_group'], 'source_group': entry['source_group'],
                   'site_group': entry.get('site_group'),
                   'label': entry['label'], 'label_source': entry['label_source'],
                   'label_confidence': entry['label_confidence'],
                   'capture_group': None, 'group': entry['source_group'], 'source_type': schema.LAB,
                   'expected_source': entry.get('source'),
                   'provenance': provenance_module.lab(
                       scenario_family=entry['scenario_group'], scenario_variant=entry['scenario_id'],
                       run_id=entry['source_group'], seed=entry['seed'],
                       generator_version=GENERATOR_VERSION,
                       ingestion='synthetic_event' if entry['ingestion'] == 'event' else 'synthetic_capture',
                       duration_seconds=entry.get('duration_seconds'), scenario_kind=entry['kind'],
                       # §41. The other half of the site metadata. `site_group`
                       # has its own column; the profile travels in provenance,
                       # and without it a per-profile result cannot be grouped
                       # the way the cost policy prices traffic.
                       profile_type=entry.get('profile_type') or None)}
        produced, collected = collect(config, parsed, context, interval=interval,
                                      max_samples_per_source=max_samples_per_source)
        room = max(0, max_samples_per_scenario - per_scenario.get(entry['scenario_id'], 0))
        produced = produced[:room]
        kept = []
        for sample in produced:
            if not budget.accept(1024):
                break
            kept.append(sample)
        per_scenario[entry['scenario_id']] = per_scenario.get(entry['scenario_id'], 0) + len(kept)
        samples.extend(kept)
        runs.append({'source_group': entry['source_group'], 'scenario_id': entry['scenario_id'],
                     'label': entry['label'], 'samples': len(kept),
                     'dropped_over_scenario_cap': len(produced) - len(kept) if room else 0,
                     **{k: stats[k] for k in ('packets', 'parse_errors', 'events', 'transmitted_packets')},
                     'skipped_over_source_cap': collected['skipped_over_cap']})
        if budget.truncated:
            break
    return samples, {'runs': runs, 'truncated': budget.truncated, 'samples': len(samples),
                     'samples_per_scenario': per_scenario}
