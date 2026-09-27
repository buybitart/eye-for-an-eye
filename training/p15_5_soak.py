"""A bounded mixed-behaviour soak, watched while it runs. P15.5 §45.

### What a soak is for here

Not throughput. The decision path has been benchmarked since P2 and its speed is
not in question. What a soak answers is whether anything *accumulates*: memory
that is never returned, descriptors that are never closed, a queue that only
grows, a cache that never evicts, a block that never expires. Those are the
failures that look perfect for an hour and take a machine down on a Sunday, and
no unit test finds them because every unit test starts from nothing.

So this runs the real `DecisionEngine` over a mixed stream of the six behaviours
§45 names — browser, batch API, admin mistakes, monitoring, scanner, credential
automation — and samples the process while it does. Every reported number is a
measurement of *this* process on *this* machine, which is the only honest claim
available: a soak is evidence about a run, not a guarantee about a deployment.

### What it watches, and what each would mean

    rss                 memory that is never returned. Read as the *trend*,
                        not the peak: allocators do not shrink eagerly and a
                        higher final RSS is only a leak if it keeps climbing.
    file_descriptors    the one that ends in EMFILE and takes the listener with
                        it. Should be flat; a socket or a file per decision is
                        the classic version of this bug.
    threads             a worker started per decision and never joined.
    history_entries     the engine's own TTL cache. Bounded by construction, so
                        a count that exceeds its limit is the bound failing.
    decisions           that work is actually happening. A soak of a stalled
                        engine reports beautiful resource numbers.
    assumption_failures whether the P15.4 shape is appearing under load — the
                        arithmetic reaching a block and one assumption refusing
                        every one of them.

### Why the engine is offline

`offline=True` keeps the classifier in-process and refuses to construct a
firewall backend, so a soak cannot write a rule by accident. That is the same
posture `analyze-pcap` runs in, and it is the reason this module is safe to run
on a machine somebody cares about.
"""
from dataclasses import dataclass, field
import json
import os
import resource
import threading
import time
from pathlib import Path

SOAK_SCHEMA_VERSION = 1

ROOT = Path(__file__).resolve().parents[1]

#: §45's list. Each is (generator module, builder, parameters) and the mix is
#: deliberately benign-heavy, because the resources a defender spends are spent
#: mostly on traffic it will not act on.
BEHAVIOURS = (
    ('benign', 'web_client', {'requests': 18, 'period': 1.0}),
    ('benign', 'web_burst', {}),
    ('profiles', 'authenticated_batch', {}),
    ('profiles', 'admin_login_mistakes', {}),
    ('benign', 'monitoring_agent', {}),
    ('benign', 'health_checker', {}),
    ('scanner', 'sequential_scan', {'port_count': 60, 'period': 0.7}),
    ('protocol', 'credential_automation', {}),
)


@dataclass
class Sample:
    at: float
    rss_bytes: int
    file_descriptors: int
    threads: int
    history_entries: int
    decisions: int
    blocks: int


@dataclass
class Soak:
    """The run and its measurements."""

    rounds: int = 20
    samples: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    events: int = 0
    errors: list = field(default_factory=list)


def _descriptors():
    """Open descriptors for this process, or -1 where the kernel will not say."""
    try:
        return len(os.listdir(f'/proc/{os.getpid()}/fd'))
    except OSError:
        return -1


def _rss():
    """Resident set size in bytes. `ru_maxrss` is a high-water mark on Linux and
    in kilobytes, so it is converted and labelled as a peak rather than a
    current reading — a distinction that matters when the question is whether
    memory is *returned*."""
    try:
        with open(f'/proc/{os.getpid()}/statm', encoding='ascii') as handle:
            pages = int(handle.read().split()[1])
        return pages * os.sysconf('SC_PAGE_SIZE')
    except (OSError, IndexError, ValueError):
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024


def _sample(engine, started, decisions, blocks):
    return Sample(at=round(time.monotonic() - started, 3),
                  rss_bytes=_rss(), file_descriptors=_descriptors(),
                  threads=threading.active_count(),
                  history_entries=len(engine.history),
                  decisions=decisions, blocks=blocks)


def run(*, rounds=20, seed='p15.5-soak'):
    """Feed the mixed stream through a real engine, sampling as it goes."""
    from dataset.collectors.pcap import events as pcap_events
    from dataset.generators.packets import render, write_pcap
    from eye_for_an_eye.config import Config
    from eye_for_an_eye.correlation.engine import CorrelationEngine
    from eye_for_an_eye.decision.engine import DecisionEngine
    import tempfile

    config = Config()
    config.decision.enabled = True
    config.enforcement.enabled = False
    # Offline: the classifier stays in-process and no firewall backend is built.
    engine = DecisionEngine(config, CorrelationEngine(config.correlation), offline=True)
    engine.start()

    soak = Soak(rounds=rounds)
    started = time.monotonic()
    decisions = blocks = 0
    soak.samples.append(_sample(engine, started, decisions, blocks))

    with tempfile.TemporaryDirectory(prefix='e4e-p15-5-soak-') as workspace:
        for round_index in range(rounds):
            for module_name, builder, params in BEHAVIOURS:
                module = __import__(f'dataset.generators.{module_name}',
                                    fromlist=[builder])
                plan = getattr(module, builder)(
                    f'soak-{builder}', builder, f'{seed}:{round_index}:{builder}', **params)
                rows, _ = render(plan)
                capture = Path(workspace) / f'{round_index}-{builder}.pcap'
                write_pcap(capture, rows)
                try:
                    parsed, _stats = pcap_events(capture, config)
                except (OSError, ValueError) as exc:
                    soak.errors.append(f'{builder}: {type(exc).__name__}')
                    continue
                for event in parsed:
                    soak.events += 1
                    try:
                        record = engine.observe(event)
                    except Exception as exc:                    # noqa: BLE001
                        soak.errors.append(f'{builder}: {type(exc).__name__}: {exc}'[:120])
                        continue
                    if record is not None:
                        decisions += 1
                        if getattr(record, 'action', '') == 'TEMP_BLOCK':
                            blocks += 1
                capture.unlink(missing_ok=True)
                soak.samples.append(_sample(engine, started, decisions, blocks))

    soak.metrics = dict(engine.metrics)
    try:
        engine.stop()
    except Exception:                                           # noqa: BLE001
        pass
    return soak


def document(soak):
    first, last = soak.samples[0], soak.samples[-1]
    peak = max(sample.rss_bytes for sample in soak.samples)
    descriptors = [s.file_descriptors for s in soak.samples if s.file_descriptors >= 0]
    findings = []
    # A leak is a *trend*, not a difference: an allocator that grew once and
    # settled is not leaking, and reporting it as one teaches an operator to
    # ignore this section.
    half = len(soak.samples) // 2 or 1
    early = sum(s.rss_bytes for s in soak.samples[:half]) / half
    late = sum(s.rss_bytes for s in soak.samples[-half:]) / half
    growth = (late - early) / early if early else 0.0
    if growth > 0.5:
        findings.append(f'resident memory grew {growth:.0%} between the first and '
                        f'second half of the run')
    if descriptors and max(descriptors) - min(descriptors) > 32:
        findings.append(f'open descriptors moved from {min(descriptors)} to '
                        f'{max(descriptors)}')
    if last.threads > first.threads + 4:
        findings.append(f'threads grew from {first.threads} to {last.threads}')
    if soak.errors:
        findings.append(f'{len(soak.errors)} errors during the run')
    if not last.decisions:
        findings.append('no decision was taken; the soak measured a stalled engine')
    # `history_entries` is expected to read zero and it is not evidence of a
    # bounded cache. The generators stamp captures at a fixed historical epoch
    # and `TTLCache` expires against the wall clock, so every entry is already
    # older than its TTL the moment it is written. The cache's bound is tested
    # where it can be tested honestly — in `tests/` against a controlled clock —
    # and this field is reported rather than dropped so that nobody reads a zero
    # here as a measurement of it.
    history_note = ('zero by construction in this harness: captures carry a '
                    'historical epoch and the cache expires against the wall '
                    'clock. Not evidence about the cache bound')
    return {
        'soak_schema_version': SOAK_SCHEMA_VERSION,
        'what_this_is': ('a bounded mixed-behaviour run watched for accumulation. '
                         'Every number is a measurement of one process on one '
                         'machine and is not a guarantee about a deployment'),
        'behaviours': [f'{module}.{builder}' for module, builder, _ in BEHAVIOURS],
        'rounds': soak.rounds,
        'events': soak.events,
        'decisions': last.decisions,
        'blocks': last.blocks,
        'blocks_note': ('the live sensor ladder decides here, not the P15 '
                        'autonomous authority, and it reads a decayed risk '
                        'against a wall clock that these historical captures do '
                        'not advance. The count is reported, not interpreted'),
        'duration_seconds': last.at,
        'rss': {'first_bytes': first.rss_bytes, 'last_bytes': last.rss_bytes,
                'peak_bytes': peak,
                'first_half_mean_bytes': int(early), 'second_half_mean_bytes': int(late),
                'growth_between_halves': round(growth, 4)},
        'file_descriptors': {'first': first.file_descriptors, 'last': last.file_descriptors,
                             'min': min(descriptors) if descriptors else None,
                             'max': max(descriptors) if descriptors else None},
        'threads': {'first': first.threads, 'last': last.threads},
        'history_entries': {'first': first.history_entries, 'last': last.history_entries,
                            'note': history_note},
        'engine_metrics': {key: value for key, value in sorted(soak.metrics.items())
                           if isinstance(value, (int, float))},
        # §10, observed in the live engine rather than in replay: a default
        # configuration enables the anomaly model and has no artifact for it, and
        # the engine counts that as *unavailable* rather than reporting silence.
        # The counter being non-zero here is the rule working.
        'optional_components': {
            'anomaly_model_unavailable_total': soak.metrics.get(
                'anomaly_model_unavailable_total', 0),
            'distribution_load_failures_total': soak.metrics.get(
                'distribution_load_failures_total', 0),
            'model_load_failure_total': soak.metrics.get('model_load_failure_total', 0),
            'review_queue_unavailable_total': soak.metrics.get(
                'review_queue_unavailable_total', 0)},
        'errors': soak.errors[:10],
        'samples': [{'at': s.at, 'rss_bytes': s.rss_bytes, 'fds': s.file_descriptors,
                     'threads': s.threads, 'decisions': s.decisions} for s in soak.samples],
        'findings': findings,
        'verdict': 'PASS' if not findings else 'FAIL',
    }


def write(path, soak=None):
    body = document(soak if soak is not None else run())
    Path(path).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return path


if __name__ == '__main__':
    print(write(ROOT / 'reports' / 'P15_5_SOAK.json'))
