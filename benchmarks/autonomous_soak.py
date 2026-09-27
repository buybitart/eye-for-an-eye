"""The integrated service, running for a long time, watched in thirds. P15.5R §27-§30.

`benchmarks/soak.py` is P5's: intake, correlation, storage, API and metrics, for
15 to 59 minutes, with no autonomous decision path because there was none. This
one runs the same service *with* the P15 stack attached -- the authority, the
calibrator, the decision journal and the shadow export -- because the question
§27 asks is not whether any of those work for a minute. It is whether the
assembled thing is still the same shape after half an hour.

### Why thirds, and not before-and-after

A pair of endpoint measurements cannot tell a steady state from a slow slide:
both are consistent with the same two numbers. Splitting the run into three
equal parts and comparing them makes the shape visible -- a leak, a queue that
fills, a rotation that stops happening, a decision rate that decays as state
accumulates -- and it costs nothing but arithmetic over samples that are being
taken anyway.

Every per-third figure is computed from the per-second samples, so the raw
series stays in the result and a reader can disagree with the summary.

### §28

Ninety seconds is not a soak. This module accepts shorter runs because a
5-minute smoke run is useful while developing one, and it labels them: the
result carries `soak_class`, and anything under `SOAK_SECONDS` is `SHORT` and
says so in its own limitations. Nothing here calls a short run long.

### What it deliberately does not do

No enforcement. The run is shadow mode throughout, so the block path is decided
and recorded and nothing is handed to a firewall -- §30's rule, and the only
honest way to run something for half an hour on a shared machine.

No accuracy claim. The workload is a fixed synthetic stream; the decisions it
produces are evidence about wiring and resource behaviour and about nothing
else.
"""
import argparse
from datetime import datetime, timezone
import gc
import http.client
import json
from pathlib import Path
import socket
import tempfile
import time

from benchmarks.bench_api import free_port
from benchmarks.common import (configuration, environment, guarded, percentiles,
                               resources)
from benchmarks.workloads import event
from eye_for_an_eye.config import Config
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime

REPOSITORY = Path(__file__).resolve().parents[1]
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'

#: Below this, the run is a smoke test of the soak and is labelled as one.
#: Thirty minutes is the shortest duration this project is willing to call a
#: soak, and it is still not evidence about a day.
SOAK_SECONDS = 1800

#: Offered events per second. The same working point `docs/CAPACITY.md` names,
#: so this run is comparable with the P5 soak rather than being a new scale.
EVENTS_PER_SECOND = 60

#: Distinct sources in the stream. Bounded on purpose: an unbounded source
#: count would make correlation state growth the dominant effect and hide
#: everything else.
SOURCES = 16


def settings_for(directory):
    """The integrated service, with the P15 stack attached and nothing enforcing."""
    config = Config()
    config.storage.enabled = config.api.enabled = config.metrics.enabled = True
    config.storage.path = str(directory / 'soak.db')
    config.storage.max_batch_events = 8
    config.storage.max_events = 2000
    config.storage.max_bytes = 16_777_216
    config.runtime.load_shedding = True
    config.runtime.queue_events = 256
    config.runtime.status_file = str(directory / 'status.json')
    config.correlation.max_sources = 64
    config.correlation.max_events_per_source = 64
    config.api.port, config.metrics.port = free_port(), free_port()
    config.logging.file = ''
    config.decision.enabled = True
    config.decision.mode = 'enforce'
    # Shadow throughout. §30: nothing in a half-hour unattended run goes near a
    # firewall, and `enforcement` stays off so there is nothing to go near.
    config.enforcement.enabled = False
    config.enforcement.host_enabled = False
    config.autonomy.enabled = True
    config.autonomy.mode = 'shadow'
    config.autonomy.calibrator_path = str(CALIBRATOR)
    config.autonomy.decision_journal_path = str(directory / 'decisions.jsonl')
    config.autonomy.shadow_export_path = str(directory / 'shadow-export.jsonl')
    return config.validate()


def _pipeline_sample(runtime):
    """What the decision path costs and holds, right now. Counters only."""
    autonomy = runtime.analysis.decisions.autonomy
    if autonomy is None:
        return {}
    journal = autonomy.journal
    export = autonomy.shadow_export
    return {
        'autonomy': dict(autonomy.counters),
        'journal': ({'bytes': journal.writer.total_bytes,
                     'files': len(journal.writer.existing()),
                     'counters': dict(journal.counters),
                     'cooling': journal.writer.cooling}
                    if journal is not None else None),
        'export': ({'bytes': export.writer.total_bytes,
                    'files': len(export.writer.existing()),
                    'counters': dict(export.counters),
                    'cooling': export.writer.cooling}
                   if export is not None else None),
    }


def _thirds(samples, keys):
    """One row per third, from the per-second samples.

    `keys` are dotted paths into a sample. Counters are reported as the
    *increase* across the third, gauges as first/last/max, because a counter's
    absolute value at the end of a third says nothing about that third.
    """
    size = len(samples) // 3
    if size < 1:
        return []
    parts = [samples[0:size], samples[size:2 * size], samples[2 * size:3 * size]]
    rows = []
    for name, part in zip(('first', 'middle', 'last'), parts):
        row = {'third': name, 'seconds': len(part),
               'from_second': part[0]['second'], 'to_second': part[-1]['second']}
        for key in keys:
            first, last = _dig(part[0], key), _dig(part[-1], key)
            values = [v for v in (_dig(sample, key) for sample in part)
                      if isinstance(v, (int, float))]
            row[key] = {
                'first': first, 'last': last,
                'delta': (last - first) if isinstance(first, (int, float))
                         and isinstance(last, (int, float)) else None,
                'max': max(values) if values else None,
                'mean': (sum(values) / len(values)) if values else None,
            }
        rows.append(row)
    return rows


def _dig(sample, dotted):
    value = sample
    for part in dotted.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


#: What a reader of a soak actually wants compared between thirds: is the
#: decision rate steady, is memory flat, is the queue empty, is the journal
#: rotating rather than growing, and is anything being dropped.
TRACKED = ('rss_bytes', 'queue.depth', 'queue.dropped', 'sources',
           'pipeline.autonomy.decisions', 'pipeline.autonomy.blocks',
           'pipeline.autonomy.journalled', 'pipeline.autonomy.journal_failures',
           'pipeline.autonomy.exported', 'pipeline.autonomy.export_failures',
           'pipeline.journal.bytes', 'pipeline.journal.counters.rotated',
           'pipeline.export.bytes', 'pipeline.export.counters.rotated')


def _drift(thirds):
    """The comparison stated rather than left to the reader, where it is safe to.

    Only ratios that a steady state makes meaningful are reported. A per-third
    delta of zero in the first third and zero in the last is not a 1.0 ratio; it
    is two zeroes, and saying `null` is the honest answer.
    """
    if len(thirds) != 3:
        return {}
    first, last = thirds[0], thirds[-1]
    out = {}
    for key in ('pipeline.autonomy.decisions', 'pipeline.autonomy.journalled',
                'pipeline.autonomy.exported'):
        start, end = first[key]['delta'], last[key]['delta']
        out[key + '_last_over_first'] = (end / start) if start else None
    for key in ('rss_bytes',):
        start, end = first[key]['mean'], last[key]['mean']
        out[key + '_last_over_first'] = (end / start) if start else None
    return out


def run(seconds):
    with socket.socket():
        pass                      # Winsock init before the resource baseline.
    before = resources()
    samples, latencies, accepted = [], [], 0
    with tempfile.TemporaryDirectory() as workspace:
        directory = Path(workspace)
        config = settings_for(directory)
        runtime = EventRuntime(config,
                               logger=EventLogger(config.logging, writer=lambda line: None))
        runtime.start()

        def poll(metrics=False):
            started = time.perf_counter()
            port = config.metrics.port if metrics else config.api.port
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            try:
                connection.request('GET', '/metrics' if metrics
                                   else '/api/v1/events?limit=10')
                response = connection.getresponse()
                body = response.read(262_145)
                if response.status != 200 or len(body) > 262_144:
                    raise RuntimeError('soak response budget/status')
            finally:
                connection.close()
            latencies.append((time.perf_counter() - started) * 1000)

        start = time.monotonic()
        index = 0
        try:
            for second in range(seconds):
                for _ in range(EVENTS_PER_SECOND):
                    value = event(index, SOURCES)
                    value.timestamp = datetime.now(timezone.utc)
                    accepted += runtime.emit(value)
                    index += 1
                    # Paced against an absolute clock, so a slow second never
                    # becomes an unbounded catch-up burst in the next one.
                    time.sleep(max(0, min(1 / EVENTS_PER_SECOND,
                                          start + index / EVENTS_PER_SECOND
                                          - time.monotonic())))
                poll()
                poll(True)
                samples.append({'second': second + 1, **resources(),
                                'queue': runtime.queue.snapshot(),
                                'disk_bytes': runtime.store.disk_bytes(),
                                'sources': len(runtime.correlator.cache),
                                'pipeline': _pipeline_sample(runtime),
                                'api_metrics_last_ms': latencies[-2:]})
        finally:
            stopping = time.perf_counter()
            closed = runtime.close()
            shutdown = time.perf_counter() - stopping
        final = runtime.snapshot()
        autonomy = runtime.analysis.decisions.autonomy
        health = autonomy.health() if autonomy is not None else None
        journal_files = sorted(
            (path.name, size) for path, size in autonomy.journal.writer.existing()) \
            if autonomy and autonomy.journal else []
        export_files = sorted(
            (path.name, size) for path, size in autonomy.shadow_export.writer.existing()) \
            if autonomy and autonomy.shadow_export else []
    after_close = resources()
    del runtime
    gc.collect()

    thirds = _thirds(samples, TRACKED)
    short = seconds < SOAK_SECONDS
    return {
        'environment': environment(),
        'configuration': configuration(config),
        'soak_class': 'SHORT' if short else 'SOAK',
        'seconds_requested': seconds,
        'seconds_observed': time.monotonic() - start,
        'workload': {'events_per_second': EVENTS_PER_SECOND, 'sources': SOURCES,
                     'mode': 'shadow', 'enforcement': 'disabled',
                     'journal': True, 'shadow_export': True},
        'offered': index, 'accepted': accepted,
        'resources_before': before, 'resources_after': after_close,
        'resources_after_gc': resources(),
        'latency': percentiles(latencies),
        'thirds': thirds,
        'drift': _drift(thirds),
        'shutdown_seconds': shutdown, 'closed': closed,
        'final': final, 'decision_health': health,
        'journal_files': journal_files, 'export_files': export_files,
        'samples': samples,
        'limitations': [
            (f'{seconds} seconds is a bounded soak, not evidence of multi-hour or '
             f'multi-day leak freedom'),
            ('this run was shorter than the ' f'{SOAK_SECONDS}-second minimum this '
             'project is willing to call a soak, and is labelled SHORT')
            if short else
            (f'{seconds} seconds is long enough to be called a soak here and is '
             f'still not evidence about a day'),
            'shadow mode throughout; no decision was handed to any enforcer',
            'same-process generator; fixed synthetic workload, so nothing here is '
            'evidence about detection accuracy',
            f'{SOURCES} sources at {EVENTS_PER_SECOND} offered events/s on one '
            f'machine; no other rate or source count is claimed',
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        prog='python -m benchmarks.autonomous_soak',
        description='The integrated service with the P15 decision stack, in thirds.')
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    if not 60 <= args.seconds <= 3540:
        parser.error('duration must be 60..3540 seconds (plus bounded cleanup)')
    if args.worker:
        print(json.dumps(run(args.seconds)))
        return
    result = guarded(['-m', 'benchmarks.autonomous_soak', '--worker',
                      '--seconds', str(args.seconds), '--output', str(args.output)],
                     wall=args.seconds + 120, cpu=min(3600, args.seconds + 120),
                     memory=1_073_741_824)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    body = result['result']
    print(json.dumps({'output': str(args.output), 'soak_class': body['soak_class'],
                      'accepted': body['accepted'], 'closed': body['closed'],
                      'drift': body['drift']}, indent=2))


if __name__ == '__main__':
    main()
