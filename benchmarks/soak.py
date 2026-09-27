"""Finite localhost soak. Default 30 seconds; explicit 900..3540 for a lab run."""
import argparse
import gc
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import socket
import tempfile
import time
from benchmarks.common import config, configuration, environment, guarded, percentiles, resources
from benchmarks.bench_api import free_port
from benchmarks.workloads import event
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime


def run(seconds):
    settings = config()
    settings.storage.enabled = settings.api.enabled = settings.metrics.enabled = True
    settings.storage.max_batch_events = 8
    settings.storage.max_events = 2000
    settings.storage.max_bytes = 16777216
    settings.runtime.load_shedding = True
    settings.runtime.queue_events = 256
    settings.correlation.max_sources = 64
    settings.api.port, settings.metrics.port = free_port(), free_port()
    # Initialize Winsock before the resource baseline (Windows retains process-wide state).
    with socket.socket():
        pass
    before = resources()
    samples, latencies, accepted = [], [], 0
    with tempfile.TemporaryDirectory() as directory:
        settings.storage.path = str(Path(directory) / 'soak.db')
        runtime = EventRuntime(settings, logger=EventLogger(settings.logging, writer=lambda line: None))
        runtime.start()
        def get(metrics=False):
            start = time.perf_counter()
            conn = http.client.HTTPConnection('127.0.0.1', settings.metrics.port if metrics else settings.api.port, timeout=2)
            try:
                conn.request('GET', '/metrics' if metrics else '/api/v1/events?limit=10')
                response = conn.getresponse()
                body = response.read(65537)
                if response.status != 200 or len(body) > 65536:
                    raise RuntimeError('soak response budget/status')
            finally:
                conn.close()
            latencies.append((time.perf_counter() - start) * 1000)
        start = time.monotonic()
        index = 0
        try:
            for second in range(seconds):
                for _ in range(60):
                    value = event(index)
                    value.timestamp = datetime.now(timezone.utc)
                    accepted += runtime.emit(value)
                    index += 1
                    # Pace against an absolute clock; never catch up with an unbounded burst.
                    time.sleep(max(0, min(1/60, start + index/60 - time.monotonic())))
                get()
                get(True)
                samples.append({'second': second+1, **resources(), 'queue': runtime.queue.snapshot(),
                    'disk_bytes': runtime.store.disk_bytes(), 'sources': len(runtime.correlator.cache),
                    'api_metrics_last_ms': latencies[-2:]})
        finally:
            stopping = time.perf_counter()
            closed = runtime.close()
            shutdown = time.perf_counter() - stopping
        final = runtime.snapshot()
    after_close = resources()
    del runtime
    gc.collect()
    after_gc = resources()
    return {'environment': environment(), 'configuration': configuration(settings), 'seconds_requested': seconds,
        'seconds_observed': time.monotonic()-start, 'offered': index, 'accepted': accepted,
        'resources_before': before, 'resources_after': after_close, 'resources_after_gc': after_gc, 'samples': samples,
        'latency': percentiles(latencies), 'shutdown_seconds': shutdown, 'closed': closed, 'final': final,
        'limitations': [f'{seconds} seconds is a bounded soak, not evidence of '
            'multi-hour or multi-day leak freedom'
            + ('' if seconds >= 900 else '; this run was shorter than the 900-second minimum '
               'the project treats as a real soak'),
            'same-process generator; fixed 16 sources/64 samples, storage retention 2000 rows',
            'one active client socket at a time, fixed API and metrics listener limits']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    if not 15 <= args.seconds <= 3540:
        parser.error('duration must be 15..3540 seconds (plus bounded cleanup)')
    if args.worker:
        print(json.dumps(run(args.seconds)))
        return
    result = guarded(['-m', 'benchmarks.soak', '--worker', '--seconds', str(args.seconds), '--output', str(args.output)],
        wall=args.seconds+60, cpu=min(3600, args.seconds+30))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'closed': result['result']['closed'], 'accepted': result['result']['accepted']}))


if __name__ == '__main__':
    main()
