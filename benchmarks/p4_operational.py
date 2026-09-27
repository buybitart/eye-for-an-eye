"""Finite operational sanity test: local producer, WAL writer, API readers and scraper."""
import argparse
from collections import Counter
import hashlib
import http.client
import json
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
from benchmarks.p3_deception import resources
from eye_for_an_eye import __version__
from eye_for_an_eye.config import Config
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime


def port():
    with socket.socket() as value:
        value.bind(('127.0.0.1', 0))
        return value.getsockname()[1]


def percentiles(values):
    values = sorted(values)
    return {key: values[int((len(values) - 1) * fraction)] if values else None
            for key, fraction in (('p50', .5), ('p95', .95), ('p99', .99), ('max', 1))}


def measure(count):
    with tempfile.TemporaryDirectory() as directory:
        config = Config()
        config.storage.enabled = config.api.enabled = config.metrics.enabled = True
        config.storage.path = str(Path(directory) / 'sanity.db')
        config.storage.max_bytes = 16_777_216
        config.storage.max_events = 5000
        config.runtime.queue_events = 256
        config.runtime.queue_bytes = 1_048_576
        config.api.port, config.metrics.port = port(), port()
        config.api.requests_per_second = 100
        config.correlation.max_sources = 64
        config.correlation.max_events_per_source = 64
        runtime = EventRuntime(config, logger=EventLogger(config.logging, writer=lambda line: None))
        before = resources()
        runtime.start()
        initial_disk = runtime.store.disk_bytes()
        stop = threading.Event()
        samples, api_ms, scrape_ms, emit_ms = [], [], [], []
        statuses = Counter()
        state_lock = threading.Lock()

        def consumer(metrics=False, source=0):
            iterations = 0
            while not stop.is_set() and iterations < 300:
                iterations += 1
                start = time.perf_counter()
                connection = http.client.HTTPConnection('127.0.0.1', config.metrics.port if metrics else config.api.port, timeout=2)
                try:
                    path = '/metrics' if metrics else ('/api/v1/events?limit=10' if source == 0 else '/api/v1/stats')
                    connection.request('GET', path)
                    response = connection.getresponse()
                    body = response.read(65537)
                    if len(body) > 65536:
                        raise ValueError('response budget')
                    if response.status == 200 and not metrics:
                        json.loads(body)
                    with state_lock:
                        statuses[('metrics_' if metrics else 'api_') + str(response.status)] += 1
                except (OSError, ValueError, http.client.HTTPException):
                    with state_lock:
                        statuses['request_failure'] += 1
                finally:
                    connection.close()
                with state_lock:
                    (scrape_ms if metrics else api_ms).append((time.perf_counter() - start) * 1000)
                stop.wait(.075)

        def monitor():
            while not stop.is_set() and len(samples) < 3000:
                q = runtime.queue.snapshot()
                samples.append({'queue_depth': q['depth'], 'queue_bytes': q['bytes'],
                    'disk_bytes': runtime.store.disk_bytes(), 'rss_bytes': resources()['rss_bytes']})
                stop.wait(.02)

        threads = [threading.Thread(target=consumer, args=(False, i)) for i in range(2)]
        threads += [threading.Thread(target=consumer, args=(True,)), threading.Thread(target=monitor)]
        started = time.perf_counter()
        for thread in threads:
            thread.start()
        accepted = 0
        try:
            for index in range(count):
                event = NetworkEvent(f'192.0.2.{index % 16 + 1}', 30000 + index % 100, '192.0.2.100',
                    8000 + index % 32, 'tcp', EventType.CONNECTION_ACCEPTED, observations={'completed_handshake': True})
                stamp = time.perf_counter()
                accepted += runtime.emit(event)
                emit_ms.append((time.perf_counter() - stamp) * 1000)
                time.sleep(.005)
            deadline = time.monotonic() + 10
            while (not runtime.queue.empty() or runtime.storage_started) and time.monotonic() < deadline:
                time.sleep(.02)
            if not runtime.queue.empty():
                raise RuntimeError('sanity drain deadline')
            # Allow one cached health/metrics refresh while readers continue.
            time.sleep(1.1)
            state = runtime.snapshot()
            health = runtime.health_response()
        finally:
            stop.set()
            for thread in threads:
                thread.join(3)
            stopping = time.perf_counter()
            closed = runtime.close()
            shutdown = time.perf_counter() - stopping
        if not closed or any(thread.is_alive() for thread in threads):
            raise RuntimeError('sanity bounded shutdown failed')
        after = resources()
        digest = hashlib.sha256()
        for path in sorted(Path('eye_for_an_eye').rglob('*.py')):
            digest.update(path.as_posix().encode())
            digest.update(path.read_bytes())
        result = {'application': __version__, 'environment': platform.platform(), 'python': platform.python_version(),
            'source_sha256': digest.hexdigest(), 'kind': 'P4 local operational sanity, not a capacity benchmark',
            'producer_events': count, 'accepted': accepted, 'elapsed_seconds': time.perf_counter() - started,
            'consumer_layout': '2 HTTP API clients + 1 metrics scraper + 1 WAL writer; 5ms producer pacing',
            'response_statuses': dict(statuses), 'emit_ms': percentiles(emit_ms), 'api_ms': percentiles(api_ms),
            'metrics_ms': percentiles(scrape_ms), 'queue_peak_depth': max(row['queue_depth'] for row in samples),
            'queue_peak_bytes': max(row['queue_bytes'] for row in samples), 'queue_budget': config.runtime.queue_events,
            'queue_byte_budget': config.runtime.queue_bytes, 'database_initial_bytes': initial_disk,
            'database_peak_bytes': max(row['disk_bytes'] for row in samples), 'database_final_bytes': runtime.store.disk_bytes(),
            'database_budget': config.storage.max_bytes, 'rss_before': before['rss_bytes'],
            'rss_peak': max(row['rss_bytes'] for row in samples if row['rss_bytes'] is not None),
            'rss_after': after['rss_bytes'], 'threads_before': before['threads'], 'threads_after': after['threads'],
            'shutdown_seconds': shutdown, 'metrics': state['metrics'], 'storage_metrics': dict(runtime.store.metrics),
            'logging_metrics': dict(runtime.logger.metrics), 'health_during_load': health, 'health_after_shutdown': runtime.health_response(),
            'limitations': ['Windows localhost only', 'no live packet capture or firewall',
                            'stdout sink discarded after JSON serialization', 'RSS is measured, not a hard process cap']}
        result['passed'] = (health['ready'] and accepted == count and state['metrics']['events_dropped_total'] == 0 and
            state['metrics']['storage_write_failures_total'] == 0 and statuses['request_failure'] == 0 and
            all(key in ('api_200', 'metrics_200', 'request_failure') for key in statuses) and
            result['database_peak_bytes'] <= config.storage.max_bytes and result['queue_peak_depth'] <= config.runtime.queue_events)
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--count', type=int, default=400)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 1 <= args.count <= 2000:
        parser.error('count must be 1..2000')
    if args.worker:
        print(json.dumps(measure(args.count)))
        return
    run = subprocess.run([sys.executable, '-B', '-m', 'benchmarks.p4_operational', '--worker', '--count', str(args.count)],
                         capture_output=True, text=True, timeout=40, check=True)
    result = json.loads(run.stdout)
    encoded = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(encoded + '\n', encoding='utf-8')
    print(encoded)
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
