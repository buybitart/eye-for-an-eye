"""Repeatable synthetic CPU/memory benchmark. Does not send or capture packets."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import gc
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from eye_for_an_eye.config import Config
from eye_for_an_eye.correlation.engine import CorrelationEngine
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.offline import analyze_pcap
from tests.fixtures.p2.generate import write_pcap


def sample(index, source=None):
    return NetworkEvent(source or '192.0.2.1', 12345, '198.51.100.1', 1000 + index % 32, 'tcp', 'connection',
        timestamp=datetime.fromtimestamp(index / 10, timezone.utc), event_id=f'benchmark-{index}')


def benchmark(count=1000, sources=10000):
    if not 32 <= count <= 10000 or not 100 <= sources <= 10000:
        raise ValueError('benchmark bounds: 32..10000 events, 100..10000 sources')
    config = Config()
    source_hash = hashlib.sha256()
    for source in sorted(Path('eye_for_an_eye').rglob('*.py')):
        source_hash.update(source.as_posix().encode())
        source_hash.update(source.read_bytes())
    engine = CorrelationEngine(config.correlation)
    latencies = []
    cpu = time.process_time()
    started = time.perf_counter()
    for index in range(count):
        event = sample(index)
        before = time.perf_counter()
        engine.observe(event)
        latencies.append(time.perf_counter() - before)
    elapsed, cpu = time.perf_counter() - started, time.process_time() - cpu
    state = engine.snapshot()
    hits, misses = state['source_cache']['hit'], state['source_cache']['miss']
    correlation = {'input_events': count, 'seconds': elapsed, 'events_per_second': count / elapsed,
        'cpu_seconds': cpu, 'latency_mean_ms': statistics.mean(latencies) * 1000,
        'latency_p50_ms': statistics.median(latencies) * 1000,
        'latency_p95_ms': sorted(latencies)[int(.95 * (count - 1))] * 1000,
        'source_cache_hit_rate': hits / max(1, hits + misses),
        'sample_drop_rate': state.get('sample_drops', 0) / count, 'state': state}
    print('correlation timing complete', file=sys.stderr, flush=True)
    del engine
    gc.collect()
    tracemalloc.start()
    engine = CorrelationEngine(config.correlation)
    for index in range(sources):
        event = sample(index, f'10.{index // 65536}.{index // 256 % 256}.{index % 256}')
        event.timestamp = datetime.fromtimestamp(index / 1000, timezone.utc)
        engine.observe(event)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    memory = {'input_sources': sources, 'retained_sources': len(engine.cache), 'python_current_bytes': current,
              'python_peak_bytes': peak, 'accounted_state_bytes': engine.snapshot()['bytes'],
              'bytes_per_input_source': current / sources, 'rss_measured': False}
    print('source memory measurement complete', file=sys.stderr, flush=True)
    from scapy.layers.inet import IP, TCP
    rows = []
    for index in range(count):
        data = bytes(IP(src=f'192.0.2.{1 + index % 16}', dst='198.51.100.1', ttl=51, id=index & 65535) /
                     TCP(sport=1234, dport=1000 + index % 32, seq=index, flags='S'))
        rows.append((index / 10 + 1, data))
    with tempfile.TemporaryDirectory(prefix='e4e-p2-benchmark-') as directory:
        path = Path(directory) / 'synthetic.pcap'
        write_pcap(path, rows)
        started = time.perf_counter()
        stats = analyze_pcap(path, config, writer=lambda line: None, max_output_bytes=1073741824)
        elapsed = time.perf_counter() - started
    return {'schema_version': 1, 'source_sha256': source_hash.hexdigest(),
        'python': sys.version.split()[0], 'platform': platform.platform(),
        'workload': 'synthetic classic PCAP + single-source correlation + 10000 active sources within TTL',
        'configuration': asdict(config.correlation), 'correlation': correlation, 'memory': memory,
        'offline_pipeline': {'packets': stats['packets'], 'seconds': elapsed, 'packets_per_second': stats['packets'] / elapsed,
                             'parse_errors': stats['parse_errors'], 'output_drops': stats.get('output_dropped', 0),
                             'input_drop_rate': 0.0, 'mode': 'paced offline; no live queue/OS capture'},
        'limitations': ['single Windows run, synthetic input, no live wire-rate claim',
                        'tracemalloc covers Python allocations, not native RSS or kernel buffers',
                        'sample drop rate is bounded-window truncation, not packet capture loss']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--events', type=int, default=1000)
    parser.add_argument('--sources', type=int, default=10000)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = benchmark(args.events, args.sources)
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
