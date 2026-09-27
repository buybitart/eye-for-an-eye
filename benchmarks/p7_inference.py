"""CPU inference and scheduling experiment; writes measured values, never a pass target."""
import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import platform
import time
from eye_for_an_eye.analysis import EventAnalysis
from eye_for_an_eye.config import Config, MLConfig
from eye_for_an_eye.decision.features import FeatureTransformer
from eye_for_an_eye.decision.onnx_model import OnnxRiskModel, IsolatedModel, benchmark_batch_runner
from eye_for_an_eye.events import NetworkEvent


def measure(run, iterations, sources_per_call=1, child=None):
    import numpy as np
    import psutil
    process = psutil.Process()
    durations = []
    rss = process.memory_info().rss
    child_process = psutil.Process(child) if child else None
    def cpu():
        info = (child_process or process).cpu_times()
        return info.user + info.system
    before_cpu, before = cpu(), time.perf_counter()
    for _ in range(iterations):
        start = time.perf_counter()
        run()
        durations.append((time.perf_counter() - start) * 1000)
        rss = max(rss, process.memory_info().rss)
    elapsed = time.perf_counter() - before
    return {'calls': iterations, 'sources_per_call': sources_per_call, 'elapsed_seconds': elapsed,
        'cpu_seconds': cpu()-before_cpu, 'cpu_scope': 'model_child' if child else 'benchmark_process',
        'parent_peak_sampled_rss_bytes': rss, 'model_child_rss_bytes': child_process.memory_info().rss if child else None,
        'sources_per_second': iterations*sources_per_call/elapsed,
        'latency_ms': dict(zip(('p50', 'p95', 'p99'), map(float, np.percentile(durations, [50, 95, 99]))))}


def benchmark(dataset, models):
    import psutil
    from training.train_baseline import load_dataset
    rows = load_dataset(dataset)
    tensor = FeatureTransformer.transform(rows[-1]['vector'])
    result = {'platform': platform.platform(), 'python': platform.python_version(), 'cpu_count': psutil.cpu_count(),
        'feature_shape': [1, len(tensor)], 'candidates': {}, 'scheduling': {},
        'limitations': ['microbenchmark_not_network_capacity', 'batch_has_zero_wait_time_here',
            'RSS_sampled_not_OS_peak', 'single_measurement_run_no_hardware_SLA']}
    for name in ('logistic', 'gradient_boosting'):
        cfg = MLConfig(model_path=str(models / (name + '-research-v1.onnx')),
            manifest_path=str(models / (name + '-research-v1.json')))
        direct = OnnxRiskModel()
        start = time.perf_counter()
        if direct.load(cfg)['status'] != 'healthy':
            raise RuntimeError(direct.health())
        load_ms = (time.perf_counter()-start)*1000
        def single():
            if direct.predict(tensor).status != 'healthy':
                raise RuntimeError('inference failed')
        single()
        batch = benchmark_batch_runner(cfg, 8)
        expected = direct.predict(tensor).risk_score
        if max(abs(v - expected) for v in batch([tensor]*8)) > 1e-5:
            raise RuntimeError('batch parity failure')
        direct_result = measure(single, 10000)
        batch_result = measure(lambda: batch([tensor]*8), 2000, 8)
        isolated = IsolatedModel(cfg)
        try:
            if isolated.load()['status'] != 'healthy':
                raise RuntimeError(isolated.health())
            def ipc():
                if isolated.predict(tensor).status != 'healthy':
                    raise RuntimeError('isolated inference failure')
            ipc_result = measure(ipc, 1000, child=isolated.process.pid)
        finally:
            isolated.close()
        result['candidates'][name] = {'model_bytes': Path(cfg.model_path).stat().st_size,
            'direct_load_ms': load_ms, 'single_validated': direct_result, 'batch8_validated': batch_result, 'isolated_ipc': ipc_result}
    for interval in (1000, 2000, 5000):
        cfg = Config()
        cfg.ml.enabled = False
        cfg.decision.interval_ms = interval
        analysis = EventAnalysis(cfg)
        start = time.perf_counter()
        total = 0
        for index in range(60):
            for source in range(20):
                event = NetworkEvent(f'192.0.2.{source+1}', dst_ip='198.51.100.1', dst_port=2000+index,
                    event_type='connection', timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index*.1))
                list(analysis.process(event))
                total += 1
        elapsed = time.perf_counter()-start
        result['scheduling'][str(interval)] = {'events': total, 'decision_opportunities': analysis.decisions.metrics['math_decision_total'],
            'wall_seconds': elapsed, 'events_per_second': total/elapsed,
            'history_retained_bytes': analysis.decisions.history.current_bytes, 'mode': 'math_only_scheduler_measurement'}
    result['batching_decision'] = 'retain single-source worker: batching throughput benefits require latency/arrival-rate study; no batch wait in production'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--models', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(benchmark(args.dataset, args.models), stream, indent=2)
