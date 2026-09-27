"""Generate comparable P5 tables; speed thresholds are opt-in, never normal CI."""
import argparse
import json
from pathlib import Path
import statistics


def generate(root):
    def load(name):
        value = json.loads((root / (name + '.json')).read_text(encoding='utf-8'))
        if value.get('valid') is False:
            raise ValueError('invalid measurement')
        return value['result']['data']
    rows = []
    def add(label, before, after, metric, scope):
        b = statistics.median(value[metric] for value in before)
        a = statistics.median(value[metric] for value in after)
        rows.append({'metric': label, 'before': b, 'after': a, 'delta_percent': (a/b-1)*100,
                     'scope': scope, 'before_runs': [value[metric] for value in before],
                     'after_runs': [value[metric] for value in after]})
    for case, key, label in (('packet_parsing', 'pipeline', 'Packet pipeline'),
                             ('correlation', 'scanner', 'Correlation scanner'),
                             ('storage', 'production_single', 'SQLite batch 1')):
        b = [load('baseline-'+case+suffix)[key] for suffix in ('', '-2', '-3')]
        a = [load('final-'+case+'-'+str(i))[key] for i in (1, 2, 3)]
        for metric in ('operations_per_second', 'p95_ms'):
            add(label+' '+metric, b, a, metric, '3 runs, same workload')
        if case == 'packet_parsing':
            add('Packet RSS bytes', [v['resources_after'] for v in b], [v['resources_after'] for v in a],
                'rss_bytes', '3 runs; process working set')
        if case == 'storage':
            for size in ('8', '32'):
                values = [load('final-storage-'+str(i))['production_batches'][size] for i in (1, 2, 3)]
                add('SQLite batch '+size+' rows/s', [{'rows_per_second': v['operations_per_second']} for v in b],
                    values, 'rows_per_second', '3 runs; opt-in batch vs old single row; 100 rows/run')
    for case, keys in (
            ('cache', ('cold', 'warm', 'churn', 'expiration_storm', 'negative', 'metrics_counter', 'metrics_scrape', 'logging_attack_sampled')),
            ('deception', ('hmac_selection', 'binary_parser'))):
        b, a = load('baseline-'+case), load('final-'+case+'-coverage')
        for key in keys:
            add(case+'/'+key+' p95 ms', [b[key]], [a[key]], 'p95_ms', 'single exploratory run')
    b, a = load('baseline-fingerprinting')['modules'], load('final-fingerprinting-coverage')['modules']
    for key in b:
        add(key+' p95 ms', [b[key]], [a[key]], 'p95_ms', 'single microbenchmark; fixture inputs')
    for protocol in ('http', 'ftp', 'ssh'):
        b = load('baseline-deception')['protocols'][protocol]['measurement']
        a = load('final-deception-coverage')['protocols'][protocol]['measurement']
        add(protocol+' conversations/s', [b], [a], 'operations_per_second', 'one complete in-memory conversation/op')
    b, a = load('baseline-tcp_listener')['stages']['fast'], load('final-tcp_listener')['stages']['fast']
    for metric in ('operations_per_second', 'p95_ms'):
        add('TCP fast '+metric, [b], [a], metric, '100 sequential loopback connects; single run')
    for scenario in ('ok', 'slow', 'timeout', 'unavailable'):
        b = load('baseline-enrichment')['scenarios'][scenario]['core_emit']
        a = load('final-enrichment-coverage')['scenarios'][scenario]['core_emit']
        add('Enrichment '+scenario+' core admission/s', [b], [a], 'operations_per_second',
            '200 admissions, not persisted throughput; one provider child')
    for name in ('under_writes',):
        b = [load('replay-baseline-api-'+str(i))[name] for i in (1, 2)]
        a = [load('replay-final-api-'+str(i))[name] for i in (1, 2)]
        add('API mixed p95 ms (alternating replay)', b, a, 'p95_ms', '2 alternating runs; exact old source SHA')
    for route in load('baseline-api')['routes']:
        b = [load('replay-baseline-api-'+str(i))['routes'][route] for i in (1, 2)]
        a = [load('replay-final-api-'+str(i))['routes'][route] for i in (1, 2)]
        add(route+' p95 ms', b, a, 'p95_ms', '2 alternating runs; 250 seed events')
    b, a = load('baseline-queue'), load('final-queue-coverage')
    add('Queue burst producer admissions/s', [b['producer']], [a['producer']], 'operations_per_second',
        'includes rejected events; exact 64 admitted / 236 dropped')
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--results', type=Path, default=Path('benchmarks/results/p5'))
    parser.add_argument('--output', type=Path, default=Path('docs/P5_MEASUREMENTS.md'))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    rows = generate(args.results)
    lines = ['# P5 measured comparisons', '',
        'Generated from the JSON artifacts by python -m benchmarks.report. Percentages use unrounded medians.',
        'Positive throughput delta is better; negative latency/RSS delta is better. No confidence interval is inferred from 1–3 runs.',
        'Environment, source hashes, configuration and per-run values remain in ../benchmarks/results/p5/.',
        'Original API outlier (25.615 ms mixed p95) is retained in final-api.json; alternating replay is shown below.',
        '', '| Metric | Before | After | Delta | Scope |', '|---|---:|---:|---:|---|']
    for row in rows:
        lines.append(f"| {row['metric']} | {row['before']:.4f} | {row['after']:.4f} | {row['delta_percent']:+.2f}% | {row['scope']} |")
    args.output.write_text('\n'.join(lines)+'\n', encoding='utf-8')
    (args.results/'comparison.json').write_text(json.dumps(rows, indent=2)+'\n', encoding='utf-8')
    failures = []
    for row in rows:
        name = row['metric']
        if name.startswith(('Packet pipeline', 'Correlation scanner', 'SQLite batch 1')):
            limit = -15 if name.endswith('operations_per_second') else 20
            if row['delta_percent'] < limit if limit < 0 else row['delta_percent'] > limit:
                failures.append(name)
        if name == 'Packet RSS bytes' and row['delta_percent'] > 15:
            failures.append(name)
    print(json.dumps({'rows': len(rows), 'opt_in_regressions': failures, 'output': str(args.output)}))
    if args.check and failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
