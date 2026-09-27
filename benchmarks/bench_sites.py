"""P12 multi-site cost and fairness (§107, §126, §131). Local, deterministic.

Answers the questions a claim of multi-site support has to answer with numbers:

1. What does site resolution cost per request?
2. Does ten sites cost ten times one site in memory? (It must not.)
3. Under a flood on one site, does a quiet site still get analysed?
4. What does a `Host:` cardinality attack cost?

Run it directly:

    python -m benchmarks.bench_sites
"""
import gc
import json
import os
import resource
import statistics
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eye_for_an_eye.sites.engine import SiteEngine  # noqa: E402
from eye_for_an_eye.sites.identity import UNKNOWN_SITE  # noqa: E402
from eye_for_an_eye.sites.profile import API, WEBSITE, build_all  # noqa: E402
from eye_for_an_eye.web.event import build  # noqa: E402
from eye_for_an_eye.web.identity import ClientResolver  # noqa: E402

SECRET = b's' * 48
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
RESOLVER = ClientResolver([])


def percentiles(samples):
    ordered = sorted(samples)

    def at(fraction):
        return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))] * 1e6
    return {'p50_us': round(at(0.50), 3), 'p95_us': round(at(0.95), 3),
            'p99_us': round(at(0.99), 3),
            'mean_us': round(statistics.fmean(ordered) * 1e6, 3),
            'samples': len(ordered)}


def measure(operation, iterations=20_000):
    for _ in range(min(500, iterations)):
        operation()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        samples.append(time.perf_counter() - start)
    return percentiles(samples)


def rss_kb():
    """Peak resident set size, in kilobytes.

    `ru_maxrss` is a **high-water mark** for the whole process, not its current
    usage. A difference between two readings therefore means "the peak rose by
    at least this much", never "this phase holds this much". It is the right
    number for answering "does adding sites multiply memory?" and the wrong one
    for attributing bytes to a phase, so the report says which question it is
    answering.
    """
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def engine_of(count):
    spec = {}
    for index in range(count):
        spec[f'site{index}'] = {
            'profile': API if index % 3 == 0 else WEBSITE,
            'domains': [f'site{index}.example.test']}
    return SiteEngine(build_all(spec), max_sites=max(1, count))


def event(peer, path='/', status=200, host='site0.example.test'):
    return build(timestamp=START, identity=RESOLVER.resolve(peer), method='GET',
                 path=path, status=status, host=host, user_agent='', referer='',
                 secret=SECRET)


def throughput(engine, hosts, requests=60_000):
    """Events per second through resolve plus observe."""
    contexts = [engine.context(host) for host in hosts]
    prepared = [event(f'10.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}',
                      f'/p{index % 97}', 404 if index % 3 else 200)
                for index in range(2000)]
    start = time.perf_counter()
    now = 0.0
    for index in range(requests):
        now += 0.001
        engine.observe(contexts[index % len(contexts)], prepared[index % len(prepared)],
                       now, probing=(index % 3 == 0))
    elapsed = time.perf_counter() - start
    return {'requests': requests, 'seconds': round(elapsed, 3),
            'per_second': round(requests / elapsed)}


def run():
    report = {'benchmark_schema_version': 1}

    one = engine_of(1)
    ten = engine_of(10)
    twenty = engine_of(20)

    report['resolution'] = {
        'known_host': measure(lambda: one.context('site0.example.test')),
        'unknown_host': measure(lambda: one.context('nothing.example.test')),
        'malformed_host': measure(lambda: one.context('exa mple.org')),
        'ten_sites': measure(lambda: ten.context('site9.example.test')),
    }

    # Memory: fill each engine to the same global ceiling and compare.
    footprints = {}
    for name, engine in (('one_site', one), ('ten_sites', ten),
                         ('twenty_sites', twenty)):
        gc.collect()
        before = rss_kb()
        hosts = [f'site{index}.example.test'
                 for index in range(len(engine.profiles))]
        contexts = [engine.context(host) for host in hosts]
        now = 0.0
        for index in range(60_000):
            now += 0.01
            engine.observe(contexts[index % len(contexts)],
                           event(f'10.{index // 65536 % 256}.'
                                 f'{index // 256 % 256}.{index % 256}'), now)
        gc.collect()
        footprints[name] = {'sites': len(engine.profiles),
                            'sources': len(engine.state),
                            'rss_growth_kb': rss_kb() - before}
    report['memory'] = footprints
    report['memory_note'] = (
        'the global source ceiling is shared, so more sites divide one budget '
        'rather than multiplying it')

    # Fairness: a flood on one site while a quiet one keeps working.
    fair = engine_of(4)
    busy = fair.context('site1.example.test')
    quiet = fair.context('site2.example.test')
    now = 0.0
    for index in range(40):
        now += 1.0
        fair.observe(quiet, event(f'192.0.2.{index}'), now)
    held_before = fair.state.site_stats('site2')['sources']
    for index in range(200_000):
        now += 0.001
        fair.observe(busy, event(f'10.{index // 65536 % 256}.'
                                 f'{index // 256 % 256}.{index % 256}'), now)
    held_after = fair.state.site_stats('site2')['sources']
    report['fairness'] = {
        'quiet_site_sources_before': held_before,
        'quiet_site_sources_after_flood': held_after,
        'quiet_site_survived': held_after >= held_before,
        'busy_site_sources': fair.state.site_stats('site1')['sources'],
        'busy_site_evictions': fair.state.site_stats('site1')['evictions'],
        'quiet_site_evictions': fair.state.site_stats('site2')['evictions']}

    # Host cardinality attack: every request a fresh invented host.
    attacked = engine_of(4)
    gc.collect()
    before = rss_kb()
    start = time.perf_counter()
    now = 0.0
    for index in range(200_000):
        now += 0.001
        context = attacked.context(f'{index}.attacker.test')
        attacked.observe(context, event(f'203.0.113.{index % 256}'), now)
    report['host_cardinality_attack'] = {
        'requests': 200_000,
        'seconds': round(time.perf_counter() - start, 3),
        'sites_created': len(attacked.profiles),
        'unknown_bucket_sources': attacked.state.site_stats(UNKNOWN_SITE)['sources'],
        'rss_growth_kb': rss_kb() - before,
        'total_sources': len(attacked.state)}

    report['throughput'] = {
        'one_site': throughput(engine_of(1), ['site0.example.test']),
        'ten_sites': throughput(engine_of(10),
                                [f'site{index}.example.test' for index in range(10)])}

    report['process_rss_kb'] = rss_kb()
    report['note'] = ('single process, one core, no network; synthetic traffic '
                      'against this configuration, not a hosting-scale claim. '
                      'Memory figures are peak-RSS differences, so they bound '
                      'growth rather than attributing bytes to a phase.')
    return report


def render(report):
    lines = ['P12 MULTI-SITE COST AND FAIRNESS', '', 'Site resolution:']
    for name, row in report['resolution'].items():
        lines.append(f'  {name:<16} p50 {row["p50_us"]:>8.3f} us   '
                     f'p99 {row["p99_us"]:>8.3f} us')
    lines += ['', 'Memory at the same global ceiling:']
    for name, row in report['memory'].items():
        lines.append(f'  {name:<14} {row["sites"]:>3} sites  '
                     f'{row["sources"]:>6} sources  {row["rss_growth_kb"]:>7} KB')
    lines += ['  ' + report['memory_note'], '']

    fair = report['fairness']
    lines += ['Fairness under a flood on one site:',
              f'  quiet site before   {fair["quiet_site_sources_before"]}',
              f'  quiet site after    {fair["quiet_site_sources_after_flood"]}',
              f'  quiet site evicted  {fair["quiet_site_evictions"]}',
              f'  busy site evicted   {fair["busy_site_evictions"]}',
              f'  survived            {"yes" if fair["quiet_site_survived"] else "NO"}',
              '']

    attack = report['host_cardinality_attack']
    lines += ['Host cardinality attack (200,000 invented hosts):',
              f'  sites created       {attack["sites_created"]} (unchanged)',
              f'  unknown bucket      {attack["unknown_bucket_sources"]} sources',
              f'  total sources       {attack["total_sources"]}',
              f'  memory growth       {attack["rss_growth_kb"]} KB',
              f'  time                {attack["seconds"]} s', '']

    lines += ['Throughput:']
    for name, row in report['throughput'].items():
        lines.append(f'  {name:<12} {row["per_second"]:>8} events/second')
    lines += ['', f'Process RSS:\n{report["process_rss_kb"]} KB', '',
              'Note:', report['note']]
    return '\n'.join(lines)


if __name__ == '__main__':
    result = run()
    if '--json' in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))
