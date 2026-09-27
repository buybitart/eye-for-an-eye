"""P11 latency and footprint (§89, §141). Local, deterministic, no network.

Answers four questions with measurements rather than adjectives:

1. What does signing a token cost?
2. What does verifying one cost — including when it is invalid, which is the
   case an attacker controls the rate of?
3. What does a normal, unchallenged request cost? This is the number that
   matters most, because almost every request is this one.
4. How much memory does challenge state occupy at its bound?

Run it directly:

    python -m benchmarks.challenge_latency
"""
import gc
import json
import os
import resource
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eye_for_an_eye.challenge.policy import ChallengeGate  # noqa: E402
from eye_for_an_eye.challenge.service import ChallengeService  # noqa: E402
from eye_for_an_eye.challenge.token import issue, verify  # noqa: E402
from eye_for_an_eye.web.gateway import WebGateway  # noqa: E402
from eye_for_an_eye.web.identity import ClientResolver  # noqa: E402

SECRET = b's' * 48
SITE = 'benchmark'
ITERATIONS = 20_000


def percentiles(samples):
    """Microseconds at p50/p95/p99, plus the worst one seen."""
    ordered = sorted(samples)
    def at(fraction):
        return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))] * 1e6
    return {'p50_us': round(at(0.50), 2), 'p95_us': round(at(0.95), 2),
            'p99_us': round(at(0.99), 2), 'max_us': round(ordered[-1] * 1e6, 2),
            'mean_us': round(statistics.fmean(ordered) * 1e6, 2),
            'samples': len(ordered)}


def measure(operation, iterations=ITERATIONS):
    """Time one operation, discarding a warm-up pass."""
    for _ in range(min(500, iterations)):
        operation()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        samples.append(time.perf_counter() - start)
    return percentiles(samples)


def rss_kb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def run():
    report = {'benchmark_schema_version': 1, 'iterations': ITERATIONS}

    token = issue(SECRET, site=SITE, ttl_seconds=900, now=1_800_000_000)
    expired = issue(SECRET, site=SITE, ttl_seconds=30, now=1_700_000_000)
    garbage = 'A' * len(token)

    report['token_signing'] = measure(
        lambda: issue(SECRET, site=SITE, ttl_seconds=900, now=1_800_000_000))
    report['token_verification_valid'] = measure(
        lambda: verify(token, SECRET, site=SITE, now=1_800_000_100))
    report['token_verification_expired'] = measure(
        lambda: verify(expired, SECRET, site=SITE, now=1_800_000_000))
    # The path an attacker can drive at any rate they like. It must not be the
    # expensive one: a verifier that costs more to reject than to accept is a
    # denial-of-service amplifier wearing a security label.
    report['token_verification_garbage'] = measure(
        lambda: verify(garbage, SECRET, site=SITE, now=1_800_000_000))

    clock = [1000.0]

    def now():
        return clock[0]

    gate = ChallengeGate(shadow=False, clock=now)
    service = ChallengeService(secret=SECRET, mode='active', site_id=SITE, gate=gate,
                               clock=now, wall_clock=now)
    gateway = WebGateway(resolver=ClientResolver([]), challenge=service)

    # A normal visitor: no token, no suspicion. This is the overwhelming majority
    # of traffic on any site, and the number that decides whether the subsystem
    # is affordable at all.
    report['normal_request'] = measure(
        lambda: gateway.handle(peer='198.51.100.5', method='GET', path='/',
                               now=1000.0),
        iterations=ITERATIONS // 4)

    # A request carrying a valid token, which is what every visitor does for the
    # rest of the token's life once challenged.
    report['request_with_valid_token'] = measure(
        lambda: gateway.handle(peer='198.51.100.6', method='GET', path='/',
                               cookie=token, now=1000.0),
        iterations=ITERATIONS // 4)

    response = service.respond(return_path='/some/page', now=1_800_000_000)
    report['challenge_response_bytes'] = len(response.body.encode('utf-8'))
    report['challenge_response'] = measure(
        lambda: service.respond(return_path='/some/page', now=1_800_000_000),
        iterations=ITERATIONS // 4)

    # State footprint at the bound: fill the context table to capacity.
    gc.collect()
    before = rss_kb()
    limit = gate.budget.concurrent_contexts
    for index in range(limit):
        gate.contexts.touch(f'10.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}',
                            clock[0])
    gc.collect()
    report['challenge_state'] = {
        'contexts': len(gate.contexts),
        'capacity': limit,
        'rss_growth_kb': rss_kb() - before,
        'bytes_per_context': round((rss_kb() - before) * 1024 / max(1, len(gate.contexts)), 1)}
    report['process_rss_kb'] = rss_kb()
    report['note'] = ('single process, one core, no network; measures this machine '
                      'and this configuration, not a deployment')
    return report


def render(report):
    lines = ['P11 CHALLENGE LATENCY', '',
             f'Iterations:\n{report["iterations"]}', '']
    for name in ('token_signing', 'token_verification_valid',
                 'token_verification_expired', 'token_verification_garbage',
                 'normal_request', 'request_with_valid_token', 'challenge_response'):
        item = report[name]
        lines += [f'{name.replace("_", " ")}:',
                  f'  p50 {item["p50_us"]:>8.2f} us',
                  f'  p95 {item["p95_us"]:>8.2f} us',
                  f'  p99 {item["p99_us"]:>8.2f} us', '']
    state = report['challenge_state']
    lines += [f'Challenge response size:\n{report["challenge_response_bytes"]} bytes', '',
              'Challenge state at capacity:',
              f'  contexts {state["contexts"]} of {state["capacity"]}',
              f'  growth   {state["rss_growth_kb"]} KB',
              f'  each     {state["bytes_per_context"]} bytes', '',
              f'Process RSS:\n{report["process_rss_kb"]} KB', '',
              'Note:', report['note']]
    return '\n'.join(lines)


if __name__ == '__main__':
    result = run()
    if '--json' in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))
