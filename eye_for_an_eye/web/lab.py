"""LAB harness: synthetic web clients driven through the real challenge flow.

Everything here is local and synthetic. No client in this file talks to a network
and none of them is a recording of a real person's traffic; they are scripted
behaviours used to answer questions that cannot be answered by reading the code:

* Does an ordinary visitor ever see a challenge? (§104, §142)
* Does a scanner that ignores cookies get stuck in a loop? (§37, §106)
* Does a scanner that *handles* cookies get treated as benign for passing? (§107)
* Does a client behind a CDN cost every other client behind it? (§111, §113)

A word about the labels on these fixtures. `intent` says what the fixture was
built to imitate — it is a property of the script, not a judgement the system
made. It exists so a test can say "this fixture imitates an ordinary browser and
the system challenged it anyway". It is never a training label, never reaches a
dataset row as ground truth, and the fixture that matters most (`patient_scanner`)
is precisely the one where the naive reading would be wrong: it passes every
challenge.
"""
from dataclasses import dataclass, field
import random

from ..challenge.token import COOKIE_NAME

WEB_LAB_SCHEMA_VERSION = 1

#: What a fixture was written to imitate. Not a verdict, not a label.
ORDINARY = 'ordinary'
AUTOMATED = 'automated'


@dataclass
class LabClient:
    """One scripted client. Deterministic given its seed.

    The three behavioural switches are the ones that actually decide what happens
    to a client in this system, and they cut across the ordinary/automated line
    on purpose: plenty of ordinary visitors block cookies, and plenty of scanners
    handle them perfectly.
    """

    name: str
    intent: str
    #: Does it keep a cookie it was given and send it back?
    keeps_cookies: bool = True
    #: Does it re-issue the original request after a redirect?
    follows_redirects: bool = True
    #: Seconds between requests.
    gap: float = 1.0
    #: How many requests it makes.
    requests: int = 40
    #: Where it goes.
    paths: tuple = ('/',)
    #: Which of its requests are unsuccessful, as a fraction. Scanners miss a lot.
    miss_ratio: float = 0.0
    method: str = 'GET'
    user_agent: str = ''
    #: Set for fixtures that hold a cookie but keep probing after passing (§42).
    probes_after_pass: bool = False
    seed: int = 1

    def path_for(self, index, stream):
        if self.miss_ratio and stream.random() < self.miss_ratio:
            return f'/{stream.randrange(1_000_000)}-{index}'
        return self.paths[index % len(self.paths)]

    def status_for(self, path):
        return 404 if path.startswith('/') and path[1:2].isdigit() else 200


#: §121. Seven ordinary fixtures and six automated ones.
#:
#: The ordinary list is not a list of easy cases. `privacy_browser` blocks
#: cookies, `api_client` cannot render HTML, and `health_checker` is a machine —
#: all three would fail a naive "can it hold a cookie" test, and none of them is
#: doing anything wrong.
LAB_CLIENTS = (
    LabClient('normal_browser', ORDINARY, requests=25, gap=3.0,
              paths=('/', '/about', '/articles/1', '/articles/2', '/contact'),
              user_agent='Mozilla/5.0', seed=11),
    LabClient('cookie_enabled_browser', ORDINARY, requests=40, gap=2.0,
              paths=('/', '/shop', '/shop/item/1', '/shop/item/2', '/cart'),
              user_agent='Mozilla/5.0', seed=12),
    LabClient('privacy_browser', ORDINARY, keeps_cookies=False, requests=25, gap=4.0,
              paths=('/', '/about', '/articles/3'),
              user_agent='Mozilla/5.0', seed=13),
    LabClient('slow_browser', ORDINARY, requests=12, gap=30.0,
              paths=('/', '/articles/4', '/articles/5'),
              user_agent='Mozilla/5.0', seed=14),
    LabClient('api_client', ORDINARY, keeps_cookies=False, follows_redirects=False,
              requests=200, gap=0.25, paths=('/api/v1/items', '/api/v1/status'),
              user_agent='acme-sdk/2.1', seed=15),
    LabClient('crawler', ORDINARY, keeps_cookies=False, requests=60, gap=5.0,
              paths=('/', '/sitemap.xml', '/articles/1', '/articles/2', '/articles/3'),
              user_agent='ExampleBot/1.0', seed=16),
    LabClient('health_checker', ORDINARY, keeps_cookies=False, follows_redirects=False,
              requests=120, gap=10.0, paths=('/health',),
              user_agent='checker/1.0', seed=17),

    LabClient('cookieless_scanner', AUTOMATED, keeps_cookies=False,
              follows_redirects=False, requests=150, gap=0.2, paths=('/',),
              miss_ratio=0.95, seed=21),
    LabClient('cookie_aware_scanner', AUTOMATED, requests=150, gap=0.2, paths=('/',),
              miss_ratio=0.95, seed=22),
    LabClient('patient_scanner', AUTOMATED, requests=200, gap=0.4, paths=('/',),
              miss_ratio=0.9, probes_after_pass=True, seed=23),
    LabClient('challenge_loop_bot', AUTOMATED, keeps_cookies=False, requests=200,
              gap=0.1, paths=('/',), miss_ratio=0.9, seed=24),
    LabClient('distributed_scanner', AUTOMATED, keeps_cookies=False, requests=30,
              gap=1.0, paths=('/',), miss_ratio=0.95, seed=25),
    LabClient('slow_scanner', AUTOMATED, keeps_cookies=False, requests=90, gap=20.0,
              paths=('/',), miss_ratio=0.95, seed=26),
)

CLIENTS_BY_NAME = {client.name: client for client in LAB_CLIENTS}


@dataclass
class LabResult:
    """What happened to one client. Counts only; no request is kept."""

    name: str
    intent: str
    requests: int = 0
    challenges_seen: int = 0
    challenges_passed: int = 0
    challenges_failed: int = 0
    redirects_followed: int = 0
    rate_limited: int = 0
    extra_requests: int = 0
    actions: dict = field(default_factory=dict)
    final_action: str = 'OBSERVE'
    final_risk: float = 0.0
    network_enforceable: bool = True

    @property
    def was_challenged(self):
        return self.challenges_seen > 0

    @property
    def challenge_rate(self):
        return self.challenges_seen / self.requests if self.requests else 0.0

    def explain(self):
        return {'web_lab_schema_version': WEB_LAB_SCHEMA_VERSION,
                'client': self.name, 'imitates': self.intent,
                'requests': self.requests,
                'challenges_seen': self.challenges_seen,
                'challenges_passed': self.challenges_passed,
                'challenges_failed': self.challenges_failed,
                'extra_requests': self.extra_requests,
                'rate_limited': self.rate_limited,
                'challenge_rate': round(self.challenge_rate, 4),
                'final_action': self.final_action,
                'final_risk': round(self.final_risk, 4),
                'actions': dict(self.actions),
                'note': ('imitates describes the fixture, not a judgement; it is '
                         'never a training label')}


def run(client, *, gateway, sensor, resolver, event_builder, peer,
        forwarded=None, host='example.test', start=0.0, max_extra=3):
    """Play one client against the real gateway and sensor.

    The loop is the actual challenge flow from §5: request, maybe a challenge,
    maybe a cookie, maybe the same request again. What a fixture does with the
    redirect is what separates the clients — not anything the system knows about
    them in advance.
    """
    stream = random.Random(client.seed)
    result = LabResult(client.name, client.intent)
    cookie, now = None, start

    for index in range(client.requests):
        now += client.gap
        path = client.path_for(index, stream)
        plan = gateway.handle(peer=peer, method=client.method, path=path,
                              forwarded=forwarded, cookie=cookie, host=host, now=now)
        result.requests += 1
        result.actions[plan.action] = result.actions.get(plan.action, 0) + 1
        result.network_enforceable = plan.network_enforceable

        if plan.plan == 'RATE_LIMIT':
            result.rate_limited += 1

        attempts = 0
        while plan.challenged and attempts < max_extra:
            attempts += 1
            result.challenges_seen += 1
            if not client.follows_redirects:
                result.challenges_failed += 1
                break
            if client.keeps_cookies:
                cookie = _cookie_from(plan)
            if cookie is None:
                # Offered a cookie, kept nothing. The request repeats unchanged
                # and the system sees a client that cannot complete the flow.
                result.challenges_failed += 1
                break
            # The client repeats the original request, now carrying the token.
            now += 0.3
            result.extra_requests += 1
            result.redirects_followed += 1
            plan = gateway.handle(peer=peer, method=client.method, path=path,
                                  forwarded=forwarded, cookie=cookie, host=host,
                                  now=now)
            if plan.token_outcome == 'valid':
                result.challenges_passed += 1
                break

        # The request itself is recorded either way: a challenged request is
        # still a request, and the behaviour is what the sensor judges.
        status = client.status_for(path)
        identity = resolver.resolve(peer, forwarded=forwarded)
        sensor.observe(event_builder(identity=identity, method=client.method,
                                     path=path, status=status, host=host,
                                     user_agent=client.user_agent), now)
        if cookie is not None:
            gateway.note(identity.address,
                         suspicious=(client.probes_after_pass and status == 404),
                         now=now)

        # Re-score the source, the way the running system does when it polls the
        # access log. Without this the gateway would read a risk of zero forever:
        # risk comes from history, and history is only summarised when the sensor
        # evaluates. The sensor's own interval decides how often this really
        # happens; here it is left to the harness's configuration.
        sensor.evaluate(identity.address, now)

    decision = sensor.evaluate(resolver.resolve(peer, forwarded=forwarded).address,
                               now, force=True)
    if decision is not None:
        result.final_action = decision.action
        result.final_risk = decision.risk
        result.network_enforceable = decision.network_enforceable
    return result


def _cookie_from(plan):
    """Pull the challenge cookie out of a plan, the way a browser would."""
    raw = plan.headers.get('Set-Cookie', '')
    for part in raw.split(';'):
        name, _, value = part.strip().partition('=')
        if name == COOKIE_NAME:
            return value
    return None


def summarise(results):
    """Aggregate user impact (§142) across a set of runs.

    The two numbers worth reading are the challenge rate among fixtures that
    imitate ordinary visitors, and how many of them completed a challenge when
    they got one. A high challenge rate for ordinary fixtures is a cost being
    paid by real people, whatever it buys.
    """
    ordinary = [item for item in results if item.intent == ORDINARY]
    automated = [item for item in results if item.intent == AUTOMATED]

    def rate(items, predicate):
        return round(sum(1 for item in items if predicate(item)) / len(items), 4) \
            if items else 0.0

    challenged_ordinary = [item for item in ordinary if item.was_challenged]
    return {'web_lab_schema_version': WEB_LAB_SCHEMA_VERSION,
            'clients': len(results),
            'ordinary_clients': len(ordinary),
            'automated_clients': len(automated),
            'ordinary_challenge_rate': rate(ordinary, lambda item: item.was_challenged),
            'ordinary_pass_rate': (
                round(sum(1 for item in challenged_ordinary if item.challenges_passed)
                      / len(challenged_ordinary), 4) if challenged_ordinary else None),
            'ordinary_extra_requests': sum(item.extra_requests for item in ordinary),
            'automated_challenge_rate': rate(automated, lambda item: item.was_challenged),
            'ordinary_reaching_block': rate(ordinary,
                                            lambda item: item.final_action == 'TEMP_BLOCK'),
            'automated_reaching_block': rate(automated,
                                             lambda item: item.final_action == 'TEMP_BLOCK'),
            'note': ('these are synthetic local fixtures; they measure this '
                     'configuration against these scripts, not real-world accuracy')}
