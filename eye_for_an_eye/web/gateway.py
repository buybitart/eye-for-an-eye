"""The request-time decision point: one HTTP request in, one response plan out.

P10 reads an Nginx access log, which means it sees a request *after* it has been
answered. That is fine for judging behaviour and it is why the sensor is safe by
construction — it cannot break a request it never touched. A challenge is
different: it has to be decided while the request is still in flight.

So this module is a second position in the system, and the split of
responsibilities between the two is the important part:

    the sensor  →  what has this source been doing?      (history, from logs)
    the gateway →  what should happen to this request?   (now, per request)

Risk comes from history. The challenge applies to the request in hand. The
gateway never computes risk itself and never blocks anything; it asks the
challenge policy a question about one request and returns a plan.

Three rules hold everywhere in this file:

**It fails open.** Every path that could raise is caught, and the answer to a
failure is always "let the request through". A security component that turns its
own bug into a site-wide 500 has caused a worse outage than the scanner it was
watching for. `handle` is written so that the only way out is a response plan.

**It never blocks a proxy.** Client identity comes from the P10 resolver and
nothing else. A forwarded header from an untrusted peer is ignored, and a
proxied client is never network-enforceable — but it *can* be challenged, because
a challenge travels over HTTP to the one client that asked for it.

**It answers, it does not enforce.** The return value is a plan. Whatever calls
this decides what to do with it, and in shadow mode the plan says PASS with a
note about what would have happened.
"""
from collections import Counter
from dataclasses import dataclass, field
import time

from ..challenge import page as page_module
from ..challenge import policy as policy_module
from ..challenge import token as token_module

WEB_GATEWAY_SCHEMA_VERSION = 1

#: What the caller should do with the request.
PASS = 'PASS'
CHALLENGE = 'CHALLENGE'
RATE_LIMIT = 'RATE_LIMIT'
PLANS = (PASS, CHALLENGE, RATE_LIMIT)


@dataclass
class GatewayPlan:
    """What to do with one request, and why.

    `plan` is the instruction. `action` is the ladder rung this request sits on,
    which is not the same thing: a request can sit on SOFT_CHALLENGE and still be
    told to PASS, because the budget was spent or because the site is in shadow
    mode. Keeping both means an operator can see the difference.
    """

    plan: str = PASS
    action: str = 'OBSERVE'
    reason: str = ''
    source: str = ''
    identity_confidence: str = 'HIGH'
    network_enforceable: bool = True
    risk: float = 0.0
    profile: str = policy_module.UNKNOWN
    shadow: bool = True
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ''
    token_outcome: str = ''
    suppressions: tuple = ()

    @property
    def challenged(self):
        return self.plan == CHALLENGE and self.status > 0

    def explain(self):
        """Everything except the parts that must never be written down.

        `Set-Cookie` carries the token. It is dropped here on purpose: this
        document goes to logs, to the incident view and to an operator's
        terminal, and a token in any of those is a live bypass sitting in a file.
        """
        headers = {name: value for name, value in self.headers.items()
                   if name.lower() != 'set-cookie'}
        return {'web_gateway_schema_version': WEB_GATEWAY_SCHEMA_VERSION,
                'plan': self.plan, 'action': self.action, 'reason': self.reason,
                'source': self.source,
                'identity_confidence': self.identity_confidence,
                'network_enforceable': self.network_enforceable,
                'web_risk': round(self.risk, 6), 'route_profile': self.profile,
                'shadow': self.shadow, 'status': self.status,
                'headers': headers,
                'token_outcome': self.token_outcome,
                'suppressions': list(self.suppressions)}


class WebGateway:
    """Decides what happens to one request. Fails open on every path.

    The sensor is optional: without one, every source has a risk of zero and no
    request is ever challenged, which is the correct behaviour for a gateway that
    has nothing to base a judgement on.
    """

    def __init__(self, *, resolver, challenge=None, sensor=None,
                 clock=time.monotonic):
        self.resolver = resolver
        self.challenge = challenge
        self.sensor = sensor
        self.clock = clock
        self.metrics = Counter()
        self.last_error = ''

    def _fail(self, where, exc):
        self.metrics['challenge_subsystem_errors_total'] += 1
        self.last_error = f'{where}: {type(exc).__name__}'

    def risk_for(self, source):
        """The most recent risk this source scored, or zero.

        Zero for an unknown source is deliberate. A client the system has never
        seen has earned no suspicion, and a gateway that challenged strangers by
        default would challenge every first-time visitor to the site.
        """
        if self.sensor is None:
            return 0.0
        try:
            return float(self.sensor.last_risk(source))
        except Exception as exc:
            self._fail('risk', exc)
            return 0.0

    def handle(self, *, peer, method, path, forwarded=None, cookie=None,
               host='', now=None):
        """Decide one request. Always returns a plan; never raises."""
        now = self.clock() if now is None else now
        try:
            return self._handle(peer=peer, method=method, path=path,
                                forwarded=forwarded, cookie=cookie, host=host,
                                now=now)
        except Exception as exc:
            self._fail('handle', exc)
            return GatewayPlan(
                plan=PASS, action='OBSERVE', source='',
                reason=('the challenge subsystem failed; the request was passed '
                        'through and the site was not affected'))

    def _handle(self, *, peer, method, path, forwarded, cookie, host, now):
        identity = self.resolver.resolve(peer, forwarded=forwarded)
        source = identity.address
        plan = GatewayPlan(
            source=source, identity_confidence=identity.confidence,
            network_enforceable=identity.network_enforceable,
            risk=self.risk_for(source), shadow=True,
            reason='no challenge subsystem is configured')

        service = self.challenge
        if service is None or not getattr(service, 'enabled', False):
            return plan
        plan.shadow = service.shadow

        # 1. What did the client bring with it?
        verification = service.verify_cookie(cookie, now=now) if cookie else None
        has_token = bool(verification and verification.valid)
        if verification is not None:
            plan.token_outcome = verification.outcome
            service.observe_token(source, verification, now=now)
            self.metrics['challenge_' + ('passed' if has_token else 'failed') + '_total'] += 1

        # 2. Should this request be challenged? The policy owns this answer, and
        #    it is the only call here that spends challenge budget.
        decision = service.consider(
            risk=plan.risk, confidence=_confidence(identity.confidence),
            method=method, path=path, source=source,
            identity_confidence=identity.confidence,
            network_enforceable=identity.network_enforceable,
            has_valid_token=has_token, now=now)
        plan.action = decision.action
        plan.reason = decision.reason
        plan.profile = decision.profile
        plan.suppressions = decision.suppressions

        if not decision.challenge:
            # The policy said no, and its reason is already on the plan. A `no`
            # here is ordinary: most requests are never challenged.
            if decision.action == 'RATE_LIMIT' and not service.shadow:
                return self._rate_limit(plan)
            return plan

        # 3. Build the response. If anything goes wrong, the request passes.
        response = service.respond(return_path=path, now=now)
        if response is None:
            plan.plan = PASS
            plan.reason = ('the challenge could not be built; the request was passed '
                           'through and the site was not affected')
            return plan
        if response.shadow or response.status == 0:
            plan.plan = PASS
            plan.reason = ('challenge shadow mode: this request would have been '
                           'challenged and was not')
            self.metrics['challenge_shadow_total'] += 1
            return plan
        if method not in page_module.SAFE_METHODS:
            # Belt and braces. `consider` already refuses unsafe methods; if that
            # ever stops being true, a redirect must still not replay a POST.
            plan.plan = PASS
            plan.reason = (f'{method} is not safe to redirect; the request was passed '
                           'through unchanged')
            return plan
        plan.plan = CHALLENGE
        plan.status = response.status
        plan.headers = dict(response.headers)
        plan.body = response.body
        self.metrics['challenge_issued_total'] += 1
        return plan

    def _rate_limit(self, plan):
        response = page_module.rate_limited()
        plan.plan = RATE_LIMIT
        plan.status = response.status
        plan.headers = dict(response.headers)
        plan.body = response.body
        self.metrics['challenge_budget_rejected_total'] += 1
        return plan

    def note(self, source, *, suspicious=False, now=None):
        """Record what a source did after passing. The continuation signal (§42)."""
        if self.challenge is None:
            return None
        return self.challenge.note_activity(source, suspicious=suspicious, now=now)

    def health(self):
        document = {'web_gateway_schema_version': WEB_GATEWAY_SCHEMA_VERSION,
                    'token_scheme': token_module.TOKEN_SCHEME,
                    'last_error': self.last_error,
                    'metrics': dict(self.metrics)}
        if self.challenge is not None:
            document['challenge'] = self.challenge.health()
        return document


def _confidence(identity_confidence):
    """Identity confidence as a number, for the policy's confidence argument."""
    return {'HIGH': 0.9, 'MEDIUM': 0.6, 'LOW': 0.2}.get(identity_confidence, 0.2)
