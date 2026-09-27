"""When to challenge, when not to, and how to stop it going wrong.

A challenge sits between watching and rate limiting:

    OBSERVE -> WATCH -> SOFT_CHALLENGE -> RATE_LIMIT -> TEMP_BLOCK

It is for the case the old ladder handled badly: the evidence is real, but not
strong enough to justify slowing somebody down. Rather than guess, ask for one
more piece of evidence.

Three things stop it becoming a problem of its own.

**A budget.** An attacker can trigger challenges deliberately. Per-source,
per-second and global caps mean the answer to a million triggers is a million
refusals, not a million challenges.

**Loop prevention.** A client that cannot keep a cookie — a privacy browser, a
broken proxy, a script — would otherwise cycle forever: challenge, redirect,
challenge. After a bounded number of attempts the policy stops challenging and
hands the decision back with what it learned.

**Route and method policy.** A redirect replays a request. Replaying a POST can
submit a form twice or charge a card twice, so unsafe methods are never
challenged. An API client cannot complete a cookie flow at all, so API routes
default to not being challenged either — sending an HTML page to a JSON client
breaks it while proving nothing.
"""
from collections import Counter, deque
from dataclasses import dataclass, field
import time

CHALLENGE_POLICY_VERSION = 1

#: The full ladder, in order. `SOFT_CHALLENGE` is inserted; nothing is replaced.
ACTIONS = ('OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT', 'TEMP_BLOCK')
STRENGTH = {name: index for index, name in enumerate(ACTIONS)}

#: What a challenge produced. `NOT_PRESENTED` matters as much as the rest: it is
#: the difference between "the client failed" and "we never asked".
NOT_PRESENTED = 'not_presented'
PRESENTED = 'presented'
PASSED = 'passed'
FAILED = 'failed'
TIMED_OUT = 'timed_out'
SUPPRESSED = 'suppressed'
OUTCOMES = (NOT_PRESENTED, PRESENTED, PASSED, FAILED, TIMED_OUT, SUPPRESSED)

#: Route profiles. What a route is cannot be guessed from a User-Agent, so an
#: operator configures it.
WEB_BROWSER = 'web_browser'
API = 'api'
STATIC = 'static'
ADMIN = 'admin'
AUTH = 'auth'
WEBHOOK = 'webhook'
HEALTH = 'health'
UNKNOWN = 'unknown'
PROFILES = (WEB_BROWSER, API, STATIC, ADMIN, AUTH, WEBHOOK, HEALTH, UNKNOWN)

#: Profiles a browser challenge may be used on. The rest get watched or rate
#: limited instead: a webhook or a health check cannot complete a cookie flow,
#: and an auth callback carries state a redirect would lose.
CHALLENGEABLE_PROFILES = (WEB_BROWSER, STATIC, ADMIN, UNKNOWN)

#: Methods a redirect challenge may be used on.
SAFE_METHODS = ('GET', 'HEAD')

#: Where a challenge is worth asking for. Below the floor the evidence does not
#: justify the user cost; above the ceiling there is enough to act without one.
DEFAULT_FLOOR = 0.45
DEFAULT_CEILING = 0.88


class ChallengePolicyError(ValueError):
    """A policy that does not make sense. Never raised while deciding."""


@dataclass(frozen=True)
class RouteRule:
    """One route's challenge policy. Prefix matching, not regular expressions."""

    path_prefix: str
    profile: str = WEB_BROWSER
    challenge: bool = True

    def __post_init__(self):
        if self.profile not in PROFILES:
            raise ChallengePolicyError(f'unknown route profile: {self.profile!r}')
        if not self.path_prefix.startswith('/'):
            raise ChallengePolicyError('a route prefix must start with /')


#: Defaults that keep a normal site working. API, auth, webhook and health routes
#: are not challenged, because a challenge there breaks something and proves
#: nothing.
DEFAULT_ROUTES = (
    RouteRule('/api/', API, challenge=False),
    RouteRule('/graphql', API, challenge=False),
    RouteRule('/oauth/', AUTH, challenge=False),
    RouteRule('/login', AUTH, challenge=False),
    RouteRule('/auth/', AUTH, challenge=False),
    RouteRule('/webhook', WEBHOOK, challenge=False),
    RouteRule('/webhooks/', WEBHOOK, challenge=False),
    RouteRule('/healthz', HEALTH, challenge=False),
    RouteRule('/health', HEALTH, challenge=False),
    RouteRule('/.well-known/', STATIC, challenge=False),
    RouteRule('/', WEB_BROWSER, challenge=True),
)


def match_route(path, routes=DEFAULT_ROUTES):
    """The most specific matching rule. Longest prefix wins."""
    best = None
    for rule in routes:
        if str(path or '/').startswith(rule.path_prefix):
            if best is None or len(rule.path_prefix) > len(best.path_prefix):
                best = rule
    return best or RouteRule('/', UNKNOWN, challenge=False)


@dataclass(frozen=True)
class ChallengeBudget:
    """Hard caps. Every one is a refusal, and a refusal is normal operation."""

    per_source_per_hour: int = 5
    per_second: int = 20
    concurrent_contexts: int = 10_000
    minimum_seconds_between: float = 10.0
    max_attempts: int = 3
    grace_seconds: float = 300.0
    failure_decay_seconds: float = 1800.0

    def __post_init__(self):
        if not 1 <= self.per_source_per_hour <= 1000:
            raise ChallengePolicyError('per_source_per_hour is out of range')
        if not 1 <= self.per_second <= 10_000:
            raise ChallengePolicyError('per_second is out of range')
        if not 1 <= self.concurrent_contexts <= 1_000_000:
            raise ChallengePolicyError('concurrent_contexts is out of range')
        if not 0 <= self.minimum_seconds_between <= 3600:
            raise ChallengePolicyError('minimum_seconds_between is out of range')
        if not 1 <= self.max_attempts <= 10:
            raise ChallengePolicyError('max_attempts is out of range')
        if not 0 <= self.grace_seconds <= 3600:
            raise ChallengePolicyError('grace_seconds is out of range')
        if not 60 <= self.failure_decay_seconds <= 86_400:
            raise ChallengePolicyError('failure_decay_seconds is out of range')

    def explain(self):
        return {'per_source_per_hour': self.per_source_per_hour,
                'per_second': self.per_second,
                'concurrent_contexts': self.concurrent_contexts,
                'minimum_seconds_between': self.minimum_seconds_between,
                'max_attempts': self.max_attempts,
                'grace_seconds': self.grace_seconds,
                'failure_decay_seconds': self.failure_decay_seconds}


@dataclass
class ChallengeContext:
    """What has happened to one source. Bounded, decaying, pseudonymous.

    Keyed by the resolved client from P10 — never by a session token, an account,
    or anything that would outlive the window.
    """

    key: str
    first_seen: float
    last_seen: float
    presented: int = 0
    passed: int = 0
    failed: int = 0
    timed_out: int = 0
    attempts_since_pass: int = 0
    last_presented_at: float = 0.0
    last_passed_at: float = 0.0
    #: Requests seen after the most recent pass. The signal that matters: a
    #: scanner that passes and keeps scanning has not become benign.
    requests_after_pass: int = 0
    suspicious_after_pass: int = 0
    recent: deque = field(default_factory=lambda: deque(maxlen=16))

    def in_grace(self, now, budget):
        """Recently passed, so do not ask again without new strong evidence."""
        return bool(self.last_passed_at) and (now - self.last_passed_at) < budget.grace_seconds

    def decayed_failures(self, now, budget):
        """Failures fade. One browser that could not keep a cookie last week is
        not evidence about this request."""
        if not self.recent:
            return 0.0
        total = 0.0
        for at, outcome in self.recent:
            if outcome not in (FAILED, TIMED_OUT):
                continue
            age = max(0.0, now - at)
            if age < budget.failure_decay_seconds:
                total += 1.0 - (age / budget.failure_decay_seconds)
        return total

    @property
    def pass_ratio(self):
        return (self.passed / self.presented) if self.presented else None

    def record(self, outcome, now):
        self.last_seen = now
        self.recent.append((now, outcome))
        if outcome == PRESENTED:
            self.presented += 1
            self.attempts_since_pass += 1
            self.last_presented_at = now
        elif outcome == PASSED:
            self.passed += 1
            self.attempts_since_pass = 0
            self.last_passed_at = now
            self.requests_after_pass = 0
            self.suspicious_after_pass = 0
        elif outcome == FAILED:
            self.failed += 1
        elif outcome == TIMED_OUT:
            self.timed_out += 1

    def explain(self):
        return {'presented': self.presented, 'passed': self.passed,
                'failed': self.failed, 'timed_out': self.timed_out,
                'pass_ratio': (None if self.pass_ratio is None
                               else round(self.pass_ratio, 3)),
                'attempts_since_pass': self.attempts_since_pass,
                'requests_after_pass': self.requests_after_pass,
                'suspicious_after_pass': self.suspicious_after_pass,
                'meaning': ('a challenge outcome is evidence about a web flow; it is '
                            'not identity and it is never a training label')}


class ChallengeContextTable:
    """Bounded table of challenge contexts, with TTL and LRU eviction."""

    def __init__(self, *, budget=None, ttl_seconds=3600.0):
        self.budget = budget or ChallengeBudget()
        self.ttl_seconds = max(60.0, float(ttl_seconds))
        self._contexts = {}
        self.evictions = 0
        self.expired = 0

    def __len__(self):
        return len(self._contexts)

    def get(self, key):
        return self._contexts.get(key)

    def touch(self, key, now):
        context = self._contexts.get(key)
        if context is None:
            self._make_room(now)
            context = ChallengeContext(key=key, first_seen=now, last_seen=now)
        else:
            self._contexts.pop(key)
        self._contexts[key] = context
        context.last_seen = now
        return context

    def _make_room(self, now):
        self.expire(now)
        while len(self._contexts) >= self.budget.concurrent_contexts:
            self._contexts.pop(next(iter(self._contexts)), None)
            self.evictions += 1

    def expire(self, now):
        cutoff = now - self.ttl_seconds
        stale = [key for key, item in self._contexts.items() if item.last_seen < cutoff]
        for key in stale:
            self._contexts.pop(key, None)
            self.expired += 1
        return len(stale)

    def stats(self):
        return {'challenge_policy_version': CHALLENGE_POLICY_VERSION,
                'contexts': len(self._contexts),
                'limit': self.budget.concurrent_contexts,
                'evictions': self.evictions, 'expired': self.expired}


@dataclass(frozen=True)
class ChallengeDecision:
    """Whether to challenge, and why not when the answer is no."""

    challenge: bool
    action: str
    reason: str
    profile: str = UNKNOWN
    suppressions: tuple = ()
    shadow: bool = True

    def explain(self):
        return {'challenge_policy_version': CHALLENGE_POLICY_VERSION,
                'challenge': self.challenge, 'action': self.action,
                'reason': self.reason, 'profile': self.profile,
                'suppressions': list(self.suppressions), 'shadow': self.shadow}


class ChallengeGate:
    """Decides whether a challenge is the right response to one request.

    Pure apart from the counters it keeps. It never sends anything; it answers a
    question, and the caller decides what to do with the answer.
    """

    def __init__(self, *, budget=None, routes=DEFAULT_ROUTES, floor=DEFAULT_FLOOR,
                 ceiling=DEFAULT_CEILING, shadow=True, clock=time.monotonic):
        self.budget = budget or ChallengeBudget()
        self.routes = tuple(routes)
        self.floor = float(floor)
        self.ceiling = float(ceiling)
        if not 0.0 < self.floor < self.ceiling <= 1.0:
            raise ChallengePolicyError('challenge floor must be below its ceiling')
        self.shadow = bool(shadow)
        self.clock = clock
        self.contexts = ChallengeContextTable(budget=self.budget)
        self.metrics = Counter()
        self._recent_issues = deque(maxlen=self.budget.per_second * 4)

    def _global_budget_available(self, now):
        while self._recent_issues and now - self._recent_issues[0] > 1.0:
            self._recent_issues.popleft()
        return len(self._recent_issues) < self.budget.per_second

    def _source_budget_available(self, context, now):
        recent = sum(1 for at, outcome in context.recent
                     if outcome == PRESENTED and now - at < 3600)
        return recent < self.budget.per_source_per_hour

    def decide(self, *, risk, confidence, method, path, network_enforceable,
               identity_confidence='HIGH', has_valid_token=False, source='', now=None):
        """Should this request be challenged?

        Every `no` carries a reason. An operator reading a decision record should
        never have to guess why a challenge did or did not happen.
        """
        now = self.clock() if now is None else now
        rule = match_route(path, self.routes)
        suppressions = []

        def refuse(reason, action='WATCH'):
            self.metrics['challenge_suppressed_total'] += 1
            return ChallengeDecision(False, action, reason, profile=rule.profile,
                                     suppressions=tuple(suppressions), shadow=self.shadow)

        if has_valid_token:
            # Already completed one. Asking again immediately is the loop.
            return refuse('the client already holds a valid challenge token', 'WATCH')

        if risk < self.floor:
            return refuse('risk is below the challenge floor; a challenge costs the '
                          'user something and this does not justify it', 'OBSERVE'
                          if risk < 0.4 else 'WATCH')

        if risk >= self.ceiling and confidence >= 0.7:
            # Enough evidence to act. A challenge would only delay it.
            return refuse('there is already enough evidence to act without a challenge',
                          'RATE_LIMIT')

        if method not in SAFE_METHODS:
            # A redirect replays the request. Replaying a POST can submit a form
            # or charge a card twice.
            return refuse(f'{method} is not a safe method to redirect; replaying it '
                          'could repeat a state-changing request', 'WATCH')

        if not rule.challenge:
            return refuse(f'the {rule.profile} route policy does not use browser '
                          'challenges', 'WATCH')

        context = self.contexts.touch(source, now) if source else None
        if context is not None:
            if context.in_grace(now, self.budget) and risk < self.ceiling:
                return refuse('this client passed a challenge recently and there is no '
                              'new strong evidence', 'WATCH')
            if context.attempts_since_pass >= self.budget.max_attempts:
                # The loop stops here. The client cannot or will not complete the
                # flow; that is now evidence, and asking again learns nothing.
                self.metrics['challenge_loop_prevented_total'] += 1
                return refuse(f'{context.attempts_since_pass} challenges went unanswered; '
                              'asking again would loop', 'RATE_LIMIT')
            if (context.last_presented_at
                    and now - context.last_presented_at < self.budget.minimum_seconds_between):
                return refuse('a challenge was issued moments ago', 'WATCH')
            if not self._source_budget_available(context, now):
                self.metrics['challenge_budget_rejected_total'] += 1
                return refuse('this client has reached its hourly challenge limit',
                              'RATE_LIMIT')

        if not self._global_budget_available(now):
            self.metrics['challenge_budget_rejected_total'] += 1
            return refuse('the global challenge rate limit is reached', 'WATCH')

        if identity_confidence == 'LOW':
            # A challenge is attached to a client. If we do not know which client,
            # there is nothing to attach it to.
            return refuse('the client address is not reliable enough to attach a '
                          'challenge to', 'WATCH')

        self._recent_issues.append(now)
        if context is not None:
            context.record(PRESENTED, now)
        self.metrics['challenge_issued_total'] += 1
        if self.shadow:
            self.metrics['challenge_shadow_total'] += 1
        return ChallengeDecision(True, 'SOFT_CHALLENGE',
                                 'the evidence is real but not strong enough to act on; '
                                 'a challenge asks for one more piece',
                                 profile=rule.profile, shadow=self.shadow)

    def available(self, source, *, risk, identity_confidence='HIGH',
                  has_valid_token=False, now=None):
        """Could a challenge be presented to this source? Read-only.

        `decide` answers for one request, and spends a budget slot doing it. This
        answers for a *source*, changes nothing, and creates no context. The
        distinction matters: the sensor re-evaluates every known source on a
        timer, and a question that consumed challenge budget would drain it on
        sources nobody was ever going to be asked anything.

        It deliberately cannot answer the two request-shaped questions — is the
        method safe to redirect, and does this route use challenges. Those need
        the path and the method, which exist at request time and are not kept
        afterwards; the request-time integration checks them with `decide`.

        Returns `(available, reason)`. The reason is filled in when the answer is
        no, and is written to be read by a person in a decision record.
        """
        now = self.clock() if now is None else now
        if has_valid_token:
            return False, 'the client already holds a valid challenge token'
        if risk < self.floor:
            return False, ('risk is below the challenge floor; a challenge costs the '
                           'user something and this does not justify it')
        if risk >= self.ceiling:
            return False, 'there is already enough evidence to act without a challenge'
        if identity_confidence == 'LOW':
            return False, ('the client address is not reliable enough to attach a '
                           'challenge to')
        context = self.contexts.get(source) if source else None
        if context is not None:
            if context.in_grace(now, self.budget):
                return False, ('this client passed a challenge recently and there is no '
                               'new strong evidence')
            if context.attempts_since_pass >= self.budget.max_attempts:
                return False, (f'{context.attempts_since_pass} challenges went '
                               'unanswered; asking again would loop')
            if (context.last_presented_at
                    and now - context.last_presented_at < self.budget.minimum_seconds_between):
                return False, 'a challenge was issued moments ago'
            if not self._source_budget_available(context, now):
                return False, 'this client has reached its hourly challenge limit'
        if not self._global_budget_available(now):
            return False, 'the global challenge rate limit is reached'
        return True, 'a challenge can be presented to this client'

    def record_outcome(self, source, outcome, now=None):
        """Record what a challenge produced. Never sets a label anywhere."""
        if outcome not in OUTCOMES:
            raise ChallengePolicyError(f'unknown challenge outcome: {outcome!r}')
        now = self.clock() if now is None else now
        context = self.contexts.touch(source, now) if source else None
        if context is not None:
            context.record(outcome, now)
        self.metrics['challenge_' + outcome + '_total'] += 1
        return context

    def record_activity(self, source, *, suspicious=False, now=None):
        """Note a request after a pass. The continuation signal.

        A scanner that passes a challenge and carries on enumerating has told us
        something more useful than the pass did.
        """
        now = self.clock() if now is None else now
        context = self.contexts.get(source)
        if context is None or not context.last_passed_at:
            return None
        context.requests_after_pass += 1
        context.suspicious_after_pass += int(bool(suspicious))
        context.last_seen = now
        return context

    def stats(self):
        return {**self.contexts.stats(), 'shadow': self.shadow,
                'budget': self.budget.explain(), 'metrics': dict(self.metrics)}


def evidence(context, now, budget=None):
    """Turn a challenge context into bounded behavioural features.

    None of these is a label, and `challenge_presented` is deliberately absent
    from anything a model could train on: the system presents a challenge because
    it already thought the source was suspicious, so training on "was challenged"
    teaches a model to reproduce its own earlier decision. That is a feedback
    loop, and it is documented rather than quietly avoided.
    """
    budget = budget or ChallengeBudget()
    if context is None:
        return {'challenge_presented_count': 0.0, 'challenge_pass_count': 0.0,
                'challenge_fail_count': 0.0, 'challenge_timeout_count': 0.0,
                'challenge_pass_ratio': None, 'challenge_decayed_failures': 0.0,
                'requests_after_pass': 0.0, 'suspicious_after_pass': 0.0,
                'continued_after_pass': False}
    return {'challenge_presented_count': float(context.presented),
            'challenge_pass_count': float(context.passed),
            'challenge_fail_count': float(context.failed),
            'challenge_timeout_count': float(context.timed_out),
            'challenge_pass_ratio': context.pass_ratio,
            'challenge_decayed_failures': round(context.decayed_failures(now, budget), 4),
            'requests_after_pass': float(context.requests_after_pass),
            'suspicious_after_pass': float(context.suspicious_after_pass),
            'continued_after_pass': context.suspicious_after_pass > 0}


#: The strongest action challenge evidence alone may reach.
#:
#: A challenge result is evidence, not ground truth, and the innocent
#: explanations for failing one are ordinary: scripting switched off, a privacy
#: browser, a cookie blocker, a flaky connection. So challenge history can push a
#: source up the ladder as far as rate limiting, and no further. TEMP_BLOCK stays
#: something only behavioural risk can reach — otherwise "did not complete a
#: challenge" would become "is malicious" by a different route.
CHALLENGE_ESCALATION_CEILING = 'RATE_LIMIT'


def adjust(action, context, now, budget=None):
    """How a challenge outcome changes the action. Bounded, and never to zero.

    Passing reduces nothing on its own. What reduces suspicion is passing *and*
    then behaving like somebody using the site. Continuing to probe after passing
    raises it, because it rules out the innocent explanation.

    Escalation stops at `CHALLENGE_ESCALATION_CEILING`. An action already above
    that ceiling was reached on behavioural evidence and is left alone; this
    function never lowers it and never raises it further.
    """
    budget = budget or ChallengeBudget()
    if context is None:
        return action, ()
    reasons = []
    start = level = STRENGTH.get(action, 0)
    ceiling = STRENGTH[CHALLENGE_ESCALATION_CEILING]

    def raise_to(step, reason):
        """Escalate by one step, never past the ceiling, never past the start."""
        nonlocal level
        raised = min(level + step, max(ceiling, start))
        if raised != level:
            level = raised
            reasons.append(reason)
        else:
            reasons.append(reason + ' (already at the limit for challenge evidence)')

    if context.suspicious_after_pass >= 5:
        raise_to(1, f'passed a challenge and then continued probing '
                    f'({context.suspicious_after_pass} suspicious requests since)')
    elif (context.last_passed_at and context.requests_after_pass >= 5
          and context.suspicious_after_pass == 0):
        level = max(0, level - 1)
        reasons.append('passed a challenge and has behaved normally since')

    failures = context.decayed_failures(now, budget)
    if failures >= budget.max_attempts:
        raise_to(1, f'{failures:.1f} recent challenge failures (decayed)')

    return ACTIONS[level], tuple(reasons)
