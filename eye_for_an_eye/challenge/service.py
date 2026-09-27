"""The challenge service: the one object a caller needs, and its failure rule.

Everything else in this package is a pure function or a bounded table. This is
where they are assembled, where the secret lives, and where one rule is enforced
that matters more than any feature here:

    **A broken challenge subsystem must never take the website down.**

That is not a nice-to-have. A security tool that returns 500 to every visitor
when its own optional component fails has caused a worse outage than the attack
it was watching for. So every entry point catches its own failures, counts them,
and returns "do not challenge" — which means the request proceeds normally.

The one exception is deliberate and narrow: an existing high-confidence
TEMP_BLOCK decided elsewhere is not weakened by anything here. Challenge
infrastructure is allowed to fail open; it is not allowed to reach into a
decision that was already made without it.
"""
from collections import Counter
from pathlib import Path
import time

from . import page as page_module
from . import policy as policy_module
from . import token as token_module

CHALLENGE_SERVICE_VERSION = 1

SHADOW = 'shadow'
ACTIVE = 'active'
DISABLED = 'disabled'
MODES = (SHADOW, ACTIVE, DISABLED)


class ChallengeServiceError(Exception):
    """The service could not be built. Never raised while handling a request."""


def load_secret(path):
    """Read a local secret file, refusing one that is weak or world-readable."""
    if not path:
        return None
    target = Path(path)
    try:
        data = target.read_bytes().strip()
        mode = target.stat().st_mode
    except OSError as exc:
        raise ChallengeServiceError(f'cannot read the challenge secret: {exc}') from exc
    if len(data) < token_module.MASTER_SECRET_MIN_BYTES:
        raise ChallengeServiceError(
            f'the challenge secret must be at least '
            f'{token_module.MASTER_SECRET_MIN_BYTES} bytes')
    if mode & 0o077:
        raise ChallengeServiceError(
            f'the challenge secret is readable by other users; chmod 600 {path}')
    return data


class ChallengeService:
    """Decides, issues and verifies challenges. Fails open, always."""

    def __init__(self, *, secret=None, previous_secret=None, mode=SHADOW,
                 site_id='default', ttl_seconds=token_module.DEFAULT_TTL_SECONDS,
                 cookie_secure=True, cookie_same_site='Lax', cookie_path='/',
                 gate=None, clock=time.monotonic, wall_clock=time.time):
        if mode not in MODES:
            raise ChallengeServiceError(f'unknown challenge mode: {mode!r}')
        self.secret = secret
        self.previous_secret = previous_secret
        self.mode = mode if secret else DISABLED
        self.site_id = token_module.normalise_site(site_id)
        self.ttl_seconds = int(ttl_seconds)
        self.cookie_secure = bool(cookie_secure)
        self.cookie_same_site = cookie_same_site
        self.cookie_path = cookie_path
        self.gate = gate or policy_module.ChallengeGate(shadow=(self.mode != ACTIVE),
                                                        clock=clock)
        self.clock = clock
        self.wall_clock = wall_clock
        self.metrics = Counter()
        self.last_error = ''

    @property
    def enabled(self):
        return self.mode in (SHADOW, ACTIVE) and self.secret is not None

    @property
    def shadow(self):
        return self.mode != ACTIVE

    def _fail(self, where, exc):
        """Record a subsystem failure and carry on. Never re-raise."""
        self.metrics['challenge_subsystem_errors_total'] += 1
        self.last_error = f'{where}: {type(exc).__name__}'
        return None

    # --- verifying what a client sent -----------------------------------

    def verify_cookie(self, cookie_value, *, now=None):
        """Check a presented token. Any failure reads as "no valid token"."""
        if not self.enabled or not cookie_value:
            return None
        try:
            return token_module.verify(
                cookie_value, self.secret, site=self.site_id,
                now=self.wall_clock() if now is None else now,
                previous_secret=self.previous_secret)
        except Exception as exc:
            return self._fail('verify', exc)

    def observe_token(self, source, verification, *, now=None):
        """Turn a verification into a challenge outcome. Evidence, not a verdict."""
        if verification is None or not self.enabled:
            return None
        try:
            if verification.valid:
                return self.gate.record_outcome(source, policy_module.PASSED, now=now)
            outcome = (policy_module.TIMED_OUT
                       if verification.outcome == token_module.EXPIRED
                       else policy_module.FAILED)
            self.metrics['challenge_' + verification.outcome + '_total'] += 1
            return self.gate.record_outcome(source, outcome, now=now)
        except Exception as exc:
            return self._fail('observe', exc)

    # --- deciding and responding ----------------------------------------

    def consider(self, *, risk, confidence, method, path, source,
                 identity_confidence='HIGH', network_enforceable=True,
                 has_valid_token=False, now=None):
        """Should this request be challenged? A failure here means "no"."""
        if not self.enabled:
            return policy_module.ChallengeDecision(
                False, 'WATCH', 'the challenge subsystem is not enabled',
                shadow=True)
        try:
            return self.gate.decide(
                risk=risk, confidence=confidence, method=method, path=path,
                network_enforceable=network_enforceable,
                identity_confidence=identity_confidence,
                has_valid_token=has_valid_token, source=source, now=now)
        except Exception as exc:
            self._fail('decide', exc)
            # Fail open: the request proceeds and the source stays watched.
            return policy_module.ChallengeDecision(
                False, 'WATCH', 'the challenge subsystem failed; the request was not '
                'challenged and the site was not affected', shadow=True)

    def available(self, source, *, risk, identity_confidence='HIGH',
                  has_valid_token=False, now=None):
        """Could this source be challenged? Read-only, and never raises.

        A failure answers "no", which degrades a proposed SOFT_CHALLENGE back to
        WATCH. That is the safe direction: a broken challenge subsystem costs
        detection, never availability.
        """
        if not self.enabled:
            return False, 'the challenge subsystem is not enabled'
        try:
            moment = self.clock() if now is None else now
            return self.gate.available(
                source, risk=risk, identity_confidence=identity_confidence,
                has_valid_token=has_valid_token, now=moment)
        except Exception as exc:
            self._fail('available', exc)
            return False, ('the challenge subsystem failed; no challenge was presented '
                           'and the site was not affected')

    def respond(self, return_path='/', *, now=None):
        """Build the challenge response, or None if anything goes wrong."""
        if not self.enabled:
            return None
        try:
            issued = token_module.issue(
                self.secret, site=self.site_id, ttl_seconds=self.ttl_seconds,
                now=self.wall_clock() if now is None else now)
            response = page_module.build(
                issued, return_path, secure=self.cookie_secure,
                max_age=self.ttl_seconds, cookie_path=self.cookie_path,
                same_site=self.cookie_same_site, shadow=self.shadow)
            self.metrics['challenge_issued_total'] += 1
            if self.shadow:
                self.metrics['challenge_shadow_total'] += 1
            return response
        except Exception as exc:
            return self._fail('respond', exc)

    def note_activity(self, source, *, suspicious=False, now=None):
        """Record what a source did after passing. The continuation signal."""
        if not self.enabled:
            return None
        try:
            return self.gate.record_activity(source, suspicious=suspicious, now=now)
        except Exception as exc:
            return self._fail('activity', exc)

    # --- reporting -------------------------------------------------------

    def evidence(self, source, *, now=None):
        """Bounded challenge features for one source."""
        if not self.enabled:
            return policy_module.evidence(None, 0.0)
        try:
            moment = self.clock() if now is None else now
            return policy_module.evidence(self.gate.contexts.get(source), moment,
                                          self.gate.budget)
        except Exception as exc:
            self._fail('evidence', exc)
            return policy_module.evidence(None, 0.0)

    def adjust(self, action, source, *, now=None):
        """How a source's challenge history changes an action."""
        if not self.enabled:
            return action, ()
        try:
            moment = self.clock() if now is None else now
            return policy_module.adjust(action, self.gate.contexts.get(source), moment,
                                        self.gate.budget)
        except Exception as exc:
            self._fail('adjust', exc)
            return action, ()

    def review_priority(self, source, risk, *, now=None):
        """Is this worth a person's time? Feeds the P8/P9 review queue (§44).

        The interesting cases are the ones the numbers cannot settle. Note that
        two of them point in opposite directions — a scanner that defeated the
        challenge, and an ordinary visitor the system keeps interrupting. Both
        belong in front of a person, and only a person can tell them apart. That
        is the whole reason this returns a priority and not a label.
        """
        context = self.gate.contexts.get(source) if self.enabled else None
        if context is None:
            return 0.0, ()
        try:
            moment = self.clock() if now is None else now
            priority, reasons = 0.0, []

            # Passed, then carried on probing. The innocent reading is ruled out.
            if context.suspicious_after_pass >= 3:
                priority += 2.0
                reasons.append(f'passed a challenge and continued probing '
                               f'({context.suspicious_after_pass} suspicious requests since)')

            # Strong evidence on both sides at once.
            if risk >= 0.7 and context.passed:
                priority += 1.0
                reasons.append('high risk despite passing a challenge')
            if risk >= 0.7 and context.failed and not context.passed:
                priority += 0.75
                reasons.append('high risk and no challenge ever completed')

            # The false-positive shape: unremarkable behaviour, asked repeatedly.
            if context.presented >= 3 and not context.passed and risk < 0.6:
                priority += 1.5
                reasons.append('challenged repeatedly without passing, on moderate '
                               'evidence; this may be a false positive')

            # A client that cannot get through the flow at all. Worth seeing
            # whether the flow is broken rather than the client.
            if context.attempts_since_pass >= self.gate.budget.max_attempts:
                priority += 0.5
                reasons.append(f'{context.attempts_since_pass} challenges in a row went '
                               'unanswered; the flow itself may be broken for this client')

            failures = context.decayed_failures(moment, self.gate.budget)
            if failures >= self.gate.budget.max_attempts:
                priority += 0.75
                reasons.append(f'{failures:.1f} recent challenge failures')
            return round(priority, 4), tuple(reasons)
        except Exception as exc:
            self._fail('review_priority', exc)
            return 0.0, ()

    def health(self):
        document = {'challenge_service_version': CHALLENGE_SERVICE_VERSION,
                    'token_scheme': token_module.TOKEN_SCHEME,
                    'enabled': self.enabled, 'mode': self.mode,
                    'shadow': self.shadow, 'site_id': self.site_id,
                    'token_ttl_seconds': self.ttl_seconds,
                    'rotation_active': self.previous_secret is not None,
                    'last_error': self.last_error,
                    'metrics': dict(self.metrics)}
        if self.enabled:
            document.update(self.gate.stats())
        # The secret never appears, in any form, at any level.
        return document


def from_config(config, *, clock=time.monotonic, wall_clock=time.time):
    """Build a service from configuration, or a disabled one.

    A misconfiguration disables challenges and says why. It never stops the
    sensor: an optional component that refuses to start must not become a reason
    the website is unprotected.
    """
    settings = getattr(config, 'challenge', None)
    if settings is None or not settings.enabled:
        return ChallengeService(secret=None, mode=DISABLED, clock=clock,
                                wall_clock=wall_clock)
    try:
        secret = load_secret(settings.secret_file)
        previous = load_secret(settings.previous_secret_file)
    except ChallengeServiceError:
        service = ChallengeService(secret=None, mode=DISABLED, clock=clock,
                                   wall_clock=wall_clock)
        service.last_error = 'the challenge secret could not be loaded'
        service.metrics['challenge_subsystem_errors_total'] += 1
        return service
    if secret is None:
        service = ChallengeService(secret=None, mode=DISABLED, clock=clock,
                                   wall_clock=wall_clock)
        service.last_error = 'no challenge.secret_file is configured'
        return service

    routes = list(policy_module.DEFAULT_ROUTES)
    for prefix in getattr(settings, 'api_path_prefixes', ()) or ():
        routes.insert(0, policy_module.RouteRule(str(prefix), policy_module.API, False))
    for prefix in getattr(settings, 'no_challenge_path_prefixes', ()) or ():
        routes.insert(0, policy_module.RouteRule(str(prefix), policy_module.UNKNOWN, False))

    budget = policy_module.ChallengeBudget(
        per_source_per_hour=settings.max_per_source_per_hour,
        per_second=settings.max_per_second,
        concurrent_contexts=settings.max_contexts,
        minimum_seconds_between=settings.minimum_seconds_between,
        max_attempts=settings.max_attempts,
        grace_seconds=settings.grace_seconds,
        failure_decay_seconds=settings.failure_decay_seconds)
    gate = policy_module.ChallengeGate(
        budget=budget, routes=tuple(routes), floor=settings.risk_floor,
        ceiling=settings.risk_ceiling, shadow=(settings.mode != ACTIVE), clock=clock)
    return ChallengeService(
        secret=secret, previous_secret=previous, mode=settings.mode,
        site_id=settings.site_id, ttl_seconds=settings.token_ttl_seconds,
        cookie_secure=settings.cookie_secure, cookie_same_site=settings.cookie_same_site,
        cookie_path=settings.cookie_path, gate=gate, clock=clock, wall_clock=wall_clock)
