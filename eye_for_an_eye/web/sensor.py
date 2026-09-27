"""The web sensor: log lines in, decisions out, and one rule about enforcement.

This is where the pieces meet. It owns the log source, the bounded per-source
table, the feature extractor and the deterministic risk engine, and it produces
a decision record in the same shape the network side produces.

The rule it enforces, and the reason this module exists rather than the caller
wiring things up itself:

    A source whose address is not the machine that connected to us may never
    reach TEMP_BLOCK.

Behind a reverse proxy or a CDN, the address we know is a client the proxy told
us about. A network-level block would hit the proxy, and the proxy is carrying
every other visitor. So the action is capped at RATE_LIMIT and the reason says
why — the difference between a defence and an outage.
"""
from collections import Counter
from dataclasses import dataclass, field
import time

from .features import DEFAULT_EXPECTED_METHODS, extract
from .risk import WebMathRisk
from .state import WebSourceTable

WEB_DECISION_SCHEMA_VERSION = 1

#: The same ladder the network side uses, so one report reads consistently.
#: P11 inserts SOFT_CHALLENGE between WATCH and RATE_LIMIT. Nothing was removed:
#: a deployment with challenges switched off sees exactly the P10 ladder.
ACTIONS = ('OBSERVE', 'WATCH', 'SOFT_CHALLENGE', 'RATE_LIMIT', 'TEMP_BLOCK')
WATCH_THRESHOLD = 0.40
#: Where asking is worth its cost to the visitor. Below this a challenge is an
#: interruption for nothing; above RATE_LIMIT_THRESHOLD the evidence is already
#: strong enough that asking politely is not the proportionate answer.
CHALLENGE_THRESHOLD = 0.45
RATE_LIMIT_THRESHOLD = 0.70
BLOCK_THRESHOLD = 0.88

#: Below this many requests, the strongest action available is WATCH. Acting on
#: a handful of requests is acting on noise.
MINIMUM_REQUESTS_FOR_ACTION = 20

#: How often a source is re-evaluated. Feature updates are cheap and run per
#: request; scoring does not need to.
DEFAULT_EVALUATION_INTERVAL = 5.0


@dataclass
class WebDecision:
    """One source's web behaviour, judged, with everything needed to explain it."""

    source: str
    action: str
    proposed_action: str
    risk: float
    scope: str
    identity_confidence: str
    network_enforceable: bool
    reasons: tuple = ()
    suppressions: tuple = ()
    contributions: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)
    observations: int = 0
    families: int = 0
    data_quality: float = 1.0
    enforced: bool = False
    shadow: bool = True
    #: Bounded challenge counters for this source. Empty when challenges are off.
    challenge: dict = field(default_factory=dict)
    #: Why a challenge was or was not presented, in words, for the incident view.
    challenge_reason: str = ''

    def explain(self):
        return {'web_decision_schema_version': WEB_DECISION_SCHEMA_VERSION,
                'source': self.source, 'action': self.action,
                'proposed_action': self.proposed_action,
                'web_risk': round(self.risk, 6), 'scope': self.scope,
                'identity_confidence': self.identity_confidence,
                'network_enforceable': self.network_enforceable,
                'observations': self.observations,
                'evidence_families': self.families,
                'data_quality': round(self.data_quality, 4),
                'reasons': list(self.reasons),
                'suppressions': list(self.suppressions),
                'contributions': dict(self.contributions),
                'challenge': dict(self.challenge),
                'challenge_reason': self.challenge_reason,
                'enforced': self.enforced, 'shadow': self.shadow}


def data_quality(features, reader_stats=None, identity_confidence='HIGH'):
    """How much this judgement can be relied on, before any of it is used.

    Four things reduce it, and each is a real reason to be less sure: too few
    requests, too short a window, dropped log lines, and an uncertain client
    address. Low quality does not mean innocent — it means the system should not
    take a strong action on what it has.
    """
    score = 1.0
    reasons = []
    if features.observations < MINIMUM_REQUESTS_FOR_ACTION:
        score *= max(0.2, features.observations / MINIMUM_REQUESTS_FOR_ACTION)
        reasons.append(f'only {features.observations} requests observed')
    if features.observation_seconds < 10:
        score *= 0.7
        reasons.append('the observation window is very short')
    if reader_stats is not None:
        total = max(1, reader_stats.lines_read)
        lost = reader_stats.parse_errors + reader_stats.oversized
        if lost / total > 0.05:
            score *= max(0.3, 1.0 - lost / total)
            reasons.append(f'{lost} of {total} log lines could not be read')
    if identity_confidence == 'MEDIUM':
        score *= 0.8
        reasons.append('the client address came from a partly trusted proxy chain')
    elif identity_confidence == 'LOW':
        score *= 0.4
        reasons.append('the client address could not be established')
    if features.saturated_paths:
        reasons.append('the distinct-path counter is saturated; the real count is higher')
    return min(1.0, max(0.0, score)), tuple(reasons)


def propose(risk):
    """The action the evidence alone suggests, before any policy is applied.

    SOFT_CHALLENGE occupies a band that used to be WATCH. It is not a stronger
    action dressed up as a gentle one: it is the system saying it does not know,
    and asking a question a browser answers by itself. If no challenge subsystem
    is available, `apply_policy` turns it back into WATCH, which is exactly the
    behaviour a deployment without challenges had before.
    """
    if risk >= BLOCK_THRESHOLD:
        return 'TEMP_BLOCK'
    if risk >= RATE_LIMIT_THRESHOLD:
        return 'RATE_LIMIT'
    if risk >= CHALLENGE_THRESHOLD:
        return 'SOFT_CHALLENGE'
    if risk >= WATCH_THRESHOLD:
        return 'WATCH'
    return 'OBSERVE'


def apply_policy(proposed, *, identity_confidence, network_enforceable, observations,
                 quality, minimum_quality=0.5, shadow=True, challenge_available=False,
                 challenge_refusal=''):
    """Reduce an action when acting on it would be unsafe. Never raise one.

    Every path here can only make the action weaker. That is deliberate: a bug in
    this function should cost detection, never availability.
    """
    strength = {name: index for index, name in enumerate(ACTIONS)}
    ceilings, suppressions = [], []

    def cap(limit, reason):
        """Record a reason whenever the rule applies, whether or not it binds.

        Reporting only the first rule that fired would show an operator one of
        three problems and hide the other two. The action is the lowest ceiling;
        the explanation is all of them.
        """
        if strength[proposed] > strength[limit]:
            ceilings.append(limit)
            suppressions.append(reason)

    # A challenge nobody can present is not an action; it is a promise the system
    # cannot keep. Degrading it to WATCH is the honest answer and restores exactly
    # the ladder a deployment without challenges already had.
    if proposed == 'SOFT_CHALLENGE' and not challenge_available:
        cap('WATCH', challenge_refusal or 'no challenge could be presented to this source')

    if observations < MINIMUM_REQUESTS_FOR_ACTION:
        cap('WATCH', f'fewer than {MINIMUM_REQUESTS_FOR_ACTION} requests observed')

    if quality < minimum_quality:
        cap('WATCH', f'data quality {quality:.2f} is below {minimum_quality:.2f}')

    # The rule that keeps a site online. Note where the ceiling sits: RATE_LIMIT,
    # not WATCH. A challenge travels over HTTP to the client that asked, so it is
    # safe precisely where a network block is not — behind a proxy it reaches the
    # one visitor and no one else.
    if not network_enforceable:
        cap('RATE_LIMIT',
            'the client is behind a proxy; blocking its address at the network layer '
            'would hit the proxy and every other visitor behind it')

    if identity_confidence == 'LOW':
        cap('WATCH', 'the client address is not reliable enough to act on')

    if not ceilings:
        return proposed, ()
    action = min(ceilings, key=lambda name: strength[name])
    return action, tuple(suppressions)


class WebSensor:
    """Reads a local web log and judges source behaviour. Blocks nothing itself.

    The sensor never touches a firewall. It produces decisions; whether anything
    is done about them is the enforcement layer's business, and in shadow mode
    the answer is always no.
    """

    def __init__(self, source, *, risk=None, table=None, shadow=True,
                 expected_methods=DEFAULT_EXPECTED_METHODS,
                 evaluation_interval=DEFAULT_EVALUATION_INTERVAL,
                 minimum_quality=0.5, challenge=None, clock=time.monotonic):
        self.source = source
        #: Optional. `None` means every SOFT_CHALLENGE degrades to WATCH and the
        #: sensor behaves exactly as it did before challenges existed.
        self.challenge = challenge
        self.risk = risk or WebMathRisk()
        self.table = table or WebSourceTable()
        self.shadow = bool(shadow)
        self.expected_methods = tuple(expected_methods)
        self.evaluation_interval = max(0.0, float(evaluation_interval))
        self.minimum_quality = float(minimum_quality)
        self.clock = clock
        self.metrics = Counter()
        self._last_evaluated = {}
        #: The last risk each source scored. Read by the request-time gateway,
        #: which must not re-score anything: judging a source is history work and
        #: does not belong on the path of a request that is waiting.
        self._last_risk = {}

    def observe(self, event, now=None):
        """Record one request. Cheap: counters only, no scoring."""
        now = self.clock() if now is None else now
        state = self.table.observe(event, now)
        if state is not None:
            self.metrics['web_requests_analyzed_total'] += 1
        return state

    def poll(self, now=None):
        """Read whatever the log has, record it, and judge the sources that moved.

        Scoring is scheduled, not per request. A busy site produces thousands of
        requests a second and its behaviour does not change thousands of times a
        second.
        """
        now = self.clock() if now is None else now
        events = self.source.poll() if self.source is not None else []
        self.metrics['web_events_total'] += len(events)
        touched = set()
        for event in events:
            state = self.observe(event, now)
            if state is not None:
                touched.add(state.key)
        decisions = [decision for decision in
                     (self.evaluate(key, now) for key in sorted(touched))
                     if decision is not None]
        self._forget_evicted()
        return decisions

    def _forget_evicted(self):
        """Drop bookkeeping for sources the bounded table has already evicted.

        The source table has a capacity and a TTL; these two dictionaries did
        not, so on a busy site they would have grown for as long as the process
        ran — one entry per address ever seen. That is the exact unbounded-state
        failure the source table exists to prevent, reintroduced beside it.

        Pruning is skipped while the dictionaries are within the table's own
        capacity, so the normal case costs nothing.
        """
        limit = getattr(self.table, 'max_sources', 4096)
        if len(self._last_evaluated) <= limit and len(self._last_risk) <= limit:
            return
        live = {key for key in self._last_evaluated if self.table.get(key) is not None}
        live |= {key for key in self._last_risk if self.table.get(key) is not None}
        self._last_evaluated = {key: value for key, value in self._last_evaluated.items()
                                if key in live}
        self._last_risk = {key: value for key, value in self._last_risk.items()
                           if key in live}
        self.metrics['web_sensor_state_pruned_total'] += 1

    def due(self, key, now):
        last = self._last_evaluated.get(key)
        return last is None or (now - last) >= self.evaluation_interval

    def evaluate(self, key, now=None, *, force=False):
        """Judge one source, or return None if it is not due yet."""
        now = self.clock() if now is None else now
        state = self.table.get(key)
        if state is None:
            return None
        if not force and not self.due(key, now):
            return None
        self._last_evaluated[key] = now

        features = extract(state, now, expected_methods=self.expected_methods)
        result = self.risk.evaluate(features)
        confidence = self._confidence(state)
        enforceable = self._enforceable(state)
        quality, quality_reasons = data_quality(
            features, getattr(self.source, 'stats', None), confidence)

        proposed = propose(result.score)
        proposed, challenge_notes, challenge_features, challenge_reason, available = \
            self._challenge(key, proposed, result.score, confidence, now)

        action, suppressions = apply_policy(
            proposed, identity_confidence=confidence, network_enforceable=enforceable,
            observations=features.observations, quality=quality,
            minimum_quality=self.minimum_quality, shadow=self.shadow,
            challenge_available=available, challenge_refusal=challenge_reason)

        if self.shadow and action in ('RATE_LIMIT', 'TEMP_BLOCK'):
            suppressions = (*suppressions, 'shadow mode: nothing was enforced')

        self._last_risk[key] = result.score
        # Prune here as well as in `poll`. These two dictionaries are keyed by
        # client address, so they are attacker-growable; relying on `poll` alone
        # meant the bound held only for callers that happen to use it, which is
        # an invariant maintained by convention rather than by the code.
        self._forget_evicted()
        self.metrics['web_risk_decisions_total'] += 1
        self.metrics['web_' + action.lower() + '_total'] += 1
        if proposed == 'TEMP_BLOCK' and self.shadow:
            self.metrics['web_shadow_would_block_total'] += 1
        if confidence == 'LOW':
            self.metrics['proxy_identity_uncertain_total'] += 1

        return WebDecision(
            source=key, action=action, proposed_action=proposed, risk=result.score,
            scope=self._scope(enforceable, confidence),
            identity_confidence=confidence, network_enforceable=enforceable,
            reasons=tuple(result.reasons) + quality_reasons + challenge_notes,
            suppressions=suppressions,
            contributions={name: round(value, 5)
                           for name, value in result.contributions.items() if value > 0},
            features=features.explain()['values'], observations=features.observations,
            families=result.families, data_quality=quality, enforced=False,
            shadow=self.shadow, challenge=challenge_features,
            challenge_reason=challenge_reason)

    def _challenge(self, key, proposed, risk, confidence, now):
        """Fold challenge history into the proposal, and ask if one is possible.

        Two separate things happen here and it is worth keeping them apart:

        * `adjust` uses what this source *did* about earlier challenges. That is
          evidence and it moves the proposed action, up or down, within a ceiling
          the challenge layer sets for itself.
        * `available` asks whether a challenge could be presented at all. It is
          read-only and spends no budget, because the sensor asks this about every
          known source on a timer, and most of them will never be challenged.

        With no challenge service configured this returns the proposal untouched
        and `available=False`, which turns a proposed SOFT_CHALLENGE back into
        WATCH — exactly the ladder this sensor had before challenges existed.
        """
        service = self.challenge
        if service is None or not getattr(service, 'enabled', False):
            return proposed, (), {}, '', False

        adjusted, notes = service.adjust(proposed, key, now=now)
        features = service.evidence(key, now=now)
        available, reason = service.available(
            key, risk=risk, identity_confidence=confidence, now=now)

        if adjusted != proposed:
            self.metrics['web_challenge_adjusted_total'] += 1
        # `web_soft_challenge_total` is deliberately not incremented here.
        # `evaluate` already counts the final action, and a challenge is only the
        # final action when one could actually be presented. Counting it in both
        # places double-counted every challenge — which would have quietly
        # doubled the challenge rate on an operator's dashboard.
        return adjusted, tuple(notes), features, reason, available

    def last_risk(self, key):
        """The most recent risk this source scored, or zero if never scored.

        Zero for an unknown source is the safe answer: a client the system has
        never seen has earned no suspicion.
        """
        return self._last_risk.get(key, 0.0)

    @staticmethod
    def _confidence(state):
        """The weakest confidence seen for this source.

        A source that reached us once through an unverifiable chain is only as
        trustworthy as that request: taking the best of several answers would let
        one clean request launder the rest.
        """
        order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        seen = [item.identity_confidence for item in state.requests]
        return max(seen, key=lambda value: order.get(value, 2)) if seen else 'LOW'

    @staticmethod
    def _enforceable(state):
        """A source is network-enforceable only if every request said so.

        One request arriving through a proxy is enough to make a network block
        unsafe: the address may not be the machine that would be hit.
        """
        if not state.requests:
            return False
        return all(item.network_enforceable for item in state.requests)

    @staticmethod
    def _scope(enforceable, confidence):
        if enforceable and confidence == 'HIGH':
            return 'NETWORK_SOURCE'
        return 'WEB_CLIENT'

    def health(self):
        document = {'web_sensor_schema_version': WEB_DECISION_SCHEMA_VERSION,
                    'shadow': self.shadow, 'sources': len(self.table),
                    'metrics': dict(self.metrics)}
        document.update(self.table.stats())
        if self.source is not None:
            document['source'] = self.source.health()
        if self.challenge is not None:
            document['challenge'] = self.challenge.health()
        return document


def incident(decision, state=None):
    """A local incident summary, generated deterministically. No model involved."""
    features = decision.features
    lines = ['WEB INCIDENT', '',
             f'Source:\n{decision.source}', '',
             f'Identity:\n{decision.identity_confidence} confidence, scope {decision.scope}', '',
             f'Requests:\n{decision.observations}', '',
             f'Unique paths:\n{int(features.get("unique_paths_900s", 0))}', '',
             f'Not found:\n{features.get("http_404_ratio", 0):.0%} of responses', '',
             f'Sensitive probes:\n{int(features.get("sensitive_probe_count", 0))} across '
             f'{int(features.get("sensitive_category_count", 0))} categories', '',
             f'Auth failures:\n{int(features.get("failed_auth_900s", 0))}', '',
             f'Persistence:\n{features.get("persistence_900s", 0) / 60:.0f} minutes', '',
             f'Web risk:\n{decision.risk:.2f}', '',
             f'Data quality:\n{decision.data_quality:.2f}', '',
             f'Decision:\n{decision.action}'
             + (f' (proposed {decision.proposed_action})'
                if decision.action != decision.proposed_action else ''), '']
    if decision.reasons:
        lines += ['Reasons:'] + ['  - ' + reason for reason in decision.reasons] + ['']
    if decision.suppressions:
        lines += ['Reduced because:'] + ['  - ' + item for item in decision.suppressions] + ['']
    if decision.challenge:
        presented = int(decision.challenge.get('challenge_presented_count', 0))
        ratio = decision.challenge.get('challenge_pass_ratio')
        lines += ['Challenges:',
                  f'  presented {presented}, '
                  f'passed {int(decision.challenge.get("challenge_pass_count", 0))}, '
                  f'failed {int(decision.challenge.get("challenge_fail_count", 0))}',
                  '  pass rate ' + ('not known yet' if ratio is None else f'{ratio:.0%}'),
                  '  ' + (decision.challenge_reason or 'no challenge decision recorded'),
                  '',
                  'About challenges:',
                  'Completing one means a client behaved like an ordinary browser. It is',
                  'not proof of a person, and failing one is not proof of an attack.', '']
    lines += ['Note:',
              'This describes behaviour in one time window. It is not proof of an attack',
              'and it does not identify a person.']
    return '\n'.join(lines)
