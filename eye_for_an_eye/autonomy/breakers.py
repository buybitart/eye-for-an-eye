"""The brakes: budgets and circuit breakers that stop a wrong idea from scaling.

Every other part of this package tries to get one decision right. This part
assumes that will sometimes fail, and asks a different question: when the system
is wrong, how wrong can it get before something stops it?

The answer has to be structural, because the failure mode that matters is not a
bad block — it is a *correlated* bad block. A model that degrades, a feature
pipeline that starts emitting zeros, a NAT that suddenly carries a conference's
worth of traffic: none of these produce one mistake. They produce the same
mistake against every source at once, each one individually justified by the
evidence, and by the time a person notices, the site is unreachable.

So there are four brakes, and they are deliberately dumb. None of them looks at
whether a block was *correct* — that judgement is exactly what has failed. They
look at rate, at share, at externally established outcomes, and at whether the
machinery underneath is working.

**The budget** (§50) caps how many new blocks can be created per minute and how
many can be active at once. It is a rate limit on the system's own certainty.

**The mass-block breaker** (§51) watches the *share* of recently seen sources
being blocked. Expecting a fraction of a percent and seeing a fifth of everything
is not a discovery, it is a fault, and the correct response is to stop blocking
rather than to keep going and be consistent about it.

**The false-positive breaker** (§52) is the only one fed by outcomes, and it
accepts them from trusted evaluation only. §61 forbids treating the system's own
decisions as ground truth, and a breaker that learned from its own blocks would
be the purest form of that mistake.

**The technical breaker** (§53) is not statistical at all. A corrupt model, a
schema mismatch, a failed firewall verification, a clock that jumped — each
means the decision path is standing on something broken, and a decision made on
broken machinery is not evidence about anything.

When any of them opens, the runtime enters AUTONOMOUS_SAFE_MODE: no new blocks,
everything else continues, and existing blocks expire on their own schedule
(§55). Recovery is automatic and needs no administrator (§54), but it needs the
fault cleared *and* a cooldown to pass, because a breaker that closed the instant
a metric dipped would flap (§194).
"""
from collections import deque
from dataclasses import dataclass
import time

#: Breaker states. COOLDOWN is the honest middle: the fault is gone, and not for
#: long enough to trust yet.
CLOSED = 'CLOSED'
OPEN = 'OPEN'
COOLDOWN = 'COOLDOWN'

#: The runtime state §55 names. Not a breaker itself: the panel's summary.
AUTONOMOUS_ACTIVE = 'AUTONOMOUS_ACTIVE'
AUTONOMOUS_SAFE_MODE = 'AUTONOMOUS_SAFE_MODE'
ENFORCEMENT_DEGRADED = 'ENFORCEMENT_DEGRADED'

#: §53's list, as names rather than prose. A fault outside this set is still
#: accepted — refusing to record an unrecognised fault would be the wrong
#: failure direction — but these are the ones with a documented meaning.
TECHNICAL_FAULTS = (
    'model_invalid', 'feature_schema_mismatch', 'data_quality_unavailable',
    'identity_resolver_failed', 'firewall_verify_failed', 'storage_corruption',
    'site_isolation_failure', 'clock_anomaly', 'model_registry_inconsistent')

#: Where a trusted outcome may come from (§63). Anything else is a heuristic, and
#: §64 is explicit that a strong heuristic stays a heuristic.
TRUSTED_OUTCOME_SOURCES = (
    'lab_scenario', 'signed_pcap_sidecar', 'deterministic_harness',
    'reviewed_evaluation')


class BreakerError(ValueError):
    """A breaker asked to do something that would defeat its purpose."""


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    """How much autonomous blocking is allowed to happen at all.

    These are ceilings on the system's own behaviour, not on any attacker's.
    §198 lists the mass-block ceiling among the limits no learned component may
    change: nothing in `learning/`, `training/` or `governance/` writes here.
    """

    #: New autonomous blocks per minute, across every scope.
    blocks_per_minute: int = 10
    #: Autonomous blocks held at once.
    max_active_blocks: int = 500
    #: The share of recently seen sources that may be under an autonomous block
    #: before the mass-block breaker opens.
    max_block_share: float = 0.02
    #: Below this many recently seen sources, share is meaningless and is not
    #: evaluated. Three blocks out of five sources is not a 60% catastrophe.
    minimum_sources_for_share: int = 200
    #: False blocks per 1000 benign sources, from trusted evaluation only.
    max_false_blocks_per_1000: float = 1.0
    #: Trusted benign sample below which the false-positive rate is not evaluated
    #: (§171: do not declare safety, or danger, from a handful of examples).
    minimum_benign_sample: int = 500
    #: How long a breaker stays shut after its fault clears (§193, §194).
    cooldown_seconds: float = 300.0

    def __post_init__(self):
        if self.blocks_per_minute < 0 or self.max_active_blocks < 0:
            raise BreakerError('budget ceilings cannot be negative')
        if not 0 < self.max_block_share <= 1:
            raise BreakerError('max_block_share must be a fraction in (0, 1]')
        if self.cooldown_seconds < 0:
            raise BreakerError('cooldown cannot be negative')

    def explain(self):
        return {'blocks_per_minute': self.blocks_per_minute,
                'max_active_blocks': self.max_active_blocks,
                'max_block_share': self.max_block_share,
                'minimum_sources_for_share': self.minimum_sources_for_share,
                'max_false_blocks_per_1000': self.max_false_blocks_per_1000,
                'minimum_benign_sample': self.minimum_benign_sample,
                'cooldown_seconds': self.cooldown_seconds}


class BlockBudget:
    """A rate limit on the system's own willingness to act (§50).

    Keeps a bounded window of recent block times and a count of active blocks.
    `permits()` is asked before a block and `record()` after one succeeds, so a
    block the executor refused does not spend budget.
    """

    def __init__(self, limits=None, *, clock=time.monotonic):
        self.limits = limits or BudgetLimits()
        self.clock = clock
        # Bounded by construction: never more entries than a minute's ceiling,
        # and an attacker cannot grow it because the system writes it, not them.
        self._recent = deque(maxlen=max(1, self.limits.blocks_per_minute * 4))
        self.active = 0
        self.refusals = 0

    def _prune(self, now):
        while self._recent and now - self._recent[0] > 60.0:
            self._recent.popleft()

    @property
    def recent_blocks(self):
        self._prune(self.clock())
        return len(self._recent)

    @property
    def utilisation(self):
        """How much of the per-minute allowance is spent, in [0, 1]."""
        if self.limits.blocks_per_minute <= 0:
            return 1.0
        return min(1.0, self.recent_blocks / self.limits.blocks_per_minute)

    def permits(self):
        """Whether one more autonomous block is within budget.

        Returns `(allowed, reason)`. The reason is a bounded token, never text
        built from anything a request contained.
        """
        if self.limits.blocks_per_minute <= 0:
            return False, 'blocks_per_minute is zero'
        if self.recent_blocks >= self.limits.blocks_per_minute:
            return False, 'per-minute block budget spent'
        if self.active >= self.limits.max_active_blocks:
            return False, 'active block ceiling reached'
        return True, ''

    def record(self, count=1):
        now = self.clock()
        self._prune(now)
        for _ in range(max(0, int(count))):
            self._recent.append(now)
        self.active += max(0, int(count))
        return self

    def refuse(self):
        self.refusals += 1
        return self

    def release(self, count=1):
        """A block expired. Automatic, and the only way active count goes down."""
        self.active = max(0, self.active - max(0, int(count)))
        return self

    def set_active(self, count):
        """Reconcile with the enforcer's own view, which is authoritative."""
        self.active = max(0, int(count))
        return self

    def explain(self):
        return {'recent_blocks_60s': self.recent_blocks,
                'active_blocks': self.active,
                'utilisation': round(self.utilisation, 4),
                'refusals': self.refusals,
                'limits': self.limits.explain()}


class Breaker:
    """One circuit breaker: open on a fault, close after the cooldown.

    Deliberately minimal. The intelligence lives in whoever calls `trip()`; a
    breaker that reasoned about whether it should really have opened would be
    another component to be wrong.
    """

    def __init__(self, name, *, cooldown_seconds=300.0, clock=time.monotonic):
        self.name = name
        self.cooldown_seconds = float(cooldown_seconds)
        self.clock = clock
        self.state = CLOSED
        self.reason = ''
        self.opened_at = 0.0
        self.cleared_at = 0.0
        self.trips = 0

    @property
    def open(self):
        return self.evaluate() == OPEN

    def trip(self, reason):
        """Open the breaker. Idempotent: a second fault does not restart nothing,
        it refreshes the reason and keeps the original open time."""
        if self.state != OPEN:
            self.opened_at = self.clock()
            self.trips += 1
        self.state = OPEN
        self.cleared_at = 0.0
        self.reason = str(reason)[:120]
        return self

    def clear(self):
        """The fault is gone. This starts the cooldown; it does not end it."""
        if self.state == OPEN:
            self.state = COOLDOWN
            self.cleared_at = self.clock()
        return self

    def evaluate(self):
        """Advance the state machine. Called before reading `state`."""
        if self.state == COOLDOWN and self.clock() - self.cleared_at >= self.cooldown_seconds:
            self.state = CLOSED
            self.reason = ''
        return self.state

    @property
    def permits(self):
        """Only a fully closed breaker permits blocking. COOLDOWN does not (§194)."""
        return self.evaluate() == CLOSED

    @property
    def cooldown_remaining(self):
        if self.evaluate() != COOLDOWN:
            return 0.0
        return max(0.0, self.cooldown_seconds - (self.clock() - self.cleared_at))

    def explain(self):
        return {'name': self.name, 'state': self.evaluate(), 'reason': self.reason,
                'trips': self.trips,
                'cooldown_remaining_seconds': round(self.cooldown_remaining, 1)}


class MassBlockBreaker:
    """§51. Watches the share of sources being blocked, not whether blocks are right.

    The scenario it exists for: a model or a feature path degrades and starts
    calling ordinary traffic malicious. Every individual decision looks
    well-supported, because the evidence itself is what went wrong. The only
    signal left is proportion — a defender that expects to block a fraction of a
    percent and finds itself blocking a fifth of everything has learned something
    about itself, not about the Internet.

    Existing blocks keep expiring while this is open. Freezing means stopping
    new mistakes, not holding old ones.
    """

    def __init__(self, limits=None, *, clock=time.monotonic, window_seconds=300.0):
        self.limits = limits or BudgetLimits()
        self.clock = clock
        self.window_seconds = float(window_seconds)
        self.breaker = Breaker('mass_block', cooldown_seconds=self.limits.cooldown_seconds,
                               clock=clock)
        self._sources = deque()   # (time,) of distinct sources seen
        self._blocks = deque()    # (time,) of autonomous blocks created
        self._distinct = {}
        self.observed_share = 0.0

    def _prune(self, now):
        cutoff = now - self.window_seconds
        while self._sources and self._sources[0] < cutoff:
            self._sources.popleft()
        while self._blocks and self._blocks[0] < cutoff:
            self._blocks.popleft()
        for key in [k for k, stamp in self._distinct.items() if stamp < cutoff]:
            del self._distinct[key]

    def observe_source(self, key):
        """One source was evaluated. Bounded: the distinct set is capped, and
        beyond the cap the count still rises, which is the safe direction —
        a larger denominator makes the breaker *less* likely to open."""
        now = self.clock()
        self._prune(now)
        if key not in self._distinct and len(self._distinct) < 20_000:
            self._distinct[key] = now
            self._sources.append(now)
        elif key in self._distinct:
            self._distinct[key] = now
        else:
            self._sources.append(now)
        return self

    def observe_block(self):
        now = self.clock()
        self._prune(now)
        self._blocks.append(now)
        return self.evaluate()

    def evaluate(self):
        now = self.clock()
        self._prune(now)
        sources = len(self._sources)
        blocks = len(self._blocks)
        self.observed_share = blocks / sources if sources else 0.0
        if sources < self.limits.minimum_sources_for_share:
            # Not enough denominator to say anything. Do not clear an open
            # breaker on a quiet window either: silence is not recovery.
            return self.breaker.evaluate()
        if self.observed_share > self.limits.max_block_share:
            self.breaker.trip(
                f'blocking {self.observed_share:.1%} of {sources} recent sources, '
                f'ceiling {self.limits.max_block_share:.1%}')
        else:
            self.breaker.clear()
        return self.breaker.evaluate()

    @property
    def permits(self):
        return self.breaker.permits

    def explain(self):
        return {'observed_share': round(self.observed_share, 5),
                'recent_sources': len(self._sources),
                'recent_blocks': len(self._blocks),
                'window_seconds': self.window_seconds,
                'breaker': self.breaker.explain()}


class FalsePositiveBreaker:
    """§52. Opens when trusted evaluation shows benign sources being blocked.

    The word that carries this class is *trusted*. It accepts outcomes only from
    the sources §63 permits: a controlled LAB scenario, a signed PCAP sidecar
    label, a deterministic harness, or a reviewed evaluation. Feeding it the
    system's own decisions is refused outright rather than discouraged, because
    a false-positive breaker trained on its own blocks would confirm whatever it
    was already doing — the exact feedback loop §61 and §74 exist to prevent.
    """

    def __init__(self, limits=None, *, clock=time.monotonic):
        self.limits = limits or BudgetLimits()
        self.breaker = Breaker('false_positive',
                               cooldown_seconds=self.limits.cooldown_seconds, clock=clock)
        self.false_blocks = 0
        self.benign_sources = 0
        self.last_source = ''

    @property
    def rate_per_1000(self):
        """False blocks per 1000 benign sources, or None when unmeasured.

        None is not zero. §156: without ground truth the answer is that there
        isn't one, and reporting 0.0 would be a claim nobody made.
        """
        if self.benign_sources <= 0:
            return None
        return 1000.0 * self.false_blocks / self.benign_sources

    def report(self, *, false_blocks, benign_sources, source):
        """Record a trusted evaluation outcome and re-evaluate."""
        if source not in TRUSTED_OUTCOME_SOURCES:
            raise BreakerError(
                f'{source!r} is not a trusted outcome source; a block is never '
                'ground truth and a heuristic is not ground truth (§61, §64)')
        self.false_blocks += max(0, int(false_blocks))
        self.benign_sources += max(0, int(benign_sources))
        self.last_source = source
        return self.evaluate()

    def reset(self):
        """Start a fresh evaluation window, e.g. after a model promotion."""
        self.false_blocks = 0
        self.benign_sources = 0
        return self

    def evaluate(self):
        rate = self.rate_per_1000
        if rate is None or self.benign_sources < self.limits.minimum_benign_sample:
            return self.breaker.evaluate()
        if rate > self.limits.max_false_blocks_per_1000:
            self.breaker.trip(
                f'{rate:.2f} false blocks per 1000 benign sources over '
                f'{self.benign_sources} trusted benign examples, ceiling '
                f'{self.limits.max_false_blocks_per_1000:.2f}')
        else:
            self.breaker.clear()
        return self.breaker.evaluate()

    @property
    def permits(self):
        return self.breaker.permits

    def explain(self):
        rate = self.rate_per_1000
        return {'false_blocks': self.false_blocks,
                'benign_sources': self.benign_sources,
                'false_blocks_per_1000': None if rate is None else round(rate, 3),
                'ground_truth': self.last_source or 'GROUND_TRUTH_UNAVAILABLE',
                'breaker': self.breaker.explain()}


class TechnicalBreaker:
    """§53. Open while any named subsystem fault is set.

    Not statistical. A corrupt artifact or a jumped clock does not make the next
    decision *less accurate* — it makes it meaningless, and a meaningless
    decision must not reach the firewall.
    """

    def __init__(self, limits=None, *, clock=time.monotonic):
        limits = limits or BudgetLimits()
        self.breaker = Breaker('technical', cooldown_seconds=limits.cooldown_seconds,
                               clock=clock)
        self.faults = {}

    def fault(self, name, detail=''):
        self.faults[str(name)[:64]] = str(detail)[:120]
        self.breaker.trip('technical faults: ' + ', '.join(sorted(self.faults)))
        return self

    def resolve(self, name):
        self.faults.pop(str(name)[:64], None)
        if not self.faults:
            self.breaker.clear()
        else:
            self.breaker.trip('technical faults: ' + ', '.join(sorted(self.faults)))
        return self

    @property
    def permits(self):
        return not self.faults and self.breaker.permits

    def explain(self):
        return {'faults': dict(sorted(self.faults.items())),
                'known_fault_names': list(TECHNICAL_FAULTS),
                'breaker': self.breaker.explain()}


class BreakerPanel:
    """All the brakes, one answer, and the runtime state that follows from it.

    `permits_block()` is what `authority.py` asks. It returns a reason code from
    `record.py`'s enum rather than free text, so the refusal ends up in the
    decision record and in a bounded metric label without anything in between
    inventing a string.
    """

    def __init__(self, limits=None, *, clock=time.monotonic):
        self.limits = limits or BudgetLimits()
        self.clock = clock
        self.budget = BlockBudget(self.limits, clock=clock)
        self.mass_block = MassBlockBreaker(self.limits, clock=clock)
        self.false_positive = FalsePositiveBreaker(self.limits, clock=clock)
        self.technical = TechnicalBreaker(self.limits, clock=clock)
        self.safe_mode_entries = 0
        self._was_safe = False

    @property
    def state(self):
        """The runtime state §55 and §153 report."""
        if not (self.mass_block.permits and self.false_positive.permits
                and self.technical.permits):
            return AUTONOMOUS_SAFE_MODE
        allowed, _ = self.budget.permits()
        return AUTONOMOUS_ACTIVE if allowed else ENFORCEMENT_DEGRADED

    @property
    def safe_mode(self):
        return self.state == AUTONOMOUS_SAFE_MODE

    def permits_block(self):
        """`(allowed, reason_code, detail)`. Order is deliberate: the technical
        breaker is checked first, because when the machinery is broken every
        other number in the system is describing something that did not happen."""
        from .record import (AUTONOMOUS_SAFE_MODE as SAFE_CODE, BLOCK_BUDGET_EXHAUSTED,
                             FALSE_POSITIVE_FREEZE, MASS_BLOCK_FREEZE, TECHNICAL_FREEZE)
        self._track()
        if not self.technical.permits:
            return False, TECHNICAL_FREEZE, self.technical.breaker.reason
        if not self.mass_block.permits:
            return False, MASS_BLOCK_FREEZE, self.mass_block.breaker.reason
        if not self.false_positive.permits:
            return False, FALSE_POSITIVE_FREEZE, self.false_positive.breaker.reason
        allowed, detail = self.budget.permits()
        if not allowed:
            return False, BLOCK_BUDGET_EXHAUSTED, detail
        if self.safe_mode:
            return False, SAFE_CODE, 'autonomous safe mode'
        return True, '', ''

    def _track(self):
        safe = self.safe_mode
        if safe and not self._was_safe:
            self.safe_mode_entries += 1
        self._was_safe = safe

    def record_block(self, *, enforced=True):
        """A block decision happened.

        Shadow decisions still count towards the mass-block share: §51 is about
        the *distribution of decisions*, and a model that would have blocked a
        fifth of the Internet is exactly what shadow mode exists to catch before
        anybody promotes it. Only a real lease spends the budget, because only a
        real lease occupies a rule.
        """
        if enforced:
            self.budget.record()
        self.mass_block.observe_block()
        return self

    def release_block(self):
        """The lease this panel was charged for does not exist after all.

        P15.5R. `AutonomousDecisionAuthority.decide` charges the budget when it
        takes an enforceable block decision, before anything has tried to place
        it; `BlockBudget`'s own contract is that `record()` follows a block that
        *succeeded*, "so a block the executor refused does not spend budget".
        Both were true while nothing constructed an executor. With the pipeline
        wired they are not, and the two available reconciliations are worse than
        this one: letting `HostEnforcer` charge as well spends the budget twice
        per real block, and moving the charge to the enforcer would let a
        deployment with no enforcer decide to block without limit.

        So the authority keeps the charge and this gives it back when the
        enforcement did not land. The mass-block share is deliberately *not*
        released: the source was still decided against, and §51 is about the
        distribution of decisions rather than of leases.
        """
        self.budget.release()
        return self

    def observe_source(self, key):
        self.mass_block.observe_source(key)
        return self

    def metrics(self):
        """Bounded counters for §158. Names only; no address, no path, no label."""
        return {'block_budget_utilization': round(self.budget.utilisation, 4),
                'autonomous_block_suppressed_total': self.budget.refusals,
                'block_circuit_breaker_total': (self.mass_block.breaker.trips
                                                + self.false_positive.breaker.trips
                                                + self.technical.breaker.trips),
                'autonomous_safe_mode_total': self.safe_mode_entries}

    def explain(self):
        return {'state': self.state,
                'safe_mode_entries': self.safe_mode_entries,
                'budget': self.budget.explain(),
                'mass_block': self.mass_block.explain(),
                'false_positive': self.false_positive.explain(),
                'technical': self.technical.explain(),
                'note': ('a breaker stops new blocks; existing temporary blocks '
                         'expire on their own schedule and observation continues')}


def from_config(config):
    """Build the panel from configuration, or from the shipped ceilings."""
    settings = getattr(config, 'autonomy', None)
    if settings is None:
        return BreakerPanel()
    return BreakerPanel(BudgetLimits(
        blocks_per_minute=int(getattr(settings, 'blocks_per_minute', 10)),
        max_active_blocks=int(getattr(settings, 'max_active_blocks', 500)),
        max_block_share=float(getattr(settings, 'max_block_share', 0.02)),
        minimum_sources_for_share=int(getattr(settings, 'minimum_sources_for_share', 200)),
        max_false_blocks_per_1000=float(getattr(settings, 'max_false_blocks_per_1000', 1.0)),
        minimum_benign_sample=int(getattr(settings, 'minimum_benign_sample', 500)),
        cooldown_seconds=float(getattr(settings, 'breaker_cooldown_seconds', 300.0))))
