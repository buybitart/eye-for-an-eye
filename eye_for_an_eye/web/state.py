"""Per-source web behaviour, in bounded memory.

Everything here answers one question: what has this source been doing, over the
last ten seconds, minute and fifteen minutes? And it answers it while assuming
the source is actively trying to make the answer expensive.

That assumption drives the whole design. An attacker can request a million
distinct URLs. Storing paths would turn "watch for a scanner" into "let a scanner
exhaust our memory", which is the protection becoming the outage. So nothing here
stores a path, a host or a User-Agent. It stores counters, and for the things
that need distinctness it stores a fixed-size ring of short digests: enough to
say "about forty different resources", never "which forty".

Every structure has a hard maximum. There is no code path that grows with the
number of distinct values an attacker can invent.
"""
from collections import Counter, deque
from dataclasses import dataclass, field
import math

WEB_STATE_SCHEMA_VERSION = 1

#: Windows, in seconds. The same three the network side uses, so a person reading
#: both reports is reading the same spans of time.
WINDOWS = (10, 60, 900)
LONGEST_WINDOW = max(WINDOWS)

#: Requests kept per source. Beyond this the oldest are dropped: the rate stays
#: correct because it is measured over a window, not over the whole history.
MAX_REQUESTS = 512
#: Distinct-value rings. Fixed size, so a million unique paths cost the same as
#: sixty-four.
MAX_DISTINCT = 64
#: Sources tracked at once, and how long a quiet one is kept.
MAX_SOURCES = 4096
SOURCE_TTL_SECONDS = 1800


@dataclass
class Observation:
    """One request, reduced to what the windows need. No strings beyond digests."""

    at: float
    status: int
    method: str
    extension: str
    path_key: str
    host_key: str
    agent_digest: str
    sensitive: tuple
    response_bytes: int
    auth_outcome: str
    referer_present: bool
    path_entropy: float = 0.0
    #: Carried per request, not per source, because a source can reach us both
    #: directly and through a proxy and the answer differs each time.
    identity_confidence: str = 'HIGH'
    network_enforceable: bool = True


class DistinctRing:
    """Approximate distinct count over a fixed-size ring of digests.

    Deliberately simple. A HyperLogLog would be more accurate at scale, but the
    question here is "a handful, dozens, or more than this ring can hold", and a
    ring answers that with no estimator to get wrong. When it is full the count
    saturates, which reads honestly as "many" rather than as a precise-looking
    number that is not.
    """

    __slots__ = ('capacity', '_items', '_seen')

    def __init__(self, capacity=MAX_DISTINCT):
        self.capacity = max(1, int(capacity))
        self._items = deque(maxlen=self.capacity)
        self._seen = set()

    def add(self, key):
        if not key:
            return False
        if key in self._seen:
            return False
        if len(self._items) == self.capacity:
            self._seen.discard(self._items[0])
        self._items.append(key)
        self._seen.add(key)
        return True

    def __contains__(self, key):
        return key in self._seen

    def __len__(self):
        return len(self._seen)

    @property
    def saturated(self):
        return len(self._seen) >= self.capacity


@dataclass
class WebSourceState:
    """What one source has done recently. Bounded in every dimension."""

    key: str
    first_seen: float
    last_seen: float
    requests: deque = field(default_factory=lambda: deque(maxlen=MAX_REQUESTS))
    paths: DistinctRing = field(default_factory=DistinctRing)
    hosts: DistinctRing = field(default_factory=lambda: DistinctRing(16))
    agents: DistinctRing = field(default_factory=lambda: DistinctRing(8))
    repeated_paths: int = 0
    total_requests: int = 0
    dropped_requests: int = 0
    agent_changes: int = 0
    _last_agent: str = ''

    def observe(self, event, now):
        """Record one request. Constant work, constant memory."""
        if len(self.requests) == self.requests.maxlen:
            self.dropped_requests += 1
        if event.path_key and event.path_key in self.paths:
            self.repeated_paths += 1
        self.paths.add(event.path_key)
        self.hosts.add(event.host_key)
        digest = event.agent.get('agent_digest', '')
        if digest:
            if self._last_agent and digest != self._last_agent:
                self.agent_changes += 1
            self._last_agent = digest
            self.agents.add(digest)
        self.requests.append(Observation(
            at=now, status=event.status, method=event.method, extension=event.extension,
            path_key=event.path_key, host_key=event.host_key, agent_digest=digest,
            sensitive=event.sensitive, response_bytes=event.response_bytes,
            auth_outcome=event.auth_outcome, referer_present=event.referer_present,
            path_entropy=event.path_entropy,
            identity_confidence=event.identity_confidence,
            network_enforceable=event.network_enforceable))
        self.total_requests += 1
        self.last_seen = now

    def within(self, now, window):
        cutoff = now - window
        return [item for item in self.requests if item.at >= cutoff]

    @property
    def persistence_seconds(self):
        return max(0.0, self.last_seen - self.first_seen)

    def explain(self):
        return {'requests': self.total_requests, 'distinct_paths': len(self.paths),
                'paths_saturated': self.paths.saturated,
                'distinct_hosts': len(self.hosts), 'distinct_agents': len(self.agents),
                'repeated_paths': self.repeated_paths,
                'persistence_seconds': round(self.persistence_seconds, 1),
                'dropped_requests': self.dropped_requests}


class WebSourceTable:
    """Bounded table of per-source state, with TTL and least-recently-used eviction.

    The eviction policy matters under attack. When a flood of new sources arrives,
    the table drops the sources that have been quiet longest, so an attacker
    generating fresh addresses cannot evict the source that is actually being
    watched any faster than time already would.
    """

    def __init__(self, *, max_sources=MAX_SOURCES, ttl_seconds=SOURCE_TTL_SECONDS,
                 max_distinct_paths=MAX_DISTINCT):
        self.max_sources = max(1, int(max_sources))
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self.max_distinct_paths = max(1, int(max_distinct_paths))
        self._sources = {}
        self.evictions = 0
        self.expired = 0

    def __len__(self):
        return len(self._sources)

    def get(self, key):
        return self._sources.get(key)

    def observe(self, event, now):
        """Record one request against its source, creating state if needed."""
        key = event.client or event.peer
        if not key:
            return None
        state = self._sources.get(key)
        if state is None:
            self._make_room(now)
            state = WebSourceState(key=key, first_seen=now, last_seen=now,
                                   paths=DistinctRing(self.max_distinct_paths))
            self._sources[key] = state
        else:
            # Move to the end so the dictionary order is least-recently-used first.
            self._sources.pop(key)
            self._sources[key] = state
        state.observe(event, now)
        return state

    def _make_room(self, now):
        self.expire(now)
        while len(self._sources) >= self.max_sources:
            self.evict_oldest()

    def evict_oldest(self):
        """Drop the single least-recently-used source. Returns whether one went.

        Separate from `_make_room` because the two answer different questions.
        `_make_room` asks "is this table over *its own* cap"; this asks "free one
        slot, because something outside this table needs the room". A shared
        global budget across several sites needs the second, and using the first
        for it silently does nothing whenever the table is under its own cap —
        which is most of the time, and is exactly when the global pool is full.
        """
        if not self._sources:
            return False
        self._sources.pop(next(iter(self._sources)), None)
        self.evictions += 1
        return True

    def expire(self, now):
        cutoff = now - self.ttl_seconds
        stale = [key for key, state in self._sources.items() if state.last_seen < cutoff]
        for key in stale:
            self._sources.pop(key, None)
            self.expired += 1
        return len(stale)

    def stats(self):
        return {'web_state_schema_version': WEB_STATE_SCHEMA_VERSION,
                'sources': len(self._sources), 'max_sources': self.max_sources,
                'evictions': self.evictions, 'expired': self.expired,
                'bounded': ('every structure has a fixed maximum; distinct paths are '
                            'counted in a fixed-size ring and never stored')}


def rate_per_minute(count, window):
    return (count / window) * 60.0 if window else 0.0


def interval_statistics(observations):
    """Mean, coefficient of variation and entropy of the gaps between requests.

    Regular gaps are the clearest automation signal there is: a person's requests
    are bursty and irregular, a script's are not. Entropy is included because a
    script that randomises its delay still produces a *distribution* that differs
    from a person's.
    """
    if len(observations) < 3:
        return {'mean': None, 'cv': None, 'entropy': None}
    gaps = [b.at - a.at for a, b in zip(observations, observations[1:], strict=False)]
    gaps = [gap for gap in gaps if gap >= 0]
    if len(gaps) < 2:
        return {'mean': None, 'cv': None, 'entropy': None}
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return {'mean': 0.0, 'cv': 0.0, 'entropy': 0.0}
    variance = sum((gap - mean) ** 2 for gap in gaps) / len(gaps)
    cv = math.sqrt(variance) / mean
    # Coarse histogram: the shape is what matters, not the exact values.
    buckets = Counter(min(9, int(gap / max(mean, 1e-6) * 2)) for gap in gaps)
    total = sum(buckets.values())
    entropy = -sum((n / total) * math.log2(n / total) for n in buckets.values())
    return {'mean': mean, 'cv': cv, 'entropy': min(1.0, entropy / math.log2(10))}
