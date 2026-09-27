"""Per-source authentication history, bounded in every direction. §11.

Counting authentication failures per source needs state, and state that grows
with attacker input is a denial-of-service surface wearing a detector's clothes.
A source that invents a new account name on every request would, in a naive
implementation, be handed unbounded memory in exchange for its trouble.

So every structure here has four limits, and the brief asks for all four:

* **TTL** — entries expire; nothing is remembered forever.
* **max entries** — a hard cap on tracked sources, enforced by the underlying
  `TTLCache`.
* **max bytes** — a byte ceiling the cache enforces independently of the entry
  count.
* **LRU on the principal set** — per source, at most
  `MAX_PRINCIPALS_PER_SOURCE` distinct principals are held, oldest evicted
  first.

### What eviction does to the evidence

It makes it conservative, which is the direction it should fail in. Once a
source exceeds the principal bound the counter stops rising, so a spray across
ten thousand accounts is indistinguishable here from a spray across sixty-four.
Both are far past any threshold that matters, and the alternative — an unbounded
set — trades a real resource guarantee for a number nobody reads.

The saturation is recorded rather than hidden: `principals_capped` says the
count is a floor, so nothing downstream reports a bound as an exact measurement.

### What is stored

Counts, and keyed pseudonyms from `decision.auth.principal_pseudonym`. No
account name, no password, no token, no header value. The pseudonym key lives in
the owning process and is never written to disk, so a dump of this state is a
set of counters and some opaque bytes.
"""
from collections import OrderedDict
from dataclasses import dataclass, field

from ..decision.auth import (AUTH_STATE_TTL_SECONDS, DENIED, FAILURE,
                             MAX_PRINCIPALS_PER_SOURCE,
                             MIN_FAILURES_FOR_A_DERIVED_STATISTIC, SUCCESS)
from ..enrichment.cache import TTLCache

AUTH_STATE_SCHEMA_VERSION = 1

#: Cache ceilings. Sized like the other correlation caches: enough sources for a
#: busy host, small enough that the worst case is a known quantity.
MAX_TRACKED_SOURCES = 10_000
MAX_STATE_BYTES = 2_097_152


@dataclass(slots=True)
class SourceAuthHistory:
    """What one source has done at the authentication layer, within the TTL."""

    first_seen: float = 0.0
    last_seen: float = 0.0
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    denials: int = 0
    #: Pseudonym -> failure count, oldest first, bounded and LRU-evicted.
    failed_principals: OrderedDict = field(default_factory=OrderedDict)
    principals_capped: bool = False
    #: Timestamps of abusive outcomes, for persistence and regularity. Bounded
    #: by the same principal cap so one source cannot grow this either.
    failure_times: list = field(default_factory=list)

    def observe(self, event):
        if not event.auth_attempted:
            return self
        stamp = float(event.timestamp)
        self.first_seen = self.first_seen or stamp
        self.last_seen = max(self.last_seen, stamp)
        self.attempts += 1
        if event.result == SUCCESS:
            self.successes += 1
            return self
        if event.result == FAILURE:
            self.failures += 1
        elif event.result == DENIED:
            self.denials += 1
        else:
            # UNKNOWN and NOT_APPLICABLE contribute nothing. §7: an outcome the
            # sensor could not observe is not a failure, and counting it as one
            # would rebuild the P15.3 defect at a different layer.
            return self
        if len(self.failure_times) < MAX_PRINCIPALS_PER_SOURCE:
            self.failure_times.append(stamp)
        if event.principal:
            if event.principal in self.failed_principals:
                self.failed_principals[event.principal] += 1
                self.failed_principals.move_to_end(event.principal)
            else:
                self.failed_principals[event.principal] = 1
                while len(self.failed_principals) > MAX_PRINCIPALS_PER_SOURCE:
                    self.failed_principals.popitem(last=False)
                    self.principals_capped = True
        return self

    @property
    def abusive(self):
        return self.failures + self.denials

    @property
    def failure_span_seconds(self):
        times = self.failure_times
        return (times[-1] - times[0]) if len(times) >= 2 else 0.0

    def explain(self):
        return {'attempts': self.attempts, 'successes': self.successes,
                'failures': self.failures, 'denials': self.denials,
                'distinct_failed_principals': len(self.failed_principals),
                'principals_capped': self.principals_capped,
                'failure_span_seconds': round(self.failure_span_seconds, 3)}


class AuthLedger:
    """Bounded authentication history, keyed by (sensor, source).

    Reads are non-mutating and return a snapshot, so a caller cannot accidentally
    extend a source's history by looking at it.
    """

    def __init__(self, entries=MAX_TRACKED_SOURCES, ttl=AUTH_STATE_TTL_SECONDS,
                 *, max_bytes=MAX_STATE_BYTES, clock=None):
        options = {'clock': clock} if clock else {}
        self.cache = TTLCache(entries, ttl, max_bytes=max_bytes, **options)

    def observe(self, key, event):
        """Record one authentication event against a source."""
        history = self.cache.get(key) or SourceAuthHistory()
        history.observe(event)
        self.cache.set(key, history)
        return history

    def history(self, key):
        """This source's history, or an empty one. Never `None`, never mutating."""
        return self.cache.get(key) or SourceAuthHistory()

    def features(self, key, *, now, short=60.0, long=900.0):
        """The quantities the feature vector needs, or `None` where unobserved.

        `None` matters here. A source that has made no authentication attempt at
        all has no failure *ratio* — not a ratio of zero — and the feature
        schema's availability flags carry that distinction into the model rather
        than flattening it to a number that looks like evidence of innocence.

        It has to be `None` for **all five** reported quantities, not four. The
        five authentication columns are a `CONDITIONAL_GROUP`, and
        `features.applicable_names` treats the group as inapplicable only when
        every one of them is absent. Reporting `auth_successes: 0` for a source
        that never authenticated would leave the group looking partly applicable
        and four fifths missing, so the data-quality completeness of every
        ordinary web visitor would fall from 1.00 to 0.83 — silently tightening
        a safety gate for the most innocent traffic there is. Measured, not
        theorised: it is what this function returned before the ledger was wired
        to the feature vector, and it is why `tests/test_p15_4_auth_wiring.py`
        asserts the completeness of a non-authenticating source directly.
        """
        history = self.cache.get(key)
        if history is None or not history.attempts:
            return {'auth_attempts': 0, 'auth_successes': None, 'auth_failures': None,
                    'auth_failure_ratio': None, 'failed_principals': None,
                    'auth_failure_span_seconds': None, 'principals_capped': False}
        recent_failures = [stamp for stamp in history.failure_times if now - stamp <= short]
        span_failures = [stamp for stamp in history.failure_times if now - stamp <= long]
        abusive = history.abusive
        return {
            'auth_attempts': history.attempts,
            'auth_successes': history.successes,
            'auth_failures': len(recent_failures) if history.failure_times else abusive,
            'auth_failure_ratio': abusive / history.attempts,
            'failed_principals': len(history.failed_principals),
            # A span is a claim about a *run* of refusals, so it needs enough of
            # them to be a claim at all. Two failures 300 seconds apart is a
            # token expiring twice, and reporting a 300-second "sustained
            # failure" span for it made a legitimate service account score 0.580
            # — the same mistake as `credentials_60s`, one layer along: a number
            # that is arithmetically true and means nothing like what its name
            # says. The threshold is not chosen here; it is
            # `auth.MIN_FAILURES_FOR_A_DERIVED_STATISTIC`, the same one the
            # failure *ratio* is gated on in `decision/families.py`, for the
            # same reason, so there is one number to argue with rather than two.
            'auth_failure_span_seconds': (span_failures[-1] - span_failures[0])
                                         if len(span_failures) >= MIN_FAILURES_FOR_A_DERIVED_STATISTIC
                                         else 0.0,
            'principals_capped': history.principals_capped,
        }

    def snapshot(self):
        return {'auth_state_schema_version': AUTH_STATE_SCHEMA_VERSION,
                'tracked_sources': len(self.cache),
                'max_tracked_sources': MAX_TRACKED_SOURCES,
                'max_principals_per_source': MAX_PRINCIPALS_PER_SOURCE,
                'ttl_seconds': AUTH_STATE_TTL_SECONDS,
                'max_bytes': MAX_STATE_BYTES}
