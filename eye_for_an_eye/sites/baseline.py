"""What normal looks like on one site, and how confident that claim is.

A baseline is a statistical description of a site's ordinary traffic: how fast,
how broad, how many errors, which methods. It exists so that "unusual" can mean
something different on an API than on a blog, without anyone having to train a
model per website.

Three ideas do most of the work.

## The first day is not "normal"

The tempting shortcut is to watch a new site for a day and call whatever it saw
normal. It is wrong for a reason that matters: **attackers are present during
the first observation too.** Every scanner probing the site while the baseline
is being built gets recorded as ordinary, and the finished baseline is precisely
blind to the traffic it should catch.

So a baseline never becomes active by the passage of time. It is built as a
candidate from data with a stated provenance, and something has to accept it.

## A missing baseline is not a normal baseline

`MISSING` and `LEARNING` are real states, and while a site is in one the honest
answer to "is this unusual?" is `INSUFFICIENT_DATA` — not "no", and definitely
not "yes, everything is unusual relative to an empty baseline", which would make
every visitor to a new site look like an attack.

## Baselines are versioned, and the active one does not drift

Continuously folding new traffic into the active baseline is the same poisoning
problem as continuously training on your own decisions: an attacker who applies
pressure slowly moves the definition of normal towards their own behaviour. So
production statistics accumulate into a *candidate*, the candidate is compared
against the active one, and activation is a deliberate act.
"""
from dataclasses import dataclass, field
import hashlib
import json
import math
import time

SITE_BASELINE_SCHEMA_VERSION = 1

#: Baseline states (§26).
MISSING = 'MISSING'
LEARNING = 'LEARNING'
VALIDATING = 'VALIDATING'
ACTIVE = 'ACTIVE'
STALE = 'STALE'
DEGRADED = 'DEGRADED'
STATES = (MISSING, LEARNING, VALIDATING, ACTIVE, STALE, DEGRADED)

#: The answer when there is not enough to say. Not "normal", not "unusual".
INSUFFICIENT_DATA = 'INSUFFICIENT_DATA'
WITHIN_BASELINE = 'WITHIN_BASELINE'
ABOVE_BASELINE = 'ABOVE_BASELINE'
BELOW_BASELINE = 'BELOW_BASELINE'

#: Where a baseline's data came from, in descending order of how much it is
#: worth. This is recorded rather than inferred, because "we do not know where
#: this came from" is itself important and must not be silently upgraded.
LAB = 'lab'
PCAP = 'pcap'
REVIEWED_SHADOW = 'reviewed_shadow'
OBSERVED = 'observed'
PROVENANCE = (LAB, PCAP, REVIEWED_SHADOW, OBSERVED)

#: Observed production traffic is the weakest provenance, because nobody has
#: confirmed an attacker was absent. It is usable, and it is labelled.
PROVENANCE_CONFIDENCE = {LAB: 1.0, PCAP: 0.9, REVIEWED_SHADOW: 0.8, OBSERVED: 0.5}

#: What a baseline measures. Each is a bounded per-source statistic the web
#: feature extractor already produces, so nothing new is collected for this.
TRACKED = ('requests_per_minute', 'unique_paths_60s', 'error_ratio',
           'method_diversity', 'auth_failure_ratio', 'interval_regularity')

#: Below this many samples a baseline says INSUFFICIENT_DATA whatever else is
#: true. Quantiles from a handful of windows describe the handful, not the site.
MIN_SAMPLES = 200

#: Distinct sources behind the samples. Two hundred windows from one client is
#: one client's habits, not a site's traffic.
MIN_SOURCES = 20

#: How long a baseline stays current before it is called STALE. Sites change:
#: a redesign, a new client, a marketing campaign.
DEFAULT_MAX_AGE_SECONDS = 30 * 24 * 3600


class SiteBaselineError(ValueError):
    """A baseline cannot be built or used as asked."""


def _quantile(ordered, fraction):
    """Linear-interpolated quantile of a pre-sorted list."""
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return float(ordered[0])
    position = fraction * (len(ordered) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return float(ordered[low])
    return float(ordered[low] + (ordered[high] - ordered[low]) * (position - low))


@dataclass(frozen=True)
class Distribution:
    """One statistic's shape, as quantiles. Bounded: six numbers, not a histogram."""

    p50: float = 0.0
    p90: float = 0.0
    p99: float = 0.0
    maximum: float = 0.0
    mean: float = 0.0
    samples: int = 0

    @classmethod
    def from_values(cls, values):
        ordered = sorted(float(value) for value in values
                         if value is not None and not math.isnan(float(value)))
        if not ordered:
            return cls()
        return cls(p50=_quantile(ordered, 0.50), p90=_quantile(ordered, 0.90),
                   p99=_quantile(ordered, 0.99), maximum=ordered[-1],
                   mean=sum(ordered) / len(ordered), samples=len(ordered))

    def explain(self):
        return {'p50': round(self.p50, 4), 'p90': round(self.p90, 4),
                'p99': round(self.p99, 4), 'max': round(self.maximum, 4),
                'mean': round(self.mean, 4), 'samples': self.samples}


@dataclass(frozen=True)
class SiteBaseline:
    """One versioned description of a site's ordinary traffic."""

    site_id: str
    version: str
    state: str = MISSING
    provenance: str = OBSERVED
    distributions: dict = field(default_factory=dict)
    samples: int = 0
    sources: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    created_at: float = 0.0
    digest: str = ''
    notes: tuple = ()

    @property
    def usable(self):
        """Can this baseline be asked a question and give a real answer?"""
        return self.state in (ACTIVE, STALE) and self.samples >= MIN_SAMPLES

    @property
    def confidence(self):
        """How much weight this baseline's answers deserve.

        Provenance sets the ceiling — observed production traffic can never be
        as trustworthy as a reviewed lab capture, because nobody checked whether
        an attacker was in it — and thinness and age reduce it from there.
        """
        if not self.usable:
            return 0.0
        score = PROVENANCE_CONFIDENCE.get(self.provenance, 0.5)
        if self.samples < MIN_SAMPLES * 5:
            score *= 0.8
        if self.sources < MIN_SOURCES * 2:
            score *= 0.8
        if self.state == STALE:
            score *= 0.6
        return round(min(1.0, max(0.0, score)), 4)

    def age_seconds(self, now=None):
        return max(0.0, (time.time() if now is None else now) - self.created_at)

    def aged(self, now=None, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
        """This baseline, marked STALE if it has grown old. Never mutated."""
        if self.state != ACTIVE:
            return self
        if self.age_seconds(now) <= max_age_seconds:
            return self
        from dataclasses import replace
        return replace(self, state=STALE,
                       notes=(*self.notes, 'older than the configured maximum age'))

    def compare(self, name, value):
        """Where does one observation sit against this baseline?

        Returns `(verdict, ratio, reason)`. The verdict is `INSUFFICIENT_DATA`
        whenever the baseline cannot really answer — which is not a hedge, it is
        the difference between "we looked and this is fine" and "we have not
        looked".
        """
        if not self.usable:
            return (INSUFFICIENT_DATA, 0.0,
                    f'the baseline for {self.site_id} is {self.state.lower()}')
        distribution = self.distributions.get(name)
        if distribution is None or distribution.samples < MIN_SAMPLES:
            return (INSUFFICIENT_DATA, 0.0,
                    f'{name} is not described by this baseline')
        reference = distribution.p99
        if reference <= 0:
            reference = max(distribution.p90, distribution.mean)
        if reference <= 0:
            return (INSUFFICIENT_DATA, 0.0, f'{name} has no usable reference value')
        ratio = float(value) / reference
        if ratio > 1.0:
            return (ABOVE_BASELINE, round(ratio, 4),
                    f'{name} is {ratio:.1f}x this site\'s 99th percentile')
        if value < distribution.p50 * 0.1:
            return (BELOW_BASELINE, round(ratio, 4),
                    f'{name} is far below this site\'s usual level')
        return (WITHIN_BASELINE, round(ratio, 4),
                f'{name} is within this site\'s usual range')

    def explain(self):
        return {'site_baseline_schema_version': SITE_BASELINE_SCHEMA_VERSION,
                'site_id': self.site_id, 'version': self.version,
                'state': self.state, 'provenance': self.provenance,
                'confidence': self.confidence,
                'samples': self.samples, 'sources': self.sources,
                'digest': self.digest,
                'distributions': {name: item.explain()
                                  for name, item in self.distributions.items()},
                'notes': list(self.notes),
                'meaning': ('a baseline describes this site\'s ordinary traffic; '
                            'being outside it is not evidence of an attack')}


def missing(site_id):
    """The baseline a site has before it has one. A real state, not a null."""
    return SiteBaseline(site_id=site_id, version='', state=MISSING,
                        notes=('no baseline has been built for this site yet',))


class BaselineBuilder:
    """Accumulates observations into a candidate baseline. Bounded.

    Values are kept in a reservoir of fixed size rather than a growing list, so
    a busy site building a candidate does not cost more memory than a quiet one.
    """

    def __init__(self, site_id, *, provenance=OBSERVED, reservoir=4000, seed=0):
        if provenance not in PROVENANCE:
            raise SiteBaselineError(f'unknown baseline provenance {provenance!r}')
        self.site_id = site_id
        self.provenance = provenance
        self.reservoir = max(MIN_SAMPLES, int(reservoir))
        self._values = {name: [] for name in TRACKED}
        self._seen = 0
        self._sources = set()
        self._max_sources = 4096
        self.first_seen = 0.0
        self.last_seen = 0.0
        self._random = __import__('random').Random(seed)

    def observe(self, values, *, source='', now=None):
        """Record one window of one source's behaviour on this site."""
        moment = time.time() if now is None else now
        if not self.first_seen:
            self.first_seen = moment
        self.last_seen = moment
        self._seen += 1
        if source and len(self._sources) < self._max_sources:
            self._sources.add(source)
        for name in TRACKED:
            if name not in values or values[name] is None:
                continue
            kept = self._values[name]
            if len(kept) < self.reservoir:
                kept.append(float(values[name]))
            else:
                # Reservoir sampling: every window has an equal chance of being
                # represented, so a candidate built over a week is not simply
                # the first four thousand windows of Monday morning.
                index = self._random.randrange(self._seen)
                if index < self.reservoir:
                    kept[index] = float(values[name])

    @property
    def samples(self):
        return self._seen

    @property
    def sources(self):
        return len(self._sources)

    def ready(self):
        """Is there enough here to describe a site? Returns `(ready, reasons)`."""
        reasons = []
        if self._seen < MIN_SAMPLES:
            reasons.append(f'{self._seen} windows observed; at least {MIN_SAMPLES} '
                           'are needed before quantiles describe a site rather than '
                           'a handful of moments')
        if self.sources < MIN_SOURCES:
            reasons.append(f'{self.sources} distinct sources; at least {MIN_SOURCES} '
                           'are needed, because many windows from one client '
                           'describe that client')
        return (not reasons), tuple(reasons)

    def build(self, version, *, state=VALIDATING, now=None):
        """Freeze what has been seen into a candidate baseline.

        The result is `VALIDATING`, never `ACTIVE`. Nothing here can activate a
        baseline — that is a separate, deliberate act, because a baseline built
        from whatever happened to arrive is exactly how an attacker's traffic
        becomes the definition of normal.
        """
        if state == ACTIVE:
            raise SiteBaselineError(
                'a builder cannot produce an ACTIVE baseline; build a candidate '
                'and activate it explicitly')
        ready, reasons = self.ready()
        distributions = {name: Distribution.from_values(values)
                         for name, values in self._values.items() if values}
        notes = list(reasons)
        if self.provenance == OBSERVED:
            notes.append('built from observed production traffic; nobody has '
                         'confirmed that no attacker was present in it')
        baseline = SiteBaseline(
            site_id=self.site_id, version=str(version),
            state=(state if ready else LEARNING),
            provenance=self.provenance, distributions=distributions,
            samples=self._seen, sources=self.sources,
            first_seen=self.first_seen, last_seen=self.last_seen,
            created_at=time.time() if now is None else now,
            notes=tuple(notes))
        from dataclasses import replace
        return replace(baseline, digest=digest_of(baseline))


def digest_of(baseline):
    """A content hash, so two baselines can be compared without trusting names."""
    payload = json.dumps(
        {'site': baseline.site_id, 'provenance': baseline.provenance,
         'samples': baseline.samples, 'sources': baseline.sources,
         'distributions': {name: item.explain()
                           for name, item in sorted(baseline.distributions.items())}},
        sort_keys=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]


def activate(candidate, *, previous=None, now=None):
    """Accept a candidate as this site's active baseline. Returns `(baseline, reasons)`.

    Deliberately a function an operator's command calls, not something that
    happens on a timer. The checks below are the ones that can be made
    automatically; the judgement about whether the period was clean is not one
    of them, and is the operator's.
    """
    problems = []
    if candidate.state == LEARNING:
        problems.append('the candidate does not have enough data yet')
    if candidate.samples < MIN_SAMPLES:
        problems.append(f'only {candidate.samples} windows')
    if candidate.sources < MIN_SOURCES:
        problems.append(f'only {candidate.sources} distinct sources')
    if previous is not None and previous.digest == candidate.digest:
        problems.append('identical to the active baseline; nothing would change')
    if problems:
        raise SiteBaselineError('; '.join(problems))

    from dataclasses import replace
    notes = tuple(note for note in candidate.notes if 'windows observed' not in note)
    return replace(candidate, state=ACTIVE,
                   created_at=time.time() if now is None else now,
                   notes=notes)


def compare_baselines(active, candidate):
    """How a candidate differs from the active baseline, for a person to read."""
    if active is None or not active.usable:
        return {'comparable': False,
                'reason': 'there is no active baseline to compare against'}
    rows = {}
    for name in TRACKED:
        before = active.distributions.get(name)
        after = candidate.distributions.get(name)
        if before is None or after is None:
            continue
        change = (after.p99 - before.p99) / before.p99 if before.p99 else None
        rows[name] = {'active_p99': round(before.p99, 4),
                      'candidate_p99': round(after.p99, 4),
                      'change': None if change is None else round(change, 4)}
    widened = [name for name, row in rows.items()
               if row['change'] is not None and row['change'] > 0.5]
    return {'comparable': True, 'metrics': rows, 'widened': widened,
            'caution': ('a candidate much wider than the active baseline may have '
                        'been built during an incident; widening the definition of '
                        'normal is how a baseline is poisoned')
            if widened else ''}
