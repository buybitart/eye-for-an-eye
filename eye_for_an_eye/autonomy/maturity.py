"""Is there enough observation to justify a strong action? §31 to §40.

### The question this answers, and the one it does not

`EvidenceMaturity` answers **"have we watched long enough to act?"** It never
answers "how malicious is this" and never contributes to that answer (§33). A
mature observation of a harmless client is mature and harmless; an immature
observation of an obvious attack is an obvious attack that will be blocked a
window later, when there is enough of it to be sure. Keeping those two questions
apart is the reason this is a separate module rather than another term in the
score.

### What went wrong with the single floor

P15.3 required twenty observations in a decision window, full stop. On the
locked benchmark a slow port scan reached a conservative probability of 0.9904 —
past every cost cutoff — with five distinct evidence families and three
behavioural ones, and was not blocked, because the window carrying that evidence
held fifteen events.

The floor was not wrong. Twenty observations is this project's stated bar for
acting against a stranger and P15.4 does not move it (§31): a number edited
because a known test revealed it is a number fitted to that test, and
`tests/test_p15_4_invariants.py` fails the build if `minimum_observations`
changes.

What was wrong is that **one count was the only way to be sure**. The floor
counts events inside a sixty-second window while the evidence it guards
accumulates across a fifteen-minute session, so a source that spreads itself
thinly enough never accumulates twenty of anything — and patience became a
defence. That is a gap in the *shape* of the question, and the answer is more
ways to be sure rather than a lower bar for the one way that existed.

### Three roads, each conservative on its own terms

**`STANDARD`** is the P15.3 rule, unchanged: twenty observations, ten seconds,
adequate data quality. Everything that matured before still matures, by the same
arithmetic.

**`LONG_DURATION`** is for behaviour that is deliberately quiet. It asks for a
quarter of an hour of *sustained* evidence rather than a burst of it, several
independent families, and more windows agreeing than the standard path needs.
A source cannot reach it quickly, which is exactly right: the thing being
measured is patience, and the only honest way to measure patience is to wait.

**`STRONG_MULTI_SIGNAL`** is for evidence corroborated so many different ways
that waiting adds little. It requires four independent families, at least three
of them behavioural, high data quality, confirmed identity and healthy
enforcement — and it still requires more than half the standard observation
count, so a single extreme packet can never reach it (§34).

### What may not create maturity

**A model may not (§38).** `ML_CLASSIFIER` and `ANOMALY` are excluded from every
family count here. A classifier that is confident about a window it has seen
once is a classifier that is confident, which is not the same as evidence
existing, and letting a model shorten the observation period would hand it the
authority the whole architecture is built to withhold.

**A high probability may not.** Probability is not an input to this module at
all. If it were, a source would mature *because* it looked malicious, which is
the circularity every part of this system is arranged to avoid.

**Low data quality may not be compensated for.** Every road requires it, and the
faster the road the more it requires.
"""
from dataclasses import dataclass, field

from .evidence import BEHAVIOURAL_FAMILIES, MODEL_FAMILIES

MATURITY_SCHEMA_VERSION = 1

#: The roads to maturity. Reported by name in every decision record, so "why was
#: this acted on so early" and "why was this not acted on yet" both have an
#: answer that is one word long before it is a paragraph.
STANDARD = 'STANDARD_MATURE'
LONG_DURATION = 'LONG_DURATION_MATURE'
STRONG_MULTI_SIGNAL = 'STRONG_MULTI_SIGNAL_MATURE'
IMMATURE = 'IMMATURE'
MODES = (STANDARD, LONG_DURATION, STRONG_MULTI_SIGNAL)


@dataclass(frozen=True, slots=True)
class MaturityPolicy:
    """What each road costs. Operator policy, and predeclared (§39).

    Every number is a judgement made without deployment data. The standard road
    reproduces `DecisionGates` exactly, and the two new roads are deliberately
    harder to reach in the dimensions they do not relax: `LONG_DURATION` asks
    for far more time than `STANDARD`, `STRONG_MULTI_SIGNAL` for far more
    corroboration, and both for more of everything else.
    """

    # --- STANDARD: the P15.3 rule, unchanged ---
    minimum_observations: int = 20
    minimum_observation_seconds: float = 10.0
    minimum_data_quality: float = 0.55

    # --- LONG_DURATION: quiet behaviour, watched for a long time ---
    #: Most of the correlation horizon. A source cannot rush this.
    long_duration_seconds: float = 600.0
    #: Still a real number of events, just spread out.
    long_duration_observations: int = 10
    #: Several independent behavioural families, sustained.
    long_duration_families: int = 3
    long_duration_behavioural: int = 2
    long_duration_data_quality: float = 0.60

    # --- STRONG_MULTI_SIGNAL: corroborated from many directions at once ---
    strong_families: int = 4
    strong_behavioural: int = 3
    #: Never less than half the standard count: one extreme packet is not a
    #: shortcut, whatever else agrees with it (§34).
    strong_observations: int = 12
    strong_observation_seconds: float = 30.0
    strong_data_quality: float = 0.75

    def __post_init__(self):
        if self.strong_observations * 2 < self.minimum_observations:
            raise ValueError('the fast road may not fall below half the standard count')
        if self.long_duration_seconds <= self.minimum_observation_seconds:
            raise ValueError('the long road must ask for more time than the standard one')
        if self.strong_data_quality < self.minimum_data_quality:
            raise ValueError('a faster road may not accept worse data')
        if self.long_duration_data_quality < self.minimum_data_quality:
            raise ValueError('a longer road may not accept worse data')

    def explain(self):
        return {
            'maturity_schema_version': MATURITY_SCHEMA_VERSION,
            'standard': {'observations': self.minimum_observations,
                         'observation_seconds': self.minimum_observation_seconds,
                         'data_quality': self.minimum_data_quality},
            'long_duration': {'seconds': self.long_duration_seconds,
                              'observations': self.long_duration_observations,
                              'families': self.long_duration_families,
                              'behavioural_families': self.long_duration_behavioural,
                              'data_quality': self.long_duration_data_quality},
            'strong_multi_signal': {'families': self.strong_families,
                                    'behavioural_families': self.strong_behavioural,
                                    'observations': self.strong_observations,
                                    'observation_seconds': self.strong_observation_seconds,
                                    'data_quality': self.strong_data_quality},
            'never_inputs': ['calibrated probability', 'model score', 'anomaly score',
                             'previous decision'],
            'note': ('maturity answers whether there is enough observation to act, '
                     'never how malicious the source is, and it is not an input to '
                     'that question'),
        }


@dataclass(frozen=True, slots=True)
class MaturityResult:
    mature: bool
    mode: str
    reasons: tuple = field(default_factory=tuple)
    #: Every road and why it did or did not open, so an operator asking "why not
    #: yet" gets the whole answer rather than the first refusal.
    roads: dict = field(default_factory=dict)

    def explain(self):
        return {'mature': self.mature, 'mode': self.mode,
                'reasons': list(self.reasons), 'roads': self.roads}


def _behavioural(families):
    """Families that describe what the source *did*. Never a model's opinion (§38)."""
    return tuple(name for name in families
                 if name in BEHAVIOURAL_FAMILIES and name not in MODEL_FAMILIES)


def evaluate(*, observations, observation_seconds, data_quality, families=(),
             windows=1, policy=None):
    """Which road to maturity is open, if any.

    `families` is the names of the evidence families actually observed — the
    same set signal diversity counts, and deliberately not the score they
    produced. How *suspicious* the evidence is has no bearing on whether there
    is enough of it.
    """
    policy = policy or MaturityPolicy()
    quality = 0.0 if data_quality is None else float(data_quality)
    seen = tuple(families or ())
    behavioural = _behavioural(seen)
    # Model opinion is excluded from every count here (§38).
    independent = tuple(name for name in seen if name not in MODEL_FAMILIES)
    roads, reasons = {}, []

    standard = (observations >= policy.minimum_observations
                and observation_seconds >= policy.minimum_observation_seconds
                and quality >= policy.minimum_data_quality)
    roads[STANDARD] = {
        'open': standard,
        'observations': f'{observations}/{policy.minimum_observations}',
        'seconds': f'{round(observation_seconds, 1)}/{policy.minimum_observation_seconds}',
        'data_quality': f'{round(quality, 3)}/{policy.minimum_data_quality}'}

    long_duration = (observation_seconds >= policy.long_duration_seconds
                     and observations >= policy.long_duration_observations
                     and len(independent) >= policy.long_duration_families
                     and len(behavioural) >= policy.long_duration_behavioural
                     and quality >= policy.long_duration_data_quality)
    roads[LONG_DURATION] = {
        'open': long_duration,
        'seconds': f'{round(observation_seconds, 1)}/{policy.long_duration_seconds}',
        'observations': f'{observations}/{policy.long_duration_observations}',
        'families': f'{len(independent)}/{policy.long_duration_families}',
        'behavioural': f'{len(behavioural)}/{policy.long_duration_behavioural}',
        'data_quality': f'{round(quality, 3)}/{policy.long_duration_data_quality}'}

    strong = (len(independent) >= policy.strong_families
              and len(behavioural) >= policy.strong_behavioural
              and observations >= policy.strong_observations
              and observation_seconds >= policy.strong_observation_seconds
              and quality >= policy.strong_data_quality)
    roads[STRONG_MULTI_SIGNAL] = {
        'open': strong,
        'families': f'{len(independent)}/{policy.strong_families}',
        'behavioural': f'{len(behavioural)}/{policy.strong_behavioural}',
        'observations': f'{observations}/{policy.strong_observations}',
        'seconds': f'{round(observation_seconds, 1)}/{policy.strong_observation_seconds}',
        'data_quality': f'{round(quality, 3)}/{policy.strong_data_quality}'}

    # Order matters only for the label: the standard road is named first when
    # more than one is open, because it is the one every earlier cycle used and
    # a record that suddenly reports a new mode for unchanged behaviour would be
    # a false signal of change.
    for mode in (STANDARD, LONG_DURATION, STRONG_MULTI_SIGNAL):
        if roads[mode]['open']:
            return MaturityResult(True, mode, tuple(reasons), roads)

    if observations < policy.strong_observations:
        reasons.append('too few observations for any road')
    if observation_seconds < policy.minimum_observation_seconds:
        reasons.append('watched for too short a time')
    if quality < policy.minimum_data_quality:
        reasons.append('data quality below the floor every road requires')
    if len(independent) < policy.long_duration_families:
        reasons.append('too few independent evidence families for a shortened road')
    _ = windows
    return MaturityResult(False, IMMATURE, tuple(reasons) or ('no road to maturity is open',),
                          roads)
