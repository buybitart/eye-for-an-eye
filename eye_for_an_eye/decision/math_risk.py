"""Independent, explicitly uncalibrated mathematical baseline.

Three versions live here. `math-risk-v1` and `math-risk-v2` are frozen so a
decision record written under either can still be read against the arithmetic
that produced it; `math-risk-v3` is what the system evaluates.

### The v3 change, in one sentence

**A normalisation anchor is a statement about how much of something is a lot,
and it may not depend on how long the observer waited or on a storage bound.**

v2 said this twice, for destination breadth and decoy contact, and then left the
same error standing in two other places. v3 finishes the job:

| Term | v2 | v3 | Why |
| --- | --- | --- | --- |
| `ports_900s` | anchor 128, weight 1.5 | anchor 64, weight 2.25 | the same ports over a longer window were worth **four times less**. The window is a property of the sensor, not of the adversary |
| `ports_60s` | anchor 64, weight 3.0 | anchor 64, weight 2.25 | the family's total weight is held at 4.5 and split evenly, so nothing gets louder |
| `connections_900s` | unused | weight 0.5 | its 60 s counterpart was weighted and it was not, which is the same discount again |
| `connections_60s` | weight 1.0 | weight 0.5 | total held at 1.0, split evenly |
| `destinations_60s` | ceiling 16 | ceiling 8 (2 × floor) | the protected host has eight addresses. A ceiling of 16 meant that touching **every address the host has** scored 0.5, so the feature could not express full breadth at all |

Every family's total weight is unchanged. This is deliberate and it is what
makes the change conservative: a loud source scores exactly as it did, because
both its windows already saturated. What changes is the *ranking* of patient
behaviour against hurried behaviour — and since calibration is monotone, ranking
is the only thing a change to this formula can affect.

The discount was found on the development corpus, by asking why families that
score 1.0 as a point estimate still sit below the cost cutoff. The answer was
not the cutoff, the gates or the calibrator: in the band those families land in,
1.6% of calibration examples are benign, so the Wilson lower bound is 0.9724
against a `public_website` cutoff of 0.9756 and the refusal is **correct**. The
evidence was too weak, which is a statement about this formula and is fixed here
rather than anywhere downstream.

### What P15.3 found earlier, and what v2 changed

`eye_for_an_eye/autonomy/evidence.py` groups features into ten evidence
families and the decision requires three of them, two behavioural. That gate
was doing something nobody intended: a family is counted only when a `MathRisk`
*contribution* names one of its features, and a feature with weight zero
produces no contribution. Four of the eight behavioural families were therefore
unreachable — `NETWORK_RATE`, `TIMING`, `DECEPTION_INTERACTION` and
`HTTP_DISCOVERY` — leaving four, of which a port scan can usually show one.

So `INSUFFICIENT_SIGNAL_DIVERSITY` was not the gate being strict. It was the
gate being asked to count families the engine could not produce. The measured
consequence is in `reports/P15_3_FAILURE_MATRIX.json`: three malicious families
whose conservative bound reached 0.995 against a cutoff of 0.9756, blocked on
zero sources, every one of them refused for insufficient diversity.

v2 makes two of those families reachable. It does not touch a single threshold,
gate or cost, and it does not lower the bar for anything — it gives the engine
the ability to state evidence it was already collecting.

### The terms, and why each one is independent

§25 asks for input, normalisation, maximum contribution, family, and the
independence argument. All five, per term:

| Term | Input | Normalisation | Max | Family | Independent because |
| --- | --- | --- | --- | --- | --- |
| `ports_60s` | distinct ports, 60 s | linear / 64 | 2.25 | PORT_BREADTH | how much surface was touched |
| `ports_900s` | distinct ports, 900 s | linear / 64 (re-anchored) | 2.25 | PORT_BREADTH | same phenomenon, longer window, and v3 stops charging less for it |
| `destinations_60s` | distinct local addresses | **see below** | 1.0 | PORT_BREADTH | breadth across addresses rather than ports |
| `families_60s` | protocol families probed | linear / 4 | 1.0 | PROTOCOL_BEHAVIOR | what kind of service, not how many |
| `repetition_60s` | largest repeated payload share | linear | 0.5 | PERSISTENCE | the same thing again |
| `sequential_60s` | adjacent-port fraction | linear | 0.7 | PORT_BREADTH | the shape of the walk |
| `anomaly_60s` | protocol anomalies / events | linear | 2.5 | PROTOCOL_BEHAVIOR | a request that does not fit the service |
| `credentials_60s` | credential-shaped requests | linear / 20 | 3.0 | AUTH_BEHAVIOR | authentication behaviour |
| `continuation_60s` | continued after a believable reply | linear | 1.0 | PERSISTENCE | kept going when a real client would stop |
| `persistence_900s` | observed span | linear / 300 | 0.5 | PERSISTENCE | how long this has gone on |
| **`deception_60s`** | decoy contacts, 60 s | **floor 3, ceiling 32** | **1.0** | DECEPTION_INTERACTION | *which* port, not how many. A decoy exists only to be contacted; a source can touch one with no breadth at all, and have wide breadth without touching one |
| **`connections_60s`** | connection attempts, 60 s | log / 512 | **0.5** | NETWORK_RATE | volume, not breadth. A single-port flood has rate and no breadth; a slow scan has breadth and no rate |
| **`connections_900s`** | connection attempts, 900 s | log / 512 | **0.5** | NETWORK_RATE | the same volume over the window the source actually used |

**`deception_60s` at 1.0**, and the first draft of this term had it at 3.0.
Leave-one-family-out on the development corpus refused that: nine of thirty-five
`hard-negative-deception` sources crossed the cutoff, which is the family that
exists to catch exactly this mistake. A decoy has no legitimate use, so the
temptation is to treat contact with one as near-proof — and the measured
distributions say otherwise. A legitimate client that reaches a decoy and gives
up produces a median of 4 contacts and as many as 9; an enumerating source
produces a median of 30. The two overlap, so the raw count is suggestive
evidence and is weighted as such.

What actually separates them is already weighted: enumeration takes the banner
and **keeps issuing commands**, which is `continuation_60s`, and it works
through several protocol families, which is `families_60s`. The decoy term's job
is to make `DECEPTION_INTERACTION` a countable family, not to carry the
discrimination on its own.

Its normalisation takes the same floor-and-saturate shape as destination
breadth: below 3 contacts it is 0, because twice can be a stale configuration,
and it saturates at 32.

**Connection rate totals 1.0** and that is small on purpose, for a reason that
is measured rather than assumed: a monitoring agent and a health checker are
among the highest-rate sources in the corpus and both are entirely legitimate.
Rate is weak evidence and gets a weak weight. v3 splits the same 1.0 across the
two windows rather than raising it.

**`destinations_60s`** keeps its weight and changes its normalisation twice.
The feature ceiling is 32 addresses, which is not a number one sensor protecting
one host ever approaches, so six addresses scored 0.19 and read as almost
nothing. v2 re-normalised against the anchor `correlation.engine.classify` has
used since P2 — at least 4 distinct destinations — but paired that floor with a
ceiling of 16, which is still twice the number of addresses the protected host
has. Touching **every address it owns** therefore scored 0.5. v3 sets the
ceiling to twice the floor so the quantity can reach the top of its own range.
The feature contract is untouched throughout: the transform, the schema and
every model input stay as they were.

### What v2 deliberately does not add

**A timing-regularity term.** `TIMING` is the third unreachable family and the
obvious candidate: machine-like traffic has a low inter-arrival coefficient of
variation, and the project already defines that as `cv <= 0.15`. Measured on the
development corpus, the most regular sources are `hard-negative-monitoring`
(cv ≈ 0.04) and `hard-negative-health-check` — both legitimate, both more
regular than any scanner. A regularity term would have fired hardest on the
benign families it exists to protect. It is left out, and the number is recorded
rather than the intention.

**`HTTP_DISCOVERY`** has no feature in schema 1 at all. Its features are
web-layer (`unique_paths_60s`, `status_4xx_60s`) and this is the network engine.
Not a gap to paper over: a different sensor sees that evidence.
"""
from dataclasses import dataclass, field
import math
from . import families
from .composition import EvidenceCompositionEngine
from .features import FeatureTransformer, NAMES, SPEC

VERSION = 'math-risk-v4'
#: Kept readable so a decision record written under an earlier formula can still
#: be interpreted against the arithmetic that produced it. Nothing evaluates
#: these; they are documentation with a test attached.
VERSION_V1 = 'math-risk-v1'
VERSION_V2 = 'math-risk-v2'
VERSION_V3 = 'math-risk-v3'
BIAS = -4.0

WEIGHTS_V1 = {'ports_60s': 3.0, 'ports_900s': 1.5, 'destinations_60s': 1.0,
              'families_60s': 1.0, 'repetition_60s': .5, 'sequential_60s': .7,
              'anomaly_60s': 2.5, 'credentials_60s': 3.0, 'continuation_60s': 1.0,
              'persistence_900s': .5}

WEIGHTS_V2 = dict(WEIGHTS_V1, **{'deception_60s': 1.0, 'connections_60s': 1.0})

#: v3. The window-parity rule, applied to both families measured over two
#: windows. Each family's *total* weight is unchanged from v2 — 4.5 for port
#: breadth, 1.0 for connection rate — and split evenly between the two windows
#: instead of being concentrated in the short one. Nothing gets louder; the
#: discount for arriving slowly is what goes away.
WEIGHTS_V3 = dict(WEIGHTS_V2, **{'ports_60s': 2.25, 'ports_900s': 2.25,
                                 'connections_60s': .5, 'connections_900s': .5})

#: v4 has no feature weights at all: `families.RELIABILITY` says how far each
#: *phenomenon* may be trusted and `composition.py` says what several of them
#: amount to. `WEIGHTS` stays bound to the v3 table so that anything still
#: reading it — a report, a review queue, a decision record written under v3 —
#: keeps reading the arithmetic that produced those records rather than silently
#: finding an empty dictionary.
WEIGHTS = WEIGHTS_V3

#: Destination-breadth anchor. The floor is `correlation.engine.classify`'s,
#: unchanged since P2: fewer than four distinct local addresses is not breadth.
#: The ceiling is twice the floor — double the threshold for breadth is as much
#: breadth as this evidence can state. It is written as a multiple rather than a
#: literal so the relationship stays visible: a ceiling chosen independently of
#: the floor is how v2 ended up saturating at a number the quantity could not
#: reach.
DESTINATION_FLOOR = 4
DESTINATION_CEILING = 2 * DESTINATION_FLOOR

#: Decoy-contact anchor. Below the floor a contact is a mistake rather than a
#: pattern; the ceiling is where sustained enumeration has already said
#: everything it is going to say.
DECEPTION_FLOOR = 3
DECEPTION_CEILING = 32

_CEILINGS = {name: ceiling for name, ceiling, *_ in SPEC}


def decay(score, elapsed, half_life):
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (score, elapsed, half_life)):
        raise ValueError('finite decay arguments required')
    if not 0 <= score <= 1 or elapsed < 0 or half_life <= 0:
        raise ValueError('invalid decay domain')
    return score * math.exp2(-min(elapsed / half_life, 1075))


def destination_breadth(normalised_value):
    """Re-score address breadth against what one sensor can actually see.

    `normalised_value` is the transformed feature, so the raw count is recovered
    by multiplying by the feature ceiling. Below the floor this returns 0: two
    addresses is a client that found the service twice, not breadth.
    """
    raw = max(0.0, float(normalised_value)) * _CEILINGS['destinations_60s']
    if raw < DESTINATION_FLOOR:
        return 0.0
    return min(1.0, raw / DESTINATION_CEILING)


def long_window_ports(normalised_value):
    """Re-anchor 900 s port breadth to the same count as the 60 s term.

    The feature contract normalises `ports_60s` by 64 and `ports_900s` by 128,
    so the *same* twenty ports read as 0.31 over a minute and 0.16 over a
    quarter of an hour. Combined with v2's lower weight on the long window, an
    identical set of ports was worth four times less to a patient source than to
    a hurried one.

    Nothing in the threat model justifies that. Twenty distinct ports touched is
    twenty distinct ports touched, and taking fifteen minutes over it is a
    choice an adversary makes precisely because it is cheaper to get away with.
    So the long window is re-anchored to the short window's count here, in the
    engine, leaving the feature contract, the transform and every model input
    exactly as they are.
    """
    ratio = _CEILINGS['ports_900s'] / _CEILINGS['ports_60s']
    return min(1.0, max(0.0, float(normalised_value)) * ratio)


def deception_interaction(normalised_value):
    """Re-score decoy contact so a mistake and an enumeration are not the same.

    Same shape as `destination_breadth`, and for the same reason: the feature
    ceiling is a storage bound rather than a statement about how much of
    something is a lot.
    """
    raw = max(0.0, float(normalised_value)) * _CEILINGS['deception_60s']
    if raw < DECEPTION_FLOOR:
        return 0.0
    return min(1.0, raw / DECEPTION_CEILING)


@dataclass(frozen=True, slots=True)
class MathRiskResult:
    score: float
    contributions: dict[str, float]
    model_version: str = VERSION
    #: v4. The family scores the composition consumed, and the composition's own
    #: account of itself. Empty under v3, which had no family layer.
    family_scores: dict = field(default_factory=dict)
    composition: dict = field(default_factory=dict)


class MathRiskEngine:
    """Deterministic, explainable, and explicitly not a probability.

    The output is a bounded score. `decision/scores.RiskScore` is the type that
    says so, and `decision/calibration.py` is what turns it into something the
    cost arithmetic may use.

    **v4 changes the shape, not the ingredients.** A weighted sum of features
    becomes a score per evidence family and a composition over those, because a
    sum cannot express "several weak independent behaviours are collectively
    strong" without individual weights large enough to let one ambiguous feature
    act alone. `families.py` and `composition.py` carry the reasoning.

    `evaluate_v3` keeps the previous arithmetic runnable. It is what the
    composition ablation compares against, and what lets a decision record
    written under v3 be recomputed rather than merely believed.
    """

    def __init__(self, *, composition=None):
        self.composition = composition or EvidenceCompositionEngine()

    def evaluate(self, vector):
        family_scores = families.scores(vector)
        effective = families.effective(family_scores)
        score, parts = self.composition.evaluate(effective)
        # `contributions` keeps its meaning for every reader of a decision
        # record: what pushed this score up, and by how much. Under v4 the
        # contributors are families and justified pairs rather than raw
        # features, which is what `signal_diversity` has always wanted to count.
        return MathRiskResult(score, dict(parts), VERSION,
                              family_scores=family_scores,
                              composition=self.composition.explain(parts))

    def evaluate_v3(self, vector):
        """The P15.3 arithmetic, kept runnable for comparison and for replay."""
        normalized = dict(zip(NAMES, FeatureTransformer.transform(vector), strict=False))
        normalized['destinations_60s'] = destination_breadth(
            normalized.get('destinations_60s', 0.0))
        normalized['deception_60s'] = deception_interaction(
            normalized.get('deception_60s', 0.0))
        normalized['ports_900s'] = long_window_ports(
            normalized.get('ports_900s', 0.0))
        terms = {name: weight * normalized[name] for name, weight in WEIGHTS_V3.items()}
        z = BIAS + sum(terms.values())
        return MathRiskResult(1 / (1 + math.exp(-z)), terms, VERSION_V3)
