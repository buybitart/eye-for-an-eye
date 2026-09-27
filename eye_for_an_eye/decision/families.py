"""Evidence family scores: one bounded number per phenomenon. §21, §22, §23.

### Why this layer exists

Until P15.4 the deterministic engine was a weighted sum of normalised features
against a fixed bias, and P15.3 measured what that cannot express: several
individually weak but *independent* behaviours adding up to a strong case. With
a bias of −4.0 and per-term weights of one or two, four families at 0.4 each
reach 1.6 and land nowhere. The only way to make them reach anything was to
raise an individual weight — which is how a single ambiguous feature acquires
the power to block on its own, and how `credentials_60s` came to block 21 of 22
legitimate API clients.

So the arithmetic is split in two. **This module answers "how strongly does each
phenomenon speak?"** and `composition.py` answers "what do several of them
amount to together?". Neither question is answerable by a single weighted sum,
and separating them means an individual family can be weak — which is usually
the truth — without the system being unable to act on a pile of weak things.

### The rules the scores obey

**One phenomenon, one family, one score (§22).** `connections_10s`,
`connections_60s`, `connections_900s` and `burst_10s` all describe how much
traffic arrived. They contribute to `NETWORK_RATE` by **maximum**, never by sum:
four descriptions of one event are not four events, and a system that added them
would have talked itself into confidence it had not earned.

**Saturating (§23).** Every family score is bounded in [0, 1] and reaches its
ceiling at a level where more of the same says nothing new. A source that sends
a million requests is not a thousand times more suspicious than one that sends a
thousand; it is at the top of what rate can tell you, which is not very much.

**A floor, below which a family is silent.** Ambient traffic produces small
non-zero values everywhere, and a composition rule that accumulates independent
evidence will happily accumulate eight kinds of nothing into something. The
floor is what makes "weak evidence from many families" mean what it says.

**Unavailable is not zero.** A family whose features were never observed scores
`None`, not 0.0. `HTTP_DISCOVERY` has no feature in this schema at all — its
signals are web-layer and this is the network engine — so it is always `None`
here, which is the honest answer rather than a silent vote for innocence.

### What is deliberately weak

`TIMING` is capped hard, and the reason is measured rather than assumed. On the
development corpus the most machine-regular sources are
`hard-negative-monitoring` (interval cv ≈ 0.04) and `hard-negative-health-check`
— both entirely legitimate, both more regular than any scanner in the corpus. A
timing family that could speak loudly would fire hardest on exactly the traffic
it exists to protect. It is kept because co-occurrence with other families is
still informative, and capped because on its own it is nearly worthless.

`AUTH_BEHAVIOR` is built from **failures**, never from credential presence (§8,
§12). `credentials_60s` is deliberately absent from every family below: it
remains in the schema as descriptive telemetry and cannot create authentication
evidence on its own, which is the specific defect P15.4 exists to fix.
"""
from ..autonomy.evidence import (AUTH_BEHAVIOR, DECEPTION_INTERACTION, HTTP_DISCOVERY,
                                 NETWORK_RATE, PERSISTENCE, PORT_BREADTH,
                                 PROTOCOL_BEHAVIOR, TIMING)
from .auth import MIN_FAILURES_FOR_A_DERIVED_STATISTIC
from .features import NAMES

FAMILY_SCORE_VERSION = 'family-scores-v1'

#: Behavioural families this engine can score, in a fixed order.
SCORED_FAMILIES = (NETWORK_RATE, PORT_BREADTH, PROTOCOL_BEHAVIOR, AUTH_BEHAVIOR,
                   TIMING, PERSISTENCE, DECEPTION_INTERACTION, HTTP_DISCOVERY)

#: Below this a family is noise rather than evidence, and contributes nothing.
#: Shared rather than per-family so that "weak" means one thing everywhere; a
#: family that needs a different sensitivity expresses it in its own transform.
FLOOR = 0.15

#: How much any single family may assert on its own, before composition. This is
#: the replacement for the individual weights that made one ambiguous feature
#: dangerous: no family here can reach certainty alone, and the ones measured to
#: be ambiguous are held furthest from it.
#:
#: Every value is a judgement made without deployment data, and the two unusual
#: ones are unusual for measured reasons recorded in the module docstring.
RELIABILITY = {
    NETWORK_RATE: 0.35,            # legitimate clients are often the loudest
    PORT_BREADTH: 0.80,            # an ordinary client has no reason to sweep
    PROTOCOL_BEHAVIOR: 0.70,       # a request shaped for another service
    AUTH_BEHAVIOR: 0.75,           # repeated *failure*, not presence
    TIMING: 0.25,                  # benign monitoring is the most regular thing here
    PERSISTENCE: 0.45,             # long sessions are normal; long probing is not
    DECEPTION_INTERACTION: 0.70,   # a decoy has no legitimate use, but see below
    HTTP_DISCOVERY: 0.70,          # unobservable in this engine; scored elsewhere
}

#: Families that may corroborate but may never carry a case on their own.
#:
#: The split is between **what a source did** and **how it did it**.
#:
#: Port breadth, protocol misuse, authentication failure and decoy contact are
#: things ordinary clients do not do. Rate, regularity and duration are things
#: ordinary clients do constantly: the loudest sources on any network are a
#: backup job and a health checker, the most machine-regular is a monitoring
#: agent, and the longest-lived is whichever daemon started first. A manner
#: family that could carry would add a near-constant to every automated client
#: on the network — and a constant added to everything is not evidence about
#: anything. That is `credentials_60s`'s mistake in a different costume, and
#: P15.4 exists because of how expensive that mistake was.
#:
#: They stay in the taxonomy because *co-occurrence* is informative and the
#: conjunctions are much narrower than the parts: a monitoring agent is regular
#: and does not sweep; a backup client is loud against one port; a long-lived
#: daemon is not also enumerating. `composition.py` admits these families only
#: through the named interactions in `INTERACTIONS`, which is where the brief's
#: own examples — RATE + PORT_BREADTH, LOW_RATE + LONG_PERSISTENCE — live.
CORROBORATING_ONLY = frozenset({NETWORK_RATE, TIMING, PERSISTENCE})

#: Families that may carry a case: the ones that describe what was *done*.
CARRYING_FAMILIES = tuple(f for f in SCORED_FAMILIES if f not in CORROBORATING_ONLY)


def _ratio(value, ceiling, floor=0.0):
    """Linear, floored, saturating. `None` in, `None` out."""
    if value is None:
        return None
    raw = max(0.0, float(value))
    if raw <= floor:
        return 0.0
    return min(1.0, (raw - floor) / (ceiling - floor))


def _strongest(parts):
    """The loudest sub-signal of one phenomenon, or `None` if none was observed.

    Maximum, never sum: several features describing one event describe one
    event. This is the rule that stops `connections_10s`, `connections_60s` and
    `burst_10s` becoming three votes for the same traffic.
    """
    seen = [value for value in parts if value is not None]
    return max(seen) if seen else None


def network_rate(f):
    """How much traffic arrived. Weak evidence, and measured to be weak.

    A backup client, a crawler and a health checker are among the loudest things
    on any network. Rate saturates early because the difference between "busy"
    and "very busy" is not a difference in intent.
    """
    return _strongest((
        _ratio(f['connections_60s'], 120, floor=20),
        _ratio(f['connections_900s'], 600, floor=60),
        # A burst is a shape, not a volume: the fraction of a minute's attempts
        # that arrived in ten seconds.
        _ratio(f['burst_10s'], 0.9, floor=0.4),
    ))


def port_breadth(f):
    """How much of the attack surface was touched, by port or by address.

    Both windows are anchored to the same count, so patience is not a discount —
    the P15.3 finding, kept. Address breadth saturates at the number of
    addresses one protected host plausibly has; touching all of them is as much
    breadth as this evidence can state.
    """
    return _strongest((
        _ratio(f['ports_60s'], 24, floor=4),
        _ratio(f['ports_900s'], 24, floor=4),
        _ratio(f['destinations_60s'], 8, floor=3),
        # Walking ports in order is a shape no ordinary client produces, but it
        # is only meaningful once there are several ports to walk.
        _ratio(f['sequential_60s'], 1.0, floor=0.5)
        if (f['ports_60s'] or 0) >= 4 else None,
    ))


def protocol_behavior(f):
    """A request that does not fit the service it was sent to."""
    return _strongest((
        _ratio(f['anomaly_60s'], 0.5, floor=0.1),
        _ratio(f['families_60s'], 4, floor=1),
    ))


def auth_behavior(f):
    """Repeated authentication **failure**, and what shape it has. §12.

    Never credential presence. A client that authenticates successfully on every
    request — which is most machine-to-machine traffic — scores exactly zero
    here, however often it does it. What counts is refusal: how many, what
    fraction of attempts, across how many distinct principals, over how long.

    Principal diversity is the strongest of these and is treated as such: one
    source failing against many accounts is a spray, and there is no ordinary
    client that does it. A single account failing repeatedly is a person who has
    forgotten a password, and the ratio and count alone are deliberately too
    weak to act on.
    """
    failures = f['auth_failures_60s']
    return _strongest((
        _ratio(failures, 12, floor=3),
        # A ratio over three attempts is not a ratio. Somebody mistyping a
        # password twice in three tries scores 0.67 and means nothing by it, so
        # the ratio only speaks once there is enough of a denominator for it to
        # be a measurement — the same rule `sequential_60s` follows about having
        # enough ports to walk, and the same constant the *span* is gated on in
        # `correlation/auth_state.py`, which is why it is imported rather than
        # written here.
        _ratio(f['auth_failure_ratio'], 0.8, floor=0.3)
        if (failures or 0) >= MIN_FAILURES_FOR_A_DERIVED_STATISTIC else None,
        _ratio(f['auth_principals_900s'], 8, floor=2),
        # Failing steadily for a quarter of an hour is not a forgotten password.
        # It is also not, on its own, an attack: the likeliest thing in the world
        # to fail every twenty-six seconds from one account for ten minutes is a
        # scheduled job whose password was rotated and whose config file was not
        # updated. `profiles.stale_credential_client` is that job, and against
        # this term ungated it scored **0.784** — higher than any other benign
        # source in the development corpus and higher than several real attacks,
        # off this single sub-signal reaching 1.0 on its own.
        #
        # Which is `credentials_60s` again, one layer along and one cycle later:
        # a quantity that is arithmetically true and does not mean what its name
        # says. So the span speaks only about failures spread across more than
        # one account. One account failing for an hour is a stuck client; several
        # accounts failing for an hour is somebody working through a list, and
        # that is the behaviour the term was written for.
        #
        # The cost is stated rather than hidden: where principal identity is
        # unavailable — HTTP, where the account name sits inside an
        # `Authorization` value this system refuses to read — the span cannot
        # speak at all, and such a source has to be carried by failure volume.
        # `training/observability.py` predeclares that for `positive-web-stuffing`.
        # The ledger's own gate still applies underneath this one: it reports no
        # span until enough refusals fall in the window to make one a measurement.
        _ratio(f['auth_failure_span_900s'], 300, floor=60)
        if (f['auth_principals_900s'] or 0) >= 2 else None,
    ))


def timing(f):
    """Machine-like regularity. Capped hard, for a measured reason.

    Low inter-arrival variation means an automated client, and automated is not
    malicious: the most regular sources in the development corpus are a
    monitoring agent and a health checker. This family exists to *corroborate*,
    never to carry, and `RELIABILITY` holds it to a quarter of what a family can
    assert.
    """
    cv = f['interarrival_cv_60s']
    if cv is None:
        return None
    # Inverted: low variation is the signal. Nothing below cv 0.5 is remarkable.
    return _ratio(max(0.0, 0.5 - float(cv)), 0.45, floor=0.05)


def persistence(f):
    """How long this went on, and whether it kept going when a client would stop."""
    return _strongest((
        _ratio(f['persistence_900s'], 300, floor=60),
        _ratio(f['continuation_60s'], 0.6, floor=0.15),
        _ratio(f['repetition_60s'], 0.8, floor=0.35),
    ))


def deception_interaction(f):
    """Contact with something that exists only to be contacted.

    The cleanest signal available to this sensor and still not proof: a
    legitimate client that reaches a decoy and gives up produces a median of four
    contacts and as many as nine, while an enumerating source produces about
    thirty. The distributions overlap, so the floor sits above a brush-past and
    the family is weighted as strong evidence rather than as certainty.
    """
    return _ratio(f['deception_60s'], 32, floor=3)


def http_discovery(f):
    """Always `None` here. Its features are web-layer; this is the network engine.

    Kept in the taxonomy rather than dropped, because the web sensor scores it
    and a family that exists in one engine and not the other is a fact about
    where a signal is observed, not a gap to paper over.
    """
    _ = f
    return None


SCORERS = {
    NETWORK_RATE: network_rate,
    PORT_BREADTH: port_breadth,
    PROTOCOL_BEHAVIOR: protocol_behavior,
    AUTH_BEHAVIOR: auth_behavior,
    TIMING: timing,
    PERSISTENCE: persistence,
    DECEPTION_INTERACTION: deception_interaction,
    HTTP_DISCOVERY: http_discovery,
}


def scores(vector):
    """family -> score in [0, 1], `None` where the family was not observed.

    Raw feature values are used, not the transformed tensor: each family states
    its own anchors above, in the units a person can argue with. That is the
    point of the layer — `ports_60s` saturating at 24 is a claim about scanning
    that somebody can disagree with, and `ports_60s / 64` is not a claim at all.
    """
    f = dict(zip(NAMES, vector.values, strict=True))
    return {family: SCORERS[family](f) for family in SCORED_FAMILIES}


def effective(family_scores, *, floor=FLOOR, reliability=None):
    """Scores after the floor and the per-family reliability cap.

    This is what `composition.py` consumes. Keeping it separate from `scores`
    means the raw family strengths stay readable in a decision record, and the
    two adjustments that make them safe to combine are visible rather than baked
    into each scorer.
    """
    reliability = reliability or RELIABILITY
    out = {}
    for family, score in family_scores.items():
        if score is None or score < floor:
            continue
        out[family] = min(1.0, max(0.0, float(score))) * reliability.get(family, 0.5)
    return out


def explain(family_scores):
    return {'family_score_version': FAMILY_SCORE_VERSION,
            'floor': FLOOR,
            'scores': {family: None if value is None else round(value, 6)
                       for family, value in sorted(family_scores.items())},
            'observed': sorted(family for family, value in family_scores.items()
                               if value is not None),
            'above_floor': sorted(family for family, value in family_scores.items()
                                  if value is not None and value >= FLOOR)}
