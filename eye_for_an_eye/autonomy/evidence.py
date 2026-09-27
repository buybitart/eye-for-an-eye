"""Independent evidence families, and why counting features is not counting evidence.

A source that opened many connections, at a high request rate, in bursts, has
done **one** thing. `connections_60s`, `request_rate_60s` and `burst_count` all
describe it, and a system that treated them as three votes would have talked
itself into confidence it had not earned (§23).

So evidence is grouped into families by *what phenomenon it describes*, and a
family contributes at most once no matter how many features it contains. Signal
diversity is the number of distinct families with real evidence in them — not the
number of features above a threshold, and not a sum.

This matters most in the case it is designed for. A single very high number in
one family is what a misconfigured monitoring probe, a legitimate crawler and a
backup job all look like. Three families agreeing is a different kind of claim:
rate, and port breadth, and continued protocol enumeration after a believable
reply, is a description of behaviour that ordinary clients do not produce by
accident.

The families are deliberately coarse. Ten of them, fixed, with every feature
assigned to exactly one — because a feature that could count under two families
would be the double-counting problem wearing a different hat.
"""
from dataclasses import dataclass, field

#: The ten families (§22). Fixed, and every feature belongs to exactly one.
NETWORK_RATE = 'NETWORK_RATE'
PORT_BREADTH = 'PORT_BREADTH'
PROTOCOL_BEHAVIOR = 'PROTOCOL_BEHAVIOR'
HTTP_DISCOVERY = 'HTTP_DISCOVERY'
AUTH_BEHAVIOR = 'AUTH_BEHAVIOR'
TIMING = 'TIMING'
PERSISTENCE = 'PERSISTENCE'
DECEPTION_INTERACTION = 'DECEPTION_INTERACTION'
ML_CLASSIFIER = 'ML_CLASSIFIER'
ANOMALY = 'ANOMALY'

FAMILIES = (NETWORK_RATE, PORT_BREADTH, PROTOCOL_BEHAVIOR, HTTP_DISCOVERY,
            AUTH_BEHAVIOR, TIMING, PERSISTENCE, DECEPTION_INTERACTION,
            ML_CLASSIFIER, ANOMALY)

#: Families that describe what the source *did*. These are the ones that can
#: support a block. The two below them describe what a model *thinks*, which is
#: a different kind of statement and is counted separately.
BEHAVIOURAL_FAMILIES = (NETWORK_RATE, PORT_BREADTH, PROTOCOL_BEHAVIOR,
                        HTTP_DISCOVERY, AUTH_BEHAVIOR, TIMING, PERSISTENCE,
                        DECEPTION_INTERACTION)

#: Model opinion. Real evidence, and not a substitute for behaviour: a block
#: supported only by `ML_CLASSIFIER` and `ANOMALY` is a block supported by two
#: opinions about the same vector, which is one opinion (§86).
MODEL_FAMILIES = (ML_CLASSIFIER, ANOMALY)

#: Which family each raw feature belongs to. A feature absent from this map
#: contributes to no family, which is the safe direction: an unmapped feature
#: cannot manufacture diversity.
FEATURE_FAMILIES = {
    # One phenomenon: how much traffic arrived.
    'connections_10s': NETWORK_RATE, 'connections_60s': NETWORK_RATE,
    'connections_900s': NETWORK_RATE, 'burst_10s': NETWORK_RATE,
    'requests_60s': NETWORK_RATE, 'requests_900s': NETWORK_RATE,
    # One phenomenon: how much of the attack surface was touched.
    'ports_60s': PORT_BREADTH, 'ports_900s': PORT_BREADTH,
    'destinations_60s': PORT_BREADTH, 'sequential_60s': PORT_BREADTH,
    # Protocol-level oddity, including continuing after a believable reply.
    'families_60s': PROTOCOL_BEHAVIOR, 'anomaly_60s': PROTOCOL_BEHAVIOR,
    'protocol_anomaly': PROTOCOL_BEHAVIOR,
    # HTTP surface discovery.
    'unique_paths_60s': HTTP_DISCOVERY, 'unique_paths_900s': HTTP_DISCOVERY,
    'sensitive_paths_60s': HTTP_DISCOVERY, 'status_4xx_60s': HTTP_DISCOVERY,
    'method_diversity_60s': HTTP_DISCOVERY,
    # Authentication ABUSE: failure, and what shape it has. `credentials_60s`
    # is deliberately absent (§8). It measures credential *presence*, which
    # every authenticated API client produces on every request, and letting it
    # create AUTH_BEHAVIOR evidence on its own is the defect that blocked 21 of
    # 22 sources of a legitimate batch client on the P15.3 benchmark. It remains
    # in the feature schema as descriptive telemetry and belongs to no family.
    'auth_failures_60s': AUTH_BEHAVIOR, 'auth_successes_60s': AUTH_BEHAVIOR,
    'auth_failure_ratio': AUTH_BEHAVIOR, 'auth_principals_900s': AUTH_BEHAVIOR,
    'auth_failure_span_900s': AUTH_BEHAVIOR,
    # Machine-like regularity, in either window.
    'interarrival_mean_60s': TIMING, 'interarrival_cv_60s': TIMING,
    'interval_mean_900s': TIMING, 'interval_cv_900s': TIMING,
    'interval_entropy_900s': TIMING,
    # How long this has been going on.
    'persistence_900s': PERSISTENCE, 'continuation_60s': PERSISTENCE,
    'repetition_60s': PERSISTENCE,
    # Interaction with something that exists only to be interacted with.
    'deception_60s': DECEPTION_INTERACTION,
}


@dataclass
class SignalFamilies:
    """Which families have evidence, how strong, and how diverse that is.

    Strength per family is the **maximum** contributing term, never the sum:
    three features describing one phenomenon do not make that phenomenon three
    times as true.
    """

    #: family -> strength in [0, 1]
    strengths: dict = field(default_factory=dict)
    #: family -> the feature or component that produced the maximum
    witnesses: dict = field(default_factory=dict)
    #: Below this, a family is noise rather than evidence.
    floor: float = 0.15

    def record(self, family, strength, witness=''):
        """Add one observation. Keeps the strongest, never accumulates."""
        if family not in FAMILIES:
            return self
        value = max(0.0, min(1.0, float(strength)))
        if value > self.strengths.get(family, 0.0):
            self.strengths[family] = value
            self.witnesses[family] = str(witness)[:64]
        return self

    def record_contributions(self, contributions):
        """Map a `MathRiskResult.contributions` dict onto families.

        Two shapes arrive here, because two formula generations do.

        Under `math-risk-v3` and earlier a contribution was keyed by *feature*,
        and `FEATURE_FAMILIES` said which phenomenon that feature described.
        Under v4 the engine already reasons in families, so a contribution is
        keyed by the family itself — or by an interaction, `A+B`, which is
        credited to **both** halves at the interaction's own strength.

        An interaction crediting two families is not double counting. The pair
        exists only because both families were independently above the floor,
        which means both were already recorded; and `record` keeps the maximum
        rather than adding, so a pair can never invent a family or inflate one
        past what it actually scored.

        A key belonging to neither shape is ignored rather than assigned to a
        default, so a new term cannot silently create diversity before somebody
        has decided what phenomenon it describes.
        """
        for name, value in (contributions or {}).items():
            if name in FAMILIES:
                self.record(name, value, witness=name)
                continue
            if '+' in name:
                for half in name.split('+'):
                    if half in FAMILIES:
                        self.record(half, value, witness=name)
                continue
            family = FEATURE_FAMILIES.get(name)
            if family is not None:
                self.record(family, value, witness=name)
        return self

    @property
    def active(self):
        return tuple(sorted(name for name, value in self.strengths.items()
                            if value >= self.floor))

    @property
    def behavioural(self):
        return tuple(name for name in self.active if name in BEHAVIOURAL_FAMILIES)

    @property
    def diversity(self):
        """How many distinct families carry evidence. The number §22 bounds."""
        return len(self.active)

    @property
    def behavioural_diversity(self):
        """Diversity among families that describe what the source *did*."""
        return len(self.behavioural)

    @property
    def model_only(self):
        """True when every active family is a model opinion.

        The case §86 exists to refuse: two models agreeing about one feature
        vector is not independent corroboration, it is one opinion counted twice.
        """
        return bool(self.active) and not self.behavioural

    def strongest(self, count=3):
        ordered = sorted(self.strengths.items(), key=lambda item: -item[1])
        return tuple(name for name, value in ordered[:count] if value >= self.floor)

    def explain(self):
        return {'families': {name: round(value, 4)
                             for name, value in sorted(self.strengths.items())},
                'witnesses': dict(sorted(self.witnesses.items())),
                'active': list(self.active),
                'behavioural': list(self.behavioural),
                'diversity': self.diversity,
                'behavioural_diversity': self.behavioural_diversity,
                'model_only': self.model_only,
                'floor': self.floor,
                'note': ('a family contributes at most once however many features '
                         'describe it')}


def correlated_pairs(contributions, threshold=0.9):
    """Feature pairs in one family that moved together, for the audit report.

    Not used in a decision — it is a reporting aid for §80. Two features in the
    same family being correlated is expected and harmless here precisely because
    the family already collapses them; this function exists so that somebody
    reviewing the feature set can see which ones are redundant.
    """
    grouped = {}
    for name, value in (contributions or {}).items():
        family = FEATURE_FAMILIES.get(name)
        if family:
            grouped.setdefault(family, []).append((name, float(value)))
    pairs = []
    for family, items in grouped.items():
        for index, (first, first_value) in enumerate(items):
            for second, second_value in items[index + 1:]:
                if abs(first_value - second_value) <= (1 - threshold):
                    pairs.append((family, first, second))
    return tuple(pairs)
