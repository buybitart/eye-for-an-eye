"""What several independent evidence families amount to together. §24 to §27.

### The problem this solves

P15.3 measured a structural limit rather than a tuning mistake. The deterministic
engine was a weighted sum of normalised features against a bias of −4.0, and
that shape cannot express:

    several individually weak but independent behaviours
        → collectively strong

Four families at 0.4 each reach 1.6 against a bias of 4.0 and land nowhere. The
only lever that made them reach anything was raising an individual weight, and
an individual weight large enough to matter is an individual feature powerful
enough to block on its own — which is exactly how `credentials_60s` at 3.0 came
to block 21 of 22 sources of a legitimate API client. **The additive form forced
a choice between "cannot combine weak evidence" and "one ambiguous feature can
act alone", and P15.3 shipped the second by accident.**

Two of the corpus families demonstrate the cost directly:
`composite-paced-breadth` and `composite-decoy-recon` were built from primitives
the corpus already contained, arranged so that no single family is loud, and
both were detected on zero of fourteen sources.

### Why noisy-OR

Of the four candidates in §25 — bounded additive, additive with interactions,
noisy-OR, small monotone logistic — only noisy-OR *says* the thing the problem
statement asks for, and it says it as arithmetic rather than as a tuned
coefficient:

    P(malicious) = 1 − Π (1 − pᵢ)

Read aloud: the source is innocent only if **every** family is independently
wrong about it. Four families each 40% convincing leave 0.6⁴ ≈ 13% innocence,
which is what "several weak independent signals" ought to mean and what a sum
cannot produce without dangerous individual weights. It is bounded in [0, 1] by
construction, monotone in every input, deterministic, and explainable to an
operator in one sentence.

The three alternatives are implemented beside it rather than argued away,
because §25 asks for a benchmark and not a preference. They are compared in
`reports/P15_4_COMPOSITION_ABLATION.json`.

### Why noisy-OR is safe here, which it is not in general

Noisy-OR accumulates. Eight families at 0.2 each would reach 0.83, and if
ordinary traffic produced small values everywhere the rule would convict the
whole internet. Two things stop that, and both live in `families.py` where they
can be read:

* **the floor** — a family below `FLOOR` contributes *nothing at all*, so
  ambient noise never enters the product;
* **reliability caps** — no family may assert more than its measured
  trustworthiness, and the two that benign traffic produces most readily
  (`NETWORK_RATE`, `TIMING`) are held to 0.35 and 0.25.

The result is that accumulation requires several families to be genuinely,
separately above the floor. That is the behaviour being bought, and the price is
paid in the family scores rather than in the composition rule.

### Interactions

§26 allows pairwise terms for co-occurrences that mean more than their parts,
and §27 insists they must not re-count the parts. Each pair here enters as one
additional pseudo-family whose strength is `k · min(a, b)`:

* `min` is the co-occurrence operator — it is zero unless **both** are present,
  and it can never exceed either, so the pair cannot restate what one family
  already said;
* `k` is small and bounded, so a pair supplements the case and never carries it;
* being a pseudo-family means it composes through the same rule as everything
  else, with no separate arithmetic to reason about.

Five pairs, each with a behavioural argument stated at its definition. Not
N×N — a pair without an argument is a coincidence, and thirty of them would be
a model nobody can inspect fitted by a route nobody chose.
"""
import math

from ..autonomy.evidence import (AUTH_BEHAVIOR, DECEPTION_INTERACTION, NETWORK_RATE,
                                 PERSISTENCE, PORT_BREADTH, PROTOCOL_BEHAVIOR, TIMING)

COMPOSITION_VERSION = 'evidence-composition-v1'

#: The methods §25 asks to be compared. `NOISY_OR` is the selected one; the
#: others are kept runnable so the comparison in the report is a measurement
#: rather than an argument, and so a later cycle can re-run it.
ADDITIVE = 'bounded_additive'
ADDITIVE_INTERACTIONS = 'additive_with_interactions'
NOISY_OR = 'noisy_or'
LOGISTIC = 'monotone_logistic'
METHODS = (ADDITIVE, ADDITIVE_INTERACTIONS, NOISY_OR, LOGISTIC)

#: Justified co-occurrences (§26). Each is (family, family, strength, why).
#:
#: The strengths are deliberately small: the largest is 0.35, so even a perfect
#: co-occurrence of two fully-present families adds less than either family
#: does. A pair is a corroboration, not a third opinion.
INTERACTIONS = (
    (AUTH_BEHAVIOR, PORT_BREADTH, 0.35,
     'failing to authenticate while also sweeping the service surface is a '
     'credential attack with reconnaissance attached; neither half explains the '
     'other, and an ordinary client that mistypes a password does not also walk '
     'twenty ports'),
    (NETWORK_RATE, PORT_BREADTH, 0.30,
     'volume and breadth together are a scan. Volume alone is a backup client '
     'and breadth alone is an administrator, which is why each is weak on its '
     'own and the conjunction is not'),
    (PERSISTENCE, PORT_BREADTH, 0.30,
     'breadth sustained over a quarter of an hour is the low-and-slow shape '
     'that neither a burst nor a long session produces by itself'),
    (DECEPTION_INTERACTION, PROTOCOL_BEHAVIOR, 0.30,
     'touching a decoy and then speaking a protocol it does not implement is '
     'enumeration rather than a stale configuration reaching a dead port'),
    (PROTOCOL_BEHAVIOR, PERSISTENCE, 0.25,
     'continuing to send malformed or misdirected requests after a believable '
     'reply is what separates a broken client from one that is probing'),
    (TIMING, PORT_BREADTH, 0.25,
     'machine-regular *and* sweeping. Regularity alone is the normal state of '
     'automation and describes the monitoring agent as well as the scanner, '
     'which is why TIMING may never carry a case; a monitoring agent that also '
     'walks the port range is not a monitoring agent'),
    (AUTH_BEHAVIOR, PERSISTENCE, 0.30,
     'authentication failing steadily over a quarter of an hour. A person who '
     'has forgotten a password fails a few times and stops or succeeds; nothing '
     'legitimate keeps failing patiently, which is the low-and-slow credential '
     'shape the count alone is too weak to reach'),
    (NETWORK_RATE, AUTH_BEHAVIOR, 0.25,
     'failing authentication at volume. Rate alone is a backup client and '
     'failure alone is a person mistyping; together they are the brute force '
     'neither half describes'),
)

#: Bias and scale for the additive and logistic comparators. Kept close to the
#: P15.3 engine so the ablation measures the *shape* of the composition rather
#: than an incidental change of scale.
LOGISTIC_BIAS = -4.0
LOGISTIC_SCALE = 6.0


def _pairs(effective):
    """Interaction pseudo-families: `k · min(a, b)`, only when both are present."""
    out = {}
    for first, second, strength, _ in INTERACTIONS:
        left, right = effective.get(first), effective.get(second)
        if not left or not right:
            continue
        out[f'{first}+{second}'] = strength * min(left, right)
    return out


def noisy_or(parts):
    """1 − Π(1 − p). Innocent only if every independent signal is wrong."""
    innocence = 1.0
    for value in parts.values():
        innocence *= (1.0 - min(0.999999, max(0.0, value)))
    return 1.0 - innocence


def compose(effective, *, method=NOISY_OR, interactions=True):
    """Combine effective family strengths into one bounded uncalibrated score.

    The result is a `RiskScore`, not a probability, exactly as before: it is
    ranked and then calibrated, and `decision/scores.py` is what refuses to let
    it be mistaken for the other thing.
    """
    if method not in METHODS:
        raise ValueError(f'unknown composition method {method!r}')
    from .families import CORROBORATING_ONLY
    # A corroborating family never enters the product on its own. It is still
    # available to the interaction terms below, which is the whole of its job:
    # "regular" describes every automated client on the network and would add a
    # constant to all of them, while "regular *and* sweeping" describes a much
    # smaller set. See `families.CORROBORATING_ONLY`.
    parts = {name: value for name, value in effective.items()
             if name not in CORROBORATING_ONLY}
    if interactions:
        parts.update(_pairs(effective))
    if not parts:
        return 0.0, {}
    if method == NOISY_OR:
        return noisy_or(parts), parts
    if method in (ADDITIVE, ADDITIVE_INTERACTIONS):
        if method == ADDITIVE:
            parts = {name: value for name, value in effective.items()
                     if name not in CORROBORATING_ONLY}
        return min(1.0, sum(parts.values())), parts
    # LOGISTIC: a monotone squash of the same sum, kept for the comparison. It
    # has the additive form's problem by construction — it can only be made to
    # fire on several weak families by a scale that also fires on one strong one
    # — and measuring that is the point of including it.
    total = sum(parts.values())
    return 1.0 / (1.0 + math.exp(-(LOGISTIC_BIAS + LOGISTIC_SCALE * total))), parts


class EvidenceCompositionEngine:
    """Deterministic, bounded, inspectable composition of family evidence. §20, §24.

    No opaque model, and none is needed: the rule is one line of arithmetic with
    a sentence of meaning attached, and every input to it is a named family score
    with its own stated anchors.
    """

    def __init__(self, method=NOISY_OR, *, interactions=True):
        if method not in METHODS:
            raise ValueError(f'unknown composition method {method!r}')
        self.method = method
        self.interactions = interactions

    def evaluate(self, effective):
        score, parts = compose(effective, method=self.method, interactions=self.interactions)
        return score, parts

    def explain(self, parts):
        base = {name: round(value, 6) for name, value in sorted(parts.items())
                if '+' not in name}
        pairs = {name: round(value, 6) for name, value in sorted(parts.items())
                 if '+' in name}
        return {
            'composition_version': COMPOSITION_VERSION,
            'method': self.method,
            'families': base,
            'interactions': pairs,
            'interaction_share': round(sum(pairs.values()), 6),
            'note': ('interaction terms are k*min(a, b): zero unless both '
                     'families are present, never larger than either, and '
                     'bounded well below what a family contributes'),
        }


def audit():
    """Double-counting audit (§27), as a check rather than an assurance.

    Two properties, both mechanical:

    * every interaction names two **different** families, so no pair can restate
      one family twice;
    * every interaction's maximum possible contribution is strictly below the
      smaller of the two families' own maxima, so a pair can never contribute
      more than the evidence it corroborates.
    """
    from .families import RELIABILITY
    findings = []
    seen = set()
    for first, second, strength, _ in INTERACTIONS:
        if first == second:
            findings.append(f'{first} interacts with itself')
        key = frozenset((first, second))
        if key in seen:
            findings.append(f'{first}+{second} appears more than once')
        seen.add(key)
        ceiling = strength * min(RELIABILITY.get(first, 0.5), RELIABILITY.get(second, 0.5))
        floor_of_pair = min(RELIABILITY.get(first, 0.5), RELIABILITY.get(second, 0.5))
        if ceiling >= floor_of_pair:
            findings.append(f'{first}+{second} can contribute more than either family')
    return {'interactions': len(INTERACTIONS), 'findings': findings,
            'verdict': 'PASS' if not findings else 'FAIL'}
