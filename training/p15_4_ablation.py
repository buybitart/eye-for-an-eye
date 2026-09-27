"""What each piece of P15.4 is actually worth. §65, §66, §67.

Three changes were made this cycle, each defended by an argument. An argument is
not a measurement, and a change that sounds right and does nothing is worse than
no change at all — it costs complexity and buys a story. So each is run against
the development corpus with the other two held fixed, beside the alternatives it
was chosen over, and the numbers go in a report whether or not they flatter the
choice.

### What is measured, and why not accuracy

No calibrator is fitted yet — §30 forbids it until the formula is frozen, and
these ablations are part of what freezes it — so there is no probability and no
threshold, and any "detection rate" would be a number about a cutoff nobody has
chosen. What can be measured without one is *ranking*, and ranking is what a
cutoff later consumes:

* **AUC** — the chance a randomly chosen malicious source outranks a randomly
  chosen benign one. Threshold-free by construction.
* **worst benign** — the highest score any benign source reaches. This is the
  number a cutoff has to clear, so it is the one that decides whether detection
  is affordable at all.
* **clean separation** — the fraction of malicious sources scoring strictly
  above every benign source. The only detection figure available without a
  threshold, and a deliberately harsh one.

All three are computed **per source**, not per window, because a source is what
gets blocked. A source's score is its worst window, since a block is taken on one
window and a benign source is only safe if all of its windows are.

### The one thing these numbers cannot say

The development corpus is development data. Every number here was available
while the design was being settled, so none of it is evidence of generalisation
— that is what the locked benchmark and the two withheld families are for. These
ablations answer a narrower question: given this design, does each part carry its
weight, and would a simpler alternative have done as well?
"""
from collections import defaultdict
import json
from pathlib import Path

from dataset import store
from eye_for_an_eye.autonomy import maturity as maturity_module
from eye_for_an_eye.decision import composition as composition_module
from eye_for_an_eye.decision import families as families_module
from eye_for_an_eye.decision import math_risk
from eye_for_an_eye.decision.features import NAMES, completeness

ABLATION_SCHEMA_VERSION = 1

#: The corpus these run against. Development data, stated as such everywhere it
#: is reported, so a reader cannot mistake one of these numbers for a result.
DEVELOPMENT_CORPUS = 'datasets/p15-4-dev-v1/processed/dataset-p15-4-dev-v1/samples.csv'

BENIGN = 'benign_like'
MALICIOUS = 'malicious_automation_like'


# --- measurement ------------------------------------------------------------


def auc(positive, negative):
    """Rank-based AUC. 0.5 is a coin, 1.0 separates perfectly.

    Mann-Whitney U over the pooled ranks, ties shared, so a family that scores
    every source identically reports 0.5 rather than something flattering.
    """
    if not positive or not negative:
        return None
    pooled = sorted([(value, 1) for value in positive] + [(value, 0) for value in negative])
    ranks, index = {}, 0
    while index < len(pooled):
        stop = index
        while stop + 1 < len(pooled) and pooled[stop + 1][0] == pooled[index][0]:
            stop += 1
        shared = (index + stop) / 2 + 1
        for position in range(index, stop + 1):
            ranks.setdefault(position, shared)
        index = stop + 1
    positive_rank_sum = sum(ranks[position] for position, (_, label) in enumerate(pooled) if label)
    count_positive, count_negative = len(positive), len(negative)
    statistic = positive_rank_sum - count_positive * (count_positive + 1) / 2
    return statistic / (count_positive * count_negative)


def separation(scored):
    """AUC, the worst benign source, and clean separation, over one scoring.

    `scored` is {source_group: (label, profile_type, score)}.
    """
    positive = [score for label, _, score in scored.values() if label == MALICIOUS]
    negative = [score for label, _, score in scored.values() if label == BENIGN]
    if not positive or not negative:
        return {'sources': len(scored), 'auc': None}
    worst_benign = max(negative)
    by_profile = defaultdict(lambda: {'benign': [], 'malicious': []})
    for label, profile, score in scored.values():
        by_profile[profile or 'unstated']['malicious' if label == MALICIOUS else 'benign'].append(score)
    return {
        'sources': len(scored),
        'benign_sources': len(negative),
        'malicious_sources': len(positive),
        'auc': round(auc(positive, negative), 6),
        'worst_benign': round(worst_benign, 6),
        'median_benign': round(sorted(negative)[len(negative) // 2], 6),
        'median_malicious': round(sorted(positive)[len(positive) // 2], 6),
        'clean_separation': round(sum(1 for score in positive if score > worst_benign)
                                  / len(positive), 6),
        'per_profile': {
            name: {'benign_sources': len(entry['benign']),
                   'malicious_sources': len(entry['malicious']),
                   'worst_benign': round(max(entry['benign']), 6) if entry['benign'] else None,
                   'median_malicious': (round(sorted(entry['malicious'])[len(entry['malicious']) // 2], 6)
                                        if entry['malicious'] else None),
                   'auc': (round(auc(entry['malicious'], entry['benign']), 6)
                           if entry['malicious'] and entry['benign'] else None)}
            for name, entry in sorted(by_profile.items())},
    }


def per_source(samples, score_of):
    """{source_group: (label, profile, worst window score)}.

    The worst window, because that is the one a block would be taken on. An
    average would hide exactly the window that causes a false block.
    """
    out = {}
    for sample in samples:
        if sample.label not in (BENIGN, MALICIOUS):
            continue
        score = score_of(sample)
        if score is None:
            continue
        key = sample.source_group or sample.sample_id
        current = out.get(key)
        profile = (sample.provenance or {}).get('profile_type')
        if current is None or score > current[2]:
            out[key] = (sample.label, profile, score)
        elif current[1] is None and profile:
            out[key] = (current[0], profile, current[2])
    return out


def load(path=DEVELOPMENT_CORPUS):
    return store.read(path)


# --- §65: what the authentication evidence should be ------------------------

#: Each variant is a set of sub-signals for `AUTH_BEHAVIOR`, combined the way
#: the shipped scorer combines its own: the strongest, never the sum, because
#: several features describing one phenomenon describe one phenomenon.
#:
#: `presence` reconstructs the P15.3 quantity inside the P15.4 shape. That is
#: the only way to compare them at the same layer: the question is not "was
#: MathRisk v3 worse" — it was, for many reasons — but "is credential presence,
#: given everything else P15.4 changed, worth anything at all".
AUTH_VARIANTS = ('presence', 'failures', 'failures_and_diversity',
                 'failures_and_span_ungated', 'failures_and_span',
                 'failures_diversity_span', 'shipped')

AUTH_VARIANT_NOTES = {
    'presence': 'credential presence, the P15.3 quantity, rebuilt inside the P15.4 shape',
    'failures': 'observed refusals in the short window, and nothing else',
    'failures_and_diversity': 'refusals, plus how many distinct accounts were refused',
    'failures_and_span_ungated': (
        'refusals, plus how long refusal went on, with no requirement that more than '
        'one account was involved. This is what the term was before the ablation, and '
        'the row exists because it is what the ablation found'),
    'failures_and_span': 'the same, but the span speaks only across two or more accounts',
    'failures_diversity_span': 'refusals, account diversity, and the gated span',
    'shipped': 'families.auth_behavior itself, called rather than reimplemented',
}


def auth_score(values, variant):
    """One candidate meaning for `AUTH_BEHAVIOR`, combined the shipped way.

    `shipped` calls the real scorer instead of reproducing it. A reimplemented
    baseline drifts from the code it claims to measure, and an ablation whose
    control is stale reports on something nobody ships.
    """
    ratio = families_module._ratio  # noqa: SLF001  the anchors are the point of the layer
    if variant == 'shipped':
        return families_module.auth_behavior(values)
    failures = values['auth_failures_60s']
    if variant == 'presence':
        # `credentials_60s` counts credential-bearing requests. Anchored here
        # the way a family score is anchored: a dozen a minute saturates, one is
        # not yet a claim. P15.3 gave this quantity weight 3.0.
        return ratio(values['credentials_60s'], 12, floor=1)
    principals = values['auth_principals_900s'] or 0
    parts = [ratio(failures, 12, floor=3)]
    if variant in ('failures_and_diversity', 'failures_diversity_span'):
        parts.append(ratio(principals, 8, floor=2))
    if variant in ('failures_and_span', 'failures_diversity_span'):
        parts.append(ratio(values['auth_failure_span_900s'], 300, floor=60)
                     if principals >= 2 else None)
    if variant == 'failures_and_span_ungated':
        parts.append(ratio(values['auth_failure_span_900s'], 300, floor=60))
    return families_module._strongest(parts)  # noqa: SLF001


def scored_with_auth(vector, variant, engine=None):
    """The shipped pipeline with only `AUTH_BEHAVIOR` swapped out."""
    engine = engine or composition_module.EvidenceCompositionEngine()
    values = dict(zip(NAMES, vector.values, strict=True))
    family_scores = families_module.scores(vector)
    family_scores[families_module.AUTH_BEHAVIOR] = auth_score(values, variant)
    score, _ = engine.evaluate(families_module.effective(family_scores))
    return score


def auth_ablation(samples=None):
    """§65. Five candidate meanings for authentication evidence, and the shipped one."""
    samples = samples if samples is not None else load()
    engine = composition_module.EvidenceCompositionEngine()
    results = {}
    for variant in AUTH_VARIANTS:
        scored = per_source(samples, lambda s, v=variant: scored_with_auth(s.features, v, engine))
        results[variant] = dict(separation(scored), description=AUTH_VARIANT_NOTES[variant])
    return {'ablation_schema_version': ABLATION_SCHEMA_VERSION,
            'question': 'what should authentication evidence mean',
            'corpus': DEVELOPMENT_CORPUS,
            'corpus_role': 'development, not a result',
            'unit': 'source; a source scores its worst window',
            'variants': results,
            'note': ('presence reconstructs the P15.3 quantity inside the P15.4 shape so the '
                     'two are comparable at the same layer. The two span rows differ only in '
                     'whether the span may speak from a single account, which is the whole of '
                     'what this ablation found')}


# --- §66: how evidence should be combined -----------------------------------

COMPOSITION_VARIANTS = (
    ('weighted_sum_v3', 'the P15.3 arithmetic, unchanged and still runnable'),
    ('bounded_additive', 'family scores summed and clipped; no interaction terms'),
    ('additive_with_interactions', 'the same sum, with the justified co-occurrences added'),
    ('noisy_or_without_interactions', 'the selected rule, with every interaction removed'),
    ('noisy_or', 'the shipped rule: noisy-OR over carrying families plus interactions'),
    ('monotone_logistic', 'a squashed sum, kept because §25 asks for the comparison'),
)


def composition_score(vector, variant, cache):
    if variant == 'weighted_sum_v3':
        return math_risk.MathRiskEngine().evaluate_v3(vector).score
    method = 'noisy_or' if variant == 'noisy_or_without_interactions' else variant
    engine = cache.get(variant)
    if engine is None:
        engine = composition_module.EvidenceCompositionEngine(
            method, interactions=variant != 'noisy_or_without_interactions')
        cache[variant] = engine
    score, _ = engine.evaluate(families_module.effective(families_module.scores(vector)))
    return score


def composition_ablation(samples=None):
    """§66. Four methods, the interaction terms on and off, and the old sum."""
    samples = samples if samples is not None else load()
    cache = {}
    results = {}
    for variant, description in COMPOSITION_VARIANTS:
        scored = per_source(samples, lambda s, v=variant: composition_score(s.features, v, cache))
        results[variant] = dict(separation(scored), description=description)
    return {'ablation_schema_version': ABLATION_SCHEMA_VERSION,
            'question': 'how should independent evidence families be combined',
            'corpus': DEVELOPMENT_CORPUS,
            'corpus_role': 'development, not a result',
            'unit': 'source; a source scores its worst window',
            'composition_version': composition_module.COMPOSITION_VERSION,
            'family_score_version': families_module.FAMILY_SCORE_VERSION,
            'interactions': [{'families': [first, second], 'strength': strength, 'why': why}
                             for first, second, strength, why in composition_module.INTERACTIONS],
            'variants': results}


# --- §67: when there is enough evidence to act ------------------------------


def maturity_of(sample, policy, *, standard_only=False):
    """Whether this window could be acted on, under one maturity policy."""
    vector = sample.features
    family_scores = families_module.scores(vector)
    observed = tuple(name for name, value in family_scores.items() if value is not None)
    quality = completeness(vector.values)
    if standard_only:
        return (vector.sample_count >= policy.minimum_observations
                and vector.observation_seconds >= policy.minimum_observation_seconds
                and quality >= policy.minimum_data_quality)
    return maturity_module.evaluate(
        observations=vector.sample_count, observation_seconds=vector.observation_seconds,
        data_quality=quality, families=observed, windows=vector.sample_count,
        policy=policy).mature


def maturity_ablation(samples=None):
    """§67. The single fixed floor against the three roads.

    Maturity decides *whether there is enough evidence to act*, never how
    malicious something is, so the figure that matters is how many sources of
    each class ever reach a state where action is possible at all — and, for the
    benign side, whether the new roads let any source through that the old floor
    kept out.
    """
    samples = samples if samples is not None else load()
    policy = maturity_module.MaturityPolicy()
    engine = composition_module.EvidenceCompositionEngine()

    scenario_of, actionable_under = {}, {}

    def measure(standard_only):
        reached, best = defaultdict(set), defaultdict(float)
        totals = defaultdict(set)
        for sample in samples:
            if sample.label not in (BENIGN, MALICIOUS):
                continue
            key = sample.source_group or sample.sample_id
            scenario_of[key] = sample.scenario_id
            totals[sample.label].add(key)
            if not maturity_of(sample, policy, standard_only=standard_only):
                continue
            reached[sample.label].add(key)
            score, _ = engine.evaluate(families_module.effective(
                families_module.scores(sample.features)))
            best[key] = max(best[key], score)
        out = {}
        for label in (BENIGN, MALICIOUS):
            sources = sorted(totals[label])
            actionable = reached[label]
            scores = sorted(best[key] for key in actionable) or [0.0]
            out[label] = {
                'sources': len(sources),
                'sources_ever_actionable': len(actionable),
                'fraction_ever_actionable': round(len(actionable) / max(1, len(sources)), 6),
                'worst_actionable_score': round(scores[-1], 6),
                'median_actionable_score': round(scores[len(scores) // 2], 6)}
            actionable_under[(label, standard_only)] = set(actionable)
        return out

    old = measure(standard_only=True)
    new = measure(standard_only=False)
    # Which behaviours the new roads actually admit. A count alone cannot say
    # whether the roads reached the low-and-slow families they were written for
    # or simply loosened everything a little, and those are different changes.
    gained = {}
    for label in (BENIGN, MALICIOUS):
        extra = actionable_under[(label, False)] - actionable_under[(label, True)]
        counts = defaultdict(int)
        for key in extra:
            counts[scenario_of.get(key, 'unknown')] += 1
        gained[label] = {'sources': len(extra), 'by_scenario': dict(sorted(counts.items()))}
    return {'ablation_schema_version': ABLATION_SCHEMA_VERSION,
            'admitted_by_the_new_roads': gained,
            'question': 'when is there enough evidence to act',
            'corpus': DEVELOPMENT_CORPUS,
            'corpus_role': 'development, not a result',
            'maturity_schema_version': maturity_module.MATURITY_SCHEMA_VERSION,
            'variants': {
                'fixed_floor': dict(old, description=(
                    'the P15.3 rule: 20 observations, 10 seconds, data quality 0.55, '
                    'and nothing else')),
                'three_roads': dict(new, description=(
                    'the standard floor unchanged, plus LONG_DURATION for quiet '
                    'behaviour watched a long time and STRONG_MULTI_SIGNAL for '
                    'evidence corroborated from several directions at once'))},
            'note': ('maturity never changes how malicious a source looks; it decides '
                     'whether the system may act. A road that admitted benign sources '
                     'the fixed floor excluded would be a cost, not a feature')}


# --- reports ----------------------------------------------------------------


def run(samples=None):
    samples = samples if samples is not None else load()
    return {'ablation_schema_version': ABLATION_SCHEMA_VERSION,
            'authentication': auth_ablation(samples),
            'composition': composition_ablation(samples),
            'maturity': maturity_ablation(samples)}


def write(document, path):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=1) + '\n', encoding='utf-8')
    return target
