"""Why each family failed in P15.2, split into the two kinds of failure.

§7 to §9. The P15.2 locked test is diagnostic evidence now — §2 says so
explicitly — and this module is the diagnosis. It answers one question per
family: *did the evidence fail, or did a gate refuse evidence that was already
sufficient?* Those have completely different repairs, and treating them as one
problem is how a project ends up lowering a gate to fix a feature.

**Type A — gate-limited.** The conservative bound cleared the cost cutoff and
something else refused. Nothing is wrong with the probability. The repair, if
there is one, is in the gate's definition — never in its threshold (§10, §15).

**Type B — evidence-limited.** The bound never approached the cutoff. The
repair is evidence: which features moved, which stayed at zero, and whether the
missing signal is extraction, aggregation, weighting or genuinely unavailable
(§9).

A third category falls out of the data and is named rather than folded into
Type B: **structurally unreachable evidence**. A feature can be extracted
correctly, aggregated correctly and mapped to an evidence family correctly, and
still contribute nothing, because `MathRisk` gives it a weight of zero. It then
produces no contribution, so no family, so no diversity — and the same omission
shows up as both a weak score and a failed diversity gate.
"""
from collections import defaultdict
import json
from pathlib import Path

from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.autonomy.evidence import BEHAVIOURAL_FAMILIES, FEATURE_FAMILIES
from eye_for_an_eye.decision.features import NAMES, FeatureTransformer, FeatureVector
from eye_for_an_eye.decision.math_risk import WEIGHTS

from . import candidates as C
from . import observability

FAILURE_MATRIX_VERSION = 1

TYPE_A = 'TYPE_A_GATE_LIMITED'
TYPE_B = 'TYPE_B_EVIDENCE_LIMITED'
DETECTED = 'DETECTED'

#: Restraint codes worth attributing a failure to. A code that only ever appears
#: alongside another is still listed: the point is to show every reason, not the
#: first one.
GATES = ('INSUFFICIENT_SIGNAL_DIVERSITY', 'MODEL_ONLY_EVIDENCE',
         'INSUFFICIENT_OBSERVATIONS', 'INSUFFICIENT_OBSERVATION_TIME',
         'INSUFFICIENT_DATA_QUALITY', 'ASSUMPTION_FAILED', 'UNCERTAINTY_HIGH',
         'HIGH_OOD', 'MODEL_UNHEALTHY', 'DRIFT_DEGRADED', 'MARGIN_NOT_MET',
         'COST_ALLOW_PREFERRED', 'CALIBRATION_UNAVAILABLE',
         'BLOCK_BUDGET_EXHAUSTED', 'POLICY_GUARD_REFUSED',
         'NETWORK_BLOCK_NOT_PERMITTED', 'IDENTITY_UNCERTAIN',
         'NOT_NETWORK_ENFORCEABLE', 'SHARED_PROXY_RISK')


def unreachable_families():
    """Evidence families no `MathRisk` term can ever put on the record.

    A family is reachable only if some feature mapped to it carries a non-zero
    weight. This is computed from the two committed tables rather than asserted,
    so it cannot drift out of date silently.
    """
    reachable = {FEATURE_FAMILIES[name] for name, weight in WEIGHTS.items()
                 if weight > 0 and name in FEATURE_FAMILIES}
    missing = [family for family in BEHAVIOURAL_FAMILIES if family not in reachable]
    detail = {}
    for family in missing:
        detail[family] = sorted(
            name for name, mapped in FEATURE_FAMILIES.items()
            if mapped == family and name in NAMES)
    return {'reachable': sorted(reachable), 'unreachable': missing,
            'features_that_would_reach_them': detail,
            'note': ('a feature with weight 0 produces no MathRisk contribution, so '
                     '`SignalFamilies.record_contributions` never sees it and the '
                     'family cannot be counted. The same omission appears as a weak '
                     'score and as a failed diversity gate')}


def normalised_profile(windows, quantile=0.9):
    """The transformed feature values at a quantile: what MathRisk actually sees."""
    columns = defaultdict(list)
    for window in windows:
        vector = FeatureVector(tuple(window['features']), window['feature_seconds'],
                               window['feature_samples'], False, 0.0)
        for name, value in zip(NAMES, FeatureTransformer.transform(vector), strict=False):
            columns[name].append(value)
    out = {}
    for name, values in columns.items():
        values.sort()
        out[name] = round(values[min(len(values) - 1, int(quantile * len(values)))], 6)
    return out


def classify_family(family, decisions, windows, *, cutoff):
    """One row of the matrix, from decisions and the raw feature profile."""
    blocked_sources = {d.source_group for d in decisions if d.blocked}
    sources = {d.source_group for d in decisions}
    cleared = [d for d in decisions if d.conservative_probability >= cutoff]
    max_probability = max((d.calibrated_probability or 0.0) for d in decisions)
    max_bound = max(d.conservative_probability for d in decisions)

    reasons = defaultdict(int)
    for decision in cleared:
        if decision.blocked:
            continue
        for code in decision.reason_codes:
            if code in GATES:
                reasons[code] += 1

    profile = normalised_profile(windows)
    terms = {name: round(weight * profile.get(name, 0.0), 6)
             for name, weight in WEIGHTS.items()}
    silent = sorted(name for name, value in terms.items() if value < 0.01)
    moved = sorted((name for name, value in terms.items() if value >= 0.01),
                   key=lambda name: -terms[name])

    if blocked_sources:
        kind = DETECTED
    elif cleared:
        kind = TYPE_A
    else:
        kind = TYPE_B

    return {
        'family': family,
        'failure_type': kind,
        'observability': observability.classify(family),
        'enforcement_eligibility': observability.eligibility(family),
        'sources': len(sources), 'blocked_sources': len(blocked_sources),
        'windows': len(decisions),
        'windows_clearing_the_cutoff': len(cleared),
        'max_calibrated_probability': round(max_probability, 6),
        'max_conservative_bound': round(max_bound, 6),
        'gate_refusals_above_the_cutoff': dict(sorted(reasons.items(),
                                                      key=lambda kv: -kv[1])),
        'mathrisk_terms_that_moved': moved,
        'mathrisk_terms_at_zero': silent,
        'mathrisk_term_sum_at_p90': round(sum(terms.values()), 6),
        'mathrisk_bias': -4.0,
        'unweighted_features_at_p90': {
            name: profile.get(name, 0.0) for name in NAMES if name not in WEIGHTS},
    }


def build(*, role='locked_test', calibrator_path='models/mathrisk-cal-v1-isotonic.json',
          root='datasets', profile='public_website'):
    """Replay the diagnostic corpus and classify every family."""
    from eye_for_an_eye.decision import calibration as cal
    from . import p15_2_evaluation as P

    cutoff = PROFILES[profile].threshold
    artifact = cal.load(calibrator_path)
    decisions, dropped, _ = P.replay_role(role, calibrator=artifact, root=root)
    windows = {w['sample_id']: w for w in C.cached_scores(role, root=root)['windows']}

    grouped = defaultdict(list)
    for decision in decisions:
        grouped[decision.scenario_group or 'none'].append(decision)

    rows = {}
    for family, family_decisions in sorted(grouped.items()):
        family_windows = [windows[d.sample_id] for d in family_decisions
                          if d.sample_id in windows]
        rows[family] = classify_family(family, family_decisions, family_windows,
                                       cutoff=cutoff)
    body = {
        'failure_matrix_version': FAILURE_MATRIX_VERSION,
        'diagnostic_corpus': role,
        'cost_profile': profile, 'cutoff': round(cutoff, 6),
        'rows_dropped': dropped,
        'unreachable_evidence': unreachable_families(),
        'families': rows,
        'summary': {
            kind: sorted(name for name, row in rows.items() if row['failure_type'] == kind)
            for kind in (DETECTED, TYPE_A, TYPE_B)},
        'note': ('the P15.2 locked test is diagnostic evidence only. §2: it may be '
                 'used for root-cause analysis and regression checks, and it is not '
                 'valid final evidence for Gate C after P15.3 changes'),
    }
    return body


def write(body, path):
    Path(path).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return path


def render(body):
    lines = [f'FAILURE MATRIX - {body["diagnostic_corpus"]} at cutoff {body["cutoff"]}', '']
    unreachable = body['unreachable_evidence']
    lines.append('Evidence families no MathRisk term can reach: '
                 + (', '.join(unreachable['unreachable']) or 'none'))
    for family, features in unreachable['features_that_would_reach_them'].items():
        lines.append(f'  {family:<24} would be reached by: {", ".join(features)}')
    lines.append('')
    lines.append(f'{"family":<28}{"type":<24}{"src":>4}{"blk":>4}{"maxP":>8}'
                 f'{"bound":>8}{"terms":>8}  top refusal')
    order = {DETECTED: 0, TYPE_A: 1, TYPE_B: 2}
    for family, row in sorted(body['families'].items(),
                              key=lambda kv: (order[kv[1]['failure_type']], kv[0])):
        refusals = row['gate_refusals_above_the_cutoff']
        top = next(iter(refusals), '') if refusals else ''
        lines.append(
            f'{family:<28}{row["failure_type"]:<24}{row["sources"]:>4}'
            f'{row["blocked_sources"]:>4}{row["max_calibrated_probability"]:>8.3f}'
            f'{row["max_conservative_bound"]:>8.3f}'
            f'{row["mathrisk_term_sum_at_p90"]:>8.2f}  {top[:34]}')
    return '\n'.join(lines)
