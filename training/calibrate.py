"""Fit, compare and write the calibrator artifacts. §35 to §37.

Calibration happens on the **calibration corpus** and nowhere else. Not on the
rows any candidate was fitted on, and never on the locked test — a calibrator
fitted on the set it is then evaluated against reports the calibration error of
a curve drawn through its own points, which is zero by construction and means
nothing.

Two methods are fitted for every candidate and compared on data neither of them
saw. §36 is explicit about how to choose between them: with limited calibration
data, prefer the method that generalises, not the one with the lowest error on
the fold it was fitted on. Isotonic will always win the second contest and
frequently lose the first.

Every artifact carries a Wilson lower bound built from its own fitting data —
`calibration.conservative_knots` — because a point estimate is not something to
deny a stranger a service over, and because that bound is the quantity P15's
uncertainty module was reaching for when it applied a Wilson correction to the
number of packets in an observation window.
"""
from dataclasses import dataclass
from pathlib import Path

from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision import math_risk

from . import candidates as C
from . import evaluation_design as design

CALIBRATION_SCHEMA_VERSION = 1

#: Where fitted artifacts land. Committed: they are small, they are text, and a
#: calibrator nobody can read is a calibrator nobody can check.
ARTIFACTS = Path('models')


@dataclass(frozen=True, slots=True)
class Fitted:
    """One calibrator plus how it behaved on data it was not fitted on."""

    calibrator: object
    quality: dict

    @property
    def method(self):
        return self.calibrator.method


def score_of(windows, source):
    """The quantity a calibrator maps, pulled from cached window scores."""
    return [window.get(source) for window in windows]


def usable(windows, source):
    pairs = [(window, window.get(source)) for window in windows]
    return [(w, s) for w, s in pairs if s is not None]


def by_source(pairs):
    """Reduce windows to one example per source: its worst window. §48.

    The unit a calibrated probability is a probability *of*. The cost model
    prices a wrongly blocked **source**, and a block is taken the first time any
    of that source's windows crosses — so the example that decides a source's
    fate is its highest-scoring window, and every other window of the same
    source is a near-copy that inflates the fitting set without adding an
    independent observation.

    Measured, not assumed: on the P15.4 development corpus the fraction of
    benign *sources* crossing a cutoff is 8.5 to 12.1 times the fraction of
    benign *windows* crossing it, across the whole range where benign traffic
    appears at all. `reports/P15_4_CALIBRATION_UNIT.json` has the sweep.

    This makes the artifact **stricter**, which is worth stating plainly so it
    cannot be mistaken for the thing §61 and §62 forbid. A source's worst window
    is drawn from the right tail of its own distribution, so at any given score
    the fraction of *sources* that are malicious is lower than the fraction of
    *windows* that are — the curve sits below the window-fitted one and the
    unchanged cost cutoff becomes harder to reach, not easier. No cost and no
    threshold moves.
    """
    worst = {}
    for window, score in pairs:
        # The corpus is part of the key. Two corpora built from the same matrix
        # produce the same `source_group` strings -- `benign/web/browse#06` in
        # both -- so keying on the group alone silently merged every calibration
        # corpus into one and halved the fitting set while appearing to work.
        # Found because the merged count came out as exactly 756 for two corpora
        # of 756 sources each.
        key = (window.get('corpus') or '', window.get('source_group') or window.get('sample_id'))
        current = worst.get(key)
        if current is None or score > current[1]:
            worst[key] = (window, score)
    return [worst[key] for key in sorted(worst)]


def fit(source, *, version, model_version='', calibration_windows, holdout_windows,
        bins=cal.CONSERVATIVE_BINS, unit=cal.WINDOW):
    """Fit sigmoid and isotonic, and measure both on the holdout. Returns both."""
    reduce = by_source if unit == cal.SOURCE else (lambda pairs: pairs)
    fitting = reduce(usable(calibration_windows, source))
    scores = [s for _, s in fitting]
    labels = [w['y'] for w, _ in fitting]
    holdout = reduce(usable(holdout_windows, source))
    held_scores = [s for _, s in holdout]
    held_labels = [w['y'] for w, _ in holdout]

    results = {}
    for method, fitter in ((cal.SIGMOID, cal.fit_sigmoid), (cal.ISOTONIC, cal.fit_isotonic)):
        artifact = fitter(scores, labels, version=f'{version}-{method}',
                          source=source, model_version=model_version, bins=bins, unit=unit)
        mapped = [artifact.probability(s) for s in held_scores]
        bounded = [artifact.lower(s) for s in held_scores]
        results[method] = Fitted(artifact, {
            'method': method,
            'unit': unit,
            'fitted_on': len(scores), 'fitted_positives': sum(labels),
            'holdout_rows': len(held_scores), 'holdout_positives': sum(held_labels),
            'brier': _round(cal.brier(mapped, held_labels), 6),
            'ece': _round(cal.expected_calibration_error(mapped, held_labels), 6),
            'brier_in_fold': _round(
                cal.brier([artifact.probability(s) for s in scores], labels), 6),
            'ece_in_fold': _round(cal.expected_calibration_error(
                [artifact.probability(s) for s in scores], labels), 6),
            # §37: calibration must not materially destroy ranking. A monotone
            # map cannot reorder anything, so any change here would be a bug in
            # the artifact rather than a property of calibration — which is
            # exactly why it is worth asserting rather than assuming.
            'window_roc_auc_before': _round(C._roc_auc(held_scores, held_labels)),
            'window_roc_auc_after': _round(C._roc_auc(mapped, held_labels)),
            'conservative_roc_auc': _round(C._roc_auc(bounded, held_labels)),
            'reliability': cal.reliability(mapped, held_labels),
            'knots': len(artifact.knots),
            'lower_knots': len(artifact.lower_knots),
            'probability_range': [_round(min(mapped), 6), _round(max(mapped), 6)],
            'bound_range': [_round(min(bounded), 6), _round(max(bounded), 6)],
            'digest': artifact.digest,
        })
    return results


def _round(value, places=4):
    return None if value is None else round(float(value), places)


def prevalence_sensitivity(artifact, holdout_windows, source, *, prevalences=(0.20, 0.05, 0.01, 0.002)):
    """§38, §39. What the same calibrator would say at a different base rate.

    A calibrated probability is calibrated *for the prevalence it was fitted at*.
    This corpus is 20% malicious by source; a public website is not. Re-weighting
    by the prior ratio shows how far the estimate would move, which is the honest
    way to say "these numbers do not transfer to every deployment" with a figure
    attached rather than a disclaimer.

    Labels are not altered anywhere: this is analysis, not relabelling (§39).
    """
    rows = usable(holdout_windows, source)
    base = sum(w['y'] for w, _ in rows) / max(1, len(rows))
    out = []
    for target in prevalences:
        # Standard prior correction on the odds scale.
        ratio = (target / (1 - target)) / max(1e-12, base / (1 - base))
        adjusted = []
        for _, score in rows:
            p = artifact.probability(score)
            odds = (p / max(1e-12, 1 - p)) * ratio
            adjusted.append(odds / (1 + odds))
        out.append({'prevalence': target,
                    'median_probability': _round(sorted(adjusted)[len(adjusted) // 2], 6),
                    'max_probability': _round(max(adjusted), 6),
                    'rows_above_0.9756': sum(1 for p in adjusted if p >= 0.9756),
                    'rows_above_0.8889': sum(1 for p in adjusted if p >= 0.8889)})
    return {'corpus_prevalence_windows': _round(base, 6), 'by_prevalence': out,
            'note': 'analysis only; no label was altered and no artifact was refitted'}


#: The P15.4 refit. §29, §30, §48, §59.
#:
#: Three things change together and all three are forced. The **formula** is
#: `math-risk-v4`, so a v3 calibrator may not answer for it. The **corpora** are
#: the P15.4 ones, because `cal-v1`/`cal2-v1` come from a matrix with no
#: authentication outcome in it at all — a calibrator fitted there would map the
#: new formula's scores having never seen the evidence the new formula reads.
#: And the **unit** is the source, for the reason `by_source` states.
P15_4_PLAN = {
    'roles': (design.P15_4_CALIBRATION, design.P15_4_CALIBRATION_2,
              design.P15_4_CALIBRATION_3, design.P15_4_CALIBRATION_4),
    'holdout_role': design.P15_4_DEVELOPMENT,
    'unit': cal.SOURCE,
    'math_risk_version': 'mathrisk-cal-v4',
}

#: P15.5: the same formula, the same unit, twelve corpora instead of four.
#:
#: The four P15.4 corpora stay in. They are independent sources fitted on the
#: formula in force, and dropping them to make the refit "cleaner" would throw
#: away evidence for no reason — the question is how many examples land in each
#: score band, and these ones already do.
#:
#: The eight new ones come from an API-enriched matrix, because the cutoff that
#: cannot be reached is the API one and calibrating it on a corpus of mostly web
#: browsing is calibrating for the wrong traffic. How many, and why eight, is in
#: `reports/P15_5_CALIBRATION_PLAN.json`, committed before the first of them was
#: generated. **Fitted once.** If the bound falls short the answer is
#: API_AUTONOMOUS_TEMP_BLOCK = NOT_SUPPORTED, not a ninth corpus.
P15_5_PLAN = {
    'roles': (design.P15_4_CALIBRATION, design.P15_4_CALIBRATION_2,
              design.P15_4_CALIBRATION_3, design.P15_4_CALIBRATION_4,
              *design.P15_5_CALIBRATION_ROLE_NAMES),
    'holdout_role': design.P15_4_DEVELOPMENT,
    'unit': cal.SOURCE,
    'math_risk_version': 'mathrisk-cal-v4',
}


def build(*, root='datasets', out=ARTIFACTS, refresh=False, roles=None,
          holdout_role=None, unit=cal.WINDOW, math_risk_version='mathrisk-cal-v3'):
    """Fit every candidate's calibrators. Returns the comparison, writes nothing."""
    roles = tuple(roles or design.CALIBRATION_ROLES)
    holdout_role = holdout_role or design.DEVELOPMENT
    calibration = []
    for role in roles:
        # Stamped here rather than in `score_windows`, so the cached score files
        # written by every earlier cycle stay readable exactly as they are.
        for window in C.cached_scores(role, root=root, refresh=refresh)['windows']:
            calibration.append(dict(window, corpus=design.CORPORA[role][1]))
    development = [dict(window, corpus=design.CORPORA[holdout_role][1])
                   for window in C.cached_scores(holdout_role, root=root,
                                                 refresh=refresh)['windows']]
    # The holdout for calibration quality is the development corpus's own
    # non-training rows: no candidate was fitted on them and no calibrator was
    # fitted on them, and the locked test stays locked.
    holdout = [w for w in development if w['split'] in ('validation', 'test')]
    body = {'calibration_schema_version': CALIBRATION_SCHEMA_VERSION,
            'calibration_corpora': [design.CORPORA[role][1] for role in roles],
            'calibration_rows': len(calibration),
            'calibration_unit': unit,
            'quality_holdout': f'{design.CORPORA[holdout_role][1]}, validation and test buckets',
            'quality_holdout_rows': len(holdout),
            'candidates': {}}
    # §84 revisited. `MathRisk` was bound to nothing, on the reasoning that a
    # formula with no learned weights cannot drift underneath its calibrator.
    # P15.3 changed the formula, which makes that reasoning false: a mapping
    # fitted on `math-risk-v1` scores says nothing about a `math-risk-v2` score,
    # and nothing in the artifact would have refused it. Binding it to the
    # formula version makes the refusal automatic rather than remembered.
    plan = [('math_risk', math_risk_version, math_risk.VERSION),
            ('model_score', 'classifier-cal-v1', 'risk-logreg-v1')]
    fitted = {}
    for source, version, model_version in plan:
        results = fit(source, version=version, model_version=model_version,
                      calibration_windows=calibration, holdout_windows=holdout,
                      unit=unit)
        fitted[source] = results
        body['candidates'][source] = {
            method: result.quality for method, result in results.items()}
        body['candidates'][source]['prevalence_sensitivity'] = prevalence_sensitivity(
            results[cal.SIGMOID].calibrator, holdout, source)
    return body, fitted


def write(fitted, source, method, *, out=ARTIFACTS):
    artifact = fitted[source][method].calibrator
    path = Path(out) / f'{artifact.version}.json'
    artifact.save(path)
    return path
