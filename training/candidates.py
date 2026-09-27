"""Candidate probability architectures, measured against each other honestly.

§1's order, and the reason for it: **discrimination before calibration**. A
calibrator is a monotone map. It can make a score mean what it says; it cannot
make a score know anything it did not already know. Calibrating a detector that
ranks at chance produces a well-calibrated detector that ranks at chance, and the
reliability diagram will look excellent while the system decides nothing useful.

So every candidate is ranked first, on data no fitted component has seen, and
only the winner is calibrated.

### The candidates

**A — supervised classifier.** The shipped family, refitted on the development
corpus alone. Its own evaluation already reports the problem P15.2 exists to
face: ROC-AUC 0.994 on scenario families it trained on and 0.517 on four it did
not. Candidate A is the question "was that the model family, or the split?"

**B — calibrated `MathRisk`.** The deterministic engine has no learned weights,
so it cannot memorise a generator, and P15.1 measured it ranking *above* the
fused decision variable. `MathRisk` itself is untouched — §17: the calibrator is
a separate versioned artifact and `P(malicious | MathRisk)` is a different value
with a different name.

**C — simple fusion.** `MathRisk` and the classifier score, combined by a
two-feature logistic regression fitted out-of-fold. Two inputs, not seven:
anomaly, OOD and data quality measure different quantities (§18, §21, §22, §23),
and adding them to a malicious-probability estimate is how "unusual" quietly
becomes "guilty".

**Reference — the P15.1 decision variable**, the conservative probability the
system currently decides on. Not a candidate. It is in every table so the
comparison is against what exists rather than against nothing.

### What is deliberately not here

No neural network (§30). No AutoML (§28). No stacking on in-fold predictions
(§19). No feature that names a scenario, a capture, a site or a source (§32) —
the model feature list is the production one, which excludes all of them, and a
test asserts it.
"""
from collections import defaultdict
from dataclasses import dataclass
import json
import math
from pathlib import Path

from dataset import split as split_module
from eye_for_an_eye.autonomy import evaluation as ev
from eye_for_an_eye.decision.features import NAMES, FeatureTransformer

from . import evaluation_design as design

CANDIDATE_SCHEMA_VERSION = 1

BENIGN = design.BENIGN
MALICIOUS = design.MALICIOUS

#: Where the cached base scores live. Scoring a corpus means running the ONNX
#: classifier in its isolated subprocess over every row, which is the slow part;
#: caching means every candidate and every ablation reads the same numbers
#: rather than each one re-deriving them slightly differently.
CACHE = Path('reports/p15_2')


def label_code(row):
    return 1 if row.label == MALICIOUS else 0


# --- base scores ------------------------------------------------------------


def score_windows(role, *, root='datasets', models=Path('models'), classifier=True):
    """Every window of one corpus, through the real engines, as plain records.

    Runs the production components — `MathRiskEngine`, the ONNX classifier in its
    isolated subprocess, the anomaly model, `OODEngine`, `DataQualityResult` —
    and records what each said. No decision is taken here: this is the evidence
    every candidate is built from, and building it once means two candidates
    cannot disagree about what the classifier returned.
    """
    from eye_for_an_eye.config import Config
    from .decision_replay import ReplayComponents, replay, trusted

    rows = design.load_role(role, root)
    config = Config()
    config.decision.enabled = True
    components = ReplayComponents(config).open(
        classifier_path=models / 'risk-logreg-v1.onnx' if classifier else '',
        classifier_manifest=models / 'risk-logreg-v1.json' if classifier else '',
        anomaly_path=models / 'isolation-v1.onnx',
        anomaly_manifest=models / 'isolation-v1.json',
        distribution_path=models / 'risk-logreg-v1-distribution.json')
    try:
        decisions, dropped = replay(rows, components)
    finally:
        components.close()
    kept, _ = trusted(rows)
    by_id = {row.sample_id: row for row in kept}
    records = []
    for decision in decisions:
        row = by_id[decision.sample_id]
        records.append({
            'sample_id': decision.sample_id,
            'source_group': decision.source_group,
            'scenario_group': decision.scenario_group,
            'split': row.split,
            'label': decision.label,
            'y': label_code(row),
            'familiarity': design.familiarity(row),
            'math_risk': decision.math_risk,
            'model_score': decision.model_score,
            'anomaly_score': decision.anomaly_score,
            'ood_status': decision.ood_status,
            'data_quality': decision.data_quality,
            'signal_diversity': decision.signal_diversity,
            'behavioural_diversity': decision.behavioural_diversity,
            'observations': decision.observations,
            'observation_seconds': decision.observation_seconds,
            'conservative_probability': decision.conservative_probability,
            'blocked': decision.blocked,
            'features': list(row.features.values),
            'feature_seconds': row.features.observation_seconds,
            'feature_samples': row.features.sample_count,
        })
    return {'candidate_schema_version': CANDIDATE_SCHEMA_VERSION, 'role': role,
            'rows': len(records), 'dropped': dropped, 'windows': records}


def cached_scores(role, *, root='datasets', models=Path('models'), refresh=False):
    """Score a corpus, or read the cache. The cache is an optimisation, not evidence."""
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f'scores-{role}.json'
    if path.is_file() and not refresh:
        return json.loads(path.read_text(encoding='utf-8'))
    body = score_windows(role, root=root, models=models)
    path.write_text(json.dumps(body), encoding='utf-8')
    return body


# --- feature matrix ---------------------------------------------------------


def matrix(windows):
    """The production feature transform, not a re-implementation of it.

    §32: the transformer is the same object the runtime uses, so a column that
    is excluded from the model in production is excluded here by construction
    rather than by a list somebody has to keep in step.
    """
    from eye_for_an_eye.decision.features import FeatureVector
    rows = []
    for window in windows:
        vector = FeatureVector(tuple(window['features']), window['feature_seconds'],
                               window['feature_samples'], False, 0.0)
        rows.append(list(FeatureTransformer.transform(vector)))
    return rows


def labels(windows):
    return [int(window['y']) for window in windows]


# --- candidates -------------------------------------------------------------


@dataclass
class Candidate:
    """A named way of turning a window into a score. Not yet a probability."""

    name: str
    description: str
    #: window dict -> score in [0, 1], or None when this candidate has no opinion
    score: object
    #: What the calibrator would be fitted on, if this candidate were chosen.
    calibration_source: str = ''
    #: Which model version the calibrator would be bound to. Empty means the
    #: quantity has no learned weights and the artifact is model-independent.
    model_version: str = ''
    detail: dict = None


def math_risk_candidate():
    return Candidate(
        name='B: MathRisk',
        description='the deterministic engine, unchanged; only the calibrator is new',
        score=lambda window: window['math_risk'],
        calibration_source='math_risk', model_version='')


def shipped_classifier_candidate():
    return Candidate(
        name='shipped classifier',
        description='risk-logreg-v1 as it ships, score only',
        score=lambda window: window['model_score'],
        calibration_source='model_score', model_version='risk-logreg-v1')


def current_decision_reference():
    return Candidate(
        name='reference: P15.1 decision variable',
        description='the conservative probability the system decides on today',
        score=lambda window: window['conservative_probability'])


def fit_logistic(train_windows, *, seed=20260912, grid=(0.01, 0.1, 1.0, 10.0),
                 class_weight='balanced', columns=None):
    """Candidate A: bounded logistic regression on the production features.

    A small log-scale grid over `C`, selected by group-aware cross-validation on
    the *training* corpus only — §28's bounded search, not a hyperparameter hunt.
    Groups are scenario families, so a fold never scores a family it fitted on
    and the selected `C` is the one that generalises rather than the one that
    memorises best.
    """
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold
    from sklearn.preprocessing import StandardScaler

    rows = np.array(matrix(train_windows), dtype=np.float64)
    if columns is not None:
        rows = rows[:, list(columns)]
    y = np.array(labels(train_windows))
    groups = np.array([w['scenario_group'] for w in train_windows])
    folds = min(4, len(set(groups.tolist())))
    scaler = StandardScaler().fit(rows)
    scaled = scaler.transform(rows)

    best, best_score = None, -1.0
    for C in grid:
        scores = []
        for train_index, test_index in GroupKFold(n_splits=folds).split(scaled, y, groups):
            if len(set(y[train_index].tolist())) < 2 or len(set(y[test_index].tolist())) < 2:
                continue
            model = LogisticRegression(C=C, max_iter=2000, class_weight=
                                       None if class_weight == 'none' else class_weight,
                                       random_state=seed)
            model.fit(scaled[train_index], y[train_index])
            probabilities = model.predict_proba(scaled[test_index])[:, 1]
            scores.append(_roc_auc(probabilities.tolist(), y[test_index].tolist()))
        mean = sum(scores) / len(scores) if scores else 0.0
        if mean > best_score:
            best, best_score = C, mean
    model = LogisticRegression(C=best, max_iter=2000,
                               class_weight=None if class_weight == 'none' else class_weight,
                               random_state=seed)
    model.fit(scaled, y)
    return model, scaler, {'C': best, 'grouped_cv_roc_auc': round(best_score, 6),
                           'folds': folds, 'class_weight': class_weight,
                           'rows': len(train_windows), 'positives': int(y.sum()),
                           'columns': list(columns) if columns is not None else 'all'}


def fit_gradient_boosting(train_windows, *, seed=20260912):
    """§29's bounded challenger. Same features, same groups, same protocol.

    Depth and estimator count are fixed rather than searched: a boosted model
    with enough capacity will fit the generator, and the question here is whether
    a *different model family* generalises better, not how much capacity it takes
    to memorise this corpus.
    """
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier

    rows = np.array(matrix(train_windows), dtype=np.float64)
    y = np.array(labels(train_windows))
    model = HistGradientBoostingClassifier(
        max_depth=3, max_iter=150, learning_rate=0.06, l2_regularization=1.0,
        early_stopping=False, random_state=seed)
    model.fit(rows, y)
    return model, {'max_depth': 3, 'max_iter': 150, 'learning_rate': 0.06,
                   'rows': len(train_windows), 'positives': int(y.sum())}


def sklearn_candidate(name, description, model, scaler=None, *, version,
                      columns=None, detail=None):
    import numpy as np

    def score(window):
        row = np.array(matrix([window]), dtype=np.float64)
        if columns is not None:
            row = row[:, list(columns)]
        if scaler is not None:
            row = scaler.transform(row)
        return float(model.predict_proba(row)[0, 1])

    def batch(windows):
        rows = np.array(matrix(windows), dtype=np.float64)
        if columns is not None:
            rows = rows[:, list(columns)]
        if scaler is not None:
            rows = scaler.transform(rows)
        return [float(value) for value in model.predict_proba(rows)[:, 1]]

    candidate = Candidate(name=name, description=description, score=score,
                          calibration_source=version, model_version=version,
                          detail=detail or {})
    candidate.batch = batch
    return candidate


def fit_fusion(train_windows, *, seed=20260912):
    """Candidate C: two inputs, fitted out-of-fold. §18, §19.

    The inputs are `MathRisk` and the classifier score, and the classifier score
    used for fitting is the *shipped* model's — which was fitted on a different
    corpus entirely, so there is no in-fold prediction anywhere in this. A fusion
    over a model refitted on these same rows would need out-of-fold predictions
    to mean anything, and §19 is explicit about why.
    """
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    usable = [w for w in train_windows if w['model_score'] is not None]
    if len(usable) < 50:
        return None, {'skipped': 'too few rows carry a classifier score'}
    X = np.array([[w['math_risk'], w['model_score']] for w in usable], dtype=np.float64)
    y = np.array(labels(usable))
    model = LogisticRegression(C=1.0, max_iter=2000, class_weight='balanced',
                               random_state=seed)
    model.fit(X, y)

    def score(window):
        if window['model_score'] is None:
            return None
        row = np.array([[window['math_risk'], window['model_score']]], dtype=np.float64)
        return float(model.predict_proba(row)[0, 1])

    detail = {'rows': len(usable), 'positives': int(y.sum()),
              'coefficients': {'math_risk': float(model.coef_[0][0]),
                               'model_score': float(model.coef_[0][1])},
              'intercept': float(model.intercept_[0])}
    candidate = Candidate(name='C: MathRisk + classifier',
                          description='two-input logistic fusion, nothing else',
                          score=score, calibration_source='fusion-v1',
                          model_version='risk-logreg-v1', detail=detail)
    return candidate, detail


# --- measurement ------------------------------------------------------------


def _roc_auc(scores, ys):
    outcomes = [ev.Outcome(blocked=False, label=ev.MALICIOUS_AUTOMATION if y else ev.BENIGN,
                           score=float(s)) for s, y in zip(scores, ys, strict=True)]
    return ev.roc_auc(outcomes)


def _pr_auc(scores, ys):
    outcomes = [ev.Outcome(blocked=False, label=ev.MALICIOUS_AUTOMATION if y else ev.BENIGN,
                           score=float(s)) for s, y in zip(scores, ys, strict=True)]
    return ev.pr_auc(outcomes)


def source_scores(windows, scored):
    """Max over a source's windows — the aggregation the runtime uses (§6).

    Returns (scores, labels, groups) aligned by source.
    """
    grouped = defaultdict(list)
    for window, score in zip(windows, scored, strict=True):
        if score is None:
            continue
        grouped[window['source_group'] or window['sample_id']].append((window, float(score)))
    scores, ys, families = [], [], []
    for group, rows in sorted(grouped.items()):
        if len({w['y'] for w, _ in rows}) != 1:
            continue
        scores.append(max(score for _, score in rows))
        ys.append(rows[0][0]['y'])
        families.append(rows[0][0]['scenario_group'])
    return scores, ys, families


def discrimination(candidate, windows, *, name=None):
    """ROC-AUC and PR-AUC per window and per source, split seen / unseen."""
    batch = getattr(candidate, 'batch', None)
    scored = batch(windows) if batch else [candidate.score(w) for w in windows]
    body = {'name': name or candidate.name, 'description': candidate.description}
    for view, subset in (('all', windows), ('seen', None), ('unseen', None)):
        if view == 'all':
            pairs = [(w, s) for w, s in zip(windows, scored, strict=True) if s is not None]
        else:
            pairs = [(w, s) for w, s in zip(windows, scored, strict=True)
                     if s is not None and w['familiarity'] == view]
        if not pairs:
            body[view] = {'windows': 0}
            continue
        w_scores = [s for _, s in pairs]
        w_y = [w['y'] for w, _ in pairs]
        s_scores, s_y, _ = source_scores([w for w, _ in pairs], w_scores)
        body[view] = {
            'windows': len(pairs), 'window_positives': sum(w_y),
            'sources': len(s_y), 'source_positives': sum(s_y),
            'window_roc_auc': _round(_roc_auc(w_scores, w_y)),
            'window_pr_auc': _round(_pr_auc(w_scores, w_y)),
            'source_roc_auc': _round(_roc_auc(s_scores, s_y)),
            'source_pr_auc': _round(_pr_auc(s_scores, s_y)),
        }
    if candidate.detail:
        body['fit'] = candidate.detail
    return body


def _round(value, places=4):
    return None if value is None else round(float(value), places)


def per_family(candidate, windows):
    """Source-level score distribution per scenario family. §59, §60.

    An aggregate hides the family that fails, and the family that fails is the
    one an operator meets first.
    """
    batch = getattr(candidate, 'batch', None)
    scored = batch(windows) if batch else [candidate.score(w) for w in windows]
    scores, ys, families = source_scores(windows, scored)
    grouped = defaultdict(list)
    for score, y, family in zip(scores, ys, families, strict=True):
        grouped[family].append((score, y))
    body = {}
    for family, rows in sorted(grouped.items()):
        values = sorted(score for score, _ in rows)
        body[family] = {
            'sources': len(rows),
            'label': MALICIOUS if rows[0][1] else BENIGN,
            'familiarity': 'unseen' if family in split_module.HOLDOUT else 'seen',
            'min': _round(values[0], 6), 'median': _round(values[len(values) // 2], 6),
            'max': _round(values[-1], 6)}
    return body


def ablation(windows, *, uncertainty_components=True):
    """§25. Where the ordering information goes, one transformation at a time.

    Each row is the same evidence with one more step applied, so the table reads
    as a chain rather than as a set of unrelated models. The step where the
    number falls is the step that costs information.
    """
    from eye_for_an_eye.autonomy.uncertainty import assess

    def conservative(window, **overrides):
        settings = {'calibrated': False, 'ood_score': None,
                    'data_quality_score': window['data_quality'],
                    'model_health': 'HEALTHY',
                    'observations': window['observations'],
                    'model_disagreement': None, 'drift_status': 'STABLE'}
        settings.update(overrides)
        doubt = assess(**settings)
        return doubt.conservative_probability(window['math_risk'])

    stages = [
        ('math_risk (raw)', lambda w: w['math_risk']),
        ('model_score (raw)', lambda w: w['model_score']),
        ('anomaly_score (raw)', lambda w: w['anomaly_score']),
        ('math_risk after shrinkage only',
         lambda w: _shrink_only(w)),
        ('math_risk after the sampling-width term only',
         lambda w: _width_only(w)),
        ('math_risk, full conservative estimate', lambda w: conservative(w)),
        ('the decision variable as shipped', lambda w: w['conservative_probability']),
    ]
    if uncertainty_components:
        stages.insert(5, ('math_risk, conservative with calibration assumed',
                          lambda w: conservative(w, calibrated=True)))
        stages.insert(6, ('math_risk, conservative with 500+ observations assumed',
                          lambda w: conservative(w, observations=500)))
    rows = []
    for name, fn in stages:
        scored = [fn(w) for w in windows]
        pairs = [(w, s) for w, s in zip(windows, scored, strict=True) if s is not None]
        if not pairs:
            rows.append({'stage': name, 'windows': 0})
            continue
        w_scores = [s for _, s in pairs]
        w_y = [w['y'] for w, _ in pairs]
        s_scores, s_y, _ = source_scores([w for w, _ in pairs], w_scores)
        rows.append({'stage': name, 'windows': len(pairs),
                     'window_roc_auc': _round(_roc_auc(w_scores, w_y)),
                     'source_roc_auc': _round(_roc_auc(s_scores, s_y)),
                     'median': _round(sorted(w_scores)[len(w_scores) // 2], 6),
                     'fraction_exactly_zero': _round(
                         sum(1 for s in w_scores if s <= 0.0) / len(w_scores))})
    return rows


def _shrink_only(window):
    """Shrinkage towards the prior, without the sampling-width subtraction."""
    from eye_for_an_eye.autonomy.uncertainty import DEFAULT_PRIOR, assess
    doubt = assess(calibrated=False, ood_score=None,
                   data_quality_score=window['data_quality'], model_health='HEALTHY',
                   observations=window['observations'], model_disagreement=None,
                   drift_status='STABLE')
    weight = doubt.total
    return (1.0 - weight) * window['math_risk'] + weight * DEFAULT_PRIOR


def _width_only(window):
    """The sampling-width subtraction, without shrinkage."""
    from eye_for_an_eye.autonomy.uncertainty import DecisionUncertainty
    point = window['math_risk']
    doubt = DecisionUncertainty(observations=window['observations'])
    return max(0.0, point - doubt._width(point))


def rank_correlation(first, second):
    """Spearman between two score vectors, for "did this step reorder anything?"."""
    pairs = [(a, b) for a, b in zip(first, second, strict=True)
             if a is not None and b is not None]
    if len(pairs) < 3:
        return None
    def ranks(values):
        order = sorted(range(len(values)), key=lambda i: values[i])
        out = [0.0] * len(values)
        index = 0
        while index < len(order):
            stop = index
            while stop + 1 < len(order) and values[order[stop + 1]] == values[order[index]]:
                stop += 1
            average = (index + stop) / 2.0 + 1.0
            for position in range(index, stop + 1):
                out[order[position]] = average
            index = stop + 1
        return out
    a_ranks = ranks([a for a, _ in pairs])
    b_ranks = ranks([b for _, b in pairs])
    n = len(pairs)
    mean_a = sum(a_ranks) / n
    mean_b = sum(b_ranks) / n
    num = sum((a - mean_a) * (b - mean_b) for a, b in zip(a_ranks, b_ranks, strict=True))
    den = math.sqrt(sum((a - mean_a) ** 2 for a in a_ranks)
                    * sum((b - mean_b) ** 2 for b in b_ranks))
    return None if den == 0 else round(num / den, 6)


__all__ = ['CACHE', 'Candidate', 'ablation', 'cached_scores', 'discrimination',
           'fit_fusion', 'fit_gradient_boosting', 'fit_logistic', 'labels', 'matrix',
           'math_risk_candidate', 'per_family', 'rank_correlation',
           'shipped_classifier_candidate', 'current_decision_reference',
           'sklearn_candidate', 'score_windows', 'source_scores', 'NAMES']
