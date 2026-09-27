"""Measuring the *final* decision, not the classifier — and refusing to flatter it.

`training/evaluate.py` measures a model: given a score and a label, how good is
the ranking? That is a question about a component. This module asks the question
the operator actually has: **of the sources this system autonomously blocked, how
many should it have blocked, and how many real visitors did it deny?**

Those are different numbers, and the second one is the release metric (§166).
A classifier with an excellent PR-AUC can still produce an unacceptable false
block rate once thresholds, gates and cost profiles have had their say, and
nothing about the model's own metrics would reveal it.

Three deliberate refusals shape the code.

**Accuracy is computed and never used as a gate.** §13: on a population that is
99.9% benign, a system that blocks nothing scores 99.9% accuracy and has
protected nobody. `usefulness()` calls that `USELESS_NO_DETECTION` no matter how
good the accuracy looks, and `release_gate()` fails it.

**Unlabelled traffic produces no accuracy.** §156: an outcome with no trusted
label contributes to the counts of what was *seen*, never to precision or recall.
When nothing is labelled the report says `GROUND_TRUTH_UNAVAILABLE` rather than
computing something from what it decided itself, which is the §61 loop wearing a
lab coat.

**Precision is reported against prevalence, not once.** §168: precision depends
on how common the positive class is, so a number from a balanced lab set says
almost nothing about production. `prevalence_sweep()` recomputes it from the
measured TPR and FPR across a range of realistic prevalences, and the report
carries the whole curve.

Pure Python on purpose: this runs in the sensor process, where numpy and
scikit-learn are not dependencies.
"""
from dataclasses import dataclass
import math
import random

BENIGN = 'BENIGN'
MALICIOUS_AUTOMATION = 'MALICIOUS_AUTOMATION'
UNLABELED = 'UNLABELED'
LABELS = (BENIGN, MALICIOUS_AUTOMATION, UNLABELED)

GROUND_TRUTH_UNAVAILABLE = 'GROUND_TRUTH_UNAVAILABLE'

#: Verdicts from `usefulness()`.
USEFUL = 'USEFUL'
USELESS_NO_DETECTION = 'USELESS_NO_DETECTION'
USELESS_BLOCKS_EVERYTHING = 'USELESS_BLOCKS_EVERYTHING'
UNKNOWN = 'UNKNOWN'


@dataclass(frozen=True, slots=True)
class Outcome:
    """One source, what the system did, and what it actually was.

    `label` is the only field here that may not be guessed. §63 and §64: it comes
    from a controlled scenario, a signed capture sidecar, a deterministic harness
    or a reviewed evaluation, and from nowhere else. UNLABELED is a first-class
    answer and the common one in production.
    """

    blocked: bool
    label: str = UNLABELED
    site_id: str = ''
    score: float | None = None
    label_source: str = ''

    def __post_init__(self):
        if self.label not in LABELS:
            raise ValueError(f'unknown label {self.label!r}')


@dataclass(frozen=True, slots=True)
class Confusion:
    """The four cells, plus what could not be counted."""

    true_negative: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_positive: int = 0
    unlabeled: int = 0

    @property
    def labelled(self):
        return (self.true_negative + self.false_positive
                + self.false_negative + self.true_positive)

    @property
    def benign(self):
        return self.true_negative + self.false_positive

    @property
    def positives(self):
        return self.true_positive + self.false_negative

    @property
    def blocked(self):
        return self.true_positive + self.false_positive

    def explain(self):
        return {'matrix': [[self.true_negative, self.false_positive],
                           [self.false_negative, self.true_positive]],
                'rows': 'actual benign, actual malicious automation',
                'columns': 'ALLOW, TEMP_BLOCK',
                'labelled': self.labelled, 'unlabeled': self.unlabeled}


def confusion(outcomes):
    """§164. The confusion matrix for the final TEMP_BLOCK decision."""
    cells = {'tn': 0, 'fp': 0, 'fn': 0, 'tp': 0, 'unlabeled': 0}
    for outcome in outcomes:
        if outcome.label == UNLABELED:
            cells['unlabeled'] += 1
        elif outcome.label == MALICIOUS_AUTOMATION:
            cells['tp' if outcome.blocked else 'fn'] += 1
        else:
            cells['fp' if outcome.blocked else 'tn'] += 1
    return Confusion(true_negative=cells['tn'], false_positive=cells['fp'],
                     false_negative=cells['fn'], true_positive=cells['tp'],
                     unlabeled=cells['unlabeled'])


def _ratio(numerator, denominator):
    """None, not zero, when the denominator is empty. The distinction matters:
    zero is a measurement and None is the absence of one."""
    return None if denominator <= 0 else numerator / denominator


@dataclass(frozen=True, slots=True)
class DecisionMetrics:
    """§12 and §165–§166, for the action rather than the score."""

    matrix: Confusion
    precision: float | None = None
    recall: float | None = None
    specificity: float | None = None
    false_positive_rate: float | None = None
    false_negative_rate: float | None = None
    accuracy: float | None = None
    prevalence: float | None = None
    block_precision: float | None = None
    false_blocks_per_1000_benign: float | None = None

    @property
    def ground_truth(self):
        return self.matrix.labelled > 0

    def explain(self):
        if not self.ground_truth:
            return {'status': GROUND_TRUTH_UNAVAILABLE,
                    'observed': self.matrix.explain(),
                    'note': ('unlabelled traffic cannot produce accuracy; these are '
                             'counts of what was decided, not of what was correct')}
        return {'status': 'MEASURED',
                'confusion_matrix': self.matrix.explain(),
                'class_prevalence': _round(self.prevalence),
                'precision': _round(self.precision),
                'recall': _round(self.recall),
                'specificity': _round(self.specificity),
                'false_positive_rate': _round(self.false_positive_rate),
                'false_negative_rate': _round(self.false_negative_rate),
                'block_precision': _round(self.block_precision),
                'false_blocks_per_1000_benign': _round(self.false_blocks_per_1000_benign),
                'accuracy': _round(self.accuracy),
                'accuracy_note': ('reported because people ask for it, and used for '
                                  'nothing: on a rare positive class it is high for a '
                                  'system that detects nothing at all'),
                'labelled_sample': self.matrix.labelled,
                'benign_sample': self.matrix.benign,
                'positive_sample': self.matrix.positives}


def _round(value, digits=6):
    return None if value is None else round(float(value), digits)


def evaluate(outcomes):
    """Everything in §12 that a binary action supports, from trusted labels only."""
    matrix = confusion(outcomes)
    tp, fp, fn, tn = (matrix.true_positive, matrix.false_positive,
                      matrix.false_negative, matrix.true_negative)
    return DecisionMetrics(
        matrix=matrix,
        precision=_ratio(tp, tp + fp),
        recall=_ratio(tp, matrix.positives),
        specificity=_ratio(tn, matrix.benign),
        false_positive_rate=_ratio(fp, matrix.benign),
        false_negative_rate=_ratio(fn, matrix.positives),
        accuracy=_ratio(tp + tn, matrix.labelled),
        prevalence=_ratio(matrix.positives, matrix.labelled),
        block_precision=_ratio(tp, matrix.blocked),
        false_blocks_per_1000_benign=(None if matrix.benign <= 0
                                      else 1000.0 * fp / matrix.benign))


#: §44. The non-degeneracy verdict, reported on its own so neither trivial
#: failure can hide behind a good number belonging to the other one.
NON_DEGENERATE = 'NON_DEGENERATE'
DEGENERATE_ALLOW_ALL = 'DEGENERATE_ALLOW_ALL'
DEGENERATE_BLOCK_ALL = 'DEGENERATE_BLOCK_ALL'


def non_degenerate_gate(metrics):
    """§41 to §44. Neither trivial system may pass, whatever else it scores.

    There are two ways to build a defender that measures beautifully and defends
    nothing.

    **Allow everything.** False blocks per 1000 benign: 0.0. False positive
    rate: 0.0. Specificity: 1.0. Accuracy, on a rare positive class, close to
    perfect. Every one of those numbers is true, and the system has never once
    stopped anything. P15.1 measured exactly this and said so in the next
    sentence — but a gate that depends on somebody reading the next sentence is
    not a gate, which is why this one exists.

    **Block everything.** Recall 1.0, and every visitor denied.

    So both properties are required at once and neither may be traded for the
    other: at least one *correct* block, and a benign population that is not
    being blocked wholesale. No recall target is set — §42 forbids inventing one
    — and this does not replace the false-block ceiling in `ReleaseThresholds`,
    which is a separate operator judgement. It rules out only the two systems
    that are trivially constructible and never useful.
    """
    blocked = metrics.matrix.blocked
    true_blocks = metrics.matrix.true_positive
    false_blocks = metrics.matrix.false_positive
    body = {'blocks_total': blocked, 'true_blocks': true_blocks,
            'false_blocks': false_blocks, 'recall': _round(metrics.recall),
            'note': ('requires one correct block and a benign population that is not '
                     'blocked wholesale; sets no recall target, per §42')}
    if not metrics.ground_truth or metrics.matrix.positives == 0:
        return {**body, 'verdict': GROUND_TRUTH_UNAVAILABLE,
                'reasons': ['no trusted positive to detect']}
    if true_blocks == 0:
        return {**body, 'verdict': DEGENERATE_ALLOW_ALL,
                'reasons': ['no trusted positive was blocked: a system that never acts '
                            'has a perfect false-block rate and no defensive value']}
    if metrics.matrix.benign > 0 and metrics.false_positive_rate >= 1.0:
        return {**body, 'verdict': DEGENERATE_BLOCK_ALL,
                'reasons': ['every trusted benign source was blocked']}
    return {**body, 'verdict': NON_DEGENERATE, 'reasons': []}


def usefulness(metrics):
    """§13, as a verdict rather than a footnote.

    The accuracy trap in one function: a system that blocked nothing on a
    population with real positives in it is useless whatever its accuracy says,
    and a system that blocked everything is useless in the more expensive
    direction. Both are named, and neither is reachable by having a good number
    somewhere else.
    """
    if not metrics.ground_truth or metrics.matrix.positives == 0:
        return UNKNOWN
    if metrics.matrix.blocked == 0:
        return USELESS_NO_DETECTION
    if metrics.matrix.benign > 0 and metrics.false_positive_rate == 1.0:
        return USELESS_BLOCKS_EVERYTHING
    if metrics.recall == 0.0:
        return USELESS_NO_DETECTION
    return USEFUL


# --- ranking metrics, over the estimate each record carried -----------------

def roc_auc(outcomes):
    """Rank-based AUC with tie handling. None when a class is missing.

    Computed over the conservative probability each decision carried, not over
    the action: the action is binary, and an AUC of a binary variable is a
    rearrangement of the confusion matrix rather than new information.
    """
    scored = [o for o in outcomes if o.label != UNLABELED and o.score is not None]
    positives = [o.score for o in scored if o.label == MALICIOUS_AUTOMATION]
    negatives = [o.score for o in scored if o.label == BENIGN]
    if not positives or not negatives:
        return None
    ranks = _average_ranks([o.score for o in scored])
    positive_rank_sum = sum(rank for rank, o in zip(ranks, scored)
                            if o.label == MALICIOUS_AUTOMATION)
    n_pos, n_neg = len(positives), len(negatives)
    u = positive_rank_sum - n_pos * (n_pos + 1) / 2
    return u / (n_pos * n_neg)


def _average_ranks(values):
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and values[order[end + 1]] == values[order[position]]:
            end += 1
        shared = (position + end) / 2 + 1
        for index in range(position, end + 1):
            ranks[order[index]] = shared
        position = end + 1
    return ranks


def pr_auc(outcomes):
    """Average precision. The right summary for a rare class; None when undefined."""
    scored = sorted((o for o in outcomes if o.label != UNLABELED and o.score is not None),
                    key=lambda o: -o.score)
    total_positives = sum(1 for o in scored if o.label == MALICIOUS_AUTOMATION)
    if not scored or not total_positives:
        return None
    seen = positives = 0
    previous_recall = 0.0
    area = 0.0
    for outcome in scored:
        seen += 1
        positives += int(outcome.label == MALICIOUS_AUTOMATION)
        recall = positives / total_positives
        precision = positives / seen
        area += (recall - previous_recall) * precision
        previous_recall = recall
    return area


# --- uncertainty -------------------------------------------------------------

def bootstrap_interval(outcomes, statistic, *, resamples=1000, confidence=0.95, seed=20250915):
    """§35, §170. A percentile bootstrap interval, named as what it is.

    Deterministic: the seed is explicit so a report is reproducible and two runs
    over the same evaluation do not disagree about the third decimal place. The
    result is an *empirical* interval from resampling — not an exact frequentist
    guarantee, which is what §36 asks to be honest about.
    """
    rows = list(outcomes)
    if len(rows) < 2:
        return None
    rng = random.Random(seed)
    values = []
    for _ in range(max(1, int(resamples))):
        sample = [rows[rng.randrange(len(rows))] for _ in range(len(rows))]
        value = statistic(sample)
        if value is not None and math.isfinite(value):
            values.append(value)
    if len(values) < 2:
        return None
    values.sort()
    tail = (1.0 - confidence) / 2.0
    low = values[max(0, min(len(values) - 1, int(math.floor(tail * len(values)))))]
    high = values[max(0, min(len(values) - 1, int(math.ceil((1 - tail) * len(values))) - 1))]
    return {'statistic_low': round(low, 6), 'statistic_high': round(high, 6),
            'confidence': confidence, 'resamples': len(values),
            'method': 'percentile bootstrap over evaluation rows',
            'interpretation': ('an empirical interval from resampling the evaluation '
                               'set; not an exact frequentist confidence interval')}


def prevalence_sweep(metrics, prevalences=(0.0001, 0.001, 0.01, 0.05, 0.10)):
    """§168, §169. What precision becomes when the positive class is rarer.

    Holds the measured TPR and FPR fixed and recomputes precision at each
    prevalence from Bayes:

        precision = TPR*p / (TPR*p + FPR*(1-p))

    This is the number that surprises people. A detector with 95% recall and a
    1% false-positive rate looks excellent on a balanced lab set and has a
    precision of 0.09 when one source in a thousand is malicious — which is why
    a cost model, and not a score, decides whether to block.
    """
    if metrics.recall is None or metrics.false_positive_rate is None:
        return []
    tpr, fpr = metrics.recall, metrics.false_positive_rate
    table = []
    for prevalence in prevalences:
        denominator = tpr * prevalence + fpr * (1 - prevalence)
        table.append({'prevalence': prevalence,
                      'precision': None if denominator <= 0
                      else round(tpr * prevalence / denominator, 6),
                      'recall': round(tpr, 6),
                      'false_positive_rate': round(fpr, 6)})
    return table


def per_site(outcomes):
    """§172. Every site, so the worst one cannot hide behind the average."""
    grouped = {}
    for outcome in outcomes:
        grouped.setdefault(outcome.site_id or 'GLOBAL', []).append(outcome)
    return {name: evaluate(rows) for name, rows in sorted(grouped.items())}


def worst_site(outcomes):
    """The site with the highest false-block rate, and how bad it is there."""
    candidates = [(name, metrics) for name, metrics in per_site(outcomes).items()
                  if metrics.false_blocks_per_1000_benign is not None]
    if not candidates:
        return None
    name, metrics = max(candidates, key=lambda item: item[1].false_blocks_per_1000_benign)
    return {'site': name, 'metrics': metrics.explain()}


# --- the report --------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ReleaseThresholds:
    """What a release has to demonstrate. Operator policy, not measurement.

    §126 says optimise for block precision rather than for a number of blocks,
    and §166 makes false blocks per 1000 benign sources the primary release
    metric. Neither of those fixes a value, and inventing one from nothing would
    be exactly the false precision §17 warns about — so these are the bar this
    project asks a release to clear, stated as a judgement.
    """

    max_false_blocks_per_1000_benign: float = 1.0
    min_block_precision: float = 0.95
    min_benign_sample: int = 500
    min_positive_sample: int = 50

    def explain(self):
        return {'max_false_blocks_per_1000_benign': self.max_false_blocks_per_1000_benign,
                'min_block_precision': self.min_block_precision,
                'min_benign_sample': self.min_benign_sample,
                'min_positive_sample': self.min_positive_sample,
                'note': 'operator policy; none of these values is measured'}


def release_gate(metrics, thresholds=None):
    """§211, §216. PASS, FAIL or INSUFFICIENT_EVIDENCE — never an optimistic guess.

    Note which way "not enough data" falls. It is not a PASS with a caveat: a
    release gate that passed on 12 benign examples would be a gate that never
    failed, and §171 exists because that is a tempting mistake.
    """
    thresholds = thresholds or ReleaseThresholds()
    if not metrics.ground_truth:
        return {'verdict': 'INSUFFICIENT_EVIDENCE', 'reasons': [GROUND_TRUTH_UNAVAILABLE],
                'thresholds': thresholds.explain()}
    reasons = []
    if metrics.matrix.benign < thresholds.min_benign_sample:
        reasons.append(f'only {metrics.matrix.benign} trusted benign sources; '
                       f'{thresholds.min_benign_sample} required')
    if metrics.matrix.positives < thresholds.min_positive_sample:
        reasons.append(f'only {metrics.matrix.positives} trusted malicious-automation '
                       f'sources; {thresholds.min_positive_sample} required')
    if reasons:
        return {'verdict': 'INSUFFICIENT_EVIDENCE', 'reasons': reasons,
                'thresholds': thresholds.explain()}
    # §41. Computed before anything else is reported, and carried on every
    # branch: an allow-all system passes the false-block ceiling perfectly, and
    # a FAIL whose only stated reason is "0.0 false blocks per 1000 benign"
    # reads as a pass to anybody skimming.
    degeneracy = non_degenerate_gate(metrics)
    verdict = usefulness(metrics)
    if verdict != USEFUL:
        return {'verdict': 'FAIL', 'reasons': [verdict],
                'non_degenerate_decision_gate': degeneracy,
                'thresholds': thresholds.explain()}
    if degeneracy['verdict'] != NON_DEGENERATE:
        return {'verdict': 'FAIL', 'reasons': [degeneracy['verdict'], *degeneracy['reasons']],
                'non_degenerate_decision_gate': degeneracy,
                'thresholds': thresholds.explain()}
    if (metrics.false_blocks_per_1000_benign is not None
            and metrics.false_blocks_per_1000_benign > thresholds.max_false_blocks_per_1000_benign):
        reasons.append(f'{metrics.false_blocks_per_1000_benign:.2f} false blocks per '
                       f'1000 benign sources exceeds '
                       f'{thresholds.max_false_blocks_per_1000_benign:.2f}')
    if (metrics.block_precision is not None
            and metrics.block_precision < thresholds.min_block_precision):
        reasons.append(f'block precision {metrics.block_precision:.3f} is below '
                       f'{thresholds.min_block_precision:.3f}')
    return {'verdict': 'FAIL' if reasons else 'PASS', 'reasons': reasons,
            'non_degenerate_decision_gate': degeneracy,
            'thresholds': thresholds.explain()}


def report(outcomes, *, thresholds=None, resamples=500):
    """§155 and §218's metrics block, in one document."""
    rows = list(outcomes)
    metrics = evaluate(rows)
    body = {'decision_metrics': metrics.explain(),
            'usefulness': usefulness(metrics),
            'non_degenerate_decision_gate': non_degenerate_gate(metrics),
            'release_gate': release_gate(metrics, thresholds)}
    if not metrics.ground_truth:
        body['ranking'] = {'status': GROUND_TRUTH_UNAVAILABLE}
        body['prevalence_sweep'] = []
        body['bootstrap'] = {}
        body['worst_site'] = None
        return body
    body['ranking'] = {'roc_auc': _round(roc_auc(rows)), 'pr_auc': _round(pr_auc(rows)),
                       'note': ('computed over the conservative probability each '
                                'decision carried, not over the binary action')}
    body['prevalence_sweep'] = prevalence_sweep(metrics)
    body['bootstrap'] = {
        'block_precision': bootstrap_interval(
            rows, lambda sample: evaluate(sample).block_precision, resamples=resamples),
        'false_positive_rate': bootstrap_interval(
            rows, lambda sample: evaluate(sample).false_positive_rate, resamples=resamples),
        'false_blocks_per_1000_benign': bootstrap_interval(
            rows, lambda sample: evaluate(sample).false_blocks_per_1000_benign,
            resamples=resamples)}
    body['worst_site'] = worst_site(rows)
    return body
