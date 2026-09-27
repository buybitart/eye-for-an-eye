"""Turning a score into a probability, in a form production can load safely.

A calibrator is a monotone map from a score to P(malicious | score). Two are
implemented, both classical, both small enough to read:

**Sigmoid (Platt).** `p = 1 / (1 + exp(a*s + b))`. Two parameters, fitted by
maximum likelihood. It assumes the map has a logistic shape, which is a real
assumption and usually a safe one; with few calibration points that assumption is
doing useful work rather than getting in the way.

**Isotonic.** A monotone step function fitted by pool-adjacent-violators. It
assumes only monotonicity, which is weaker and therefore needs more data; with
few points it interpolates the noise and calibrates beautifully on the fold it
was fitted on and nowhere else.

### Why not pickle

§79. A calibrator loaded in production is code the process will run if it is
allowed to be. These artifacts serialise to JSON — two floats, or a list of
knots — validated on load: finite, in range, monotone, and bound to the model
version they were fitted against. An artifact that fails any of those checks is
refused rather than repaired, because a silently repaired calibrator is a
probability nobody can account for.

### Why the artifact names the model

§84. A calibrator maps *one model's* scores. Point it at a retrained model and
every number it emits is wrong in a way that looks entirely reasonable. So the
artifact carries `model_version`, `calibrate()` refuses a mismatch, and the
refusal is `CALIBRATION_UNAVAILABLE` rather than an exception — the decision path
must degrade to "no autonomous block", never crash.

A calibrator fitted on `MathRisk` is the exception: `MathRisk` is deterministic
and has no weights that can be retrained under it, so its artifact declares an
empty `model_version` and is compatible with anything. That is a property of the
quantity, not a shortcut, and `requires_model` says which case an artifact is.
"""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

from .scores import CalibratedProbability

#: Bumped when the artifact shape changes. Values are covered by the digest.
CALIBRATION_SCHEMA_VERSION = 1

SIGMOID = 'sigmoid'
ISOTONIC = 'isotonic'
METHODS = (SIGMOID, ISOTONIC)

#: What one fitting example was. §48, and it is not bookkeeping.
#:
#: A `WINDOW`-fitted curve answers "of windows scoring like this, what fraction
#: came from a malicious source". A `SOURCE`-fitted one answers "of sources
#: whose worst window scored like this, what fraction were malicious". The cost
#: arithmetic in `autonomy/cost.py` prices a wrongly blocked **source**, and a
#: block is taken the first time any one of a source's windows crosses — so a
#: source watched for ten minutes gets dozens of chances to be wrong about,
#: while a window-fitted probability was fitted as though it got one.
#:
#: Measured on the P15.4 development corpus and recorded in
#: `reports/P15_4_CALIBRATION_UNIT.json`: across every cutoff where benign
#: traffic appears at all, the fraction of benign *sources* crossing is **8.5 to
#: 12.1 times** the fraction of benign *windows* crossing. Every cycle before
#: P15.4 fitted per window and compared per source, and none measured the gap.
#:
#: `WINDOW` remains the default because it is what every existing artifact on
#: disk was fitted on, and describing an old file accurately matters more than
#: tidiness. New artifacts say which they are.
WINDOW = 'window'
SOURCE = 'source'
UNITS = (WINDOW, SOURCE)

#: An artifact this big is not a calibrator any more.
MAX_KNOTS = 4096
MAX_ARTIFACT_BYTES = 1_048_576

#: Wilson z for the conservative bound. 1.96 is the 95% two-sided normal
#: quantile, and here it is used for a real one-sided lower bound on a real
#: binomial proportion, so the name is earned rather than borrowed — see
#: `conservative_knots`.
WILSON_Z = 1.96

#: How many score bins the conservative bound is estimated over. More bins
#: follow the calibration curve more closely and leave fewer examples in each,
#: which widens every interval; this is the usual bias-variance trade and 20 is
#: a round number chosen before any result was looked at.
CONSERVATIVE_BINS = 20


def wilson_lower(positives, total, *, z=WILSON_Z):
    """Lower end of the Wilson score interval for a binomial proportion.

    This is the correction P15 reached for and applied to the wrong quantity.
    The proportion being bounded is P(malicious | score in this band), and `n` is
    the number of *calibration examples* in that band. P15 used the number of
    packets in the observation window, which is not the sample size of this
    estimate and is typically two orders of magnitude smaller — so the interval
    was enormous and the estimate collapsed to zero for three quarters of all
    windows.

    With no examples the bound is 0.0, which is the honest answer: a score band
    the calibration data never visited supports no claim at all.
    """
    n = max(0, int(total))
    if n <= 0:
        return 0.0
    p = max(0.0, min(1.0, float(positives) / n))
    denominator = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(max(0.0, p * (1.0 - p) / n + z * z / (4 * n * n))) / denominator
    return max(0.0, min(1.0, centre - half))


class CalibrationError(ValueError):
    """An artifact that cannot be trusted to produce a probability."""


def _finite(value, name):
    number = float(value)
    if not math.isfinite(number):
        raise CalibrationError(f'{name} is not finite')
    return number


@dataclass(frozen=True, slots=True)
class Calibrator:
    """A validated, serialisable score-to-probability map.

    Immutable, because a calibrator that could be edited after validation is one
    that was never validated — the same reasoning as `EnforcementRequest`.
    """

    method: str
    version: str
    source: str
    model_version: str = ''
    #: Sigmoid parameters. Unused by isotonic.
    a: float = 0.0
    b: float = 0.0
    #: Isotonic knots, ascending in x, non-decreasing in y. Unused by sigmoid.
    knots: tuple = ()
    #: Conservative knots: a monotone lower bound on P(malicious | score), from
    #: the calibration data's own sample sizes. Optional — an artifact without
    #: them supports no autonomous block, because there is then nothing to
    #: compare against a cost cutoff that is not an optimistic point estimate.
    lower_knots: tuple = ()
    samples: int = 0
    positives: int = 0
    #: §48. What one fitting example was — see `UNITS`. Defaults to `WINDOW`
    #: because that is what every artifact written before P15.4 was fitted on,
    #: and a default that describes the existing files truthfully is worth more
    #: than one that describes the current preference.
    unit: str = WINDOW
    schema_version: int = CALIBRATION_SCHEMA_VERSION

    def __post_init__(self):
        if self.method not in METHODS:
            raise CalibrationError(f'unknown calibration method {self.method!r}')
        if self.unit not in UNITS:
            raise CalibrationError(f'unknown calibration unit {self.unit!r}')
        if self.schema_version != CALIBRATION_SCHEMA_VERSION:
            raise CalibrationError('unsupported calibration schema version')
        if not str(self.version) or not str(self.source):
            raise CalibrationError('a calibrator must name its version and its source quantity')
        if self.method == SIGMOID:
            _finite(self.a, 'a')
            _finite(self.b, 'b')
            if self.knots:
                raise CalibrationError('a sigmoid calibrator carries no knots')
        else:
            knots = tuple((float(x), float(y)) for x, y in self.knots)
            if not 2 <= len(knots) <= MAX_KNOTS:
                raise CalibrationError(f'isotonic needs 2 to {MAX_KNOTS} knots, got {len(knots)}')
            previous_x = -math.inf
            previous_y = -math.inf
            for x, y in knots:
                _finite(x, 'knot x')
                _finite(y, 'knot y')
                if not 0.0 <= y <= 1.0:
                    raise CalibrationError('isotonic outputs must lie in [0, 1]')
                if x <= previous_x:
                    raise CalibrationError('isotonic knots must ascend in x')
                if y < previous_y - 1e-12:
                    raise CalibrationError('isotonic knots must not decrease in y')
                previous_x, previous_y = x, y
            object.__setattr__(self, 'knots', knots)
        if self.lower_knots:
            lower = tuple((float(x), float(y)) for x, y in self.lower_knots)
            if not 2 <= len(lower) <= MAX_KNOTS:
                raise CalibrationError('conservative knots must number 2 to MAX_KNOTS')
            previous_x = -math.inf
            previous_y = -math.inf
            for x, y in lower:
                _finite(x, 'lower knot x')
                _finite(y, 'lower knot y')
                if not 0.0 <= y <= 1.0:
                    raise CalibrationError('conservative bounds must lie in [0, 1]')
                if x <= previous_x:
                    raise CalibrationError('conservative knots must ascend in x')
                if y < previous_y - 1e-12:
                    raise CalibrationError('conservative knots must not decrease in y')
                previous_x, previous_y = x, y
            object.__setattr__(self, 'lower_knots', lower)
        if int(self.samples) < 0 or int(self.positives) < 0:
            raise CalibrationError('sample counts cannot be negative')
        if int(self.positives) > int(self.samples):
            raise CalibrationError('more positives than samples')

    @property
    def requires_model(self):
        """Whether this artifact is tied to one model version."""
        return bool(self.model_version)

    def probability(self, score):
        """The raw mapped value. Use `calibrate()` on the decision path.

        A non-finite score raises rather than clamping. §82, and a specific
        trap: `min(1.0, nan)` returns 1.0 in Python, so a naive clamp turns a
        NaN feature into total certainty of maliciousness — the single worst
        value it could become. Found by `tests/test_p15_2_scores.py`, which was
        written before this line was.
        """
        number = float(score)
        if not math.isfinite(number):
            raise CalibrationError(f'cannot calibrate a non-finite score: {score!r}')
        value = max(0.0, min(1.0, number))
        if self.method == SIGMOID:
            # The standard Platt form. Clamped before exp so a steep fit on an
            # extreme score cannot overflow into a NaN that then propagates into
            # a decision.
            z = max(-60.0, min(60.0, self.a * value + self.b))
            return 1.0 / (1.0 + math.exp(z))
        return self._interpolate(value)

    @property
    def conservative(self):
        """Whether this artifact carries a lower bound, and may therefore block."""
        return bool(self.lower_knots)

    def lower(self, score):
        """A conservative lower bound on P(malicious | score), or None.

        `None` when the artifact has no conservative knots. On the decision path
        that means `CALIBRATION_UNAVAILABLE`: a point estimate is not something
        to deny a stranger a service over.
        """
        if not self.lower_knots:
            return None
        number = float(score)
        if not math.isfinite(number):
            raise CalibrationError(f'cannot bound a non-finite score: {score!r}')
        return self._interpolate(max(0.0, min(1.0, number)), self.lower_knots)

    def _interpolate(self, value, knots=None):
        knots = self.knots if knots is None else knots
        if value <= knots[0][0]:
            return knots[0][1]
        if value >= knots[-1][0]:
            return knots[-1][1]
        low, high = 0, len(knots) - 1
        while high - low > 1:
            middle = (low + high) // 2
            if knots[middle][0] <= value:
                low = middle
            else:
                high = middle
        (x0, y0), (x1, y1) = knots[low], knots[high]
        if x1 <= x0:
            return y1
        return y0 + (y1 - y0) * (value - x0) / (x1 - x0)

    def calibrate(self, score, *, model_version=''):
        """A `CalibratedProbability`, or `None` when this artifact does not apply.

        `None` rather than an exception: on the decision path an unusable
        calibrator means `CALIBRATION_UNAVAILABLE` and therefore no autonomous
        block, which is a decision the system knows how to make. An exception
        there would hand the choice to whichever caller caught it.
        """
        if self.requires_model and str(model_version or '') != self.model_version:
            return None
        try:
            value = self.probability(score)
            bound = self.lower(score)
        except (TypeError, ValueError):
            # Includes CalibrationError, which subclasses ValueError. On the
            # decision path an unusable score means no probability and therefore
            # no autonomous block, which is a state the system knows how to be
            # in; raising here would hand the choice to whichever caller caught
            # it, and one of them would eventually choose to carry on.
            return None
        if not math.isfinite(value):
            return None
        value = max(0.0, min(1.0, value))
        return CalibratedProbability(
            value=value, source=self.source,
            calibrator_version=self.version, model_version=self.model_version,
            calibration_samples=int(self.samples),
            lower=None if bound is None else min(value, max(0.0, min(1.0, bound))))

    def document(self):
        body = {'schema_version': self.schema_version, 'method': self.method,
                'version': self.version, 'source': self.source,
                'model_version': self.model_version,
                'samples': int(self.samples), 'positives': int(self.positives)}
        if self.method == SIGMOID:
            body['a'] = self.a
            body['b'] = self.b
        else:
            body['knots'] = [[x, y] for x, y in self.knots]
        if self.lower_knots:
            body['lower_knots'] = [[x, y] for x, y in self.lower_knots]
        # Written only when it is not the default, exactly as `lower_knots` is.
        # The digest covers this document, so emitting `unit: window`
        # unconditionally would change the digest of every artifact ever
        # written and make each of them refuse to load — a compatibility break
        # bought for nothing, since an artifact without the field IS a
        # window-fitted one.
        if self.unit != WINDOW:
            body['unit'] = self.unit
        return body

    @property
    def digest(self):
        payload = json.dumps(self.document(), sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(payload.encode()).hexdigest()

    def save(self, path):
        body = self.document()
        body['sha256'] = self.digest
        Path(path).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
        return path


def load(path):
    """Read and validate an artifact. Refuses rather than repairs."""
    target = Path(path)
    if not target.is_file():
        raise CalibrationError(f'no calibrator at {target}')
    size = target.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise CalibrationError(f'calibrator artifact is {size} bytes; refusing to parse')
    try:
        body = json.loads(target.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise CalibrationError(f'unreadable calibrator: {error}') from error
    return from_document(body)


def from_document(body):
    if not isinstance(body, dict):
        raise CalibrationError('a calibrator document is an object')
    stated = body.get('sha256')
    known = {'schema_version', 'method', 'version', 'source', 'model_version',
             'samples', 'positives', 'a', 'b', 'knots', 'lower_knots', 'unit', 'sha256'}
    unknown = set(body) - known
    if unknown:
        # Same rule as the enforcement request: a field this code does not
        # understand is either newer than it or an attempt to smuggle one in.
        raise CalibrationError(f'unknown calibrator fields: {sorted(unknown)}')
    calibrator = Calibrator(
        method=str(body.get('method', '')),
        version=str(body.get('version', '')),
        source=str(body.get('source', '')),
        model_version=str(body.get('model_version', '')),
        a=float(body.get('a', 0.0)), b=float(body.get('b', 0.0)),
        knots=tuple(tuple(pair) for pair in body.get('knots', ())),
        lower_knots=tuple(tuple(pair) for pair in body.get('lower_knots', ())),
        samples=int(body.get('samples', 0)),
        positives=int(body.get('positives', 0)),
        unit=str(body.get('unit', WINDOW)),
        schema_version=int(body.get('schema_version', CALIBRATION_SCHEMA_VERSION)))
    if stated and stated != calibrator.digest:
        raise CalibrationError('calibrator digest does not match its contents')
    return calibrator


# --- fitting ----------------------------------------------------------------
#
# Fitting lives here rather than in `training/` because the shapes are tiny and
# the production loader has to agree with the fitter exactly. Two copies of a
# sigmoid is how a calibration bug gets written.


def conservative_knots(scores, labels, *, bins=CONSERVATIVE_BINS, z=WILSON_Z):
    """A monotone Wilson lower bound on P(malicious | score), from the fit data.

    This is the piece P15's uncertainty module was reaching for and applied to
    the wrong sample size. Here the arithmetic matches the claim:

    * the proportion is the observed malicious fraction among calibration
      examples whose score falls in a band;
    * `n` is how many calibration examples that band holds;
    * the interval is a genuine Wilson score interval, so calling it one is
      accurate rather than aspirational.

    Bands are equal-count rather than equal-width. Scores pile up near zero on
    this kind of evidence, and equal-width bands would put almost every example
    in the first band and leave the interesting end of the range estimated from
    a handful of points — precisely where a wrong bound does damage.

    The result is made non-decreasing by a running maximum. A dip would say that
    *more* evidence of maliciousness supports a *weaker* claim, which is not
    something any of this is meant to express (§100, §26).
    """
    points = sorted(((max(0.0, min(1.0, float(score))), 1 if int(label) else 0)
                     for score, label in zip(scores, labels, strict=True)),
                    key=lambda pair: pair[0])
    if len(points) < 2:
        raise CalibrationError('a conservative bound needs at least two points')
    bins = max(2, min(int(bins), len(points)))
    per_bin = max(1, len(points) // bins)
    bands = []
    index = 0
    while index < len(points):
        stop = min(len(points), index + per_bin)
        # Never split a run of identical scores across two bands: two examples
        # with the same score must get the same bound.
        while stop < len(points) and points[stop][0] == points[stop - 1][0]:
            stop += 1
        band = points[index:stop]
        bands.append((band[0][0], band[-1][0], sum(label for _, label in band), len(band)))
        index = stop
    knots = []
    running = 0.0
    for low, high, positives, total in bands:
        running = max(running, wilson_lower(positives, total, z=z))
        knots.append((low, running))
        if high > low:
            knots.append((high, running))
    # Anchor both ends so a score outside the observed range is still answered,
    # and answered conservatively at the bottom.
    if knots[0][0] > 0.0:
        knots.insert(0, (0.0, knots[0][1]))
    if knots[-1][0] < 1.0:
        knots.append((1.0, knots[-1][1]))
    cleaned = []
    for x, y in knots:
        if cleaned and x <= cleaned[-1][0]:
            cleaned[-1] = (cleaned[-1][0], max(cleaned[-1][1], y))
            continue
        cleaned.append((x, max(y, cleaned[-1][1]) if cleaned else y))
    return tuple(cleaned)


def fit_sigmoid(scores, labels, *, version, source, model_version='', unit=WINDOW,
                iterations=200, tolerance=1e-8, conservative=True,
                bins=CONSERVATIVE_BINS):
    """Platt scaling by Newton's method on the regularised log-likelihood.

    The target smoothing is Platt's own: `(N+ + 1)/(N+ + 2)` for positives and
    `1/(N- + 2)` for negatives, which keeps the fit finite when one class is
    perfectly separable. Without it a separable calibration fold drives the
    parameters to infinity and every probability becomes 0 or 1 — the most
    confident possible statement from the least informative possible evidence.
    """
    points = [(max(0.0, min(1.0, float(score))), 1 if int(label) else 0)
              for score, label in zip(scores, labels, strict=True)]
    if len(points) < 2:
        raise CalibrationError('sigmoid calibration needs at least two points')
    positives = sum(label for _, label in points)
    negatives = len(points) - positives
    if not positives or not negatives:
        raise CalibrationError('sigmoid calibration needs both classes')
    high = (positives + 1.0) / (positives + 2.0)
    low = 1.0 / (negatives + 2.0)
    targets = [high if label else low for _, label in points]
    a, b = 0.0, math.log((negatives + 1.0) / (positives + 1.0))
    for _ in range(iterations):
        g1 = g2 = h11 = h22 = h12 = 0.0
        for (score, _), target in zip(points, targets, strict=True):
            z = max(-60.0, min(60.0, a * score + b))
            p = 1.0 / (1.0 + math.exp(z))
            d = p * (1.0 - p)
            error = target - p
            g1 += score * error
            g2 += error
            h11 += score * score * d
            h12 += score * d
            h22 += d
        determinant = h11 * h22 - h12 * h12
        if abs(determinant) < 1e-14:
            break
        step_a = (h22 * g1 - h12 * g2) / determinant
        step_b = (h11 * g2 - h12 * g1) / determinant
        a -= step_a
        b -= step_b
        if abs(step_a) < tolerance and abs(step_b) < tolerance:
            break
    lower = conservative_knots(scores, labels, bins=bins) if conservative else ()
    return Calibrator(method=SIGMOID, version=version, source=source,
                      model_version=model_version, a=a, b=b, lower_knots=lower,
                      samples=len(points), positives=positives, unit=unit)


def fit_isotonic(scores, labels, *, version, source, model_version='', unit=WINDOW,
                 max_knots=MAX_KNOTS, conservative=True, bins=CONSERVATIVE_BINS):
    """Pool-adjacent-violators, then thinned to the points where the map changes.

    The thinning is not cosmetic: a knot per distinct score would carry the
    calibration fold into the artifact, which is both larger than it needs to be
    and closer to publishing the evaluation set than anybody intends.
    """
    points = sorted(((max(0.0, min(1.0, float(score))), 1.0 if int(label) else 0.0)
                     for score, label in zip(scores, labels, strict=True)),
                    key=lambda pair: pair[0])
    if len(points) < 2:
        raise CalibrationError('isotonic calibration needs at least two points')
    positives = int(sum(label for _, label in points))
    if not positives or positives == len(points):
        raise CalibrationError('isotonic calibration needs both classes')

    # Average ties first: PAVA on tied x values otherwise depends on input order.
    merged = []
    for score, label in points:
        if merged and merged[-1][0] == score:
            merged[-1][1] += label
            merged[-1][2] += 1
        else:
            merged.append([score, label, 1])

    blocks = []  # [sum, count, x_start, x_end]
    for score, total, count in merged:
        blocks.append([total, count, score, score])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            total_b, count_b, start, _ = blocks.pop()
            blocks[-1][0] += total_b
            blocks[-1][1] += count_b
            blocks[-1][3] = start if start > blocks[-1][3] else blocks[-1][3]
            blocks[-1][3] = max(blocks[-1][3], start)

    knots = []
    for total, count, start, end in blocks:
        value = total / count
        knots.append((start, value))
        if end > start:
            knots.append((end, value))
    # Strictly ascending x, non-decreasing y, and no redundant middle points.
    cleaned = []
    for x, y in knots:
        if cleaned and x <= cleaned[-1][0]:
            cleaned[-1] = (cleaned[-1][0], max(cleaned[-1][1], y))
            continue
        cleaned.append((x, max(y, cleaned[-1][1]) if cleaned else y))
    if len(cleaned) == 1:
        x, y = cleaned[0]
        cleaned = [(0.0, y), (1.0, y)] if x not in (0.0, 1.0) else [(0.0, y), (1.0, y)]
    if len(cleaned) > max_knots:
        step = len(cleaned) / max_knots
        thinned = [cleaned[int(index * step)] for index in range(max_knots)]
        if thinned[-1] != cleaned[-1]:
            thinned[-1] = cleaned[-1]
        cleaned = thinned
    lower = conservative_knots(scores, labels, bins=bins) if conservative else ()
    return Calibrator(method=ISOTONIC, version=version, source=source,
                      model_version=model_version, knots=tuple(cleaned),
                      lower_knots=lower,
                      samples=len(points), positives=positives, unit=unit)


# --- calibration quality ----------------------------------------------------


def brier(probabilities, labels):
    """Mean squared error of the probabilities. Lower is better; 0.25 is a coin."""
    pairs = list(zip(probabilities, labels, strict=True))
    if not pairs:
        return None
    return sum((float(p) - (1.0 if int(actual) else 0.0)) ** 2
               for p, actual in pairs) / len(pairs)


def reliability(probabilities, labels, *, bins=10):
    """Observed frequency against predicted probability, per bin."""
    pairs = list(zip((float(p) for p in probabilities),
                     (1 if int(actual) else 0 for actual in labels), strict=True))
    edges = [index / bins for index in range(bins + 1)]
    rows = []
    for index in range(bins):
        low, high = edges[index], edges[index + 1]
        inside = [(p, actual) for p, actual in pairs
                  if (low <= p < high) or (index == bins - 1 and p == 1.0)]
        if not inside:
            rows.append({'bin': [round(low, 3), round(high, 3)], 'count': 0,
                         'mean_probability': None, 'observed_frequency': None})
            continue
        rows.append({'bin': [round(low, 3), round(high, 3)], 'count': len(inside),
                     'mean_probability': round(sum(p for p, _ in inside) / len(inside), 6),
                     'observed_frequency': round(sum(a for _, a in inside) / len(inside), 6)})
    return rows


def expected_calibration_error(probabilities, labels, *, bins=10):
    """ECE: the average gap between claim and outcome, weighted by bin size.

    Reported alongside Brier because they fail differently. A model that says
    0.5 about everything has a mediocre Brier and a perfect ECE at the right
    prevalence — calibration is necessary and nowhere near sufficient, which is
    why §1 puts discrimination first.
    """
    rows = reliability(probabilities, labels, bins=bins)
    total = sum(row['count'] for row in rows)
    if not total:
        return None
    return sum(row['count'] * abs(row['mean_probability'] - row['observed_frequency'])
               for row in rows if row['count']) / total
