"""P8 out-of-distribution detection.

OOD answers one question: how far is this observation from the data the model
was fitted on?

A high OOD score is NOT evidence of an attack. It means the classifier knows
less about this input than usual, so its opinion must count for less. OOD can
only ever reduce trust in the supervised model; it never raises risk on its own.
"""
from dataclasses import dataclass, field
import math

IN_DISTRIBUTION = 'IN_DISTRIBUTION'
BORDERLINE = 'BORDERLINE'
OUT_OF_DISTRIBUTION = 'OUT_OF_DISTRIBUTION'
INSUFFICIENT_REFERENCE = 'INSUFFICIENT_REFERENCE'

# Provisional band contributions. Calibrate against real deployments before
# treating them as tuned values.
INNER_BAND = 0.0        # inside p05..p95: the model has seen this often
OUTER_BAND = 0.35       # p01..p05 or p95..p99: uncommon but represented
TAIL_BAND = 0.70        # beyond p01..p99 but inside the observed training range
BEYOND_RANGE = 0.85     # outside min..max: never seen during training
TOP_CONTRIBUTORS = 3


@dataclass(frozen=True, slots=True)
class FeatureDeviation:
    feature: str
    value: float
    contribution: float
    band: str
    reference_low: float
    reference_high: float

    def explain(self):
        return {'feature': self.feature, 'value': round(self.value, 6),
                'contribution': round(self.contribution, 4), 'band': self.band,
                'training_p01': round(self.reference_low, 6), 'training_p99': round(self.reference_high, 6)}


@dataclass(frozen=True, slots=True)
class OODResult:
    status: str = INSUFFICIENT_REFERENCE
    score: float = 0.0
    reference_version: str = 'none'
    reason: str = 'no reference distribution configured'
    evaluated_features: int = 0
    missing_features: int = 0
    top_outlier_features: tuple[FeatureDeviation, ...] = field(default_factory=tuple)

    @property
    def usable(self):
        return self.status in (IN_DISTRIBUTION, BORDERLINE, OUT_OF_DISTRIBUTION)

    @property
    def distribution_confidence(self):
        """How much the supervised model should still be trusted, 0..1.

        With no reference we do not pretend to know: confidence stays at 1.0 and
        the separate INSUFFICIENT_REFERENCE status is what policy reacts to.
        """
        return 1.0 - self.score if self.usable else 1.0

    def explain(self):
        return {'status': self.status, 'score': round(self.score, 4),
                'distribution_confidence': round(self.distribution_confidence, 4),
                'reference_version': self.reference_version, 'reason': self.reason,
                'evaluated_features': self.evaluated_features, 'missing_features': self.missing_features,
                'top_outlier_features': [d.explain() for d in self.top_outlier_features]}


def _deviation(ref, value):
    """Bounded distance of one value from its training band."""
    q = ref.quantiles
    if q['p05'] <= value <= q['p95']:
        return INNER_BAND, 'inner'
    if q['p01'] <= value <= q['p99']:
        return OUTER_BAND, 'outer'
    if ref.minimum <= value <= ref.maximum:
        return TAIL_BAND, 'tail'
    # Outside the training range. Scale the extra distance by the robust spread
    # so a feature with a wide natural range is not punished like a narrow one.
    overshoot = (ref.minimum - value) if value < ref.minimum else (value - ref.maximum)
    extra = min(0.15, 0.15 * (overshoot / ref.spread))
    return min(1.0, BEYOND_RANGE + extra), 'beyond_range'


class OODEngine:
    """Per-observation OOD scoring against an immutable reference distribution."""

    def __init__(self, reference=None, *, borderline_threshold=0.25, high_threshold=0.60,
                 minimum_features=4):
        self.reference = reference
        self.borderline_threshold = borderline_threshold
        self.high_threshold = high_threshold
        self.minimum_features = minimum_features

    def evaluate(self, values):
        """Score a transformed feature mapping. Missing values are skipped, not guessed."""
        if self.reference is None:
            return OODResult()
        deviations, missing = [], 0
        for name, ref in self.reference.features.items():
            if name.startswith('available_'):
                continue  # availability flags describe completeness, not distribution
            value = values.get(name)
            if value is None or not isinstance(value, (int, float)) or not math.isfinite(value):
                missing += 1
                continue
            if ref.constant:
                continue  # a constant reference cannot say anything about distance
            contribution, band = _deviation(ref, float(value))
            deviations.append(FeatureDeviation(feature=name, value=float(value), contribution=contribution,
                band=band, reference_low=ref.quantiles['p01'], reference_high=ref.quantiles['p99']))
        if len(deviations) < self.minimum_features:
            return OODResult(status=INSUFFICIENT_REFERENCE, reference_version=self.reference.model_version,
                reason='too few comparable features in this observation',
                evaluated_features=len(deviations), missing_features=missing)
        contributions = sorted((d.contribution for d in deviations), reverse=True)
        # Neither a plain mean (one extreme feature disappears) nor a plain max
        # (one noisy feature dominates). Half the average, half the worst few.
        average = sum(contributions) / len(contributions)
        top = contributions[:TOP_CONTRIBUTORS]
        score = min(1.0, 0.5 * average + 0.5 * (sum(top) / len(top)))
        status = (OUT_OF_DISTRIBUTION if score >= self.high_threshold else
                  BORDERLINE if score >= self.borderline_threshold else IN_DISTRIBUTION)
        outliers = tuple(sorted((d for d in deviations if d.contribution > 0),
                                key=lambda d: d.contribution, reverse=True)[:TOP_CONTRIBUTORS])
        reason = {IN_DISTRIBUTION: 'observation matches the training distribution',
                  BORDERLINE: 'observation sits in the tails of the training distribution',
                  OUT_OF_DISTRIBUTION: 'observation is unlike the training distribution'}[status]
        return OODResult(status=status, score=score, reference_version=self.reference.model_version,
            reason=reason, evaluated_features=len(deviations), missing_features=missing,
            top_outlier_features=outliers)
