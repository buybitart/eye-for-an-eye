"""P8 drift detection and model health.

Drift is a statement about the *population*, not about any one source. A drifted
feature distribution means the model may be out of date. It never makes an
individual source more suspicious.

The method is Population Stability Index over the reference's own fixed bins,
plus a quantile-shift check. Both are simple enough to audit by hand.
"""
from dataclasses import dataclass, field
import math

INSUFFICIENT_DATA = 'INSUFFICIENT_DATA'
STABLE = 'STABLE'
WARNING = 'WARNING'
DRIFTED = 'DRIFTED'

HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNRELIABLE = 'UNRELIABLE'
UNAVAILABLE = 'UNAVAILABLE'

# Provisional PSI thresholds. The usual industry rule of thumb is 0.1 / 0.25.
# They are configurable and must be calibrated per deployment before being
# treated as tuned. PSI is not a probability.
PSI_WARNING = 0.10
PSI_DRIFTED = 0.25
EPSILON = 1e-6
MINIMUM_SAMPLES = 200


def psi(reference_fractions, current_counts):
    """Population Stability Index over fixed reference bins.

    Empty bins are floored with a small epsilon on both sides, so the result is
    always finite and no division by zero is possible.
    """
    total = sum(current_counts)
    if total <= 0:
        return None
    score = 0.0
    for expected, count in zip(reference_fractions, current_counts, strict=True):
        actual = max(count / total, EPSILON)
        expected = max(expected, EPSILON)
        score += (actual - expected) * math.log(actual / expected)
    return score if math.isfinite(score) and score >= 0 else None


def quantile_shift(ref, current_counts):
    """Shift of the current median bin against the reference median bin, 0..1."""
    total = sum(current_counts)
    if total <= 0:
        return None
    cumulative, current_median_bin = 0, len(current_counts) - 1
    for index, count in enumerate(current_counts):
        cumulative += count
        if cumulative >= total / 2:
            current_median_bin = index
            break
    cumulative, reference_median_bin = 0.0, len(ref.bin_fractions) - 1
    for index, fraction in enumerate(ref.bin_fractions):
        cumulative += fraction
        if cumulative >= 0.5:
            reference_median_bin = index
            break
    return abs(current_median_bin - reference_median_bin) / max(1, len(current_counts) - 1)


@dataclass(frozen=True, slots=True)
class FeatureDrift:
    feature: str
    status: str
    psi: float | None
    quantile_shift: float | None
    samples: int

    def explain(self):
        return {'feature': self.feature, 'status': self.status,
                'psi': None if self.psi is None else round(self.psi, 4),
                'quantile_shift': None if self.quantile_shift is None else round(self.quantile_shift, 4),
                'samples': self.samples}


@dataclass(frozen=True, slots=True)
class DriftResult:
    status: str = INSUFFICIENT_DATA
    overall_score: float = 0.0
    window: str = ''
    sample_count: int = 0
    reference_version: str = 'none'
    reference_dataset: str = 'none'
    drifted_features: int = 0
    warning_features: int = 0
    per_feature: tuple[FeatureDrift, ...] = field(default_factory=tuple)
    reason: str = 'not evaluated'

    def explain(self, limit=12):
        ordered = sorted(self.per_feature, key=lambda f: (f.psi is None, -(f.psi or 0)))
        return {'status': self.status, 'overall_score': round(self.overall_score, 4), 'window': self.window,
                'sample_count': self.sample_count, 'reference_version': self.reference_version,
                'reference_dataset': self.reference_dataset, 'drifted_features': self.drifted_features,
                'warning_features': self.warning_features, 'reason': self.reason,
                'features': [f.explain() for f in ordered[:limit]]}


class DriftEngine:
    """Compares a bounded production snapshot against an immutable reference."""

    def __init__(self, reference, *, warning_threshold=PSI_WARNING, drifted_threshold=PSI_DRIFTED,
                 minimum_samples=MINIMUM_SAMPLES):
        self.reference = reference
        self.warning_threshold = warning_threshold
        self.drifted_threshold = drifted_threshold
        self.minimum_samples = minimum_samples

    def evaluate(self, snapshot):
        window = snapshot.get('window', '')
        samples = snapshot.get('sample_count', 0)
        if self.reference is None:
            return DriftResult(status=INSUFFICIENT_DATA, window=window, sample_count=samples,
                               reason='no reference distribution configured')
        base = {'window': window, 'sample_count': samples,
                'reference_version': self.reference.model_version,
                'reference_dataset': self.reference.dataset_version}
        if samples < self.minimum_samples:
            # Never call a quiet window "stable"; that would fabricate confidence.
            return DriftResult(status=INSUFFICIENT_DATA, **base,
                               reason=f'need {self.minimum_samples} samples, have {samples}')
        counts = snapshot.get('counts', {})
        per_feature, scored = [], []
        for name, ref in self.reference.features.items():
            if name.startswith('available_') or ref.constant:
                continue
            current = counts.get(name)
            if not current or sum(current) < self.minimum_samples:
                per_feature.append(FeatureDrift(name, INSUFFICIENT_DATA, None, None, sum(current or [])))
                continue
            value = psi(ref.bin_fractions, current)
            shift = quantile_shift(ref, current)
            if value is None:
                per_feature.append(FeatureDrift(name, INSUFFICIENT_DATA, None, shift, sum(current)))
                continue
            status = (DRIFTED if value >= self.drifted_threshold else
                      WARNING if value >= self.warning_threshold else STABLE)
            per_feature.append(FeatureDrift(name, status, value, shift, sum(current)))
            scored.append(value)
        if not scored:
            return DriftResult(status=INSUFFICIENT_DATA, **base, per_feature=tuple(per_feature),
                               reason='no feature had enough samples to compare')
        drifted = sum(1 for f in per_feature if f.status == DRIFTED)
        warning = sum(1 for f in per_feature if f.status == WARNING)
        # A weighted aggregate, not max(): one noisy low-value feature must not
        # permanently mark a model unusable, and one severe shift must not hide
        # inside an average of forty stable features.
        average = sum(scored) / len(scored)
        worst = sorted(scored, reverse=True)[:3]
        overall = 0.6 * average + 0.4 * (sum(worst) / len(worst))
        share = drifted / len(scored)
        status = (DRIFTED if overall >= self.drifted_threshold or share >= 0.25 else
                  WARNING if overall >= self.warning_threshold or drifted or warning >= 3 else STABLE)
        reason = {STABLE: 'production traffic matches the training distribution',
                  WARNING: 'some features have moved away from the training distribution',
                  DRIFTED: 'production traffic differs from the training distribution'}[status]
        return DriftResult(status=status, overall_score=overall, drifted_features=drifted,
                           warning_features=warning, per_feature=tuple(per_feature), reason=reason, **base)


@dataclass(frozen=True, slots=True)
class ModelHealth:
    state: str = UNAVAILABLE
    reasons: tuple[str, ...] = field(default_factory=tuple)
    model_version: str = 'none'
    drift_status: str = INSUFFICIENT_DATA
    ood_rate: float | None = None
    inference_failure_rate: float | None = None

    @property
    def allows_ml_enforcement(self):
        """Whether the classifier may still contribute to a strong automatic action.

        The mathematical engine is never disabled by this: an unhealthy model
        must reduce ML authority, not remove the deterministic defence.
        """
        return self.state == HEALTHY

    def explain(self):
        return {'state': self.state, 'model_version': self.model_version, 'reasons': list(self.reasons),
                'drift_status': self.drift_status,
                'ood_rate': None if self.ood_rate is None else round(self.ood_rate, 4),
                'inference_failure_rate': None if self.inference_failure_rate is None
                else round(self.inference_failure_rate, 5),
                'allows_ml_enforcement': self.allows_ml_enforcement,
                'note': 'the mathematical engine stays active in every state'}


def model_health(*, loaded, model_version='none', drift=None, ood_rate=None, inference_failure_rate=None,
                 ood_warning=0.30, ood_unreliable=0.60, failure_warning=0.01):
    """Combine model state, drift and population OOD into one health verdict."""
    if not loaded:
        return ModelHealth(state=UNAVAILABLE, reasons=('model not loaded',), model_version=model_version,
                           drift_status=drift.status if drift else INSUFFICIENT_DATA)
    reasons, state = [], HEALTHY
    if drift is not None and drift.status == DRIFTED:
        reasons.append('feature distribution has drifted')
        state = DEGRADED
    elif drift is not None and drift.status == WARNING:
        reasons.append('feature distribution is moving')
        state = DEGRADED
    if ood_rate is not None:
        if ood_rate >= ood_unreliable:
            reasons.append(f'{ood_rate:.0%} of recent observations are out of distribution')
            state = UNRELIABLE
        elif ood_rate >= ood_warning and state == HEALTHY:
            reasons.append(f'{ood_rate:.0%} of recent observations are out of distribution')
            state = DEGRADED
    if inference_failure_rate is not None and inference_failure_rate >= failure_warning:
        reasons.append('inference failures above threshold')
        state = UNRELIABLE if state == UNRELIABLE else DEGRADED
    if state == HEALTHY:
        reasons.append('model matches its training distribution')
    return ModelHealth(state=state, reasons=tuple(reasons), model_version=model_version,
                       drift_status=drift.status if drift else INSUFFICIENT_DATA,
                       ood_rate=ood_rate, inference_failure_rate=inference_failure_rate)
