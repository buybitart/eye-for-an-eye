"""P8 reference and production distributions.

The reference distribution is the training baseline a model was fitted on. It is
immutable, model-scoped and validated before use: a model never runs against
another model's baseline.

The production distribution is a bounded rolling summary of what the sensor sees
now. It stores counts in the reference's own fixed bins, so memory is
O(features x bins x window slices) and never grows with traffic.

Both live in the transformed feature space (0..1), which is what the model sees.
"""
from collections import deque
from dataclasses import dataclass
import json
import math
import time

from .features import INPUT_ORDER, NAMES
from .onnx_model import MODEL_SCHEMAS
from .onnx_model import _read as read_local_artifact

DISTRIBUTION_VERSION = 1
MAX_DISTRIBUTION_BYTES = 4_194_304
QUANTILES = ('p01', 'p05', 'p25', 'p50', 'p75', 'p95', 'p99')
REQUIRED_STATS = ('count', 'missing_rate', 'min', 'max', 'mean', 'std', *QUANTILES)


class DistributionError(ValueError):
    """The reference distribution is missing, malformed or belongs to another model."""


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


@dataclass(frozen=True, slots=True)
class FeatureReference:
    """Immutable per-feature training statistics."""
    name: str
    count: int
    missing_rate: float
    minimum: float
    maximum: float
    mean: float
    std: float
    quantiles: dict[str, float]
    bin_edges: tuple[float, ...]
    bin_fractions: tuple[float, ...]
    constant: bool
    nearly_constant: bool

    @property
    def spread(self):
        """Robust spread. Falls back to the full range, then to a small epsilon."""
        inter_quartile = self.quantiles['p75'] - self.quantiles['p25']
        if inter_quartile > 1e-9:
            return inter_quartile
        full = self.maximum - self.minimum
        return full if full > 1e-9 else 1e-9


@dataclass(frozen=True, slots=True)
class ReferenceDistribution:
    model_version: str
    dataset_version: str
    feature_schema_version: int
    created_at: str
    sample_count: int
    value_space: str
    features: dict[str, FeatureReference]
    source_path: str = ''

    def feature(self, name):
        return self.features.get(name)

    def describe(self):
        return {'model_version': self.model_version, 'dataset_version': self.dataset_version,
                'feature_schema_version': self.feature_schema_version, 'created_at': self.created_at,
                'sample_count': self.sample_count, 'features': len(self.features),
                'value_space': self.value_space}


def _feature_reference(name, payload):
    for key in REQUIRED_STATS:
        if key not in payload or not _finite(payload[key]):
            raise DistributionError(f'{name}: missing or non-finite {key}')
    edges = payload.get('bin_edges') or []
    fractions = payload.get('bin_fractions') or []
    if len(edges) != len(fractions) + 1 or not fractions:
        raise DistributionError(f'{name}: bin_edges must be one longer than bin_fractions')
    constant = bool(payload.get('constant', False))
    if len(fractions) < 2 and not constant:
        raise DistributionError(f'{name}: a varying feature needs at least two bins')
    if not all(_finite(v) for v in (*edges, *fractions)):
        raise DistributionError(f'{name}: non-finite bin values')
    if any(b < a for a, b in zip(edges, edges[1:])):
        raise DistributionError(f'{name}: bin edges must not decrease')
    total = sum(fractions)
    if not 0.99 <= total <= 1.01:
        raise DistributionError(f'{name}: bin fractions must sum to 1, got {total}')
    return FeatureReference(name=name, count=int(payload['count']), missing_rate=float(payload['missing_rate']),
        minimum=float(payload['min']), maximum=float(payload['max']), mean=float(payload['mean']),
        std=float(payload['std']), quantiles={q: float(payload[q]) for q in QUANTILES},
        bin_edges=tuple(float(v) for v in edges), bin_fractions=tuple(float(v) for v in fractions),
        constant=constant, nearly_constant=bool(payload.get('nearly_constant', False)))


def load_reference(path, *, expected_model_version=None):
    """Read and strictly validate a reference distribution.

    A distribution is bound to one model. Loading it for a different model is an
    error, never a silent fallback: a stale baseline would quietly mis-measure
    every out-of-distribution check made against it.
    """
    payload = json.loads(read_local_artifact(path, MAX_DISTRIBUTION_BYTES))
    if not isinstance(payload, dict):
        raise DistributionError('distribution object required')
    if payload.get('distribution_version') != DISTRIBUTION_VERSION:
        raise DistributionError('unsupported distribution_version')
    # A reference distribution describes the columns it was built from and is
    # validated against the schema it declares. P15.4 appended features; a
    # reference built before that still describes its own columns correctly and
    # simply holds no opinion about the new ones. Silence about a column nobody
    # measured is the right answer — an OOD verdict invented for it would not be.
    declared = payload.get('feature_schema_version')
    if declared not in MODEL_SCHEMAS:
        raise DistributionError('distribution feature schema is not one this build can serve')
    for key in ('model_version', 'dataset_version', 'created_at', 'value_space'):
        if not isinstance(payload.get(key), str) or not payload[key]:
            raise DistributionError(f'missing {key}')
    if payload['value_space'] != 'transformed':
        raise DistributionError('only transformed-space distributions are supported')
    if expected_model_version is not None and payload['model_version'] != expected_model_version:
        raise DistributionError(
            f'distribution belongs to {payload["model_version"]!r}, model is {expected_model_version!r}')
    if type(payload.get('sample_count')) is not int or payload['sample_count'] <= 0:
        raise DistributionError('sample_count must be a positive integer')
    raw = payload.get('features')
    if not isinstance(raw, dict) or not raw:
        raise DistributionError('features object required')
    unknown = set(raw) - set(MODEL_SCHEMAS[declared])
    if unknown:
        raise DistributionError(f'unknown features in distribution: {sorted(unknown)[:4]}')
    features = {name: _feature_reference(name, value) for name, value in raw.items()}
    return ReferenceDistribution(model_version=payload['model_version'], dataset_version=payload['dataset_version'],
        feature_schema_version=payload['feature_schema_version'], created_at=payload['created_at'],
        sample_count=payload['sample_count'], value_space=payload['value_space'], features=features,
        source_path=str(path))


class WindowedHistogram:
    """Fixed-memory counts over a rolling time window.

    The window is split into equal slices. Each slice holds one integer per bin.
    Expiry drops whole slices, so nothing is ever re-scanned and memory is
    constant regardless of traffic volume.
    """

    __slots__ = ('bins', 'slice_seconds', 'slices', '_buckets')

    def __init__(self, bins, slice_seconds, slices):
        if bins < 1 or slice_seconds <= 0 or slices < 1:
            raise ValueError('invalid histogram geometry')
        self.bins, self.slice_seconds, self.slices = bins, slice_seconds, slices
        self._buckets = deque()

    def _expire(self, now):
        oldest = now - self.slice_seconds * self.slices
        while self._buckets and self._buckets[0][0] <= oldest:
            self._buckets.popleft()

    def add(self, index, now):
        if not 0 <= index < self.bins:
            raise ValueError('bin index out of range')
        slot = math.floor(now / self.slice_seconds) * self.slice_seconds
        self._expire(now)
        if not self._buckets or self._buckets[-1][0] != slot:
            if self._buckets and self._buckets[-1][0] > slot:
                return  # out-of-order sample older than the newest slice; drop it
            self._buckets.append((slot, [0] * self.bins))
            while len(self._buckets) > self.slices:
                self._buckets.popleft()
        self._buckets[-1][1][index] += 1

    def counts(self, now):
        self._expire(now)
        totals = [0] * self.bins
        for _, bucket in self._buckets:
            for i, value in enumerate(bucket):
                totals[i] += value
        return totals

    def total(self, now):
        return sum(self.counts(now))


class RollingDistribution:
    """Bounded production feature distribution, binned against a reference.

    Only the hot path runs here: one bin lookup per feature per decision. Full
    drift evaluation is periodic and reads these counts.
    """

    def __init__(self, reference, windows=(('1h', 300.0, 12), ('24h', 3600.0, 24), ('7d', 86400.0, 7)),
                 clock=time.time):
        self.reference = reference
        self.clock = clock
        self.window_names = tuple(name for name, _, _ in windows)
        self._missing = {name: 0 for name in self.window_names}
        self._observed = {name: 0 for name in self.window_names}
        self._histograms = {
            window: {feature: WindowedHistogram(len(ref.bin_fractions), slice_seconds, slices)
                     for feature, ref in reference.features.items()}
            for window, slice_seconds, slices in windows}
        self._geometry = {name: (slice_seconds, slices) for name, slice_seconds, slices in windows}

    @staticmethod
    def bin_index(ref, value):
        """Place a value in the reference's own fixed bins. Tails clamp to the edges."""
        edges = ref.bin_edges
        if value <= edges[0]:
            return 0
        if value >= edges[-1]:
            return len(edges) - 2
        low, high = 0, len(edges) - 1
        while low < high - 1:
            middle = (low + high) // 2
            if value < edges[middle]:
                high = middle
            else:
                low = middle
        return min(low, len(edges) - 2)

    def observe(self, values):
        """Record one transformed feature mapping. Missing values are counted, not binned."""
        now = self.clock()
        for window in self.window_names:
            self._observed[window] += 1
        for feature, ref in self.reference.features.items():
            value = values.get(feature)
            if value is None or not _finite(value):
                for window in self.window_names:
                    self._missing[window] += 1
                continue
            index = self.bin_index(ref, float(value))
            for window in self.window_names:
                self._histograms[window][feature].add(index, now)

    def snapshot(self, window):
        if window not in self.window_names:
            raise ValueError(f'unknown window {window!r}')
        now = self.clock()
        histograms = self._histograms[window]
        counts = {feature: histogram.counts(now) for feature, histogram in histograms.items()}
        samples = max((sum(values) for values in counts.values()), default=0)
        return {'window': window, 'sample_count': samples, 'counts': counts,
                'reference_model_version': self.reference.model_version,
                'reference_dataset_version': self.reference.dataset_version}

    def describe(self):
        return {'windows': list(self.window_names),
                'geometry': {name: {'slice_seconds': s, 'slices': n} for name, (s, n) in self._geometry.items()},
                'features': len(self.reference.features),
                'bounded_cells': sum(len(self.reference.features) * n for _, n in self._geometry.values())
                                 * len(next(iter(self.reference.features.values())).bin_fractions)}


def transformed_values(vector):
    """Map a FeatureVector to the transformed name -> value space, keeping missing as None."""
    from .features import FeatureTransformer
    tensor = FeatureTransformer.transform(vector)
    values = dict(zip(INPUT_ORDER, tensor))
    for index, name in enumerate(NAMES):
        if vector.values[index] is None:
            values[name] = None
    return values
