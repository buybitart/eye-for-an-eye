"""P8 unsupervised anomaly detection.

An anomaly is behaviour unlike the trusted baseline. **It is not an attack.**
A new backup job, a new monitoring probe or a new deployment are all anomalous
and all harmless. The score is one piece of evidence with a small weight; it can
never, on its own, reach a blocking decision.

That last sentence is a claim about arithmetic, so here is the arithmetic, in
`decision/policy.py`. `anomaly_weight` (0.10 by default) is **carved out of** the
maths+ML pool rather than added on top: the remaining weights are scaled by
`(pool - anomaly_weight) / pool` first, so total evidence with an anomaly model
present can never exceed what it would have been without one. A source with a
perfect anomaly score and nothing else therefore reaches 0.10 evidence. Then
`PolicyGuard` refuses ML-assisted enforcement whenever the deterministic score is
below `minimum_math_risk` (0.80). Two independent mechanisms, either one of which
is sufficient; a reader can check both without taking this docstring's word.

The artifact is ONNX, so the production runtime never unpickles a model. It is
loaded through the same hardened reader as the classifier: local regular file,
no symlink, no group- or world-writable permissions, size capped, SHA-256
checked against its manifest.
"""
from dataclasses import dataclass, field
import json
import math
import re
import time

from ..compatibility import FEATURE_SCHEMA, MODEL_MANIFEST
from .features import SCHEMA_VERSION
from .onnx_model import MODEL_SCHEMAS
from .onnx_model import _read as read_local_artifact

HEALTHY = 'healthy'
UNAVAILABLE = 'ANOMALY_MODEL_UNAVAILABLE'
DISABLED = 'disabled'
SKIPPED = 'skipped_budget'

MAX_MANIFEST_BYTES = 65_536
DEFAULT_MAX_MODEL_BYTES = 16_777_216
TOP_SIGNALS = 3


class AnomalyContractError(ValueError):
    """The anomaly artifact is missing, malformed or does not match this build."""


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    status: str = UNAVAILABLE
    anomaly_score: float | None = None
    raw_score: float | None = None
    model_version: str = 'none'
    feature_schema_version: int = SCHEMA_VERSION
    top_signals: tuple[str, ...] = field(default_factory=tuple)
    inference_ms: float = 0.0
    error: str | None = None

    @property
    def usable(self):
        return (self.status == HEALTHY and self.anomaly_score is not None
                and math.isfinite(self.anomaly_score) and 0.0 <= self.anomaly_score <= 1.0)

    def explain(self):
        return {'status': self.status,
                'anomaly_score': None if self.anomaly_score is None else round(self.anomaly_score, 4),
                'raw_score': None if self.raw_score is None else round(self.raw_score, 6),
                'model_version': self.model_version,
                'feature_schema_version': self.feature_schema_version,
                'top_signals': list(self.top_signals),
                'inference_ms': round(self.inference_ms, 3), 'error': self.error,
                'semantics': '0 = common in the trusted baseline, 1 = far outside it',
                'note': 'an anomaly is unusual behaviour, not evidence of an attack'}


def read_manifest(manifest_path, model_path, *, max_model_bytes=DEFAULT_MAX_MODEL_BYTES):
    """Strictly validate the anomaly manifest and its model, or refuse to load."""
    manifest = json.loads(read_local_artifact(manifest_path, MAX_MANIFEST_BYTES))
    if not isinstance(manifest, dict):
        raise AnomalyContractError('manifest object required')
    if not MODEL_MANIFEST.supports(manifest.get('manifest_version')):
        raise AnomalyContractError('unsupported anomaly manifest_version')
    if manifest.get('model_family') != 'isolation_forest':
        raise AnomalyContractError('unsupported anomaly model family')
    # Like the classifier, an anomaly model is validated against the schema it
    # declares rather than the one this build has. Its column list includes
    # availability flags, and those moved when P15.4 appended features — so
    # resolving them against the wrong schema would hand the model correct
    # numbers in the wrong slots, which yields confident nonsense instead of an
    # error.
    declared = manifest.get('feature_schema_version')
    if not FEATURE_SCHEMA.supports(declared):
        raise AnomalyContractError('anomaly model feature schema is not one this build can serve')
    order = MODEL_SCHEMAS[declared]
    version = manifest.get('model_version')
    if not isinstance(version, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', version or ''):
        raise AnomalyContractError('invalid anomaly model version identifier')
    columns = manifest.get('feature_names')
    if not isinstance(columns, list) or not columns or any(name not in order for name in columns):
        raise AnomalyContractError('anomaly feature_names must be known schema columns')
    if manifest.get('input_shape') != [1, len(columns)]:
        raise AnomalyContractError('anomaly input shape does not match its feature list')
    if manifest.get('input_dtype') != 'float32':
        raise AnomalyContractError('anomaly input dtype must be float32')
    spec = manifest.get('normalization')
    if not isinstance(spec, dict) or not all(k in spec for k in ('method', 'high', 'low')):
        raise AnomalyContractError('anomaly manifest must record its score normalisation')
    if not all(isinstance(spec[k], (int, float)) and math.isfinite(spec[k]) for k in ('high', 'low')):
        raise AnomalyContractError('non-finite normalisation anchors')
    if spec['high'] - spec['low'] <= 0:
        raise AnomalyContractError('normalisation anchors must be ordered')
    index = manifest.get('raw_score_output_index')
    if type(index) is not int or index < 0:
        raise AnomalyContractError('raw_score_output_index required')
    data = read_local_artifact(model_path, max_model_bytes)
    import hashlib
    if manifest.get('sha256') != hashlib.sha256(data).hexdigest():
        raise AnomalyContractError('anomaly model SHA256 mismatch')
    return manifest, data


def normalise(spec, raw):
    """Raw decision function to documented 0..1 semantics. Higher raw is more normal."""
    span = spec['high'] - spec['low']
    return min(1.0, max(0.0, (spec['high'] - float(raw)) / span))


class AnomalyModel:
    """Bounded in-process anomaly scoring with a safe fallback.

    Unlike the supervised classifier this runs in-process: its input is a float
    vector the sensor built itself, not attacker bytes. It is still bounded by a
    per-call time budget and a consecutive-failure breaker, and any failure
    degrades to ANOMALY_MODEL_UNAVAILABLE rather than raising.
    """

    def __init__(self, *, manifest_path='', model_path='', enabled=True,
                 timeout_ms=200.0, max_failures=5, max_model_bytes=DEFAULT_MAX_MODEL_BYTES):
        self.enabled = enabled
        self.manifest_path = manifest_path
        self.model_path = model_path
        self.timeout_ms = timeout_ms
        self.max_failures = max_failures
        self.max_model_bytes = max_model_bytes
        self.manifest = None
        self.session = None
        self.columns = ()
        self.positions = ()
        self.failures = 0
        self.load_error = None
        self.inferences = 0
        self.failed_inferences = 0

    @property
    def loaded(self):
        return self.session is not None

    def load(self):
        """Load the artifact. Never raises: an absent model is a supported state."""
        if not self.enabled or not (self.manifest_path and self.model_path):
            self.load_error = None if not self.enabled else 'no anomaly model configured'
            return False
        try:
            manifest, data = read_manifest(self.manifest_path, self.model_path,
                                           max_model_bytes=self.max_model_bytes)
            import onnxruntime
            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = 1
            options.inter_op_num_threads = 1
            session = onnxruntime.InferenceSession(data, options, providers=['CPUExecutionProvider'])
            columns = tuple(manifest['feature_names'])
            if session.get_inputs()[0].name != manifest.get('input_name'):
                raise AnomalyContractError('anomaly input name does not match the manifest')
            self.manifest, self.session, self.columns = manifest, session, columns
            order = MODEL_SCHEMAS[manifest['feature_schema_version']]
            self.positions = tuple(order.index(name) for name in columns)
            self.load_error = None
            return True
        except Exception as exc:  # a broken model must never stop the sensor
            self.session = None
            self.load_error = type(exc).__name__
            return False

    def close(self):
        self.session = None

    @property
    def feature_schema_version(self):
        """The schema this artifact was fitted on. Callers project to it."""
        return self.manifest['feature_schema_version'] if self.manifest else SCHEMA_VERSION

    def health(self):
        return {'status': HEALTHY if self.loaded else DISABLED if not self.enabled else UNAVAILABLE,
                'model_version': self.manifest['model_version'] if self.manifest else 'none',
                'feature_schema_version': self.feature_schema_version,
                'loaded': self.loaded, 'error': self.load_error,
                'inferences': self.inferences, 'failures': self.failed_inferences}

    def score(self, tensor):
        """Score one transformed feature tensor. Returns a result, never raises."""
        if not self.enabled:
            return AnomalyResult(status=DISABLED, error=None)
        if not self.loaded:
            return AnomalyResult(status=UNAVAILABLE, error=self.load_error or 'model not loaded')
        if self.failures >= self.max_failures:
            # Circuit breaker: stop paying for a model that keeps failing.
            return AnomalyResult(status=UNAVAILABLE, model_version=self.manifest['model_version'],
                                 error='disabled after repeated inference failures')
        started = time.perf_counter()
        try:
            import numpy
            row = [tensor[position] for position in self.positions]
            if any(value is None or not math.isfinite(float(value)) for value in row):
                return AnomalyResult(status=UNAVAILABLE, model_version=self.manifest['model_version'],
                                     error='non-finite feature value')
            batch = numpy.asarray([row], dtype=numpy.float32)
            outputs = self.session.run(None, {self.manifest['input_name']: batch})
            raw = float(numpy.asarray(outputs[self.manifest['raw_score_output_index']]).ravel()[0])
            if not math.isfinite(raw):
                raise ValueError('non-finite raw score')
            elapsed = (time.perf_counter() - started) * 1000.0
            self.failures = 0
            self.inferences += 1
            if elapsed > self.timeout_ms:
                # Over budget: record it and skip rather than let the hot path drift.
                return AnomalyResult(status=SKIPPED, model_version=self.manifest['model_version'],
                                     inference_ms=elapsed, error='inference exceeded the time budget')
            score = normalise(self.manifest['normalization'], raw)
            signals = self._top_signals(row)
            return AnomalyResult(status=HEALTHY, anomaly_score=score, raw_score=raw,
                                 model_version=self.manifest['model_version'],
                                 top_signals=signals, inference_ms=elapsed)
        except Exception as exc:
            self.failures += 1
            self.failed_inferences += 1
            return AnomalyResult(status=UNAVAILABLE,
                                 model_version=self.manifest['model_version'] if self.manifest else 'none',
                                 inference_ms=(time.perf_counter() - started) * 1000.0,
                                 error=type(exc).__name__)

    def _top_signals(self, row):
        """Largest feature values, as a hint only.

        An isolation forest does not attribute its score to features, so this is
        explicitly a hint about what stood out in the input, not an explanation
        of the model's decision.
        """
        # Availability flags are 1.0 whenever a value exists, so they would always
        # win a magnitude ranking while saying nothing. Rank behaviour only.
        behaviour = [(name, value) for name, value in zip(self.columns, row)
                     if not name.startswith('available_')]
        pairs = sorted(behaviour, key=lambda item: item[1], reverse=True)
        return tuple(name for name, value in pairs[:TOP_SIGNALS] if value > 0)
