"""Trusted local ONNX artifacts, CPU-only sessions and a killable deadline boundary.

Only this module imports onnxruntime. No downloaded models or pickle artifacts.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import stat
import threading
import time
from .features import MODEL_SCHEMAS, SCHEMA_VERSION

#: The shape of the manifest beside an exported model: which keys it has and
#: what each means. Named rather than inlined because `compatibility.py` is
#: where a consumer asks whether a version is servable, and it cannot ask
#: about a number that only exists inside a dict literal.
MANIFEST_VERSION = 1

CLASSES = ['benign-like', 'malicious-automation-like']

#: Reasons this module raises itself, and the only exception text allowed to
#: reach an operator.
#:
#: Everything here refuses a model. Reporting only `type(exc).__name__` made all
#: twenty-odd of those refusals indistinguishable: an operator whose model would
#: not load saw the word `ValueError` and had no way to tell a corrupt file from
#: a hash mismatch from a permission problem. That is not a small inconvenience
#: for a defender whose classifier has silently stopped answering.
#:
#: The reason the class name was used alone is real, though, and is kept: an
#: arbitrary exception message may carry a filesystem path, and paths are not
#: for logs. So the rule is narrow -- text is passed through only when it is one
#: of this module's own fixed strings, none of which interpolates anything.
#: Anything raised by onnxruntime, json or the OS still reports its class only.
#: `tests/test_p13_integration.py` parses this file and fails if a new literal
#: raise is added without listing it here.
SAFE_REASONS = frozenset((
    'local regular artifact required', 'artifact size/type rejected',
    'artifact ownership/write permissions rejected', 'artifact grew beyond limit',
    'manifest object required', 'strict manifest version/shape types required',
    'manifest contract mismatch', 'invalid manifest version identifier',
    'manifest creation timestamp required', 'model SHA256 mismatch',
    'unsupported model graph', 'external/oversized tensor rejected',
    'unsupported ONNX operator', 'nested/external graph data rejected',
    'ONNX input/output mismatch', 'invalid bounded numeric tensor',
    'invalid model output', 'model stopped during startup', 'load deadline',
    'inference deadline', 'benchmark batch size must be 2..16',
    'baseline artifact rejected', 'invalid batch tensor', 'invalid batch output'))

#: Bound on what reaches a log line, so a reason can never become a payload.
MAX_REASON_CHARS = 120


def _reason(exc):
    """`ClassName: why` for our own refusals, bare `ClassName` for anything else."""
    name = type(exc).__name__
    text = str(exc)
    return f'{name}: {text}'[:MAX_REASON_CHARS] if text in SAFE_REASONS else name

OPS = frozenset(('LinearClassifier', 'TreeEnsembleClassifier', 'Cast', 'Identity', 'Normalizer',
    'MatMul', 'Add', 'Sub', 'Mul', 'Div', 'Sigmoid', 'Concat', 'Softmax', 'ArgMax', 'Constant', 'Reshape'))


@dataclass(frozen=True, slots=True)
class MLResult:
    status: str = 'unavailable'
    risk_score: float | None = None
    predicted_class: str | None = None
    confidence: float | None = None
    model_version: str = 'none'
    feature_schema_version: int = SCHEMA_VERSION
    inference_ms: float = 0.0
    error: str | None = None


def _read(path, limit):
    source = Path(path)
    if not path or str(path).startswith(('\\\\', '//')) or source.is_symlink():
        raise ValueError('local regular artifact required')
    with source.open('rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('artifact size/type rejected')
        if os.name == 'posix' and (info.st_mode & 0o022 or info.st_uid not in (0, os.geteuid())):
            raise ValueError('artifact ownership/write permissions rejected')
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError('artifact grew beyond limit')
    return content


def read_artifacts(config):
    manifest = json.loads(_read(config.manifest_path, 32768))
    if not isinstance(manifest, dict):
        raise ValueError('manifest object required')
    if (type(manifest.get('manifest_version')) is not int or type(manifest.get('feature_schema_version')) is not int or
            not isinstance(manifest.get('input_shape'), list) or any(type(v) is not int for v in manifest['input_shape'])):
        raise ValueError('strict manifest version/shape types required')
    declared = manifest['feature_schema_version']
    if declared not in MODEL_SCHEMAS:
        raise ValueError(f'unsupported model feature schema {declared}')
    order = list(MODEL_SCHEMAS[declared])
    expected = {'manifest_version': MANIFEST_VERSION, 'feature_schema_version': declared, 'feature_order': order,
        'input_name': 'features', 'input_shape': [1, len(order)], 'input_dtype': 'float32',
        'output_names': ['label', 'probabilities'], 'classes': CLASSES, 'score_semantics': 'uncalibrated_model_score'}
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise ValueError('manifest contract mismatch')
    for name in ('model_version', 'training_dataset_version'):
        if not isinstance(manifest.get(name), str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', manifest[name]):
            raise ValueError('invalid manifest version identifier')
    if not isinstance(manifest.get('created_at'), str) or len(manifest['created_at']) > 40:
        raise ValueError('manifest creation timestamp required')
    data = _read(config.model_path, config.max_model_bytes)
    if manifest.get('sha256') != hashlib.sha256(data).hexdigest():
        raise ValueError('model SHA256 mismatch')
    return manifest, data


class OnnxRiskModel:
    """Serialized CPU session. Production calls this only inside IsolatedModel's child."""
    def __init__(self):
        self.session = None
        self.manifest = {}
        self.error = None
        self.lock = threading.Lock()

    def load(self, config):
        with self.lock:
            self.session = None
            try:
                manifest, data = read_artifacts(config)
                import onnx
                import onnxruntime as ort
                ort.disable_telemetry_events()
                graph = onnx.load_model_from_string(data)
                if graph.functions or graph.graph.sparse_initializer or len(graph.graph.node) > 4096:
                    raise ValueError('unsupported model graph')
                for tensor in graph.graph.initializer:
                    if tensor.external_data or tensor.data_location or math.prod(tensor.dims) > 4_194_304:
                        raise ValueError('external/oversized tensor rejected')
                for node in graph.graph.node:
                    if node.domain not in ('', 'ai.onnx.ml') or node.op_type not in OPS:
                        raise ValueError('unsupported ONNX operator')
                    for attr in node.attribute:
                        if attr.type in (5, 10, 11, 12) or attr.t.external_data or attr.t.data_location:
                            raise ValueError('nested/external graph data rejected')
                onnx.checker.check_model(graph)
                options = ort.SessionOptions()
                options.intra_op_num_threads = options.inter_op_num_threads = 1
                options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
                options.add_session_config_entry('session.intra_op.allow_spinning', '0')
                options.log_severity_level = 3
                session = ort.InferenceSession(data, sess_options=options, providers=['CPUExecutionProvider'])
                inputs, outputs = session.get_inputs(), session.get_outputs()
                width = len(MODEL_SCHEMAS[manifest['feature_schema_version']])
                if (len(inputs) != 1 or inputs[0].name != 'features' or inputs[0].shape != [1, width] or
                        inputs[0].type != 'tensor(float)' or [o.name for o in outputs] != ['label', 'probabilities'] or
                        outputs[0].shape != [1] or outputs[0].type != 'tensor(int64)' or
                        outputs[1].shape != [1, 2] or outputs[1].type != 'tensor(float)'):
                    raise ValueError('ONNX input/output mismatch')
                self.session, self.manifest = session, manifest
                self._predict([0.0] * width)
                self.error = None
            except Exception as exc:
                self.session = None
                self.error = _reason(exc)
            return self.health()

    def _predict(self, tensor):
        import numpy as np
        if len(tensor) != len(MODEL_SCHEMAS[self.manifest['feature_schema_version']]) or any(
                type(v) not in (float, int) or not math.isfinite(v) or not 0 <= v <= 1 for v in tensor):
            raise ValueError('invalid bounded numeric tensor')
        start = time.perf_counter()
        label, scores = self.session.run(['label', 'probabilities'], {'features': np.asarray([tensor], dtype=np.float32)})
        if (label.shape != (1,) or scores.shape != (1, 2) or not np.isfinite(scores).all() or
                (scores < 0).any() or (scores > 1).any() or abs(float(scores.sum()) - 1) > .001 or
                int(label[0]) not in (0, 1)):
            raise ValueError('invalid model output')
        score = float(scores[0, 1])
        return MLResult('healthy', score, CLASSES[int(label[0])], max(score, 1 - score),
            self.manifest['model_version'], inference_ms=(time.perf_counter() - start) * 1000)

    def predict(self, tensor):
        with self.lock:
            try:
                if self.session is None:
                    return MLResult(error=self.error or 'not_loaded')
                result = self._predict(tensor)
                self.error = None
                return result
            except Exception as exc:
                self.error = _reason(exc)
                return MLResult('degraded', model_version=self.manifest.get('model_version', 'none'), error=self.error)

    def health(self):
        return {'status': 'unavailable' if self.session is None else 'degraded' if self.error else 'healthy',
            'model_version': self.manifest.get('model_version', 'none'),
            # The schema this artifact was fitted on, which is what a reader
            # needs in order to know which columns it actually saw. Reporting
            # the build's own schema here would have said "2" about a model
            # trained on 18 columns.
            'feature_schema_version': self.manifest.get('feature_schema_version', SCHEMA_VERSION),
            'loaded': self.session is not None, 'error': self.error}


def _serve(connection, config):
    """IPC carries bounded JSON numbers; no deserialization of network-controlled pickle."""
    try:
        model = OnnxRiskModel()
        connection.send_bytes(json.dumps(model.load(config)).encode())
        if model.session is None:
            return
        while True:
            tensor = json.loads(connection.recv_bytes(8192))
            connection.send_bytes(json.dumps(asdict(model.predict(tensor)), allow_nan=False).encode())
    except (EOFError, OSError, ValueError):
        pass
    finally:
        connection.close()


class IsolatedModel:
    """One process, one in-flight request, hard inference/startup deadlines, no auto restart loop."""
    def __init__(self, config):
        self.config = config
        self.process = self.connection = None
        self.state = {'status': 'unavailable', 'model_version': 'none', 'feature_schema_version': SCHEMA_VERSION, 'loaded': False}
        self.lock = threading.Lock()
        self.closing = threading.Event()

    def load(self):
        with self.lock:
            if self.closing.is_set() or not self.config.enabled or not self.config.model_path or not self.config.manifest_path:
                return self.health()
            context = multiprocessing.get_context('spawn')
            parent, child = context.Pipe()
            self.connection = parent
            self.process = context.Process(target=_serve, args=(child, self.config), daemon=True)
            try:
                self.process.start()
                child.close()
                if self.closing.is_set():
                    raise RuntimeError('model stopped during startup')
                if not parent.poll(self.config.startup_timeout_seconds):
                    raise TimeoutError('load deadline')
                self.state = json.loads(parent.recv_bytes(8192))
                if self.closing.is_set():
                    raise RuntimeError('model stopped during startup')
                if self.state['status'] != 'healthy':
                    self._stop()
            except Exception as exc:
                child.close()
                self._stop()
                self.state.update(status='unavailable', loaded=False, error=_reason(exc))
            return self.health()

    def predict(self, tensor):
        with self.lock:
            if not self.state.get('loaded'):
                return MLResult(error=self.state.get('error', 'not_loaded'))
            start = time.perf_counter()
            try:
                self.connection.send_bytes(json.dumps(tensor, allow_nan=False).encode())
                if not self.connection.poll(self.config.inference_timeout_ms / 1000):
                    raise TimeoutError('inference deadline')
                result = MLResult(**json.loads(self.connection.recv_bytes(8192)))
                self.state['status'] = result.status
                return result
            except Exception as exc:
                self._stop()
                self.state.update(status='degraded', loaded=False, error=_reason(exc))
                return MLResult('degraded', model_version=self.state['model_version'], error=_reason(exc),
                    inference_ms=(time.perf_counter() - start) * 1000)

    def health(self):
        return dict(self.state)

    def _stop(self):
        if self.process and self.process.pid is not None:
            if self.process.is_alive():
                self.process.terminate()
            self.process.join(.2)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(.2)
        if self.connection:
            self.connection.close()

    def close(self):
        self.closing.set()
        with self.lock:
            self._stop()
            self.state.update(status='unavailable', loaded=False)

    def abort(self):
        """Wake a blocking load/predict during shutdown; their EOF handler records failure."""
        self.closing.set()
        self._stop()


def benchmark_batch_runner(config, size):
    """Offline experiment only: clone a validated graph to fixed batch 2..16 in memory.

    Never exports or promotes this graph. Production's manifest remains strictly [1,N].
    """
    if type(size) is not int or not 2 <= size <= 16:
        raise ValueError('benchmark batch size must be 2..16')
    baseline = OnnxRiskModel()
    if baseline.load(config)['status'] != 'healthy':
        raise ValueError('baseline artifact rejected')
    import numpy as np
    import onnx
    import onnxruntime as ort
    ort.disable_telemetry_events()
    manifest, data = read_artifacts(config)
    width = len(MODEL_SCHEMAS[manifest['feature_schema_version']])
    graph = onnx.load_model_from_string(data)
    for tensor in (*graph.graph.input, *graph.graph.output):
        tensor.type.tensor_type.shape.dim[0].dim_value = size
    options = ort.SessionOptions()
    options.intra_op_num_threads = options.inter_op_num_threads = 1
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    options.add_session_config_entry('session.intra_op.allow_spinning', '0')
    options.log_severity_level = 3
    session = ort.InferenceSession(graph.SerializeToString(), sess_options=options, providers=['CPUExecutionProvider'])
    def predict(rows):
        if len(rows) != size or any(len(r) != width or
                any(type(v) not in (float, int) or not math.isfinite(v) or not 0 <= v <= 1 for v in r) for r in rows):
            raise ValueError('invalid batch tensor')
        label, scores = session.run(['label', 'probabilities'], {'features': np.asarray(rows, dtype=np.float32)})
        if (label.shape != (size,) or scores.shape != (size, 2) or not np.isfinite(scores).all() or
                (scores < 0).any() or (scores > 1).any() or not np.allclose(scores.sum(axis=1), 1, atol=.001)):
            raise ValueError('invalid batch output')
        return scores[:, 1].tolist()
    return predict
