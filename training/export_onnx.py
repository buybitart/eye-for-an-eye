"""Explicit ONNX + manifest export. Never installs an active model."""
import hashlib
import json
from pathlib import Path
from eye_for_an_eye.decision.features import INPUT_ORDER, MODEL_SCHEMAS, SCHEMA_VERSION
from eye_for_an_eye.decision.onnx_model import CLASSES


def write_artifact(graph, directory, version, dataset_version, extra=None, *, deterministic_name=False):
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    graph.ir_version = min(graph.ir_version, 10)
    if deterministic_name:
        # Converters name the graph with a fresh UUID, which alone makes two identical models
        # hash differently. Fixing it lets an operator reproduce the artifact byte for byte.
        graph.graph.name = version
    data = graph.SerializeToString()
    manifest = {'manifest_version': 1, 'model_version': version, 'feature_schema_version': SCHEMA_VERSION,
        'feature_order': list(INPUT_ORDER), 'input_name': 'features', 'input_shape': [1, len(INPUT_ORDER)],
        'input_dtype': 'float32', 'output_names': ['label', 'probabilities'], 'classes': CLASSES,
        'score_semantics': 'uncalibrated_model_score', 'training_dataset_version': dataset_version,
        'created_at': '2026-09-08T00:00:00Z', 'sha256': hashlib.sha256(data).hexdigest()}
    # Extra documentation fields never override the strict production contract keys.
    manifest = {**(extra or {}), **manifest}
    if len(json.dumps(manifest).encode()) > 32768:
        raise ValueError('manifest exceeds the production reader limit')
    model, info = path / (version + '.onnx'), path / (version + '.json')
    if model.exists() or info.exists():
        raise FileExistsError('export requires new artifact names/directory')
    model.write_bytes(data)
    info.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return model, info


def export(classifier, directory, version, dataset_version, extra=None, *, deterministic_name=False):
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    graph = convert_sklearn(classifier, initial_types=[('features', FloatTensorType([1, len(INPUT_ORDER)]))],
        options={id(classifier): {'zipmap': False}}, target_opset={'': 17, 'ai.onnx.ml': 3})
    return write_artifact(graph, directory, version, dataset_version, extra, deterministic_name=deterministic_name)


def widen(model):
    """Re-place a subset-fitted linear model into the frozen [1,36] production contract.

    Excluded columns keep coefficient exactly 0, so the exported graph consumes the whole
    tensor the runtime already produces while the fitted model never saw those columns.
    """
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from .schema import MODEL_INDEX
    if model.coef_.shape != (1, len(MODEL_INDEX)):
        raise ValueError('expected one binary coefficient row over the model feature contract')
    full = LogisticRegression(**model.get_params())
    coefficients = np.zeros((1, len(INPUT_ORDER)), dtype=model.coef_.dtype)
    coefficients[0, list(MODEL_INDEX)] = model.coef_[0]
    full.classes_ = model.classes_.copy()
    full.coef_ = coefficients
    full.intercept_ = model.intercept_.copy()
    full.n_features_in_ = len(INPUT_ORDER)
    full.n_iter_ = getattr(model, 'n_iter_', None)
    return full


def tiny_fixture(directory, version='tiny-v1', *, nan=False):
    import onnx
    from onnx import helper as h, TensorProto as T
    size = len(INPUT_ORDER)
    weights = [0.0] * size
    weights[3] = 10.0
    graph = h.make_graph([
        h.make_node('MatMul', ['features', 'weights'], ['z']),
        h.make_node('Add', ['z', 'bias'], ['s']),
        h.make_node('Sigmoid', ['s'], ['risk']),
        h.make_node('Sub', ['one', 'risk'], ['benign']),
        h.make_node('Concat', ['benign', 'risk'], ['probabilities'], axis=1),
        h.make_node('ArgMax', ['probabilities'], ['label'], axis=1, keepdims=0),
    ], version, [h.make_tensor_value_info('features', T.FLOAT, [1, size])],
        [h.make_tensor_value_info('label', T.INT64, [1]), h.make_tensor_value_info('probabilities', T.FLOAT, [1, 2])],
        [h.make_tensor('weights', T.FLOAT, [size, 1], weights),
         h.make_tensor('bias', T.FLOAT, [1], [float('nan') if nan else -4.0]), h.make_tensor('one', T.FLOAT, [1], [1.0])])
    return write_artifact(onnx.helper.make_model(graph, opset_imports=[h.make_opsetid('', 17)]), directory, version, 'test-fixture-v1')


def finalize_manifest(manifest_path, updates):
    """Add measured documentation fields after export without touching the contract or the graph."""
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding='utf-8'))
    protected = ('manifest_version', 'model_version', 'feature_schema_version', 'feature_order', 'input_name',
                 'input_shape', 'input_dtype', 'output_names', 'classes', 'score_semantics',
                 'training_dataset_version', 'created_at', 'sha256')
    if set(updates) & set(protected):
        raise ValueError('contract fields are immutable after export')
    merged = {**manifest, **updates}
    if len(json.dumps(merged).encode()) > 32768:
        raise ValueError('manifest exceeds the production reader limit')
    if hashlib.sha256(Path(str(path).removesuffix('.json') + '.onnx').read_bytes()).hexdigest() != merged['sha256']:
        raise ValueError('model hash no longer matches its manifest')
    path.write_text(json.dumps(merged, indent=2) + '\n', encoding='utf-8')
    return merged


def coefficients_from_onnx(model_path):
    """Read the exported positive-class weights back out of the graph itself.

    Evaluation then describes the artifact that would actually run, not a fitted object
    that only existed during training.
    """
    import onnx
    graph = onnx.load(str(model_path))
    nodes = [node for node in graph.graph.node if node.op_type == 'LinearClassifier']
    if len(nodes) != 1:
        raise ValueError('expected exactly one LinearClassifier node')
    attributes = {attribute.name: attribute for attribute in nodes[0].attribute}
    weights = list(attributes['coefficients'].floats)
    intercepts = list(attributes['intercepts'].floats)
    # The graph's own width, not this build's. A model exported under an earlier
    # feature schema has fewer coefficients, and reading it against the current
    # schema would either refuse a perfectly valid artifact or — if the counts
    # happened to line up — pair weights with the wrong column names, which is
    # the silent failure this whole contract exists to prevent.
    if len(intercepts) != 2 or len(weights) % 2:
        raise ValueError('unexpected binary LinearClassifier layout')
    size = len(weights) // 2
    matches = [order for order in MODEL_SCHEMAS.values() if len(order) == size]
    if len(matches) != 1:
        raise ValueError(f'no single feature schema has {size} columns')
    return dict(zip(matches[0], weights[size:], strict=True)), float(intercepts[1])
