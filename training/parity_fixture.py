"""Build the committable ONNX parity fixture. §32.

`tests/test_p8_onnx_parity.py` has always skipped in a clean clone, because it
needs the research dataset to get feature vectors and the research dataset is
not distributed. So the one check that proves the exported graph computes what
the trained model computes has never run anywhere except a machine that already
had the private data — which is the opposite of what a parity test is for.

The fix is small: parity does not need the dataset, it needs *vectors*. This
writes a fixture holding a spread of feature vectors together with the score
each path produces for them, and the test reads that instead.

### What is in it, and why it is safe to commit

Each row is 18 floats: counts, ratios and durations aggregated over a window —
how many ports, how many connection attempts, what fraction of probes repeated.
There is no address, no port number, no payload, no digest and no timestamp, so
there is nothing to sanitise and nothing to leak. The rows are drawn from the
synthetic development corpus, quantised, and de-duplicated, and each is stored
beside the score three independent computations give for it:

* `native` — the coefficients read out of the ONNX graph, applied in float64
  Python. This is the arithmetic the model *means*.
* `onnx` — `OnnxRiskModel.predict`, the runtime path.
* `math_risk` — the deterministic engine, which has no ONNX involvement at all
  and is here so a change to the feature transform is caught even when the
  classifier is absent.

A fixture that stored only the ONNX output would agree with itself forever.
Storing the independent recomputation is what makes disagreement possible, which
is the only thing that makes the test worth running.

### What this does not do

§33. Parity proves the implementation is consistent. It says nothing about
whether the model is any good, and the classifier stays auxiliary regardless of
how green this is.
"""
import json
import math
from pathlib import Path

from eye_for_an_eye.decision.features import (FeatureTransformer, FeatureVector, INPUT_ORDER,
                                             NAMES, SCHEMA_VERSION)
from eye_for_an_eye.decision.math_risk import MathRiskEngine, VERSION as MATH_VERSION

PARITY_FIXTURE_VERSION = 1
FIXTURE = Path('tests/fixtures/p15_3/onnx_parity.json')
#: Enough rows to cover the range without making the file large. Parity is an
#: arithmetic identity: it either holds everywhere or it is broken, and a
#: thousand rows would not prove it harder than sixty.
ROWS = 60
PLACES = 6


def _quantise(values):
    """Round, and keep `None` as `None`.

    A missing value is not zero and the transform does not treat it as zero — it
    sets the availability flag instead. A fixture that flattened missing to zero
    would test the wrong half of the 36-column tensor, so the rows carry `null`
    and the test rebuilds the vector with it.
    """
    return [None if value is None else round(float(value), PLACES) for value in values]


def _spread(rows, count):
    """A deterministic spread across the score range, not the first N rows.

    Taking the head of a corpus would sample one scenario family. Sorting by
    score and stepping through it covers the whole range, including the ends,
    where a normalisation mistake shows up first.
    """
    ordered = sorted(rows, key=lambda row: row[1])
    if len(ordered) <= count:
        return ordered
    step = (len(ordered) - 1) / (count - 1)
    return [ordered[min(len(ordered) - 1, round(index * step))] for index in range(count)]


def build(role='development', root='datasets', models=Path('models'), version='risk-logreg-v1'):
    from training import evaluation_design as design
    from training.export_onnx import coefficients_from_onnx

    engine = MathRiskEngine()
    seen, candidates = set(), []
    for sample in design.load_role(role, root):
        vector = sample.features
        key = tuple(_quantise(vector.values))
        if key in seen:
            continue
        seen.add(key)
        candidates.append((sample, engine.evaluate(vector).score))
    chosen = _spread(candidates, ROWS)

    weights, intercept = coefficients_from_onnx(Path(models) / (version + '.onnx'))
    ordered = [weights[name] for name in INPUT_ORDER]

    from eye_for_an_eye.config import MLConfig
    from eye_for_an_eye.decision.onnx_model import OnnxRiskModel
    model = OnnxRiskModel()
    state = model.load(MLConfig(model_path=str(Path(models) / (version + '.onnx')),
                                manifest_path=str(Path(models) / (version + '.json'))))
    if state['status'] != 'healthy':
        raise RuntimeError('the classifier did not load: ' + str(state))

    rows = []
    for sample, _ in chosen:
        # Recompute from the *quantised* vector, not the original. The file
        # stores rounded values, so a score computed before rounding would be a
        # score the fixture cannot reproduce — a self-inconsistency that reads
        # as parity drift the first time anybody checks.
        source = sample.features
        values = _quantise(source.values)
        vector = FeatureVector(tuple(values), source.observation_seconds,
                               source.sample_count, False, 0.0)
        tensor = list(FeatureTransformer.transform(vector))
        native = 1 / (1 + math.exp(-(sum(c * v for c, v in zip(ordered, tensor, strict=True))
                                     + intercept)))
        predicted = model.predict(list(tensor))
        if predicted.status != 'healthy':
            raise RuntimeError('the classifier refused a fixture row: ' + predicted.status)
        rows.append({
            'values': values,
            'observation_seconds': round(float(vector.observation_seconds), 3),
            'sample_count': int(vector.sample_count),
            'native': round(native, 9),
            'onnx': round(float(predicted.risk_score), 9),
            'math_risk': round(float(engine.evaluate(vector).score), 9),
        })

    return {
        'parity_fixture_version': PARITY_FIXTURE_VERSION,
        'feature_schema_version': SCHEMA_VERSION,
        'feature_names': list(NAMES),
        'model_version': version,
        'math_risk_version': MATH_VERSION,
        'rows': rows,
        'contents': ('windowed aggregate counts, ratios and durations from the '
                     'synthetic development corpus. No address, port, payload, '
                     'digest or timestamp appears here, and no row is traceable '
                     'to a source'),
        'note': ('`native` is the ONNX graph-s own coefficients applied in '
                 'float64 Python, computed independently of `onnx`. A fixture '
                 'storing only the runtime output would agree with itself '
                 'forever'),
    }


def write(path=FIXTURE, **kwargs):
    body = build(**kwargs)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return target
