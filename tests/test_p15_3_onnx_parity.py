"""ONNX parity that actually runs in a clean clone. §32.

`test_p8_onnx_parity.py` proves the same identity and skips everywhere, because
it reaches for the research dataset to get feature vectors and that dataset is
not distributed. P15.1 and P15.2 both reported runtime parity as `NOT_RUN` for
this reason — a check that never executes is a check the project does not have.

Parity does not need a dataset. It needs vectors and an answer to compare
against, and both fit in a committed file:
`tests/fixtures/p15_3/onnx_parity.json`, written by `training/parity_fixture.py`
from windowed aggregate counts with no address, port, payload, digest or
timestamp in them.

The fixture stores `native` — the ONNX graph's own coefficients applied in
float64 Python — alongside `onnx`, the runtime output. That is the part that
makes this a test rather than a tautology: a file holding only the runtime's
answer would agree with the runtime forever.

§33: none of this promotes the classifier. Parity is about implementation
consistency, and the classifier stays auxiliary whatever this reports.
"""
import json
from pathlib import Path
import unittest

from eye_for_an_eye.decision.features import (FeatureTransformer, FeatureVector, MODEL_SCHEMAS,
                                              SCHEMA_VERSION, upgrade)
from eye_for_an_eye.decision.math_risk import MathRiskEngine, VERSION as MATH_VERSION

FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'p15_3' / 'onnx_parity.json'
MODELS = Path(__file__).resolve().parent.parent / 'models'
#: The float32 graph against float64 Python. Anything larger than this is a
#: different computation, not rounding.
TOLERANCE = 1e-5


def fixture():
    return json.loads(FIXTURE.read_text(encoding='utf-8'))


def vector_of(row):
    """Rebuild the vector, lifting a fixture written under an older schema.

    `upgrade` appends explicit unknowns for columns that did not exist when the
    fixture was recorded. That is what keeps a committed parity fixture usable
    across a schema addition — and it is only sound because an appended column
    never changes what an existing one means.
    """
    return FeatureVector(upgrade(tuple(row['values'])), row['observation_seconds'],
                         row['sample_count'], False, 0.0)


class TestTheFixtureIsUsable(unittest.TestCase):

    def test_it_is_committed(self):
        self.assertTrue(FIXTURE.is_file(),
                        'the parity fixture is what lets this run in a clean clone')

    def test_it_declares_a_feature_schema_this_build_can_read(self):
        """A fixture records the schema it was written under, not today's.

        Pinning the current schema here would have made a committed parity
        fixture expire the moment a column was appended — which is the opposite
        of what a regression fixture is for. What must hold is that this build
        can still interpret it, and that its column list is that schema's.
        """
        body = fixture()
        declared = body['feature_schema_version']
        self.assertIn(declared, MODEL_SCHEMAS)
        self.assertLessEqual(declared, SCHEMA_VERSION)
        expected = [name for name in MODEL_SCHEMAS[declared] if not name.startswith('available_')]
        self.assertEqual(body['feature_names'], expected)

    def test_it_carries_no_identifying_data(self):
        """Counts and ratios only. Nothing here describes who did anything."""
        body = fixture()
        width = len(body['feature_names'])
        for row in body['rows']:
            self.assertEqual(set(row), {'values', 'observation_seconds', 'sample_count',
                                        'native', 'onnx', 'math_risk'})
            self.assertEqual(len(row['values']), width)

    def test_it_spans_the_score_range(self):
        """A fixture bunched at one end would pass while normalisation was broken."""
        scores = [row['onnx'] for row in fixture()['rows']]
        self.assertLess(min(scores), 0.1)
        self.assertGreater(max(scores), 0.9)

    def test_it_includes_windows_with_missing_values(self):
        rows = fixture()['rows']
        self.assertTrue(any(value is None for row in rows for value in row['values']),
                        'without a missing value the availability half of the '
                        'tensor is never exercised')


class TestRuntimeParity(unittest.TestCase):
    """The exported graph computes what the coefficients say it computes."""

    def test_onnx_matches_the_independent_recomputation(self):
        worst = 0.0
        for row in fixture()['rows']:
            worst = max(worst, abs(row['native'] - row['onnx']))
        self.assertLessEqual(worst, TOLERANCE, f'worst disagreement {worst}')

    def test_the_runtime_reproduces_the_recorded_scores(self):
        try:
            import onnxruntime  # noqa: F401
        except ImportError:
            self.skipTest('onnxruntime is not installed')
        from eye_for_an_eye.config import MLConfig
        from eye_for_an_eye.decision.onnx_model import OnnxRiskModel

        body = fixture()
        model = OnnxRiskModel()
        state = model.load(MLConfig(
            model_path=str(MODELS / (body['model_version'] + '.onnx')),
            manifest_path=str(MODELS / (body['model_version'] + '.json'))))
        if state['status'] != 'healthy':
            self.skipTest('the classifier artifact is not present: ' + str(state))
        worst = 0.0
        for row in body['rows']:
            tensor = list(FeatureTransformer.project(
                vector_of(row), state['feature_schema_version']))
            result = model.predict(tensor)
            self.assertEqual(result.status, 'healthy')
            worst = max(worst, abs(result.risk_score - row['onnx']))
        self.assertLessEqual(worst, TOLERANCE, f'worst drift from the fixture {worst}')


class TestTheDeterministicEngineIsAlsoPinned(unittest.TestCase):
    """No ONNX involved. This catches a feature-transform change on its own."""

    def test_math_risk_reproduces_the_recorded_scores(self):
        body = fixture()
        if body['math_risk_version'] != MATH_VERSION:
            self.skipTest(f'fixture records {body["math_risk_version"]}, '
                          f'the engine is {MATH_VERSION}; rebuild the fixture')
        engine = MathRiskEngine()
        worst = 0.0
        for row in body['rows']:
            score = engine.evaluate(vector_of(row)).score
            worst = max(worst, abs(score - row['math_risk']))
        self.assertLessEqual(worst, 1e-9, f'worst drift {worst}')

    def test_the_fixture_names_the_formula_it_was_built_from(self):
        """So a stale fixture skips loudly instead of asserting old arithmetic."""
        self.assertIn('math_risk_version', fixture())


if __name__ == '__main__':
    unittest.main()
