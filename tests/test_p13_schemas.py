"""P13 §6, §8: the compatibility matrix stays true, and training matches runtime.

Two questions that only make sense about the whole system.

**§6.** Thirteen stages have left about forty version constants in this codebase.
A handful of them gate behaviour or are written to files that outlive the
process; most are labels on a report. Nobody can hold that distinction in their
head, so it is written down in `docs/SCHEMA_COMPATIBILITY.md` — and a document
like that is worth exactly as much as the mechanism that notices when it stops
being true. That mechanism is here: the source is read, every version constant
found, and each one checked against the matrix.

**§8.** The model is trained in float64 by scikit-learn and run in float32 by
onnxruntime, in a different process, through a different code path. Training and
runtime agreeing is not something to assume. The existing parity tests use the
research dataset, which is not distributed in the source archive, so they skip
for anyone who has only the repository — which is everyone doing a security
review. The parity check here uses the shipped model and synthetic inputs, so it
runs from a clean checkout.
"""
import ast
import math
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / 'docs' / 'SCHEMA_COMPATIBILITY.md'
MODELS = ROOT / 'models'

#: A module-level constant whose name claims to be a version of something.
VERSION_NAME = re.compile(r'^[A-Z][A-Z0-9_]*(?:SCHEMA_VERSION|_VERSION|VERSION)$')

#: Names that are not versions of a format: local variables of the loader, and
#: the token module's string constants describing a *verification outcome*.
NOT_A_FORMAT = frozenset(('UNKNOWN_VERSION',))

PACKAGES = ('eye_for_an_eye', 'dataset', 'training')


def declared_versions():
    """Every module-level `SOMETHING_VERSION = ...` in the three packages."""
    found = {}
    for package in PACKAGES:
        for path in sorted((ROOT / package).rglob('*.py')):
            if '__pycache__' in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'))
            module = path.relative_to(ROOT).with_suffix('').as_posix().replace('/', '.')
            for node in tree.body:
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if (isinstance(target, ast.Name)
                            and VERSION_NAME.match(target.id)
                            and target.id not in NOT_A_FORMAT):
                        found[f'{module}.{target.id}'] = target.id
    return found


class TestTheCompatibilityMatrixIsComplete(unittest.TestCase):
    """§6. A version constant nobody documented is a migration nobody planned."""

    @classmethod
    def setUpClass(cls):
        cls.matrix = MATRIX.read_text(encoding='utf-8')
        cls.versions = declared_versions()

    def test_the_matrix_exists_and_is_not_a_stub(self):
        self.assertGreater(len(self.matrix), 2000)

    def test_the_scan_found_a_believable_number_of_versions(self):
        """A regex that silently matches nothing would make every other test
        here pass for the wrong reason."""
        self.assertGreater(len(self.versions), 25, 'the scan found almost nothing')

    def test_every_version_constant_in_the_code_appears_in_the_matrix(self):
        for qualified, name in sorted(self.versions.items()):
            with self.subTest(constant=qualified):
                self.assertIn(name, self.matrix,
                              f'{qualified} is not in docs/SCHEMA_COMPATIBILITY.md. '
                              'If it gates behaviour or is written to a file that '
                              'outlives the process, it needs a stated answer to '
                              '"what happens when an old one is found".')

    def test_the_feature_schema_version_is_documented_with_its_width(self):
        """The mismatch that would be worst: right column count, wrong columns."""
        from eye_for_an_eye.decision.features import INPUT_ORDER, NAMES, SCHEMA_VERSION
        self.assertEqual(len(INPUT_ORDER), 2 * len(NAMES))
        self.assertIn(f'{len(INPUT_ORDER)} float32 columns', self.matrix)
        self.assertIn(f'{len(NAMES)} values + {len(NAMES)} availability flags', self.matrix)
        self.assertIn(f'`decision.features.SCHEMA_VERSION` | {SCHEMA_VERSION} |', self.matrix)

    def test_the_dataset_schema_documents_that_it_reads_both_versions(self):
        from dataset.schema import DATASET_SCHEMA_VERSION, READABLE_SCHEMA_VERSIONS
        self.assertEqual(DATASET_SCHEMA_VERSION, 2)
        self.assertEqual(tuple(READABLE_SCHEMA_VERSIONS), (1, 2))
        self.assertIn('READABLE_SCHEMA_VERSIONS = (1, 2)', self.matrix)

    def test_the_documented_values_match_the_code(self):
        """Numbers in a table rot faster than anything else in a document."""
        import importlib
        for qualified, name in sorted(self.versions.items()):
            module_name = qualified.rsplit('.', 1)[0]
            try:
                value = getattr(importlib.import_module(module_name), name)
            except Exception:                       # optional dependency, etc.
                continue
            if not isinstance(value, str) or not value:
                continue
            with self.subTest(constant=qualified, value=value):
                self.assertIn(value, self.matrix,
                              f'{qualified} is {value!r}, which the matrix does '
                              'not mention')


class TestTrainingAndRuntimeAgree(unittest.TestCase):
    """§8. float64 in scikit-learn, float32 in onnxruntime, another process.

    The shipped model is a logistic regression, so its exact output can be
    recomputed in Python from the coefficients in the graph. If the two disagree
    by more than rounding, every threshold chosen during evaluation describes a
    model that is not the one making decisions.
    """

    TOLERANCE = 1e-5

    def setUp(self):
        try:
            import onnxruntime  # noqa: F401
        except ImportError:
            self.skipTest('onnxruntime is in the optional `ml` extra')
        if not (MODELS / 'risk-logreg-v1.onnx').is_file():
            self.skipTest('the shipped model artifact is not present')

    def adapter(self):
        from eye_for_an_eye.config import MLConfig
        from eye_for_an_eye.decision.onnx_model import OnnxRiskModel
        model = OnnxRiskModel()
        state = model.load(MLConfig(model_path=str(MODELS / 'risk-logreg-v1.onnx'),
                                    manifest_path=str(MODELS / 'risk-logreg-v1.json')))
        if state['status'] != 'healthy':
            self.skipTest(f"the shipped model did not load: {state.get('error')}")
        return model

    def coefficients(self):
        from training.export_onnx import coefficients_from_onnx
        return coefficients_from_onnx(MODELS / 'risk-logreg-v1.onnx')

    def tensors(self):
        """Deterministic inputs spanning the space, including the corners."""
        # The shipped model declares feature schema 1, and this suite checks the
        # *model*, so the tensor width is the one that model was fitted on
        # rather than whichever schema this build now constructs.
        from eye_for_an_eye.decision.features import MODEL_SCHEMAS
        width = len(MODEL_SCHEMAS[1])
        yield [0.0] * width
        yield [1.0] * width
        yield [0.5] * width
        for index in range(0, width, 5):
            row = [0.25] * width
            row[index] = 1.0
            yield row
        for seed in range(12):
            yield [((seed * 37 + position * 17) % 101) / 100.0
                   for position in range(width)]

    def test_the_runtime_reproduces_a_float64_recomputation(self):
        from eye_for_an_eye.decision.features import MODEL_SCHEMAS
        adapter = self.adapter()
        weights, intercept = self.coefficients()
        # Against the schema the artifact declares. The claim being checked is
        # that the graph's columns are ones this build understands and can feed
        # — not that they are the columns this build happens to construct today.
        order = MODEL_SCHEMAS[adapter.health()['feature_schema_version']]
        self.assertEqual(list(weights), list(order),
                         'the graph names columns this build does not have')
        ordered = [weights[name] for name in order]
        worst = 0.0
        for tensor in self.tensors():
            result = adapter.predict(list(tensor))
            self.assertEqual(result.status, 'healthy')
            expected = 1 / (1 + math.exp(-(sum(c * v for c, v in
                                               zip(ordered, tensor, strict=True))
                                           + intercept)))
            worst = max(worst, abs(expected - result.risk_score))
        self.assertLessEqual(worst, self.TOLERANCE,
                             f'training and runtime disagree by {worst}')

    def test_a_column_the_model_must_ignore_changes_nothing(self):
        """Excluded features carry zero weight, and that is checked by moving
        them rather than by reading the coefficient."""
        from eye_for_an_eye.decision.features import MODEL_SCHEMAS
        from training import schema
        adapter = self.adapter()
        # The model's own schema throughout: its width, and the excluded columns
        # at the positions *it* puts them. Resolving the indices against the
        # build's schema would move them — which is the exact failure mode this
        # test exists to catch, so it must not be the one the test commits.
        order = MODEL_SCHEMAS[adapter.health()['feature_schema_version']]
        row = [0.3] * len(order)
        baseline = adapter.predict(list(row)).risk_score
        for index in [order.index(name) for name in schema.EXCLUDED_FEATURES if name in order]:
            changed = list(row)
            changed[index] = 1.0
            with self.subTest(column=index):
                self.assertEqual(adapter.predict(changed).risk_score, baseline)

    def test_the_manifest_feature_order_is_this_build_s_feature_order(self):
        """The mismatch with no symptom: same width, different meaning."""
        import json
        from eye_for_an_eye.decision.features import MODEL_SCHEMAS
        manifest = json.loads((MODELS / 'risk-logreg-v1.json').read_text(encoding='utf-8'))
        # The order the manifest claims must be exactly the order of the schema
        # it declares. Comparing against the build's current schema instead
        # would turn an appended column into a false alarm, and this alarm has to
        # keep meaning "same width, different meaning".
        declared = manifest['feature_schema_version']
        self.assertIn(declared, MODEL_SCHEMAS)
        self.assertEqual(list(manifest['feature_order']), list(MODEL_SCHEMAS[declared]))

    def test_the_shipped_model_is_honest_about_not_passing_its_gate(self):
        """§147. It is shipped in shadow, and its card says why."""
        import json
        card = json.loads((MODELS / 'risk-logreg-v1.json').read_text(encoding='utf-8'))
        if 'quality_gate_passed' not in card:
            self.skipTest('the evaluation record is in a separate artifact here')
        self.assertFalse(card['quality_gate_passed'])
        self.assertEqual(card.get('recommended_mode'), 'shadow')


if __name__ == '__main__':
    unittest.main()
