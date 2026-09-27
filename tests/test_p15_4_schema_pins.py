"""No decision path may pin a feature schema to a literal. P15.4.

The P15.4 locked benchmark failed on one line:

    registry.record('feature_schema_compatible', inputs.feature_schema_version == 1, ...)

`AutonomousDecisionAuthority._assumptions` compared the schema to the integer 1,
and schema 2 had been in force since earlier in the same cycle. So the assumption
failed on every window of every source, `ASSUMPTION_FAILED` refused every block,
and the system could not act at all. Every other gate agreed the sources were
malicious — cost, margin, signal diversity, data quality, identity, model health,
observations, a conservative bound of 0.981951 against a cutoff of 0.975610 — and
889 of 889 qualifying windows were refused by an integer comparison.

What makes it worth a test file rather than a one-line fix is that this was the
**second** occurrence. `decision.policy.usable_ml` had the same literal, it was
found and fixed when schema 2 landed, and its docstring explains the reasoning
that should have been applied everywhere at once:

    "The schema check used to pin the literal 1, which stopped meaning 'a schema
    we understand' the moment a column was appended."

Its twin in `autonomy/authority.py` was missed. A bug that recurs in a second
place is a bug the codebase invites, so the guard here is textual and repository
wide: no module on the decision path may compare a feature schema to a literal
at all. That is a blunt rule, and blunt is what is wanted — the subtle version is
what let the second copy through.

The behavioural half of the file checks the consequence rather than the text,
because a comparison written some other way would pass the grep and still stop
the system dead.
"""
from pathlib import Path
import re
import tokenize
import unittest

from eye_for_an_eye.autonomy.authority import (AutonomousDecisionAuthority, DecisionGates)
from eye_for_an_eye.decision.features import MODEL_SCHEMAS, SCHEMA_VERSION
from eye_for_an_eye.decision.policy import usable_ml

REPOSITORY = Path(__file__).resolve().parents[1]


def _code_lines(path):
    """Executable lines only: comments and string literals removed.

    Scanning raw text was good enough while the pattern was narrow. Widened to
    catch `if schema != 1`, it also matches the docstring in
    `FeatureTransformer.project` that *quotes* that line while explaining why it
    is gone — so the file would fail for describing the defect it fixed. Dropping
    comments and strings through the tokenizer keeps the guard aimed at code, and
    keeps a module free to explain its own history.
    """
    lines = {}
    with path.open('rb') as stream:
        for token in tokenize.tokenize(stream.readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING, tokenize.NL,
                              tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
                continue
            if token.type == tokenize.FSTRING_START:
                continue
            row = token.start[0]
            lines.setdefault(row, []).append(token.string)
    return [' '.join(parts) for parts in lines.values()]

#: Modules whose decisions can stop a block. A literal schema comparison in any
#: of them is the defect this file exists for.
DECISION_PATH = (
    'eye_for_an_eye/autonomy/authority.py',
    'eye_for_an_eye/autonomy/record.py',
    'eye_for_an_eye/compatibility.py',
    'eye_for_an_eye/decision/policy.py',
    'eye_for_an_eye/decision/engine.py',
    'eye_for_an_eye/decision/features.py',
    'eye_for_an_eye/decision/onnx_model.py',
    'eye_for_an_eye/decision/anomaly.py',
    'eye_for_an_eye/decision/distribution.py',
)

#: `feature_schema_version == 1`, `schema_version != 2`, `schema != 1`, and every
#: spacing of them. Deliberately catches a comparison to the *current* schema
#: too: pinning 2 today is the same defect waiting for schema 3.
#:
#: P15.5 widened this. The original pattern required the word `schema_version`
#: and therefore missed `if schema != 1` in `FeatureTransformer.project` — the
#: identical defect, in the one function every model feed passes through, sitting
#: unnoticed while this file was being written to prevent it. A tripwire that
#: only catches the spelling of the bug already found is not a tripwire.
PINNED = re.compile(r'\w*schema\w*\s*[!=]=\s*\d')


class TestNoLiteralSchemaPinOnTheDecisionPath(unittest.TestCase):

    def test_no_decision_module_compares_a_schema_to_a_number(self):
        for relative in DECISION_PATH:
            path = REPOSITORY / relative
            with self.subTest(module=relative):
                self.assertTrue(path.is_file(), f'{relative} has moved; update this list')
                offenders = [line for line in _code_lines(path) if PINNED.search(line)]
                self.assertEqual(offenders, [],
                                 'compare against decision.features.MODEL_SCHEMAS instead: a '
                                 'literal stops meaning "a schema we understand" the moment a '
                                 'column is appended')

    def test_the_pattern_would_actually_catch_the_original_defect(self):
        """A guard nobody has seen fire is a guard nobody can trust."""
        self.assertTrue(PINNED.search('registry.record("x", inputs.feature_schema_version == 1)'))
        self.assertTrue(PINNED.search('if result.feature_schema_version != 2:'))
        self.assertTrue(PINNED.search('schema_version ==1'))
        self.assertIsNone(PINNED.search('inputs.feature_schema_version in MODEL_SCHEMAS'))
        self.assertIsNone(PINNED.search('FEATURE_SCHEMA.supports(inputs.feature_schema_version)'))

    def test_the_pattern_catches_the_spelling_p15_4_missed(self):
        """`if schema != 1` in `project`. Same defect, different words, and the
        reason the P15.4 pattern was too narrow to be worth trusting."""
        self.assertTrue(PINNED.search('        if schema != 1:'))
        self.assertTrue(PINNED.search('if declared_schema == 2:'))
        self.assertIsNone(PINNED.search('order = MODEL_SCHEMAS.get(schema)'))


class TestTheCurrentSchemaCanActuallyDecide(unittest.TestCase):
    """The consequence, checked directly. A comparison written some other way
    would pass the grep above and still refuse every block in production."""

    def test_the_schema_in_force_is_one_this_build_can_serve(self):
        self.assertIn(SCHEMA_VERSION, MODEL_SCHEMAS)

    def test_the_authority_accepts_the_schema_in_force(self):
        authority = AutonomousDecisionAuthority(gates=DecisionGates())
        for schema in sorted(MODEL_SCHEMAS):
            with self.subTest(schema=schema):
                registry = authority._assumptions(_inputs(schema))  # noqa: SLF001
                self.assertNotIn('feature_schema_compatible', registry.blocking_failures)

    def test_an_unservable_schema_is_still_refused(self):
        """The assumption must keep doing its job. Widening it to 'any integer'
        would have fixed the symptom and removed the check."""
        authority = AutonomousDecisionAuthority(gates=DecisionGates())
        unknown = max(MODEL_SCHEMAS) + 1
        registry = authority._assumptions(_inputs(unknown))  # noqa: SLF001
        self.assertIn('feature_schema_compatible', registry.blocking_failures,
                      'a schema this build cannot serve must not be assumed compatible; '
                      'widening the check to "any integer" would fix the symptom by '
                      'deleting the check')

    def test_the_classifier_gate_agrees_with_the_authority(self):
        """The two checks that disagreed. They are asked the same question here
        so a future divergence is a test failure rather than a silent one."""
        class Result:
            status = 'healthy'
            risk_score = 0.5
            confidence = 0.5

            def __init__(self, schema):
                self.feature_schema_version = schema

        for schema in sorted(MODEL_SCHEMAS):
            with self.subTest(schema=schema):
                self.assertTrue(usable_ml(Result(schema)))
        self.assertFalse(usable_ml(Result(max(MODEL_SCHEMAS) + 1)))


def _inputs(schema):
    """The smallest DecisionInputs that reaches the schema assumption."""
    from eye_for_an_eye.autonomy.authority import DecisionInputs
    return DecisionInputs(
        source='192.0.2.1', scope='GLOBAL',
        identity_confidence='HIGH', identity_origin='direct_peer',
        network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
        feature_schema_version=schema,
        observations=40, observation_seconds=120.0, data_quality=0.9,
        math_risk=0.8, math_version='math-risk-v4',
        calibrated=True, model_artifact_valid=True, features_finite=True,
        enforcement_healthy=True, clock_sane=True)


if __name__ == '__main__':
    unittest.main()
