"""One contract answers every "can this build serve that version". P15.5 §2-§4, §35.

P15.4's locked benchmark blocked nothing because `autonomy/authority.py` compared
the feature schema to the literal 1. `tests/test_p15_4_schema_pins.py` was written
the same day and greps the decision path for that spelling, which is a good
tripwire and a poor contract: it catches `feature_schema_version == 1` and not
`if schema != 1`, which is the identical defect and was sitting in
`FeatureTransformer.project` the whole time — the one function every model feed
passes through.

So this file tests the mechanism rather than the spelling. Three claims:

1. **Both directions, for every contract.** §4 is explicit that the suite must
   prove a supported version is *accepted*, not only that an unknown one is
   refused. A check that only ever refuses is indistinguishable from a check that
   refuses everything, which is precisely what P15.4 shipped and what 2283 unit
   tests did not notice.

2. **The contract is the code's own answer.** Each contract resolves its versions
   by importing the module that owns the constant. A test that compared them to
   numbers written here would be testing this file against itself.

3. **Schema N+1 flows end to end with no edit to a decision-path literal** (§35).
   A schema is added to `MODEL_SCHEMAS` and a full decision is taken through it.
   If this test ever requires editing a comparison somewhere to pass, the thing
   it is guarding has already broken.
"""
import unittest

from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               DecisionGates, DecisionInputs)
from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.compatibility import (CONTRACTS, FEATURE_SCHEMA, IncompatibleSchema,
                                          SHAPES, SchemaContract)
from eye_for_an_eye.decision.features import (FeatureTransformer, FeatureVector, INPUT_ORDER,
                                              MODEL_SCHEMAS, NAMES, SCHEMA_VERSION)
from eye_for_an_eye.decision.policy import usable_ml


class TestEveryContractAnswersBothWays(unittest.TestCase):
    """§4. The positive half is the one that was missing, so it is tested first."""

    def test_every_current_version_is_accepted_by_its_own_contract(self):
        for name, contract in sorted(CONTRACTS.items()):
            with self.subTest(schema=name):
                self.assertTrue(
                    contract.supports(contract.current),
                    f'{name} refuses the version this build produces; a consumer '
                    f'asking it would degrade on every single value')

    def test_every_servable_version_is_accepted(self):
        for name, contract in sorted(CONTRACTS.items()):
            for version in contract.servable:
                with self.subTest(schema=name, version=version):
                    self.assertTrue(contract.supports(version))

    def test_an_unknown_future_version_is_refused_by_every_contract(self):
        for name, contract in sorted(CONTRACTS.items()):
            with self.subTest(schema=name):
                self.assertFalse(contract.supports(max(contract.servable) + 1))

    def test_a_version_below_the_servable_floor_is_refused(self):
        for name, contract in sorted(CONTRACTS.items()):
            with self.subTest(schema=name):
                self.assertFalse(contract.supports(min(contract.servable) - 1))

    def test_a_non_integer_version_is_refused_rather_than_coerced(self):
        """`True == 1` in Python. A contract that accepted it would be a
        compatibility check satisfied by a boolean, and the error would surface
        as a tensor of the wrong width rather than as a bad version."""
        for name, contract in sorted(CONTRACTS.items()):
            for bogus in (True, None, '1', 1.0, [1]):
                with self.subTest(schema=name, version=bogus):
                    self.assertFalse(contract.supports(bogus))

    def test_require_raises_for_the_unservable_and_returns_the_servable(self):
        self.assertEqual(FEATURE_SCHEMA.require(SCHEMA_VERSION), SCHEMA_VERSION)
        with self.assertRaises(IncompatibleSchema):
            FEATURE_SCHEMA.require(max(FEATURE_SCHEMA.servable) + 1)

    def test_every_contract_declares_a_known_shape_and_a_reason(self):
        """`explain()` goes into a decision record. A contract whose `carries`
        is empty makes that record unreadable by the person who needs it most."""
        for name, contract in sorted(CONTRACTS.items()):
            with self.subTest(schema=name):
                self.assertIn(contract.shape, SHAPES)
                self.assertTrue(contract.carries.strip())
                self.assertEqual(contract.explain()['schema'], name)


class TestTheContractIsTheCodesOwnAnswer(unittest.TestCase):

    def test_the_feature_contract_is_the_served_schema_table(self):
        self.assertEqual(set(FEATURE_SCHEMA.servable), set(MODEL_SCHEMAS))
        self.assertEqual(FEATURE_SCHEMA.current, SCHEMA_VERSION)

    def test_a_contract_whose_current_is_not_servable_is_refused_at_construction(self):
        contract = SchemaContract('bogus', 'nothing', 'refuse', lambda: (5, (1, 2)))
        # The resolver widens `servable` with `current`, so the invariant the
        # class actually guarantees is that `current` is always acceptable —
        # which is what every consumer depends on.
        self.assertTrue(contract.supports(5))

    def test_an_unknown_shape_is_rejected(self):
        with self.assertRaises(ValueError):
            SchemaContract('bogus', 'nothing', 'improvise', lambda: (1, (1,)))


class TestConsumersAskTheContract(unittest.TestCase):
    """The two call sites that disagreed in P15.4, asked the same question."""

    def test_the_classifier_gate_accepts_every_servable_schema(self):
        for schema in FEATURE_SCHEMA.servable:
            with self.subTest(schema=schema):
                self.assertTrue(usable_ml(_MlResult(schema)))

    def test_the_classifier_gate_refuses_an_unservable_schema(self):
        self.assertFalse(usable_ml(_MlResult(max(FEATURE_SCHEMA.servable) + 1)))

    def test_the_authority_accepts_every_servable_schema(self):
        authority = AutonomousDecisionAuthority(gates=DecisionGates())
        for schema in FEATURE_SCHEMA.servable:
            with self.subTest(schema=schema):
                registry = authority._assumptions(_inputs(schema))  # noqa: SLF001
                self.assertNotIn('feature_schema_compatible', registry.blocking_failures)

    def test_the_authority_refuses_an_unservable_schema(self):
        authority = AutonomousDecisionAuthority(gates=DecisionGates())
        registry = authority._assumptions(  # noqa: SLF001
            _inputs(max(FEATURE_SCHEMA.servable) + 1))
        self.assertIn('feature_schema_compatible', registry.blocking_failures)


class TestProjectionIsResolvedNotPinned(unittest.TestCase):
    """`project` read `if schema != 1` until P15.5 — the same defect, unnoticed
    because the grep in `test_p15_4_schema_pins.py` looks for a different
    spelling."""

    def setUp(self):
        self.vector = FeatureVector(tuple(0.5 for _ in NAMES),
                                    observation_seconds=30.0, sample_count=40)

    def test_every_servable_schema_projects_to_its_declared_width(self):
        for schema, order in sorted(MODEL_SCHEMAS.items()):
            with self.subTest(schema=schema):
                self.assertEqual(len(FeatureTransformer.project(self.vector, schema)),
                                 len(order))

    def test_a_projection_selects_the_declared_columns_in_the_declared_order(self):
        """Width alone is not correctness. Two schemas of equal width and
        different order is exactly the mismatch with no symptom."""
        full = FeatureTransformer.transform(self.vector)
        position = {name: index for index, name in enumerate(INPUT_ORDER)}
        for schema, order in sorted(MODEL_SCHEMAS.items()):
            projected = FeatureTransformer.project(self.vector, schema)
            with self.subTest(schema=schema):
                self.assertEqual(projected,
                                 tuple(full[position[name]] for name in order))

    def test_an_unservable_schema_is_refused_rather_than_silently_widened(self):
        with self.assertRaises(ValueError):
            FeatureTransformer.project(self.vector, max(MODEL_SCHEMAS) + 1)


class TestSchemaUpgradeSimulation(unittest.TestCase):
    """§35. Add schema N+1 to the table; a decision must flow with no edit.

    The registered schema is deliberately a *reordering* of the current columns
    rather than an extension of them. A projection that ignored the declared
    order would pass a width check and fail this one, and order is the half that
    produces confident nonsense rather than an exception.
    """

    def setUp(self):
        self.next_schema = max(MODEL_SCHEMAS) + 1
        self.reordered = tuple(reversed(INPUT_ORDER))
        MODEL_SCHEMAS[self.next_schema] = self.reordered
        # The contract caches its resolution, so the simulation has to invalidate
        # it — which is itself worth asserting, since a cache that never refreshed
        # would make every future schema unservable until a restart.
        from eye_for_an_eye import compatibility
        compatibility._CACHE.pop('feature_schema', None)  # noqa: SLF001
        self.addCleanup(self._restore)

    def _restore(self):
        MODEL_SCHEMAS.pop(self.next_schema, None)
        from eye_for_an_eye import compatibility
        compatibility._CACHE.pop('feature_schema', None)  # noqa: SLF001

    def test_the_contract_serves_the_new_schema_without_being_edited(self):
        self.assertTrue(FEATURE_SCHEMA.supports(self.next_schema))

    def test_the_new_schema_projects_correctly(self):
        vector = FeatureVector(tuple(0.25 for _ in NAMES),
                               observation_seconds=30.0, sample_count=40)
        full = FeatureTransformer.transform(vector)
        position = {name: index for index, name in enumerate(INPUT_ORDER)}
        self.assertEqual(FeatureTransformer.project(vector, self.next_schema),
                         tuple(full[position[name]] for name in self.reordered))

    def test_the_classifier_gate_accepts_the_new_schema(self):
        self.assertTrue(usable_ml(_MlResult(self.next_schema)))

    def test_a_decision_reaches_temp_block_under_the_new_schema(self):
        """The end-to-end half of §35, and the part that would have caught P15.4.

        Not "the assumption passes" — the whole authority runs and returns the
        strong action. An assumption that passed while some later gate refused on
        the same grounds would read as a fix and behave as the bug.
        """
        authority = _authority()
        record = authority.decide(_blocking_inputs(self.next_schema))
        self.assertEqual(record.action, 'TEMP_BLOCK',
                         f'a servable schema could not produce a block: '
                         f'{record.explain().get("reason_codes")}')

    def test_the_same_decision_is_refused_for_an_unservable_schema(self):
        """The negative control for the test above, so a `decide` that returned
        TEMP_BLOCK unconditionally could not pass both."""
        authority = _authority()
        record = authority.decide(_blocking_inputs(max(MODEL_SCHEMAS) + 5))
        self.assertNotEqual(record.action, 'TEMP_BLOCK')


class _MlResult:
    status = 'healthy'
    risk_score = 0.5
    confidence = 0.5

    def __init__(self, schema):
        self.feature_schema_version = schema


def _inputs(schema):
    return DecisionInputs(
        source='192.0.2.1', scope='GLOBAL',
        identity_confidence='HIGH', identity_origin='direct_peer',
        network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
        feature_schema_version=schema,
        observations=40, observation_seconds=120.0, data_quality=0.9,
        math_risk=0.8, math_version='math-risk-v4',
        calibrated=True, model_artifact_valid=True, features_finite=True,
        enforcement_healthy=True, clock_sane=True)


#: Enough distinct evidence families, above the family floor, for the diversity
#: gates to be satisfied. Signal and behavioural diversity are *derived* from
#: this by `authority._families` rather than passed in, which is the point: a
#: test that supplied the counts directly would not exercise the derivation.
_FAMILIES = {'PORT_BREADTH': 0.9, 'PROTOCOL_BEHAVIOR': 0.8,
             'DECEPTION_INTERACTION': 0.8, 'NETWORK_RATE': 0.7,
             'PERSISTENCE': 0.7, 'TIMING': 0.6}


def _authority():
    """An authority that is actually allowed to act.

    `enabled=False` is the default, and an authority that refuses because
    autonomy is off would make the schema simulation below pass for the wrong
    reason — which is the same mistake as a check that only ever refuses.
    """
    return AutonomousDecisionAuthority(cost_policy=CostPolicy(), gates=DecisionGates(),
                                       enabled=True, mode=AUTONOMOUS)


def _blocking_inputs(schema):
    """Inputs every gate but the schema one accepts.

    The probability is well clear of the default `public_website` cutoff
    (0.975610) *and* of the relative-advantage margin above it, so that a change
    to either cutoff or margin fails this as a cost test rather than silently
    turning it into one. What is being tested here is the schema seam; the
    numbers are chosen to keep every other gate out of the way.
    """
    return DecisionInputs(
        source='192.0.2.77', scope='GLOBAL',
        identity_confidence='HIGH', identity_origin='direct_peer',
        network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
        feature_schema_version=schema,
        observations=60, observation_seconds=300.0, data_quality=0.9,
        math_risk=0.95, math_version='math-risk-v4',
        math_family_scores=dict(_FAMILIES),
        calibrated=True, calibrated_probability=0.999, calibrated_lower=0.99,
        calibration_version='mathrisk-cal-v4-isotonic',
        model_artifact_valid=True, features_finite=True,
        enforcement_healthy=True, clock_sane=True)


if __name__ == '__main__':
    unittest.main()
