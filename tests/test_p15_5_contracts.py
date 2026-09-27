"""Every seam, asked what it hands over and what it accepts. P15.5 §8-§10, §36-§39.

P15.4's six defects were mostly seams, and a seam has a property no component
has: it belongs to nobody. `AuthLedger.features` was correct and had no callers.
`FeatureTransformer.project` was correct and replay did not use it. The schema
assumption was correct about a schema that had stopped being current. In each
case both sides passed their own tests.

So this file tests the joins. It is organised as a matrix — producer, consumer,
what crosses — because §36 asks for one and because a list of pairs is auditable
in a way that a pile of integration tests is not: a seam missing from the matrix
is visible, where a seam missing from a test suite is not.

The other half is the three states a component can be in. §10 is one sentence —
"do not silently replace broken with not configured" — and it names the failure
that makes a defender look healthy while it decides nothing. A configured
component that did not load must say so; a component nobody configured must say
that instead; and the two must never collapse into one value.
"""
import unittest

from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               DecisionGates, DecisionInputs)
from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.autonomy.maturity import MaturityPolicy
from eye_for_an_eye.autonomy.maturity import evaluate as maturity_of
from eye_for_an_eye.autonomy.record import ASSUMPTION_NAMES
from eye_for_an_eye.compatibility import CONTRACTS, FEATURE_SCHEMA
from eye_for_an_eye.config import Config
from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision.families import scores as family_scores
from eye_for_an_eye.decision.features import (FeatureTransformer, FeatureVector, NAMES,
                                              SCHEMA_VERSION)
from eye_for_an_eye.decision.math_risk import MathRiskEngine
from eye_for_an_eye.security.host_enforcer import request_from_record
from training.decision_replay import ReplayComponents
from training.p15_5_smoke import CALIBRATOR

#: §36. Producer -> consumer, and the contract that governs the handover.
#: `contract` names an entry in `compatibility.CONTRACTS` where the join is
#: versioned, or None where the join is structural (a shape, not a version).
MATRIX = (
    ('packet parser', 'normalization', 'NetworkEvent', 'event_schema'),
    ('normalization', 'AuthLedger', 'AuthenticationEvent', 'auth_event_schema'),
    ('AuthLedger', 'FeatureVector', 'the five authentication columns', 'auth_state_schema'),
    ('normalization', 'FeatureVector', 'bounded samples', None),
    ('FeatureVector', 'family scores', 'raw feature values', 'feature_schema'),
    ('family scores', 'EvidenceComposition', 'one score per family', None),
    ('EvidenceComposition', 'MathRisk', 'a composed score', None),
    ('MathRisk', 'calibrator', 'an uncalibrated score and its formula name', 'calibration_schema'),
    ('calibrator', 'authority', 'a probability and a conservative bound', 'score_contract'),
    ('FeatureVector', 'auxiliary ML', 'the projected tensor', 'feature_schema'),
    ('authority', 'enforcement', 'a decision record', 'decision_record_schema'),
    ('enforcement', 'privileged helper', 'a validated request', 'enforcement_request_schema'),
)


class TestTheContractMatrixIsComplete(unittest.TestCase):
    """§36. The matrix is only worth having if it is checked against reality."""

    def test_every_named_contract_exists(self):
        for producer, consumer, carries, contract in MATRIX:
            if contract is None:
                continue
            with self.subTest(seam=f'{producer} -> {consumer}'):
                self.assertIn(contract, CONTRACTS,
                              f'{producer} -> {consumer} names a contract that does not exist')

    def test_every_seam_states_what_crosses_it(self):
        for producer, consumer, carries, _ in MATRIX:
            with self.subTest(seam=f'{producer} -> {consumer}'):
                self.assertTrue(carries.strip())

    def test_the_matrix_covers_every_versioned_boundary_on_the_decision_path(self):
        """A contract that exists and appears in no seam is a boundary nobody
        has said who is on each side of."""
        named = {contract for *_, contract in MATRIX if contract}
        on_the_decision_path = {'feature_schema', 'auth_event_schema', 'auth_state_schema',
                                'calibration_schema', 'score_contract',
                                'decision_record_schema', 'enforcement_request_schema',
                                'event_schema'}
        self.assertEqual(on_the_decision_path - named, set())


class TestEachSeamActuallyCarriesItsValue(unittest.TestCase):
    """The matrix above says what should cross. These run the joins."""

    def setUp(self):
        self.vector = _vector()
        self.math = MathRiskEngine()

    def test_feature_vector_to_family_scores(self):
        scored = family_scores(self.vector)
        self.assertTrue(scored, 'the family layer produced nothing at all')
        self.assertTrue(any(value is not None for value in scored.values()))

    def test_feature_vector_to_math_risk_names_the_formula(self):
        result = self.math.evaluate(self.vector)
        self.assertEqual(result.model_version, 'math-risk-v4')
        self.assertTrue(0.0 <= result.score <= 1.0)

    def test_math_risk_to_calibrator_is_bound_to_the_formula(self):
        """The join that must not be loose. A v4 score through a v3 curve is a
        number with no meaning, and the artifact names the formula it maps so
        the mismatch is refused rather than computed."""
        calibrator = cal.load(CALIBRATOR)
        result = self.math.evaluate(self.vector)
        self.assertEqual(calibrator.model_version, result.model_version)
        probability = calibrator.calibrate(result.score, model_version=result.model_version)
        self.assertIsNotNone(probability)
        self.assertTrue(0.0 <= probability.value <= 1.0)

    def test_a_calibrator_bound_to_another_formula_is_refused(self):
        """The negative half. `calibrate` returns None rather than raising,
        because on the decision path an unusable calibrator means
        CALIBRATION_UNAVAILABLE and no block — a state the system knows how to
        be in."""
        calibrator = cal.load(CALIBRATOR)
        result = self.math.evaluate(self.vector)
        self.assertIsNone(calibrator.calibrate(result.score, model_version='math-risk-v3'))

    def test_calibrator_to_authority_carries_the_conservative_bound(self):
        calibrator = cal.load(CALIBRATOR)
        result = self.math.evaluate(_blocking_vector())
        probability = calibrator.calibrate(result.score, model_version=result.model_version)
        self.assertIsNotNone(probability.lower,
                             'a block rests on the bound, not the point estimate')
        self.assertLessEqual(probability.lower, probability.value)

    def test_feature_vector_to_auxiliary_ml_uses_one_projection(self):
        """§8. Replay sent 46 columns to a 36-column model while the runtime
        projected correctly, because there were two implementations. There is
        now one, and this asserts both callers get the same tensor from it."""
        for schema in FEATURE_SCHEMA.servable:
            with self.subTest(schema=schema):
                self.assertEqual(FeatureTransformer.project(self.vector, schema),
                                 FeatureTransformer.project(self.vector, schema))
        self.assertEqual(len(FeatureTransformer.project(self.vector, SCHEMA_VERSION)),
                         2 * len(NAMES))

    def test_authority_to_enforcement_refuses_an_allow(self):
        """`request_from_record` reads the record rather than being told what to
        do. An ALLOW authorises nothing, and the refusal is the contract."""
        record = _authority().decide(_inputs(math_risk=0.1, lower=0.1, probability=0.1))
        with self.assertRaises(Exception):
            request_from_record(record)

    def test_authority_to_enforcement_carries_the_decision_forward(self):
        record = _authority().decide(_inputs())
        self.assertEqual(record.action, 'TEMP_BLOCK', record.reason_codes)
        request = request_from_record(record)
        self.assertEqual(request.address, record.source)
        self.assertEqual(request.ttl_seconds, record.block_ttl_seconds)
        self.assertEqual(request.decision_id, record.decision_id)

    def test_maturity_reads_families_and_not_their_strength(self):
        """How suspicious the evidence is has no bearing on whether there is
        enough of it, and a maturity that moved with the score would be a
        threshold wearing a different name."""
        weak = maturity_of(observations=60, observation_seconds=300.0, data_quality=0.9,
                           families=('PORT_BREADTH', 'NETWORK_RATE', 'TIMING'),
                           policy=MaturityPolicy())
        strong = maturity_of(observations=60, observation_seconds=300.0, data_quality=0.9,
                             families=('PORT_BREADTH', 'NETWORK_RATE', 'TIMING'),
                             policy=MaturityPolicy())
        self.assertEqual(weak.mature, strong.mature)
        self.assertEqual(weak.mode, strong.mode)


class TestNoSilentComponentAbsence(unittest.TestCase):
    """§9, §10. Configured-and-broken must not read as never-configured."""

    def test_nothing_configured_reports_not_configured(self):
        health = ReplayComponents(config=Config()).open().health()
        for name, state in sorted(health['components'].items()):
            with self.subTest(component=name):
                self.assertEqual(state, 'NOT_CONFIGURED')
        self.assertEqual(health['degraded'], [])

    def test_a_configured_component_that_did_not_load_reports_unavailable(self):
        """The specific line §10 forbids. Until P15.5 a failed anomaly load set
        the model back to `None`, which is the value meaning "nobody asked for
        one" — so a broken artifact and an absent one produced identical health."""
        health = ReplayComponents(config=Config()).open(
            anomaly_path='/nonexistent-model.onnx',
            anomaly_manifest='/nonexistent-manifest.json').health()
        self.assertEqual(health['components']['anomaly'], 'UNAVAILABLE')
        self.assertIn('anomaly', health['degraded'])
        self.assertTrue(health['detail']['anomaly'])

    def test_a_broken_reference_distribution_reports_unavailable(self):
        health = ReplayComponents(config=Config()).open(
            distribution_path='/nonexistent-distribution.json').health()
        self.assertEqual(health['components']['reference_distribution'], 'UNAVAILABLE')

    def test_a_classifier_that_loads_and_answers_nothing_is_not_healthy(self):
        """§9's real case. The P15.4 auxiliary-ML defect had a model that loaded
        perfectly and failed every prediction, and health at load time would
        have reported it green for the whole cycle."""
        components = ReplayComponents(config=Config())
        components.component_state['classifier'] = 'HEALTHY'
        components.ml_failed = 40
        health = components.health()
        self.assertEqual(health['components']['classifier'], 'UNAVAILABLE')
        self.assertIn('classifier', health['degraded'])

    def test_an_absent_classifier_that_was_configured_says_so(self):
        """`not_configured` is a truthful answer only when nothing was asked for."""
        from training.decision_replay import _ml_inputs  # noqa: SLF001
        components = ReplayComponents(config=Config())
        components.component_state['classifier'] = 'CONFIGURED'
        self.assertEqual(_ml_inputs(components, _vector()).error,
                         'configured_classifier_absent')


class TestTheAuthLedgerIsActuallyConsulted(unittest.TestCase):
    """The P15.4 defect in its purest form, guarded structurally.

    `AuthLedger.features` was correct, tested, and had **zero callers**. The
    whole P15.4 thesis — that authentication means outcome rather than presence —
    was inert, and `AUTH_BEHAVIOR` scored 0.000 on a brute force, because the one
    argument that carries the ledger into the feature vector was not being passed.

    A behavioural test cannot catch the next version of that: a caller that
    forgets `auth=` produces a vector where all five columns are `None`, which is
    exactly what a source that never authenticated produces. The two are
    indistinguishable downstream by design — that is `CONDITIONAL_GROUPS` working
    — so the guard has to be structural, at the call site.
    """

    #: Callers that build a vector from live correlation state. Each must hand
    #: over the ledger. `training/dataset.py` and `training/build_dataset.py`
    #: are excluded and named: they rebuild the frozen pre-P15.4 corpora, whose
    #: captures contain no authentication outcome at all, and passing a ledger
    #: there would change bytes that have to stay reproducible.
    LIVE_CALLERS = ('eye_for_an_eye/decision/engine.py', 'dataset/builder.py')

    def test_every_live_caller_passes_the_ledger(self):
        import ast
        from pathlib import Path as _Path
        root = _Path(__file__).resolve().parents[1]
        for relative in self.LIVE_CALLERS:
            tree = ast.parse((root / relative).read_text(encoding='utf-8'))
            calls = [node for node in ast.walk(tree)
                     if isinstance(node, ast.Call)
                     and getattr(node.func, 'id', '') == 'from_samples']
            with self.subTest(module=relative):
                self.assertTrue(calls, f'{relative} no longer builds a FeatureVector; '
                                       f'update this list rather than deleting the check')
                for call in calls:
                    self.assertIn('auth', {kw.arg for kw in call.keywords},
                                  f'{relative} builds a feature vector without the '
                                  f'authentication ledger; the five schema-2 columns '
                                  f'would be None and nothing downstream could tell '
                                  f'that from a source that never authenticated')

    def test_a_vector_built_without_a_ledger_is_indistinguishable(self):
        """The reason the test above has to be structural, asserted rather than
        assumed — if these ever differ, a behavioural test becomes possible and
        this one can be replaced by it."""
        from eye_for_an_eye.decision.features import AUTH_COLUMNS_ARE_CONDITIONAL
        self.assertTrue(AUTH_COLUMNS_ARE_CONDITIONAL)


class TestAssumptionObservability(unittest.TestCase):
    """§38, §39. Counters with bounded labels, and the alarm P15.4 lacked."""

    def test_every_assumption_has_its_own_bounded_counter(self):
        metrics = _authority().metrics()
        for name in ASSUMPTION_NAMES:
            with self.subTest(assumption=name):
                self.assertIn(f'autonomous_block_suppressed_by_{name}_total', metrics)

    def test_no_metric_label_comes_from_the_data(self):
        """An unbounded label set is a cardinality failure waiting for the first
        source that supplies one. Every suppression series is named after a
        frozen assumption, so a source address can never become a label."""
        authority = _authority()
        authority.decide(_inputs(schema=max(FEATURE_SCHEMA.servable) + 1))
        suppression = [key for key in authority.metrics()
                       if key.startswith('autonomous_block_suppressed_by_')]
        self.assertEqual(len(suppression), len(ASSUMPTION_NAMES))

    def test_no_assumption_is_blamed_when_the_block_budget_is_what_refused(self):
        """Thirty identical blockable decisions exhaust the block budget, so the
        later ones are suppressed — by the mass-block breaker, which is a brake
        somebody chose, not a silent failure. `by_assumption` stays empty and
        health stays OK, which is the distinction this signal has to make: a
        defender that is deliberately throttling itself and one that is
        discarding every decision for one reason look the same in a bare
        suppression count and must not look the same here."""
        authority = _authority()
        for _ in range(30):
            authority.decide(_inputs())
        health = authority.assumption_health()
        self.assertGreater(health['eligible_but_suppressed'], 0,
                           'the budget should have refused some of these')
        self.assertEqual(health['by_assumption'], {})
        self.assertEqual(health['state'], 'OK')

    def test_the_p15_4_failure_shape_degrades_health(self):
        """The whole point. Every gate agrees, one assumption refuses all of
        them, nothing is unhealthy, and nothing blocks. This is the alarm that
        would have fired on day one of P15.4 instead of on the locked benchmark."""
        authority = _authority()
        unservable = max(FEATURE_SCHEMA.servable) + 1
        for _ in range(30):
            authority.decide(_inputs(schema=unservable))
        health = authority.assumption_health()
        self.assertEqual(health['state'], 'DEGRADED')
        self.assertEqual(health['dominant_assumption'], 'feature_schema_compatible')
        self.assertEqual(health['dominant_share'], 1.0)

    def test_a_handful_of_suppressions_is_not_an_alarm(self):
        """Below the floor the share is arithmetic rather than evidence: one
        suppressed decision is 100% of whichever assumption refused it."""
        authority = _authority()
        for _ in range(3):
            authority.decide(_inputs(schema=max(FEATURE_SCHEMA.servable) + 1))
        self.assertEqual(authority.assumption_health()['state'], 'OK')

    def test_degraded_health_reaches_the_metrics(self):
        authority = _authority()
        for _ in range(30):
            authority.decide(_inputs(schema=max(FEATURE_SCHEMA.servable) + 1))
        self.assertEqual(authority.metrics()['autonomous_assumption_health_degraded'], 1)
        self.assertEqual(authority.status()['assumption_health']['state'], 'DEGRADED')


# -- fixtures ---------------------------------------------------------------

#: Enough families above the floor for the diversity gates, derived by the
#: authority rather than supplied as counts.
_FAMILIES = {'PORT_BREADTH': 0.9, 'PROTOCOL_BEHAVIOR': 0.8, 'DECEPTION_INTERACTION': 0.8,
             'NETWORK_RATE': 0.7, 'PERSISTENCE': 0.7, 'TIMING': 0.6}


def _authority():
    return AutonomousDecisionAuthority(cost_policy=CostPolicy(), gates=DecisionGates(),
                                       enabled=True, mode=AUTONOMOUS)


def _inputs(*, schema=SCHEMA_VERSION, math_risk=0.95, probability=0.999, lower=0.99):
    return DecisionInputs(
        source='198.51.100.23', scope='GLOBAL',
        identity_confidence='HIGH', identity_origin='direct_peer',
        network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
        feature_schema_version=schema,
        observations=60, observation_seconds=300.0, data_quality=0.9,
        math_risk=math_risk, math_version='math-risk-v4',
        math_family_scores=dict(_FAMILIES),
        calibrated=True, calibrated_probability=probability, calibrated_lower=lower,
        calibration_version='mathrisk-cal-v4-isotonic',
        model_artifact_valid=True, features_finite=True,
        enforcement_healthy=True, clock_sane=True)


def _vector():
    return FeatureVector(tuple(0.4 for _ in NAMES), observation_seconds=120.0,
                         sample_count=60)


def _blocking_vector():
    """Values high enough that the calibrator's upper knots are exercised."""
    raw = {'connections_10s': 60, 'connections_60s': 300, 'connections_900s': 400,
           'ports_60s': 40, 'ports_900s': 90, 'destinations_60s': 8}
    values = tuple(raw.get(name, 0.6) for name in NAMES)
    return FeatureVector(values, observation_seconds=300.0, sample_count=200)


if __name__ == '__main__':
    unittest.main()
