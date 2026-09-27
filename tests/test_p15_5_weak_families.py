"""Why four families detect poorly, measured against their own controls. §16-§19.

P15.4 named four families with weak evidence and P15.5 §16 asks what each one
actually is: observable, partially observable, or out of scope — decided from the
architecture, not from whether detection currently succeeds.

§17 supplies the constraint that makes the question honest. `if probe_repeated:
add risk` would fix the number and answer nothing, so the only admissible finding
is about generic primitives: repetition, breadth, protocol completion,
persistence, decoy interaction. And a primitive is only worth strengthening if it
separates the family from the benign behaviour it most resembles — which is what
this file measures.

The result, from the runs below:

    probe-repeated    math 0.000   NETWORK_RATE 0.25, TIMING 0.62   no carrying family
    monitoring_agent  math 0.000   TIMING 1.00, PERSISTENCE 0.24    no carrying family
    monitoring fast   math 0.000   NETWORK_RATE 0.30, TIMING 1.00   no carrying family
    health_checker    math 0.000   NETWORK_RATE 0.56, TIMING 1.00   no carrying family

    scan-horizontal        PORT_BREADTH carries; control scores nothing
    protocol-mismatch      PORT_BREADTH + PROTOCOL_BEHAVIOR;  control nothing
    composite-decoy-recon  PORT_BREADTH carries; control scores nothing

Those are two different findings and they need different answers.

**probe-repeated produces no carrying evidence at all** — only how it ran, never
what it did. Its three benign controls produce the same kind of evidence, and the
comparison is sharper than "similar": the *monitoring agent* is the more
machine-regular of the two, TIMING 1.00 against the attack's 0.62. Any primitive
strong enough to convict a repeated probe on regularity convicts every monitoring
agent on the network first, and convicts it harder.

That is not a weighting problem. The quantity that separates them is whether the
operator asked for the probing, which is authorisation rather than traffic, so it
is reclassified `IN_SCOPE_PARTIALLY_OBSERVABLE` in `training/observability.py`.
This file is the evidence, so that a later cycle tempted to reclassify it back
has to answer the measurement rather than the prose.

**The other three separate correctly and are limited elsewhere.** Each is carried
by `PORT_BREADTH` while its nearest benign control produces nothing, which is the
family layer working exactly as designed. They do not block because of where they
land after calibration, not because the formula cannot see them — so §19 holds
and `math-risk-v4` is unchanged.

The scores here come from short single-scenario runs and are lower than the same
families reach in a full corpus. That does not matter for the comparison: every
case is built and scored the same way, and the claim is about the *difference*
between a family and its control, not about either absolute number.
"""
import tempfile
import unittest

from eye_for_an_eye.config import Config
from eye_for_an_eye.decision.families import FLOOR
from eye_for_an_eye.decision.families import scores as family_scores
from eye_for_an_eye.decision.math_risk import MathRiskEngine
from training.p15_5_smoke import _samples_for  # noqa: SLF001

#: The family under review, and the benign behaviour a defender must not confuse
#: it with. A finding about a weak family is worth nothing without its control.
CASES = {
    'probe-repeated': ('protocol', 'repeated_probes', {}),
    'monitoring-agent': ('benign', 'monitoring_agent', {}),
    'monitoring-agent-fast': ('benign', 'monitoring_agent', {'checks': 70, 'period': 1.2}),
    'health-checker': ('benign', 'health_checker', {}),
    'scan-horizontal': ('scanner', 'horizontal_scan', {}),
    'service-discovery': ('benign', 'service_discovery', {}),
    'protocol-mismatch': ('protocol', 'protocol_mismatch', {}),
    'composite-decoy-recon': ('composite', 'decoy_then_enumerate', {}),
    'decoy-brush-past': ('deception', 'decoy_brush_past', {}),
}

MEASURED = {}


def setUpModule():
    """Build and score each behaviour once. Two runs is enough for a comparison
    that turns on whether any family clears the floor at all."""
    config = Config()
    config.decision.enabled = True
    math = MathRiskEngine()
    with tempfile.TemporaryDirectory(prefix='e4e-weak-families-') as workspace:
        for name, (module_name, builder, params) in CASES.items():
            module = __import__(f'dataset.generators.{module_name}', fromlist=[builder])
            best, families = 0.0, {}
            for run in range(2):
                plan = getattr(module, builder)(f'wf-{name}', name, f'p15.5:{name}:{run}',
                                                **params)
                samples, _ = _samples_for(plan, config, workspace)
                for sample in samples:
                    score = math.evaluate(sample.features).score
                    if score >= best:
                        best = score
                        families = {key: value for key, value
                                    in family_scores(sample.features).items()
                                    if value is not None and value >= FLOOR}
            MEASURED[name] = {'math_risk': best, 'families': families}


def _carrying(name):
    """The measured families that are allowed to carry a decision on their own."""
    from eye_for_an_eye.decision.families import CARRYING_FAMILIES
    return {key: value for key, value in MEASURED[name]['families'].items()
            if key in CARRYING_FAMILIES}


class TestProbeRepeatedIsNotSeparableFromMonitoring(unittest.TestCase):
    """The finding that changes a classification, so it carries the evidence."""

    CONTROLS = ('monitoring-agent', 'monitoring-agent-fast', 'health-checker')

    def test_the_family_produces_no_carrying_evidence(self):
        """Only how it ran — rate and regularity — never what it did."""
        self.assertEqual(_carrying('probe-repeated'), {})
        self.assertEqual(MEASURED['probe-repeated']['math_risk'], 0.0)

    def test_neither_do_its_benign_controls(self):
        for control in self.CONTROLS:
            with self.subTest(control=control):
                self.assertEqual(_carrying(control), {})

    def test_the_control_is_the_more_machine_regular_of_the_two(self):
        """The measurement that settles it. If the attack were merely *less*
        separable one could argue for a better timing term; the benign control
        being more regular than the attack says which way that term would fire."""
        probe = MEASURED['probe-repeated']['families'].get('TIMING', 0.0)
        for control in self.CONTROLS:
            with self.subTest(control=control):
                self.assertGreaterEqual(MEASURED[control]['families'].get('TIMING', 0.0),
                                        probe)

    def test_both_are_represented_only_by_corroborating_families(self):
        """The distinction the reclassification rests on: not similar scores from
        different evidence, but the same kind of evidence from both."""
        from eye_for_an_eye.decision.families import CORROBORATING_ONLY
        for name in ('probe-repeated', *self.CONTROLS):
            with self.subTest(behaviour=name):
                observed = set(MEASURED[name]['families'])
                self.assertTrue(observed, 'nothing was observed at all, which would '
                                          'make this comparison vacuous')
                self.assertTrue(observed <= set(CORROBORATING_ONLY))

    def test_the_observability_document_records_it_as_partially_observable(self):
        from training.observability import FAMILIES, IN_SCOPE_PARTIALLY_OBSERVABLE
        self.assertEqual(FAMILIES['probe-repeated'][0], IN_SCOPE_PARTIALLY_OBSERVABLE)

    def test_repetition_did_not_become_a_carrying_family(self):
        """§17. The fix that would have made the number better and the system
        worse: any primitive strong enough to carry probe-repeated carries every
        monitoring agent with it, because they are the same evidence."""
        from eye_for_an_eye.decision.families import CARRYING_FAMILIES, CORROBORATING_ONLY
        self.assertIn('TIMING', CORROBORATING_ONLY)
        self.assertIn('NETWORK_RATE', CORROBORATING_ONLY)
        self.assertIn('PERSISTENCE', CORROBORATING_ONLY)
        self.assertNotIn('TIMING', CARRYING_FAMILIES)


class TestTheOtherThreeSeparateCorrectly(unittest.TestCase):
    """Limited by where they land after calibration, not by the formula (§19)."""

    PAIRS = (('scan-horizontal', 'service-discovery'),
             ('protocol-mismatch', 'service-discovery'),
             ('composite-decoy-recon', 'decoy-brush-past'))

    def test_each_scores_above_its_benign_control(self):
        for family, control in self.PAIRS:
            with self.subTest(family=family):
                self.assertGreater(MEASURED[family]['math_risk'],
                                   MEASURED[control]['math_risk'])

    def test_each_is_carried_by_a_carrying_family(self):
        """Not by rate or timing. A source blocked on how it ran rather than what
        it did is the monitoring-agent failure with a different name."""
        from eye_for_an_eye.decision.families import CARRYING_FAMILIES
        for family, _ in self.PAIRS:
            with self.subTest(family=family):
                observed = set(MEASURED[family]['families'])
                self.assertTrue(observed & set(CARRYING_FAMILIES),
                                f'{family} is carried only by corroborating evidence: '
                                f'{sorted(observed)}')

    def test_no_control_produces_a_carrying_family(self):
        from eye_for_an_eye.decision.families import CARRYING_FAMILIES
        for _, control in self.PAIRS:
            with self.subTest(control=control):
                self.assertFalse(set(MEASURED[control]['families']) & set(CARRYING_FAMILIES))


class TestTheFormulaWasNotChanged(unittest.TestCase):
    """§18, §19. A generic change would have meant a new formula version and a
    refitted calibrator. None was made, so the name must not have moved."""

    def test_the_formula_version_is_still_v4(self):
        from eye_for_an_eye.decision.math_risk import VERSION
        self.assertEqual(VERSION, 'math-risk-v4')

    def test_the_family_and_composition_versions_are_unchanged(self):
        from eye_for_an_eye.decision.composition import COMPOSITION_VERSION
        from eye_for_an_eye.decision.families import FAMILY_SCORE_VERSION
        self.assertEqual(FAMILY_SCORE_VERSION, 'family-scores-v1')
        self.assertEqual(COMPOSITION_VERSION, 'evidence-composition-v1')

    def test_no_scenario_name_reaches_the_scoring_code(self):
        """§17 literally: no scoring module may branch on a scenario family name.

        Executable lines only. `composition.py` explains the P15.3 failure by
        naming `composite-decoy-recon` in its docstring, and a module must stay
        free to say why it is shaped the way it is — the same lesson the schema
        pin test learned when it was widened.
        """
        from pathlib import Path
        import tokenize
        root = Path(__file__).resolve().parents[1]
        names = ('probe_repeated', 'probe-repeated', 'scan_horizontal', 'scan-horizontal',
                 'protocol_mismatch', 'protocol-mismatch', 'composite_decoy',
                 'composite-decoy-recon')
        for relative in ('eye_for_an_eye/decision/families.py',
                         'eye_for_an_eye/decision/composition.py',
                         'eye_for_an_eye/decision/math_risk.py',
                         'eye_for_an_eye/decision/features.py'):
            with (root / relative).open('rb') as stream:
                code = ' '.join(
                    token.string for token in tokenize.tokenize(stream.readline)
                    if token.type not in (tokenize.COMMENT, tokenize.STRING))
            for name in names:
                with self.subTest(module=relative, name=name):
                    self.assertNotIn(name, code)


if __name__ == '__main__':
    unittest.main()
