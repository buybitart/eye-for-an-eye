"""Three defects the P15.5 locked benchmark found in the measuring instrument.

None of them is a defect in the candidate. All three make a *measurement* mean
something other than what it appears to, which is worse than a wrong number
because a wrong number invites checking and a mislabelled one does not.

They were found after the benchmark was scored, and the benchmark was **not**
rescored — §25 and §26 are absolute, the candidate had already failed Gate C on
other grounds, and re-deriving a verdict from a corrected instrument would have
produced a second result from a corpus entitled to one. The corrections apply
from the next cycle and these tests are what stop them regressing in the
meantime.

1. **Every decision was priced at the same cutoff.** `replay_sample` set
   `scope='GLOBAL'`, and an unmapped scope resolves to the default profile, so
   every window of every locked benchmark since P15.1 was decided at
   `public_website`'s 0.975610 whatever site it belonged to. The per-profile
   tables in P15.4's and P15.5's reports are outcomes *grouped* by profile, not
   outcomes *decided* per profile — and the API eligibility question, which this
   cycle spent eight corpora on, was never actually asked at the API cutoff.

2. **The generalisation gate checked the wrong pair.** It read P15.4's withheld
   constant, so it looked for `withheld-mobile-sync` in the P15.5 benchmark,
   found neither of P15.4's families, and failed — while P15.5's own withheld
   pair sat in the same results at 0/18 benign blocked and 14/14 positive
   detected.

3. **The withheld pair counted as seen.** `familiarity` reads the training-split
   holdout list, which knows nothing about the `withheld.` prefix. The two
   families that had never been near a fitting corpus were excluded from the
   unseen aggregate — understating precisely the number a generalisation claim
   rests on.
"""
import unittest

from eye_for_an_eye.autonomy.cost import PROFILES
from training import evaluation_design as design
from training import p15_5_evaluation as E
from training.p15_4_evaluation import generalization_gate


class TestTheCostProfileReachesTheDecision(unittest.TestCase):
    """Defect 1. A per-profile table is a lie unless the profile priced it."""

    def test_each_profile_name_resolves_to_itself(self):
        policy = E.cost_policy()
        for name, profile in sorted(PROFILES.items()):
            with self.subTest(profile=name):
                self.assertEqual(policy.for_scope(name).name, name)
                self.assertAlmostEqual(policy.for_scope(name).threshold,
                                       profile.threshold, places=9)

    def test_an_unmapped_scope_still_gets_the_default(self):
        """The old behaviour, preserved for corpora that declare no profile:
        a site nobody classified is priced by the most protective general
        profile rather than a cheap one."""
        policy = E.cost_policy()
        self.assertEqual(policy.for_scope('GLOBAL').name, policy.default_profile)
        self.assertEqual(policy.for_scope('').name, policy.default_profile)

    def test_an_empty_map_sends_every_scope_to_one_profile(self):
        """The defect itself, asserted so the fix is not mistaken for decoration.
        This is what every locked benchmark before P15.5 was measured with."""
        from eye_for_an_eye.autonomy.cost import CostPolicy
        default = CostPolicy()
        self.assertEqual(default.scope_profiles, {})
        for name in sorted(PROFILES):
            with self.subTest(profile=name):
                self.assertEqual(default.for_scope(name).name, default.default_profile)

    def test_replay_passes_the_declared_profile_as_the_scope(self):
        """The scope reaching the authority is derived, never written down.

        P15.5R moved *where* it is derived. The scope used to be a `scope=`
        keyword on a `DecisionInputs` built inside `replay_sample`; it is now a
        `declared=` keyword on `ScopeResolver.resolve`, because the runtime and
        the replay share one resolver and one assembly (§17, §19). The guarantee
        is unchanged and so is this test's purpose: whatever the keyword is
        called, a literal there prices every decision in every corpus at one
        profile, which is the defect this test was written for.
        """
        import ast
        import inspect
        from training import decision_replay
        source = inspect.getsource(decision_replay.replay_sample)
        tree = ast.parse(source.lstrip())
        scopes = [node for node in ast.walk(tree)
                  if isinstance(node, ast.keyword) and node.arg in ('scope', 'declared')]
        self.assertTrue(scopes, 'replay no longer derives a scope at all')
        for keyword in scopes:
            with self.subTest():
                self.assertNotIsInstance(
                    keyword.value, ast.Constant,
                    'the scope is a literal again; every decision would be priced '
                    'at the default profile whatever site it belongs to')

    def test_replay_and_the_runtime_assemble_a_decision_with_the_same_code(self):
        """P15.5R §17. One `decision_inputs`, called by both.

        The strongest available statement of the rule P15.4 taught: a benchmark
        that assembles a decision differently from the runtime is measuring a
        product that does not ship. Asserted structurally, because the two would
        agree on every test that exercised only one of them.
        """
        import ast
        import inspect
        from eye_for_an_eye.autonomy import pipeline
        from eye_for_an_eye.decision import engine
        from training import decision_replay

        self.assertIs(decision_replay.decision_inputs, pipeline.decision_inputs,
                      'the replay harness has its own assembly again')

        called = {node.func.id for node in ast.walk(
            ast.parse(inspect.getsource(decision_replay.replay_sample).lstrip()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertIn('decision_inputs', called,
                      'replay builds DecisionInputs by hand rather than through '
                      'the shipped assembly')

        # The runtime reaches the same function through the pipeline it holds,
        # so the check there is that it holds one at all rather than building
        # its own inputs.
        engine_source = inspect.getsource(engine.DecisionEngine)
        self.assertNotIn('DecisionInputs(', engine_source,
                         'the decision engine assembles its own inputs; the '
                         'runtime and the evaluator would drift apart again')


class TestTheGeneralisationGateChecksItsOwnPair(unittest.TestCase):
    """Defect 2."""

    FAMILIES = {
        'withheld-backup-sweep': {'label': design.BENIGN, 'sources': 18,
                                  'blocked_sources': 0},
        'withheld-credential-drift': {'label': design.MALICIOUS, 'sources': 14,
                                      'blocked_sources': 14},
    }

    def test_the_gate_passes_when_its_own_pair_is_present_and_behaving(self):
        result = generalization_gate(self.FAMILIES, E.WITHHELD_FAMILIES)
        self.assertEqual(result['verdict'], 'PASS', result['failures'])
        self.assertEqual(result['withheld_present'], sorted(E.WITHHELD_FAMILIES))

    def test_the_gate_fails_when_the_withheld_benign_family_is_blocked(self):
        families = {**self.FAMILIES,
                    'withheld-backup-sweep': {'label': design.BENIGN, 'sources': 18,
                                              'blocked_sources': 3}}
        result = generalization_gate(families, E.WITHHELD_FAMILIES)
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertTrue(any(f['condition'] == 'the_withheld_benign_family_was_blocked'
                            for f in result['failures']))

    def test_the_gate_fails_when_a_withheld_family_is_missing(self):
        result = generalization_gate({'withheld-backup-sweep': self.FAMILIES[
            'withheld-backup-sweep']}, E.WITHHELD_FAMILIES)
        self.assertEqual(result['verdict'], 'FAIL')

    def test_the_default_is_still_p15_4s_pair(self):
        """So the P15.4 report keeps meaning what it meant."""
        from training.p15_4_evaluation import WITHHELD_FAMILIES as p15_4
        result = generalization_gate({})
        self.assertEqual(result['withheld_expected'], sorted(p15_4))


class TestStructurallyWithheldFamiliesCountAsUnseen(unittest.TestCase):
    """Defect 3."""

    class Row:
        def __init__(self, group):
            self.scenario_group = group

    def test_every_structurally_withheld_family_is_unseen(self):
        for name in design.STRUCTURALLY_WITHHELD:
            with self.subTest(family=name):
                self.assertEqual(design.familiarity(self.Row(name)), 'unseen')

    def test_an_ordinary_family_is_still_seen(self):
        self.assertEqual(design.familiarity(self.Row('benign-web')), 'seen')

    def test_the_training_holdout_is_still_unseen(self):
        from dataset import split as split_module
        for name in sorted(split_module.HOLDOUT):
            with self.subTest(family=name):
                self.assertEqual(design.familiarity(self.Row(name)), 'unseen')

    def test_the_list_covers_every_withheld_family_in_every_locked_matrix(self):
        """Derived from the matrices rather than remembered.

        A family's *group* name is what `familiarity` sees, and the group is
        written in the matrix rather than derived from the generator — which is
        why `backup_window_sweep` is the generator and `withheld-backup-sweep` is
        the family. Reading the matrices is the only derivation that cannot drift
        from what a corpus actually contains, and it means a third withheld pair
        added later is covered the day its matrix names it.
        """
        from pathlib import Path as _Path
        from dataset.generators import withheld
        from dataset.scenarios import load
        from tests.test_p15_4_withheld import LOCKED_MATRICES, REPOSITORY

        named = set()
        for relative in LOCKED_MATRICES:
            for entry in load(_Path(REPOSITORY) / relative)['scenario']:
                if entry['generator'].startswith(withheld.WITHHELD_PREFIX):
                    named.add(entry['group'])
        self.assertTrue(named, 'no locked matrix names a withheld family')
        missing = sorted(named - set(design.STRUCTURALLY_WITHHELD))
        self.assertEqual(missing, [],
                         f'{missing} appears in a locked corpus as a withheld '
                         f'family and would be classified `seen`, which '
                         f'understates unseen recall')


if __name__ == '__main__':
    unittest.main()
