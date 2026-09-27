"""Withholding, enforced instead of promised. §49, §50.

"We did not tune against this family" is a statement about what people intended,
and nobody can check it afterwards. The claim is only worth anything if breaking
it breaks something.

So the two P15.4 withheld families live in their own module, are registered
under a `withheld.` prefix, and this file refuses any matrix used for training,
calibration or development that contains one. Adding a withheld family to a
fitting corpus turns the suite red — which converts an assertion about
discipline into a property of the repository.

The prefix is read from `dataset.generators.withheld.WITHHELD_PREFIX` and the
registry is enumerated live, so a third withheld family added later is protected
by these tests the day it is written, without anybody remembering to extend a
list.
"""
from pathlib import Path
import unittest

from dataset.generators import withheld
from dataset.scenarios import REGISTRY, load, plans

REPOSITORY = Path(__file__).resolve().parents[1]

#: Every matrix that any fitting, calibration or development corpus is built
#: from. A matrix absent from this tuple is not exempt — `test_every_matrix_in_
#: the_repository_is_accounted_for` refuses one that nobody has classified.
FITTING_MATRICES = (
    'dataset/scenarios/matrix-v1.toml',
    'dataset/scenarios/matrix-eval-v1.toml',
    'dataset/scenarios/matrix-p15-4-dev-v1.toml',
    'dataset/scenarios/matrix-p15-5-cal-v1.toml',
)

#: Matrices that exist to be scored once, never fitted against. A withheld
#: family belongs in one of these and nowhere else.
LOCKED_MATRICES = (
    'dataset/scenarios/matrix-generalization-v2.toml',
    'dataset/scenarios/matrix-p15-4-locked-v1.toml',
    'dataset/scenarios/matrix-p15-5-locked-v1.toml',
)


def withheld_generators():
    return tuple(sorted(name for name in REGISTRY if name.startswith(withheld.WITHHELD_PREFIX)))


class TestTheWithheldFamiliesExistAndAreIdentifiable(unittest.TestCase):

    def test_the_prefix_actually_selects_something(self):
        """A guard that matches nothing passes every test below for the wrong
        reason, so the count is asserted before the exclusions are."""
        self.assertGreaterEqual(len(withheld_generators()), 2)

    def test_each_cycles_pair_appears_in_exactly_one_locked_matrix(self):
        """§24, and the reason the P15.4 pair is absent from the P15.5 benchmark.

        A withheld family scored on two locked corpora has been scored twice, and
        the second score is not a second independent result however carefully it
        is labelled. So each pair belongs to one benchmark: mobile-app-sync and
        probe-then-login to P15.4's, backup-window-sweep and credential-drift to
        P15.5's.
        """
        for generator in withheld_generators():
            appearances = [relative for relative in LOCKED_MATRICES
                           if generator in {entry['generator'] for entry
                                            in load(REPOSITORY / relative)['scenario']}]
            with self.subTest(generator=generator):
                self.assertEqual(len(appearances), 1,
                                 f'{generator} appears in {appearances}; a family '
                                 f'withheld for one cycle is not unseen in the next')

    def test_every_registered_withheld_generator_comes_from_the_withheld_module(self):
        for name in withheld_generators():
            with self.subTest(generator=name):
                self.assertEqual(REGISTRY[name].__module__, withheld.__name__,
                                 'the prefix is the guarantee; a generator registered '
                                 'under it from elsewhere makes the guarantee a lie')

    def test_no_generator_outside_that_module_is_registered_under_the_prefix(self):
        for name, generator in REGISTRY.items():
            if generator.__module__ == withheld.__name__:
                with self.subTest(generator=name):
                    self.assertTrue(name.startswith(withheld.WITHHELD_PREFIX),
                                    'a withheld family registered without the prefix is '
                                    'invisible to every exclusion in this file')

    def test_the_locked_matrix_actually_contains_them(self):
        """The mirror of every other test here. Withholding a family from the
        fitting corpora and then forgetting to put it in the benchmark would
        pass every exclusion above and measure nothing at all."""
        named = set()
        for relative in LOCKED_MATRICES:
            matrix = load(REPOSITORY / relative)
            named |= {entry['generator'] for entry in matrix['scenario']}
        for generator in withheld_generators():
            with self.subTest(generator=generator):
                self.assertIn(generator, named,
                              'a withheld family that appears in no locked corpus is '
                              'withheld from everything, including the test')

    def test_there_is_at_least_one_of_each_class(self):
        """A withheld benign family and a withheld positive family, because
        generalisation has two failure modes and one family can only measure
        one of them."""
        labels = set()
        for name in withheld_generators():
            labels.add(REGISTRY[name](name, 'g', 'withheld-check').label)
        self.assertIn('benign_like', labels)
        self.assertIn('malicious_automation_like', labels)


class TestNoFittingCorpusCanContainThem(unittest.TestCase):
    """The load-bearing assertion of this module."""

    def test_no_fitting_matrix_names_a_withheld_generator(self):
        for relative in FITTING_MATRICES:
            matrix = load(REPOSITORY / relative)
            named = {entry['generator'] for entry in matrix['scenario']}
            with self.subTest(matrix=relative):
                self.assertEqual(named & set(withheld_generators()), set(),
                                 'a withheld family in a fitting corpus makes every '
                                 'generalisation number in the final report meaningless')

    def test_no_fitting_matrix_produces_a_plan_from_the_withheld_module(self):
        """The same question asked of the built plans rather than the matrix
        text, so a generator reached through an alias or a default would still
        be caught."""
        for relative in FITTING_MATRICES:
            matrix = load(REPOSITORY / relative)
            with self.subTest(matrix=relative):
                for plan in plans(matrix):
                    self.assertFalse(
                        str(plan.parameters.get('generator', '')).startswith(
                            withheld.WITHHELD_PREFIX),
                        f'{plan.scenario_id} is built by a withheld generator')

    def test_every_matrix_in_the_repository_is_accounted_for(self):
        """A new matrix file is neither silently a fitting corpus nor silently
        exempt. Somebody has to say which it is, here, in a diff."""
        directory = REPOSITORY / 'dataset' / 'scenarios'
        found = {f'dataset/scenarios/{path.name}' for path in directory.glob('*.toml')}
        self.assertEqual(found, set(FITTING_MATRICES) | set(LOCKED_MATRICES))


class TestTheWithheldFamiliesAreNotCopiesOfSomethingAlreadyFitted(unittest.TestCase):
    """§47. A withheld family that reproduces a fitted one measures nothing.

    This cannot be checked mechanically in full — "is this behaviour new" is a
    judgement, and the docstrings in `withheld.py` are where it is argued. What
    *can* be checked is the cheap failure mode: a withheld family whose plan is
    identical to a family already in a fitting corpus, which is what a rename or
    a copy-paste produces.
    """

    def fingerprint(self, plan):
        """Behaviour only: no source address, no scenario id, no seed."""
        return tuple(sorted((round(contact.time, 3), contact.port, contact.shape,
                             len(contact.request), contact.auth)
                            for contact in plan.contacts))

    def test_no_withheld_family_reproduces_a_fitted_one(self):
        fitted = {}
        for relative in FITTING_MATRICES:
            for plan in plans(load(REPOSITORY / relative)):
                fitted[self.fingerprint(plan)] = plan.scenario_id
        for name in withheld_generators():
            plan = REGISTRY[name](name, 'g', 'withheld-check')
            with self.subTest(generator=name):
                self.assertNotIn(self.fingerprint(plan), fitted)


if __name__ == '__main__':
    unittest.main()
