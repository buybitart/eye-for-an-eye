"""Authentication outcome, end to end: generator -> parser -> ledger -> families. §5, §7, §15, §16.

Every other P15.4 test checks one component against its own contract. This one
checks that the components are *connected*, because for most of this cycle they
were not and nothing said so.

The ledger recorded authentication outcomes correctly. `families.auth_behavior`
scored them correctly. `from_samples` accepted an `auth=` argument and filled
five schema-2 columns from it. Every unit test passed. And the five columns were
`None` on every source in every code path, because no caller ever passed the
argument — so `AUTH_BEHAVIOR` scored zero on a brute force, and the entire
P15.4 thesis was inert while its parts were individually correct.

That failure is invisible to a component test by construction, so the tests here
are deliberately end-to-end: a generated capture is written to disk, read back
through the production packet parser, correlated by the production correlation
engine, and scored by the production risk engine. If any link is missing the
numbers collapse, and these assertions are what notice.

The second thing this module exists for is the *pairs*. A benign family and a
malicious family that present the same surface — credentials on every request,
repeated authentication failures, high rate — and differ only in outcome. Those
comparisons are the claim P15.4 makes, and asserting them here makes the claim
falsifiable on every commit rather than once in a report.
"""
from pathlib import Path
import tempfile
import unittest

from dataset.builder import FeatureCollector
from dataset.collectors.pcap import events as pcap_events, offline_config
from dataset.generators import benign, profiles, withheld
from dataset.generators.packets import render, write_pcap
from eye_for_an_eye.decision import auth as auth_module
from eye_for_an_eye.decision.features import applicable_names, completeness
from eye_for_an_eye.decision.math_risk import MathRiskEngine

#: One run per family. These are deterministic generators, and the assertions
#: below are about which side of a wide gap a family falls on rather than about
#: a third decimal place, so a second seed would cost time and settle nothing.
SEED = 'p15.4-wiring'


class Scored:
    """Every window of one rendered family, scored the way production scores it."""

    def __init__(self, plan, samples, engine):
        self.plan = plan
        self.samples = samples
        self.v4 = sorted(engine.evaluate(sample.features).score for sample in samples)
        self.v3 = sorted(engine.evaluate_v3(sample.features).score for sample in samples)
        self.families = set()
        for sample in samples:
            for name, value in engine.evaluate(sample.features).family_scores.items():
                if value:
                    self.families.add(name)

    @property
    def worst(self):
        """The highest score any window of this source reached.

        The maximum rather than the median, deliberately. A block is taken on one
        window, so a benign family is safe only if its *worst* window is safe,
        and an average would hide exactly the window that causes the false block.
        """
        return self.v4[-1] if self.v4 else 0.0

    @property
    def worst_v3(self):
        return self.v3[-1] if self.v3 else 0.0

    def column(self, name):
        """The last observed value of one feature, or `None` if never observed."""
        from eye_for_an_eye.decision.features import NAMES
        position = NAMES.index(name)
        seen = [sample.features.values[position] for sample in self.samples
                if sample.features.values[position] is not None]
        return seen[-1] if seen else None


_CACHE = {}


def scored(generator):
    """Render, parse, correlate and score one family. Memoised across tests."""
    if generator.__name__ in _CACHE:
        return _CACHE[generator.__name__]
    config = offline_config()
    engine = MathRiskEngine()
    plan = generator(generator.__name__, 'p15-4', SEED)
    rows, _ = render(plan)
    with tempfile.TemporaryDirectory() as directory:
        capture = Path(directory) / f'{generator.__name__}.pcap'
        write_pcap(capture, rows)
        produced, _ = pcap_events(capture, config)
    collector = FeatureCollector(config, interval=2.0, max_samples_per_source=64)
    context = {'expected_source': plan.source, 'group': plan.scenario_group,
               'dataset_version': 'p15.4-wiring', 'source_type': 'PCAP',
               'capture_group': plan.scenario_id, 'source_group': plan.scenario_id,
               'label': plan.label, 'label_source': plan.label_source,
               'label_confidence': plan.label_confidence, 'provenance': {}}
    samples = [sample for sample in
               (collector.observe(event, context) for event in produced) if sample]
    result = Scored(plan, samples, engine)
    _CACHE[generator.__name__] = result
    return result


class TestTheLedgerReachesTheFeatureVector(unittest.TestCase):
    """The wire itself. Without it every assertion below is vacuously true."""

    def test_a_source_that_fails_repeatedly_has_observed_authentication_columns(self):
        result = scored(profiles.admin_brute_force)
        self.assertTrue(result.samples, 'no windows were produced at all')
        self.assertIsNotNone(result.column('auth_failures_60s'),
                             'the authentication columns are empty, so the ledger is '
                             'not reaching from_samples')
        self.assertGreaterEqual(result.column('auth_failures_60s'), 6)
        self.assertGreaterEqual(result.column('auth_principals_900s'), 2)

    def test_the_family_the_ledger_feeds_actually_fires(self):
        self.assertIn('AUTH_BEHAVIOR', scored(profiles.admin_brute_force).families)

    def test_a_source_that_never_authenticates_has_none_in_every_authentication_column(self):
        """All five, not four. `applicable_names` treats the group as
        inapplicable only when every column is absent, so one stray zero would
        make four genuine gaps appear for every ordinary visitor."""
        for generator in (benign.web_client, profiles.asset_fetch):
            with self.subTest(generator=generator.__name__):
                result = scored(generator)
                for name in ('auth_failures_60s', 'auth_successes_60s', 'auth_failure_ratio',
                             'auth_principals_900s', 'auth_failure_span_900s'):
                    self.assertIsNone(result.column(name))

    def test_wiring_the_ledger_did_not_lower_data_quality_for_ordinary_traffic(self):
        """The regression this cost, measured directly rather than reasoned about.

        Before the conditional group was made properly absent, a plain web
        client's completeness fell from 1.00 to 0.83 the moment the ledger was
        connected — silently tightening a safety gate for the most innocent
        traffic there is.
        """
        for generator in (benign.web_client, profiles.asset_fetch):
            with self.subTest(generator=generator.__name__):
                values = scored(generator).samples[-1].features.values
                self.assertEqual(completeness(values), 1.0)
                self.assertNotIn('auth_failures_60s', applicable_names(values))
                self.assertEqual(len(applicable_names(values)), 18)


class TestAuthenticatingIsNotEvidence(unittest.TestCase):
    """§5, §15. The defect P15.3 shipped, as a permanent regression test."""

    #: A hard negative may not reach this. It is far below any cost-sensitive
    #: cutoff in `autonomy.cost` — the most block-happy profile, honeypot, sits
    #: at 0.667 — so it is a bound on the *evidence*, not a tuned threshold.
    BENIGN_CEILING = 0.30

    def test_an_authenticated_batch_client_is_not_evidence_of_anything(self):
        result = scored(profiles.authenticated_batch)
        self.assertGreater(result.column('auth_successes_60s') or 0, 20,
                           'this family is supposed to authenticate constantly')
        self.assertEqual(result.column('auth_failures_60s'), 0)
        self.assertLessEqual(result.worst, self.BENIGN_CEILING)
        self.assertNotIn('AUTH_BEHAVIOR', result.families)

    def test_the_previous_formula_scored_that_same_client_far_higher(self):
        """The point of the pair. v3 is kept runnable precisely so this
        comparison is a measurement rather than a claim in a report."""
        result = scored(profiles.authenticated_batch)
        self.assertGreater(result.worst_v3, 0.5)
        self.assertLess(result.worst, result.worst_v3 / 2)

    def test_a_high_rate_authenticated_api_client_is_not_evidence_either(self):
        result = scored(profiles.high_rate_api)
        self.assertLessEqual(result.worst, self.BENIGN_CEILING)
        self.assertNotIn('AUTH_BEHAVIOR', result.families)

    def test_a_signed_webhook_callback_is_not_evidence_for_being_regular(self):
        result = scored(profiles.signed_webhook)
        self.assertLessEqual(result.worst, self.BENIGN_CEILING)
        self.assertNotIn('AUTH_BEHAVIOR', result.families)

    def test_an_administrator_working_by_hand_is_not_evidence(self):
        result = scored(profiles.admin_console)
        self.assertLessEqual(result.worst, self.BENIGN_CEILING)


class TestFailureAloneIsNotEvidenceEither(unittest.TestCase):
    """§16. The over-correction, which is the easy mistake to make next.

    Having established that credential presence says nothing, the tempting move
    is to count failures instead. These two families are why that is also wrong:
    real people and real services fail to authenticate, in small numbers, and
    then succeed.
    """

    def test_one_administrator_mistyping_a_password_is_not_a_brute_force(self):
        result = scored(profiles.admin_login_mistakes)
        self.assertGreaterEqual(result.column('auth_failures_60s'), 2,
                                'this family is supposed to fail a few times')
        self.assertEqual(result.column('auth_principals_900s'), 1)
        self.assertLessEqual(result.worst, TestAuthenticatingIsNotEvidence.BENIGN_CEILING)

    def test_a_service_token_expiring_twice_is_not_sustained_failure(self):
        """The span term, which read "300 seconds of sustained failure" from two
        refusals ten minutes apart and took this family to 0.580 on its own."""
        result = scored(profiles.service_account)
        self.assertEqual(result.column('auth_principals_900s'), 1)
        self.assertEqual(result.column('auth_failure_span_900s'), 0.0,
                         'a span needs enough refusals to be a span')
        self.assertLessEqual(result.worst, TestAuthenticatingIsNotEvidence.BENIGN_CEILING)

    def test_a_job_retrying_an_old_password_is_not_a_brute_force(self):
        """The likeliest false positive in the whole authentication design.

        A scheduled job whose credential was rotated and whose config file was
        not updated fails every time, at a machine interval, for as long as
        nobody notices. It has sustained refusals, a long failure span and
        perfect regularity — every surface property of a slow brute force. The
        one thing it does not have is a second account.

        Against the failure-span term ungated it scored **0.784**: higher than
        any other benign source in the development corpus, and higher than
        several real attacks. That is `credentials_60s` again, one layer along.
        """
        result = scored(profiles.stale_credential_client)
        self.assertGreaterEqual(result.column('auth_failure_ratio'), 1.0,
                                'this family is supposed to fail every time')
        self.assertEqual(result.column('auth_principals_900s'), 1)
        self.assertLessEqual(result.worst, TestAuthenticatingIsNotEvidence.BENIGN_CEILING)
        self.assertNotIn('AUTH_BEHAVIOR', result.families)

    def test_the_failure_span_needs_more_than_one_account_to_speak(self):
        """Stated as the mechanism rather than the score, so the test still fails
        if the gate is removed and some unrelated change happens to keep the
        stuck client quiet."""
        walk = scored(profiles.patient_account_walk)
        stuck = scored(profiles.stale_credential_client)
        self.assertGreaterEqual(walk.column('auth_principals_900s'), 2)
        self.assertEqual(stuck.column('auth_principals_900s'), 1)
        self.assertGreater(walk.column('auth_failure_span_900s'), 60)
        self.assertGreater(stuck.column('auth_failure_span_900s'), 60,
                           'the stuck client must still HAVE a long span — the point '
                           'is that the span is not allowed to speak alone')

    def test_a_span_is_only_reported_once_it_has_a_denominator(self):
        """Stated against the constant rather than the number, so the two places
        that gate on it cannot drift apart."""
        self.assertEqual(auth_module.MIN_FAILURES_FOR_A_DERIVED_STATISTIC, 6)

    def test_unobservable_outcomes_are_not_treated_as_failure(self):
        """§7. `mobile_app_sync` attempts authentication constantly and the
        sensor cannot see the outcome of a third of those attempts."""
        result = scored(withheld.mobile_app_sync)
        self.assertGreater(result.column('auth_successes_60s') or 0, 0)
        self.assertEqual(result.column('auth_failures_60s'), 0)
        self.assertLessEqual(result.worst, TestAuthenticatingIsNotEvidence.BENIGN_CEILING)


class TestRepeatedRefusalIsEvidence(unittest.TestCase):
    """The other half. A system safe for every benign family and blind to every
    attack is not safe, it is switched off."""

    #: What a positive must clear. Chosen as "clearly above every benign family
    #: measured here", not as a decision threshold: what a score of 0.5 means for
    #: action is settled by calibration and the cost-sensitive cutoff, neither of
    #: which this module touches.
    POSITIVE_FLOOR = 0.5

    def test_a_credential_spray_across_many_accounts_is_evidence(self):
        result = scored(profiles.api_credential_spray)
        self.assertGreaterEqual(result.column('auth_principals_900s'), 8)
        self.assertGreaterEqual(result.worst, self.POSITIVE_FLOOR)
        self.assertIn('AUTH_BEHAVIOR', result.families)

    def test_a_brute_force_against_the_management_interface_is_evidence(self):
        result = scored(profiles.admin_brute_force)
        self.assertGreaterEqual(result.worst, self.POSITIVE_FLOOR)

    def test_credential_stuffing_is_evidence_even_without_principal_diversity(self):
        """Over HTTP the account name is inside a value `decision/auth.py`
        refuses to read, so this positive has to be carried by failure volume
        alone. It is the measure of what that refusal costs."""
        result = scored(profiles.login_stuffing)
        self.assertEqual(result.column('auth_principals_900s'), 0,
                         'an Authorization header must not yield a principal')
        self.assertGreaterEqual(result.worst, self.POSITIVE_FLOOR)

    def test_a_patient_account_walk_is_evidence_despite_having_no_rate(self):
        """§68. One failure every forty seconds: nothing in a sixty-second window
        is remarkable, and only the long view shows fourteen accounts refused."""
        result = scored(profiles.patient_account_walk)
        self.assertLessEqual(result.column('auth_failures_60s'), 3,
                             'if this has a short-window rate it is not low-and-slow')
        self.assertGreaterEqual(result.worst, self.POSITIVE_FLOOR)

    def test_the_previous_formula_could_not_see_the_patient_walk_at_all(self):
        result = scored(profiles.patient_account_walk)
        self.assertLess(result.worst_v3, 0.1)


class TestThePairsDoNotOverlap(unittest.TestCase):
    """The summary claim, stated as one assertion per profile.

    Under v3 the benign member of the api pair scored *higher* than four of the
    five positives. Under v4 the classes have to separate, and separation is a
    property of the pair rather than of either family alone.
    """

    PAIRS = (('api', profiles.authenticated_batch, profiles.api_credential_spray),
             ('api', profiles.service_account, profiles.patient_account_walk),
             ('admin', profiles.admin_login_mistakes, profiles.admin_brute_force),
             ('public_website', profiles.asset_fetch, profiles.login_stuffing),
             ('withheld', withheld.mobile_app_sync, withheld.probe_then_login))

    def test_every_positive_outscores_its_benign_twin(self):
        for profile, benign_family, positive in self.PAIRS:
            with self.subTest(profile=profile, benign=benign_family.__name__):
                self.assertGreater(scored(positive).worst,
                                   scored(benign_family).worst + 0.3)

    def test_the_api_pair_was_inverted_under_the_previous_formula(self):
        """Not a nice-to-have: it is the defect P15.4 exists to fix, and a
        version of this suite that only checked v4 could not tell a fix from a
        family that was never hard."""
        self.assertGreater(scored(profiles.authenticated_batch).worst_v3,
                           scored(profiles.patient_account_walk).worst_v3)


if __name__ == '__main__':
    unittest.main()
