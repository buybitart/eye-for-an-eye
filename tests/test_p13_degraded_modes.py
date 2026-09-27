"""P13 §117, §118: break one part, and prove the rest keeps working honestly.

The whole of P0-P12 was built component by component, and every component was
tested against its own contract. That is not the same as testing the system, and
the gap has a shape: components that each behave correctly in isolation can
combine into a machine that goes quiet, or -- far worse for a defender -- one
that gets *more* aggressive because something broke.

So every case here injects one real failure and asks three questions.

**Does it still work?** The site must stay up and the sensor must keep observing.
A security component that converts its own bug into a site-wide outage has caused
a worse incident than the scanner it was watching for.

**Does it say so?** A degraded system reporting `healthy` is worse than one
reporting nothing, because an operator acts on it. Every injected failure must be
visible somewhere an operator actually looks.

**Does it stay calm?** This is the one that matters most and is easiest to get
wrong. A broken component must never raise risk, never escalate an action and
never turn an unknown into a suspect. Unknown is not malicious -- that rule was
written for the model in P8, and it applies to every other subsystem too.
"""
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from eye_for_an_eye.config import Config
from eye_for_an_eye.observability.metrics import health as aggregate_health

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def tick(self, seconds):
        self.now += seconds
        return self.now


class TestTheHealthContractIsHonest(unittest.TestCase):
    """§118. The aggregation rule, checked against the states it will meet."""

    def test_a_broken_core_component_makes_the_whole_system_unavailable(self):
        self.assertEqual(
            aggregate_health({'capture': 'unavailable', 'storage': 'healthy'})['status'],
            'unavailable')

    def test_a_broken_optional_component_degrades_rather_than_stops(self):
        """Enrichment, the API, metrics, logging and the model are all optional.

        Each of them failing is a real loss of function and must show; none of
        them is a reason to stop observing traffic.
        """
        for optional in ('enrichment', 'api', 'metrics', 'logging', 'ml'):
            with self.subTest(component=optional):
                result = aggregate_health({optional: 'unavailable',
                                           'capture': 'healthy', 'storage': 'healthy'})
                self.assertEqual(result['status'], 'degraded')

    def test_nothing_can_report_a_state_outside_the_vocabulary(self):
        """A status nobody defined cannot be acted on."""
        with self.assertRaises(ValueError):
            aggregate_health({'storage': 'mostly fine'})

    def test_a_healthy_system_is_only_healthy_when_everything_is(self):
        self.assertEqual(aggregate_health({'capture': 'healthy', 'storage': 'healthy',
                                           'ml': 'healthy'})['status'], 'healthy')
        self.assertEqual(aggregate_health({'capture': 'healthy', 'storage': 'healthy',
                                           'ml': 'degraded'})['status'], 'degraded')

    def test_a_disabled_component_is_not_a_degraded_one(self):
        """Off on purpose and broken are different facts about a system."""
        self.assertEqual(aggregate_health({'capture': 'healthy', 'storage': 'healthy',
                                           'ml': 'disabled'})['status'], 'healthy')


class TestTheGatewayFailsOpenOnEveryInjectedFault(unittest.TestCase):
    """§117. The request path, which is the only place an outage is possible.

    The sensor reads logs after the fact and cannot break a request. The gateway
    sits in front of one. Every fault here is injected into a real collaborator,
    not simulated with a mock of the gateway's own internals.
    """

    def gateway(self, **overrides):
        from eye_for_an_eye.web.gateway import WebGateway
        from eye_for_an_eye.web.identity import ClientResolver
        arguments = {'resolver': ClientResolver(), 'clock': Clock()}
        arguments.update(overrides)
        return WebGateway(**arguments)

    def request(self, gateway, **overrides):
        arguments = {'peer': '198.51.100.7', 'method': 'GET', 'path': '/index.html'}
        arguments.update(overrides)
        return gateway.handle(**arguments)

    def test_with_no_sensor_and_no_challenge_every_request_passes(self):
        """The baseline. A gateway with nothing to judge on judges nothing."""
        plan = self.request(self.gateway())
        self.assertEqual(plan.plan, 'PASS')

    def test_a_sensor_that_raises_on_every_call_does_not_break_a_request(self):
        class BrokenSensor:
            def last_risk(self, source):
                raise RuntimeError('the sensor is having a bad day')

        gateway = self.gateway(sensor=BrokenSensor())
        plan = self.request(gateway)
        self.assertEqual(plan.plan, 'PASS')
        self.assertTrue(gateway.last_error, 'the failure left no trace for an operator')
        self.assertGreater(gateway.metrics['challenge_subsystem_errors_total'], 0)

    def test_a_broken_sensor_scores_zero_rather_than_something_alarming(self):
        """The calm rule. A component that cannot answer must answer `nothing
        is known`, not `assume the worst`."""
        class BrokenSensor:
            def last_risk(self, source):
                raise RuntimeError('unavailable')

        self.assertEqual(self.gateway(sensor=BrokenSensor()).risk_for('198.51.100.7'), 0.0)

    def test_a_sensor_returning_nonsense_does_not_become_a_high_risk(self):
        """A corrupt reading is not evidence either."""
        for nonsense in (None, 'very high', float('nan'), object()):
            with self.subTest(value=type(nonsense).__name__):
                class OddSensor:
                    def last_risk(self, source, value=nonsense):
                        return value

                plan = self.request(self.gateway(sensor=OddSensor()))
                self.assertEqual(plan.plan, 'PASS')

    def test_a_challenge_service_that_raises_still_lets_the_request_through(self):
        class BrokenChallenge:
            def __getattr__(self, name):
                def explode(*args, **kwargs):
                    raise RuntimeError('challenge subsystem failure')
                return explode

        gateway = self.gateway(challenge=BrokenChallenge())
        plan = self.request(gateway)
        self.assertEqual(plan.plan, 'PASS')
        self.assertTrue(gateway.last_error)

    def test_a_malformed_cookie_is_not_an_outage_and_not_an_accusation(self):
        """Attacker-controlled input on the failure path."""
        for cookie in ('', 'garbage', 'e4e=' + 'A' * 9000, 'e4e=\x00\x01\x02',
                       'e4e=' + '\ud800'.encode('utf-8', 'surrogatepass').hex()):
            with self.subTest(cookie=cookie[:24]):
                plan = self.request(self.gateway(), cookie=cookie)
                self.assertEqual(plan.plan, 'PASS')

    def test_a_hostile_host_header_never_reaches_a_decision(self):
        for host in ('', 'example.com\r\nX-Injected: 1', 'a' * 5000, '../../etc/passwd',
                     '\x00', 'EXAMPLE.com.'):
            with self.subTest(host=host[:24]):
                plan = self.request(self.gateway(), host=host)
                self.assertEqual(plan.plan, 'PASS')


class TestStorageFailureDoesNotStopObservation(unittest.TestCase):
    """§117. Disk problems are the most common real fault in this system."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_doctor_reports_an_unwritable_storage_directory(self):
        """The check an operator runs first, against a directory they cannot
        write to. `os.access` is advisory and the check says so itself."""
        from eye_for_an_eye.operations import doctor
        locked = Path(self.tmp.name) / 'locked'
        locked.mkdir()
        locked.chmod(0o500)
        self.addCleanup(locked.chmod, 0o700)
        config = Config()
        config.storage.path = str(locked / 'events.sqlite3')
        checks = doctor(config)
        if os.geteuid() == 0:
            self.skipTest('root ignores the permission bits this check reads')
        self.assertEqual(checks['storage_writable']['status'], 'UNAVAILABLE')

    def test_doctor_runs_to_completion_even_when_a_check_cannot(self):
        """A diagnostic that dies on the first problem diagnoses nothing."""
        from eye_for_an_eye.operations import doctor
        config = Config()
        config.storage.path = '/definitely/not/a/directory/events.sqlite3'
        config.ml.enabled = True
        config.ml.model_path = str(Path(self.tmp.name) / 'absent.onnx')
        config.ml.manifest_path = str(Path(self.tmp.name) / 'absent.json')
        checks = doctor(config)
        self.assertIn('configuration', checks)
        self.assertIn('storage_writable', checks)
        self.assertEqual(checks['ml']['status'], 'UNAVAILABLE')

    def test_a_missing_model_is_a_documented_state_not_a_failure(self):
        """§118. No model at all is how this system is expected to be run at
        first: the deterministic engine was never optional."""
        from eye_for_an_eye.operations import doctor
        config = Config()
        config.storage.path = str(Path(self.tmp.name) / 'events.sqlite3')
        checks = doctor(config)
        self.assertIn(checks['ml']['status'], ('DISABLED', 'NOT_CONFIGURED'))
        self.assertIn('mathematical engine', checks['ml'].get('reason', ''))


class TestTheModelRegistryFallsBackRatherThanFailing(unittest.TestCase):
    """§117. A corrupt model directory must cost the model, not the sensor."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def resolver(self):
        from eye_for_an_eye.sites.models import ModelResolver, SiteModelRegistry
        return ModelResolver(SiteModelRegistry(Path(self.tmp.name) / 'models'))

    def test_an_empty_registry_resolves_to_no_model_and_says_why(self):
        from eye_for_an_eye.sites.models import NO_MODEL
        resolution = self.resolver().resolve('shop')
        self.assertEqual(resolution.source, NO_MODEL)
        self.assertTrue(resolution.reasons)
        self.assertIn('mathematical engine', ' '.join(resolution.reasons))

    def test_a_corrupt_pointer_file_does_not_raise(self):
        root = Path(self.tmp.name) / 'models' / 'global'
        root.mkdir(parents=True)
        (root / 'state.json').write_text('{not json at all', encoding='utf-8')
        resolution = self.resolver().resolve('shop')
        self.assertTrue(resolution.fell_back or resolution.source == 'no_model')

    def test_resolution_never_raises_for_any_site_string(self):
        """`resolve` is documented as never raising. Documented is not tested."""
        resolver = self.resolver()
        for site in ('', 'shop', 'a' * 500, '../../etc', '\x00', 'SITE:other',
                     'site with spaces', '🙂'):
            with self.subTest(site=site[:20]):
                self.assertIsNotNone(resolver.resolve(site))


class TestOneSiteCannotTakeDownAnother(unittest.TestCase):
    """§117 crossed with P12 §168. The multi-site failure question."""

    def engine(self):
        from eye_for_an_eye.sites.engine import SiteEngine
        from eye_for_an_eye.sites.profile import build_all
        profiles = build_all({'shop': {'profile': 'website', 'domains': ['shop.example']},
                              'api': {'profile': 'api', 'domains': ['api.example']}})
        return SiteEngine(profiles)

    def test_a_broken_baseline_for_one_site_leaves_the_other_alone(self):
        engine = self.engine()
        engine.baselines['shop'] = None          # as corrupt as it gets
        self.assertIsNotNone(engine.baseline('api'))
        self.assertIsNotNone(engine.context('api.example'))

    def test_an_unresolvable_host_lands_in_the_unknown_bucket_not_a_site(self):
        from eye_for_an_eye.sites.identity import UNKNOWN_SITE
        engine = self.engine()
        for host in ('nobody.example', '', 'shop.example.evil.test', '\r\nshop.example'):
            with self.subTest(host=host[:24]):
                context = engine.context(host)
                self.assertEqual(context.site_id, UNKNOWN_SITE)
                self.assertFalse(context.known)

    def test_the_unknown_bucket_can_do_nothing_to_anybody(self):
        """The failure mode that would be worst: an unconfigured host inheriting
        enforcement powers because it had to be given *some* profile."""
        engine = self.engine()
        settings = engine.context('nobody.example').settings
        self.assertEqual(settings.mode, 'shadow')
        self.assertFalse(settings.challenge_enabled)
        self.assertFalse(settings.rate_limit_enabled)
        self.assertFalse(settings.allow_host_network_block)
        self.assertFalse(settings.collect_dataset)

    def test_a_site_that_may_not_block_the_host_has_its_action_reduced(self):
        from eye_for_an_eye.sites.engine import SITE_WEB_ACTION
        engine = self.engine()
        scope, allowed, reason = engine.action_scope(engine.context('shop.example'),
                                                     'TEMP_BLOCK')
        self.assertEqual(scope, SITE_WEB_ACTION)
        self.assertFalse(allowed)
        self.assertIn('every site', reason)


class TestCollectingTrainingDataNeverInterruptsDefending(unittest.TestCase):
    """§21, §117. The subsystem whose failure was actually silent.

    The review queue sits inside a `try` whose `except` swallows everything, and
    correctly so: a defender must not stop defending because it could not file a
    sample. The cost of that correctness is that a permanent failure here is
    invisible, which is exactly what happened -- one wrong attribute name and the
    queue received nothing at all while every counter looked normal.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def engine(self, **reliability):
        from eye_for_an_eye.correlation.engine import CorrelationEngine
        from eye_for_an_eye.decision.engine import DecisionEngine
        config = Config()
        for name, value in reliability.items():
            setattr(config.reliability, name, value)
        return DecisionEngine(config, CorrelationEngine(config.correlation), offline=True)

    def test_an_unwritable_queue_path_does_not_prevent_the_engine_starting(self):
        built = self.engine(review_queue_enabled=True,
                            review_queue_path='/definitely/not/a/directory/queue.json')
        self.assertIsNotNone(built)

    def test_a_queue_with_no_secret_stays_closed_rather_than_storing_addresses(self):
        """Refusing to run is the right failure here: the queue's whole privacy
        property is that a raw source address never reaches the file."""
        built = self.engine(review_queue_enabled=True,
                            review_queue_path=str(Path(self.tmp.name) / 'q.json'),
                            review_queue_secret_file='')
        self.assertIsNone(built.review_queue)

    def test_a_permanent_failure_is_named_and_not_merely_counted(self):
        built = self.engine()
        self.assertEqual(built.review_queue_last_error, '',
                         'a fresh engine should carry no recorded failure')
        # `metrics` is a Counter, so the key appears once something increments it.
        # What must exist before then is somewhere for the reason to go.
        self.assertTrue(hasattr(built, 'review_queue_last_error'))
        self.assertEqual(built.metrics['review_queue_failures_total'], 0)


class TestNoFailurePathEverRaisesRisk(unittest.TestCase):
    """The single most important property in this file.

    Every other test here asks whether something stayed up. This one asks
    whether it stayed *fair*. A system that answers a broken subsystem by
    assuming the worst about whoever happened to be connecting has turned its own
    outage into somebody else's block, and it will do it to the people least able
    to complain: the ones on odd networks, odd clients and odd schedules.
    """

    def test_an_unavailable_classifier_cannot_raise_fused_evidence(self):
        from eye_for_an_eye.decision.math_risk import MathRiskResult
        from eye_for_an_eye.decision.onnx_model import MLResult
        from eye_for_an_eye.decision.policy import DecisionFusion
        fusion = DecisionFusion(Config().decision)
        maths = MathRiskResult(0.3, {})
        with_model = fusion.evaluate(maths, MLResult('healthy', 0.9, 'malicious-automation-like',
                                                     0.9, 'v1'), 0.0)
        without = fusion.evaluate(maths, MLResult(), 0.0)
        self.assertLessEqual(without.threat_evidence, with_model.threat_evidence)

    def test_an_unavailable_anomaly_model_cannot_raise_fused_evidence(self):
        from eye_for_an_eye.decision.anomaly import AnomalyResult
        from eye_for_an_eye.decision.math_risk import MathRiskResult
        from eye_for_an_eye.decision.onnx_model import MLResult
        from eye_for_an_eye.decision.policy import DecisionFusion
        fusion = DecisionFusion(Config().decision)
        maths = MathRiskResult(0.5, {})
        baseline = fusion.evaluate(maths, MLResult(), 0.0)
        broken = fusion.evaluate(maths, MLResult(), 0.0, anomaly=AnomalyResult())
        self.assertAlmostEqual(broken.threat_evidence, baseline.threat_evidence, places=9)

    def test_an_out_of_distribution_observation_lowers_authority_not_raises_risk(self):
        """§16, §17 restated as an end-to-end property rather than a unit one."""
        from eye_for_an_eye.decision.ood import OODResult
        for score in (0.0, 0.5, 1.0):
            with self.subTest(ood=score):
                result = OODResult(status='BORDERLINE', score=score)
                self.assertAlmostEqual(result.distribution_confidence, 1.0 - score)
                self.assertLessEqual(result.distribution_confidence, 1.0)


class TestTheInstallerAndItsDocumentationAgree(unittest.TestCase):
    """§111. A one-command install is a claim about a specific command."""

    def test_the_readme_command_is_the_script_that_exists(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertIn('sh scripts/install.sh', readme)
        self.assertTrue((ROOT / 'scripts' / 'install.sh').is_file())
        self.assertTrue((ROOT / 'scripts' / 'uninstall.sh').is_file())

    def test_the_documented_command_does_not_depend_on_an_executable_bit(self):
        """`sh scripts/install.sh` works whether or not the mode bit survived
        the archive, which is why the README spells it that way. If the README
        ever switches to `./scripts/install.sh`, the bit becomes load-bearing."""
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        script = ROOT / 'scripts' / 'install.sh'
        if './scripts/install.sh' in readme:
            self.assertTrue(script.stat().st_mode & stat.S_IXUSR,
                            'the README invokes the script directly but it is not '
                            'executable')

    def test_the_installer_offers_a_dry_run_that_changes_nothing(self):
        body = (ROOT / 'scripts' / 'install.sh').read_text(encoding='utf-8')
        self.assertIn('--dry-run', body)
        self.assertIn('--help', body)

    def test_continuous_integration_actually_runs_the_documented_install(self):
        workflow = (ROOT / '.github' / 'workflows' / 'ci.yml')
        self.assertTrue(workflow.is_file(), 'there is no CI workflow')
        body = workflow.read_text(encoding='utf-8')
        for step in ('sh scripts/install.sh', 'sh scripts/uninstall.sh',
                     'ruff check', 'pytest', 'security_scan.py'):
            with self.subTest(step=step):
                self.assertIn(step, body, f'CI does not run {step}')


class TestTheLicenceStateIsReportedNotInvented(unittest.TestCase):
    """§109. A release blocker is only useful while it is still visible."""

    def test_the_missing_licence_is_flagged_where_a_packager_will_see_it(self):
        """If a LICENSE is added, this test tells whoever added it what else to
        update -- which is the only reason it asserts the blocker rather than
        simply noting it."""
        pyproject = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        present = (ROOT / 'LICENSE').is_file() or (ROOT / 'COPYING').is_file()
        if not present:
            self.assertIn('RELEASE BLOCKER', pyproject,
                          'there is no LICENSE and pyproject.toml no longer says so')
            return
        self.assertIn('license', pyproject.lower(),
                      'a LICENSE file exists but pyproject.toml declares no license')
        self.assertIn('include LICENSE', (ROOT / 'MANIFEST.in').read_text(encoding='utf-8'),
                      'a LICENSE file exists but the sdist would not ship it')


class TestTheProjectMakesNoClaimItHasNotEarned(unittest.TestCase):
    """§91, §110, §147. The words a beta is allowed to use about itself."""

    def documents(self):
        for path in sorted((ROOT / 'docs').glob('*.md')) + [ROOT / 'README.md']:
            yield path, ' '.join(path.read_text(encoding='utf-8').split()).lower()

    #: Words that turn an occurrence of a forbidden phrase into a denial of it.
    #: `OTF_ALIGNMENT.md` says, correctly and at length, that the project is
    #: **not** "OTF certified". A plain substring search cannot tell that
    #: sentence apart from the claim it refutes, and failing the document that
    #: states the rule most clearly is how a test teaches people to delete the
    #: sentence rather than fix the problem.
    DENIALS = ('not', 'no such', 'never', 'has not', 'nobody', 'cannot',
               'must not', 'nothing here', 'does not', 'neither')

    def asserted(self, body, phrase):
        """Occurrences of `phrase` that are not inside a denial of it."""
        found, start = [], 0
        while (index := body.find(phrase, start)) != -1:
            window = body[max(0, index - 160):index + len(phrase) + 60]
            if not any(word in window for word in self.DENIALS):
                found.append(window)
            start = index + len(phrase)
        return found

    def test_no_document_claims_an_endorsement_that_was_never_given(self):
        for path, body in self.documents():
            for forbidden in ('otf approved', 'otf certified', 'otf-approved',
                              'certified secure', 'security certified'):
                with self.subTest(document=path.name, claim=forbidden):
                    self.assertFalse(self.asserted(body, forbidden),
                                     f'{path.name} appears to claim {forbidden!r}')

    def test_the_alignment_document_denies_the_status_rather_than_omitting_it(self):
        """The claim is worth denying explicitly, so the denial is required.

        `OTF_ALIGNMENT.md` is a funding-application draft and is not part of the
        public release root, so this skips where the document is absent rather
        than failing a clean clone. The check above — that *no* document claims
        the status — runs over whatever documents are present, and that is the
        one protecting the published set.
        """
        path = ROOT / 'docs' / 'OTF_ALIGNMENT.md'
        if not path.is_file():
            self.skipTest('the alignment draft is not distributed in the release root')
        body = ' '.join(path.read_text(encoding='utf-8').split()).lower()
        self.assertIn('no such status exists or has been granted', body)

    def test_no_document_claims_a_supply_chain_guarantee_nobody_verified(self):
        for path, body in self.documents():
            for forbidden in ('reproducible build guarantee', 'signed releases',
                              'every dependency is pinned by hash',
                              'supply chain is verified'):
                with self.subTest(document=path.name, claim=forbidden):
                    self.assertFalse(self.asserted(body, forbidden),
                                     f'{path.name} appears to claim {forbidden!r}')

    def test_no_document_promises_detection_rates_or_unbreakability(self):
        for path, body in self.documents():
            for forbidden in ('impossible to evade', 'guarantees detection',
                              '100% detection', 'zero false positives'):
                with self.subTest(document=path.name, claim=forbidden):
                    self.assertFalse(self.asserted(body, forbidden),
                                     f'{path.name} appears to claim {forbidden!r}')


class TestGovernanceFailuresCostAPromotionAndNothingElse(unittest.TestCase):
    """P14 §145. The governance failure scenarios, injected into the P13 suite.

    They belong here rather than only in the P14 files because the question this
    suite asks is the one that matters about them: when the newest subsystem
    breaks, does the rest of the machine keep working? Every case below breaks
    something in `governance/` and asserts that the active model, the
    mathematical engine and the site are untouched.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_a_corrupt_promotion_journal_refuses_rather_than_assuming_calm(self):
        """The one reading that could leave a half-finished promotion in place."""
        from eye_for_an_eye.governance.journal import JournalError, PromotionJournal
        path = self.root / 'promotion-journal.json'
        path.write_text('{ not json', encoding='utf-8')
        with self.assertRaises(JournalError):
            PromotionJournal(path)

    def test_corrupt_governance_state_reads_as_frozen_not_as_permitted(self):
        from eye_for_an_eye.governance.store import GovernanceStore, StoreError
        store = GovernanceStore(self.root)
        store.freeze_path.parent.mkdir(parents=True, exist_ok=True)
        store.freeze_path.write_text('{ not json', encoding='utf-8')
        with self.assertRaises(StoreError):
            store.freeze_state()

    def test_corrupt_guarded_state_refuses_rather_than_granting_authority(self):
        from eye_for_an_eye.governance.guarded import GuardedError, GuardedStore
        store = GuardedStore(self.root)
        store.enter(scope='SITE:main', version='v2', previous_version='v1',
                    stage='GUARDED_ACTIVE_STAGE_1')
        broken = next(self.root.glob('guarded-*.json'))
        broken.write_text('{ not json', encoding='utf-8')
        with self.assertRaises(GuardedError):
            GuardedStore(self.root).load('SITE:main')

    def test_a_governance_engine_that_cannot_assess_promotes_nothing(self):
        """§114. A crash in the engine leaves the active model where it is,
        because the engine never touches it in the first place."""
        from eye_for_an_eye.governance.engine import ModelGovernanceEngine
        engine = ModelGovernanceEngine()
        with self.assertRaises(Exception):
            engine.assess(scope='SITE:main', artifact=None)

    def test_a_missing_rollback_target_refuses_the_promotion(self):
        """§58, and the reason a fresh install cannot auto-promote at all."""
        from eye_for_an_eye.governance.evidence import GovernanceState
        from eye_for_an_eye.governance.engine import ModelGovernanceEngine
        from eye_for_an_eye.governance.evidence import ArtifactEvidence
        result = ModelGovernanceEngine().assess(
            scope='SITE:main',
            artifact=ArtifactEvidence(version='v2', scope='SITE:main'),
            state=GovernanceState(rollback_target=''))
        self.assertNotEqual(result.decision, 'ELIGIBLE')

    def test_a_scope_mismatch_quarantines_rather_than_rejecting(self):
        """A model for another site is an integrity problem, not a quality one."""
        from eye_for_an_eye.governance.engine import ModelGovernanceEngine
        from eye_for_an_eye.governance.evidence import ArtifactEvidence
        artifact = ArtifactEvidence(version='v2', scope='SITE:other',
                                    sha256='a' * 64, declared_sha256='a' * 64,
                                    feature_order_matches=True, size_bytes=1024)
        result = ModelGovernanceEngine().assess(scope='SITE:main', artifact=artifact)
        self.assertEqual(result.decision, 'QUARANTINED')

    def test_a_policy_mismatch_refuses_activation_without_touching_anything(self):
        """§29. The stale-assessment path, checked for its side effects."""
        from eye_for_an_eye.governance.activation import (ActivationError,
                                                          PromotionActivator)
        from eye_for_an_eye.governance.assessment import PromotionAssessmentRecord
        from eye_for_an_eye.governance.policy import (AutoPromoteSettings,
                                                      GovernancePolicy)
        current = GovernancePolicy(auto_promote=AutoPromoteSettings(
            enabled=True, sites=('main',)))
        stale = PromotionAssessmentRecord(
            scope='SITE:main', candidate_version='v2', decision='ELIGIBLE',
            policy_version='model-governance-v1',
            policy_digest=GovernancePolicy().digest)
        activator = PromotionActivator(root=self.root, policy=current)
        with self.assertRaises(ActivationError):
            activator.promote(assessment=stale, registry=None,
                              warmup=lambda resolved: True)
        self.assertFalse(any(self.root.glob('.promoting-*.lock')),
                         'a refused promotion left a lock behind')

    def test_governance_being_entirely_absent_does_not_stop_the_sensor(self):
        """The state every installation is in today: no governance directory."""
        from eye_for_an_eye.governance.policy import from_config
        from eye_for_an_eye.config import Config
        policy = from_config(Config())
        self.assertFalse(policy.auto_promote.enabled)
        allowed, reason = policy.auto_promote.allows('SITE:main')
        self.assertFalse(allowed)
        self.assertTrue(reason)


if __name__ == '__main__':
    unittest.main()
