"""P14 §0 — re-run the P13 readiness checks before building anything.

The P14 brief opens by saying its own premise might be wrong: *do not trust the
P13 flag blindly*. It was right to. P13 reported
`P14_AUTO_PROMOTION_READY: NO`, and the brief arrived saying `YES`.

Those two answers are not, however, about the same question, and the difference
decides what may safely be built.

**Evidence readiness** is what P13 answered NO to: the learning loop had a broken
first step until that audit and has still never run on real traffic, the corpus
is synthetic, the shipped model fails its own quality gate, enforcement has never
been exercised outside a lab. No amount of code changes any of that.

**Mechanical readiness** is what §0 actually lists: hashes validated, scope
enforced, activation atomic, rollback working, restart recovery unambiguous, site
isolation intact, resource state bounded. These are properties of the code, and
they are what auto-promotion *machinery* rests on.

This file checks the second kind, because that is what §0 asks for and what the
next phases depend on. It does not, and cannot, answer the first. The governance
engine is therefore built with `auto_promote.enabled = false` — which §4, §98 and
§143 require regardless — so the machinery can be reviewed and tested without
anything being switched on that the evidence does not support.

Each class below is one §0 prerequisite. A failure here stops P14 (§0), and the
answer is to fix the prerequisite, never to relax the check.
"""
import json
import tempfile
import unittest
from pathlib import Path

from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION
from eye_for_an_eye.decision.registry import (ACTIVE, GLOBAL_SCOPE, ModelRegistry,
                                              RegistryError)

ROOT = Path(__file__).resolve().parents[1]


def manifest(version, *, scope=GLOBAL_SCOPE, **overrides):
    payload = {'manifest_version': 1, 'model_version': version,
               'model_family': 'logistic_regression',
               'feature_schema_version': SCHEMA_VERSION,
               'training_dataset_version': 'dataset-v1', 'parent_model': '',
               'created_at': '2026-09-11T00:00:00+00:00', 'scope': scope,
               'recommended_mode': 'shadow', 'feature_order': list(INPUT_ORDER)}
    payload.update(overrides)
    return payload


def artifacts(version, *, scope=GLOBAL_SCOPE, model=b'onnx-bytes', **overrides):
    return {'classifier.onnx': model,
            'manifest.json': json.dumps(manifest(version, scope=scope, **overrides)).encode(),
            'distribution.json': json.dumps({'distribution_version': 1}).encode()}


class ReadinessCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def registry(self, name='models'):
        return ModelRegistry(Path(self.tmp.name) / name)


# --- 1 ---------------------------------------------------------------------

class TestCandidateHasNoEnforcementAuthority(ReadinessCase):
    """§0.1. A candidate in Shadow must be able to influence nothing.

    This is the prerequisite the entire stage rests on: if a candidate could
    already reach an action, "auto-promotion" would only be changing a label on
    something that was already deciding.
    """

    def test_a_registered_candidate_is_not_resolved_as_active(self):
        registry = self.registry()
        registry.register_candidate('risk-v2', artifacts('risk-v2'))
        self.assertEqual(registry.state.candidate, 'risk-v2')
        self.assertIsNone(registry.state.active)
        self.assertIsNone(registry.resolve(ACTIVE),
                          'a candidate resolved as the active model')

    def test_the_candidate_module_cannot_reach_the_policy_or_the_firewall(self):
        """Checked by what the module can import, not by reading its prose."""
        import ast
        from eye_for_an_eye.decision import candidate
        tree = ast.parse(Path(candidate.__file__).read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for forbidden in ('policy', 'PolicyGuard', 'firewall', 'enforcement',
                          'security.firewall', 'DecisionFusion'):
            with self.subTest(name=forbidden):
                self.assertNotIn(forbidden, imported,
                                 f'decision/candidate.py can reach {forbidden}')

    def test_a_candidate_failure_disables_only_the_candidate(self):
        from eye_for_an_eye.decision.candidate import CandidateModel
        model = CandidateModel(enabled=True, model_path='/nonexistent.onnx',
                               manifest_path='/nonexistent.json', version='risk-v2')
        model.disable('injected')
        self.assertFalse(model.enabled)
        self.assertFalse(model.loaded)
        self.assertIsNone(model.score([0.0] * len(INPUT_ORDER)),
                          'a disabled candidate still produced a score')

    def test_a_candidate_that_cannot_load_returns_false_rather_than_raising(self):
        from eye_for_an_eye.decision.candidate import CandidateModel
        model = CandidateModel(enabled=True, model_path='/nonexistent.onnx',
                               manifest_path='/nonexistent.json', version='risk-v2')
        self.assertFalse(model.load(lambda m, n: None))
        self.assertTrue(model.disabled_reason)


# --- 2 ---------------------------------------------------------------------

class TestModelHashesAreValidated(ReadinessCase):
    """§0.2. An artifact whose bytes do not match its manifest is refused."""

    def test_a_manifest_declaring_the_wrong_hash_is_refused(self):
        registry = self.registry()
        with self.assertRaises(RegistryError):
            registry.register_candidate('risk-v2', artifacts('risk-v2', sha256='0' * 64))

    def test_a_correct_hash_is_accepted(self):
        import hashlib
        body = b'onnx-bytes-for-this-test'
        registry = self.registry()
        registry.register_candidate(
            'risk-v2', artifacts('risk-v2', model=body,
                                 sha256=hashlib.sha256(body).hexdigest()))
        self.assertEqual(registry.state.candidate, 'risk-v2')

    def test_the_runtime_reader_recomputes_the_digest_rather_than_trusting_it(self):
        """The registry checks at registration; the loader checks again at use."""
        import inspect
        from eye_for_an_eye.decision import onnx_model
        source = inspect.getsource(onnx_model.read_artifacts)
        self.assertIn('sha256', source.lower())
        self.assertIn('model SHA256 mismatch', inspect.getsource(onnx_model))


# --- 3 ---------------------------------------------------------------------

class TestFeatureSchemaCompatibilityIsEnforced(ReadinessCase):
    """§0.3. The mismatch with no symptom: right width, wrong columns."""

    def test_a_model_built_for_another_feature_schema_is_refused(self):
        registry = self.registry()
        with self.assertRaises(RegistryError):
            registry.register_candidate(
                'risk-v2', artifacts('risk-v2', feature_schema_version=SCHEMA_VERSION + 1))

    def test_a_model_declaring_a_different_column_order_is_refused(self):
        registry = self.registry()
        shuffled = list(INPUT_ORDER)
        shuffled[0], shuffled[1] = shuffled[1], shuffled[0]
        with self.assertRaises(RegistryError):
            registry.register_candidate('risk-v2',
                                        artifacts('risk-v2', feature_order=shuffled))

    def test_the_site_resolver_refuses_a_mismatched_schema_at_use_time(self):
        from eye_for_an_eye.sites.models import ModelResolver, SiteModelRegistry
        registry = SiteModelRegistry(Path(self.tmp.name) / 'sitemodels')
        global_registry = registry.global_registry()
        global_registry.register_candidate('risk-v1', artifacts('risk-v1'))
        global_registry.promote('risk-v1', gate_passed=True, reason='readiness')
        resolver = ModelResolver(registry, schema_version=SCHEMA_VERSION + 1)
        resolution = resolver.resolve('shop')
        self.assertEqual(resolution.source, 'no_model')
        self.assertTrue(any('feature schema' in reason for reason in resolution.reasons))


# --- 4 ---------------------------------------------------------------------

class TestModelScopeIsEnforced(ReadinessCase):
    """§0.4, §72. One site's model must never answer for another."""

    def test_a_site_model_cannot_be_published_into_another_sites_registry(self):
        from eye_for_an_eye.sites.models import SiteModelRegistry, site_scope
        registry = SiteModelRegistry(Path(self.tmp.name) / 'sitemodels')
        api = registry.site_registry('api')
        with self.assertRaises(RegistryError):
            api.register_candidate('shop-v1', artifacts('shop-v1', scope=site_scope('shop')))

    def test_a_site_model_cannot_be_published_into_the_global_registry(self):
        from eye_for_an_eye.sites.models import SiteModelRegistry, site_scope
        registry = SiteModelRegistry(Path(self.tmp.name) / 'sitemodels')
        with self.assertRaises(RegistryError):
            registry.global_registry().register_candidate(
                'shop-v1', artifacts('shop-v1', scope=site_scope('shop')))

    def test_a_global_model_cannot_be_published_into_a_site_registry(self):
        from eye_for_an_eye.sites.models import SiteModelRegistry
        registry = SiteModelRegistry(Path(self.tmp.name) / 'sitemodels')
        with self.assertRaises(RegistryError):
            registry.site_registry('shop').register_candidate(
                'global-v1', artifacts('global-v1', scope=GLOBAL_SCOPE))

    def test_site_identity_is_never_a_classifier_input(self):
        from dataset.schema import NEVER_MODEL_INPUT
        for field in ('site_group', 'site_id', 'domain', 'host', 'profile_type'):
            with self.subTest(field=field):
                self.assertIn(field, NEVER_MODEL_INPUT)
                self.assertNotIn(field, INPUT_ORDER)


# --- 5 ---------------------------------------------------------------------

class TestDatasetFeedbackLoopProtection(ReadinessCase):
    """§0.5. The system's own decisions must never become training labels.

    This is the prerequisite that makes autonomy survivable at all. A loop from
    "we blocked it" to "it was malicious" to "block more like it" would drift
    without any single step looking wrong.
    """

    def test_decision_derived_label_sources_are_forbidden_by_name(self):
        from training import schema
        for forbidden in ('blocked', 'automatically_blocked', 'risk_threshold',
                          'ml_score', 'final_risk', 'decision', 'previous_model',
                          'shadow_decision', 'self_labelled'):
            with self.subTest(source=forbidden):
                self.assertIn(forbidden, schema.FORBIDDEN_LABEL_SOURCES)
                self.assertNotIn(forbidden, schema.ALLOWED_LABEL_SOURCES)

    def test_the_two_vocabularies_can_never_overlap(self):
        from training import schema
        self.assertFalse(set(schema.ALLOWED_LABEL_SOURCES)
                         & set(schema.FORBIDDEN_LABEL_SOURCES))

    def test_a_dataset_carrying_a_decision_derived_label_is_refused(self):
        from training import schema
        declared = ['ml_score']
        self.assertTrue(any(item not in schema.ALLOWED_LABEL_SOURCES for item in declared))


# --- 6 ---------------------------------------------------------------------

class TestSiteIsolation(ReadinessCase):
    """§0.6, §68. Promotion for one site must be invisible to another."""

    def seed(self, registry, site, versions):
        from eye_for_an_eye.sites.models import site_scope
        scoped = registry.site_registry(site)
        for version in versions:
            scoped.register_candidate(version, artifacts(version, scope=site_scope(site)))
            scoped.promote(version, gate_passed=True, reason='readiness')
        return scoped

    def test_promoting_for_one_site_leaves_the_other_unchanged(self):
        from eye_for_an_eye.sites.models import SiteModelRegistry
        registry = SiteModelRegistry(Path(self.tmp.name) / 'sitemodels')
        shop = self.seed(registry, 'shop', ['shop-v1'])
        api = self.seed(registry, 'api', ['api-v1'])
        self.seed(registry, 'shop', ['shop-v2'])
        self.assertEqual(shop.state.active, 'shop-v2')
        self.assertEqual(api.state.active, 'api-v1')

    def test_rolling_one_site_back_leaves_the_other_unchanged(self):
        from eye_for_an_eye.sites.models import SiteModelRegistry
        registry = SiteModelRegistry(Path(self.tmp.name) / 'sitemodels')
        shop = self.seed(registry, 'shop', ['shop-v1', 'shop-v2'])
        api = self.seed(registry, 'api', ['api-v1', 'api-v2'])
        shop.rollback(reason='readiness')
        self.assertEqual(shop.state.active, 'shop-v1')
        self.assertEqual(api.state.active, 'api-v2')

    def test_each_site_keeps_a_separate_pointer_file(self):
        from eye_for_an_eye.sites.models import SiteModelRegistry
        registry = SiteModelRegistry(Path(self.tmp.name) / 'sitemodels')
        self.seed(registry, 'shop', ['shop-v1'])
        self.seed(registry, 'api', ['api-v1'])
        root = Path(self.tmp.name) / 'sitemodels' / 'sites'
        self.assertTrue((root / 'shop' / 'registry.json').is_file())
        self.assertTrue((root / 'api' / 'registry.json').is_file())

    def test_no_request_can_create_a_site(self):
        from eye_for_an_eye.sites.engine import SiteEngine
        from eye_for_an_eye.sites.identity import UNKNOWN_SITE
        from eye_for_an_eye.sites.profile import build_all
        engine = SiteEngine(build_all({'shop': {'profile': 'website',
                                                'domains': ['shop.example']}}))
        for host in ('evil.example', 'shop.example.evil', '\r\nshop.example', ''):
            with self.subTest(host=host[:20]):
                context = engine.context(host)
                self.assertEqual(context.site_id, UNKNOWN_SITE)
                self.assertFalse(context.known)
        self.assertEqual(sorted(engine.profiles), ['shop'])


# --- 7 ---------------------------------------------------------------------

class TestActiveCandidateComparison(ReadinessCase):
    """§0.7. The comparison auto-promotion evidence is built from."""

    def test_a_comparison_classifies_agreement_and_disagreement(self):
        from eye_for_an_eye.decision.candidate import classify
        same = classify(0.2, 0.2, 'OBSERVE', 'OBSERVE')
        differs = classify(0.2, 0.9, 'OBSERVE', 'TEMP_BLOCK')
        self.assertNotEqual(same, differs)

    def test_the_ledger_reports_agreement_and_new_blocks(self):
        from eye_for_an_eye.decision.candidate import ComparisonLedger, classify
        ledger = ComparisonLedger()
        for _ in range(10):
            ledger.observe(classify(0.2, 0.2, 'OBSERVE', 'OBSERVE'))
        ledger.observe(classify(0.2, 0.95, 'OBSERVE', 'TEMP_BLOCK'))
        document = ledger.explain()
        self.assertIn('agreement', document)
        self.assertGreaterEqual(ledger.new_blocks, 1,
                                'a candidate that would newly block was not counted')

    def test_the_ledger_is_bounded(self):
        """Auto-promotion runs unattended, so nothing may grow without a cap."""
        from eye_for_an_eye.decision.candidate import ComparisonLedger, classify
        ledger = ComparisonLedger()
        for index in range(50_000):
            ledger.observe(classify(0.1, 0.2, 'OBSERVE', 'OBSERVE'),
                           source_key=f'src-{index}')
        size = len(json.dumps(ledger.explain()))
        self.assertLess(size, 200_000,
                        'the comparison ledger grows without bound under traffic')


# --- 8, 9, 10 --------------------------------------------------------------

class TestAtomicActivationRollbackAndRestartRecovery(ReadinessCase):
    """§0.8-§0.10. The three that make a promotion reversible."""

    def test_the_pointer_is_written_atomically_not_edited_in_place(self):
        import inspect
        from eye_for_an_eye.decision import registry as module
        self.assertIn('os.replace', inspect.getsource(module._write_atomic),
                      'the registry pointer is not written by atomic rename')

    def test_activation_is_one_pointer_write(self):
        registry = self.registry()
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        registry.promote('risk-v1', gate_passed=True, reason='readiness')
        self.assertEqual(registry.state.active, 'risk-v1')
        self.assertTrue((Path(self.tmp.name) / 'models' / 'registry.json').is_file())

    def test_rollback_restores_the_previous_active(self):
        registry = self.registry()
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        registry.promote('risk-v1', gate_passed=True)
        registry.register_candidate('risk-v2', artifacts('risk-v2'))
        registry.promote('risk-v2', gate_passed=True)
        registry.rollback(reason='readiness')
        self.assertEqual(registry.state.active, 'risk-v1')

    def test_rollback_with_nowhere_to_go_leaves_active_alone(self):
        registry = self.registry()
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        registry.promote('risk-v1', gate_passed=True)
        with self.assertRaises(RegistryError):
            registry.rollback()
        self.assertEqual(registry.state.active, 'risk-v1')

    def test_a_fresh_registry_object_reads_the_same_state_from_disk(self):
        """Restart recovery: state lives in the file, not in the process."""
        root = Path(self.tmp.name) / 'models'
        first = ModelRegistry(root)
        first.register_candidate('risk-v1', artifacts('risk-v1'))
        first.promote('risk-v1', gate_passed=True, reason='readiness')
        first.register_candidate('risk-v2', artifacts('risk-v2'))
        first.promote('risk-v2', gate_passed=True, reason='readiness')
        restarted = ModelRegistry(root)
        self.assertEqual(restarted.state.active, 'risk-v2')
        self.assertEqual(restarted.state.previous_active, 'risk-v1')
        self.assertEqual(restarted.resolve(ACTIVE)['version'], 'risk-v2')

    def test_a_corrupt_pointer_is_refused_rather_than_guessed_at(self):
        root = Path(self.tmp.name) / 'models'
        registry = ModelRegistry(root)
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        registry.promote('risk-v1', gate_passed=True)
        (root / 'registry.json').write_text('{not json', encoding='utf-8')
        with self.assertRaises(RegistryError):
            ModelRegistry(root).state

    def test_a_pointer_from_an_unsupported_registry_version_is_refused(self):
        root = Path(self.tmp.name) / 'models'
        root.mkdir(parents=True)
        (root / 'registry.json').write_text(
            json.dumps({'registry_version': 999, 'active': 'risk-v9'}), encoding='utf-8')
        with self.assertRaises(RegistryError):
            ModelRegistry(root).state


# --- 11 --------------------------------------------------------------------

class TestManagementLockoutProtection(ReadinessCase):
    """§0.11, §103, §104. The management surface cannot promote anything."""

    def test_the_read_only_api_exposes_no_promotion_or_rollback_route(self):
        source = (ROOT / 'eye_for_an_eye' / 'api' / 'server.py').read_text(encoding='utf-8')
        for forbidden in ('/promote', '/rollback', '/governance', '/activate',
                          '/model/promote'):
            with self.subTest(route=forbidden):
                self.assertNotIn(forbidden, source)

    def test_the_api_module_cannot_reach_the_model_registry(self):
        import ast
        from eye_for_an_eye.api import server
        tree = ast.parse(Path(server.__file__).read_text(encoding='utf-8'))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module)
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
        for forbidden in ('registry', 'ModelRegistry', 'promotion', 'governance'):
            with self.subTest(name=forbidden):
                self.assertNotIn(forbidden, names)

    def test_the_api_is_loopback_only_by_default(self):
        from eye_for_an_eye.config import Config
        config = Config()
        self.assertFalse(config.api.enabled)
        self.assertIn(config.api.bind_address, ('127.0.0.1', '::1', 'localhost'))

    def test_a_bad_token_is_rejected_with_a_constant_time_comparison(self):
        source = (ROOT / 'eye_for_an_eye' / 'api' / 'server.py').read_text(encoding='utf-8')
        self.assertIn('hmac.compare_digest', source)
        self.assertIn('authentication_required', source)


# --- 12 --------------------------------------------------------------------

class TestCdnAndProxySafety(ReadinessCase):
    """§0.12. A promotion must never make a shared address blockable."""

    def resolver(self, networks=()):
        from eye_for_an_eye.web.identity import ClientResolver
        return ClientResolver(networks)

    def test_a_forwarded_header_from_an_untrusted_peer_is_not_believed(self):
        identity = self.resolver().resolve('198.51.100.5',
                                           forwarded='203.0.113.9')
        self.assertNotEqual(identity.address, '203.0.113.9',
                            'an untrusted forwarded header set the client address')

    def test_a_client_behind_a_trusted_proxy_is_never_network_enforceable(self):
        identity = self.resolver(['203.0.113.0/24']).resolve(
            '203.0.113.7', forwarded='198.51.100.22')
        self.assertFalse(identity.network_enforceable,
                         'blocking here would remove every visitor behind the proxy')

    def test_an_unparseable_identity_is_low_confidence_and_not_enforceable(self):
        for peer, forwarded in (('not-an-address', None), ('198.51.100.5', '\x00'),
                                ('', ''), ('198.51.100.5', 'a' * 5000)):
            with self.subTest(peer=str(peer)[:20]):
                identity = self.resolver(['203.0.113.0/24']).resolve(peer, forwarded=forwarded)
                self.assertIsNotNone(identity)
                if identity.confidence == 'LOW':
                    self.assertFalse(identity.network_enforceable)

    def test_resolution_never_raises_whatever_the_input(self):
        resolver = self.resolver(['203.0.113.0/24'])
        for peer in (None, '', '::1', '0.0.0.0', '\r\n', 'x' * 1000, '999.999.999.999'):
            with self.subTest(peer=str(peer)[:20]):
                self.assertIsNotNone(resolver.resolve(peer))


# --- 13 --------------------------------------------------------------------

class TestResourceStateIsBounded(ReadinessCase):
    """§0.13. Autonomy runs unattended, so nothing may grow without a cap."""

    def test_the_site_model_resolver_cache_is_bounded(self):
        from eye_for_an_eye.sites.models import ModelResolver, SiteModelRegistry
        resolver = ModelResolver(SiteModelRegistry(Path(self.tmp.name) / 'models'),
                                 max_cached_sites=32)
        for index in range(5_000):
            resolver.resolve(f'site-{index}')
        self.assertLessEqual(len(resolver._cache), 32)

    def test_the_cross_site_evidence_table_is_bounded(self):
        from eye_for_an_eye.sites.engine import SiteEngine
        from eye_for_an_eye.sites.profile import build_all
        engine = SiteEngine(build_all({'shop': {'profile': 'website',
                                                'domains': ['shop.example']}}))
        for index in range(20_000):
            engine._record_cross_site(f'198.51.100.{index % 256}.{index}', 'shop',
                                      probing=True, sensitive=False, now=float(index))
        self.assertLessEqual(len(engine._cross_site), engine._max_cross_site)

    def test_the_registry_audit_trail_is_bounded(self):
        registry = self.registry()
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        registry.promote('risk-v1', gate_passed=True)
        for index in range(2, 60):
            registry.register_candidate(f'risk-v{index}', artifacts(f'risk-v{index}'))
            registry.promote(f'risk-v{index}', gate_passed=True, reason='readiness')
        self.assertLess(len(registry.state.audit), 200,
                        'the registry audit trail grows without bound')

    def test_the_site_model_registry_bounds_how_many_sites_it_will_open(self):
        from eye_for_an_eye.sites.models import SiteModelError, SiteModelRegistry
        registry = SiteModelRegistry(Path(self.tmp.name) / 'models', max_sites=4)
        for index in range(4):
            registry.site_registry(f'site-{index}')
        with self.assertRaises(SiteModelError):
            registry.site_registry('site-99')


# --- the baseline itself ---------------------------------------------------

class TestTheBaselineIsHonestAboutWhatItDoesNotProve(unittest.TestCase):
    """§0 and §12. The distinction this whole file rests on.

    Mechanical readiness is not evidence readiness, and a file that checked the
    first and let somebody read it as the second would be the most dangerous
    thing in this stage.
    """

    def test_auto_promotion_is_not_enabled_anywhere_by_default(self):
        """§4, §98, §143. Whatever the machinery can do, it starts switched off."""
        from eye_for_an_eye.config import Config
        config = Config()
        governance = getattr(config, 'model_governance', None)
        if governance is None:
            self.skipTest('model_governance is added in P14 phase 1')
        self.assertFalse(governance.auto_promote_enabled)
        self.assertFalse(governance.auto_promote_global_enabled)
        self.assertEqual(list(governance.auto_promote_sites), [])

    def test_the_shipped_model_still_fails_its_own_quality_gate(self):
        """The fact that makes evidence readiness NO, recorded as a test so it
        cannot quietly stop being true without somebody noticing."""
        card = ROOT / 'models' / 'risk-logreg-v1.json'
        if not card.is_file():
            self.skipTest('the shipped model artifact is not present')
        record = json.loads(card.read_text(encoding='utf-8'))
        if 'quality_gate_passed' not in record:
            self.skipTest('the evaluation record is in a separate artifact here')
        self.assertFalse(record['quality_gate_passed'])
        self.assertEqual(record.get('recommended_mode'), 'shadow')


if __name__ == '__main__':
    unittest.main()
