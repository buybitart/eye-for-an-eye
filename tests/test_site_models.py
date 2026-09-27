"""P12 Phase 5 (§29-§39, §73-§78, §137, §138, §144, §148): model scope.

The failure this file is mostly about has no symptom. A model built for site A,
loaded for site B, runs perfectly: it accepts the feature vector, returns a
score, and the score is confident and wrong. Nothing downstream can tell. So the
scope check has to happen at the boundary, and it has to be structural.

The other half is fallback. A site whose model is broken must degrade to the
base model, and a site with no model at all must degrade to the mathematical
engine — which was never optional and never depended on a classifier.
"""
import json
import tempfile
import unittest
from pathlib import Path

from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION
from eye_for_an_eye.decision.registry import ACTIVE, GLOBAL_SCOPE, RegistryError
from eye_for_an_eye.sites.models import (BASE_MODEL, ModelResolver, NO_MODEL,
                                         Resolution, SITE_MODEL, SiteModelError,
                                         SiteModelRegistry, parse_scope, site_scope)

ONNX = b'\x08\x01' + b'x' * 600


def artifacts(version, *, scope=GLOBAL_SCOPE, schema=SCHEMA_VERSION):
    import hashlib
    manifest = {'model_version': version, 'scope': scope,
                'feature_schema_version': schema,
                'feature_order': list(INPUT_ORDER),
                'sha256': hashlib.sha256(ONNX).hexdigest(),
                'created_at': '2026-09-10T00:00:00+00:00',
                'recommended_mode': 'shadow'}
    return {'classifier.onnx': ONNX,
            'manifest.json': json.dumps(manifest).encode('utf-8')}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.registry = SiteModelRegistry(self.root)
        self.resolver = ModelResolver(self.registry)

    def publish_global(self, version='global-v1'):
        registry = self.registry.global_registry()
        registry.register_candidate(version, artifacts(version))
        # `gate_passed` is required by P9 and is not a formality: a model cannot
        # become active without something having judged it fit. These tests are
        # about scope, so the gate is asserted separately below and asserted
        # here only by having to be passed at all.
        registry.promote(version, gate_passed=True, reason='test fixture')
        return registry

    def publish_site(self, site, version, **kwargs):
        registry = self.registry.site_registry(site)
        registry.register_candidate(version, artifacts(version, scope=site_scope(site),
                                                       **kwargs))
        registry.promote(version, gate_passed=True, reason='test fixture')
        return registry


class TestScopeStrings(unittest.TestCase):
    def test_a_site_scope_is_spelled_predictably(self):
        self.assertEqual(site_scope('main'), 'SITE:main')
        self.assertEqual(site_scope('MAIN'), 'SITE:main')

    def test_scopes_round_trip(self):
        self.assertEqual(parse_scope(GLOBAL_SCOPE), (GLOBAL_SCOPE, ''))
        self.assertEqual(parse_scope(site_scope('api')), ('SITE', 'api'))

    def test_an_absent_scope_reads_as_global(self):
        """Every model written before P12 is global by definition."""
        self.assertEqual(parse_scope(None), (GLOBAL_SCOPE, ''))
        self.assertEqual(parse_scope(''), (GLOBAL_SCOPE, ''))

    def test_nonsense_scopes_are_refused(self):
        for bad in ('SITE:', 'site:main', 'EVERYTHING', 'SITE:///'):
            with self.subTest(scope=bad):
                with self.assertRaises(SiteModelError):
                    parse_scope(bad)

    def test_a_site_scope_cannot_escape_the_registry_directory(self):
        for bad in ('../../etc', 'a/b', '..'):
            with self.subTest(site=bad):
                scope = site_scope(bad) if bad != '..' else None
                if scope:
                    self.assertNotIn('/', scope[len('SITE:'):])


class TestWrongScopeIsRefused(Base):
    """§33, §138. The mix-up with no symptom."""

    def test_a_site_model_cannot_be_published_into_the_global_registry(self):
        registry = self.registry.global_registry()
        with self.assertRaises(RegistryError) as raised:
            registry.register_candidate('v1', artifacts('v1', scope=site_scope('main')))
        self.assertIn('must not be loaded for another', str(raised.exception))

    def test_a_model_for_one_site_cannot_be_published_into_another(self):
        registry = self.registry.site_registry('api')
        with self.assertRaises(RegistryError):
            registry.register_candidate('v1', artifacts('v1', scope=site_scope('main')))

    def test_a_global_model_cannot_be_published_into_a_site_registry(self):
        registry = self.registry.site_registry('main')
        with self.assertRaises(RegistryError):
            registry.register_candidate('v1', artifacts('v1', scope=GLOBAL_SCOPE))

    def test_a_rejected_candidate_leaves_nothing_behind(self):
        registry = self.registry.site_registry('main')
        with self.assertRaises(RegistryError):
            registry.register_candidate('v1', artifacts('v1', scope=GLOBAL_SCOPE))
        self.assertEqual(registry.list_versions(), [])

    def test_a_manifest_edited_after_publication_is_caught_at_resolve_time(self):
        """Belt and braces: the files were changed underneath the registry."""
        registry = self.publish_site('main', 'main-v1')
        path = Path(registry.version_path('main-v1')) / 'manifest.json'
        manifest = json.loads(path.read_text(encoding='utf-8'))
        manifest['scope'] = site_scope('api')
        path.write_text(json.dumps(manifest), encoding='utf-8')
        self.publish_global()

        resolved = self.resolver.resolve('main')
        self.assertEqual(resolved.source, BASE_MODEL)
        self.assertTrue(any('another site' in reason for reason in resolved.reasons))


class TestResolution(Base):
    """§34. Site model if there is one, base model otherwise."""

    def test_a_site_without_its_own_model_uses_the_base_model(self):
        self.publish_global('global-v3')
        resolved = self.resolver.resolve('main')
        self.assertEqual(resolved.source, BASE_MODEL)
        self.assertEqual(resolved.version, 'global-v3')
        self.assertFalse(resolved.fell_back)

    def test_using_the_base_model_is_not_reported_as_a_failure(self):
        """§31. It is the intended arrangement for most sites."""
        self.publish_global()
        self.assertEqual(self.resolver.resolve('main').reasons, ())
        self.assertIn('not a deficiency', self.resolver.health()['note'])

    def test_a_site_with_its_own_model_uses_it(self):
        self.publish_global()
        self.publish_site('api', 'site-api-v1')
        resolved = self.resolver.resolve('api')
        self.assertEqual(resolved.source, SITE_MODEL)
        self.assertEqual(resolved.version, 'site-api-v1')

    def test_two_sites_get_their_own_models(self):
        """§137. The right model reaches the right site."""
        self.publish_global()
        self.publish_site('main', 'site-main-v1')
        self.publish_site('api', 'site-api-v1')
        self.assertEqual(self.resolver.resolve('main').version, 'site-main-v1')
        self.assertEqual(self.resolver.resolve('api').version, 'site-api-v1')

    def test_sites_sharing_the_base_model_resolve_to_one_version(self):
        """§128. One file, loaded once, not once per site."""
        self.publish_global('global-v1')
        paths = {self.resolver.resolve(f'site{index}').path for index in range(20)}
        self.assertEqual(len(paths), 1)

    def test_with_nothing_published_the_maths_engine_decides_alone(self):
        resolved = self.resolver.resolve('main')
        self.assertEqual(resolved.source, NO_MODEL)
        self.assertTrue(any('mathematical engine' in reason
                            for reason in resolved.reasons))


class TestFallback(Base):
    """§35, §78, §144. One site's failure is one site's problem."""

    def test_a_broken_site_model_falls_back_to_the_base_model(self):
        self.publish_global('global-v2')
        registry = self.publish_site('main', 'main-v1')
        (Path(registry.version_path('main-v1')) / 'manifest.json').write_text(
            'not json at all', encoding='utf-8')

        resolved = self.resolver.resolve('main')
        self.assertEqual(resolved.source, BASE_MODEL)
        self.assertEqual(resolved.version, 'global-v2')
        self.assertTrue(resolved.fell_back)

    def test_a_fallback_says_why_rather_than_looking_like_a_choice(self):
        self.publish_global()
        registry = self.publish_site('main', 'main-v1')
        (Path(registry.version_path('main-v1')) / 'manifest.json').unlink()
        resolved = self.resolver.resolve('main')
        self.assertTrue(resolved.reasons)
        self.assertTrue(resolved.explain()['fell_back'])

    def test_one_site_failing_leaves_the_others_untouched(self):
        self.publish_global()
        registry = self.publish_site('main', 'main-v1')
        self.publish_site('api', 'api-v1')
        (Path(registry.version_path('main-v1')) / 'manifest.json').unlink()

        self.assertEqual(self.resolver.resolve('main').source, BASE_MODEL)
        self.assertEqual(self.resolver.resolve('api').source, SITE_MODEL)
        self.assertEqual(self.resolver.resolve('api').version, 'api-v1')

    def test_a_model_built_for_another_feature_schema_is_refused(self):
        """§34. Wrong columns produce confident nonsense, not an error.

        The registry will not publish a mismatched model in the first place, so
        the way this really happens is an upgrade: the model was published under
        schema N and the software now runs schema N+1. The resolver checks on
        every resolution rather than trusting what was true at publication.
        """
        self.publish_global()
        self.publish_site('main', 'main-v1')
        upgraded = ModelResolver(self.registry, schema_version=SCHEMA_VERSION + 5)
        resolved = upgraded.resolve('main')
        self.assertTrue(any('feature schema' in reason for reason in resolved.reasons))
        # The base model was built for the old schema too, so nothing is usable
        # and the mathematical engine decides alone. That is the safe end of the
        # chain, not an outage.
        self.assertEqual(resolved.source, NO_MODEL)

    def test_a_site_model_is_refused_when_only_it_has_the_wrong_schema(self):
        self.publish_global()
        registry = self.publish_site('main', 'main-v1')
        path = Path(registry.version_path('main-v1')) / 'manifest.json'
        manifest = json.loads(path.read_text(encoding='utf-8'))
        manifest['feature_schema_version'] = SCHEMA_VERSION + 5
        path.write_text(json.dumps(manifest), encoding='utf-8')

        resolved = self.resolver.resolve('main')
        self.assertEqual(resolved.source, BASE_MODEL)
        self.assertTrue(any('feature schema' in reason for reason in resolved.reasons))

    def test_resolution_never_raises_however_broken_the_registry(self):
        import shutil
        self.publish_global()
        self.publish_site('main', 'main-v1')
        shutil.rmtree(self.root / 'sites' / 'main' / 'versions')
        self.assertEqual(self.resolver.resolve('main').source, BASE_MODEL)

    def test_everything_broken_still_returns_a_resolution(self):
        import shutil
        self.publish_global()
        self.publish_site('main', 'main-v1')
        shutil.rmtree(self.root)
        self.resolver.invalidate()
        self.assertEqual(self.resolver.resolve('main').source, NO_MODEL)


class TestScopedPromotionAndRollback(Base):
    """§76, §77, §148. Rolling one site back touches nothing else."""

    def test_each_scope_keeps_its_own_pointer(self):
        self.publish_global('global-v1')
        self.publish_site('main', 'main-v1')
        self.assertEqual(self.registry.global_registry().state.active, 'global-v1')
        self.assertEqual(self.registry.site_registry('main').state.active, 'main-v1')

    def test_rolling_one_site_back_leaves_the_other_alone(self):
        self.publish_global()
        main = self.registry.site_registry('main')
        for version in ('main-v1', 'main-v2'):
            main.register_candidate(version, artifacts(version, scope=site_scope('main')))
            main.promote(version, gate_passed=True, reason='test fixture')
        self.publish_site('api', 'api-v1')

        main.rollback()

        self.assertEqual(main.state.active, 'main-v1')
        self.assertEqual(self.registry.site_registry('api').state.active, 'api-v1')
        self.assertEqual(self.registry.global_registry().state.active, 'global-v1')

    def test_promoting_a_site_model_does_not_change_the_global_active(self):
        self.publish_global('global-v1')
        self.publish_site('main', 'main-v1')
        self.assertEqual(self.registry.global_registry().state.active, 'global-v1')

    def test_a_site_registry_lives_in_its_own_directory(self):
        self.publish_site('main', 'main-v1')
        self.assertTrue((self.root / 'sites' / 'main').is_dir())
        self.assertIn('main', self.registry.configured_sites())

    def test_the_number_of_site_registries_is_bounded(self):
        registry = SiteModelRegistry(self.root, max_sites=3)
        for index in range(3):
            registry.site_registry(f'site{index}')
        with self.assertRaises(SiteModelError):
            registry.site_registry('one-too-many')


class TestPromotionStillNeedsAGate(Base):
    """§75, §153. Site scope does not weaken the P9 rule."""

    def test_a_site_model_cannot_be_promoted_without_a_passing_gate(self):
        registry = self.registry.site_registry('main')
        registry.register_candidate('main-v1', artifacts('main-v1',
                                                         scope=site_scope('main')))
        with self.assertRaises(RegistryError) as raised:
            registry.promote('main-v1', gate_passed=False)
        self.assertIn('quality gate', str(raised.exception))
        self.assertIsNone(registry.state.active)

    def test_there_is_no_auto_promote_setting_on_any_scope(self):
        for registry in (self.registry.global_registry(),
                         self.registry.site_registry('main')):
            with self.subTest(scope=registry.scope):
                for name in dir(registry):
                    self.assertNotIn(name, ('auto_promote', 'promote_if_better',
                                            'auto_activate'))


class TestCaching(Base):
    def test_a_resolution_is_cached_per_site(self):
        self.publish_global()
        first = self.resolver.resolve('main')
        self.assertIs(self.resolver.resolve('main'), first)

    def test_invalidating_one_site_leaves_the_others_cached(self):
        self.publish_global()
        main = self.resolver.resolve('main')
        api = self.resolver.resolve('api')
        self.resolver.invalidate('main')
        self.assertIsNot(self.resolver.resolve('main'), main)
        self.assertIs(self.resolver.resolve('api'), api)

    def test_a_promotion_is_visible_after_invalidation(self):
        self.publish_global('global-v1')
        self.assertEqual(self.resolver.resolve('main').version, 'global-v1')
        registry = self.registry.global_registry()
        registry.register_candidate('global-v2', artifacts('global-v2'))
        registry.promote('global-v2', gate_passed=True, reason='test fixture')
        self.resolver.invalidate()
        self.assertEqual(self.resolver.resolve('main').version, 'global-v2')


class TestReporting(Base):
    def test_a_resolution_explains_itself(self):
        self.publish_global('global-v1')
        document = self.resolver.resolve('main').explain()
        self.assertEqual(document['model_source'], BASE_MODEL)
        self.assertEqual(document['model_scope'], GLOBAL_SCOPE)
        json.dumps(document)

    def test_a_model_version_reports_its_scope(self):
        registry = self.publish_site('main', 'main-v1')
        described = registry.describe_version('main-v1', ACTIVE)
        self.assertEqual(described.scope, site_scope('main'))
        self.assertEqual(described.explain()['scope'], site_scope('main'))

    def test_a_resolution_is_frozen(self):
        with self.assertRaises(Exception):
            Resolution('main', BASE_MODEL).site_id = 'api'


if __name__ == '__main__':
    unittest.main()
