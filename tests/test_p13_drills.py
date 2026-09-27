"""P13 §128-§130: the three drills, run as tests so they cannot rot.

A rollback procedure that has never been executed is a paragraph, not a
procedure. The same is true of a config migration path and of the claim that
rolling one site back leaves the others alone. Each of these is cheap to run and
expensive to discover broken, which is the definition of something that belongs
in the suite rather than in a runbook nobody opens.

Each drill below is written as the sequence an operator would actually perform,
in order, with the state inspected between steps -- not as an assertion about
one method. The point is the sequence.
"""
import json
import tempfile
import unittest
from pathlib import Path

from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION
from eye_for_an_eye.decision.registry import (ACTIVE, GLOBAL_SCOPE, ModelRegistry,
                                              RegistryError)


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


class TestTheModelRollbackDrill(unittest.TestCase):
    """§128. Promote, regret it, and get back -- offline, on one machine.

    Rollback is the feature an operator needs at the worst possible moment: the
    new model is blocking real visitors and the phone is ringing. So it must
    work with no network, no registry service, no credentials, and no second
    chance to read the documentation.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = ModelRegistry(Path(self.tmp.name) / 'models')

    def test_the_whole_sequence_start_to_finish(self):
        registry = self.registry

        # 1. A fresh install has no model at all, and that is a valid state.
        self.assertIsNone(registry.state.active)
        self.assertIsNone(registry.resolve(ACTIVE))

        # 2. Register v1. Registering must grant no authority whatsoever.
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        self.assertEqual(registry.state.candidate, 'risk-v1')
        self.assertIsNone(registry.state.active,
                          'registering a candidate made it active')

        # 3. Promote it. A person did this; the gate result is an input.
        registry.promote('risk-v1', gate_passed=True, reason='initial model')
        self.assertEqual(registry.state.active, 'risk-v1')

        # 4. Register and promote v2, the one that turns out to be wrong.
        registry.register_candidate('risk-v2', artifacts('risk-v2'))
        registry.promote('risk-v2', gate_passed=True, reason='looked better offline')
        self.assertEqual(registry.state.active, 'risk-v2')
        self.assertEqual(registry.state.previous_active, 'risk-v1')

        # 5. The phone rings. Roll back.
        result = registry.rollback(reason='false positives on real traffic')
        self.assertEqual(registry.state.active, 'risk-v1')
        self.assertIsNotNone(result)

        # 6. The sensor must now resolve to v1's files, not v2's.
        resolved = registry.resolve(ACTIVE)
        self.assertEqual(resolved['version'], 'risk-v1')
        self.assertTrue(Path(resolved['manifest_path']).is_file())

        # 7. v2 is still on disk. Rollback is not deletion, and the next step
        #    after a rollback is usually working out what went wrong.
        self.assertIn('risk-v2', {v.version for v in registry.list_versions()})

        # 8. Rolling back again returns to v2: the pointer swaps, it does not
        #    walk a history. An operator who runs rollback twice by mistake gets
        #    the model they just rejected, so the command is not idempotent and
        #    the state after each step must be visible.
        registry.rollback(reason='drill: confirming this is a swap')
        self.assertEqual(registry.state.active, 'risk-v2')

    def test_rollback_with_nowhere_to_go_refuses_rather_than_clearing_active(self):
        """The failure that would turn a bad model into no model at all."""
        self.registry.register_candidate('risk-v1', artifacts('risk-v1'))
        self.registry.promote('risk-v1', gate_passed=True)
        with self.assertRaises(RegistryError):
            self.registry.rollback()
        self.assertEqual(self.registry.state.active, 'risk-v1',
                         'a refused rollback must leave ACTIVE alone')

    def test_promotion_without_a_passing_gate_is_refused(self):
        self.registry.register_candidate('risk-v1', artifacts('risk-v1'))
        with self.assertRaises(RegistryError):
            self.registry.promote('risk-v1', gate_passed=False)
        self.assertIsNone(self.registry.state.active)

    def test_the_active_model_and_its_fallback_are_never_prunable(self):
        """Retention must not delete the thing rollback depends on."""
        registry = self.registry
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        registry.promote('risk-v1', gate_passed=True)
        registry.register_candidate('risk-v2', artifacts('risk-v2'))
        registry.promote('risk-v2', gate_passed=True)
        prunable = set(registry.prunable())
        self.assertNotIn('risk-v2', prunable, 'ACTIVE is prunable')
        self.assertNotIn('risk-v1', prunable, 'the rollback target is prunable')

    def test_every_step_of_the_drill_is_in_the_audit_record(self):
        """An operator explaining an outage afterwards needs the sequence."""
        registry = self.registry
        registry.register_candidate('risk-v1', artifacts('risk-v1'))
        registry.promote('risk-v1', gate_passed=True, reason='initial model')
        registry.register_candidate('risk-v2', artifacts('risk-v2'))
        registry.promote('risk-v2', gate_passed=True, reason='looked better')
        registry.rollback(reason='false positives on real traffic')
        events = json.dumps(registry.state.explain())
        for expected in ('risk-v1', 'risk-v2'):
            with self.subTest(version=expected):
                self.assertIn(expected, events)


class TestTheSiteRollbackDrill(unittest.TestCase):
    """§129. Rolling site A back must be invisible to site B.

    This is the property that makes per-site models safe to have at all. If a
    rollback were global, one site's bad afternoon would become every site's,
    and an operator would rightly never use the feature.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from eye_for_an_eye.sites.models import SiteModelRegistry
        self.registry = SiteModelRegistry(Path(self.tmp.name) / 'models')

    def seed(self, site, versions):
        from eye_for_an_eye.sites.models import site_scope
        registry = self.registry.site_registry(site)
        for version in versions:
            registry.register_candidate(version,
                                        artifacts(version, scope=site_scope(site)))
            registry.promote(version, gate_passed=True, reason='drill')
        return registry

    def test_rolling_one_site_back_leaves_the_other_exactly_where_it_was(self):
        shop = self.seed('shop', ['shop-v1', 'shop-v2'])
        api = self.seed('api', ['api-v1', 'api-v2'])
        self.assertEqual(shop.state.active, 'shop-v2')
        self.assertEqual(api.state.active, 'api-v2')

        shop.rollback(reason='drill')

        self.assertEqual(shop.state.active, 'shop-v1')
        self.assertEqual(api.state.active, 'api-v2',
                         "site A's rollback changed site B's active model")

    def test_each_site_keeps_its_own_pointer_file(self):
        """The mechanism the isolation rests on, checked on disk."""
        self.seed('shop', ['shop-v1'])
        self.seed('api', ['api-v1'])
        root = Path(self.tmp.name) / 'models' / 'sites'
        self.assertTrue((root / 'shop').is_dir())
        self.assertTrue((root / 'api').is_dir())
        self.assertNotEqual((root / 'shop').resolve(), (root / 'api').resolve())

    def test_a_model_built_for_one_site_cannot_be_published_into_another(self):
        """The failure with no symptom: it would load and answer confidently."""
        from eye_for_an_eye.sites.models import site_scope
        api = self.registry.site_registry('api')
        with self.assertRaises(RegistryError):
            api.register_candidate('shop-v1', artifacts('shop-v1',
                                                        scope=site_scope('shop')))

    def test_a_running_resolver_notices_the_rollback_without_being_told(self):
        """The half of the drill that was broken, and the reason it mattered.

        An operator runs `model rollback` from the CLI. The sensor is a
        different, already-running process, and it holds its own resolution
        cache with no expiry. Nothing called `invalidate()` -- nothing in the
        codebase called it at all -- so the sensor went on using the model that
        had just been withdrawn, indefinitely, while the registry, the audit
        trail and the CLI all reported the rollback as done.

        The registry half of the drill passed the whole time. That is what made
        it worth running the drill as a *sequence*: the emergency lever moved
        and nothing at the far end of it did.
        """
        from eye_for_an_eye.sites.models import ModelResolver
        shop = self.seed('shop', ['shop-v1', 'shop-v2'])
        resolver = ModelResolver(self.registry)
        self.assertEqual(resolver.resolve('shop').version, 'shop-v2')

        shop.rollback(reason='drill')

        self.assertEqual(resolver.resolve('shop').version, 'shop-v1',
                         'the running resolver is still serving the withdrawn model')

    def test_it_also_notices_a_promotion_without_being_told(self):
        """The same mechanism, in the direction an operator uses more often."""
        from eye_for_an_eye.sites.models import ModelResolver
        shop = self.seed('shop', ['shop-v1'])
        resolver = ModelResolver(self.registry)
        self.assertEqual(resolver.resolve('shop').version, 'shop-v1')
        shop.register_candidate('shop-v2', artifacts('shop-v2', scope='SITE:shop'))
        shop.promote('shop-v2', gate_passed=True, reason='drill')
        self.assertEqual(resolver.resolve('shop').version, 'shop-v2')

    def test_an_unchanged_registry_is_answered_from_cache(self):
        """The cache still has to be a cache: the pointer check is two stats,
        not a manifest re-read per request."""
        from eye_for_an_eye.sites.models import ModelResolver
        self.seed('shop', ['shop-v1'])
        resolver = ModelResolver(self.registry)
        first = resolver.resolve('shop')
        self.assertIs(resolver.resolve('shop'), first,
                      'an unchanged registry rebuilt the resolution')

    def test_invalidate_still_works_for_a_caller_in_the_same_process(self):
        from eye_for_an_eye.sites.models import ModelResolver
        self.seed('shop', ['shop-v1'])
        resolver = ModelResolver(self.registry)
        resolver.resolve('shop')
        resolver.invalidate('shop')
        self.assertEqual(resolver.resolve('shop').version, 'shop-v1')

    def test_invalidating_one_site_does_not_clear_another(self):
        from eye_for_an_eye.sites.models import ModelResolver
        self.seed('shop', ['shop-v1'])
        self.seed('api', ['api-v1'])
        resolver = ModelResolver(self.registry)
        resolver.resolve('shop')
        resolver.resolve('api')
        resolver.invalidate('shop')
        self.assertEqual(resolver.resolve('api').version, 'api-v1')


class TestTheConfigurationMigrationDrill(unittest.TestCase):
    """§130. An operator upgrades. Their old file must still work.

    Every stage since P10 has added configuration sections. A file written for
    P9 has none of them. If it failed to load, the upgrade path would be "edit
    your config before the service will start", which on a server people depend
    on is an outage with a changelog entry.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, body):
        path = Path(self.tmp.name) / 'eye-for-an-eye.toml'
        path.write_text(body, encoding='utf-8')
        return str(path)

    def test_a_pre_p10_configuration_still_loads_with_safe_defaults(self):
        from eye_for_an_eye.config import load_config
        config = load_config(self.write(
            '[storage]\nenabled = true\n\n'
            '[deception]\nenabled = true\nmode = "sensor"\n\n'
            '[decision]\nenabled = true\n'))
        self.assertTrue(config.storage.enabled)
        # Everything added after that file was written must arrive switched off.
        self.assertFalse(config.web.enabled)
        self.assertFalse(config.sites.enabled)
        self.assertFalse(config.enforcement.enabled)
        self.assertFalse(config.learning.enabled)

    def test_an_empty_configuration_file_is_a_working_configuration(self):
        from eye_for_an_eye.config import load_config
        config = load_config(self.write(''))
        self.assertFalse(config.enforcement.enabled)
        self.assertFalse(config.web.enabled)

    def test_an_unknown_section_is_refused_rather_than_ignored(self):
        """A typo'd section name that loads silently is a setting that is not
        applied, on a security tool, with no error. Refusing is kinder."""
        from eye_for_an_eye.config import load_config
        with self.assertRaises(ValueError):
            load_config(self.write('[enforcment]\nenabled = true\n'))

    def test_an_unknown_setting_inside_a_known_section_is_refused(self):
        from eye_for_an_eye.config import load_config
        with self.assertRaises(ValueError):
            load_config(self.write('[enforcement]\nenabledd = true\n'))

    def test_upgrading_never_turns_enforcement_on_by_itself(self):
        """The one migration outcome that would be unforgivable."""
        from eye_for_an_eye.config import load_config
        for body in ('', '[storage]\nenabled = true\n',
                     '[decision]\nenabled = true\n',
                     '[deception]\nenabled = true\nmode = "sensor"\n'):
            with self.subTest(configuration=body.replace('\n', ' ')[:40]):
                self.assertFalse(load_config(self.write(body)).enforcement.enabled)

    def test_the_shipped_example_configurations_all_load(self):
        """They are what an operator copies, so they are part of the path."""
        from eye_for_an_eye.config import load_config
        root = Path(__file__).resolve().parents[1]
        examples = sorted(root.glob('config.*.toml'))
        self.assertTrue(examples, 'no example configuration is shipped')
        for example in examples:
            with self.subTest(configuration=example.name):
                self.assertIsNotNone(load_config(str(example)))


if __name__ == '__main__':
    unittest.main()
