"""One authority, one enforcer, and nothing else that can reach a firewall.

P15.5R §2, §4, §5, §30, §32, §33.

### Why this file is structural rather than behavioural

A behavioural test of "the legacy path did not block" passes for two reasons:
because the legacy path is disabled, or because this particular traffic did not
reach its threshold. The second is worthless and looks identical to the first.

So most of what is asserted here is about *what exists in the process*. When the
P15 pipeline owns TEMP_BLOCK, `TemporaryBlocks` is not constructed — absent, not
merely unused — and no function outside the pipeline calls `HostEnforcer`. An
object that exists is an object somebody can call, and P15.4 is a lesson about
what "somebody" turns out to mean six months later.

### The four refusals

`AutonomousDecisionPipeline._enforce` names each of them separately and this
file tests each separately, because "nothing was enforced" is a fact an operator
will have to explain, and a single boolean cannot tell them whether the answer
was shadow mode, a missing helper, or a decision that was never a block.
"""
import ast
import inspect
from pathlib import Path
import unittest

from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               SHADOW)
from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.autonomy.pipeline import (AutonomousDecisionPipeline,
                                              from_config as pipeline_from_config)
from eye_for_an_eye.config import Config
from eye_for_an_eye.decision.engine import DecisionEngine
from eye_for_an_eye.correlation.engine import CorrelationEngine

REPOSITORY = Path(__file__).resolve().parents[1]
PACKAGE = REPOSITORY / 'eye_for_an_eye'
CALIBRATOR = REPOSITORY / 'models' / 'mathrisk-cal-v4-isotonic.json'


def config(*, autonomy=False, mode='shadow', enforcement=False, host=False):
    settings = Config()
    settings.decision.enabled = True
    settings.decision.mode = 'enforce'
    settings.storage.enabled = False
    settings.api.enabled = False
    settings.metrics.enabled = False
    settings.logging.path = ''
    settings.autonomy.enabled = autonomy
    settings.autonomy.mode = mode
    settings.autonomy.calibrator_path = str(CALIBRATOR) if autonomy else ''
    settings.enforcement.enabled = enforcement
    settings.enforcement.host_enabled = host
    if host:
        settings.enforcement.management_networks = ['192.0.2.0/24']
    return settings


def engine_for(settings):
    return DecisionEngine(settings, CorrelationEngine(settings.correlation))


class RecordingEnforcer:
    """Counts what it was asked to do. Has no privilege and touches nothing."""

    has_firewall_privilege = False

    def __init__(self):
        self.calls = []

    def execute(self, record):
        self.calls.append(record)
        raise AssertionError('the enforcer must not be called in this state')


class TestOnlyOneAuthorityIsBuilt(unittest.TestCase):
    """§2, §32."""

    def test_the_legacy_enforcer_is_not_constructed_when_autonomy_owns_blocking(self):
        engine = engine_for(config(autonomy=True, mode='autonomous'))
        self.assertTrue(engine.autonomous_authority)
        engine.start()
        self.addCleanup(engine.close)
        self.assertIsNone(engine.enforcer,
                          'the legacy namespace enforcer exists alongside the P15 '
                          'authority; two objects in this process could place a block')

    def test_the_legacy_enforcer_is_still_built_when_autonomy_is_off(self):
        """The P0-P14 path is untouched by this change, which is what makes it
        a wiring change rather than a rewrite. Construction is asserted from the
        source rather than by running it, because `TemporaryBlocks` reaches for
        `nft` and this test may not have one."""
        source = inspect.getsource(DecisionEngine.start)
        self.assertIn('TemporaryBlocks(self.config)', source)
        self.assertIn('not self.autonomous_authority', source,
                      'the legacy enforcer is constructed without asking whether '
                      'the P15 authority owns blocking')

    def test_a_configuration_asking_for_both_enforcement_paths_is_refused(self):
        """The lab namespace path has its own preconditions (`lab` profile,
        enforce mode, an isolated namespace), so the configuration has to be a
        *valid* lab one before the new rule is the thing that refuses it —
        otherwise this test would pass on an error about something else."""
        settings = config(autonomy=True, enforcement=True)
        settings.deployment.profile = 'lab'
        settings.firewall.lab_namespace = 'e4e-lab-p15-5r'
        with self.assertRaises(ValueError) as caught:
            settings.validate()
        self.assertIn('mutually exclusive', str(caught.exception))

    def test_the_same_lab_configuration_is_accepted_without_autonomy(self):
        """So the refusal above is about the pair, not about the lab path."""
        settings = config(autonomy=False, enforcement=True)
        settings.deployment.profile = 'lab'
        settings.firewall.lab_namespace = 'e4e-lab-p15-5r'
        settings.validate()

    def test_autonomous_mode_without_a_calibrator_is_refused(self):
        settings = config(autonomy=True, mode='autonomous')
        settings.autonomy.calibrator_path = ''
        with self.assertRaises(ValueError) as caught:
            settings.validate()
        self.assertIn('calibrator_path', str(caught.exception))

    def test_shadow_mode_without_a_calibrator_is_allowed(self):
        """Shadow is where a deployment finds out what it would have done, and
        "nothing, because there is no calibrator" is a legitimate answer to
        discover there rather than a configuration error."""
        settings = config(autonomy=True, mode='shadow')
        settings.autonomy.calibrator_path = ''
        settings.validate()


class TestNothingElseCanReachEnforcement(unittest.TestCase):
    """§4. Asserted over the whole package, not over the paths we remembered."""

    def _calls_to(self, method):
        found = []
        for path in sorted(PACKAGE.rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == method):
                    owner = node.func.value
                    name = (owner.attr if isinstance(owner, ast.Attribute)
                            else getattr(owner, 'id', '<expr>'))
                    found.append((str(path.relative_to(REPOSITORY)), node.lineno, name))
        return found

    def test_only_the_pipeline_executes_an_enforcement_record(self):
        callers = {path for path, _line, name in self._calls_to('execute')
                   if name in ('enforcer', 'host_enforcer')}
        self.assertEqual(callers, {'eye_for_an_eye/autonomy/pipeline.py'},
                         'something other than the pipeline hands a record to an '
                         'enforcer; §4 allows exactly one such path')

    def test_only_the_decision_engine_calls_the_legacy_block(self):
        callers = {path for path, _line, name in self._calls_to('block')
                   if name == 'enforcer'}
        self.assertEqual(callers, {'eye_for_an_eye/decision/engine.py'})

    def test_the_pipeline_holds_no_firewall_privilege(self):
        self.assertFalse(AutonomousDecisionPipeline.has_firewall_privilege)
        self.assertFalse(AutonomousDecisionAuthority.has_enforcement_privilege)

    def test_the_pipeline_module_does_not_import_a_firewall_at_module_scope(self):
        """A shadow deployment should not even load the enforcement path, so
        `sys.modules` stays an honest answer to "could this process have
        enforced anything"."""
        tree = ast.parse((PACKAGE / 'autonomy' / 'pipeline.py').read_text(encoding='utf-8'))
        top_level = [node for node in tree.body
                     if isinstance(node, (ast.Import, ast.ImportFrom))]
        for node in top_level:
            names = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                     else [node.module or ''])
            for name in names:
                with self.subTest(module=name):
                    self.assertNotIn('firewall', name)
                    self.assertNotIn('host_enforcer', name)
                    self.assertNotIn('temporary_blocks', name)


class TestShadowNeverEnforces(unittest.TestCase):
    """§5, §30. The complete path runs; the last step does not."""

    def _pipeline(self, *, enabled, mode, enforcer=None):
        authority = AutonomousDecisionAuthority(
            cost_policy=CostPolicy(), enabled=enabled, mode=mode)
        return AutonomousDecisionPipeline(authority=authority,
                                          cost_policy=CostPolicy(), enforcer=enforcer)

    def test_shadow_withholds_a_block_record_from_the_enforcer(self):
        pipeline = self._pipeline(enabled=True, mode=SHADOW,
                                  enforcer=RecordingEnforcer())
        execution, withheld = pipeline._enforce(_BlockedRecord())
        self.assertIsNone(execution)
        self.assertEqual(withheld, 'shadow_mode')
        self.assertEqual(pipeline.enforcer.calls, [])

    def test_a_disabled_authority_withholds_even_in_autonomous_mode(self):
        pipeline = self._pipeline(enabled=False, mode=AUTONOMOUS,
                                  enforcer=RecordingEnforcer())
        self.assertTrue(pipeline.shadow)
        execution, withheld = pipeline._enforce(_BlockedRecord())
        self.assertIsNone(execution)
        self.assertEqual(withheld, 'shadow_mode')

    def test_autonomous_with_no_enforcer_says_so_rather_than_nothing(self):
        pipeline = self._pipeline(enabled=True, mode=AUTONOMOUS)
        execution, withheld = pipeline._enforce(_BlockedRecord())
        self.assertIsNone(execution)
        self.assertEqual(withheld, 'no_host_enforcer_configured')

    def test_an_allow_record_is_not_a_withheld_block(self):
        pipeline = self._pipeline(enabled=True, mode=AUTONOMOUS,
                                  enforcer=RecordingEnforcer())
        execution, withheld = pipeline._enforce(_AllowRecord())
        self.assertIsNone(execution)
        self.assertEqual(withheld, '')

    def test_a_shadow_record_is_refused_by_the_request_builder_as_well(self):
        """Belt and braces, and deliberately so: the pipeline decides not to
        call, and the thing it would have called refuses a shadow record on its
        own. Either alone is one edit away from being wrong."""
        from eye_for_an_eye.security.enforcement import EnforcementError
        from eye_for_an_eye.security.host_enforcer import request_from_record
        with self.assertRaises(EnforcementError):
            request_from_record(_BlockedRecord(shadow=True))

    def test_from_config_attaches_no_enforcer_in_shadow(self):
        pipeline = pipeline_from_config(config(autonomy=True, mode='shadow', host=False))
        self.assertIsNone(pipeline.enforcer)
        self.assertTrue(pipeline.shadow)
        self.assertTrue(pipeline.owns_enforcement)


class TestTheBlockBudgetHasOneAccountant(unittest.TestCase):
    """§4, and a defect this wiring would otherwise have activated.

    `AutonomousDecisionAuthority.decide` charges the budget when it takes an
    enforceable block decision. `HostEnforcer` was written to charge it on a
    successful block, and its docstring gives the reason: a refusal is not an
    autonomous action. Both were true while nothing built an enforcer. With one
    built, a real block would spend the budget twice and `blocks_per_minute = 10`
    would mean five.
    """

    def test_the_pipeline_builds_the_enforcer_without_a_panel(self):
        source = inspect.getsource(
            __import__('eye_for_an_eye.autonomy.pipeline', fromlist=['_host_enforcer'])
            ._host_enforcer)
        self.assertNotIn('panel=', source,
                         'the enforcer charges the breaker panel as well as the '
                         'authority; one real block would spend two units of budget')

    def test_a_refused_enforcement_gives_the_lease_back(self):
        class Refusing:
            has_firewall_privilege = False

            def execute(self, record):
                from eye_for_an_eye.security.host_enforcer import ExecutionResult
                return ExecutionResult(requested=True, succeeded=False, refused=True,
                                       reason='the helper said no')

        authority = AutonomousDecisionAuthority(
            cost_policy=CostPolicy(), enabled=True, mode=AUTONOMOUS)
        pipeline = AutonomousDecisionPipeline(authority=authority,
                                              cost_policy=CostPolicy(),
                                              enforcer=Refusing())
        authority.panel.record_block(enforced=True)
        before = authority.panel.budget.active
        pipeline._enforce(_BlockedRecord())
        self.assertEqual(authority.panel.budget.active, before - 1,
                         'a refused request still occupies an active-block slot')

    def test_a_successful_enforcement_keeps_the_single_charge(self):
        class Succeeding:
            has_firewall_privilege = False

            def execute(self, record):
                from eye_for_an_eye.security.host_enforcer import ExecutionResult
                return ExecutionResult(requested=True, succeeded=True, refused=False)

        authority = AutonomousDecisionAuthority(
            cost_policy=CostPolicy(), enabled=True, mode=AUTONOMOUS)
        pipeline = AutonomousDecisionPipeline(authority=authority,
                                              cost_policy=CostPolicy(),
                                              enforcer=Succeeding())
        authority.panel.record_block(enforced=True)
        pipeline._enforce(_BlockedRecord())
        self.assertEqual(authority.panel.budget.active, 1)


class _BlockedRecord:
    """The smallest thing `_enforce` reads. Not a real decision, and not one
    this file ever treats as evidence about detection."""

    def __init__(self, *, shadow=False):
        self.blocked = True
        self.shadow = shadow
        self.decision_id = 'test-decision'
        self.source = '198.51.100.9'
        self.block_ttl_seconds = 300
        self.network_enforceable = True
        self.enforcement_scope = 'NETWORK_SOURCE'
        self.reason_codes = ('HIGH_PORT_BREADTH',)


class _AllowRecord(_BlockedRecord):
    def __init__(self):
        super().__init__()
        self.blocked = False


if __name__ == '__main__':
    unittest.main()


class TestTheServiceScopeSetIsBoundedByConfiguration(unittest.TestCase):
    """P15.5R. A cap on attacker-influenced state, applied in the safe order.

    `ScopeResolver.resolve` takes the most protective candidate, so a *dropped*
    candidate can only ever make a decision less protective. A cap applied to
    the raw list of destination ports in a window is therefore a cap a source
    can aim: touch enough other ports first and the priced one falls off the
    end, and the window is decided at the deployment default instead.

    Filtering by the operator's map before the cap moves the bound from
    something the traffic chooses to something the operator chose. Found by the
    runtime end-to-end test, which priced a port-22 scanner at `public_website`
    because port 22 was the twenty-first distinct port in that window.
    """

    class Sample:
        def __init__(self, port, transport='tcp'):
            self.port = port
            self.transport = transport

    def _resolver(self, mapping):
        from eye_for_an_eye.autonomy.scope import ScopeResolver
        return ScopeResolver(CostPolicy(scope_profiles=dict(mapping)))

    def test_a_priced_port_survives_however_many_others_came_first(self):
        from eye_for_an_eye.autonomy.scope import MAX_SERVICE_SCOPES
        resolver = self._resolver({'SERVICE:22/tcp': 'api'})
        window = [self.Sample(9000 + n) for n in range(MAX_SERVICE_SCOPES * 4)]
        window.append(self.Sample(22))
        self.assertEqual(resolver.services_for(window), ('SERVICE:22/tcp',))

    def test_unpriced_ports_never_enter_the_candidate_set(self):
        resolver = self._resolver({'SERVICE:443/tcp': 'api'})
        window = [self.Sample(port) for port in (80, 443, 8080)]
        self.assertEqual(resolver.services_for(window), ('SERVICE:443/tcp',))

    def test_the_list_is_still_bounded(self):
        from eye_for_an_eye.autonomy.scope import MAX_SERVICE_SCOPES
        mapping = {f'SERVICE:{port}/tcp': 'api' for port in range(1000, 1100)}
        resolver = self._resolver(mapping)
        window = [self.Sample(port) for port in range(1000, 1100)]
        self.assertEqual(len(resolver.services_for(window)), MAX_SERVICE_SCOPES)

    def test_the_most_protective_candidate_wins_a_tie_of_scopes(self):
        resolver = self._resolver({'SERVICE:22/tcp': 'honeypot',
                                   'SERVICE:443/tcp': 'api'})
        window = [self.Sample(22), self.Sample(443)]
        resolution = resolver.resolve(services=resolver.services_for(window))
        self.assertEqual(resolution.profile.name, 'api')
        self.assertTrue(resolution.ambiguous)

    def test_a_profile_that_forbids_blocking_wins_outright(self):
        resolver = self._resolver({'SERVICE:22/tcp': 'api',
                                   'SERVICE:9000/tcp': 'payment_webhook'})
        window = [self.Sample(22), self.Sample(9000)]
        resolution = resolver.resolve(services=resolver.services_for(window))
        self.assertEqual(resolution.profile.name, 'payment_webhook')
        self.assertFalse(resolution.profile.network_block_permitted)
