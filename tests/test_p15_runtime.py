"""P15 §104-§105, §160-§162 and §192-§194: starting, degrading, recovering.

Failure injection is the point of this file. §161 sets the bar: no failure may
produce a random block, a permanent block, a firewall flush, a website outage or
cross-site corruption. So each test breaks one thing and asserts the same two
properties — the system keeps running, and it does not block.

The pairing matters. "It did not crash" is easy and almost worthless on its own:
a system that survives a corrupt model by carrying on and blocking people has
failed in the expensive direction. "It did not block" alone is worthless too,
because a system that stops working is not protecting anything. Both together
are the behaviour §44 calls fail-safe.

The recovery tests are the ones with a trap in them. Coming back is supposed to
be automatic (§54, §193) and it is also supposed to be slow (§194), and those
pull against each other. A fault that clears must not immediately restore
autonomous blocking, because the measurement that degraded the system is usually
the same one that just wobbled back over its threshold. Each recovery test
therefore asserts what does *not* happen first.
"""
from pathlib import Path
import unittest

from eye_for_an_eye.autonomy.authority import AUTONOMOUS, AutonomousDecisionAuthority
from eye_for_an_eye.autonomy.breakers import BudgetLimits, BreakerPanel
from eye_for_an_eye.autonomy.record import ALLOW, TEMP_BLOCK
from eye_for_an_eye.autonomy.authority import DecisionInputs
from eye_for_an_eye.autonomy.runtime import (AUTONOMOUS as MODE_AUTONOMOUS,
                                             AutonomousRuntime, FAIL, NOT_APPLICABLE,
                                             PASS, SAFE_OBSERVE, SHADOW,
                                             evaluate_readiness)
from eye_for_an_eye.config import Config

#: The shipped v4 calibrator. Named rather than discovered: a fixture that
#: silently fell back to "no calibrator" would make every test below assert the
#: behaviour of a deployment that cannot block, which is not what they are for.
CALIBRATOR = Path(__file__).resolve().parents[1] / 'models' / 'mathrisk-cal-v4-isotonic.json'

#: `credentials_60s` deliberately absent: from P15.4 it measures credential
#: presence, belongs to no evidence family, and cannot support a block on its
#: own. `auth_failures_60s` is what carries `AUTH_BEHAVIOR` now.
CONTRIBUTIONS = {'ports_60s': 0.9, 'auth_failures_60s': 0.8,
                 'anomaly_60s': 0.7, 'persistence_900s': 0.4}

BLOCKABLE = dict(
    source='198.51.100.7', identity_confidence='HIGH', network_enforceable=True,
    enforcement_scope='NETWORK_SOURCE', observations=600, observation_seconds=300.0,
    data_quality=1.0, math_risk=0.99, math_contributions=CONTRIBUTIONS,
    ml_usable=True, model_score=0.97, calibrated=True, calibrated_probability=0.999,
    anomaly_score=0.8, ood_score=0.0, ood_status='IN_DISTRIBUTION',
    drift_status='STABLE', model_health='HEALTHY', policy_guard_action='ALLOW')


def ready_config():
    """A configuration that passes the gate, so tests can break one thing at a time.

    The calibrator became part of "ready" in P15.5R. An autonomous deployment
    without one refuses every block with `CALIBRATION_UNAVAILABLE`, so a
    configuration that named none was never actually ready — it only looked it,
    because nothing in the runtime loaded a calibrator at all.
    """
    config = Config()
    config.enforcement.management_networks = ['192.0.2.0/24']
    config.ml.enabled = False
    config.autonomy.enabled = True
    config.autonomy.mode = 'autonomous'
    config.autonomy.calibrator_path = str(CALIBRATOR)
    return config


class TestTheReadinessGate(unittest.TestCase):

    def test_the_prepared_configuration_passes(self):
        report = evaluate_readiness(ready_config())
        self.assertTrue(report.ready,
                        f'blocked by {[c.name for c in report.blocking]}')
        self.assertEqual(report.recommended_mode, MODE_AUTONOMOUS)

    def test_an_installation_with_no_protected_networks_is_refused(self):
        """§41. A tool that can lock its operator out has failed unrecoverably."""
        config = ready_config()
        config.enforcement.management_networks = []
        report = evaluate_readiness(config)
        self.assertFalse(report.ready)
        self.assertIn('protected_networks', [check.name for check in report.blocking])

    def test_one_critical_failure_is_enough_and_is_not_hidden(self):
        """§216."""
        config = ready_config()
        config.decision.enabled = False
        report = evaluate_readiness(config)
        self.assertFalse(report.ready)
        self.assertEqual(report.explain()['autonomous_ready'], 'NO')

    def test_a_missing_classifier_is_a_warning_rather_than_a_refusal(self):
        """§104 accepts a healthy model *or* a deterministic fallback."""
        config = ready_config()
        config.ml.enabled = True
        config.ml.model_path = ''
        report = evaluate_readiness(config)
        model = [check for check in report.checks if check.name == 'model_available'][0]
        self.assertEqual(model.status, FAIL)
        self.assertFalse(model.critical)
        self.assertTrue(report.ready)

    def test_the_enforcement_check_states_the_lab_restriction_plainly(self):
        """The check a green dashboard would be tempted to hide."""
        check = [c for c in evaluate_readiness(ready_config()).checks
                 if c.name == 'enforcement_available'][0]
        self.assertEqual(check.status, NOT_APPLICABLE)
        self.assertIn('lab namespace', check.detail)
        self.assertFalse(check.critical)

    def test_enabling_enforcement_outside_a_lab_fails_the_configuration_itself(self):
        config = ready_config()
        config.decision.mode = 'enforce'
        config.enforcement.enabled = True
        report = evaluate_readiness(config)
        self.assertFalse(report.ready)
        self.assertIn('config_valid', [check.name for check in report.blocking])

    def test_the_math_engine_check_runs_the_engine_rather_than_importing_it(self):
        check = [c for c in evaluate_readiness(ready_config()).checks
                 if c.name == 'math_engine'][0]
        self.assertEqual(check.status, PASS)
        # The version, not a fixed string: P15.3 made it v2 and a test that
        # pinned the literal would have read as a regression rather than as the
        # deliberate change it was.
        from eye_for_an_eye.decision.math_risk import VERSION
        self.assertIn(VERSION, check.detail)

    def test_the_report_refuses_to_be_read_as_an_accuracy_claim(self):
        body = evaluate_readiness(ready_config()).explain()
        self.assertIn('not a measurement of how often the decisions are right',
                      body['note'])


class TestStartup(unittest.TestCase):

    def test_a_passing_gate_starts_autonomous(self):
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        report = runtime.start(ready_config())
        self.assertTrue(report.ready)
        self.assertEqual(runtime.mode, MODE_AUTONOMOUS)
        self.assertTrue(runtime.authority.enabled)

    def test_a_failing_gate_starts_safe_and_says_so(self):
        """§105. Never a system that pretends to be enforcing."""
        config = ready_config()
        config.enforcement.management_networks = []
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        report = runtime.start(config)
        self.assertFalse(report.ready)
        self.assertEqual(runtime.mode, SAFE_OBSERVE)
        self.assertFalse(runtime.authority.enabled)
        self.assertIn('readiness:', runtime.transitions[-1]['reason'])

    def test_a_configuration_that_never_asked_for_autonomy_starts_in_shadow(self):
        config = ready_config()
        config.autonomy.enabled = False
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        runtime.start(config)
        self.assertEqual(runtime.mode, SHADOW)

    def test_starting_never_raises_on_a_broken_configuration(self):
        """A security tool that refuses to start is not protecting anything."""
        broken = Config()
        broken.decision.watch_threshold = 5.0
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        report = runtime.start(broken)
        self.assertFalse(report.ready)
        self.assertIn(runtime.mode, (SHADOW, SAFE_OBSERVE))


class TestFailureInjection(unittest.TestCase):
    """§160, §161. Break one thing; assert it keeps running and does not block."""

    FAULTS = ('model_invalid', 'feature_schema_mismatch', 'data_quality_unavailable',
              'identity_resolver_failed', 'firewall_verify_failed',
              'storage_corruption', 'site_isolation_failure', 'clock_anomaly',
              'model_registry_inconsistent')

    def runtime(self):
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        runtime.start(ready_config())
        self.assertEqual(runtime.mode, MODE_AUTONOMOUS)
        return runtime

    def test_every_injected_fault_degrades_instead_of_blocking(self):
        for fault in self.FAULTS:
            with self.subTest(fault=fault):
                runtime = self.runtime()
                runtime.degrade(fault, 'injected by test')
                self.assertEqual(runtime.mode, SAFE_OBSERVE)
                record = runtime.authority.decide(DecisionInputs(**BLOCKABLE))
                self.assertEqual(record.action, ALLOW)

    def test_a_fault_never_produces_a_random_or_permanent_block(self):
        runtime = self.runtime()
        runtime.degrade('storage_corruption')
        for index in range(50):
            record = runtime.authority.decide(
                DecisionInputs(**{**BLOCKABLE, 'source': f'198.51.100.{index}'}))
            self.assertEqual(record.action, ALLOW)
            self.assertEqual(record.block_ttl_seconds, 0)

    def test_degrading_does_not_stop_the_system_deciding_and_recording(self):
        """§55. Observation continues; only new blocks stop."""
        runtime = self.runtime()
        runtime.degrade('model_invalid')
        record = runtime.authority.decide(DecisionInputs(**BLOCKABLE))
        self.assertTrue(record.decision_id)
        self.assertTrue(record.reason_codes)
        self.assertTrue(record.math_risk > 0)

    def test_a_bad_feature_vector_is_an_allow_with_a_named_assumption(self):
        authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS)
        record = authority.decide(DecisionInputs(**{**BLOCKABLE,
                                                    'feature_schema_version': 99}))
        self.assertEqual(record.action, ALLOW)
        self.assertIn('feature_schema_compatible', record.failed_assumptions)
        self.assertIn('features', record.failed_subsystems)

    def test_a_clock_jump_stops_blocking_because_a_ttl_would_mean_nothing(self):
        authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS)
        record = authority.decide(DecisionInputs(**{**BLOCKABLE, 'clock_sane': False}))
        self.assertEqual(record.action, ALLOW)
        self.assertIn('clock_sane', record.failed_assumptions)

    def test_a_failed_firewall_verification_stops_new_blocks(self):
        authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS)
        record = authority.decide(
            DecisionInputs(**{**BLOCKABLE, 'enforcement_healthy': False}))
        self.assertEqual(record.action, ALLOW)


class TestAutomaticRecovery(unittest.TestCase):
    """§54, §193, §194. Automatic, and deliberately not immediate."""

    def runtime(self, cooldown=900.0):
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(cooldown_seconds=cooldown),
                             clock=lambda: clock[0])
        authority = AutonomousDecisionAuthority(panel=panel, clock=lambda: clock[0])
        runtime = AutonomousRuntime(authority=authority, cooldown_seconds=cooldown,
                                    clock=lambda: clock[0])
        runtime.start(ready_config())
        return runtime, clock

    def test_clearing_the_fault_does_not_immediately_restore_blocking(self):
        runtime, clock = self.runtime()
        runtime.degrade('model_invalid')
        runtime.resolve('model_invalid')
        mode, reason = runtime.attempt_recovery(ready_config())
        self.assertEqual(mode, SAFE_OBSERVE)
        self.assertIn('cooldown', reason)

    def test_recovery_happens_without_anybody_being_asked(self):
        runtime, clock = self.runtime(cooldown=60.0)
        runtime.degrade('model_invalid')
        runtime.resolve('model_invalid')
        clock[0] += 121.0
        mode, reason = runtime.attempt_recovery(ready_config())
        self.assertEqual(mode, MODE_AUTONOMOUS)
        self.assertEqual(reason, 'recovered')
        self.assertTrue(runtime.authority.enabled)

    def test_recovery_is_refused_while_a_second_fault_remains(self):
        runtime, clock = self.runtime(cooldown=60.0)
        runtime.degrade('model_invalid')
        runtime.degrade('storage_corruption')
        runtime.resolve('model_invalid')
        clock[0] += 121.0
        mode, reason = runtime.attempt_recovery(ready_config())
        self.assertEqual(mode, SAFE_OBSERVE)
        self.assertIn('technical fault', reason)

    def test_recovery_is_refused_when_the_readiness_gate_no_longer_passes(self):
        runtime, clock = self.runtime(cooldown=60.0)
        runtime.degrade('clock_anomaly')
        runtime.resolve('clock_anomaly')
        clock[0] += 121.0
        broken = ready_config()
        broken.enforcement.management_networks = []
        mode, reason = runtime.attempt_recovery(broken)
        self.assertEqual(mode, SAFE_OBSERVE)
        self.assertIn('readiness:', reason)

    def test_the_transitions_are_recorded_for_an_operator_to_read(self):
        runtime, clock = self.runtime(cooldown=60.0)
        runtime.degrade('model_invalid', 'digest mismatch')
        runtime.resolve('model_invalid')
        clock[0] += 121.0
        runtime.attempt_recovery(ready_config())
        reasons = [entry['reason'] for entry in runtime.transitions]
        self.assertTrue(any('digest mismatch' in reason for reason in reasons))
        self.assertTrue(any('cooldown' in reason for reason in reasons))

    def test_repeated_degrade_and_recover_does_not_flap(self):
        """§194. Ten cycles, and the mode changes only when it should."""
        runtime, clock = self.runtime(cooldown=100.0)
        for _ in range(10):
            runtime.degrade('model_invalid')
            runtime.resolve('model_invalid')
            self.assertEqual(runtime.attempt_recovery(ready_config())[0], SAFE_OBSERVE)
            clock[0] += 201.0
            self.assertEqual(runtime.attempt_recovery(ready_config())[0],
                             MODE_AUTONOMOUS)


class TestTheKillSwitch(unittest.TestCase):
    """§189, §190."""

    def test_disabling_is_local_immediate_and_stops_blocking(self):
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        runtime.start(ready_config())
        self.assertEqual(runtime.authority.decide(DecisionInputs(**BLOCKABLE)).action,
                         TEMP_BLOCK)
        runtime.disable()
        self.assertEqual(runtime.mode, SHADOW)
        self.assertEqual(runtime.authority.decide(DecisionInputs(**BLOCKABLE)).action,
                         ALLOW)

    def test_the_status_explains_what_safe_observe_means(self):
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        runtime.start(ready_config())
        runtime.degrade('model_invalid')
        body = runtime.status()
        self.assertIn('existing blocks still expire', body['note'])
        self.assertEqual(body['mode'], SAFE_OBSERVE)


class TestTheConfiguredModeIsHonoured(unittest.TestCase):
    """P15.5R §44. The mode an operator asked for is the mode they are told about.

    `start` read `autonomy.enabled` and ignored `autonomy.mode`, so the default
    and recommended production posture -- enabled, in shadow -- came back
    AUTONOMOUS. The sensor was never wrong: `authority.from_config` reads both
    settings and `pipeline.shadow` stays true. What was wrong was
    `eye-for-an-eye autonomy status`, which is the one command an operator runs
    to check whether they are blocking anybody.

    Two failures in one: a missing condition, and two constants called
    `AUTONOMOUS` in two modules with different cases -- the runtime state
    machine's `'AUTONOMOUS'` and the configured mode's `'autonomous'` -- so the
    first repair compared them directly and was quietly always False.
    """

    def shadow_config(self):
        config = ready_config()
        config.autonomy.mode = 'shadow'
        return config

    def test_an_enabled_shadow_deployment_reports_shadow(self):
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        report = runtime.start(self.shadow_config())
        self.assertTrue(report.ready, 'the fixture stopped passing the gate')
        self.assertEqual(runtime.mode, SHADOW)
        self.assertFalse(runtime.authority.enabled)

    def test_shadow_is_not_reported_as_a_fault_state(self):
        """SAFE_OBSERVE means "wanted to be autonomous and cannot be".

        A deployment configured for shadow is not in a fault state; it is doing
        what it was asked. `status()` says so twice: the mode is SHADOW, and
        `degraded_reason` is empty rather than carrying a complaint.
        """
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        runtime.start(self.shadow_config())
        body = runtime.status()
        self.assertNotEqual(body['mode'], SAFE_OBSERVE)
        self.assertEqual(body['mode'], SHADOW)
        self.assertEqual(body['degraded_reason'], '')

    def test_a_shadow_deployment_does_not_recover_into_autonomous(self):
        """The transition this object must never make on its own.

        The breaker cooldown is set explicitly and moved past, so the refusal
        under test is the configured mode rather than a breaker that had not
        finished counting -- which is what the first version of this test
        actually asserted.
        """
        clock = [1000.0]
        panel = BreakerPanel(BudgetLimits(cooldown_seconds=30.0),
                             clock=lambda: clock[0])
        runtime = AutonomousRuntime(
            authority=AutonomousDecisionAuthority(panel=panel,
                                                  clock=lambda: clock[0]),
            cooldown_seconds=30.0, clock=lambda: clock[0])
        runtime.start(ready_config())
        self.assertEqual(runtime.mode, MODE_AUTONOMOUS)
        runtime.degrade('model_invalid')
        runtime.resolve('model_invalid')
        clock[0] += 61.0
        mode, reason = runtime.attempt_recovery(self.shadow_config())
        self.assertEqual(mode, SAFE_OBSERVE)
        self.assertIn('autonomy.mode is shadow', reason)
        self.assertEqual(runtime.attempt_recovery(ready_config())[0],
                         MODE_AUTONOMOUS,
                         'nothing but the configured mode was holding it back')

    def test_the_two_mode_vocabularies_still_do_not_collide_by_accident(self):
        """The trap that made the first repair a no-op, pinned so it stays visible."""
        from eye_for_an_eye.autonomy import runtime as runtime_module
        self.assertNotEqual(runtime_module.AUTONOMOUS,
                            runtime_module.CONFIGURED_AUTONOMOUS,
                            'the runtime state and the configured mode became the '
                            'same string, so a comparison between them can no '
                            'longer be wrong in the way it was')
        self.assertEqual(runtime_module.CONFIGURED_AUTONOMOUS, AUTONOMOUS,
                         'the configured-mode constant drifted from the one '
                         'autonomy/authority.py actually reads')
        self.assertEqual(Config().autonomy.mode, 'shadow')

    def test_the_status_command_reports_the_configured_mode(self):
        """End to end, through the renderer an operator reads."""
        from eye_for_an_eye.autonomy_cli import render_status
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        runtime.start(self.shadow_config())
        rendered = render_status(runtime.status())
        self.assertIn('Mode:\nSHADOW', rendered)
        self.assertNotIn('Mode:\nAUTONOMOUS', rendered)


class TestTheSnippetEnableTellsYouToTypeActuallyWorks(unittest.TestCase):
    """P15.5R §44. The command whose whole job is to say what to type.

    It printed four lines that `config validate` refuses to load, because the
    same cycle that made `calibrator_path` mandatory for autonomous mode did not
    update the snippet. The readiness gate did not catch it either: without a
    calibrator the check is a *warning* in shadow mode -- deliberately, so a
    shadow deployment is not refused for being unable to act -- and the renderer
    printed only blocking failures. So the answer was AUTONOMOUS_READY: YES plus
    a configuration that cannot start.

    The test is the obvious one nobody had written: take what the command
    prints, write it to a file, and load it.
    """

    def snippet_config(self, autonomy_toml):
        import tempfile
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'eye-for-an-eye.toml'
        path.write_text('config_version = 1\n\n'
                        '[deployment]\nprofile = "sensor"\n\n'
                        '[decision]\nenabled = true\n\n'
                        '[enforcement]\nmanagement_networks = ["192.0.2.0/24"]\n\n'
                        + autonomy_toml, encoding='utf-8')
        return path

    def test_the_printed_configuration_loads(self):
        from eye_for_an_eye.autonomy_cli import enable_document
        from eye_for_an_eye.config import load_config
        document = enable_document(ready_config())
        self.assertEqual(document['autonomous_ready'], 'YES')
        self.assertTrue(document['configuration_is_complete'],
                        'the snippet says it is incomplete for a configuration '
                        'that has everything it needs')
        config = load_config(self.snippet_config(document['configuration_to_add']))
        self.assertTrue(config.autonomy.enabled)
        self.assertEqual(config.autonomy.mode, 'autonomous')
        self.assertEqual(config.autonomy.calibrator_path, str(CALIBRATOR))

    def test_a_snippet_that_cannot_load_says_so_instead_of_claiming_readiness(self):
        from eye_for_an_eye.autonomy_cli import enable_document, render_enable
        from eye_for_an_eye.config import load_config
        config = Config()
        config.enforcement.management_networks = ['192.0.2.0/24']
        config.ml.enabled = False
        document = enable_document(config)
        self.assertEqual(document['autonomous_ready'], 'YES',
                         'the gate is meant to pass here: no calibrator is a '
                         'warning in shadow, not a refusal')
        self.assertFalse(document['configuration_is_complete'])
        rendered = render_enable(document)
        self.assertIn('NOT complete', rendered)
        self.assertIn('calibrator', rendered)
        with self.assertRaises(ValueError):
            load_config(self.snippet_config(document['configuration_to_add']))

    def test_a_non_blocking_warning_is_printed_rather_than_swallowed(self):
        """A warning nobody prints is a check nobody ran."""
        from eye_for_an_eye.autonomy_cli import enable_document, render_enable
        config = Config()
        config.enforcement.management_networks = ['192.0.2.0/24']
        config.ml.enabled = False
        document = enable_document(config)
        self.assertIn('calibrator', document['warnings'])
        self.assertIn('calibrator', render_enable(document))

    def test_the_documented_configuration_block_loads_too(self):
        """The same check against the page an operator is more likely to read."""
        import re
        from eye_for_an_eye.config import load_config
        page = (Path(__file__).resolve().parents[1] / 'docs'
                / 'AUTONOMOUS_MODE.md').read_text(encoding='utf-8')
        blocks = [block for block in re.findall(r'```toml\n(.*?)```', page, re.DOTALL)
                  if '[autonomy]' in block and 'mode = "autonomous"' in block]
        self.assertTrue(blocks, 'the page no longer shows how to turn it on')
        for block in blocks:
            with self.subTest(block=block[:60]):
                config = load_config(
                    self.snippet_config(block.replace('<path to the calibrator>',
                                                      str(CALIBRATOR))))
                self.assertEqual(config.autonomy.mode, 'autonomous')


class TestTheCommandLine(unittest.TestCase):

    def test_readiness_returns_non_zero_when_the_gate_fails(self):
        from eye_for_an_eye.autonomy_cli import enable_document, render_enable
        config = Config()
        document = enable_document(config)
        self.assertEqual(document['autonomous_ready'], 'NO')
        self.assertIn('nothing was changed', render_enable(document))

    def test_enable_never_edits_the_configuration_itself(self):
        from eye_for_an_eye.autonomy_cli import enable_document, render_enable
        config = ready_config()
        config.autonomy.enabled = False
        document = enable_document(config)
        self.assertEqual(document['autonomous_ready'], 'YES')
        text = render_enable(document)
        self.assertIn('does not edit your', text)
        self.assertIn('[autonomy]', text)
        self.assertFalse(config.autonomy.enabled)

    def test_the_policy_output_names_the_costs_as_weights(self):
        from eye_for_an_eye.autonomy_cli import policy_document, render_policy
        text = render_policy(policy_document(ready_config()))
        self.assertIn('not money', text)
        self.assertIn('No autonomous block is ever permanent', text)

    def test_the_status_output_reports_no_fabricated_accuracy(self):
        from eye_for_an_eye.autonomy_cli import render_status
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        runtime.start(ready_config())
        text = render_status(runtime.status())
        self.assertIn('GROUND_TRUTH_UNAVAILABLE', text)

    def test_a_decision_record_from_an_unknown_schema_is_refused(self):
        import json
        import tempfile
        from pathlib import Path
        from eye_for_an_eye.autonomy_cli import explain_document
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'record.json'
            path.write_text(json.dumps({'record_version': 99, 'action': 'TEMP_BLOCK'}))
            with self.assertRaises(ValueError):
                explain_document(str(path))

    def test_the_science_report_without_labels_says_so(self):
        """§155, §156. The most tempting number is the one nobody has."""
        from eye_for_an_eye.autonomy_cli import render_science, science_document
        document = science_document(None)
        self.assertEqual(document['status'], 'GROUND_TRUTH_UNAVAILABLE')
        self.assertIn('GROUND_TRUTH_UNAVAILABLE', render_science(document))
        self.assertIn('reviewed_evaluation', document['accepted_label_sources'])

    def test_the_science_report_with_labels_reports_the_release_metric(self):
        import json
        import tempfile
        from pathlib import Path
        from eye_for_an_eye.autonomy_cli import render_science, science_document
        rows = ([{'blocked': False, 'label': 'BENIGN', 'score': 0.1}] * 900
                + [{'blocked': True, 'label': 'BENIGN', 'score': 0.9}] * 1
                + [{'blocked': True, 'label': 'MALICIOUS_AUTOMATION', 'score': 0.95}] * 80
                + [{'blocked': False, 'label': 'MALICIOUS_AUTOMATION', 'score': 0.2}] * 20)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'eval.json'
            path.write_text(json.dumps(rows))
            document = science_document(str(path))
        text = render_science(document)
        self.assertIn('False blocks per 1000 benign', text)
        self.assertIn('used for nothing', text)
        self.assertEqual(document['usefulness'], 'USEFUL')

    def test_a_current_record_renders_with_its_reasons(self):
        import json
        import tempfile
        from pathlib import Path
        from eye_for_an_eye.autonomy_cli import explain_document, render_explain
        authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS)
        record = authority.decide(DecisionInputs(**BLOCKABLE))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'record.json'
            path.write_text(json.dumps(record.explain()))
            text = render_explain(explain_document(str(path)))
        self.assertIn('TEMP_BLOCK', text)
        self.assertIn('automated credential attempts', text)
        self.assertIn('then it expires', text)


if __name__ == '__main__':
    unittest.main()
