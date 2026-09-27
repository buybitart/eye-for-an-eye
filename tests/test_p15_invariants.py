"""P15 §195: fourteen invariants, and the module-graduation claims that must stay true.

These are not tests of features. They are regression tests for properties that
somebody breaks later by adding one convenient function, and each one is written
so that the convenient function fails the build rather than the deployment.

Where an invariant is already enforced elsewhere in the suite, the test here
still asserts it rather than deferring — a property enforced in exactly one place
is one delete away from being enforced nowhere, and these fourteen are the ones
where that would matter most.

Two of them are asserted structurally rather than behaviourally, and it is worth
saying which and why.

**Invariant 14, hack-back, has nothing to enforce.** There is no retaliation code
in this repository, so the test reads the source tree and asserts there is still
none. That is a weaker guarantee than a runtime refusal and a stronger one than a
policy document, and it is the honest one: you cannot switch off a capability that
was never written.

**Invariant 12, CDN blocking, is enforced in three independent places** — the
identity resolver, the web sensor, and now the decision authority. The test
checks the authority, because that is the new one, and the others have their own
tests in `test_web_enforcement_safety.py`.
"""
import ast
import unittest
from pathlib import Path

from eye_for_an_eye.autonomy import record as codes
from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               DecisionInputs)
from eye_for_an_eye.autonomy.record import ALLOW, MAX_BLOCK_TTL_SECONDS, TEMP_BLOCK
from eye_for_an_eye.config import Config, load_config

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'eye_for_an_eye'
TEMPLATES = PACKAGE / 'templates'

#: The one shipped template that turns autonomous host blocking on, and the
#: reason the invariants below name it rather than forbidding it outright.
#:
#: P16 added the two production postures. `production-autonomous` is what an
#: operator selects when they have decided to block, and this file's own words
#: for why that is a different thing from a default are worth keeping: *a guard
#: protects somebody who has decided to block, and a default protects somebody
#: who has not decided anything.*
#:
#: So the invariant is sharper than "no profile", not weaker than it. Every
#: other template must have enforcement off; a fresh `Config()` must have it
#: off; and this one has to *refuse to validate as shipped*, which is checked
#: below. An operator reaches a blocking deployment only by selecting this
#: profile and then supplying the networks that must never be blocked.
ENFORCING_TEMPLATE = 'production-autonomous.toml'

CONTRIBUTIONS = {'ports_60s': 0.9, 'credentials_60s': 0.8,
                 'anomaly_60s': 0.7, 'persistence_900s': 0.4}

BLOCKABLE = dict(
    source='198.51.100.7', identity_confidence='HIGH', network_enforceable=True,
    enforcement_scope='NETWORK_SOURCE', observations=600, observation_seconds=300.0,
    data_quality=1.0, math_risk=0.99, math_contributions=CONTRIBUTIONS,
    ml_usable=True, model_score=0.97, calibrated=True, calibrated_probability=0.999,
    anomaly_score=0.8, ood_score=0.0, ood_status='IN_DISTRIBUTION',
    drift_status='STABLE', model_health='HEALTHY', policy_guard_action='ALLOW')


def python_files(*roots):
    for root in roots:
        for path in sorted(root.rglob('*.py')):
            if '__pycache__' not in path.parts:
                yield path


def decide(**changes):
    authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS)
    return authority.decide(DecisionInputs(**{**BLOCKABLE, **changes}))


class TestInvariant01CandidateNeverWritesFirewall(unittest.TestCase):

    def test_no_candidate_or_training_module_imports_the_firewall(self):
        roots = (PACKAGE / 'decision', PACKAGE / 'governance', PACKAGE / 'autonomy',
                 ROOT / 'training', ROOT / 'dataset')
        allowed = {'engine.py'}          # the sensor's own engine holds the enforcer
        for path in python_files(*(root for root in roots if root.is_dir())):
            if path.name in allowed:
                continue
            with self.subTest(module=str(path.relative_to(ROOT))):
                tree = ast.parse(path.read_text(encoding='utf-8'))
                for node in ast.walk(tree):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        names = [(node.module or '')] + [a.name for a in node.names]
                    for name in names:
                        self.assertNotIn('firewall', name)
                        self.assertNotIn('temporary_blocks', name)


class TestInvariant02MLCannotBypassPolicyGuard(unittest.TestCase):

    def test_a_policy_guard_refusal_survives_a_perfect_model_score(self):
        record = decide(policy_guard_action='REFUSED', model_score=1.0,
                        calibrated_probability=1.0)
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.POLICY_GUARD_REFUSED, record.reason_codes)

    def test_the_authority_cannot_raise_an_action_policy_guard_lowered(self):
        """PolicyGuard weakens; nothing in the authority can undo that."""
        from eye_for_an_eye.decision.policy import PolicyGuard
        source = (PACKAGE / 'decision' / 'policy.py').read_text(encoding='utf-8')
        self.assertIn('It can never raise one', source)
        self.assertTrue(hasattr(PolicyGuard, 'apply'))


class TestInvariant03OODIsNeverMalicious(unittest.TestCase):

    def test_an_extreme_out_of_distribution_sample_reduces_authority(self):
        """§27, §82, §176. Unfamiliar means the model knows less, not that the
        source is guilty."""
        record = decide(ood_status='OUT_OF_DISTRIBUTION', ood_score=1.0)
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.HIGH_OOD, record.reason_codes)

    def test_a_higher_ood_score_never_raises_the_conservative_estimate(self):
        from eye_for_an_eye.autonomy.uncertainty import assess
        previous = 1.0
        for score in (0.0, 0.25, 0.5, 0.75, 1.0):
            doubt = assess(calibrated=True, ood_score=score, data_quality_score=1.0,
                           observations=1000)
            value = doubt.conservative_probability(0.99)
            self.assertLessEqual(value, previous)
            previous = value


class TestInvariant04AnomalyIsNeverMalicious(unittest.TestCase):

    def test_a_maximum_anomaly_score_alone_does_not_block(self):
        """§177. The unusual backup job is the case this protects."""
        record = decide(anomaly_score=1.0, math_contributions={}, model_score=None,
                        ml_usable=False, calibrated=False, calibrated_probability=None)
        self.assertEqual(record.action, ALLOW)

    def test_anomaly_is_not_a_behavioural_family(self):
        from eye_for_an_eye.autonomy.evidence import ANOMALY, BEHAVIOURAL_FAMILIES
        self.assertNotIn(ANOMALY, BEHAVIOURAL_FAMILIES)


class TestInvariant05DriftIsNeverMalicious(unittest.TestCase):

    def test_drift_reduces_authority_rather_than_raising_suspicion(self):
        record = decide(drift_status='DRIFTED')
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.DRIFT_DEGRADED, record.reason_codes)

    def test_drift_is_not_a_signal_family(self):
        from eye_for_an_eye.autonomy.evidence import FAMILIES
        self.assertNotIn('DRIFT', FAMILIES)
        for family in FAMILIES:
            self.assertNotIn('drift', family.lower())


class TestInvariant06BlockIsNeverTrainingGroundTruth(unittest.TestCase):

    def test_the_forbidden_label_vocabulary_still_rejects_a_block(self):
        from training.schema import ALLOWED_LABEL_SOURCES, FORBIDDEN_LABEL_SOURCES
        for name in ('blocked', 'automatically_blocked', 'ml_score', 'final_risk'):
            with self.subTest(label_source=name):
                self.assertIn(name, FORBIDDEN_LABEL_SOURCES)
                self.assertNotIn(name, ALLOWED_LABEL_SOURCES)

    def test_the_false_positive_breaker_refuses_self_generated_outcomes(self):
        from eye_for_an_eye.autonomy.breakers import (BreakerError,
                                                      FalsePositiveBreaker,
                                                      TRUSTED_OUTCOME_SOURCES)
        for name in ('autonomous_block', 'temp_block', 'ml_high', 'heuristic'):
            with self.subTest(source=name):
                self.assertNotIn(name, TRUSTED_OUTCOME_SOURCES)
                with self.assertRaises(BreakerError):
                    FalsePositiveBreaker().report(false_blocks=1, benign_sources=1,
                                                  source=name)

    def test_an_autonomous_decision_carries_no_label_field(self):
        body = decide().explain()
        for key in ('label', 'ground_truth', 'is_malicious', 'verdict'):
            with self.subTest(key=key):
                self.assertNotIn(key, body)


class TestInvariant07ChallengeOutcomeIsNeverGroundTruth(unittest.TestCase):

    def test_no_reason_code_treats_a_challenge_result_as_evidence_of_a_class(self):
        for code in codes.REASON_CODES:
            with self.subTest(code=code):
                self.assertNotIn('CHALLENGE_FAILED', code)
                self.assertNotIn('CHALLENGE_PASSED', code)

    def test_the_challenge_policy_still_says_so_in_words(self):
        source = (PACKAGE / 'challenge' / 'policy.py').read_text(encoding='utf-8')
        self.assertIn('never a training label', source)


class TestInvariant08HostHeaderIsNeverTrustedSiteID(unittest.TestCase):

    def test_a_host_header_cannot_create_a_site(self):
        """The resolver has no method that adds one, which is the whole guarantee."""
        from eye_for_an_eye.sites.identity import SiteResolver, UNKNOWN_SITE
        resolver = SiteResolver({'main': ['example.org']})
        self.assertEqual(resolver.resolve('anything-i-like.example.net').site_id,
                         UNKNOWN_SITE)
        self.assertEqual(resolver.resolve('example.org').site_id, 'main')
        self.assertFalse([name for name in dir(resolver)
                          if name.startswith(('add', 'register', 'create'))])

    def test_a_traversal_attempt_in_a_site_name_is_stripped_not_stored(self):
        from eye_for_an_eye.sites.identity import normalise_site_id
        self.assertNotIn('/', normalise_site_id('../../etc/passwd'))

    def test_a_decision_scope_comes_from_configuration_not_from_a_request(self):
        """The authority is given a scope; it never parses one out of traffic."""
        source = (PACKAGE / 'autonomy' / 'authority.py').read_text(encoding='utf-8')
        for forbidden in ('host', 'headers', 'request.'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(f'{forbidden}=', source.lower())


class TestInvariant09UntrustedProxyHeaderIsNeverIdentity(unittest.TestCase):

    def test_a_forwarded_header_from_an_unknown_peer_is_ignored(self):
        from eye_for_an_eye.web.identity import ClientResolver
        identity = ClientResolver(['10.0.0.0/8']).resolve(
            '203.0.113.9', forwarded='198.51.100.1')
        self.assertEqual(identity.address, '203.0.113.9')
        self.assertTrue(identity.forwarded_ignored)

    def test_a_low_confidence_identity_cannot_reach_a_block(self):
        record = decide(identity_confidence='LOW')
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.IDENTITY_UNCERTAIN, record.reason_codes)


class TestInvariant10AutomaticBlockAlwaysExpires(unittest.TestCase):

    def test_every_block_record_carries_a_bounded_positive_ttl(self):
        for offences in range(0, 12):
            with self.subTest(offences=offences):
                record = decide(offence_count=offences)
                self.assertEqual(record.action, TEMP_BLOCK)
                self.assertGreater(record.block_ttl_seconds, 0)
                self.assertLessEqual(record.block_ttl_seconds, MAX_BLOCK_TTL_SECONDS)

    def test_the_configured_ladder_cannot_exceed_the_ceiling(self):
        config = Config()
        for value in config.enforcement.block_seconds:
            with self.subTest(seconds=value):
                self.assertLessEqual(value, MAX_BLOCK_TTL_SECONDS)

    def test_no_code_path_produces_a_permanent_ban(self):
        for name in ('permanent_block', 'permanent_ban', 'blacklist_forever',
                     'ban_forever'):
            with self.subTest(name=name):
                for path in python_files(PACKAGE):
                    self.assertNotIn(name, path.read_text(encoding='utf-8'))


class TestInvariant11SiteLocalActionStaysLocal(unittest.TestCase):

    def test_a_site_scoped_decision_names_only_its_own_scope(self):
        record = decide(scope='SITE:main', site_id='main')
        self.assertEqual(record.scope, 'SITE:main')
        self.assertEqual(record.site_id, 'main')

    def test_a_cost_profile_for_one_scope_does_not_change_another(self):
        from eye_for_an_eye.autonomy.cost import CostPolicy
        policy = CostPolicy().with_scope('SITE:a', 'honeypot')
        self.assertEqual(policy.for_scope('SITE:a').name, 'honeypot')
        self.assertEqual(policy.for_scope('SITE:b').name, 'public_website')


class TestInvariant12CDNClientNeverBlocksTheCDN(unittest.TestCase):

    def test_a_client_known_only_through_a_proxy_is_never_network_blocked(self):
        """§40, §178. Blocking the edge takes the site off the air for everyone."""
        record = decide(network_enforceable=False, enforcement_scope='WEB_CLIENT')
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.NOT_NETWORK_ENFORCEABLE, record.reason_codes)

    def test_the_resolver_marks_a_proxy_chain_as_not_enforceable(self):
        from eye_for_an_eye.web.identity import ClientResolver, source_scope
        identity = ClientResolver(['10.0.0.0/8']).resolve(
            '10.1.2.3', forwarded='198.51.100.77')
        self.assertFalse(identity.network_enforceable)
        self.assertEqual(source_scope(identity), 'WEB_CLIENT')


class TestInvariant13UnboundedRemoteStateIsImpossible(unittest.TestCase):

    def test_the_mass_block_distinct_source_set_is_capped(self):
        from eye_for_an_eye.autonomy.breakers import BreakerPanel
        panel = BreakerPanel()
        for index in range(25_000):
            panel.observe_source(f'source-{index}')
        self.assertLessEqual(len(panel.mass_block._distinct), 20_000)

    def test_the_block_budget_window_is_bounded_by_construction(self):
        from eye_for_an_eye.autonomy.breakers import BlockBudget, BudgetLimits
        budget = BlockBudget(BudgetLimits(blocks_per_minute=5))
        budget.record(10_000)
        self.assertLessEqual(len(budget._recent), 20)

    def test_a_decision_record_cannot_grow_without_limit(self):
        record = decide()
        self.assertLessEqual(len(record.reason_codes), 16)
        self.assertLessEqual(len(record.math_contributions), 6)
        self.assertLessEqual(len(record.policy_guard_reasons), 8)

    def test_the_transition_log_is_trimmed(self):
        from eye_for_an_eye.autonomy.runtime import AutonomousRuntime
        runtime = AutonomousRuntime(authority=AutonomousDecisionAuthority())
        for index in range(200):
            runtime._transition('AUTONOMOUS' if index % 2 else 'SHADOW', 'churn')
        self.assertLessEqual(len(runtime.transitions), 32)


class TestInvariant14HackBackCannotBeEnabled(unittest.TestCase):
    """There is no capability to disable, which is the strongest form of this."""

    FORBIDDEN = ('hack_back', 'hackback', 'retaliate', 'retaliation', 'counter_attack',
                 'counterattack', 'strike_back', 'exploit_target', 'attack_source')

    def test_no_module_contains_retaliation_code(self):
        for path in python_files(PACKAGE, ROOT / 'training', ROOT / 'dataset'):
            text = path.read_text(encoding='utf-8').lower()
            for name in self.FORBIDDEN:
                with self.subTest(module=path.name, term=name):
                    self.assertNotIn(name, text)

    def test_no_configuration_setting_could_turn_one_on(self):
        from dataclasses import fields
        config = Config()
        for section in fields(config):
            value = getattr(config, section.name)
            if not hasattr(value, '__dataclass_fields__'):
                continue
            for setting in fields(value):
                with self.subTest(setting=f'{section.name}.{setting.name}'):
                    for name in self.FORBIDDEN:
                        self.assertNotIn(name, setting.name.lower())

    def test_the_only_outward_reaching_module_stays_lab_only(self):
        config = Config()
        self.assertFalse(config.active_probes.enabled)
        config.active_probes.enabled = True
        config.deployment.profile = 'sensor'
        with self.assertRaises(ValueError):
            config.validate()


# --- module graduation claims (§3, §207) -----------------------------------

class TestEnforcementStaysLabOnly(unittest.TestCase):
    """`docs/MODULE_GRADUATION.md` makes three claims. These are them.

    P15.1 added a real-host path beside the namespace one, so a fourth claim
    joins them: that path is off in every shipped profile too. The lab claims
    below are unchanged, and that is the point — the host path was written as
    new code next to the guards, not by loosening them.
    """

    def test_no_shipped_profile_enables_the_lab_namespace_path(self):
        """The namespace path stays lab-only in every profile without exception.

        `production-autonomous` enables the *host* path and not this one; the
        configuration refuses both at once, because one set of protected
        networks cannot describe two places to enforce in.
        """
        for path in sorted(TEMPLATES.glob('*.toml')):
            with self.subTest(profile=path.name):
                config = load_config(str(path), validate=False)
                self.assertFalse(config.enforcement.enabled,
                                 f'{path.name} ships with lab enforcement on')

    def test_only_the_autonomous_profile_enables_host_enforcement(self):
        """§20. Installing this must never be the act that turns blocking on.

        The default matters more than any of the guards behind it: a guard
        protects somebody who has decided to block, and a default protects
        somebody who has not decided anything.
        """
        self.assertFalse(Config().enforcement.host_enabled,
                         'a fresh configuration can block on a real host')
        for path in sorted(TEMPLATES.glob('*.toml')):
            if path.name == ENFORCING_TEMPLATE:
                continue
            with self.subTest(profile=path.name):
                config = load_config(str(path), validate=False)
                self.assertFalse(config.enforcement.host_enabled,
                                 f'{path.name} ships with host enforcement on')

    def test_the_enforcing_profile_refuses_to_validate_as_shipped(self):
        """What keeps the exception above from being a hole.

        The template turns host blocking on and leaves `management_networks`
        empty, so it cannot start until an operator says which addresses must
        never be blocked. Selecting the profile is a decision; the refusal is
        what stops that decision from being a careless one.
        """
        path = TEMPLATES / ENFORCING_TEMPLATE
        self.assertTrue(path.is_file(), 'the enforcing template is named and absent')
        config = load_config(str(path), validate=False)
        self.assertTrue(config.enforcement.host_enabled)
        with self.assertRaises(ValueError) as raised:
            config.validate()
        self.assertIn('management_networks', str(raised.exception))

    def test_host_enforcement_without_a_protected_network_is_refused(self):
        """A host that can be locked out of itself is not one this may act on."""
        config = Config()
        config.decision.enabled = True
        config.enforcement.host_enabled = True
        config.enforcement.management_networks = ()
        config.enforcement.allowlist = ()
        with self.assertRaises(ValueError):
            config.validate()

    def test_the_two_enforcement_paths_cannot_both_be_on(self):
        config = Config()
        config.decision.enabled = True
        config.enforcement.enabled = True
        config.enforcement.host_enabled = True
        config.enforcement.management_networks = ('203.0.113.0/24',)
        with self.assertRaises(ValueError):
            config.validate()

    def test_enforcement_outside_a_lab_namespace_is_refused(self):
        config = Config()
        config.decision.enabled = True
        config.decision.mode = 'enforce'
        config.enforcement.enabled = True
        config.deployment.profile = 'sensor'
        with self.assertRaises(ValueError):
            config.validate()

    def test_the_firewall_backend_still_refuses_the_host_namespace(self):
        source = (PACKAGE / 'security' / 'firewall.py').read_text(encoding='utf-8')
        self.assertIn('refusing the initial/host network namespace', source)
        self.assertIn('/proc/1/ns/net', source)
        self.assertIn("'netns', 'exec'", source)

    def test_no_autonomy_setting_can_reach_the_firewall(self):
        from dataclasses import fields
        for setting in fields(Config().autonomy):
            with self.subTest(setting=setting.name):
                for forbidden in ('firewall', 'nftables', 'namespace', 'enforce'):
                    self.assertNotIn(forbidden, setting.name.lower())


class TestDeceptionCannotReachAShell(unittest.TestCase):
    """§8. Checked by reading the package, not by reading its documentation."""

    def test_no_deception_module_imports_a_process_or_database(self):
        for path in python_files(PACKAGE / 'deception'):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or '']
                for name in names:
                    with self.subTest(module=path.name, imported=name):
                        for forbidden in ('subprocess', 'sqlite3', 'shutil', 'pty', 'os.system'):
                            self.assertNotIn(forbidden, name)

    def test_no_deception_module_calls_eval_or_exec(self):
        for path in python_files(PACKAGE / 'deception'):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    with self.subTest(module=path.name, call=node.func.id):
                        self.assertNotIn(node.func.id, ('eval', 'exec', 'compile'))


class TestAutonomyIsOffByDefault(unittest.TestCase):

    def test_a_fresh_configuration_is_not_autonomous(self):
        config = Config()
        self.assertFalse(config.autonomy.enabled)
        self.assertEqual(config.autonomy.mode, 'shadow')

    def test_no_shipped_profile_turns_autonomy_on_without_being_chosen(self):
        """The two production postures run the authority; nothing else does.

        Running the authority is not the same as acting on it. Shadow enables
        it precisely so that a deployment can see what it would have done, and
        `test_only_the_autonomous_profile_enables_host_enforcement` is what
        keeps "decides" apart from "blocks".
        """
        for path in sorted(TEMPLATES.glob('*.toml')):
            if path.name.startswith('production-'):
                continue
            with self.subTest(profile=path.name):
                self.assertFalse(load_config(str(path), validate=False).autonomy.enabled)

    def test_the_shadow_posture_decides_and_does_not_act(self):
        config = load_config(str(TEMPLATES / 'production-shadow.toml'))
        self.assertTrue(config.autonomy.enabled)
        self.assertEqual(config.autonomy.mode, 'shadow')
        self.assertFalse(config.enforcement.host_enabled)

    def test_autonomy_requires_the_decision_engine(self):
        config = Config()
        config.autonomy.enabled = True
        config.decision.enabled = False
        with self.assertRaises(ValueError):
            config.validate()

    def test_the_kill_switch_is_local_and_immediate(self):
        """§189, §190. No cloud anywhere in the path."""
        authority = AutonomousDecisionAuthority(enabled=True, mode=AUTONOMOUS)
        self.assertEqual(authority.decide(DecisionInputs(**BLOCKABLE)).action, TEMP_BLOCK)
        authority.deactivate()
        record = authority.decide(DecisionInputs(**BLOCKABLE))
        self.assertEqual(record.action, ALLOW)
        self.assertIn(codes.AUTONOMY_DISABLED, record.reason_codes)


class TestNoLLMAndNoReinforcementLearningInTheDecisionPath(unittest.TestCase):
    """§56, §57. Neither exists here, and the test says where it looked."""

    FORBIDDEN = ('openai', 'anthropic', 'llm', 'gpt', 'langchain', 'transformers',
                 'epsilon_greedy', 'thompson', 'q_learning', 'qlearning',
                 'policy_gradient', 'replay_buffer')

    def test_the_runtime_package_imports_nothing_of_the_kind(self):
        for path in python_files(PACKAGE):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or '']
                for name in names:
                    with self.subTest(module=path.name, imported=name):
                        for forbidden in self.FORBIDDEN:
                            self.assertNotIn(forbidden, name.lower())

    def test_the_final_action_set_contains_no_exploratory_arm(self):
        """§58. TEMP_BLOCK is never an experiment on a real visitor."""
        from eye_for_an_eye.autonomy.record import FINAL_ACTIONS
        self.assertEqual(set(FINAL_ACTIONS), {'ALLOW', 'TEMP_BLOCK'})


if __name__ == '__main__':
    unittest.main()
