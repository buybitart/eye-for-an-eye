"""P14 phases 4-5: the promotion transaction, the journal, and guarded activation.

Everything here is about the moment something actually changes. The governance
engine can be wrong and refuse a good model; this code can be wrong and leave a
website with no model, two models, or a model that cannot answer. So the tests
are mostly about interruption: kill the process at each phase, fill the disk,
restart in the middle, and ask afterwards whether the answer is unambiguous.

The property being defended throughout is not "promotion works". It is that
every reachable intermediate state has exactly one correct resolution, and that
the system finds it without guessing.
"""
import json
import tempfile
import unittest
from pathlib import Path

from eye_for_an_eye.decision.features import INPUT_ORDER, SCHEMA_VERSION
from eye_for_an_eye.decision.registry import ModelRegistry
from eye_for_an_eye.governance import journal as journal_module
from eye_for_an_eye.governance.activation import (ActivationError, PromotionActivator,
                                                  ScopeLock, ScopeLocked)
from eye_for_an_eye.governance.assessment import (ELIGIBLE, NOT_ELIGIBLE,
                                                  PromotionAssessmentRecord)
from eye_for_an_eye.governance.guarded import (ADVANCE, COMPLETE, CONTINUE, HOLD,
                                               GuardedStore, ceiling_for, clamp,
                                               evaluate_advance)
from eye_for_an_eye.governance.policy import (ACTION_LADDER, AutoPromoteSettings,
                                              GovernancePolicy)

SITE = 'SITE:main'


def manifest(version, *, scope=SITE, **overrides):
    payload = {'manifest_version': 1, 'model_version': version,
               'model_family': 'logistic_regression',
               'feature_schema_version': SCHEMA_VERSION,
               'training_dataset_version': 'dataset-v2', 'parent_model': '',
               'created_at': '2026-09-11T00:00:00+00:00', 'scope': scope,
               'recommended_mode': 'shadow', 'feature_order': list(INPUT_ORDER)}
    payload.update(overrides)
    return payload


def artifacts(version, *, scope=SITE, model=b'onnx-bytes', **overrides):
    return {'classifier.onnx': model,
            'manifest.json': json.dumps(manifest(version, scope=scope, **overrides)).encode(),
            'distribution.json': json.dumps({'distribution_version': 1}).encode()}


def policy(**changes):
    import dataclasses
    auto = AutoPromoteSettings(enabled=True, sites=('main',))
    return dataclasses.replace(GovernancePolicy(auto_promote=auto), **changes)


def eligible(version='web-risk-v5', *, scope=SITE, current_policy=None):
    current_policy = current_policy or policy()
    return PromotionAssessmentRecord(
        scope=scope, candidate_version=version, decision=ELIGIBLE,
        policy_version=current_policy.version, policy_digest=current_policy.digest,
        active_version='web-risk-v4', created_at='2026-09-11T00:00:00+00:00')


class ActivationCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = policy()
        self.registry = ModelRegistry(self.root / 'models', scope=SITE)
        self.registry.register_candidate('web-risk-v4', artifacts('web-risk-v4'))
        self.registry.promote('web-risk-v4', gate_passed=True, reason='seed')
        self.registry.register_candidate('web-risk-v5', artifacts('web-risk-v5'))
        self.warmups = []

    def warmup(self, resolved):
        self.warmups.append(resolved and resolved.get('version'))
        return True

    def activator(self):
        return PromotionActivator(root=self.root / 'governance', policy=self.policy)


class TestTheTransactionSucceeds(ActivationCase):
    """§127. The happy path lands in guarded, never in full ACTIVE."""

    def test_an_eligible_candidate_becomes_guarded_not_active(self):
        result = self.activator().promote(assessment=eligible(),
                                          registry=self.registry,
                                          warmup=self.warmup)
        self.assertTrue(result.activated)
        self.assertEqual(result.stage, 'GUARDED_ACTIVE_STAGE_1')
        self.assertEqual(self.registry.state.active, 'web-risk-v5')

        state = GuardedStore(self.root / 'governance').load(SITE)
        self.assertIsNotNone(state, 'the model is active with no guarded record')
        self.assertEqual(state.stage, 'GUARDED_ACTIVE_STAGE_1')
        self.assertEqual(state.previous_version, 'web-risk-v4')

    def test_the_first_ceiling_cannot_block_anybody(self):
        """§37. Whatever it thinks, on its own it may only raise attention."""
        self.activator().promote(assessment=eligible(), registry=self.registry,
                                 warmup=self.warmup)
        state = GuardedStore(self.root / 'governance').load(SITE)
        self.assertEqual(ceiling_for(state, self.policy), 'WATCH')

    def test_the_model_is_loaded_before_the_pointer_moves(self):
        """§148. Switch first and discover it fails to load is how this becomes
        an outage."""
        self.activator().promote(assessment=eligible(), registry=self.registry,
                                 warmup=self.warmup)
        self.assertEqual(self.warmups[0], 'web-risk-v5',
                         'the candidate was not warmed up before activation')
        self.assertEqual(len(self.warmups), 2,
                         'inference was not verified again after the switch')

    def test_the_rollback_target_is_recorded(self):
        result = self.activator().promote(assessment=eligible(),
                                          registry=self.registry,
                                          warmup=self.warmup)
        self.assertEqual(result.rollback_target, 'web-risk-v4')
        self.assertEqual(self.registry.state.previous_active, 'web-risk-v4')

    def test_the_previous_model_is_still_on_disk(self):
        """§119. Promotion never deletes the way back."""
        self.activator().promote(assessment=eligible(), registry=self.registry,
                                 warmup=self.warmup)
        path = Path(self.registry.version_path('web-risk-v4')) / 'classifier.onnx'
        self.assertTrue(path.is_file())


class TestTheTransactionRefuses(ActivationCase):
    """Everything that must stop before the pointer moves."""

    def assertUnchanged(self):
        self.assertEqual(self.registry.state.active, 'web-risk-v4',
                         'the active model changed on a path that must not change it')

    def test_a_non_eligible_assessment_is_refused(self):
        import dataclasses
        assessment = dataclasses.replace(eligible(), decision=NOT_ELIGIBLE)
        with self.assertRaises(ActivationError):
            self.activator().promote(assessment=assessment, registry=self.registry,
                                     warmup=self.warmup)
        self.assertUnchanged()

    def test_an_assessment_from_another_policy_is_refused(self):
        """§29, §141. A policy change never retroactively authorises anything."""
        stale = eligible(current_policy=GovernancePolicy())
        with self.assertRaises(ActivationError) as caught:
            self.activator().promote(assessment=stale, registry=self.registry,
                                     warmup=self.warmup)
        self.assertIn('policy', str(caught.exception))
        self.assertUnchanged()

    def test_an_assessment_for_another_scope_is_refused(self):
        with self.assertRaises(ActivationError):
            self.activator().promote(assessment=eligible(scope='SITE:other'),
                                     registry=self.registry, warmup=self.warmup,
                                     scope=SITE)
        self.assertUnchanged()

    def test_a_candidate_that_is_no_longer_registered_is_refused(self):
        with self.assertRaises(ActivationError):
            self.activator().promote(assessment=eligible('web-risk-v9'),
                                     registry=self.registry, warmup=self.warmup)
        self.assertUnchanged()

    def test_a_promotion_with_no_rollback_target_is_refused(self):
        """§58. The most important refusal in the file."""
        fresh = ModelRegistry(self.root / 'fresh', scope=SITE)
        fresh.register_candidate('web-risk-v5', artifacts('web-risk-v5'))
        with self.assertRaises(ActivationError) as caught:
            self.activator().promote(assessment=eligible(), registry=fresh,
                                     warmup=self.warmup)
        self.assertIn('reversible', str(caught.exception))
        self.assertIsNone(fresh.state.active)

    def test_a_candidate_that_does_not_warm_up_never_reaches_the_pointer(self):
        """§148, §111. It failed to load; the site keeps the model it had."""
        result = self.activator().promote(assessment=eligible(),
                                          registry=self.registry,
                                          warmup=lambda resolved: False)
        self.assertFalse(result.activated)
        self.assertTrue(result.quarantined)
        self.assertUnchanged()

    def test_a_candidate_whose_warmup_raises_never_reaches_the_pointer(self):
        def explode(resolved):
            raise RuntimeError('the model process died')

        result = self.activator().promote(assessment=eligible(),
                                          registry=self.registry, warmup=explode)
        self.assertFalse(result.activated)
        self.assertUnchanged()

    def test_a_model_that_answers_before_and_not_after_is_rolled_back(self):
        """The narrow window the second warmup exists to catch."""
        calls = []

        def once(resolved):
            calls.append(resolved.get('version'))
            return len(calls) == 1

        result = self.activator().promote(assessment=eligible(),
                                          registry=self.registry, warmup=once)
        self.assertFalse(result.activated)
        self.assertTrue(result.quarantined)
        self.assertEqual(self.registry.state.active, 'web-risk-v4',
                         'the previous model was not restored')


class TestOneTransitionPerScope(ActivationCase):
    """§33, §140. Two eligible candidates must not both activate."""

    def test_a_second_promotion_while_one_is_in_flight_is_refused(self):
        lock = ScopeLock(self.root / 'governance', SITE).acquire(owner='web-risk-v5')
        self.addCleanup(lock.release)
        with self.assertRaises(ScopeLocked):
            self.activator().promote(assessment=eligible('web-risk-v5'),
                                     registry=self.registry, warmup=self.warmup)
        self.assertEqual(self.registry.state.active, 'web-risk-v4')

    def test_the_lock_is_released_even_when_the_transaction_fails(self):
        self.activator().promote(assessment=eligible(), registry=self.registry,
                                 warmup=lambda resolved: False)
        # A second attempt must not be refused by a leftover lock.
        second = ScopeLock(self.root / 'governance', SITE)
        second.acquire()
        second.release()

    def test_two_scopes_do_not_block_each_other(self):
        """§68, §69. Site isolation reaches the lock too."""
        held = ScopeLock(self.root / 'governance', 'SITE:other').acquire()
        self.addCleanup(held.release)
        result = self.activator().promote(assessment=eligible(),
                                          registry=self.registry,
                                          warmup=self.warmup)
        self.assertTrue(result.activated)

    def test_the_journal_refuses_a_second_in_flight_entry_for_one_scope(self):
        journal = journal_module.PromotionJournal(self.root / 'j.json')
        journal.open(scope=SITE, candidate_version='web-risk-v5',
                     rollback_target='web-risk-v4')
        with self.assertRaises(journal_module.JournalError):
            journal.open(scope=SITE, candidate_version='web-risk-v6',
                         rollback_target='web-risk-v4')


class TestCrashRecovery(ActivationCase):
    """§62, §135. Kill the process at each phase; one valid answer each time."""

    def journal(self):
        return journal_module.PromotionJournal(self.root / 'governance'
                                               / 'promotion-journal.json')

    def interrupted_at(self, phase, *, active):
        journal = self.journal()
        journal.open(scope=SITE, candidate_version='web-risk-v5',
                     rollback_target='web-risk-v4')
        if phase != journal_module.PREPARE:
            journal.advance(SITE, phase,
                            guarded_stage='GUARDED_ACTIVE_STAGE_1'
                            if phase == journal_module.GUARDED else '')
        return journal.recover(SITE, registry_active=active)

    def test_interrupted_at_prepare_changes_nothing(self):
        action, message, _ = self.interrupted_at(journal_module.PREPARE,
                                                 active='web-risk-v4')
        self.assertEqual(action, journal_module.DISCARD)
        self.assertIn('nothing had been changed', message)

    def test_interrupted_at_staged_changes_nothing(self):
        action, _, _ = self.interrupted_at(journal_module.STAGED, active='web-risk-v4')
        self.assertEqual(action, journal_module.DISCARD)

    def test_interrupted_during_activation_before_the_write_changes_nothing(self):
        action, _, _ = self.interrupted_at(journal_module.ACTIVATING,
                                           active='web-risk-v4')
        self.assertEqual(action, journal_module.DISCARD)

    def test_interrupted_during_activation_after_the_write_resumes_guarded(self):
        """Not full ACTIVE. The model got in; it has earned nothing yet."""
        action, message, _ = self.interrupted_at(journal_module.ACTIVATING,
                                                 active='web-risk-v5')
        self.assertEqual(action, journal_module.RESUME_GUARDED)
        self.assertIn('guarded', message)

    def test_an_unexpected_pointer_is_ambiguous_rather_than_resolved(self):
        """§115. The system says it does not know instead of picking."""
        action, message, _ = self.interrupted_at(journal_module.ACTIVATING,
                                                 active='web-risk-v999')
        self.assertEqual(action, journal_module.AMBIGUOUS)
        self.assertIn('not safe to resolve automatically', message)

    def test_interrupted_while_guarded_stays_guarded(self):
        """§66, §137. A restart earns a model nothing."""
        action, message, _ = self.interrupted_at(journal_module.GUARDED,
                                                 active='web-risk-v5')
        self.assertEqual(action, journal_module.RESUME_GUARDED)
        self.assertIn('resets no requirement', message)

    def test_an_interrupted_rollback_is_completed(self):
        action, _, _ = self.interrupted_at(journal_module.ROLLING_BACK,
                                           active='web-risk-v5')
        self.assertEqual(action, journal_module.ROLL_BACK)

    def test_a_rollback_that_already_took_effect_is_closed(self):
        action, _, _ = self.interrupted_at(journal_module.ROLLING_BACK,
                                           active='web-risk-v4')
        self.assertEqual(action, journal_module.COMPLETE_ROLLBACK)

    def test_an_unreadable_journal_freezes_rather_than_assuming_nothing_happened(self):
        """§115. The one reading that could leave a half-promotion in place."""
        path = self.root / 'governance' / 'promotion-journal.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{ not json', encoding='utf-8')
        with self.assertRaises(journal_module.JournalError):
            journal_module.PromotionJournal(path)

    def test_the_activator_reports_an_unreadable_journal_as_ambiguous(self):
        path = self.root / 'governance' / 'promotion-journal.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{ not json', encoding='utf-8')
        with self.assertRaises(journal_module.JournalError):
            self.activator()

    def test_recovery_after_a_real_promotion_keeps_it_guarded(self):
        activator = self.activator()
        activator.promote(assessment=eligible(), registry=self.registry,
                          warmup=self.warmup)
        restarted = PromotionActivator(root=self.root / 'governance',
                                       policy=self.policy)
        action, message = restarted.recover(scope=SITE, registry=self.registry)
        self.assertEqual(action, journal_module.RESUME_GUARDED)
        state = restarted.guarded.load(SITE)
        self.assertEqual(state.stage, 'GUARDED_ACTIVE_STAGE_1')
        self.assertEqual(self.registry.state.active, 'web-risk-v5')

    def test_the_journal_survives_being_reopened(self):
        journal = self.journal()
        journal.open(scope=SITE, candidate_version='web-risk-v5',
                     rollback_target='web-risk-v4')
        journal.advance(SITE, journal_module.GUARDED,
                        guarded_stage='GUARDED_ACTIVE_STAGE_1')
        reopened = self.journal()
        entry = reopened.in_flight(SITE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.phase, journal_module.GUARDED)
        self.assertEqual(entry.guarded_stage, 'GUARDED_ACTIVE_STAGE_1')

    def test_the_journal_is_bounded(self):
        journal = self.journal()
        for index in range(500):
            journal.open(scope=f'SITE:s{index}', candidate_version=f'v{index}',
                         rollback_target='v0')
            journal.advance(f'SITE:s{index}', journal_module.COMMITTED)
        self.assertLessEqual(len(journal.entries), journal_module.MAX_ENTRIES)


class TestDiskFull(ActivationCase):
    """§65, §136. A full disk must cost the promotion, not the site."""

    def test_a_failure_writing_the_pointer_leaves_the_active_model_alone(self):
        class FullDisk(ModelRegistry):
            def promote(self, version, *, gate_passed, reason=''):
                raise OSError(28, 'No space left on device')

        registry = FullDisk(self.root / 'models', scope=SITE)
        with self.assertRaises(OSError):
            self.activator().promote(assessment=eligible(), registry=registry,
                                     warmup=self.warmup)
        self.assertEqual(ModelRegistry(self.root / 'models', scope=SITE).state.active,
                         'web-risk-v4')

    def test_a_failure_writing_the_journal_happens_before_anything_changes(self):
        blocked = self.root / 'governance'
        blocked.mkdir(parents=True, exist_ok=True)
        (blocked / 'promotion-journal.json').write_text('{ not json', encoding='utf-8')
        with self.assertRaises(journal_module.JournalError):
            self.activator()
        self.assertEqual(self.registry.state.active, 'web-risk-v4')


class TestTheActionCeiling(unittest.TestCase):
    """§37, §38, §128. What a guarded model may cause on its own."""

    def test_a_ceiling_clamps_a_stronger_action(self):
        self.assertEqual(clamp('TEMP_BLOCK', 'WATCH'), 'WATCH')
        self.assertEqual(clamp('RATE_LIMIT', 'WATCH'), 'WATCH')
        self.assertEqual(clamp('SOFT_CHALLENGE', 'WATCH'), 'WATCH')

    def test_a_ceiling_leaves_a_weaker_action_alone(self):
        self.assertEqual(clamp('OBSERVE', 'WATCH'), 'OBSERVE')
        self.assertEqual(clamp('WATCH', 'WATCH'), 'WATCH')

    def test_an_unknown_action_clamps_to_the_ceiling_rather_than_raising(self):
        """This runs in a live decision path; an exception here is an outage
        caused by the safety mechanism."""
        self.assertEqual(clamp('SOMETHING_NEW', 'WATCH'), 'WATCH')
        self.assertEqual(clamp('TEMP_BLOCK', 'NOT_AN_ACTION'), 'TEMP_BLOCK')

    def test_the_stages_get_progressively_more_authority(self):
        stages = GovernancePolicy().stages
        indexes = [ACTION_LADDER.index(stage.action_ceiling) for stage in stages]
        self.assertEqual(indexes, sorted(indexes))
        self.assertLess(indexes[-1], ACTION_LADDER.index('TEMP_BLOCK'),
                        'a guarded stage may not reach TEMP_BLOCK on its own')

    def test_a_model_that_is_not_guarded_has_no_extra_ceiling(self):
        self.assertIsNone(ceiling_for(None, GovernancePolicy()))


class TestStageAdvancement(unittest.TestCase):
    """§40, §41, §129. Observations, never the clock."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = GuardedStore(Path(self.tmp.name))
        self.policy = policy()

    def guarded(self, **observation):
        state = self.store.enter(scope=SITE, version='web-risk-v5',
                                 previous_version='web-risk-v4',
                                 stage='GUARDED_ACTIVE_STAGE_1')
        for key, value in observation.items():
            if key == 'observed_seconds':
                state.observed_seconds = value
            else:
                setattr(state.observation, key, value)
        return state

    def satisfied(self, **changes):
        base = dict(observed_seconds=90_000.0, feature_vectors=2_500,
                    source_groups=250, trusted_outcomes=0, scored_by_both=2_500,
                    large_disagreements=100)
        base.update(changes)
        return self.guarded(**base)

    def test_enough_evidence_advances(self):
        verdict, reasons = evaluate_advance(self.satisfied(), self.policy)
        self.assertEqual(verdict, ADVANCE, reasons)

    def test_time_alone_does_not_advance(self):
        """§41. The most important test in this class."""
        state = self.satisfied(observed_seconds=10_000_000.0, feature_vectors=11,
                               source_groups=2, scored_by_both=11,
                               large_disagreements=0)
        verdict, reasons = evaluate_advance(state, self.policy)
        self.assertEqual(verdict, CONTINUE)
        self.assertTrue(any('feature vectors' in reason for reason in reasons))

    def test_traffic_from_a_handful_of_sources_does_not_advance(self):
        """Volume is not a population: a million requests from four addresses
        says nothing about how the model treats everyone else."""
        state = self.satisfied(source_groups=4)
        verdict, reasons = evaluate_advance(state, self.policy)
        self.assertEqual(verdict, CONTINUE)
        self.assertTrue(any('source groups' in reason for reason in reasons))

    def test_an_inference_failure_holds_rather_than_waits(self):
        """A technical fault is not a slow start, and more time will not fix it."""
        verdict, reasons = evaluate_advance(self.satisfied(inference_failures=3),
                                            self.policy)
        self.assertEqual(verdict, HOLD)

    def test_large_disagreement_holds_for_review(self):
        """§52. Not a verdict about the model: a reason for a person to look."""
        state = self.satisfied(scored_by_both=2_500, large_disagreements=2_000)
        verdict, reasons = evaluate_advance(state, self.policy)
        self.assertEqual(verdict, HOLD)
        self.assertTrue(any('person should look' in reason for reason in reasons))

    def test_the_last_stage_completes_rather_than_advancing(self):
        state = self.satisfied()
        state.stage = 'GUARDED_ACTIVE_STAGE_2'
        state.observation.feature_vectors = 20_000
        state.observation.source_groups = 2_000
        state.observation.trusted_outcomes = 50
        state.observed_seconds = 300_000.0
        state.observation.scored_by_both = 20_000
        state.observation.large_disagreements = 500
        verdict, _ = evaluate_advance(state, self.policy)
        self.assertEqual(verdict, COMPLETE)

    def test_advancing_resets_the_evidence_for_the_next_rung(self):
        """Otherwise stage 1's traffic would buy stage 2 as well."""
        state = self.satisfied()
        advanced = self.store.advance_to(state, 'GUARDED_ACTIVE_STAGE_2')
        self.assertEqual(advanced.observation.feature_vectors, 0)
        self.assertEqual(advanced.observed_seconds, 0.0)

    def test_a_frozen_guarded_model_does_not_advance(self):
        """§54."""
        state = self.satisfied()
        state.frozen = True
        state.freeze_reason = 'operator freeze'
        verdict, reasons = evaluate_advance(state, self.policy)
        self.assertEqual(verdict, HOLD)
        self.assertIn('operator freeze', reasons[0])

    def test_a_stage_removed_from_the_policy_holds_for_a_person(self):
        """A policy change under a guarded model is not something to resolve
        automatically in either direction."""
        state = self.satisfied()
        state.stage = 'A_STAGE_THAT_NO_LONGER_EXISTS'
        verdict, reasons = evaluate_advance(state, self.policy)
        self.assertEqual(verdict, HOLD)
        self.assertTrue(any('person should decide' in reason for reason in reasons))

    def test_a_clock_jump_cannot_complete_a_stage(self):
        """§67, §138. The stage counts accumulated observation, not wall time."""
        state = self.satisfied(observed_seconds=0.0, feature_vectors=11,
                               source_groups=2)
        verdict, _ = evaluate_advance(state, self.policy,
                                      now_seconds=10 ** 12)
        self.assertEqual(verdict, CONTINUE,
                         'a clock jump advanced a guarded stage')


class TestGuardedStateSurvivesRestart(unittest.TestCase):
    """§66, §137."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_the_state_is_read_back_identically(self):
        store = GuardedStore(self.root)
        state = store.enter(scope=SITE, version='web-risk-v5',
                            previous_version='web-risk-v4',
                            stage='GUARDED_ACTIVE_STAGE_1')
        state.observation.feature_vectors = 1_234
        state.observation.source_groups = 56
        state.observed_seconds = 4_321.0
        store.save(state)

        reloaded = GuardedStore(self.root).load(SITE)
        self.assertEqual(reloaded.version, 'web-risk-v5')
        self.assertEqual(reloaded.stage, 'GUARDED_ACTIVE_STAGE_1')
        self.assertEqual(reloaded.observation.feature_vectors, 1_234)
        self.assertEqual(reloaded.observed_seconds, 4_321.0)

    def test_a_restart_does_not_promote_a_guarded_model(self):
        store = GuardedStore(self.root)
        store.enter(scope=SITE, version='web-risk-v5', previous_version='web-risk-v4',
                    stage='GUARDED_ACTIVE_STAGE_1')
        reloaded = GuardedStore(self.root).load(SITE)
        self.assertEqual(reloaded.stage, 'GUARDED_ACTIVE_STAGE_1')
        self.assertNotEqual(reloaded.stage, 'ACTIVE')

    def test_two_sites_keep_separate_guarded_state(self):
        store = GuardedStore(self.root)
        store.enter(scope='SITE:main', version='main-v2', previous_version='main-v1',
                    stage='GUARDED_ACTIVE_STAGE_1')
        store.enter(scope='SITE:api', version='api-v7', previous_version='api-v6',
                    stage='GUARDED_ACTIVE_STAGE_1')
        self.assertEqual(store.load('SITE:main').version, 'main-v2')
        self.assertEqual(store.load('SITE:api').version, 'api-v7')
        store.clear('SITE:main')
        self.assertIsNone(store.load('SITE:main'))
        self.assertIsNotNone(store.load('SITE:api'))


class TestRollbackKeepsEverything(ActivationCase):
    """§85, §118, §119."""

    def test_rollback_restores_the_previous_model(self):
        activator = self.activator()
        activator.promote(assessment=eligible(), registry=self.registry,
                          warmup=self.warmup)
        result = activator.roll_back(scope=SITE, registry=self.registry,
                                     reason='inference error rate exceeded the limit')
        self.assertEqual(self.registry.state.active, 'web-risk-v4')
        self.assertEqual(result['to'], 'web-risk-v4')

    def test_rollback_clears_the_guarded_state(self):
        activator = self.activator()
        activator.promote(assessment=eligible(), registry=self.registry,
                          warmup=self.warmup)
        activator.roll_back(scope=SITE, registry=self.registry, reason='test')
        self.assertIsNone(activator.guarded.load(SITE))

    def test_rollback_reports_that_it_touched_neither_firewall_nor_dataset(self):
        """§85, §86. The two things an operator most needs to be told."""
        activator = self.activator()
        activator.promote(assessment=eligible(), registry=self.registry,
                          warmup=self.warmup)
        result = activator.roll_back(scope=SITE, registry=self.registry,
                                     reason='test')
        self.assertEqual(result['firewall_state'], 'unchanged')
        self.assertEqual(result['dataset'], 'unchanged')

    def test_the_withdrawn_model_stays_on_disk(self):
        activator = self.activator()
        activator.promote(assessment=eligible(), registry=self.registry,
                          warmup=self.warmup)
        activator.roll_back(scope=SITE, registry=self.registry, reason='test')
        path = Path(self.registry.version_path('web-risk-v5')) / 'classifier.onnx'
        self.assertTrue(path.is_file(), 'rollback deleted the withdrawn model')


if __name__ == '__main__':
    unittest.main()
