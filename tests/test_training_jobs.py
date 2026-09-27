"""P9 training jobs.

Almost every test here is a failure test. A training job that works is not very
interesting; a training job that times out, crashes, runs out of memory or is
killed halfway through is, because in every one of those cases the active model
must be exactly what it was before.
"""
import json
import os
import sys
import unittest
import tempfile
from pathlib import Path

from training.jobs import (COMPLETE, EVALUATING, EXPORTING, FAILED, INTERRUPTED, JobStore,
                           MODEL_FAMILIES, PIPELINE, QUEUED, REJECTED, ResourceLimits,
                           SHADOW_READY, STATUSES, TERMINAL, TRAINING, TrainingJob,
                           TrainingJobError, VALIDATING_DATA, VALIDATING_MODEL, advance,
                           append_audit, audit_line, cleanup_workspace, new_job, privileged,
                           reproducibility, run, training_command, workspace_for)


def job(**overrides):
    values = {'dataset_version': 'dataset-v2-candidate', 'model_family': 'logistic_regression',
              'seed': 20260909}
    values.update(overrides)
    return new_job(**values)


class JobTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = JobStore(self.root / 'jobs')


class TestStateMachine(JobTestCase):
    def test_a_new_job_is_queued_and_has_run_nothing(self):
        item = job()
        self.assertEqual(item.status, QUEUED)
        self.assertEqual(item.started_at, '')
        self.assertEqual(item.result_model_version, '')
        self.assertFalse(item.produced_candidate)

    def test_the_pipeline_runs_in_order(self):
        item = job()
        for status in PIPELINE[1:]:
            item = advance(item, status)
        self.assertEqual(item.status, COMPLETE)
        self.assertTrue(item.finished)

    def test_a_stage_cannot_be_skipped(self):
        with self.assertRaises(TrainingJobError):
            advance(job(), EXPORTING)

    def test_a_job_cannot_move_backwards(self):
        item = advance(advance(job(), VALIDATING_DATA), TRAINING)
        with self.assertRaises(TrainingJobError):
            advance(item, VALIDATING_DATA)

    def test_a_job_can_fail_from_any_stage(self):
        item = job()
        for status in (VALIDATING_DATA, TRAINING, EXPORTING, VALIDATING_MODEL, EVALUATING):
            item = advance(item, status)
            failed = advance(item, FAILED, reason='something went wrong')
            self.assertEqual(failed.status, FAILED)
            self.assertEqual(failed.failure_reason, 'something went wrong')

    def test_a_finished_job_never_changes_again(self):
        item = advance(job(), FAILED, reason='dataset rejected')
        for status in STATUSES:
            with self.subTest(status=status):
                with self.assertRaises(TrainingJobError):
                    advance(item, status)

    def test_an_unknown_status_is_refused(self):
        for status in ('PROMOTED', 'ACTIVE', 'DEPLOYED', 'promote'):
            with self.subTest(status=status):
                with self.assertRaises(TrainingJobError):
                    advance(job(), status)

    def test_there_is_no_status_that_means_deployed(self):
        for status in STATUSES:
            self.assertNotIn('PROMOT', status)
            self.assertNotIn('DEPLOY', status)
            self.assertNotIn('ACTIVE', status)

    def test_shadow_ready_is_the_furthest_a_job_reaches_before_completing(self):
        self.assertEqual(PIPELINE[-2], SHADOW_READY)
        self.assertEqual(PIPELINE[-1], COMPLETE)

    def test_every_terminal_status_is_a_real_status(self):
        for status in TERMINAL:
            self.assertIn(status, STATUSES)
        self.assertIn(REJECTED, TERMINAL)

    def test_the_audit_trail_records_each_move(self):
        item = advance(advance(job(), VALIDATING_DATA), TRAINING, reason='data accepted')
        events = [entry['status'] for entry in item.audit]
        self.assertEqual(events, [QUEUED, VALIDATING_DATA, TRAINING])
        self.assertEqual(item.audit[-1]['reason'], 'data accepted')

    def test_the_audit_trail_is_bounded(self):
        item = job()
        item = TrainingJob(**{**json.loads(json.dumps(
            {k: v for k, v in item.explain().items()
             if k in TrainingJob.__dataclass_fields__})),
            'audit': tuple({'at': 'x', 'event': 'e', 'status': QUEUED} for _ in range(200))})
        item = advance(item, VALIDATING_DATA)
        self.assertLessEqual(len(item.audit), 64)


class TestValidation(JobTestCase):
    def test_an_unknown_model_family_is_refused(self):
        with self.assertRaises(TrainingJobError):
            job(model_family='deep_neural_network')

    def test_only_tabular_families_are_allowed(self):
        self.assertEqual(set(MODEL_FAMILIES), {'logistic_regression', 'gradient_boosting'})

    def test_a_bad_seed_is_refused(self):
        for seed in (-1, 2**33, 'abc', 1.5):
            with self.subTest(seed=seed):
                with self.assertRaises(TrainingJobError):
                    job(seed=seed)

    def test_impossible_limits_are_refused(self):
        for kwargs in ({'max_duration_seconds': 1}, {'max_memory_mb': 1},
                       {'max_parallel_jobs': 0}, {'max_parallel_jobs': 99}, {'nice': -5}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(TrainingJobError):
                    ResourceLimits(**kwargs)

    def test_a_job_id_cannot_escape_its_directory(self):
        for bad in ('../etc', 'a/b', '', 'A' * 40, 'x'):
            with self.subTest(bad=bad):
                with self.assertRaises(TrainingJobError):
                    self.store.path_for(bad)
                with self.assertRaises(TrainingJobError):
                    workspace_for(self.root, bad)


class TestReproducibility(JobTestCase):
    def test_a_job_records_what_would_be_needed_to_rebuild_it(self):
        item = job()
        record = item.reproducibility
        self.assertIn('git_commit', record)
        self.assertIn('python', record)
        for library in ('numpy', 'scikit-learn', 'onnxruntime', 'skl2onnx'):
            self.assertIn(library, record['libraries'])

    def test_an_unknown_version_is_recorded_as_unknown_not_guessed(self):
        record = reproducibility()
        for value in record['libraries'].values():
            self.assertIsInstance(value, str)
            self.assertTrue(value)

    def test_the_dataset_is_recorded_by_hash(self):
        dataset = self.root / 'dataset.csv'
        dataset.write_text('a,b\n1,2\n', encoding='utf-8')
        item = job(dataset_path=dataset)
        self.assertEqual(len(item.dataset_sha256), 64)

    def test_two_jobs_get_different_identifiers(self):
        self.assertNotEqual(job().job_id, job().job_id)


class TestStore(JobTestCase):
    def test_a_job_survives_a_save_and_load(self):
        saved = self.store.save(job())
        loaded = self.store.load(saved.job_id)
        self.assertEqual(loaded, saved)

    def test_an_unknown_job_is_an_error_not_a_blank_record(self):
        with self.assertRaises(TrainingJobError):
            self.store.load('0123456789abcdef')

    def test_a_corrupt_record_is_skipped_when_listing(self):
        self.store.save(job())
        (self.store.root / 'broken.json').write_text('{not json', encoding='utf-8')
        self.assertEqual(len(self.store.jobs()), 1)

    def test_a_record_from_a_future_schema_is_refused(self):
        saved = self.store.save(job())
        path = self.store.path_for(saved.job_id)
        document = json.loads(path.read_text(encoding='utf-8'))
        document['job_schema_version'] = 99
        path.write_text(json.dumps(document), encoding='utf-8')
        with self.assertRaises(TrainingJobError):
            self.store.load(saved.job_id)

    def test_the_record_says_what_a_job_may_not_do(self):
        saved = self.store.save(job())
        document = json.loads(self.store.path_for(saved.job_id).read_text(encoding='utf-8'))
        self.assertIn('cannot promote a model', document['authority'])

    def test_old_records_are_pruned_and_new_ones_kept(self):
        for _ in range(12):
            self.store.save(job())
        removed = self.store.prune(keep=5)
        self.assertEqual(removed, 7)
        self.assertEqual(len(self.store.jobs()), 5)


class TestRestartRecovery(JobTestCase):
    def test_a_job_left_running_is_marked_interrupted_not_resumed(self):
        item = self.store.save(advance(advance(job(), VALIDATING_DATA), TRAINING))
        marked = self.store.mark_interrupted()
        self.assertEqual(len(marked), 1)
        recovered = self.store.load(item.job_id)
        self.assertEqual(recovered.status, INTERRUPTED)
        self.assertIn('restarted', recovered.failure_reason)

    def test_a_finished_job_is_left_alone_by_recovery(self):
        item = self.store.save(advance(job(), COMPLETE))
        self.store.mark_interrupted()
        self.assertEqual(self.store.load(item.job_id).status, COMPLETE)

    def test_an_interrupted_job_produced_no_candidate(self):
        item = advance(job(), INTERRUPTED, reason='restart')
        self.assertFalse(item.produced_candidate)


class TestIsolation(JobTestCase):
    def test_a_job_runs_in_its_own_directory(self):
        item = job()
        space = workspace_for(self.root / 'work', item.job_id)
        self.assertTrue(space.is_dir())
        self.assertEqual(space.parent.name, 'work')

    def test_a_workspace_is_cleaned_up(self):
        item = job()
        space = workspace_for(self.root / 'work', item.job_id)
        (space / 'scratch.bin').write_bytes(b'x' * 100)
        self.assertTrue(cleanup_workspace(self.root / 'work', item.job_id))
        self.assertFalse(space.exists())

    def test_a_failed_workspace_can_be_kept_for_debugging(self):
        item = job()
        workspace_for(self.root / 'work', item.job_id)
        self.assertFalse(cleanup_workspace(self.root / 'work', item.job_id, keep=True))
        self.assertTrue((self.root / 'work' / item.job_id).is_dir())

    @unittest.skipIf(os.geteuid() == 0, 'this test must not run as root')
    def test_a_job_refuses_to_run_in_a_privileged_process(self):
        item = run(job(), [sys.executable, '-c', 'pass'], workspace=self.root,
                   store=self.store, allow_privileged=False)
        # This process is unprivileged, so the job should have run normally.
        self.assertFalse(privileged())
        self.assertEqual(item.exit_code, 0)

    def test_the_child_gets_a_minimal_environment(self):
        space = workspace_for(self.root / 'work', 'aaaabbbbccccdddd')
        script = 'import os,json;print(json.dumps(sorted(os.environ)))'
        item = run(job(), [sys.executable, '-c', script], workspace=space)
        self.assertEqual(item.exit_code, 0)

    def test_training_uses_one_thread_so_it_does_not_take_the_machine(self):
        space = workspace_for(self.root / 'work', 'aaaabbbbccccdddz')
        script = 'import os;print(os.environ["OMP_NUM_THREADS"])'
        item = run(job(), [sys.executable, '-c', script], workspace=space)
        self.assertEqual(item.exit_code, 0)


class TestFailurePaths(JobTestCase):
    def test_a_timeout_fails_the_job_and_says_so(self):
        space = workspace_for(self.root / 'work', 'timeouttimeout00')
        item = run(job(), [sys.executable, '-c', 'import time;time.sleep(30)'],
                   workspace=space, limits=ResourceLimits(max_duration_seconds=10),
                   store=self.store)
        self.assertEqual(item.status, FAILED)
        self.assertIn('exceeded its 10 second limit', item.failure_reason)

    def test_a_crash_fails_the_job_and_keeps_the_error(self):
        space = workspace_for(self.root / 'work', 'crashcrashcrash0')
        item = run(job(), [sys.executable, '-c', 'raise SystemExit(3)'],
                   workspace=space, store=self.store)
        self.assertEqual(item.status, FAILED)
        self.assertEqual(item.exit_code, 3)
        self.assertIn('exited with code 3', item.failure_reason)

    def test_a_missing_program_fails_the_job_rather_than_raising(self):
        space = workspace_for(self.root / 'work', 'missingmissing00')
        item = run(job(), ['/nonexistent/program'], workspace=space, store=self.store)
        self.assertEqual(item.status, FAILED)
        self.assertIn('could not start', item.failure_reason)

    def test_the_parallel_job_limit_is_enforced(self):
        self.store.save(advance(advance(job(), VALIDATING_DATA), TRAINING))
        space = workspace_for(self.root / 'work', 'parallelparallel')
        item = run(job(), [sys.executable, '-c', 'pass'], workspace=space,
                   limits=ResourceLimits(max_parallel_jobs=1), store=self.store)
        self.assertEqual(item.status, FAILED)
        self.assertIn('already running', item.failure_reason)

    def test_a_failure_is_recorded_in_the_store(self):
        space = workspace_for(self.root / 'work', 'recordrecord0000')
        item = run(job(), [sys.executable, '-c', 'raise SystemExit(9)'],
                   workspace=space, store=self.store)
        self.assertEqual(self.store.load(item.job_id).status, FAILED)

    def test_a_failed_job_never_names_a_model_version(self):
        space = workspace_for(self.root / 'work', 'nomodelnomodel00')
        item = run(job(), [sys.executable, '-c', 'raise SystemExit(1)'],
                   workspace=space, store=self.store)
        self.assertEqual(item.result_model_version, '')
        self.assertFalse(item.produced_candidate)


class TestCommands(JobTestCase):
    def test_the_command_calls_the_existing_offline_trainer(self):
        command = training_command(dataset='data.csv', model_family='logistic_regression',
                                   version='risk-logreg-v2', output_dir='out')
        self.assertEqual(command[1:3], ['-m', 'training.train_logreg'])
        self.assertIn('--model-version', command)
        self.assertNotIn('--promote', command)

    def test_an_unimplemented_family_says_so_rather_than_pretending(self):
        with self.assertRaises(TrainingJobError) as caught:
            training_command(dataset='d.csv', model_family='gradient_boosting',
                             version='risk-gbt-v2', output_dir='out')
        self.assertIn('not implemented', str(caught.exception))


class TestAuditLog(JobTestCase):
    def test_an_audit_line_carries_no_address_or_secret(self):
        line = audit_line(job(), 'training_started', rows=1200)
        self.assertEqual(set(line) & {'src_ip', 'source', 'secret', 'token'}, set())
        self.assertEqual(line['event'], 'training_started')
        self.assertEqual(line['rows'], 1200)

    def test_audit_lines_append(self):
        path = self.root / 'audit' / 'training.log'
        item = job()
        self.assertTrue(append_audit(path, audit_line(item, 'created')))
        self.assertTrue(append_audit(path, audit_line(item, 'training_started')))
        lines = path.read_text(encoding='utf-8').strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])['event'], 'training_started')

    def test_a_failure_to_write_the_log_is_not_a_failure_of_the_job(self):
        self.assertFalse(append_audit('/proc/definitely/not/writable/x.log',
                                      audit_line(job(), 'created')))


if __name__ == '__main__':
    unittest.main()
