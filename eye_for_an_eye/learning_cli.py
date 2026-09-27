"""P9 operator commands for the learning loop.

    eye-for-an-eye learning status     what the system thinks, and why
    eye-for-an-eye learning prepare    build a candidate dataset from reviewed rows
    eye-for-an-eye learning train      train a candidate model
    eye-for-an-eye learning jobs       what has been attempted
    eye-for-an-eye learning job <id>   one attempt in full

`prepare` and `train` change files on disk. Neither of them changes which model
the sensor loads, and there is no `learning promote`: promotion lives in
`model promote`, needs `--yes`, and is a separate decision on purpose.
"""
import argparse
import json
import sys
from pathlib import Path

from .config import load_config

MAX_LISTED_JOBS = 20


def _paths(config):
    """Where jobs, workspaces and the audit log live, with sensible fallbacks."""
    learning = config.learning
    base = Path(config.storage.path).parent if getattr(config.storage, 'path', '') else Path('.')
    jobs = Path(learning.jobs_path) if learning.jobs_path else base / 'training' / 'jobs'
    workspace = (Path(learning.workspace_path) if learning.workspace_path
                 else base / 'training' / 'workspaces')
    audit = (Path(learning.audit_log_path) if learning.audit_log_path
             else base / 'training' / 'training-audit.log')
    return jobs, workspace, audit


def _limits(config):
    from training.jobs import ResourceLimits
    learning = config.learning
    return ResourceLimits(max_duration_seconds=learning.training_max_duration_seconds,
                          max_memory_mb=learning.training_max_memory_mb,
                          max_parallel_jobs=learning.training_max_parallel_jobs,
                          nice=learning.training_nice)


def _signals(config):
    """Gather what the retraining advice needs. Every missing value stays missing."""
    from .decision.retraining import RetrainingSignals, system_signals
    counts = {'benign': 0, 'malicious': 0, 'uncertain': 0, 'sources': 0}
    try:
        from .review_cli import _queue
        queue = _queue(config)
        groups = set()
        for entry in queue.labelled():
            groups.add(entry.source_key)
            if entry.state == 'BENIGN_LIKE':
                counts['benign'] += 1
            elif entry.state == 'MALICIOUS_AUTOMATION_LIKE':
                counts['malicious'] += 1
            elif entry.state == 'UNCERTAIN':
                counts['uncertain'] += 1
        counts['sources'] = len(groups)
    except Exception:
        pass

    drift_status, ood_rate, health = '', None, ''
    try:
        from .reliability_cli import _reference, _state
        reference, _ = _reference(config)
        if reference is not None:
            state = _state(config, '24h')
            if state is not None:
                from .decision.drift import DriftEngine
                result = DriftEngine(reference, config.reliability).evaluate(state)
                drift_status = result.status
    except Exception:
        drift_status = ''

    machine = system_signals()
    return RetrainingSignals(new_benign_labels=counts['benign'],
                             new_malicious_labels=counts['malicious'],
                             new_uncertain_labels=counts['uncertain'],
                             new_label_sources=counts['sources'],
                             drift_status=drift_status, ood_rate=ood_rate,
                             model_health=health, **machine)


def _policy(config):
    from .decision.retraining import RetrainingPolicy
    learning = config.learning
    return RetrainingPolicy(min_new_labels=learning.minimum_trusted_samples,
                            min_new_per_label=learning.minimum_samples_per_label,
                            min_new_sources=learning.minimum_label_sources,
                            cooldown_days=learning.minimum_retraining_interval_days)


def _active_version(config):
    try:
        from .reliability_cli import _registry
        return _registry(config).state.active or ''
    except Exception:
        return ''


def learning_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(
        prog='eye-for-an-eye learning',
        description='Local adaptive learning. Prepares and trains candidates. Never promotes.')
    parser.add_argument('action', choices=('status', 'prepare', 'train', 'jobs', 'job'))
    parser.add_argument('job_id', nargs='?', default='')
    parser.add_argument('--parent-dataset', default='', help='the dataset this one grows from')
    parser.add_argument('--parent-rows', default='', help='CSV of the parent dataset rows')
    parser.add_argument('--labels', default='', help='a review export written by "review export"')
    parser.add_argument('--dataset-version', default='', help='version for the new candidate')
    parser.add_argument('--dataset', default='', help='dataset CSV to train on')
    parser.add_argument('--model-version', default='', help='version for the new candidate model')
    parser.add_argument('--output-dir', default='', help='where training writes its artifacts')
    parser.add_argument('--out', default='', help='where to write a report')
    parser.add_argument('--yes', action='store_true', help='confirm a step that writes files')
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure

    try:
        config = load_config(args.config)

        if args.action == 'status':
            return _status(config, args)
        if args.action == 'prepare':
            return _prepare(config, args)
        if args.action == 'train':
            return _train(config, args)
        if args.action in ('jobs', 'job'):
            return _jobs(config, args)
        raise ValueError('unknown learning action')
    except (OSError, ValueError, TypeError, RuntimeError, ImportError) as exc:
        return failure(exc, machine=args.json, debug=debug)


def _status(config, args):
    from .decision.retraining import evaluate
    advice = evaluate(_signals(config), _policy(config))
    payload = dict(advice.explain())
    payload['active_model'] = _active_version(config) or 'the model in your configuration'
    payload['auto_train'] = bool(config.learning.auto_train)
    # Reported as a string rather than a bool so that a machine reader cannot
    # mistake "configured false" for "wired up and currently off".
    payload['auto_train_status'] = 'reserved_not_honoured'
    # Read from the governance section rather than hardcoded. Through P13 this
    # was a literal False and the CLI said no such setting existed; P14 adds one,
    # and a status command that kept printing the old sentence would be the
    # first place an operator was misled about what their own system can do.
    governance = getattr(config, 'model_governance', None)
    payload['auto_promote'] = 'ON' if getattr(
        governance, 'auto_promote_enabled', False) else 'OFF'
    payload['auto_promote_global'] = 'ON' if getattr(
        governance, 'auto_promote_global_enabled', False) else 'OFF'
    if args.json:
        print(json.dumps(payload))
        return 0

    signals = advice.signals
    print('LEARNING STATUS\n')
    print(f'Active model:\n{payload["active_model"]}\n')
    print(f'Reviewed new samples:\n{signals["new_benign_labels"] + signals["new_malicious_labels"]} '
          f'({signals["new_benign_labels"]} benign, {signals["new_malicious_labels"]} automation)\n')
    print(f'Answered uncertain:\n{signals["new_uncertain_labels"]} '
          '(kept out of supervised training)\n')
    print(f'Label sources:\n{signals["new_label_sources"]}\n')
    print(f'Drift:\n{signals["drift_status"]}\n')
    print(f'Next action:\n{advice.recommendation}\n')
    if advice.reasons:
        print('Reasons:')
        for reason in advice.reasons:
            print('  + ' + reason)
        print()
    if advice.blockers:
        print('Not yet:')
        for blocker in advice.blockers:
            print('  - ' + blocker)
        print()
    if advice.next_step:
        print(f'You could run:\n{advice.next_step}\n')
    print(f'auto_train:\n{"true" if payload["auto_train"] else "false"} in your '
          'configuration - RESERVED, not honoured; no code reads it to start a job\n')
    print(f'auto_promote:\n{payload["auto_promote"]} '
          '(model_governance.auto_promote_enabled; a candidate that passes every '
          'gate enters service under a reduced action ceiling, never as the '
          'active model)')
    return 0


def _prepare(config, args):
    """Build a candidate dataset. Refuses to write one that fails its quality gate."""
    from dataset import store
    from dataset.candidate import IntakeLimits, build, read_review_export, write_report
    if not args.parent_rows or not args.parent_dataset or not args.labels:
        print('Use: learning prepare --parent-dataset <name> --parent-rows <csv> '
              '--labels <review export> --dataset-version <name>', file=sys.stderr)
        return 2
    version = args.dataset_version or f'{args.parent_dataset}-candidate'
    parent_samples = store.read(args.parent_rows)
    rows = read_review_export(args.labels)
    result = build(parent_samples=parent_samples, parent_dataset=args.parent_dataset,
                   review_rows=rows, dataset_version=version,
                   sensor_placement=config.deployment.placement
                   if hasattr(config.deployment, 'placement') else 'unspecified',
                   limits=IntakeLimits())

    summary = {'schema_version': 1, 'dataset_version': version,
               'quality_gate': result['quality_gate'],
               'reasons': list(result['quality_reasons']),
               'lineage': result['lineage'].explain(),
               'intake': result['intake'].explain(),
               'total_rows': len(result['samples'])}
    if args.out:
        write_report(result, args.out)
        summary['report'] = args.out

    if args.json:
        print(json.dumps(summary))
    else:
        print('CANDIDATE DATASET\n')
        print(f'Version:\n{version}\n')
        print(f'Parent:\n{args.parent_dataset} ({result["lineage"].parent_rows} rows)\n')
        print(f'New reviewed rows:\n{result["intake"].accepted} '
              f'from {result["intake"].distinct_sources} sources\n')
        if result['intake'].dropped:
            print('Dropped:')
            for reason, count in sorted(result['intake'].dropped.items()):
                print(f'  {count} {reason.replace("_", " ")}')
            print()
        print(f'Quality gate:\n{result["quality_gate"]}\n')
        if result['quality_reasons']:
            print('Notes:')
            for reason in result['quality_reasons']:
                print('  ' + reason)
            print()

    if result['quality_gate'] == 'FAIL':
        print('The dataset was not written. Fix the problems above first.', file=sys.stderr)
        return 2
    if not args.out:
        print('Nothing was written. Add --out <file> to keep the report.')
    print('Nothing has been trained. "learning train" is a separate step.')
    return 0


def _train(config, args):
    """Run one training job. Writes a candidate model; promotes nothing."""
    from training.jobs import (COMPLETE, JobStore, TrainingJobError, advance, append_audit,
                               audit_line, cleanup_workspace, new_job, run, training_command,
                               workspace_for, EVALUATING, EXPORTING, TRAINING, VALIDATING_DATA,
                               VALIDATING_MODEL, SHADOW_READY)
    if not args.dataset or not args.model_version or not args.output_dir:
        print('Use: learning train --dataset <csv> --model-version <name> '
              '--output-dir <dir> --yes', file=sys.stderr)
        return 2
    if not args.yes:
        print('Refusing to train without --yes.', file=sys.stderr)
        print(f'This would train {args.model_version} and write it into {args.output_dir}.',
              file=sys.stderr)
        print('It would not change which model the sensor loads.', file=sys.stderr)
        return 2

    jobs_dir, workspace_dir, audit_path = _paths(config)
    store = JobStore(jobs_dir)
    limits = _limits(config)
    job = store.save(new_job(dataset_version=args.dataset_version or 'unspecified',
                             model_family='logistic_regression',
                             parent_model=_active_version(config),
                             dataset_path=args.dataset, limits=limits))
    append_audit(audit_path, audit_line(job, 'job_created'))
    space = workspace_for(workspace_dir, job.job_id)

    try:
        job = store.save(advance(job, VALIDATING_DATA))
        job = store.save(advance(job, TRAINING))
        append_audit(audit_path, audit_line(job, 'training_started'))
        command = training_command(dataset=Path(args.dataset).resolve(),
                                   model_family=job.model_family,
                                   version=args.model_version,
                                   output_dir=Path(args.output_dir).resolve())
        job = run(job, command, workspace=space, limits=limits, store=store)
        if job.finished:
            append_audit(audit_path, audit_line(job, 'training_failed',
                                                reason=job.failure_reason))
            print(f'Training failed:\n{job.failure_reason}\n', file=sys.stderr)
            print('The active model is unchanged.', file=sys.stderr)
            cleanup_workspace(workspace_dir, job.job_id, keep=True)
            return 2
        for status in (EXPORTING, VALIDATING_MODEL, EVALUATING, SHADOW_READY):
            job = store.save(advance(job, status))
        job = store.save(advance(job, COMPLETE, result_model_version=args.model_version))
        append_audit(audit_path, audit_line(job, 'candidate_created',
                                            model_version=args.model_version))
    except TrainingJobError as exc:
        from training.jobs import FAILED
        job = store.save(advance(job, FAILED, reason=str(exc)))
        append_audit(audit_path, audit_line(job, 'training_failed', reason=str(exc)))
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    finally:
        cleanup_workspace(workspace_dir, job.job_id, keep=job.status != COMPLETE)
        store.prune(keep=config.learning.keep_job_records)

    if args.json:
        print(json.dumps({'schema_version': 1, 'job': job.explain()}))
        return 0
    print('TRAINING COMPLETE\n')
    print(f'Job:\n{job.job_id}\n')
    print(f'Candidate:\n{args.model_version}\n')
    print(f'Duration:\n{job.duration_seconds:.1f} seconds\n' if job.duration_seconds
          else 'Duration:\nunknown\n')
    print(f'Written to:\n{args.output_dir}\n')
    print('The active model is unchanged.\n')
    print('Next:\nRegister it as a candidate, watch it in shadow, then decide.\n'
          'Promotion is a separate command a person runs.')
    return 0


def _jobs(config, args):
    from training.jobs import JobStore
    jobs_dir, _, _ = _paths(config)
    store = JobStore(jobs_dir)

    if args.action == 'job':
        if not args.job_id:
            print('Which job? Use "learning jobs" to see the ids.', file=sys.stderr)
            return 2
        job = store.load(args.job_id)
        if args.json:
            print(json.dumps(job.explain()))
            return 0
        print('TRAINING JOB\n')
        print(f'Job:\n{job.job_id}\n')
        print(f'Status:\n{job.status}\n')
        print(f'Dataset:\n{job.dataset_version}\n')
        print(f'Parent model:\n{job.parent_model or "none"}\n')
        print(f'Model family:\n{job.model_family}\n')
        print(f'Seed:\n{job.seed}\n')
        print(f'Candidate:\n{job.result_model_version or "none"}\n')
        if job.failure_reason:
            print(f'Failure:\n{job.failure_reason}\n')
        print('Reproducibility:')
        for name, value in sorted((job.reproducibility.get('libraries') or {}).items()):
            print(f'  {name}: {value}')
        print(f'  python: {job.reproducibility.get("python", "unknown")}')
        print(f'  git commit: {job.reproducibility.get("git_commit", "unknown")}')
        print(f'  dataset sha256: {job.dataset_sha256 or "unknown"}')
        print('\nAuthority:\nA job can only produce a candidate. It cannot promote a model.')
        return 0

    found = store.jobs(limit=MAX_LISTED_JOBS)
    if args.json:
        print(json.dumps({'schema_version': 1, 'rows': len(found),
                          'jobs': [job.explain() for job in found]}))
        return 0
    print('TRAINING JOBS\n')
    if not found:
        print('No training jobs have been run.')
        return 0
    print(f'{"Job":20} {"Status":16} {"Dataset":24} Candidate')
    for job in found:
        print(f'  {job.job_id:18} {job.status:16} {job.dataset_version:24} '
              f'{job.result_model_version or "-"}')
    print(f'\n{len(found)} shown. Use "learning job <id>" for one in full.')
    return 0
