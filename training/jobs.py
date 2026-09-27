"""P9 training jobs: a bounded, isolated, recorded attempt to build a candidate.

A training job is deliberately boring. It writes a record, starts a separate
unprivileged process with hard resource limits, waits with a timeout, and writes
the outcome. It never touches the active model, never touches a firewall, and
never runs inside the process that holds capture or enforcement privileges.

The state machine exists so that a failure has a name. "It did not work" is not
an acceptable outcome for something that decides who gets blocked; "FAILED at
VALIDATING_MODEL because ONNX parity was 3e-3" is.

Three rules:

* A job can only ever produce a **candidate**. There is no code path from here to
  the ACTIVE role.
* Every limit is enforced by the operating system, not by good intentions. A
  runaway job is killed by an rlimit or a timeout, not by a polite check.
* A crashed, killed or interrupted job leaves the active model exactly as it was.
  That is the property worth protecting, and every failure path preserves it.
"""
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

JOB_SCHEMA_VERSION = 1

QUEUED = 'QUEUED'
VALIDATING_DATA = 'VALIDATING_DATA'
TRAINING = 'TRAINING'
EXPORTING = 'EXPORTING'
VALIDATING_MODEL = 'VALIDATING_MODEL'
EVALUATING = 'EVALUATING'
SHADOW_READY = 'SHADOW_READY'
COMPLETE = 'COMPLETE'
FAILED = 'FAILED'
REJECTED = 'REJECTED'
INTERRUPTED = 'INTERRUPTED'

STATUSES = (QUEUED, VALIDATING_DATA, TRAINING, EXPORTING, VALIDATING_MODEL, EVALUATING,
            SHADOW_READY, COMPLETE, FAILED, REJECTED, INTERRUPTED)

#: A job that reached one of these is finished and will not change again.
TERMINAL = (COMPLETE, FAILED, REJECTED, INTERRUPTED)

#: The order a healthy job moves through. A job may jump to a terminal state from
#: anywhere, but it may never move backwards or skip forwards.
PIPELINE = (QUEUED, VALIDATING_DATA, TRAINING, EXPORTING, VALIDATING_MODEL, EVALUATING,
            SHADOW_READY, COMPLETE)

MODEL_FAMILIES = ('logistic_regression', 'gradient_boosting')

JOB_ID_PATTERN = re.compile(r'[a-z0-9]{8,32}')

LIBRARIES = ('numpy', 'scikit-learn', 'scipy', 'onnx', 'onnxruntime', 'skl2onnx')


class TrainingJobError(Exception):
    """A job could not be created, moved or run. The active model is unaffected."""


@dataclass(frozen=True)
class ResourceLimits:
    """Hard bounds, enforced by the operating system where the platform allows it.

    Training is the lowest-priority thing this project does. If a limit is
    reached the job dies; the sensor does not notice.
    """

    max_duration_seconds: int = 1800
    max_memory_mb: int = 2048
    max_output_bytes: int = 536_870_912
    max_rows: int = 500_000
    max_parallel_jobs: int = 1
    #: Scheduling niceness for the training process. Higher means "yield first".
    nice: int = 10

    def __post_init__(self):
        if not 10 <= self.max_duration_seconds <= 86_400:
            raise TrainingJobError('max_duration_seconds is out of range')
        if not 128 <= self.max_memory_mb <= 131_072:
            raise TrainingJobError('max_memory_mb is out of range')
        if not 1_048_576 <= self.max_output_bytes <= 10_737_418_240:
            raise TrainingJobError('max_output_bytes is out of range')
        if not 100 <= self.max_rows <= 100_000_000:
            raise TrainingJobError('max_rows is out of range')
        if not 1 <= self.max_parallel_jobs <= 4:
            raise TrainingJobError('max_parallel_jobs is out of range')
        if not 0 <= self.nice <= 19:
            raise TrainingJobError('nice must be between 0 and 19')

    def explain(self):
        return asdict(self)


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment=None):
    return (moment or _now()).isoformat().replace('+00:00', 'Z')


def reproducibility():
    """What would be needed to build this model again.

    Recorded honestly: a version that cannot be determined is recorded as
    unknown rather than guessed at.
    """
    import platform
    versions = {}
    for name in LIBRARIES:
        try:
            import importlib.metadata
            versions[name] = importlib.metadata.version(name)
        except Exception:
            versions[name] = 'unknown'
    commit = 'unknown'
    try:
        finished = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True,
                                  text=True, timeout=10)
        value = finished.stdout.strip()
        if finished.returncode == 0 and len(value) == 40:
            commit = value
    except (OSError, subprocess.SubprocessError):
        commit = 'unknown'
    return {'git_commit': commit, 'python': platform.python_version(),
            'platform': platform.system(), 'libraries': versions}


@dataclass(frozen=True)
class TrainingJob:
    """One attempt to produce a candidate model."""

    job_id: str
    created_at: str
    dataset_version: str
    feature_schema_version: int
    model_family: str
    seed: int
    status: str = QUEUED
    started_at: str = ''
    completed_at: str = ''
    result_model_version: str = ''
    failure_reason: str = ''
    parent_model: str = ''
    dataset_sha256: str = ''
    exit_code: int | None = None
    duration_seconds: float | None = None
    peak_memory_mb: float | None = None
    reproducibility: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    audit: tuple = ()

    def __post_init__(self):
        if not JOB_ID_PATTERN.fullmatch(self.job_id or ''):
            raise TrainingJobError('invalid job identifier')
        if self.status not in STATUSES:
            raise TrainingJobError(f'unknown job status: {self.status!r}')
        if self.model_family not in MODEL_FAMILIES:
            raise TrainingJobError(f'unknown model family: {self.model_family!r}')
        if not isinstance(self.seed, int) or not 0 <= self.seed <= 2**32 - 1:
            raise TrainingJobError('the seed must be a non-negative 32-bit integer')

    @property
    def finished(self):
        return self.status in TERMINAL

    @property
    def produced_candidate(self):
        """True only for a job that completed and named a model version."""
        return self.status == COMPLETE and bool(self.result_model_version)

    def explain(self):
        document = asdict(self)
        document['job_schema_version'] = JOB_SCHEMA_VERSION
        document['audit'] = list(self.audit)
        document['authority'] = ('a training job can only produce a candidate; it cannot '
                                 'promote a model or change a firewall')
        return document


def new_job(*, dataset_version, model_family='logistic_regression', seed=20260909,
            feature_schema_version=1, parent_model='', dataset_path=None, limits=None):
    """Create a QUEUED job record. Nothing runs yet."""
    limits = limits or ResourceLimits()
    # Coerce nothing that was not already the right type. `int('abc')` raises the
    # wrong exception and `int(1.5)` silently changes the seed, which would make a
    # job claim to be reproducible when it is not.
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise TrainingJobError('the seed must be a non-negative 32-bit integer')
    if type(feature_schema_version) is not int:
        raise TrainingJobError('the feature schema version must be an integer')
    if not dataset_version or not isinstance(dataset_version, str):
        raise TrainingJobError('a training job needs a dataset version')
    digest = ''
    if dataset_path:
        digest = file_digest(dataset_path)
    job_id = hashlib.sha256(
        f'{dataset_version}|{model_family}|{seed}|{_stamp()}|{os.urandom(8).hex()}'
        .encode()).hexdigest()[:16]
    return TrainingJob(job_id=job_id, created_at=_stamp(), dataset_version=dataset_version,
                       feature_schema_version=feature_schema_version,
                       model_family=model_family, seed=seed, parent_model=parent_model,
                       dataset_sha256=digest, reproducibility=reproducibility(),
                       limits=limits.explain(),
                       audit=({'at': _stamp(), 'event': 'created', 'status': QUEUED},))


def file_digest(path):
    """SHA-256 of a dataset, so a job records exactly what it was trained on.

    A dataset can be one CSV or a directory holding several splits plus a
    manifest. For a directory the manifest is the dataset's identity — it already
    names and hashes every split — so hashing it is both cheaper and stricter
    than hashing the rows again. A directory without a manifest falls back to the
    digests of its files, in a fixed order.
    """
    target = Path(path)
    if target.is_dir():
        manifest = target / 'dataset_manifest.json'
        if manifest.is_file():
            return file_digest(manifest)
        rolling = hashlib.sha256()
        for child in sorted(target.rglob('*')):
            if child.is_file():
                rolling.update(child.relative_to(target).as_posix().encode())
                rolling.update(bytes.fromhex(file_digest(child)))
        return rolling.hexdigest()
    digest = hashlib.sha256()
    with target.open('rb') as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def advance(job, status, *, reason='', **updates):
    """Move a job to a new state, or refuse.

    A job never moves backwards and never skips a stage. It may fall to a
    terminal state from anywhere, because failure can happen at any point.
    """
    if status not in STATUSES:
        raise TrainingJobError(f'unknown job status: {status!r}')
    if job.status in TERMINAL:
        raise TrainingJobError(f'job {job.job_id} already finished as {job.status}')
    if status not in TERMINAL:
        if status not in PIPELINE or job.status not in PIPELINE:
            raise TrainingJobError(f'cannot move from {job.status} to {status}')
        if PIPELINE.index(status) != PIPELINE.index(job.status) + 1:
            raise TrainingJobError(f'cannot move from {job.status} to {status}')
    entry = {'at': _stamp(), 'event': 'status', 'status': status}
    if reason:
        entry['reason'] = str(reason)[:500]
    changes = dict(updates)
    changes['status'] = status
    changes['audit'] = (*job.audit, entry)[-64:]
    if status == TRAINING and not job.started_at:
        changes['started_at'] = _stamp()
    if status in TERMINAL:
        changes['completed_at'] = _stamp()
        if status in (FAILED, REJECTED, INTERRUPTED) and reason:
            changes['failure_reason'] = str(reason)[:500]
    return replace(job, **changes)


class JobStore:
    """Job records on disk, one JSON file each, written atomically."""

    def __init__(self, root, *, limits=None):
        self.root = Path(root)
        self.limits = limits or ResourceLimits()

    def path_for(self, job_id):
        if not JOB_ID_PATTERN.fullmatch(job_id or ''):
            raise TrainingJobError('invalid job identifier')
        return self.root / f'{job_id}.json'

    def save(self, job):
        self.root.mkdir(parents=True, exist_ok=True)
        target = self.path_for(job.job_id)
        handle, temporary = tempfile.mkstemp(dir=str(self.root), prefix='.job-')
        try:
            with os.fdopen(handle, 'w', encoding='utf-8') as stream:
                json.dump(job.explain(), stream, indent=2, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return job

    def load(self, job_id):
        try:
            document = json.loads(self.path_for(job_id).read_text(encoding='utf-8'))
        except FileNotFoundError as exc:
            raise TrainingJobError(f'no training job with id {job_id}') from exc
        except ValueError as exc:
            raise TrainingJobError(f'training job {job_id} is not valid JSON') from exc
        return self._from_document(document)

    @staticmethod
    def _from_document(document):
        if document.get('job_schema_version') != JOB_SCHEMA_VERSION:
            raise TrainingJobError('unsupported training job schema')
        fields = set(TrainingJob.__dataclass_fields__)
        payload = {key: value for key, value in document.items() if key in fields}
        payload['audit'] = tuple(payload.get('audit') or ())
        return TrainingJob(**payload)

    def jobs(self, *, limit=50):
        if not self.root.is_dir():
            return []
        found = []
        for path in sorted(self.root.glob('*.json'), reverse=True):
            try:
                found.append(self._from_document(
                    json.loads(path.read_text(encoding='utf-8'))))
            except (TrainingJobError, ValueError, OSError):
                continue
            if len(found) >= limit:
                break
        found.sort(key=lambda job: job.created_at, reverse=True)
        return found

    def running(self):
        """Jobs that were left mid-flight. Used to enforce the parallel-job limit."""
        return [job for job in self.jobs(limit=200) if not job.finished]

    def mark_interrupted(self, *, reason='the service restarted while this job was running'):
        """Called at startup. A partly-finished job is never silently resumed.

        Resuming from a half-written workspace is how a corrupted candidate gets
        built. Starting again from zero is slower and correct.
        """
        marked = []
        for job in self.running():
            marked.append(self.save(advance(job, INTERRUPTED, reason=reason)))
        return marked

    def prune(self, *, keep=50):
        """Keep the newest job records; drop the rest. Never touches a model."""
        records = sorted(self.root.glob('*.json'), reverse=True) if self.root.is_dir() else []
        removed = 0
        for path in records[keep:]:
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed


def workspace_for(root, job_id):
    """An isolated directory for one job. Never inside the model registry."""
    if not JOB_ID_PATTERN.fullmatch(job_id or ''):
        raise TrainingJobError('invalid job identifier')
    path = Path(root) / job_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup_workspace(root, job_id, *, keep=False):
    """Remove a job's temporary files. A kept workspace is for debugging a failure."""
    path = Path(root) / job_id
    if keep or not path.is_dir():
        return False
    try:
        shutil.rmtree(path)
        return True
    except OSError:
        return False


def _limit_process(limits):
    """Applied in the child, before exec. Best effort: an unsupported limit is skipped.

    This is what makes a runaway job the operating system's problem rather than
    the sensor's. It also drops the child's scheduling priority, so training
    yields to traffic processing on a busy machine.
    """
    try:
        import resource
        memory = limits.max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_FSIZE,
                           (limits.max_output_bytes, limits.max_output_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except (ImportError, ValueError, OSError):
        pass
    try:
        os.nice(limits.nice)
    except (AttributeError, OSError):
        pass
    try:
        os.setsid()
    except (AttributeError, OSError):
        pass


def privileged():
    """True if this process holds capabilities training must never run with.

    Training reads a CSV and fits a model. It has no reason to be able to open a
    raw socket or change a firewall, and a bug in a training dependency should
    not inherit those powers.
    """
    if os.geteuid() == 0:
        return True
    try:
        with open('/proc/self/status', encoding='utf-8') as stream:
            for line in stream:
                if line.startswith('CapEff:'):
                    return int(line.split()[1], 16) != 0
    except (OSError, ValueError, IndexError):
        return False
    return False


def run(job, command, *, workspace, limits=None, store=None, env=None, allow_privileged=False):
    """Run one training command as an isolated child process.

    Returns the job in its terminal state. Every path through this function
    leaves the active model untouched, because nothing here can reach it: the
    child writes only into `workspace`, and only a later, separate, explicit step
    registers anything as a candidate.
    """
    limits = limits or ResourceLimits()
    store = store
    if privileged() and not allow_privileged:
        finished = advance(job, FAILED,
                           reason='training must not run in a privileged process; '
                                  'run it as an unprivileged user')
        return store.save(finished) if store else finished

    if store is not None:
        others = [item for item in store.running() if item.job_id != job.job_id]
        if len(others) >= limits.max_parallel_jobs:
            finished = advance(job, FAILED,
                               reason=f'{len(others)} training jobs are already running; '
                                      f'the limit is {limits.max_parallel_jobs}')
            return store.save(finished)

    workspace = Path(workspace)
    # The child runs in its own workspace, so the project is not on its path by
    # accident. Point it at the installed tree explicitly: a training process
    # should import this project and nothing else the shell happened to export.
    project_root = Path(__file__).resolve().parent.parent
    child_env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                 'HOME': str(workspace),
                 'TMPDIR': str(workspace),
                 'PYTHONPATH': str(project_root),
                 'PYTHONHASHSEED': str(job.seed % 4294967295),
                 'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1',
                 'MKL_NUM_THREADS': '1', 'NUMEXPR_NUM_THREADS': '1'}
    child_env.update(env or {})

    started = _now()
    try:
        finished_process = subprocess.run(
            list(command), cwd=str(workspace), env=child_env,
            capture_output=True, text=True, timeout=limits.max_duration_seconds,
            preexec_fn=(lambda: _limit_process(limits)) if hasattr(os, 'fork') else None,
            check=False)
    except subprocess.TimeoutExpired:
        elapsed = (_now() - started).total_seconds()
        result = advance(job, FAILED, duration_seconds=elapsed, exit_code=None,
                         reason=f'training exceeded its {limits.max_duration_seconds} second limit '
                                'and was stopped')
        return store.save(result) if store else result
    except (OSError, ValueError) as exc:
        result = advance(job, FAILED, reason=f'training could not start: {exc}')
        return store.save(result) if store else result

    elapsed = (_now() - started).total_seconds()
    if finished_process.returncode != 0:
        tail = (finished_process.stderr or '').strip().splitlines()[-3:]
        result = advance(job, FAILED, exit_code=finished_process.returncode,
                         duration_seconds=elapsed,
                         reason='training exited with code '
                                f'{finished_process.returncode}: {" | ".join(tail)[:300]}')
        return store.save(result) if store else result

    result = replace(job, exit_code=0, duration_seconds=elapsed)
    return store.save(result) if store else result


def audit_line(job, event, **fields):
    """One line for the training audit log. Never contains a secret or an address."""
    line = {'at': _stamp(), 'job_id': job.job_id, 'event': event,
            'dataset_version': job.dataset_version, 'model_family': job.model_family,
            'status': job.status}
    line.update({key: value for key, value in fields.items()
                 if isinstance(value, (str, int, float, bool)) or value is None})
    return line


def append_audit(path, line):
    """Append one JSON line. A failure to write the log never fails a job."""
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(line, sort_keys=True) + '\n')
        return True
    except OSError:
        return False


def training_command(*, dataset, model_family, version, output_dir):
    """The command a job runs. Built here so a test can inspect it without running it.

    This calls the existing offline trainer rather than reimplementing training.
    There is one feature transformer and one training path in this project, so a
    job cannot accidentally train against a different normalisation.
    """
    if model_family == 'logistic_regression':
        return [sys.executable, '-m', 'training.train_logreg',
                '--dataset', str(dataset), '--output-dir', str(output_dir),
                '--model-version', str(version)]
    if model_family == 'gradient_boosting':
        raise TrainingJobError(
            'a gradient boosting trainer is not implemented in this build; '
            'only logistic_regression can be trained')
    raise TrainingJobError(f'no training command is implemented for {model_family!r}')
