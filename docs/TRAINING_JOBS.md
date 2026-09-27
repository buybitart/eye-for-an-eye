# Training Jobs

A training job is one bounded, isolated, recorded attempt to build a candidate
model.

Status: **Beta.**

## Why a Job and Not Just a Function Call

Because training is the one thing this project does that can use a lot of
resources for a long time, and the sensor must keep working while it happens. A
job gives that three properties:

* a **name for every failure**, so "it did not work" is never the answer
* **operating-system limits**, so a runaway run is killed rather than tolerated
* an **audit record**, so months later you can see what produced a model

## The States

```text
QUEUED -> VALIDATING_DATA -> TRAINING -> EXPORTING
       -> VALIDATING_MODEL -> EVALUATING -> SHADOW_READY -> COMPLETE
```

A job moves forward one step at a time. It can never move backwards and can
never skip a step.

From any point it may fall to a terminal state:

| State | Meaning |
| --- | --- |
| `COMPLETE` | a candidate was produced |
| `FAILED` | something went wrong; the reason is recorded |
| `REJECTED` | the result was not good enough to keep |
| `INTERRUPTED` | the service restarted while this job was running |

A job that has reached a terminal state never changes again.

There is no state called `PROMOTED`, `DEPLOYED` or `ACTIVE`. A job cannot reach
one, because producing a candidate is the most it is able to do.

## Isolation

Training runs as a **separate process**, never inside the process that holds
capture or enforcement privileges. If the current process is privileged (running
as root, or holding any effective capability) the job refuses to start and says
why.

The reason is simple: training reads a CSV and fits a model. It has no need to
open a raw socket or change a firewall, and a bug in a training dependency should
not inherit those powers.

The child gets:

* its own workspace directory, which is the only place it writes
* a minimal environment: no inherited shell variables
* one thread (`OMP_NUM_THREADS=1` and friends), so it cannot take the machine
* `nice 10`, so it yields to traffic processing
* its own session, so a runaway process group can be cleaned up

## Limits

Enforced with `setrlimit` where the platform supports it, so they are the
operating system's problem rather than a polite check.

| Limit | Default | Enforced by |
| --- | --- | --- |
| duration | 1800 s | a timeout that kills the process |
| memory | 2048 MB | `RLIMIT_AS` |
| output size | 512 MB | `RLIMIT_FSIZE` |
| dataset rows | 500,000 | the dataset loader |
| parallel jobs | 1 | refused before starting |
| core dumps | none | `RLIMIT_CORE` = 0 |
| child processes | 64 | `RLIMIT_NPROC` |

Reaching a limit fails the job. It does not slow the sensor down, because the
sensor is a different process that shares nothing with it.

## Reproducibility

Every job records what would be needed to build the same model again:

```text
git commit          python version
numpy               scikit-learn
scipy               onnx
onnxruntime         skl2onnx
seed                dataset SHA-256
```

A version that cannot be determined is recorded as `unknown`. It is never
guessed at, because a guessed version makes a job look reproducible when it is
not.

For a dataset directory the SHA-256 is the manifest's hash. The manifest already
names and hashes every split, so hashing it identifies the dataset exactly.

## What Happens When Things Go Wrong

| Failure | Result |
| --- | --- |
| the dataset is invalid | `FAILED`; nothing is trained |
| training crashes | `FAILED` with the exit code and the last lines of the error |
| training runs too long | `FAILED`; the process is killed |
| ONNX export fails | `FAILED`; the sklearn object is **never** used as a fallback |
| metrics cannot be computed | `FAILED`; the candidate does not progress |
| the service restarts mid-run | `INTERRUPTED` on the next start |

In every one of these cases the active model is exactly what it was. Nothing in
a job can reach it: the child writes only into its own workspace, and registering
a candidate is a separate, later, explicit step.

A failed job keeps its workspace so you can look at it. A successful one cleans
up after itself.

## Restart Recovery

A job left mid-flight by a restart is marked `INTERRUPTED` and is **not**
resumed. Resuming from a half-written workspace is how a corrupted candidate gets
built. Starting again from zero is slower and correct.

## The Audit Log

One JSON line per lifecycle event:

```text
job_created  training_started  training_failed  candidate_created
```

No secrets, no addresses, no traffic. A failure to write the log never fails a
job.

## Retention

Job records are pruned to the newest 50 by default. The `ACTIVE` model, the
rollback target and the current candidate are never touched by any of this.

## Where Things Live

```toml
[learning]
jobs_path = "/var/lib/eye-for-an-eye/training/jobs"
workspace_path = "/var/lib/eye-for-an-eye/training/workspaces"
audit_log_path = "/var/lib/eye-for-an-eye/training/training-audit.log"
```

## Commands

```bash
eye-for-an-eye learning jobs         # what has been attempted
eye-for-an-eye learning job <id>     # one attempt in full, with its versions
```

## Related

* [RETRAINING.md](RETRAINING.md): when a job is worth running
* [MODEL_VALIDATION.md](MODEL_VALIDATION.md): what happens to the result
* [MODEL_REGISTRY.md](MODEL_REGISTRY.md): where a candidate goes
