# Controlled self-learning

Many security tools say they "learn by themselves". This project does something
narrower, and the difference is the point of this page.

## The rule

**The running sensor never changes the model it is using.**

While `eye-for-an-eye` runs, the sensor process does not:

* train a model,
* update any weight,
* move a threshold,
* replace a model file,
* label its own traffic,
* download anything.

You can check most of this: there is no `fit` and no `partial_fit` anywhere in
the `eye_for_an_eye/` package. Training lives in a separate `training/` package,
and when it runs it runs as a **separate unprivileged process**, never inside the
process that captures traffic or changes a firewall.

Since P9 the system can prepare data and train a candidate model on its own, if
you configure it to. It still cannot promote one. Model promotion is a command a
person types.

## Why not full self-learning

A defender that learns from its own decisions has one big problem: it has no
teacher. If it blocks a normal customer today and then learns from that block, it
will block that customer again tomorrow, with more confidence.

This is how a small mistake becomes a permanent rule. The defence against it is
simple: a person has to be in the loop, and the loop has to be shaped so the
system's own opinion cannot get back in through a side door.

So the project holds one line everywhere:

```text
A decision is not a label.
```

Not a block, not a score, not a threshold, not an anomaly, not an
out-of-distribution reading. The dataset code refuses all of them by name.

## The loop

```text
  1. Shadow Mode         the system watches and writes decisions
           |
  2. Review queue        unclear behaviour is put in front of a person
           |
  3. Human review        a person answers; "uncertain" is a real answer
           |
  4. Candidate dataset   parent dataset + new reviewed rows, with lineage
           |
  5. Data validation     leakage, balance, duplicates, source concentration
           |
  6. Training job        bounded, isolated, reproducible, offline
           |
  7. Model validation    ONNX parity, artifact checks, offline metrics
           |
  8. Candidate role      the new model runs in shadow, beside the active one
           |
  9. Comparison          where they agree, where they differ, what is new
           |
 10. Recommendation      PROMOTE / KEEP_ACTIVE / REJECT / NEED_MORE_DATA
           |
 11. Your decision       you promote it, or you do not
```

Steps 4 to 9 can run automatically when configured. Step 11 cannot.

## Step 2: the review queue

The sensor puts a window in front of a person when it could **not** settle it:
the mathematical engine and the model disagree, the risk landed in the middle,
the behaviour is outside the training distribution.

A confident decision the system already acted on is **not** queued. Reviewing
what the system already blocked is exactly how a model ends up learning its own
opinion.

The queue is bounded and expiring, and no single source can fill it. See
[REVIEW_QUEUE.md](REVIEW_QUEUE.md).

```sh
eye-for-an-eye review status
eye-for-an-eye review list
eye-for-an-eye review show <entry>
```

## Step 3: human review

```sh
eye-for-an-eye review answer <entry> --answer benign --note "nightly backup"
eye-for-an-eye review answer <entry> --answer automation
eye-for-an-eye review answer <entry> --answer uncertain
eye-for-an-eye review export --out labels.json
```

A reviewer may answer `uncertain`, and should whenever the evidence does not
settle it. An uncertain row stays out of supervised training. Guessing is worse
than a smaller dataset.

The offline pipeline has its own review commands for an exported pool:

```sh
python -m dataset.cli review-queue
python -m dataset.cli review
```

Shadow rows leave the system with **no label**. The system's own action
(`WATCH`, `TEMP_BLOCK`) is stored as context only. In the code this is
`SHADOW_UNLABELED`, and the validator refuses a shadow row that arrives with a
supervised label.

## Step 4: the candidate dataset

New data never edits an old dataset. It makes a new version, and that version
records its parent:

```sh
eye-for-an-eye learning prepare \
    --parent-dataset dataset-v1 \
    --parent-rows datasets/processed/dataset-v1/samples.csv \
    --labels labels.json \
    --dataset-version dataset-v2-candidate \
    --out reports/dataset-v2-candidate.json
```

Limits apply to how much of the new data any one source, one group or one day
may be. The report says what was refused and why. See
[MODEL_LINEAGE.md](MODEL_LINEAGE.md).

## Step 6: training, offline

```sh
eye-for-an-eye learning train --dataset <prepared dir> \
    --model-version risk-logreg-v2 --output-dir models/staging --yes
```

No Internet. No cloud service. No external AI API. The job has hard limits on
time, memory and disk, runs at low priority, and records the library versions and
dataset hash needed to build it again. See [TRAINING_JOBS.md](TRAINING_JOBS.md).

## Step 7: model validation

A candidate must pass before it is worth considering:

* block precision on the held-out test set,
* false blocks per 1000 benign sources,
* hard-negative performance — traffic that must never be blocked,
* leakage checks and a group-based split, never a random row split,
* ONNX and scikit-learn giving the same answer for the same input.

If a check fails, the report says so and nothing is installed. See
[MODEL_VALIDATION.md](MODEL_VALIDATION.md).

## Step 8: the candidate runs in shadow

A candidate model scores the same traffic the active model scores, at the same
moment. It **cannot** change an action and cannot reach the firewall.

This is worth stating clearly, because "canary" usually means something else.
Here it means **parallel inference, never parallel enforcement**. No fraction of
decisions is routed to a candidate.

## Step 11: your decision

There is a local model registry. Promotion is one atomic pointer write:

```sh
eye-for-an-eye model list
eye-for-an-eye model candidate
eye-for-an-eye model promote risk-logreg-v2 --yes
eye-for-an-eye model rollback --yes
```

The registry is a directory on your own disk. There is no remote registry, no
auto-update, and nothing to phone home to. See
[MODEL_REGISTRY.md](MODEL_REGISTRY.md).

`auto_promote` is not a setting. There is no configuration that makes a candidate
become the active model.

## What the system does keep updating

Two things change at run time, and both are short-lived and local:

* **The decayed risk score.** It halves every 60 seconds by default. It is
  memory, not learning.
* **The offence counter.** It decides how long a temporary block lasts, and it
  resets after `enforcement.offense_decay_seconds` (default 6 hours).

Neither touches the model or its weights.

## Fair words for this

Accurate:

```text
controlled self-learning
adaptive local learning
```

Not accurate, and not used:

```text
The AI teaches itself from every attacker.
```

It does not. It learns from data a person agreed to label, and only after that
person promotes the result.

## See also

* [Retraining](RETRAINING.md)
* [Review queue](REVIEW_QUEUE.md)
* [Training jobs](TRAINING_JOBS.md)
* [Model validation](MODEL_VALIDATION.md)
* [Model lineage](MODEL_LINEAGE.md)
* [Dataset](DATASET.md)
* [Shadow Mode](SHADOW_MODE.md)
* [Model evaluation](MODEL_EVALUATION.md)
