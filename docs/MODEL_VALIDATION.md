# Model validation

Before a candidate model is worth anyone's attention, it has to survive a series
of checks. This page says what they are and why each one exists.

Status: **Beta.** Threshold values are provisional.

## The order

```text
dataset validation
  -> training
  -> ONNX export
  -> parity check
  -> artifact validation
  -> offline metrics
  -> system-level evaluation
  -> shadow comparison
  -> promotion gate
```

A failure at any step stops the candidate there. The active model is unaffected
by every one of them.

## Dataset validation

Run before any model is fitted. A critical finding aborts training.

```text
schema validation          finite values
range validation           duplicate analysis
group leakage analysis     class distribution
scenario diversity         source concentration
feature coverage           metadata exclusion check
label source check         no conflicting labels
```

The label source check is the important one. A dataset whose labels came from a
decision this system made is rejected outright: `blocked`, `ml_score`,
`risk_threshold`, `shadow_decision` and their relatives are all refused.

A dataset may declare several trusted label sources — a controlled corpus plus
reviewed rows, for example. Every one of them must be independently trustworthy;
one bad source fails the whole dataset.

## Splitting

Never a random row split. Security windows from one source are correlated, so a
random split puts near-copies of the same behaviour on both sides and produces a
score that means nothing.

Splits follow groups: scenario group, source group, capture group, and time
period where it applies. For reviewed observed data a chronological holdout is
preferred — older rows train, later rows test — because that is what deployment
actually looks like.

The trainer verifies this itself and fails on leakage.

## Training rules

* Training uses **TRAIN** only.
* Hyperparameters are chosen on **VALIDATION** only.
* Final numbers come from **TEST**, read once.

Repeatedly tuning against a frozen test set turns it into a training set slowly.
Where an old test corpus has already influenced many decisions, a new holdout is
made for the new dataset.

No automatic oversampling. Class balance is measured and reported first; if
balancing is applied it happens after the split and only on training data.
Validation and test distributions are never modified.

## ONNX export and parity

Every production classifier is exported to ONNX. Pickle and joblib are never
deployed as production classifier artifacts: loading one executes whatever is
inside it.

Parity compares the trained model's output with the ONNX runtime's output on the
same rows:

```text
max_abs_difference    mean_abs_difference
```

The tolerance is 1e-5. Beyond that, model validation fails — a model that
computes something different in production than it did in training is not the
model that was evaluated.

The last measured run: max 2.38e-07, mean 4.54e-08 over 554 test rows.

## Artifact validation

Before a candidate is registered:

| Check | Why |
| --- | --- |
| size within bounds | a truncated or implausibly large file |
| expected inputs | one `features` input, shape `[1, 36]`, float |
| expected outputs | `label` and `probabilities`, correct shapes |
| feature schema matches | a model for other features would read garbage |
| feature order matches | the same features in a different order is a different model |
| SHA-256 matches the manifest | the file changed after it was written |
| finite inference | a trial prediction that produces real numbers |

A model that fails any of these is not registered at all.

## Offline metrics

Accuracy alone is not measured, because a model that never blocks anything scores
well on it.

```text
precision      recall            F1
false positive rate               false negative rate
PR-AUC         ROC-AUC           calibration
block precision                   false blocks per 1000 benign sources
```

### Block precision

The security metric that matters most. Among sources the system **would have
blocked**, how many are truly positive according to trusted labels?

This is measured by simulating the whole decision path — mathematical risk,
classifier, anomaly, out-of-distribution, data quality, fusion and policy — not
by reading the classifier's score. Production uses the whole system, so the whole
system is what gets evaluated.

## Hard negatives

A dedicated set of traffic that must never be blocked:

```text
monitoring          health checkers        reverse proxies
load balancers      backup clients         service discovery
administrator diagnostics
```

A candidate that performs worse on these is normally rejected, whatever its
overall numbers look like. Blocking a legitimate user is not paid for by being
right more often elsewhere.

## Hard positives

The difficult automation:

```text
slow scans          random scans           burst scans
low-rate reconnaissance                    credential automation
multi-stage reconnaissance
```

A candidate must not buy better precision by ignoring all of these.

## Out-of-distribution behaviour

A candidate is tested on known in-distribution, borderline and out-of-distribution
input. A model is not more trustworthy because it produces a higher score on
input it has never seen.

A candidate's reference distribution comes from **its own** training data. Judging
it against the active model's baseline would describe the wrong model.

## The gate result

```text
PASS                  every check passed
PASS_WITH_WARNINGS    a warning check failed; read it before deciding
FAIL                  a blocking check failed
```

`PASS` is not a promotion. It is permission to be considered.

## What is measured and what is not

Where trusted labels exist, recent precision, recent false-positive rate and
recent block precision are tracked.

Where they do not, the status is `INSUFFICIENT_LABELS`. Production accuracy is
never calculated from unlabelled observed traffic. No ground truth means
**unknown**, not 99%.

## Related

* [MODEL_EVALUATION.md](MODEL_EVALUATION.md) — the metric definitions
* [MODEL_PROMOTION.md](MODEL_PROMOTION.md) — what the gate feeds into
* [TRAINING_JOBS.md](TRAINING_JOBS.md) — how a run is bounded
* [OOD.md](OOD.md) — out-of-distribution detection
