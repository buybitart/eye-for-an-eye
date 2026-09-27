# Drift Detection

Traffic changes with time. A model can become less useful when real traffic is
very different from its training data.

Eye for an Eye compares new traffic with the training data. This is called
**drift detection**.

Status: **Beta.** Thresholds are provisional and are not yet calibrated against
a real deployment.

## What Drift Is Not

**Drift is not an attack.** It says something about your whole traffic
population, not about one source.

A new backup job, a new monitoring service or a new deployment can all cause
drift. None of them is hostile.

So drift never makes a single source more suspicious. It only lowers how much
the system trusts the model. See [Model health](#model-health).

## What Is Compared

Every model ships with a **reference distribution**: a small file that records
what the training data looked like, feature by feature.

```
models/risk-logreg-v1.onnx                  the model
models/risk-logreg-v1.json                  the manifest
models/risk-logreg-v1-distribution.json     the training baseline
```

The reference belongs to one model. Loading it for a different model is an
error, not a fallback. A stale baseline would quietly mis-measure every check
made against it.

The baseline is **never** updated from production traffic. If it were, an
attacker could slowly redefine "normal".

## How Production Traffic Is Measured

The sensor keeps counts in the reference's own fixed bins, in three rolling
windows: 1 hour, 24 hours and 7 days.

Memory is fixed. It does not grow with traffic. About 15 000 integers in total,
whatever the volume.

The hot path does one bin lookup per feature. The full comparison is periodic,
not per packet.

## The Method

**Population Stability Index (PSI)** over the reference bins:

```text
PSI = sum( (actual - expected) * ln(actual / expected) )
```

Empty bins are floored with a small epsilon on both sides, so the result is
always finite and there is no division by zero.

A **quantile shift** check is also reported: how far the current median bin has
moved from the reference median bin.

PSI is not a probability. It is a distance.

## Statuses

| Status | Meaning |
| --- | --- |
| `INSUFFICIENT_DATA` | Not enough samples yet. The system does not guess. |
| `STABLE` | Traffic matches the training data. |
| `WARNING` | Some features have moved. |
| `DRIFTED` | Traffic differs from the training data. |

Provisional thresholds: PSI 0.10 for a warning, 0.25 for drift. Both are
configurable.

After a restart, or in a quiet window, the status is `INSUFFICIENT_DATA`. It is
never `STABLE`, because that would fabricate confidence.

## Per-feature Results

One global number is not enough. An operator needs to know *what* changed.

```text
Feature                    Drift              PSI
  repetition_60s           High               1.094
  interarrival_cv_60s      High               1.033
  continuation_60s         High               0.854
  connections_10s          High               0.340
  ports_60s                Stable             0.021
```

The overall score is a weighted aggregate, not `max()`. One noisy low-value
feature must not permanently mark a model unusable, and one severe shift must
not hide inside an average of forty stable features.

## Commands

```sh
eye-for-an-eye drift status --config eye-for-an-eye.toml
eye-for-an-eye drift report --config eye-for-an-eye.toml --window 24h
eye-for-an-eye drift report --config eye-for-an-eye.toml --json
```

Both are read-only. They never train, download, promote or change a firewall.

## Model Health

Drift feeds a separate model health state.

| State | Meaning |
| --- | --- |
| `HEALTHY` | The model matches its training distribution. |
| `DEGRADED` | Drift, or many unusual observations. |
| `UNRELIABLE` | Most traffic is unlike the training data, or inference is failing. |
| `UNAVAILABLE` | No model is loaded. |

When the model is not healthy, it may still advise, but it may not drive a
strong action on its own.

**The mathematical engine is never disabled by this.** A degraded model reduces
machine-learning authority. It does not remove the deterministic defence.

```sh
eye-for-an-eye model health --config eye-for-an-eye.toml
```

## Configuration

```toml
[reliability]
drift_enabled = true
distribution_path = "models/risk-logreg-v1-distribution.json"
drift_minimum_samples = 200
drift_warning_threshold = 0.10
drift_drifted_threshold = 0.25
drift_interval_seconds = 900.0
```

## Building a Reference Distribution

Offline only, from a validated dataset:

```sh
python -m training.export_distribution \
    --dataset datasets/processed/dataset-v1/train.csv \
    --model-version risk-logreg-v1 \
    --dataset-version dataset-v1 \
    --supervised-only \
    --output models/risk-logreg-v1-distribution.json
```

The command refuses to overwrite an existing file. A reference distribution is
immutable.

## See Also

* [Out-of-distribution detection](OOD.md)
* [Data quality](DATA_QUALITY.md)
* [Decision engine](DECISION_ENGINE.md)
* [Local AI](AI.md)
