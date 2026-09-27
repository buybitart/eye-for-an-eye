# Anomaly Detection

An **anomaly** is unusual behaviour.

Unusual does not always mean dangerous. Eye for an Eye uses anomaly data as one
signal among several.

Status: **Beta.** Shadow Mode only.

## What It Is Not

A new backup job is anomalous. A new monitoring probe is anomalous. A new
deployment is anomalous. None of them is an attack.

So the anomaly score is **never** allowed to cause a block on its own. That is
not a rule someone could switch off. It is arithmetic: the anomaly signal carries
a weight of 0.10, and the block threshold is 0.88. Maximum anomaly with no other
evidence produces a risk of about 0.12, which is `OBSERVE`.

## The Model

| Fact | Value |
| --- | --- |
| Family | Isolation Forest |
| Version | `isolation-v1` |
| Format | ONNX (no pickle in production) |
| Size | about 1.1 MB |
| Inputs | 34 behaviour features |
| Trained on | trusted benign-like rows of `dataset-v1` only |
| Latency | p50 1.9 ms, p95 2.0 ms |
| Recommended mode | **shadow only** |

An Isolation Forest was chosen over an autoencoder because the input is a small
tabular vector, it runs on a CPU in milliseconds, the artifact is inspectable,
and it needs no training framework at run time.

## What It Was Trained On

**Trusted benign behaviour only.** This matters more than the algorithm.

If the detector were fitted on a mixture of benign and malicious traffic, its
output would quietly become "similar to attacks we labelled", and calling that an
anomaly score would be dishonest. Fitted on benign traffic only, the score means
what it says: *unlike normal traffic we validated*.

Four source groups are held out of training for evaluation, so the model is not
scored on rows it memorised.

## The Score

The raw Isolation Forest output is a `decision_function` value where higher means
more normal. That is not an anomaly score, and it is not exposed as one.

The manifest records the transformation:

```text
anomaly_score = clamp01((high - raw) / (high - low))
```

`high` and `low` are quantiles of the raw score on the benign training
population. The result is `0` for common behaviour and `1` for behaviour far
outside the baseline. Both the raw value and the normalised score are reported.

## Measured Behaviour

On `dataset-v1`:

| Population | Mean | Share above 0.5 |
| --- | --- | --- |
| trusted benign | 0.270 | 15.8% |
| malicious automation | 0.509 | 43.0% |
| unlabelled shadow | 0.581 | 75.9% |

Read this honestly: the separation is **modest**. About one benign window in six
scores above 0.5. That is why the signal has a small weight and why no threshold
here is safe to block on.

The shadow population scores highest of all. Shadow traffic is real observation
the model never trained on, so it is genuinely unusual relative to a lab
baseline. This is a statement about the training data, not about the traffic.

## Threshold Analysis

Choosing a threshold trades review volume against coverage. It does **not**
produce a firewall rule.

| Threshold | Benign flagged | Scanner flagged |
| --- | --- | --- |
| 0.3 | 46.5% | 90.8% |
| 0.5 | 15.8% | 43.0% |
| 0.7 | 5.5% | 14.0% |
| 0.9 | 0.5% | 5.2% |

At every setting the benign rate is high relative to the scanner rate. This is a
dial for selecting samples to review, nothing more.

## When It Fails

The sensor keeps working. A missing, corrupt or failing anomaly model is a
supported state, not an error:

* no artifact configured → `disabled`
* artifact missing or invalid → `ANOMALY_MODEL_UNAVAILABLE`
* repeated inference failures → the circuit breaker opens and scoring stops
* inference over its time budget → `skipped_budget`

In every case the decision continues with the mathematical engine, the
supervised classifier and the policy guard.

The model is never trained at startup. Only a validated artifact is loaded.

## Safety of the Artifact

Loaded through the same hardened reader as the classifier: a local regular file,
no symlink, no network path, not group- or world-writable, size capped, and its
SHA-256 checked against the manifest. The manifest's feature schema, feature
names, input shape, dtype and normalisation are all validated before use.

One honest difference from the classifier: the anomaly model runs **in-process**,
not in an isolated child process. Its input is a float vector the sensor built
itself rather than attacker bytes, and it is bounded by a time budget and a
failure breaker. The classifier keeps its stronger isolation.

## Training It Yourself

```sh
python -m training.train_anomaly \
    --dataset datasets/processed/dataset-v1/train.csv \
    --dataset-version dataset-v1 \
    --version isolation-v1 \
    --output-dir models
```

Offline, no network. The command records the dataset version, feature schema,
seed, parameters and library versions in the manifest, and refuses to overwrite
an existing artifact. It checks ONNX parity against scikit-learn before writing
(measured: 2.3e-07).

## Configuration

```toml
[reliability]
anomaly_enabled = true
anomaly_model_path = "models/isolation-v1.onnx"
anomaly_manifest_path = "models/isolation-v1.json"
anomaly_timeout_ms = 200.0
anomaly_max_failures = 5

[decision]
anomaly_weight = 0.10
```

With no artifact configured, fusion arithmetic is identical to before this
component existed.

## See Also

* [Out-of-distribution detection](OOD.md)
* [Drift detection](DRIFT.md)
* [Data quality](DATA_QUALITY.md)
* [Decision engine](DECISION_ENGINE.md)
