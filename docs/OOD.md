# Out-of-distribution Detection

An **out-of-distribution** (OOD) observation is different from the data used to
train the model.

**High OOD does not mean attack.** It means the model may know less about this
traffic.

Status: **Beta.** Band values are provisional.

## Why This Exists

A machine-learning model is only reliable on data that looks like its training
data. Outside that, its confident answer is still confident, but it is worth
less.

Without an OOD check the system would treat this:

```text
ML score:  0.98
```

exactly the same whether the observation was ordinary or something the model had
never seen. That is how confident machine-learning systems make confident
mistakes.

## What It Measures

For each feature, the value is compared with the training bands:

| Where the value falls | Meaning | Contribution |
| --- | --- | --- |
| inside p05–p95 | seen often during training | 0.00 |
| p01–p05 or p95–p99 | uncommon, but represented | 0.35 |
| outside p01–p99, inside min–max | rare tail | 0.70 |
| outside the training min–max | never seen during training | 0.85+ |

The final score mixes the average contribution with the worst few. A single
odd feature should not dominate, and one extreme value should not disappear in
an average.

Missing values are skipped, not guessed. Availability flags and constant
features are excluded: they say nothing about distance.

## Statuses

| Status | Score | Meaning |
| --- | --- | --- |
| `IN_DISTRIBUTION` | below 0.25 | the model has seen traffic like this |
| `BORDERLINE` | 0.25–0.60 | in the tails of the training data |
| `OUT_OF_DISTRIBUTION` | 0.60 and above | unlike the training data |
| `INSUFFICIENT_REFERENCE` | - | no baseline, or too few comparable features |

With no reference the confidence stays at 1.0. Absence of evidence must not be
turned into a discount.

## What It Changes

OOD lowers the classifier's share of the decision. It can never raise risk.

```text
DistributionConfidence = 1 - OODScore

trust  = model_confidence * DistributionConfidence
weight = ml_weight * trust
```

The weight the classifier loses returns to the mathematical engine, which does
not depend on a training distribution.

When the status is `OUT_OF_DISTRIBUTION`, the policy guard also reduces a
proposed block to `WATCH`.

## A Worked Example

```text
Decision: WATCH

Threat evidence:     0.86
Decision confidence: 0.24
Reliable risk:       0.21

Math risk:  0.90
ML score:   0.95
ML confidence: 0.89
OOD score:  0.76

Top OOD features:
  anomaly_60s        value 1.000   training p99 0.286
  connections_10s    value 0.996   training p99 0.627
  connections_60s    value 0.996   training p99 0.706

Reason:
Traffic is suspicious, but it is far from the model training data.

Policy:
Automatic block reduced to WATCH because OOD is high.
```

This behaviour is intended. The system says "this looks bad, but I do not know
this kind of traffic well enough to act on my own".

## Measured Behaviour

On `dataset-v1`, scored against the `risk-logreg-v1` reference:

| Population | Mean OOD | Share above 0.60 |
| --- | --- | --- |
| benign, training-like | 0.044 | 0% |
| malicious, training-like | 0.079 | 0% |

Malicious traffic is **not** flagged as out of distribution. That is the point:
OOD measures distance from the training data, not danger.

## Configuration

```toml
[reliability]
ood_enabled = true
distribution_path = "models/risk-logreg-v1-distribution.json"
ood_borderline_threshold = 0.25
ood_high_threshold = 0.60
ood_minimum_features = 4
ood_suppresses_block = true
```

## See Also

* [Drift detection](DRIFT.md)
* [Data quality](DATA_QUALITY.md)
* [Local AI](AI.md)
* [Decision engine](DECISION_ENGINE.md)
