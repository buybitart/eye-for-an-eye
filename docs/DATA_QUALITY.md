# Data Quality

Before asking "is this dangerous?", the system asks "do I have enough evidence?"

Data quality is that second question. It is a number from 0 to 1 describing how
complete and reliable the current observation is.

Status: **Stable** (the score), **Beta** (the P8 status and reason reporting).

## What It Looks At

| Input | Weight | Why |
| --- | --- | --- |
| sample count | 0.35 | A handful of packets says little. |
| observation duration | 0.25 | A one-second view is not a pattern. |
| feature completeness | 0.25 | Missing values mean missing evidence. |
| independent behaviour categories | 0.15 | One signal repeated is still one signal. |

The score is then reduced by known packet loss. If loss cannot be measured at
all, the score is reduced anyway: an unmeasured gap is not the same as no gap.

A capped window is limited to 0.49, because a truncated view cannot be complete.

## Independent Signal Families

One repeated signal must not look like ten independent ones. Evidence is grouped
into families:

* port breadth
* protocol anomaly
* credential behaviour
* session continuation and persistence

A strong action needs a configurable minimum number of **independent** families,
not a high count of one thing.

## What It Controls

Low data quality prevents strong automatic action. This is a hard gate in the
policy guard, not a suggestion.

```text
Reliable risk: 0.95
Data quality:  0.25
Result:        WATCH, not TEMP_BLOCK
```

The refusal is recorded as a reason on the decision, so an operator can see
exactly why the action was reduced.

## Health Is Not Guilt

A broken feature extractor must never make traffic look more dangerous.

```text
parser failure
  -> feature unavailable
  -> data quality lower
  -> strong automatic action disabled
```

Security risk and system health are kept apart on purpose. If the sensor is
unhealthy, the system does less, not more.

## Feature Health

The reference distribution records, per feature, whether it was constant or
nearly constant during training. A feature that is constant in production but
varied in training is a signal that something upstream may be broken.

This is reported, not acted on automatically. A constant value can also simply
mean "nothing unusual happened".

## Configuration

```toml
[decision]
minimum_quality = 0.70
minimum_samples_for_block = 20
minimum_observation_seconds = 5.0
minimum_categories = 3
```

## See Also

* [Decision engine](DECISION_ENGINE.md)
* [Out-of-distribution detection](OOD.md)
* [Drift detection](DRIFT.md)
