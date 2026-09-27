# Math risk score, fusion, and decision policy

This page explains how Eye for an Eye turns raw numbers about a source into a risk score, and how it turns that score into an action. It is for developers and reviewers who want to check or extend the decision logic.

## The math risk score (math-risk-v1)

Eye for an Eye has a small math model called `math-risk-v1`. It does not need the ONNX machine-learning model. It can work alone.

The formula is:

```
score = sigmoid(-4.0 + sum(weight * normalised_value))
```

A **sigmoid** is a math function. It takes any number and turns it into a number between 0 and 1. The value -4.0 is called the **bias**. It pulls the score down when nothing unusual is seen.

Each feature (see [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md)) has its own weight. The engine multiplies each normalised value by its weight. This is one **contribution**. Then it adds up all contributions and the bias, and puts the sum through the sigmoid function.

| Feature | Weight |
|---|---:|
| ports_60s | 3.0 |
| credentials_60s | 3.0 |
| anomaly_60s | 2.5 |
| ports_900s | 1.5 |
| destinations_60s | 1.0 |
| families_60s | 1.0 |
| continuation_60s | 1.0 |
| sequential_60s | 0.7 |
| repetition_60s | 0.5 |
| persistence_900s | 0.5 |

A decision record keeps the six largest contributions. This helps a human see why the score came out the way it did.

The contributions are **logit terms**. This means they are added together before the sigmoid step. They are not simple percentages of the final score, and they do not have to add up to 1.

The score from `math-risk-v1` is **uncalibrated**. This is an honesty marker you will see again in this project. It means the score is not a real probability. A score of 0.80 does not mean "80% chance of an attack." It only means the math model found more or stronger signals than at 0.40.

## Combining math and the machine-learning model (fusion)

Eye for an Eye can also use an ONNX machine-learning model (see [ONNX_MODEL.md](ONNX_MODEL.md)). The decision engine mixes the math score and the model score together. This mixing step is called **fusion**.

The default fusion weights are:

| Part | Default weight |
|---|---:|
| Math score | 0.55 |
| ML (machine-learning) score | 0.35 |
| Persistence | 0.10 |

The ML weight is not always used at full strength. The engine first computes a **trust** value from the model's confidence:

```
trust = max(0, 2 * confidence - 1)
```

Here, `confidence = max(model_score, 1 - model_score)`. This just means: how far is the model's score from the middle point of 0.5? A score of 0.5 means trust is 0. A score of 1.0 or 0.0 means trust is 1.

The engine then uses `effective_ml_weight = 0.35 * trust`. If the model is unsure, or missing, or broken (a `NaN` result, or a failed call), its weight drops to zero. Any ML weight that is not used goes back to the math score. So in the worst case, when trust is 0, the fusion becomes:

```
fused_score = 0.90 * math_score + 0.10 * persistence
```

The model's confidence is a measure of how separated the model's two class scores are. It is **not** a real, tested measure of certainty. It has not been calibrated against real-world outcomes.

Two safety rules protect against a bad or wrong model:

* If the math score is high (0.80 or above) and the ML score is low (0.20 or below), this is called a **disagreement**. A disagreement blocks any strong action.
* If the model's confidence is low, this also blocks any strong action.

A high ML score alone can never unlock a strong action. It must still pass the math confirmation gate, described later on this page.

## Risk score over time (decay)

A source's risk score does not disappear right after a decision. It fades over time. The formula is:

```
risk = max(fused_score, previous_risk * 2^(-elapsed_seconds / half_life_seconds))
```

The default `half_life_seconds` is 60. This means: after 60 seconds with no new activity, the old risk value is worth half as much. This uses a stable, tested `2^x` function, not an approximation.

Eye for an Eye keeps a bounded history of past risk values per source. It does not keep a never-ending log of every score. When a source is quiet, its risk value is decayed the next time that source is evaluated. Eye for an Eye does **not** invent extra decision events on a timer just to decay an idle score. If a source's history entry expires from the bounded history cache, it starts fresh, as if from zero.

Eye for an Eye does not use an **EMA** (exponential moving average, a common way to smooth a value over time) here. The reason is that the fixed time windows already used in the features (10s, 60s, 900s) would overlap with what an EMA does, without adding new supporting evidence.

## Turning a risk score into an action

There are four possible actions: `OBSERVE`, `WATCH`, `RATE_LIMIT`, and `TEMP_BLOCK` (temporary block).

The default entry thresholds are:

| Action | Enters at risk ≥ |
|---|---:|
| WATCH | 0.40 |
| RATE_LIMIT | 0.70 |
| TEMP_BLOCK | 0.88 |

**These are baseline research thresholds. They are not production-calibrated.** [OWNER INPUT REQUIRED] before real deployment.

Once a source is in a stricter state (for example `WATCH`), Eye for an Eye does not drop it back down the moment the score dips slightly. There is a **hysteresis margin** of 0.10. This means the exit points are lower than the entry points:

| Action | Exits below risk |
|---|---:|
| WATCH | 0.30 |
| RATE_LIMIT | 0.60 |
| TEMP_BLOCK | 0.78 |

Hysteresis just means: it takes a bigger drop to leave a state than it took to enter it. This stops the action from flapping back and forth on small score changes. Even while a source stays in a stricter state because of hysteresis, the gates in the next section still apply.

## Data quality score

Before Eye for an Eye trusts a decision enough to act strongly, it checks the quality of the evidence behind it. The quality formula is:

```
quality = 0.35 * min(sample_count / 20, 1)
        + 0.25 * min(observation_seconds / 5, 1)
        + 0.25 * feature_completeness
        + 0.15 * min(categories / 3, 1)
```

Then:

* Multiply the result by `(1 - loss_fraction)` if the loss fraction is known. If it is not known, multiply by 0.65 instead.
* If the samples were capped (cut off at a limit), cap the final quality score at 0.49.

"Categories" here means one of four separate behaviour categories:

| Category | Rule |
|---|---|
| Port breadth | `ports_60s` is 8 or more |
| Anomaly fraction | `anomaly_60s` is 0.2 or more |
| Credentials | `credentials_60s` is 3 or more |
| Continuation | `continuation_60s` is 0.15 or more, AND `persistence_900s` (span) is 5 seconds or more |

These four categories are just four different kinds of evidence. They are not a claim that the categories are statistically independent of each other.

Eye for an Eye does not use P0 fingerprint or enrichment data (extra network fingerprinting features) in this quality score, because those inputs are not validated for this FeatureVector. The listener component reports how many events it dropped at the application level, so that count is known. But loss caused by packet capture or the kernel, or loss in a PCAP replay file, stays unknown. Unknown loss prevents a strong action by default (through the 0.65 multiplier above).

## Requirements for a strong action

A strong action (`RATE_LIMIT` or `TEMP_BLOCK`) needs **all** of these to be true:

* At least 20 samples (`minimum_samples_for_block`).
* At least 5 seconds of observation (`minimum_observation_seconds`).
* Quality score of at least 0.70 (`minimum_quality`).
* At least 3 of the 4 behaviour categories (`minimum_categories`).
* Math score of at least 0.80 (`minimum_math_risk`).
* A healthy sensor.
* No low-confidence or conflicting ML result (`minimum_ml_confidence` is 0.70).

If any of these checks fail, `RATE_LIMIT` or `TEMP_BLOCK` is downgraded to `WATCH`. A protected source (see below) always becomes `OBSERVE`. If the policy code itself fails to run correctly, the result also becomes `OBSERVE`, with the reason `policy_failure`.

A machine-learning model can **never** skip these checks by itself. The checks always run.

**`RATE_LIMIT` is recorded as a decision today, but it is not actually applied by this implementation yet.**

## Blocking history (the offense counter)

Eye for an Eye keeps a small offense counter per source. This counter only goes up when an enforcement action (a real, successful block) actually happens — not just when a `TEMP_BLOCK` decision is proposed.

Block durations get longer each time, in this order: 300, 1800, 7200, then 43200 seconds. There is no permanent ban.

If 21600 seconds (6 hours) pass since the last successful block on a source, the offense counter resets to zero, and the next block goes back to the shortest duration.

This state is temporary. It lives only in memory, it is bounded in size, and it is tied to one source IP address. It is never a judgement about who that source "really is." Also, the underlying firewall rule expiry (in the kernel) does not depend on whether the Eye for an Eye process is still running.

## Looking at a decision record

Every decision is saved as a structured record, so it can be reviewed later. This uses event schema version 3, with `decision_version = 1`. No database migration is needed for this.

A decision record includes:

* the final action and the action that was first proposed,
* the risk score,
* the math model's version and its top contribution terms,
* the ML (machine-learning) result,
* the data quality result,
* the ID of the event that supported this decision,
* the list of policy reasons (why gates passed or failed),
* whether the system would have enforced this action, whether it actually did, and for how long.

You can look up one decision like this:

```sh
eye-for-an-eye decision explain EVENT_ID --storage-path /path/events.sqlite3 --json
```

Normal storage retention rules apply to these records (see [STORAGE.md](STORAGE.md)). Under heavy storage pressure, some metadata can be trimmed. So if you cannot find a stored explanation for a decision, that is not proof that no decision was made.

## See also

* [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md) — the input numbers this page's formulas use.
* [MATH_MODEL.md](MATH_MODEL.md) — more detail on the math risk model.
* [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md) — how the machine-learning path fits around this logic.
* [ONNX_MODEL.md](ONNX_MODEL.md) — the machine-learning model itself.
* [ENFORCEMENT.md](ENFORCEMENT.md) — what happens when a block is enforced.
* [SHADOW_MODE.md](SHADOW_MODE.md) — running decisions without enforcing them.
* [MODEL_EVALUATION.md](MODEL_EVALUATION.md) — measured results for these thresholds.
* [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md) — known limits of this approach.
