# Feature Schema 1

This page explains the list of numbers, called **features**, that Eye for an Eye builds about a source and feeds into its risk models. It is for developers who write feature or model code, and for reviewers who want to know exactly what data reaches a model.

## What a Feature Vector Is

For one source, Eye for an Eye builds 18 raw numbers. For each of those 18 numbers, it also builds one "did we actually see this?" flag. That gives 36 numbers in total. This ordered list of 36 numbers is called `INPUT_ORDER`. It lives in the code at `eye_for_an_eye/decision/features.py`, and that file is the authoritative source for the exact order.

* Numbers 1 to 18 are the raw feature values, listed below.
* Numbers 19 to 36 are the matching `available_<name>` flags, in the same order. Each flag is `0` (not seen) or `1` (seen).

No IP address, ASN (a number that identifies a network operator), country, other identifier, text, payload byte, or credential value ever goes into this list of 36 numbers. When a destination address is counted, it is only counted. It is never stored as an identity.

## How a Raw Number Becomes a 0-to-1 Number

All 18 raw values go through the same transform code, called `FeatureTransformer`, both when training a model and when running live. Each feature has a **ceiling**: the highest raw value the transform will use. Anything above the ceiling is treated as the ceiling.

There are two kinds of transform:

* **linear**: `min(raw_value, ceiling) / ceiling`
* **log**: `log1p(min(raw_value, ceiling)) / log1p(ceiling)`

`log1p(x)` means "the natural logarithm of `1 + x`." It is used for features that can have occasional huge spikes, so one very large burst does not dominate the number.

The input to this transform must be a normal, non-negative, finite number, or it can be `None` (meaning "missing"). The output is always rounded to a 32-bit floating point number (`float32`) and stays between 0 and 1.

Missing values and zero values are not the same thing:

* A **missing** value becomes `(value = 0, available = 0)`.
* An **observed zero** becomes `(value = 0, available = 1)`.

So a `0` in the value column can mean either "we checked, and it was zero" or "we could not check." The matching `available_` flag tells you which one it was.

## The 18 Features

| # | Name | Raw ceiling / units | Transform | Window | What it measures, and when it is missing |
|---|---|---|---|---:|---|
| 0 | connections_10s | 512 observations | log | 10s | Count of connection attempts in the last 10 seconds. Zero is a real observed value. |
| 1 | connections_60s | 512 observations | log | 60s | Same count, over the last 60 seconds. |
| 2 | connections_900s | 512 observations | log | 900s | Same count, over the last 900 seconds. Missing if the configured history window is shorter than 900 seconds. |
| 3 | ports_60s | 64 ports | linear | 60s | Number of different destination ports seen. |
| 4 | ports_900s | 128 ports | linear | 900s | Same, over 900 seconds. Missing if the history window is shorter than 900 seconds. |
| 5 | destinations_60s | 32 addresses counted | linear | 60s | Number of different destination addresses seen. Addresses are counted, never turned into an identity. |
| 6 | families_60s | 4 families | linear | 60s | Number of different protocol families seen (needs payload inspection). Missing without payload inspection. |
| 7 | repetition_60s | 1 fraction | linear | 60s | How often the single most-repeated probe pattern was seen, as a fraction. Eye for an Eye compares probes using an HMAC (a scrambled fingerprint of the probe, not its raw content), so it can spot repeats without storing what was sent. Simple retries are not counted here. Missing without payload inspection. |
| 8 | sequential_60s | 1 fraction | linear | 60s | Fraction of destination ports that go up or down one at a time (for example 21, 22, 23). Missing if there were fewer than 2 attempts. |
| 9 | anomaly_60s | 1 fraction | linear | 60s | Fraction of observations flagged as a protocol anomaly by a fixed rule. Missing without payload inspection. |
| 10 | credentials_60s | 20 observations | linear | 60s | Count of credential-like signals seen (for example, a login attempt was made). The actual credential content is never counted or stored here. Missing without payload inspection. |
| 11 | continuation_60s | 1 fraction | linear | 60s | Fraction of observations where the source kept talking after an initial probe. Missing without payload inspection. |
| 12 | persistence_900s | 300 seconds | linear | 900s | Time span between the first and last kept sample. Missing if the history window is shorter than 900 seconds. |
| 13 | burst_10s | 1 fraction of the 60s count | linear | 10s / 60s | The 10-second attempt count divided by the 60-second attempt count. Missing if there were no attempts. |
| 14 | interarrival_mean_60s | 60 seconds | log | 60s | Average time between events. Missing if there is no interval to measure. |
| 15 | interarrival_cv_60s | 4 (coefficient) | linear | 60s | How spread out the timing is, compared to its average (the "coefficient of variation": the timing's standard deviation divided by its mean). Missing with fewer than 3 intervals, or if the mean is zero. |
| 16 | deception_60s | 64 observations | linear | 60s | Count of deception-related connections or protocol commands (see [DECEPTION.md](DECEPTION.md)). Zero here is a real, measured value: it means "none seen." |
| 17 | previous_risk | 1 (a score) | linear | from the prior decision | This source's risk score from its last decision, faded ("decayed") over time. Zero for a source seen for the first time. |

## Evidence Outside the 36 Numbers

A few extra values travel alongside the 36 numbers, but they are not features themselves:

* `schema_version`: always `1` for this schema.
* `sample_count`: from 0 to 512.
* `observation_seconds`: from 0 to 900.
* `capped`: `true` or `false`.
* `loss_fraction`: either unknown, or a number from 0 to 1.

By default, an earlier part of the project (called "P2") keeps at most 256 samples per source. When a source is `capped`, the counts above are a **lower bound** (the real activity may have been higher), and a capped source is prevented from reaching a strong action (see [DECISION_ENGINE.md](DECISION_ENGINE.md)). This later part of the project (called "P7", where features and models live) reuses P2's existing bounded list of samples. It does not keep a second copy of packet history. Only the aggregate decision step runs on its own fixed schedule (the configured interval); nothing else runs on a separate timer.

## What These Counts Do and Do Not Mean

These counts describe observations, not unique real network connections. A retransmission, a limit in what the listener or the packet capture can see, and both a new connection and a new command inside a connection, can all add to the count.

A "warm" 900-second window is not a guarantee that 900 seconds of traffic were actually captured. The `observation_seconds` value tells you how much time was actually covered.

`UNKNOWN` does not mean a network handshake failed. It only means the answer was not determined.

Some other signals are deliberately left out of this schema: the ratio of failed handshakes, TCP timestamp values, p0f confidence (p0f is a tool that guesses an operating system from network traffic patterns), enrichment data, timing entropy, and country or ASN. They are left out because the shared event data that this project currently trusts does not have a validated, tested way to produce them. The mean and coefficient-of-variation features (14 and 15) reuse P2's existing timing data, instead of keeping a second, duplicate set of timing statistics.

## The previous_risk Column

In the version 2 synthetic training data, `previous_risk` is always `0` for every row. Because of that, both trained models (see [MODEL_TRAINING.md](MODEL_TRAINING.md)) learned to give this column zero real influence.

Any future training data must reproduce a source's risk history in the correct time order before using this column for real. No label, and no earlier block decision, may be substituted in as a stand-in value for it.

## Two Contracts: The 36-number Tensor and the 34-column Model

There are two related but different numbers here, and it is important to keep them apart.

**The running system always uses all 36 numbers.** The live decision engine, and the ONNX model file it loads, both use the full `INPUT_ORDER` list: `float32[1, 36]`. This has not changed.

**Training only learns from 34 of those 36 numbers.** The frozen model feature contract, version 1, is defined in `dataset/schema.py` as `MODEL_FEATURES`, and it is checked again in `training/schema.py`. It excludes exactly 2 columns:

* `previous_risk`
* `available_previous_risk`

The reason is simple: `previous_risk` is this system's own past output, decayed over time. It is not a fresh observation about the network. If a model were trained to use its own old output as an input, it would tend to just agree with itself. This is called a **feedback loop**, and a model built this way can look accurate while really only repeating its own earlier guess.

So how can training exclude 2 columns, while the model file still takes all 36 numbers as input? The training code builds the model on only 34 columns, then places those 34 fitted weights back into their correct positions in the full 36-number layout. The 2 excluded positions are filled in with a weight of exactly zero. A "weight" (or **coefficient**, for a logistic regression model) is a number the model multiplies against one input. A weight of zero means: whatever value sits in that slot, it can never change the model's answer. This way, the shipped model file still matches the running system's `float32[1, 36]` contract, the loader and manifest do not need to change, but only 34 of the 36 numbers can ever actually affect the result.

Changing which columns are used, their order, or what any column means, needs both a new feature contract version and a new model version. The test file `tests/test_p8_dataset_validation.py` checks that the column list matches what is expected.

`training/schema.py` also lists columns that may **never** become model inputs, in any future contract, because they would leak information the model should not use to "cheat": any form of network address, ASN, hosting provider, country, username, hostname, split or grouping keys, the label itself, and anything the decision system produced by itself (`previous_action`, `blocked`, `rate_limited`, `firewall_status`, `final_risk`, `ml_score`, `math_score`).

Schema 1 has no TTL, IP-ID, TCP-timestamp, or p0f column. These are all examples of network "fingerprinting" signals that can hint at what operating system or device sent traffic. Because none of them are in this schema, no fingerprint-based signal can ever dominate a model trained on it. If one is ever added in a future schema, `training/schema.py` has a place called `ABLATIONS` where its real effect must be measured first. An **ablation** is a test where you remove one input and see how much the model's answers change without it. This is how the project would check that a new fingerprint feature is not doing all the work by itself.

## See Also

* [DECISION_ENGINE.md](DECISION_ENGINE.md): how these numbers turn into a risk score and an action.
* [MATH_MODEL.md](MATH_MODEL.md): the math model that reads these features directly.
* [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md): how features flow into the machine-learning model.
* [ONNX_MODEL.md](ONNX_MODEL.md): the model file that reads the 36-number tensor.
* [MODEL_TRAINING.md](MODEL_TRAINING.md): how the 34-column model contract is trained.
* [DATASET.md](DATASET.md): how training data is built and stored.
* [PRIVACY.md](PRIVACY.md): why no identity or payload content is ever a feature.
* [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md): known limits of this feature set.
