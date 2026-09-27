# How the AI works

This page explains the machine-learning part in simple words.

## Short answer

* The model is **logistic regression**. It is one of the simplest models there is.
* It runs on **your CPU**, on **your machine**, with **ONNX Runtime**.
* The model file is **730 bytes**.
* The shipped model has **36 inputs**. Every input is a behaviour number.
* It never sees your data. It never sends anything anywhere.
* It is **optional**. With no model file the maths engine works alone.
* Today it is for **watching only**. Do not use it to block.

## Why such a small model

A big model would be harder to check. This project needs the operator to be able
to answer one question: *why did it decide that?*

Logistic regression gives a straight answer: each input has one weight, and the
score is the sum. Nothing is hidden.

A small model is also fast. Inference is a few microseconds of CPU time, with a
200 ms timeout as a hard limit.

## What the model can see

The shipped model gets 36 numbers:

* 18 behaviour numbers (counts, shares, timings), and
* 18 "is this number known?" flags.

That is all. A flag of 0 means the value was missing, so the model can tell the
difference between "zero connections" and "we did not see".

## What the model can never see

This list is enforced in code, in `dataset/schema.py` (`NEVER_MODEL_INPUT`).

* The source IP address.
* The country, the ASN, the hosting provider, the hostname.
* HTTP bodies, cookies, `Authorization` headers, tokens.
* Usernames and passwords.
* Raw packet bytes.
* The port number your service happens to run on.
* Which scenario or which capture file the sample came from.
* Any decision the system itself made before.

Two of these need a word of explanation:

**Identity is not behaviour.** If the model could see the country, it would learn
"this country is bad". That is wrong and unfair, and it breaks the moment the
attacker changes their address.

**`previous_risk` is handled carefully.** The 18th behaviour number is the
system's own earlier score. Feeding a system its own output teaches it to agree
with itself.

The shipped `risk-logreg-v1` was trained before this rule and still takes all 36
columns. The dataset pipeline defines a **34-column** model feature set
(`MODEL_FEATURES` in `dataset/schema.py`) that drops `previous_risk` and its
flag. That 34-column set is the contract for the next model, not for the one
that ships today.

## The manifest contract

A model file alone is not enough. The system needs two files:

* `risk-logreg-v1.onnx` — the model,
* `risk-logreg-v1.json` — the manifest.

Before loading, the system checks:

| Check | Why |
| --- | --- |
| SHA-256 of the model matches the manifest | The file was not swapped or damaged. |
| `feature_schema_version` is 1 | The model expects today's inputs. |
| `feature_order` matches exactly | Input 7 means the same thing on both sides. |
| `input_shape` is `[1, 36]`, dtype float32 | The shape is what the code sends. |
| `output_names` are `label`, `probabilities` | The outputs are what the code reads. |
| The file is a normal local file, not a symlink or a network path | No surprise sources. |
| File permissions are not group- or world-writable | Nobody else can swap it. |
| Size is under `ml.max_model_bytes` (16 MiB) | No memory surprise. |

If any check fails, the model is not loaded. The system keeps running with the
maths engine. It does not crash and it does not "try anyway".

## Where the model runs

The model runs in a **separate process**, not inside the main service.

* If it hangs, the main service is not blocked.
* If it crashes, the main service keeps working.
* Only one inference runs at a time (`ml.max_concurrent = 1`).
* At most 64 requests wait in line (`ml.max_pending = 64`).
* Each inference has 200 ms (`ml.inference_timeout_ms`).
* Results are cached for 10 seconds.

## How much the model is trusted

The model never decides alone. Three rules limit it.

**1. Weight by confidence.**

```
trust  = max(0, 2 * confidence - 1)
weight = ml_weight * trust
```

A model that says "50/50" gets a trust of 0 and no weight at all. The weight it
does not use goes back to the maths engine.

**2. Minimum confidence for action.** Below `decision.minimum_ml_confidence`
(default 0.70) the decision is written down as "low model confidence" and a
strong action is refused.

**3. Disagreement blocks action.** If the maths engine says 0.8 or more and the
model says 0.2 or less, that is recorded as `model_disagreement` and the action
is reduced to `WATCH`.

There is a fourth rule, and it is the important one: **a model can never grant
firewall rights.** Enforcement needs the maths engine to agree
(`decision.minimum_math_risk`, default 0.80). A model file, on its own, can
never cause a block.

## The current model

| Fact | Value |
| --- | --- |
| Name | `risk-logreg-v1` |
| Type | Logistic regression |
| Format | ONNX, opset `ai.onnx` 17 / `ai.onnx.ml` 3 |
| Size | 730 bytes |
| Inputs | 36 (the runtime contract, `INPUT_ORDER`) |
| Classes | `benign-like`, `malicious-automation-like` (the ONNX contract; dataset labels use `benign_like` / `malicious_automation_like`) |
| Recommendation | **Shadow only** |

Full detail, including how it was measured and where it is weak:
[Model card](../models/MODEL_CARD_risk-logreg-v1.md) and
[the model report](../reports/model-risk-logreg-v1.md).

## Checking it yourself

```sh
eye-for-an-eye model status
```

Output:

```
Model: risk-logreg-v1
Format: ONNX
Feature schema: 1
Status: Healthy
Mode: Shadow
```

`Status: Not configured` means there is no model file. That is a normal, safe
state, not an error.

## See also

* [The maths engine](MATH_MODEL.md)
* [Feature schema](FEATURE_SCHEMA.md)
* [Controlled self-learning](SELF_LEARNING.md)
* [ONNX model contract](ONNX_MODEL.md)
