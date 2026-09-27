# The Maths Engine

The maths engine is the first of the two risk engines. It is small, fixed and
easy to read. You can check it by hand.

It is called `math-risk-v1`. The code is in
`eye_for_an_eye/decision/math_risk.py` (33 lines).

## Why a Maths Engine at All

The AI model is optional. Sometimes there is no model file. Sometimes the model
is unhealthy. Sometimes it is not sure.

In all of those cases the system must still work. The maths engine is the part
that always works. It never needs a file, a download or a GPU.

It is also the part you can argue with. Every weight is written in the source
code, in one place.

## The Formula

```
z     = bias + (weight_1 * feature_1) + (weight_2 * feature_2) + ...
score = 1 / (1 + e^(-z))
```

This is a plain logistic function. The score is always between 0 and 1.

The bias is `-4.0`. That means: with no evidence at all, the score is about
`0.018`. The system starts by trusting you.

## The Weights

Only 13 of the 18 behaviour numbers have a weight. The others are used by the
policy rules, not by this formula.

| Behaviour number | Weight | Plain meaning |
| --- | ---: | --- |
| `credentials_60s` | 3.0 | How many login-like attempts in 60 seconds. |
| `anomaly_60s` | 2.5 | Share of odd packets (bad flags, bad sizes). |
| `ports_60s` | 2.25 | How many different ports in 60 seconds. |
| `ports_900s` | 2.25 | How many different ports in 15 minutes. |
| `destinations_60s` | 1.0 | How many of your addresses it touched. |
| `families_60s` | 1.0 | How many protocol families it tried. |
| `continuation_60s` | 1.0 | Share of sessions it kept going after the first answer. |
| `deception_60s` | 1.0 | How often it touched a decoy service. |
| `sequential_60s` | 0.7 | Share of ports touched in order (1, 2, 3, ...). |
| `repetition_60s` | 0.5 | Share of repeated, identical attempts. |
| `persistence_900s` | 0.5 | How many seconds it kept coming back. |
| `connections_60s` | 0.5 | How many connection attempts in 60 seconds. |
| `connections_900s` | 0.5 | How many connection attempts in 15 minutes. |

The two biggest weights are login guessing and odd packets, with port sweeping
just behind. That matches what a scanner or a brute-force bot really does.

Notice that port sweeping is weighted the same over a minute as over a quarter
of an hour, and so is connection volume. That is deliberate, and it was not
always true: until `math-risk-v3` the long window carried half the weight
*and* was measured against twice the ceiling, so the same twenty ports were
worth four times less if the source took its time. Taking your time is a choice
an attacker makes precisely because it used to be cheaper. It is not any more.

## Before the Formula: Normalisation

Every raw number is first mapped into the range 0 to 1. Each behaviour number
has a ceiling and a shape (`linear` or `log`). Example:

* `ports_60s` has ceiling 64 and shape `linear`. 32 ports becomes 0.5.
* `connections_60s` has ceiling 512 and shape `log`. Big values grow slowly.

A missing value becomes 0, and a second column marks it as missing. The model
is never told "0 connections" when the true answer is "we do not know".

The transformation lives in `FeatureTransformer.transform`. Training and
inference use **the same function**. There is no second copy.

## What the Engine Returns

* `score`: a number from 0 to 1.
* `contributions`: how much each behaviour number added to `z`.
* `model_version`: `math-risk-v1`.

The contributions are why the system can explain itself. A decision can say
"most of this score came from `ports_60s` and `credentials_60s`".

## The Score Is Not a Probability

This is important. The score is **not** the chance that the source is bad. It
is an uncalibrated number. It only says "more" or "less".

The code says this too: the result object is documented as
"explicitly uncalibrated".

## Decay Over Time

A source that stops behaving badly gets better again. The old score is halved
every `decision.half_life_seconds` (default: 60 seconds).

```
new_score = old_score * 2^(-elapsed / half_life)
```

The final risk is the higher of the fresh score and the decayed old score.

## How It Joins the AI Model

See [Decision engine](DECISION_ENGINE.md) and [How the AI works](AI.md).

Short version: the maths engine holds the base weight. The model can only take
part of that weight, and only when it is confident.
