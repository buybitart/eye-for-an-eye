# Web dataset

How web behaviour would become training data, and what exists today.

Status: **Not implemented.** This page describes the design and states plainly
what has and has not been built, so nobody has to read the code to find out.

## What exists

| Piece | State |
| --- | --- |
| web behavioural features | implemented, 35 features in 9 families |
| deterministic `web-math-risk-v1` | implemented |
| LAB web scenarios as **tests** | implemented — 13 scenarios |
| LAB web scenarios as a **dataset generator** | not implemented |
| web PCAP fixtures | not implemented |
| shadow web collection | not implemented |
| web-aware ML model | not implemented |

P10 works with no new machine learning. That is the design, not a shortfall:
deterministic risk with explanations comes first, and a model only afterwards
when there is real data to train it on.

## The scenarios that exist as tests

These run in `tests/test_web_behaviour.py` and are real request sequences
replayed through the production feature code.

**Benign, must not be flagged:**

```text
browser loading a page with 30 assets      health checker, every 5 seconds
API client at 240 requests per minute      broken frontend, 120 404s a minute
legitimate crawler, 120 distinct paths     administrator using the admin panel
one mistyped password then a success       load balancer probing the root
```

**Suspicious, should raise risk:**

```text
path enumeration, 90 distinct 404s         sensitive file probing, 10 categories
credential spraying across 30 accounts     low-and-slow probe over 10 minutes
HTTP method probing                        virtual host enumeration
```

Their measured scores are in [HTTP_FEATURES.md](HTTP_FEATURES.md).

Turning these into a dataset means emitting labelled `DatasetSample` rows from
the same sequences. The scenarios exist; the emitter does not.

## The design, when it is built

### Labels

The same terminology the rest of the project uses:

```text
BENIGN_LIKE                     SUSPICIOUS_AUTOMATION_LIKE
```

Never `human` versus `bot`. **Not every bot is malicious** — monitoring, uptime
checkers, search crawlers and API automation are all bots you want. A model
trained on `bot = bad` learns to block your own infrastructure.

### Where labels may come from

The P9 rules apply unchanged:

```text
allowed:  controlled LAB scenarios, trusted labelled captures,
          manually reviewed shadow telemetry
never:    a model score, a risk score, an anomaly score, the final decision,
          the block status, would_block
```

Shadow web telemetry is unlabelled until a person reviews it. See
[REVIEW_QUEUE.md](REVIEW_QUEUE.md).

### Splitting

Never a random request-level split. Requests from one source in one session are
correlated, so a random split puts near-copies on both sides and produces a
score that means nothing.

Split by source group, session, time period and scenario — the same rule the
network dataset follows.

### What must not become a feature

```text
the raw path         the domain or Host name       the source address
the path digest      the User-Agent string         the scenario id
```

A model that can see the domain learns the site instead of the behaviour, and
then does nothing useful on a different site. A model that can see the path
digest memorises URLs.

The path digest exists for counting repeats and is deliberately excluded from any
model input.

### Diversity

A benign set without monitoring, API clients, crawlers, proxies and
administrators produces meaningless false-positive numbers. The eight benign
scenarios above are the minimum, not the target.

### Site profile

Different sites have different normal traffic: a blog, an API, a shop and an
admin panel look nothing alike. Dataset metadata should record a coarse
`site_type` (`web`, `api`, `mixed`) for grouping and evaluation.

**Not as a model feature.** It is for reading results, not for the model to
learn.

## Per-site baseline

One global model will not be right for every website, which is what P9's
controlled retraining is for:

```text
site shadow telemetry -> reviewed local samples -> candidate dataset
  -> candidate model -> validation -> candidate shadow -> recommendation
```

Each installation stays independent. Nothing is uploaded, no models are shared,
and there is no federated learning.

## When a web model is built

It uses the P9 lifecycle without exception: candidate dataset, training job, ONNX
export, parity check, validation, candidate shadow, promotion recommendation.
`auto_promote` stays false.

Start with logistic regression, then gradient boosting if the metrics justify it.
No deep learning.

## Feature schema

Adding web features to the network `FeatureVector` would break every existing v1
model. So the recommended path — and what is built — keeps them separate:
`web-math-risk-v1` produces its own score, which joins the existing fusion as
another piece of evidence.

If a combined vector is ever built it must be **feature schema v2**, and a v1
model must never be fed v2 input.

## Related

* [DATASET.md](DATASET.md) — the network dataset pipeline
* [RETRAINING.md](RETRAINING.md) — the P9 lifecycle any web model must use
* [HTTP_FEATURES.md](HTTP_FEATURES.md) — what would be in a row
