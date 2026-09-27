# Model and dataset lineage

Lineage answers one question: **where did this come from?**

Status: **Beta.**

## Why it matters

A model that starts blocking the wrong traffic is only fixable if you can find
out what taught it to. Without lineage the answer is a shrug. With it, the chain
is:

```text
this model  <-  this dataset  <-  this parent dataset + these reviewed rows
```

Every link is a recorded fact, not a reconstruction.

## Datasets are immutable

A published dataset version is never modified. New data means a new version:

```text
dataset-v1  ->  dataset-v2  ->  dataset-v3
```

Never an edit to `dataset-v1`. This is what makes an old result reproducible: the
data that produced it still exists, unchanged.

A new dataset is built as a **candidate** first:

```text
dataset-v2-candidate  ->  (validation passes)  ->  dataset-v2
```

## What a dataset records about its parent

```json
{
  "dataset_version": "dataset-v2-candidate",
  "parent_dataset": "dataset-v1",
  "parent_rows": 2334,
  "parent_digest": "…",
  "new_reviewed_samples": 214,
  "new_benign_samples": 121,
  "new_malicious_samples": 93,
  "new_distinct_sources": 37,
  "built_at": "…",
  "label_origin": "parent rows keep their original label source; new rows are labelled only by a person answering a review entry"
}
```

Beside it, the intake report says what was **refused** and why: per-source limits,
per-day limits, duplicates, rows from a single source over its share. A dataset
that accepted 214 of 900 offered rows says so.

## What every row records about itself

```text
source_type            lab, capture, reviewed shadow, unlabelled shadow
source_group           pseudonymous grouping key
scenario_group         controlled scenario family
capture_group          capture the row came from
label_source           controlled_scenario, manual_review, trusted_fixture…
label_confidence       HIGH, MEDIUM or LOW
collection time        when the behaviour was observed
review time            when a person answered, if they did
```

None of this is a model feature. It exists for grouping, splitting, provenance
and review. The dataset validator refuses a manifest that lists any of it as a
model input.

## Label confidence

| Confidence | When |
| --- | --- |
| `HIGH` | deterministic controlled ground truth: the scenario decided the label before it produced the traffic |
| `MEDIUM` | a person reviewed a behaviour summary and judged it |
| `LOW` | a person reviewed it and could not tell |

A reviewed label is never `HIGH`. `LOW` rows stay out of supervised training.

## What a model records about its parent

```json
{
  "model_version": "risk-logreg-v2",
  "parent_model": "risk-logreg-v1",
  "dataset_version": "dataset-v2",
  "feature_schema_version": 1,
  "training_job": "b075b91ee2eff95b",
  "created_at": "…",
  "sha256": "…"
}
```

The training job id ties the model back to the exact library versions, seed and
dataset hash that produced it.

## Model versions are immutable too

```text
risk-logreg-v1  ->  risk-logreg-v2
```

Never an overwrite of `risk-logreg-v1.onnx`. The registry enforces this: a
version directory that already exists cannot be written again.

## The feature schema lock

Every dataset and every model states its `feature_schema_version`.

If the feature schema changes, that is **not** ordinary retraining. It is a new
model family, and it needs a compatibility review. A model trained against a
different feature order would read one number as another, confidently, forever.
The registry refuses a model whose feature order does not match the build.

## The two dataset formats in this repository

This repository carries two column contracts, from different stages:

| Format | Columns | Labels | Used by |
| --- | --- | --- | --- |
| `training.dataset` | 32 | numeric (0/1) | the baseline trainer |
| `dataset.schema` | 37 | strings | the dataset package, and P9 candidates |

`training/bridge.py` converts the newer format to the older one so a candidate
dataset can reach the trainer. The conversion is a documented projection: it drops
five metadata columns the trainer has no field for, converts labels rather than
deriving them, and refuses to let uncertain or unlabelled rows cross at all. The
manifest it writes records what was dropped.

This seam is worth knowing about. Unifying the two contracts would be a better
answer than bridging them, and it has not been done.

## Answering the audit questions

For any candidate, these are answerable from the recorded lineage alone:

* **What data trained this model?** the dataset version and its hash
* **What changed from the active model?** the parent dataset and the new rows
* **Which features were used?** the model feature list in the manifest
* **What improved and what got worse?** the evaluation report beside the model
* **Why is promotion recommended?** the gate result and its per-check details

## Related

* [DATASET.md](DATASET.md) — how datasets are built
* [MODEL_REGISTRY.md](MODEL_REGISTRY.md) — how versions are stored
* [TRAINING_JOBS.md](TRAINING_JOBS.md) — reproducibility metadata
* [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md) — the feature contract
