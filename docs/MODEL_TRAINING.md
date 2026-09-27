# Offline training and manual promotion

This page explains how a candidate risk model is trained and checked. Training happens completely separately from the running service, and no script on this page turns a candidate into an active model by itself. It is for developers who want to build or update a candidate model.

## Nothing here changes what is currently running

No labelled real capture has ever been given to this project. Every dataset described on this page is synthetic — made-up, but carefully structured, test data. It is a reproducible **engineering** dataset, built to test the code, not a proof of real-world security performance.

Training always ends with a candidate file. A human must review it and manually copy it into place before it can be used, even in shadow mode (see [ONNX_MODEL.md](ONNX_MODEL.md)).

## The first research pass: dataset synthetic-behavior-v2

The dataset `synthetic-behavior-v2` was built with a fixed, repeatable generator seed pattern: `p7-v2:<scenario>:<trial>`. It has 16 scenarios times 18 source groups, giving 6534 feature snapshots (rows) in total.

Each label describes what the generator **meant** to simulate — it is never a record of a real, automatic block that actually happened.

The data is stored as JSONL (one JSON object per line). Each row has: `dataset_version`, `scenario_id`, `source_group`, `timestamp`, `split`, `label` (0 or 1), `label_source`, and the `FeatureVector` itself. Only the already-transformed `FeatureTransformer` output (the 0-to-1 numbers) is ever used for fitting a model — raw values never reach it directly.

The loader that reads this data enforces limits: 64 MiB maximum file size, 50,000 rows maximum, and 8,192 characters per row maximum. A single source group can never be split across training, validation, and test. These same limits and `FeatureVector` checks also apply to any external data someone else tries to load.

## How the data was split

All rows from one source stay together, and are assigned to a split using "trial number modulo 6": 4 of the 6 possible trial values go to training, 1 goes to validation, and 1 goes to test.

The "slow scan," "low-rate credentials," and "distributed sources" scenario families are test-only — the model never sees them during training.

Some scenario families do appear in more than one split. This is intentional **group separation** (the same individual source never crosses a split boundary) — it is not a claim that the splits come from completely separate real-world environments. Rows from the same source stay correlated with each other, because they came from the same source.

Row counts by split:

| Split | Benign rows | Attack rows |
|---|---:|---:|
| Training | 2304 | 1440 |
| Validation | 576 | 360 |
| Test | 576 | 1278 |

The test set was **not** rebalanced to make the classes equal. Its mix of benign and attack rows is a side effect of the generator, not an estimate of how common attacks are in a real deployment.

## A shortcut the team found, and fixed

An early version of the data generator accidentally made one signal — whether "deception" activity was involved — always match the label. This meant a model could get every answer right just by reading that one signal, without learning anything real about behaviour. This kind of accidental shortcut is a well-known trap in machine learning: a model can look accurate for the wrong reason.

This version of the generator was rejected before it was ever used to pick a real candidate model. Version 2 fixed the problem: both the benign and the malicious classes now include deception and non-deception cases, and both overlap in "continuation" behaviour, so a model actually has to learn a real pattern.

Automated tests now check that this specific shortcut does not come back, and separately check that no identity, label, or scenario column ever reaches a model's input. Other, still-undiscovered shortcuts remain possible — see the limitations noted in [MODEL_EVALUATION.md](MODEL_EVALUATION.md).

## Commands for the research pass (synthetic-behavior-v2)

`uv` is the Python package and command-runner tool this project uses. The `--frozen` flag means "use exactly the locked dependency versions; do not update anything."

```sh
uv sync --frozen --extra ml --extra ml-training
uv run --frozen python -m training.build_dataset --output /new/path/corpus.jsonl
uv run --frozen python -m training.train_baseline --dataset /new/path/corpus.jsonl --output /new/path/candidates
uv run --frozen python -m training.shadow_evaluate --dataset /new/path/corpus.jsonl --models /new/path/candidates --output /new/path/shadow.json
```

## How the two research candidates were trained

First, a `LogisticRegression` model: regularisation strength `C=1`, "balanced" class weights (to make up for the uneven benign/attack row counts), random seed `7`, and a maximum of 1000 training iterations.

Then a `GradientBoostingClassifier` model: 48 trees, a maximum depth of 2, at least 12 samples required per leaf, seed `7`, also with balanced sample weights.

The test data is never artificially resampled or rebalanced for either model. Both models share the exact same, fixed, external, deterministic normalisation step (`FeatureTransformer`) — there is no separate, hidden "scaler" that could behave differently between training and the running service.

Export uses ONNX opset 17 for the main operator set and `ai.onnx.ml` opset 3 for the machine-learning-specific operators, IR version 10, with the `zipmap=false` export option (see the [official exporter options](https://onnx.ai/sklearn-onnx/parameterized.html)). After export, the exported model's answers must match the original scikit-learn model's answers within 0.00001 (`1e-5`) on held-out rows, and the production loader code must accept the file without any errors. The raw training-library file format is never allowed anywhere near production.

## How a candidate is chosen

Candidates are selected in this order: first, the lowest false positive rate on the validation data; if there is a tie, the highest recall; if there is still a tie, the simpler logistic model is preferred over the more complex one. Test-set metrics are only measured and reported **after** a candidate has already been chosen — they are never used to help choose it.

An automatic **regression gate** never promotes a model on its own: if a new candidate's false positive rate is higher than the current model's, plus a tolerance (0 by default, meaning no increase at all is allowed), that candidate is not even eligible for manual review.

A small, fixed, 64-row labelled test set stays as a quick smoke check only — it is never a stand-in for the full validation dataset. Any new model needs independently labelled data, the same careful split rules described above, the ONNX checks above, a shadow replay (see [SHADOW_MODE.md](SHADOW_MODE.md)), and an explicit human review, before it goes anywhere further. Copying a new model file into place, and updating the configuration to point at it, only happens after that human review is done.

**None of the scripts described on this page activates a model by itself.**

## Baseline v1: risk-logreg-v1, trained on synthetic-behavior-v3

The research pass above produced the `research-v2` model files. The newer "v1 baseline" workflow replaces the older single JSONL file with a proper versioned dataset directory, an automatic dataset validator that runs before any model is fit, and separate commands for each step: build the dataset, validate it, train, replay in shadow mode, and evaluate.

```sh
uv sync --frozen --extra ml --extra ml-training
uv run --frozen python -m training.dataset --output datasets/synthetic-behavior-v3
uv run --frozen python -m training.validation --dataset datasets/synthetic-behavior-v3
uv run --frozen python -m training.train_logreg --dataset datasets/synthetic-behavior-v3 \
    --output-dir models
uv run --frozen python -m training.shadow_replay --dataset datasets/synthetic-behavior-v3 \
    --model-dir models --output models/risk-logreg-v1-shadow.json
uv run --frozen python -m training.evaluate_model --dataset datasets/synthetic-behavior-v3 \
    --model-dir models --output models/risk-logreg-v1-evaluation.json \
    --report reports/model-risk-logreg-v1.md --shadow models/risk-logreg-v1-shadow.json
```

Each of these 5 steps can be run entirely on its own — none of them depend on shared notebook state. The dataset builder and the model exporter both refuse to overwrite an existing output file: every run either creates new files, or fails cleanly, and nothing gets silently overwritten. `training.validation` exits with a non-zero error code if it finds a critical problem. `training.train_logreg` refuses to fit a model at all if validation found a critical problem, or if any source group appears in more than one split.

## The synthetic-behavior-v3 dataset

This dataset has 30 scenario families, in four kinds:

* ordinary benign behaviour,
* "hard negatives" — legitimate behaviour that looks suspicious, including the project's own vulnerability scanner,
* malicious automation,
* "hard positives" — hostile behaviour that tries to stay quiet.

It has 336 source sequences, producing 4464 prefix-window feature vectors (feature snapshots taken at different points along each sequence). Labels come only from the generator's own intent (`label_source = synthetic_scenario`); any label that would come from a real decision this system made is always rejected. A whole source sequence stays in one split, and four of the scenario families are test-only.

## How risk-logreg-v1 was trained

The model type is `LogisticRegression`, trained only on the frozen 34-column model contract described in [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md).

A grid search tried `C` values of 0.01, 0.1, 1.0, and 10.0, each combined with `class_weight` set to either "none" or "balanced," using L2 regularisation, the "lbfgs" solver, and random seed `20260909`.

The model is selected in this order: first, the best validation PR-AUC; if there is a tie, the best validation false positive rate at a threshold of 0.50; if there is still a tie, the more cautious (stronger) regularisation setting. Test labels are never used to help select the model.

No separate scaler (normalisation step) was fitted for this model. The shared `FeatureTransformer` already produces the runtime's `[0, 1]` number range, and adding a second normalisation step on top could let training and the real running system slowly drift apart from each other.

## From 34 columns back to 36, and reproducing the exact same file

Export takes the 34 fitted numbers and places them back into the full 36-column contract (see [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md)), filling the 2 excluded positions with a weight of exactly zero. It then measures the difference between the original scikit-learn model's answers and the exported ONNX file's answers ("parity"), on every held-out row, through the same production loader code the real service uses — and it fails the whole export if any difference is above 0.00001 (`1e-5`).

The ONNX conversion tool normally picks a random name for one of its internal graph parts. Here, that name is pinned (fixed) to the model's version string instead. This means: fitting the exact same data again produces a byte-for-byte identical file, and therefore the exact same SHA-256 hash, on the same locked software environment. The dataset builder is reproducible in the same way.

The manifest file (see [ONNX_MODEL.md](ONNX_MODEL.md)) records the measured metrics, the parity check result, `quality_gate_passed`, and `recommended_mode = shadow`.

## The result: it does not generalise, and the manifest says so

`risk-logreg-v1` separates the exact scenario families it saw **during training** almost perfectly: a test PR-AUC of 0.9949, and a false positive rate of 0.0 at a threshold of 0.90 — but only for families it has already seen.

On scenario families it has **never** seen before, the very same model does much worse: a PR-AUC of only 0.4181, and a false positive rate of 0.5774.

**Because of this gap, the quality gate fails — on purpose.** This is by design: the manifest is meant to say honestly that this model does not yet generalise well, not to hide that fact.

See the full write-up in [the model report](../reports/model-risk-logreg-v1.md) and [the model card](../models/MODEL_CARD_risk-logreg-v1.md).

**This artifact is shadow-only. No model is configured, promoted, or activated by any of these scripts.**

## What comes next

The next planned experiment is a Gradient Boosting candidate, trained on the exact same dataset version, the same split, the same feature contract, the same metrics, and the same thresholds as `risk-logreg-v1` — so the two candidates can be compared fairly.

## See also

* [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md) — the 34-column model contract used here.
* [ONNX_MODEL.md](ONNX_MODEL.md) — how a trained model is packaged and safely loaded.
* [MODEL_EVALUATION.md](MODEL_EVALUATION.md) — full measured results for these candidates.
* [DATASET.md](DATASET.md) — how the underlying datasets are structured and validated.
* [SHADOW_MODE.md](SHADOW_MODE.md) — running a trained candidate without enforcement.
* [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md) — how a trained model fits into the running pipeline.
* [DECISION_ENGINE.md](DECISION_ENGINE.md) — how a model's score is actually used in a decision.
