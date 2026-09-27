# Retraining

Eye for an Eye can build and test a new model from local data. It does **not**
replace the model it is using. A person does that.

Status: **Beta.** All threshold values are provisional.

## The short version

```text
Eye for an Eye can collect new local security data.
Only trusted labels can be used for supervised training.
The system can build and test a new model automatically.
The new model first runs in Shadow Mode.
It does not replace the active model automatically.
```

## What "retraining" means here

It does not mean this:

```text
new traffic  ->  retrain  ->  deploy
```

It means this:

```text
new trusted evidence
  -> candidate dataset
  -> validation
  -> candidate model
  -> independent evaluation
  -> shadow comparison
  -> a recommendation for a person
```

The difference is where the traffic stops having influence. Traffic can put a
window in front of a person. It cannot become a label, and it cannot rewrite the
active model.

## Three separate authorities

| Authority | What it may do | Who has it |
| --- | --- | --- |
| Training | build a candidate | the system, when configured |
| Evaluation | say whether the candidate is good enough | the system |
| Deployment | change the active model | a person, with `--yes` |

These are kept apart on purpose. Merging them is the same as having none.

## Where labels come from

Allowed as ground truth:

* controlled lab scenarios, where the intent was decided before the traffic
* trusted labelled captures, where a sidecar file carries the label
* reviewed observed traffic, where a person answered a question

Never allowed as ground truth:

```text
a model score        a mathematical risk score
an anomaly score     an out-of-distribution score
the final decision   the block status
would_block          the previous model's output
```

These may sit beside a row as context for a reviewer. They are never the label
and never a model input. The dataset code refuses them: a row whose label source
is a decision this system made is rejected before it reaches training.

## When retraining is suggested

`eye-for-an-eye learning status` reads a few numbers and gives one of five
answers.

| Answer | Meaning |
| --- | --- |
| `SYSTEM_BUSY` | the machine is loaded or short of disk; defending comes first |
| `WAIT_COOLDOWN` | a model was trained recently; rebuilding now mostly repeats it |
| `COLLECT_MORE` | not enough reviewed labels, or from too few sources |
| `CONSIDER_RETRAINING` | there is enough new evidence to be worth your time |
| `NO_ACTION` | nothing to do |

Defaults: 200 new reviewed labels, at least 50 of each kind, from at least 20
sources, and 14 days since the last training run.

Drift and a high out-of-distribution rate appear as **reasons**, never as
triggers. A drifted population means the model knows less about current traffic
than it used to. It says nothing about who is sending the traffic, and on its own
it never recommends anything.

Time passing is not a reason to retrain.

## Anti-poisoning

Observed traffic is chosen by whoever sends it, so the pipeline assumes somebody
will try to shape it. Every limit below is a refusal, and every one is
configurable.

| Limit | Default | What it stops |
| --- | --- | --- |
| rows per source | 25 | one source dominating the new data |
| single-source share | 10% | the same, measured across the whole batch |
| rows per day | 200 | one busy day dominating |
| new rows per candidate | 1000 | an unbounded intake |
| new-row share | 25% | new observed data outweighing the trusted corpus |
| distinct sources | at least 10 | a batch that is really one point of view |
| identical behaviour | dropped | a flood of repeats counting many times |

The report says what was dropped and why. A dataset of 2000 offered rows that
produced 300 accepted rows says so out loud.

## Commands

```bash
eye-for-an-eye learning status                 # what the system thinks, and why
eye-for-an-eye review export --out labels.json # answered rows a person produced
eye-for-an-eye learning prepare \
    --parent-dataset dataset-v1 \
    --parent-rows datasets/processed/dataset-v1/samples.csv \
    --labels labels.json \
    --dataset-version dataset-v2-candidate \
    --out reports/dataset-v2-candidate.json
eye-for-an-eye learning train \
    --dataset <prepared dataset directory> \
    --model-version risk-logreg-v2 \
    --output-dir models/staging --yes
eye-for-an-eye learning jobs                   # what has been attempted
```

`learning train` needs `--yes`, and even with it the active model does not
change. Promotion is `model promote`, which is a different command with its own
confirmation.

There is no `learning promote`.

## Settings

```toml
[learning]
enabled = true
auto_prepare_dataset = false   # RESERVED - not honoured, see below
auto_train = false             # RESERVED - not honoured, see below
minimum_retraining_interval_days = 14
minimum_trusted_samples = 200
training_max_duration_seconds = 1800
training_max_memory_mb = 2048
training_max_parallel_jobs = 1
```

### `auto_prepare_dataset` and `auto_train` are reserved, not switches

Both names exist in `LearningConfig`, both default to `false`, and **no code path
reads either one to start anything**. `learning status` prints the configured
value of `auto_train` and says, in those words, that it is not honoured. Setting
either to `true` changes no behaviour in this release.

They are not deleted because their eventual meaning is already fixed -- build a
candidate dataset, train a candidate model, neither of which may ever promote one
-- and a later release that wires them up must not silently inherit a value an
operator set expecting something else.

If you want a candidate dataset or a candidate model today, you run the command
yourself. That is the whole design, and it is why there is no `auto_promote`
setting at all: a name that does not exist cannot be set by accident.

`auto_promote` is not in this list, and not anywhere else. There is no setting
that makes a candidate become the active model.

## Why promotion stays manual

Because everything upstream of it can be wrong.

* A training pipeline can be poisoned.
* Labels can be wrong; a person reading a behaviour summary is doing their best.
* Traffic changes, so a model that measured well last month may not now.
* A candidate can look good offline and fail in production.

None of these is unlikely. Together they mean the last step should cost somebody
thirty seconds of attention.

## Known limits

* The provisional thresholds throughout this document are starting points. No
  measured deployment data supports them yet.
* Only logistic regression can be trained in this build. Gradient boosting is
  named in the configuration vocabulary but has no trainer; asking for it returns
  an error rather than a silent substitution.
* Automatic dataset preparation and automatic training are implemented as
  settings and commands. They are off by default and have not been exercised over
  a long deployment.

## Related

* [SELF_LEARNING.md](SELF_LEARNING.md) — what this project does and does not learn
* [REVIEW_QUEUE.md](REVIEW_QUEUE.md) — where labels come from
* [TRAINING_JOBS.md](TRAINING_JOBS.md) — how a training run is bounded
* [MODEL_PROMOTION.md](MODEL_PROMOTION.md) — the manual last step
