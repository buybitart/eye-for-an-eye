# Autonomous Data Curation

How data becomes a dataset without a person approving each row, and the rules
that make that safe.

## The Pipeline

```
ingest
  -> schema validation
  -> type validation
  -> finite-value validation
  -> deduplication
  -> near-duplicate analysis
  -> missingness analysis
  -> outlier analysis
  -> provenance validation
  -> leakage checks
  -> source concentration
  -> scenario diversity
  -> immutable dataset candidate
```

Nothing in this pipeline trains, promotes or deletes anything. It produces a
candidate dataset and a report, and a candidate that fails a gate is refused,
which is the safe outcome, not a setback.

## The Data Dictionary

`datasets/model_features_v1.json` is the machine-readable dictionary, generated
from `dataset/schema.py` rather than maintained by hand. Every column carries:

| Field | Meaning |
| --- | --- |
| `name`, `index`, `tensor_index` | identity and position in the 36-column tensor |
| `kind` | `behaviour` or `availability_mask` |
| `units` | what the number counts |
| `window_seconds` | the observation window it summarises |
| `raw_ceiling`, `transform` | the bound and the normalisation applied |
| `feature_family` | which evidence family it contributes to at decision time |
| `privacy` | `behavioural_aggregate`, `availability_mask`, or `identity_or_decision` |
| `source` | where the value comes from |
| `model_usage` | `input`, `excluded`, or `never` |
| `reason_for_inclusion` | why it is there |

`never_model_input` is the list that matters most. It names every column a model
may never see, with the reason: addresses, ASN, country, domain, source and
capture groups, scenario identifiers, labels, and every decision this system
itself made: `blocked`, `block_status`, `would_block`, `final_risk`,
`math_score`, `ml_score`, `previous_risk`.

## Trusted Labels, and Only Trusted Labels

A supervised label may come from four places:

- a controlled lab scenario whose definition establishes the class
- a verified, signed PCAP sidecar label
- a deterministic test-harness outcome
- a person answering a review-queue entry

That is the whole list, and each entry has a documented reason the label is
trustworthy. Everything else is unlabelled, which is a first-class state and the
common one in production.

**Forbidden as label sources, permanently:** `blocked`, `automatically_blocked`,
`shadow_decision`, `model_score`, `math_score`, `risk_threshold`, `firewall`,
`previous_model`, `self_labelled`. A dataset row carrying one of these cannot be
constructed. The schema refuses it before any quality gate is consulted.

A strong heuristic is still a heuristic. It does not become ground truth by
performing well.

## Autonomy Without New Labels

The runtime operates autonomously even when no new trusted labels arrive. This
is **not** solved by pseudo-labelling its own decisions. Unlabelled production
data feeds the things that do not need a label:

- drift detection
- OOD scoring
- anomaly baseline candidates
- distribution monitoring
- feature health
- candidate evaluation where ground truth is not required

Supervised retraining needs trustworthy labels. If none arrive for six months,
the system keeps running on the validated model it has, plus MathRisk, anomaly,
OOD, drift, the local baseline and the cost model. **Model age alone is not a
reason to replace anything**: health, drift, OOD and trusted performance
evidence are.

The review queue stays available for diagnostics, and the runtime never waits on
it. Unreviewed samples remain unlabelled.

## Model Collapse

Lineage is tracked and provenance shares are bounded, because a dataset that is
mostly the previous model's own output teaches the next model to agree with the
last one.

| Limit | Default |
| --- | --- |
| new observed rows as a share of a candidate | 25% |
| rows one pseudonymous source may contribute | 25 |
| share of new rows any single source may account for | 10% |
| distinct sources the new rows must come from | 10 |
| one group as a share of the whole dataset | 25% blocking, 10% warning |

A candidate dominated by one group fails the quality gate. So does one with no
rows of a class, or a smaller class below 10% of the data.

## Synthetic Data

Allowed, and never hidden. Synthetic rows are purposeful, versioned,
scenario-defined, marked as synthetic, and evaluated separately. The synthetic
fraction is recorded in the manifest, and sanitised real captures and reviewed
shadow evaluation are preserved rather than replaced by generated data.

## Leakage

Critical tests prevent all of:

- scaling or imputing across the whole dataset before the split
- selecting features using test labels
- calibrating on test data
- tuning a threshold on test data
- using a previous decision as a feature
- future-window information in a current FeatureVector

Security traffic is temporal: a future event must never contribute to an earlier
decision's features. Splits are grouped by source, scenario, capture, site and
time so that correlated rows never straddle the boundary, and exact or near
duplicates are controlled across splits.

## Class Imbalance

Malicious automation is the rare class, and it is treated as one. Any resampling
happens on the **training split only**; validation and test keep realistic
prevalence, because a metric measured on an artificially balanced set describes a
world that does not exist. Class and sample weighting is preferred over invented
rows, and weights are recorded in the training manifest.

SMOTE is not enabled by default. Synthesising minority-class points in a
heavy-tailed feature space invents behaviour nobody observed.

## Pipeline Parity

There is exactly one FeatureVector implementation. `dataset/schema.py` reuses
`eye_for_an_eye.decision.features` and never restates a formula, so a dataset row
and a runtime tensor cannot drift apart. There is no notebook-only preprocessing
step anywhere in this project.

## Multiple Testing

Feature screening across many columns produces small p-values by chance. This
project does not select runtime behaviour from raw per-feature significance
tests, and no blocking decision depends on one. Where many tests are run, false
discovery is controlled or the results are treated as descriptive.

Correlated features are audited and reported, and (crucially) they cannot
manufacture evidence diversity: correlated columns share a family, and a family
contributes once.

## The Catalogue

Local metadata, no cloud anything:

| What | Where |
| --- | --- |
| datasets | `datasets/processed/`, `datasets/manifests/` |
| data card | `docs/DATA_CARD_v1.md` |
| feature dictionary | `datasets/model_features_v1.json` |
| statistics | `datasets/stats_v1.json` |
| models and manifests | the model registry (`registry.json` plus immutable version directories) |
| baselines | per-site baseline state |
| evaluation reports | `reports/` |

## See Also

- [DATASET.md](DATASET.md)
- [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md)
- [SELF_LEARNING.md](SELF_LEARNING.md)
- [MODEL_LINEAGE.md](MODEL_LINEAGE.md)
- [AUTONOMOUS_SAFETY_INVARIANTS.md](AUTONOMOUS_SAFETY_INVARIANTS.md)
