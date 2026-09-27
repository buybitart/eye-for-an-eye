# Model card: risk-logreg-v1

> **ENGINEERING BASELINE ONLY - NOT VALIDATED FOR PRODUCTION ENFORCEMENT.**
> Recommended deployment mode: **SHADOW ONLY**. Quality gate passed: **no**.

| field | value |
|---|---|
| model version | `risk-logreg-v1` |
| family | logistic regression, L2, C=10.0, `class_weight="balanced"`, seed 20260909 |
| artifact | `models/risk-logreg-v1.onnx`, 730 bytes |
| SHA-256 | `04c66d6e1f5375168bfe3f33f42e30601218c25672ec57651110fbb360375601` |
| manifest | `models/risk-logreg-v1.json` |
| feature schema | 1 (`eye_for_an_eye/decision/features.py`) |
| model feature contract | 1, 34 fitted columns of the frozen 36-column tensor |
| training data | `synthetic-behavior-v3`, locally generated, 4464 rows |
| output | `model_score` for `malicious_automation_like`, uncalibrated |
| report | [`reports/model-risk-logreg-v1.md`](../reports/model-risk-logreg-v1.md) |

## Purpose

A first local baseline for the ML side of the decision engine, and the reference every later
candidate is compared against on identical data, splits, feature contract, metrics and threshold
table. Its purpose is a trustworthy, reproducible experiment, not a high score.

## Intended use

- Shadow-mode scoring beside the independent mathematical risk model, for observation only.
- Offline comparison of future candidates (gradient boosting and others) under identical conditions.
- Engineering validation of the dataset, split, export, parity, manifest and adapter path.

## Not intended use

This model does **not**:

- identify a person, an operator or an organisation;
- determine the identity of an attacker;
- determine geographic identity, and it never sees country, ASN, provider or address;
- prove malicious intent, or that any attack occurred or succeeded;
- distinguish authorised from unauthorised automation - authorisation is not a behaviour;
- justify a permanent ban, an abuse report, an accusation or any statement about a third party;
- act as an enforcement authority. It emits a score; `DecisionFusion` and `PolicyGuard` decide.

`malicious_automation_like` means automation-like behaviour observed by this sensor in a bounded
window. It is a description of traffic shape, not a verdict about a source.

## Training data

Locally generated synthetic scenarios (`training/corpus.py`, `synthetic-behavior-v3`). No capture,
no live traffic, no Internet access, no downloaded dataset, no production traffic. 30 scenario
families across four kinds - ordinary benign, hard negatives (legitimate but hostile-looking),
malicious automation, and hard positives (hostile but quiet) - as 336 independent source sequences
turned into 4464 prefix-window feature vectors.

Labels come from generator intent and are recorded with `label_source = synthetic_scenario`. No
label is derived from a risk score, a fused decision, an action, or a firewall state; the dataset
loader rejects decision-derived label sources outright.

Splits keep whole source sequences together, and four families (`few_port_scan`,
`multi_burst_recon`, `service_discovery`, `owner_vulnerability_scanner`) are held out entirely for
test. Train 2776 rows / 208 sources, validation 694 / 52, test 994 / 76.

## Features

34 fitted columns: 17 behavioural values and their 17 availability masks. Two columns are excluded
from fitting and exported with coefficient exactly zero, so the frozen `float32 [1, 36]` runtime
contract is unchanged:

- `previous_risk` - autoregressive, derived from this system's own prior output;
- `available_previous_risk` - its mask.

No identity feature exists in the tensor: no address, numeric address, ASN, provider, country,
username or hostname. No decision-derived feature either: no prior action, block state, fused risk,
math score or previous model score. Feature schema 1 contains no TTL, IP-ID, TCP-timestamp or p0f
column, so no fingerprint-derived feature can dominate this model by construction.

Preprocessing is the shared `FeatureTransformer` used by the runtime. No fitted scaler exists, so
training and inference cannot drift into two different normalisations. Missing values keep an
explicit availability mask; unknown is never silently converted to an observed zero.

## Metrics

Measured once on the held-out test split, scored through the production ONNX adapter.

| metric | value |
|---|---|
| rows / positives / negatives | 994 / 488 / 506 |
| ROC-AUC | 0.8291 |
| PR-AUC | 0.6989 |
| Brier score | 0.1297 |
| precision @0.50 | 0.7990 |
| recall @0.50 | 0.9447 |
| false positive rate @0.50 | 0.2292 |
| block precision @0.90 | 0.8072 |
| false blocks per 1000 benign @0.90 | 191.7 |

The split that matters:

| subset | PR-AUC | FPR @0.90 |
|---|---|---|
| scenario families also seen in training | 0.9949 | 0.0000 |
| scenario families never seen in training | 0.4181 | 0.5774 |

The model separates behaviour it has already seen and does not generalise to behaviour it has not.
Validation cannot detect this, because validation shares families with train.

Scores are uncalibrated (expected calibration error 0.119 over 10 bins) and saturate near 0 and 1.
The manifest declares `score_semantics = uncalibrated_model_score`; treat the output as a score, not
a probability of maliciousness.

## False positives

116 at threshold 0.50, 97 at 0.90. 99% of the false positives at 0.90 come from one family,
`owner_vulnerability_scanner`: an authorised scan run by the system owner. This is not a modelling
defect. An authorised scan and an unauthorised scan look the same to a behavioural sensor; the
difference is authorisation, which is identity and policy. The control for it is the `PolicyGuard`
allowlist and management-network protection, not the model. `service_discovery`,
`deployment_probe`, `admin_diagnostic` and `software_updater` produce the same failure at lower
intensity. Excluding the authorised scanner, the false positive rate at 0.90 would be 0.0024; that
counterfactual is descriptive, not a deployment estimate.

Raising the threshold does not fix this. The false positives sit near 1.0, so every threshold from
0.50 to 0.98 keeps them.

## False negatives

27 at threshold 0.50, 82 at 0.90. They are the quiet cases: `few_port_scan` (small port set, long
gaps), `repeated_probe_bot` (rate resembling a monitoring agent), `low_rate_credentials`,
`randomized_port_scan` and `credential_automation` early in a sequence. Moving towards a stricter
threshold trades a large amount of recall for almost no reduction in false positives.

## Known limitations

- Synthetic training and evaluation data. Nothing here estimates real-world accuracy or prevalence.
- Test prevalence is a generator artefact and cannot estimate deployment prevalence.
- Rows within a source are correlated prefix windows; the effective sample size is 336 sequences.
- Coefficients are not individually interpretable. `families_60s` carries a large negative weight
  although its marginal correlation with the label is positive, which is a correlated-column effect.
- `available_interarrival_cv_60s`, an availability mask, carries meaningful weight. It is nearly
  constant in this corpus, so that weight is a corpus artefact and not evidence about behaviour.
- `deception_60s` is engine-influenced: the sensor decides whether to answer, so the column partly
  measures our own behaviour. Ablation shows it is not load bearing.
- The selected `C=10.0` is the weakest regularisation in the grid, chosen on a validation split that
  shares scenario families with train.
- No PCAP replay corpus and no sanitised production shadow export existed to evaluate against.

## Bias and coverage concerns

- Coverage is limited to what the generator can express. Real environments contain automation this
  corpus does not model, and the unseen-family result suggests those would be scored badly.
- The corpus is close to class balanced. Real sensors are not, and precision at a fixed threshold
  falls as the positive rate falls.
- The model systematically scores legitimate operational tooling - scanners, discovery agents,
  deployment probes, administrator scripts - as automation-like, because it is automation. Any
  deployment must allowlist its own infrastructure rather than expect the model to recognise it.
- Windows are short and bounded, so quiet behaviour spread over hours is structurally invisible.
- No demographic, geographic or organisational attribute is available to the model, so it cannot
  be biased along those axes directly. It can still be biased against whoever runs noisy automation.

## Runtime requirements

CPU only, `onnxruntime` and `onnx`; no training library is needed for inference. The graph uses one
`LinearClassifier` node, opset ai.onnx 17 / ai.onnx.ml 3, IR 10. Input `features` float32 `[1, 36]`
in fixed order; outputs `label` int64 `[1]` and `probabilities` float32 `[1, 2]`, of which
production consumes the positive-class score. Measured on one Linux x86-64 machine: load 7.1 ms,
single inference p50 0.020 ms / p95 0.026 ms / p99 0.054 ms, about 47000 inferences per second.
Inference is per source per decision window, never per packet. A single measurement run is not a
performance guarantee.

## Security considerations

- Trained and exported entirely offline. No cloud training, no external API, no downloaded dataset.
- No raw payload, header bytes, credential material, cookie, username or arbitrary attacker string
  reaches the model. Only normalised structured features derived by the deterministic parser and
  correlation stage.
- The manifest carries the model SHA-256 and the runtime verifies it; the adapter also enforces the
  operator list, graph size, feature order, dtype, shape and finite bounded input, and rejects
  symlinks, oversized artifacts and world-writable files.
- The score is untrusted input to policy. `DecisionFusion` weights it by confidence and falls back
  to the independent mathematical model when the model is unavailable, degraded or disagreeing.
- Because the model cannot recognise authorisation, granting it enforcement authority would create
  a self-inflicted denial of service against the operator's own tooling.

## Recommended deployment mode

**SHADOW MODE.** Do not enable automatic firewall blocking from this score.

Shadow replay through the real fusion and policy path: the mathematical baseline alone would block
no source on this corpus; adding this model moves two sources past the block threshold, and both are
the authorised scanner family, giving a shadow block precision of 0.0. That is the direct evidence
for the recommendation.

The labelled lab captures replay cleanly through the whole chain - packets, deterministic parser,
correlation, `FeatureVector`, ONNX score, fusion, policy - with no traffic transmitted and no
firewall rule created. On the scanner capture the model scores 1.0 where the mathematical baseline
scores 0.20, and policy still holds the source at WATCH. That is an integration result on two tiny
synthetic captures, not accuracy evidence.

Promotion beyond shadow requires independent realistic labelled data, a capture-domain-independent
test split, block precision measured at the threshold policy would actually use, hard negatives from
the target environment, an operator-agreed false positive budget, ONNX parity and manifest
verification on the promoted artifact, and shadow replay in that environment that supports the
offline result. None of those conditions is met today.
