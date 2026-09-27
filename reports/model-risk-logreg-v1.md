# Model Report: risk-logreg-v1

> **ENGINEERING BASELINE ONLY. NOT VALIDATED FOR PRODUCTION ENFORCEMENT.**
>
> The corpus is locally generated synthetic behaviour. Every number below describes that corpus and
> nothing else. None of it estimates deployment accuracy, prevalence or risk.
> Recommended deployment mode: **SHADOW ONLY**.
> Quality gate passed: **no**.

## 1. Purpose

Build a reproducible training, evaluation and export pipeline, and a first local ONNX baseline that later candidates can be compared against on identical data, splits, features, metrics and thresholds. The purpose is a trustworthy experiment, not a high score.

## 2. Dataset

| field | value |
|---|---|
| version | synthetic-behavior-v3 |
| content hash | `7162949bc533b7cd0f5974fe6c4e160613388c2d6ea3d45b8f7252c53dcdf005` |
| source | locally generated synthetic scenarios; no capture, no live traffic, no Internet |
| label source | generator intent (`synthetic_scenario`); never a risk score, action or firewall state |
| label schema | 0 = benign_like, 1 = malicious_automation_like |
| rows | 4464 |
| source groups | 336 |
| scenario families | 30 |
| seed | 20260909 |

`malicious_automation_like` means automation-like behaviour observed by this sensor. It is not a claim that a person attacked anything, that an attack succeeded, or that the source is hostile.

### Dataset Limitations

- synthetic sequences cannot represent real traffic distributions, noise or adversarial adaptation
- test prevalence is a generator artefact and cannot estimate deployment prevalence
- rows from one source are prefix windows of one sequence and are strongly correlated
- four scenario families are test-only, so the test split is deliberately harder than validation
- no labelled capture, PCAP corpus or reviewed production sample was available

Validator warnings:

- 4 near-duplicate vectors cross the train boundary
- constant columns carry no evidence in this corpus: available_connections_10s, available_connections_60s, available_connections_900s, available_ports_60s, available_ports_900s, available_destinations_60s, available_sequential_60s, available_persistence_900s, available_burst_10s, available_interarrival_mean_60s, available_deception_60s
- documented ceiling clipping above 5% of rows: persistence_900s

## 3. Feature Schema and Model Contract

| field | value |
|---|---|
| feature schema version | 1 |
| model feature contract version | 1 |
| runtime tensor | `features` float32 [1, 36], fixed order from `decision.features.INPUT_ORDER` |
| fitted columns | 34 of 36 |
| excluded columns | `previous_risk`, `available_previous_risk` |
| preprocessing | eye_for_an_eye.decision.features.FeatureTransformer only; no fitted scaler, because the transformer already emits the float32 [0,1] runtime contract |
| missing values | explicit availability mask per column; unknown never becomes an observed zero |
| range contract | every transformed column in [0, 1]; violations fail validation, nothing is silently clipped |

Exclusion rationale:

- `previous_risk`: autoregressive: decayed output of this system, not an observation
- `available_previous_risk`: availability mask of an excluded autoregressive column

No identity column reaches the model: no address, numeric address, ASN, provider, country, username or hostname exists in the tensor. No decision-derived column reaches it either: no prior action, block state, fused risk, math score or earlier model score. Feature schema 1 contains no TTL, IP-ID, TCP-timestamp or p0f column, so no fingerprint-derived feature can dominate v1 by construction.

Zero-weight verification in the exported graph: `previous_risk` = 0.0, `available_previous_risk` = 0.0.

## 4. Split Method and Leakage Checks

Whole source sequences are the split unit. A row-level random split would place prefix windows of the same simulated source in both train and test and inflate every metric. Four scenario families are additionally held out entirely for test, to measure behaviour never seen while fitting.

| split | rows | sources | families | benign_like | malicious_automation_like | benign % | positive % |
|---|---|---|---|---|---|---|---|
| train | 2776 | 208 | 26 | 1352 | 1424 | 48.7 | 51.3 |
| validation | 694 | 52 | 26 | 338 | 356 | 48.7 | 51.3 |
| test | 994 | 76 | 30 | 506 | 488 | 50.9 | 49.1 |

| check | result |
|---|---|
| source groups in more than one split | 0 |
| identical vectors crossing the train boundary | 0 |
| near-duplicate vectors crossing the train boundary | 4 |
| exact duplicate rows in the corpus | 0 |
| test-only scenario families | few_port_scan, multi_burst_recon, owner_vulnerability_scanner, service_discovery |
| chronological split | only when the dataset comes from a single real temporal stream |

Group separation is a failing test, not a warning: `training.split.assert_group_separation` raises `LeakageError` and `tests/test_p8_training_split.py` asserts it.

## 5. Hyperparameters and Selection

| field | value |
|---|---|
| family | logistic regression |
| penalty / solver | l2 (l1_ratio=0) / lbfgs |
| C grid | 0.01, 0.1, 1.0, 10.0 |
| class weight grid | none, balanced |
| max_iter | 5000 |
| seed | 20260909 |
| selected | C=10.0, class_weight=balanced, converged in 81 iterations |
| selection rule | highest validation PR-AUC, then lowest validation FPR at 0.50, then strongest regularisation; test labels are never used for selection |

| C | class weight | val PR-AUC | val ROC-AUC | val FPR @0.50 | val recall @0.50 | val block precision @0.90 |
|---|---|---|---|---|---|---|
| 0.01 | none | 0.9662 | 0.9578 | 0.0118 | 0.7612 | 1.0000 |
| 0.1 | none | 0.9854 | 0.9824 | 0.0325 | 0.8483 | 1.0000 |
| 1.0 | none | 0.9946 | 0.9940 | 0.0207 | 0.9129 | 1.0000 |
| 10.0 | none | 0.9974 | 0.9970 | 0.0148 | 0.9522 | 1.0000 |
| 0.01 | balanced | 0.9661 | 0.9577 | 0.0000 | 0.7472 | 1.0000 |
| 0.1 | balanced | 0.9854 | 0.9824 | 0.0266 | 0.8427 | 1.0000 |
| 1.0 | balanced | 0.9947 | 0.9941 | 0.0178 | 0.9073 | 1.0000 |
| 10.0 | balanced | 0.9974 | 0.9970 | 0.0148 | 0.9466 | 1.0000 |

Class balance is close to even in this corpus, so `class_weight="balanced"` changed little. No resampling and no SMOTE was applied; the comparison was made on validation, not assumed.

## 6. Locked Test Metrics

Computed once, after selection, from scores produced by the production ONNX adapter.

| metric | value |
|---|---|
| rows / positives / negatives | 994 / 488 / 506 |
| precision @0.50 | 0.7990 |
| recall @0.50 | 0.9447 |
| F1 @0.50 | 0.8657 |
| false positive rate @0.50 | 0.2292 |
| false negative rate @0.50 | 0.0553 |
| specificity @0.50 | 0.7708 |
| accuracy @0.50 | 0.8561 |
| ROC-AUC | 0.8291 |
| PR-AUC | 0.6989 |
| Brier score | 0.1297 |

Accuracy is reported because it was asked for, not because it is informative: the corpus is near balanced by construction, which flatters it.

### Confusion Matrix at 0.50

|  | predicted benign_like | predicted malicious_automation_like |
|---|---|---|
| **actual benign_like** | 390 | 116 |
| **actual malicious_automation_like** | 27 | 461 |

### Generalisation to Unseen Scenario Families

| subset | rows | PR-AUC | ROC-AUC | FPR @0.90 | recall @0.90 | families |
|---|---|---|---|---|---|---|
| unseen_scenario_families | 300 | 0.4181 | 0.5171 | 0.5774 | 0.8258 | few_port_scan, multi_burst_recon, owner_vulnerability_scanner, service_discovery |
| seen_scenario_families | 694 | 0.9949 | 0.9936 | 0.0000 | 0.8343 | admin_diagnostic, backup_client, bursty_recon, cdn_origin_fetch, credential_automation, deception_prober, deployment_probe, flaky_client, health_checker, horizontal_scan, human_manual_access, interactive_ssh, load_balancer, low_rate_credentials, mobile_app_client, monitoring_agent, paced_random_scan, protocol_mismatch_probe, randomized_port_scan, repeated_probe_bot, reverse_proxy, sequential_port_scan, service_enumeration, slow_sequential_scan, software_updater, web_browser |

This is the most important table in the report. Within families the model already saw, separation is near perfect; on families it never saw, it is close to unusable. Validation cannot detect this, because validation shares families with train.

## 7. Threshold Evaluation

The model returns a score. It does not select an action. `DecisionFusion` and `PolicyGuard` decide, and a WATCH threshold may be far lower than a TEMP_BLOCK threshold.

| threshold | precision | recall | FPR | FNR | block precision | false blocks / 1000 benign | positive decisions |
|---|---|---|---|---|---|---|---|
| 0.50 | 0.7990 | 0.9447 | 0.2292 | 0.0553 | 0.7990 | 229.2 | 577 |
| 0.60 | 0.8085 | 0.9344 | 0.2134 | 0.0656 | 0.8085 | 213.4 | 564 |
| 0.70 | 0.8103 | 0.9016 | 0.2036 | 0.0984 | 0.8103 | 203.6 | 543 |
| 0.75 | 0.8118 | 0.8750 | 0.1957 | 0.1250 | 0.8118 | 195.7 | 526 |
| 0.80 | 0.8108 | 0.8607 | 0.1937 | 0.1393 | 0.8108 | 193.7 | 518 |
| 0.85 | 0.8098 | 0.8463 | 0.1917 | 0.1537 | 0.8098 | 191.7 | 510 |
| 0.90 | 0.8072 | 0.8320 | 0.1917 | 0.1680 | 0.8072 | 191.7 | 503 |
| 0.95 | 0.8016 | 0.8033 | 0.1917 | 0.1967 | 0.8016 | 191.7 | 489 |
| 0.98 | 0.7927 | 0.7520 | 0.1897 | 0.2480 | 0.7927 | 189.7 | 463 |

Raising the threshold barely moves the false positive rate: the false positives are saturated near 1.0, so they survive every threshold in the table. At 0.90, 97 of 506 benign rows are flagged and 0.990 of them come from `owner_vulnerability_scanner`; excluding that one family the rate would be 0.0024. That counterfactual is descriptive only.

## 8. Score Distribution

| class | count | min | median | mean | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|---|
| benign_like | 506 | 0.0000 | 0.0489 | 0.2725 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| malicious_automation_like | 488 | 0.0169 | 0.9997 | 0.9262 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## 9. Calibration

Brier score 0.1297, expected calibration error over 10 bins 0.1194. The output is reported as `model_score` and the manifest declares `score_semantics = uncalibrated_model_score`. No calibrator was fitted: the corpus is small and synthetic, so a calibration curve learned from it would describe the generator.

| bin | count | mean score | observed positive fraction |
|---|---|---|---|
| 0.0-0.1 | 306 | 0.0280 | 0.0131 |
| 0.1-0.2 | 43 | 0.1369 | 0.0465 |
| 0.2-0.3 | 23 | 0.2567 | 0.1304 |
| 0.3-0.4 | 30 | 0.3451 | 0.2667 |
| 0.4-0.5 | 15 | 0.4399 | 0.6667 |
| 0.5-0.6 | 13 | 0.5470 | 0.3846 |
| 0.6-0.7 | 21 | 0.6569 | 0.7619 |
| 0.7-0.8 | 25 | 0.7381 | 0.8000 |
| 0.8-0.9 | 15 | 0.8514 | 0.9333 |
| 0.9-1.0 | 503 | 0.9950 | 0.8072 |

## 10. Coefficients

Intercept -1.8801.

| feature | coefficient | absolute importance | direction |
|---|---|---|---|
| `anomaly_60s` | 18.383 | 18.383 | towards_malicious_automation_like |
| `ports_900s` | 11.575 | 11.575 | towards_malicious_automation_like |
| `deception_60s` | 11.270 | 11.270 | towards_malicious_automation_like |
| `sequential_60s` | 11.033 | 11.033 | towards_malicious_automation_like |
| `families_60s` | -10.278 | 10.278 | towards_benign_like |
| `ports_60s` | 8.884 | 8.884 | towards_malicious_automation_like |
| `credentials_60s` | 8.229 | 8.229 | towards_malicious_automation_like |
| `interarrival_mean_60s` | 7.905 | 7.905 | towards_malicious_automation_like |
| `available_interarrival_cv_60s` | 6.312 | 6.312 | towards_malicious_automation_like |
| `connections_10s` | 5.820 | 5.820 | towards_malicious_automation_like |
| `destinations_60s` | 4.943 | 4.943 | towards_malicious_automation_like |
| `connections_60s` | -3.711 | 3.711 | towards_benign_like |
| `repetition_60s` | -3.377 | 3.377 | towards_benign_like |
| `continuation_60s` | -2.540 | 2.540 | towards_benign_like |
| `persistence_900s` | -1.986 | 1.986 | towards_benign_like |
| `interarrival_cv_60s` | 1.353 | 1.353 | towards_malicious_automation_like |

### Coefficient Sanity Review

- `anomaly_60s`, `ports_900s`, `ports_60s`, `sequential_60s` and `credentials_60s` pushing towards the positive class is behaviourally plausible: port breadth, sequential ordering, protocol mismatch and repeated credential prompts are what automated probing looks like to this sensor.
- `families_60s` carries a large **negative** coefficient while its marginal correlation with the label is positive. A sign flip against the marginal direction means correlated columns are redistributing weight, not that protocol diversity indicates benign traffic. Individual coefficients here are not standalone evidence.
- `available_interarrival_cv_60s` carries meaningful positive weight. It is an availability mask, not a behaviour, and it is nearly constant in this corpus, so that weight is a corpus artefact.
- `deception_60s` is engine-influenced: the sensor decides whether to answer, so it partly measures our own behaviour. The ablation below shows it is not load bearing.
- Strong separation on seen families does not make the coefficients trustworthy. The unseen-family result in section 6 is the counter-evidence.

## 11. Feature Ablation

| variant | features | val PR-AUC | val ROC-AUC | val FPR @0.50 |
|---|---|---|---|---|
| all_model_features | 34 | 0.9974 | 0.9970 | 0.0148 |
| behaviour_only_no_masks | 17 | 0.9954 | 0.9951 | 0.0207 |
| no_engine_influenced_deception | 32 | 0.9962 | 0.9958 | 0.0207 |

Behaviour columns alone carry almost all of the separation, and removing the engine-influenced deception counter changes little. Feature schema 1 has no fingerprint-derived column, so the fingerprint-domination question does not arise for v1; if such a column is ever added, this ablation is where it must be checked before the column is trusted.

## 12. False Positive Analysis

At threshold 0.50: 116 false positives; at 0.90: 97.

| scenario family | false positives @0.50 | false positives @0.90 |
|---|---|---|
| `admin_diagnostic` | 4 | 0 |
| `deployment_probe` | 5 | 0 |
| `owner_vulnerability_scanner` | 96 | 96 |
| `service_discovery` | 8 | 1 |
| `software_updater` | 3 | 0 |

Strongest examples, features only and never payload:

- `owner_vulnerability_scanner` score 1.000, 12 observations over 2.44s - `anomaly_60s`=0.67 (+12.26), `sequential_60s`=1.00 (+11.03), `families_60s`=0.75 (-7.71), `available_interarrival_cv_60s`=1.00 (+6.31)
- `owner_vulnerability_scanner` score 1.000, 18 observations over 3.72s - `anomaly_60s`=0.72 (+13.28), `sequential_60s`=1.00 (+11.03), `families_60s`=0.75 (-7.71), `available_interarrival_cv_60s`=1.00 (+6.31)
- `owner_vulnerability_scanner` score 1.000, 24 observations over 5.19s - `anomaly_60s`=0.71 (+13.02), `sequential_60s`=1.00 (+11.03), `families_60s`=0.75 (-7.71), `available_interarrival_cv_60s`=1.00 (+6.31)
- `owner_vulnerability_scanner` score 1.000, 30 observations over 6.44s - `anomaly_60s`=0.63 (+11.64), `sequential_60s`=1.00 (+11.03), `families_60s`=0.75 (-7.71), `available_interarrival_cv_60s`=1.00 (+6.31)
- `owner_vulnerability_scanner` score 1.000, 36 observations over 7.65s - `sequential_60s`=1.00 (+11.03), `anomaly_60s`=0.58 (+10.72), `families_60s`=0.75 (-7.71), `available_interarrival_cv_60s`=1.00 (+6.31)
- `owner_vulnerability_scanner` score 1.000, 42 observations over 8.93s - `sequential_60s`=1.00 (+11.03), `anomaly_60s`=0.57 (+10.50), `families_60s`=0.75 (-7.71), `available_interarrival_cv_60s`=1.00 (+6.31)

`owner_vulnerability_scanner` is the dominant false positive and it is not a modelling defect. An authorised scan and an unauthorised scan produce the same behaviour; the difference is authorisation, which is an identity and policy fact. The correct control is the `PolicyGuard` allowlist, not a behavioural model. `service_discovery`, `deployment_probe` and `admin_diagnostic` fail the same way at lower intensity.

## 13. False Negative Analysis

At threshold 0.50: 27 false negatives; at 0.90: 82.

| scenario family | missed @0.50 | missed @0.90 |
|---|---|---|
| `credential_automation` | 2 | 4 |
| `deception_prober` | 1 | 2 |
| `few_port_scan` | 11 | 23 |
| `horizontal_scan` | 0 | 1 |
| `low_rate_credentials` | 2 | 16 |
| `paced_random_scan` | 0 | 3 |
| `randomized_port_scan` | 3 | 3 |
| `repeated_probe_bot` | 8 | 29 |
| `service_enumeration` | 0 | 1 |

The misses are exactly the quiet cases: small port sets, long gaps between probes, low-rate credential attempts, and repeated-probe bots whose rate resembles a monitoring agent. Moving the threshold to 0.90 makes this substantially worse while barely improving the false positive rate.

## 14. Per-scenario Behaviour on Test

| scenario family | label | rows | flagged @0.50 | median score | max score |
|---|---|---|---|---|---|
| `admin_diagnostic` | 0 | 20 | 0.20 | 0.234 | 0.686 |
| `backup_client` | 0 | 24 | 0.00 | 0.006 | 0.179 |
| `bursty_recon` | 1 | 32 | 1.00 | 1.000 | 1.000 |
| `cdn_origin_fetch` | 0 | 32 | 0.00 | 0.028 | 0.095 |
| `credential_automation` | 1 | 32 | 0.94 | 0.996 | 0.998 |
| `deception_prober` | 1 | 28 | 0.96 | 0.998 | 1.000 |
| `deployment_probe` | 0 | 24 | 0.21 | 0.087 | 0.731 |
| `few_port_scan` | 1 | 60 | 0.82 | 0.967 | 1.000 |
| `flaky_client` | 0 | 24 | 0.00 | 0.067 | 0.319 |
| `health_checker` | 0 | 32 | 0.00 | 0.027 | 0.144 |
| `horizontal_scan` | 1 | 32 | 1.00 | 0.997 | 1.000 |
| `human_manual_access` | 0 | 16 | 0.00 | 0.010 | 0.468 |
| `interactive_ssh` | 0 | 20 | 0.00 | 0.053 | 0.312 |
| `load_balancer` | 0 | 32 | 0.00 | 0.006 | 0.011 |
| `low_rate_credentials` | 1 | 20 | 0.90 | 0.729 | 0.998 |
| `mobile_app_client` | 0 | 24 | 0.00 | 0.048 | 0.109 |
| `monitoring_agent` | 0 | 24 | 0.00 | 0.009 | 0.090 |
| `multi_burst_recon` | 1 | 72 | 1.00 | 1.000 | 1.000 |
| `owner_vulnerability_scanner` | 0 | 96 | 1.00 | 1.000 | 1.000 |
| `paced_random_scan` | 1 | 24 | 1.00 | 0.999 | 1.000 |
| `protocol_mismatch_probe` | 1 | 32 | 1.00 | 1.000 | 1.000 |
| `randomized_port_scan` | 1 | 32 | 0.91 | 1.000 | 1.000 |
| `repeated_probe_bot` | 1 | 32 | 0.75 | 0.675 | 0.995 |
| `reverse_proxy` | 0 | 32 | 0.00 | 0.032 | 0.061 |
| `sequential_port_scan` | 1 | 32 | 1.00 | 1.000 | 1.000 |
| `service_discovery` | 0 | 72 | 0.11 | 0.242 | 0.970 |
| `service_enumeration` | 1 | 28 | 1.00 | 0.984 | 0.996 |
| `slow_sequential_scan` | 1 | 32 | 1.00 | 1.000 | 1.000 |
| `software_updater` | 0 | 14 | 0.21 | 0.000 | 0.846 |
| `web_browser` | 0 | 20 | 0.00 | 0.027 | 0.073 |

## 15. ONNX Export and Equivalence

| field | value |
|---|---|
| artifact | `risk-logreg-v1.onnx` |
| size | 730 bytes |
| SHA-256 | `04c66d6e1f5375168bfe3f33f42e30601218c25672ec57651110fbb360375601` |
| input | `features`, float32, shape [1, 36], fixed order |
| output | `label` int64 [1] and `probabilities` float32 [1, 2]; production consumes the positive-class score |
| opset | ai.onnx 17 / ai.onnx.ml 3, IR 10, zipmap disabled |
| reproducible bytes | yes; the converter graph name is pinned to the model version so an identical fit exports an identical file on the same locked environment |
| training vs runtime dtype | float64 vs float32 |
| parity rows | 994 |
| max absolute difference | 3.576e-07 |
| mean absolute difference | 3.589e-08 |
| tolerance | 1.0e-05 |
| parity passed | yes |
| coefficient widening error | 4.768e-07 |
| independent float64 recomputation error | 3.494e-07 |

Equality is not assumed to be bit exact: fitting runs in float64 and the runtime graph in float32, so the difference is measured on every held-out row and the export fails if it exceeds tolerance. The excluded columns are exported with coefficient exactly zero, which keeps the frozen [1, 36] runtime contract while the fitted model never saw them. The adapter also rejects a wrong feature count, a wrong schema version, a wrong tensor shape, non-finite input and a hash that does not match the manifest.

## 16. Inference Benchmark

| measurement | value |
|---|---|
| model load | 6.6 ms |
| single inference p50 / p95 / p99 | 0.019 ms / 0.033 ms / 0.046 ms |
| inferences per second | 46713 |
| process RSS | 184823808 bytes |

| batch size | rows per second | per-row ms |
|---|---|---|
| 1 | 46713 | 0.0194 |
| 8 | 88289 | 0.0113 |
| 16 | 132218 | 0.0076 |

offline measurement only; production keeps the strict [1,36] contract and one in-flight request per source. Inference is per source per decision window, never per packet. No performance target is asserted from a single measurement run on one machine.

## 17. Shadow Replay Through Fusion and Policy

Enforcement disabled, decision mode shadow, no firewall interaction and no packet transmitted.

| candidate | sources | would block sources | block precision | benign families that would block | disagreements |
|---|---|---|---|---|---|
| math_only | 76 | 0 | n/a | none | 0 |
| risk-logreg-v1 | 76 | 2 | 0.0000 | owner_vulnerability_scanner | 12 |

The mathematical baseline alone would block nothing on this corpus. Adding the model score to fusion moves sources past the block threshold, and they are the authorised scanner family, so shadow block precision is 0. On this evidence the model must not gain enforcement authority.

### Disagreements Kept for Investigation


**math_low_ml_high**

| scenario family | label | math score | model score | fused risk | action |
|---|---|---|---|---|---|
| `bursty_recon` | 1 | 0.182 | 1.000 | 0.450 | WATCH |
| `credential_automation` | 1 | 0.179 | 0.872 | 0.343 | OBSERVE |
| `deception_prober` | 1 | 0.122 | 0.912 | 0.341 | OBSERVE |
| `deception_prober` | 1 | 0.121 | 0.939 | 0.364 | OBSERVE |
| `deception_prober` | 1 | 0.142 | 0.990 | 0.423 | WATCH |
| `deception_prober` | 1 | 0.139 | 0.994 | 0.426 | WATCH |
| `deception_prober` | 1 | 0.141 | 0.998 | 0.432 | WATCH |
| `deception_prober` | 1 | 0.145 | 0.999 | 0.437 | WATCH |

The model is consistently more aggressive than the mathematical baseline, mostly on true positives, which is where its value would be. `PolicyGuard` holds almost all of it at WATCH or OBSERVE through the data-quality, minimum-sample and math-confirmation gates. Cases in the other direction (math high, model low) are worth investigating whenever they appear.

## 18. Offline PCAP Replay

Captures are read from disk through the existing offline analysis path and never retransmitted; enrichment, active probes, firewall and enforcement are refused by that path. The corpus labels belong to the correlation label space, not the model label space, so they are reported beside the decisions and never scored against them.

| sample | packets | correlation label | decisions | math score | model score | fused risk | action | would enforce | disagreement |
|---|---|---|---|---|---|---|---|---|---|
| scan | 32 | 192.0.2.1@60s=scanner, 192.0.2.1@900s=scanner | 16 | 0.197 | 1.000 | 0.469 | WATCH | no | math_low_ml_high |
| noise | 1 | 192.0.2.1@60s=noise, 192.0.2.1@900s=noise | 1 | 0.020 | 0.004 | 0.012 | OBSERVE | no | none |

The corpus is two tiny deterministic synthetic captures, so this is an integration result and not accuracy evidence. What it does show is that the whole chain runs: packets to deterministic parser to correlation to FeatureVector to ONNX score to fusion to policy, with no enforcement and no transmitted traffic.

## 19. Quality Gate

Status **PROVISIONAL**. These thresholds are conservative starting candidates proposed for review. No measured deployment data supports them yet, and they must not be presented as established production targets.

| check | configured | measured | result |
|---|---|---|---|
| test FPR at reference block threshold | <= 0.02 | 0.1917 | no |
| test block precision at reference block threshold | >= 0.95 | 0.8072 | no |
| ONNX parity | <= 1.0e-05 | 3.576e-07 | yes |
| no group leakage | required | none detected | yes |
| **overall** |  |  | **no** |

Reference block threshold used for the gate: 0.9. The gate failing is the expected and correct outcome for a first baseline on synthetic data. The artifact is still exported, because the pipeline, the frozen contract and the parity checks are the deliverable; the manifest records `quality_gate_passed=false` and `recommended_mode=shadow`.

## 20. Known Limitations

- synthetic corpus generated locally; not a representative security dataset
- test prevalence is an artefact of the generator and cannot estimate deployment prevalence
- validation shares scenario families with train, so it cannot detect family-level overfitting
- scores are uncalibrated; they are model scores, not probabilities of maliciousness
- the model cannot distinguish authorised from unauthorised automation, because authorisation is not a behaviour
- coefficients are not individually interpretable; correlated columns redistribute weight
- the selected C is the weakest regularisation in the grid, chosen on a validation split that shares scenario families with train; the unseen-family result is the honest counterweight
- a single measurement run on one machine is not a performance guarantee
- no PCAP replay corpus and no sanitised production shadow export existed to evaluate against

## 21. Recommendation

**SHADOW ONLY.** Do not grant this model enforcement authority and do not enable automatic firewall blocking from its score.

Before limited enforcement could even be discussed, all of the following would have to hold, and none of them holds today:

1. an independent, realistic, labelled evaluation set not generated by this repository;
2. a test split independent at the capture-domain level, not only at the source level;
3. block precision measured on that data at the threshold policy would actually use;
4. hard negatives from the real environment, including its own monitoring and scanning tools;
5. an acceptable false positive rate agreed with the operator, in the operator's own units;
6. ONNX parity and manifest verification on the promoted artifact;
7. shadow replay in that environment supporting the offline result;

## 22. Next Experiment

Do not replace this baseline yet. The next step is a gradient boosting candidate trained and evaluated on the **exact same** dataset version, split, feature contract, metrics and threshold table, so the comparison is fair. Expect it to fit the seen families better; the question worth answering is whether it does anything for the unseen families, which is where this baseline fails.

## 23. Reproduction

| component | version |
|---|---|
| python | 3.12.13 |
| platform | Linux-6.8.0-136-generic-x86_64-with-glibc2.35 |
| numpy | 2.5.3 |
| scikit-learn | 1.9.0 |
| scipy | 1.18.1 |
| onnx | 1.22.0 |
| onnxruntime | 1.29.0 |
| skl2onnx | 1.20.0 |

~~~sh
uv sync --frozen --extra ml --extra ml-training
uv run --frozen python -m training.dataset --output datasets/synthetic-behavior-v3
uv run --frozen python -m training.validation --dataset datasets/synthetic-behavior-v3
uv run --frozen python -m training.train_logreg --dataset datasets/synthetic-behavior-v3 --output-dir models
uv run --frozen python -m training.evaluate_model --dataset datasets/synthetic-behavior-v3 --model-dir models \
    --output models/risk-logreg-v1-evaluation.json --report reports/model-risk-logreg-v1.md \
    --shadow models/risk-logreg-v1-shadow.json --pcap models/risk-logreg-v1-pcap.json
uv run --frozen python -m training.shadow_replay --dataset datasets/synthetic-behavior-v3 --model-dir models \
    --output models/risk-logreg-v1-shadow.json
uv run --frozen python -m training.pcap_evaluate --corpus tests/fixtures/p2/corpus.json \
    --model-dir models --output models/risk-logreg-v1-pcap.json
~~~

