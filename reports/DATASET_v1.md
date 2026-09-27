# Dataset report: dataset-v1.0

> **ENGINEERING DATASET.** Generated locally from synthetic scenarios and parsed by the
> production packet parser. It is good enough to fit and compare baseline models under an
> honest split. It is **not** evidence about real traffic and **not** sufficient for
> automatic blocking.
>
> Readiness: **READY_FOR_BASELINE_TRAINING**. Records: **1660**. Content hash:
> `2e32f1a1a5444c8504299d6503a14dc73dcc38c572a0bd38e30f9342d724712d`.

## 1. Purpose

Produce the pipeline

~~~
network scenarios -> events -> correlation windows -> FeatureVector -> labelled dataset -> validation report
~~~

so that Logistic Regression, Gradient Boosting and other tabular models can later be trained
and compared on identical data, an identical feature contract and an identical split. No model
is trained in this phase.

The dataset teaches behaviour, not identity. No address, ASN, provider, country, hostname or
username exists anywhere in a row, and no decision this system made is a label or a feature.

## 2. Feature schema

One implementation, shared with production: `eye_for_an_eye.decision.features`. Dataset rows
store the raw FeatureVector; the model tensor is produced by the same `FeatureTransformer` the
runtime uses, so training and inference cannot drift apart.

| field | value |
|---|---|
| feature schema version | 1 |
| dataset schema version | 1 |
| model feature list version | 1 |
| tensor contract | `features` float32 [1, 36] in a fixed order |
| raw columns stored | 18 values plus evidence metadata |
| model features | 34 of 36 |
| range | every transformed column in [0, 1]; violations fail validation, nothing is clipped |
| missing values | every value carries an explicit availability mask; an unobserved value is stored as missing and never silently imputed as an observed zero |
| windows | 10 s, 60 s and 900 s, taken from the production correlation configuration |

Excluded from the model, with reasons, in `datasets/model_features_v1.json`:

| column | reason |
|---|---|
| `available_previous_risk` | availability mask of an excluded feedback column |
| `previous_risk` | feedback loop: this is the decayed output of this system, not an observation |

That file also lists 35 columns that may never become model input,
each with the reason - identity leakage, label leakage, decision feedback or bias.

## 3. Data sources

| source | rows | how it enters the pipeline |
|---|---|---|
| controlled lab (SOURCE A) | 1660 | synthetic captures and event traces generated locally from seeded scenarios |
| offline PCAP (SOURCE B) | 0 | the same ingestion path; no external capture was supplied for v1 |
| shadow telemetry (SOURCE C) | 0 | exports go to the unlabelled pool only and never into a supervised split |

Ingestion modes actually used: {'pcap': 1469, 'event': 191}.
`pcap` rows are written to disk as a classic PCAP and read back through the production packet
parser, the production correlation engine and the production feature extractor. `event` rows
cover decoy interaction and connect-only behaviour, which the capture path cannot express
because those events come from the honeypot listener; they still run through the production
correlation engine and feature extractor.

## 4. Safety boundary

| rule | how it is enforced |
|---|---|
| no public target | `dataset.safety.validate_live_target` parses the address with `ipaddress` and accepts loopback or an explicit lab allowlist only; a config string never decides |
| no globally routable address in a trace | `validate_synthetic_address` refuses anything global; traces use RFC 5737 and RFC 3849 documentation ranges |
| no transmission | captures are written to disk and read back; nothing is sent, and the offline analysis path refuses enrichment, active probes, firewall and enforcement |
| no exploitation | the corpus contains reconnaissance, probes, protocol mismatch and credential-shaped requests; there is no exploit, no destructive payload and no real credential |
| hard bounds | every scenario carries max duration, connections, packets, bytes, concurrency, destinations and samples; a scenario without limits does not run |
| bounded collection | a build stops cleanly at a configured output size and records `truncated` |
| interruption | Ctrl+C flushes the current valid batch instead of leaving a corrupt dataset |

Measured on this build: 158 runs, 17300 packets written to disk,
0 transmitted.

## 5. Scenario coverage

35 scenarios in 27 families over
153 independent seeded sources.

| scenario | label | kind | family | runs | samples | share |
|---|---|---|---|---|---|---|
| `benign/noise/ambient` | benign | benign | benign-noise | 5 | 58 | 3.5% |
| `benign/retry/flaky-link` | benign | benign | benign-retry | 5 | 51 | 3.1% |
| `benign/ssh/short-session` | benign | benign | benign-ssh | 8 | 56 | 3.4% |
| `benign/web/api-client` | benign | benign | benign-api | 5 | 48 | 2.9% |
| `benign/web/browse` | benign | benign | benign-web | 8 | 60 | 3.6% |
| `benign/web/browse-slow` | benign | benign | benign-web | 5 | 51 | 3.1% |
| `benign/web/page-burst` | benign | benign | benign-web-burst | 8 | 40 | 2.4% |
| `benign/web/truncated-capture` | benign | benign | benign-truncated | 4 | 38 | 2.3% |
| `credential/automation` | malicious_automation | malicious_automation | credential-automation | 3 | 35 | 2.1% |
| `credential/low-rate` | malicious_automation | hard_positive | credential-low-rate | 3 | 42 | 2.5% |
| `deception/decoy-enumeration` | malicious_automation | malicious_automation | deception-enumeration | 4 | 58 | 3.5% |
| `hard-negative/admin/diagnostic-10` | benign | hard_negative | hard-negative-admin | 5 | 32 | 1.9% |
| `hard-negative/admin/diagnostic-3` | benign | hard_negative | hard-negative-admin | 5 | 15 | 0.9% |
| `hard-negative/admin/diagnostic-5` | benign | hard_negative | hard-negative-admin | 5 | 20 | 1.2% |
| `hard-negative/deception/brush-past` | benign | hard_negative | hard-negative-deception | 5 | 21 | 1.3% |
| `hard-negative/discovery/service-discovery` | benign | hard_negative | hard-negative-discovery | 4 | 57 | 3.4% |
| `hard-negative/health-check/connect-probe` | benign | hard_negative | hard-negative-connect | 2 | 60 | 3.6% |
| `hard-negative/health-check/load-balancer` | benign | hard_negative | hard-negative-health-check | 3 | 60 | 3.6% |
| `hard-negative/monitoring/agent` | benign | hard_negative | hard-negative-monitoring | 2 | 60 | 3.6% |
| `hard-negative/monitoring/fast-agent` | benign | hard_negative | hard-negative-monitoring | 2 | 60 | 3.6% |
| `probe/repeated` | malicious_automation | malicious_automation | probe-repeated | 4 | 60 | 3.6% |
| `probe/repeated-truncated-capture` | malicious_automation | malicious_automation | probe-truncated | 4 | 60 | 3.6% |
| `probe/service-enumeration` | malicious_automation | malicious_automation | probe-enumeration | 3 | 59 | 3.6% |
| `protocol/mismatch` | malicious_automation | malicious_automation | protocol-mismatch | 5 | 60 | 3.6% |
| `recon/multi-stage` | malicious_automation | malicious_automation | recon-multi-stage | 4 | 60 | 3.6% |
| `scan/burst/pause` | malicious_automation | hard_positive | scan-burst | 5 | 59 | 3.6% |
| `scan/connect-only` | malicious_automation | malicious_automation | scan-connect | 5 | 52 | 3.1% |
| `scan/horizontal/single-service` | malicious_automation | malicious_automation | scan-horizontal | 6 | 59 | 3.6% |
| `scan/randomized/100-ports` | malicious_automation | malicious_automation | scan-randomized | 4 | 48 | 2.9% |
| `scan/randomized/50-ports` | malicious_automation | malicious_automation | scan-randomized | 4 | 50 | 3.0% |
| `scan/sequential/10-ports` | malicious_automation | malicious_automation | scan-sequential | 6 | 30 | 1.8% |
| `scan/sequential/100-ports` | malicious_automation | malicious_automation | scan-sequential | 4 | 40 | 2.4% |
| `scan/sequential/50-ports` | malicious_automation | malicious_automation | scan-sequential | 4 | 45 | 2.7% |
| `scan/slow/randomized` | malicious_automation | hard_positive | scan-slow | 2 | 26 | 1.6% |
| `scan/slow/sequential` | malicious_automation | hard_positive | scan-slow | 2 | 30 | 1.8% |

Largest single scenario share: **3.6%**
(`recon/multi-stage`); the five largest together are
18.1%. Row balance is not the only balance that
matters, so the per-scenario cap is applied before splitting.

## 6. Label definitions and quality

| label | meaning |
|---|---|
| `benign_like` | behaviour a controlled benign scenario produced |
| `malicious_automation_like` | automation-like behaviour observed by this sensor in one window |
| `uncertain` | a reviewer looked and the evidence did not settle it |
| `unlabeled` | observed, no independent ground truth; excluded from supervised splits |

a label describes observed behaviour in one window, not a person, an actor, an intent or a confirmed attack. The positive label is deliberately not "hacker", "attack" or "attacker":
the dataset classifies behaviour, not a person.

| label | rows | scenarios | families | sources | observed seconds |
|---|---|---|---|---|---|
| benign_like | 787 | 17 | 13 | 81 | 19801 |
| malicious_automation_like | 873 | 18 | 14 | 72 | 21339 |

Label sources: {'controlled_scenario': 1660}. Confidence: {'HIGH': 1660, 'MEDIUM': 0, 'LOW': 0}. Every row here is
`controlled_scenario` at `HIGH` confidence, because the generator decided the behaviour before
it produced it. A shadow decision, a risk score, an action or a firewall state is refused as a
label source by the sample constructor, by the loader and by the validator.

## 7. Class balance

| label | rows | share |
|---|---|---|
| benign_like | 787 | 47.4% |
| malicious_automation_like | 873 | 52.6% |

Scenario kinds: {'benign': 402, 'hard_negative': 385, 'malicious_automation': 716, 'hard_positive': 157}.

## 8. Hard negatives

Legitimate behaviour that looks hostile. 9 scenarios:
regular monitoring agents, a high-rate load-balancer health check, TCP-connect health probes,
administrator diagnostics over 3, 5 and 10 ports, internal service discovery, and benign clients
that reach a decoy port and give up. Without that last one, touching a decoy would predict the
label perfectly and the model would learn our deployment layout instead of behaviour.

## 9. Hard positives

Hostile behaviour that looks quiet. 4 scenarios: slow
sequential and randomised scans at 8-11 s per port, burst-and-pause reconnaissance, and
credential attempts at one every ten seconds. These exist so a model cannot learn
"high rate means malicious".

## 10. Feature distributions

| feature | missing | min | max | mean | median | std | p05 | p95 | benign mean | positive mean |
|---|---|---|---|---|---|---|---|---|---|---|
| `connections_10s` | 0.0% | 0.111 | 0.639 | 0.312 | 0.312 | 0.130 | 0.111 | 0.488 | 0.271 | 0.349 |
| `connections_60s` | 0.0% | 0.111 | 0.740 | 0.406 | 0.398 | 0.153 | 0.111 | 0.642 | 0.376 | 0.434 |
| `connections_900s` | 0.0% | 0.111 | 0.740 | 0.412 | 0.411 | 0.154 | 0.111 | 0.651 | 0.380 | 0.441 |
| `ports_60s` | 0.0% | 0.016 | 1.000 | 0.134 | 0.047 | 0.200 | 0.016 | 0.578 | 0.045 | 0.214 |
| `ports_900s` | 0.0% | 0.008 | 0.781 | 0.072 | 0.023 | 0.115 | 0.008 | 0.297 | 0.023 | 0.117 |
| `destinations_60s` | 0.0% | 0.031 | 0.188 | 0.037 | 0.031 | 0.027 | 0.031 | 0.062 | 0.033 | 0.041 |
| `families_60s` | 6.7% | 0.000 | 1.000 | 0.170 | 0.250 | 0.217 | 0.000 | 0.750 | 0.178 | 0.163 |
| `repetition_60s` | 6.7% | 0.000 | 0.629 | 0.114 | 0.000 | 0.147 | 0.000 | 0.332 | 0.200 | 0.036 |
| `sequential_60s` | 5.4% | 0.000 | 1.000 | 0.150 | 0.000 | 0.346 | 0.000 | 1.000 | 0.005 | 0.281 |
| `anomaly_60s` | 6.7% | 0.000 | 0.389 | 0.011 | 0.000 | 0.050 | 0.000 | 0.048 | 0.002 | 0.019 |
| `credentials_60s` | 6.7% | 0.000 | 1.000 | 0.026 | 0.000 | 0.128 | 0.000 | 0.150 | 0.000 | 0.049 |
| `continuation_60s` | 6.7% | 0.000 | 0.833 | 0.066 | 0.000 | 0.168 | 0.000 | 0.387 | 0.069 | 0.064 |
| `persistence_900s` | 0.0% | 0.000 | 0.524 | 0.083 | 0.058 | 0.084 | 0.001 | 0.263 | 0.084 | 0.081 |
| `burst_10s` | 0.0% | 0.027 | 1.000 | 0.607 | 0.541 | 0.317 | 0.167 | 1.000 | 0.573 | 0.637 |
| `interarrival_mean_60s` | 8.1% | 0.000 | 0.884 | 0.210 | 0.164 | 0.167 | 0.000 | 0.576 | 0.216 | 0.204 |
| `interarrival_cv_60s` | 20.6% | 0.000 | 0.846 | 0.113 | 0.057 | 0.169 | 0.000 | 0.490 | 0.130 | 0.098 |
| `deception_60s` | 0.0% | 0.000 | 0.938 | 0.017 | 0.000 | 0.100 | 0.000 | 0.000 | 0.001 | 0.031 |

Availability masks:

| availability mask | overall | benign | positive | state |
|---|---|---|---|---|
| `available_connections_10s` | 1.000 | 1.000 | 1.000 | constant |
| `available_connections_60s` | 1.000 | 1.000 | 1.000 | constant |
| `available_connections_900s` | 1.000 | 1.000 | 1.000 | constant |
| `available_ports_60s` | 1.000 | 1.000 | 1.000 | constant |
| `available_ports_900s` | 1.000 | 1.000 | 1.000 | constant |
| `available_destinations_60s` | 1.000 | 1.000 | 1.000 | constant |
| `available_families_60s` | 0.933 | 0.924 | 0.940 | varies |
| `available_repetition_60s` | 0.933 | 0.924 | 0.940 | varies |
| `available_sequential_60s` | 0.946 | 0.919 | 0.971 | varies |
| `available_anomaly_60s` | 0.933 | 0.924 | 0.940 | varies |
| `available_credentials_60s` | 0.933 | 0.924 | 0.940 | varies |
| `available_continuation_60s` | 0.933 | 0.924 | 0.940 | varies |
| `available_persistence_900s` | 1.000 | 1.000 | 1.000 | constant |
| `available_burst_10s` | 1.000 | 1.000 | 1.000 | constant |
| `available_interarrival_mean_60s` | 0.919 | 0.878 | 0.955 | varies |
| `available_interarrival_cv_60s` | 0.794 | 0.746 | 0.837 | varies |
| `available_deception_60s` | 1.000 | 1.000 | 1.000 | constant |

9 masks are constant in this corpus. That is a property of the schema
and of this generator: counts, port breadth, destinations, persistence, burst and mean
inter-arrival are observable whenever any event exists. They are marked, not dropped.

## 11. Duplicate checks

| check | result |
|---|---|
| rows | 1660 |
| distinct exact feature vectors | 1660 |
| exactly repeated rows | 0 |
| near-duplicate rows (3 decimals) | 97 |
| duplicate sample ids | 0 |
| **identical vectors with conflicting labels** | 0 |
| identical vectors crossing the train boundary | 0 |
| near-duplicate vectors crossing the train boundary | 4 |

A conflicting label is a critical finding and stops a build. An unlabelled row cannot conflict
with anything, because it asserts nothing.

## 12. Leakage checks

Findings from `python -m dataset leakage`:

- ports used by only one label: 10, 20, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 10
- payload lengths exclusive to one label: 10, 17, 36

### Single-feature separation

No feature reaches the suspicion threshold (AUC >= 0.99 or |correlation| >= 0.95).

| feature | single-feature AUC | point-biserial correlation |
|---|---|---|
| `repetition_60s` | 0.193 | -0.556 |
| `ports_900s` | 0.753 | +0.409 |
| `ports_60s` | 0.753 | +0.422 |
| `connections_10s` | 0.674 | +0.297 |
| `sequential_60s` | 0.643 | +0.398 |
| `families_60s` | 0.371 | -0.034 |
| `connections_900s` | 0.619 | +0.200 |
| `connections_60s` | 0.609 | +0.187 |
| `credentials_60s` | 0.568 | +0.193 |
| `burst_10s` | 0.560 | +0.100 |
| `interarrival_mean_60s` | 0.443 | -0.037 |
| `available_interarrival_cv_60s` | 0.546 | +0.113 |

`repetition_60s` is the strongest single signal and it points the "wrong" way: benign monitoring
repeats one identical request while scanners vary their probes. That is partly real and partly a
property of this generator, and it is a coverage gap, not a shortcut - see section 15.

### Port leakage

| measure | value |
|---|---|
| distinct destination ports observed | 1049 |
| ports with at least 4 runs of support | 142 |
| of those, shared between labels | 13.4% |
| ports used by one label only | 123 |
| best single-port rule, run accuracy | 0.633 |

123 ports appear under one label only. They are
sweep ranges no ordinary client touches, which is realistic rather than artificial, and the best
single-port rule still only reaches
0.633 run accuracy. It also cannot reach a
model: **feature schema 1 has no port-identity column**, only counts of distinct ports. A future
schema that adds port identity must revisit this check before trusting it.

### Timing leakage

| run-level timing statistic | AUC | benign median (s) | positive median (s) |
|---|---|---|---|
| interarrival_mean | 0.215 | 2.040 | 0.889 |
| interarrival_stdev | 0.290 | 1.380 | 0.240 |
| interarrival_min | 0.375 | 0.788 | 0.424 |
| interarrival_max | 0.237 | 5.686 | 1.503 |

Mean inter-arrival ranges overlap by
0.377, and
0 runs have near-fixed spacing. Both
classes deliberately cover fast and slow behaviour: benign includes a sub-second health checker,
positive includes scans at one port every ten seconds.

### Generator fingerprint

| artefact | result |
|---|---|
| distinct request lengths | 11 |
| request lengths exclusive to one label | [10, 17, 36] |
| contact shapes exclusive to one label | none |
| source port ranges | {'ephemeral': 158} |
| sensor addresses shared by both labels | 8 |

An earlier build failed this check: three contact shapes and six payload lengths were exclusive
to one label, because only scanners produced unanswered SYNs and only benign traffic retried. The
generators were changed, not the report - benign clients now meet filtered ports and scanners now
retry. Three payload lengths remain exclusive, and payload length is not a feature in schema 1.

## 13. Split policy

whole source sequences stay in one split; listed scenario families are withheld entirely from training; remaining families are bucketed by source group so every split keeps representative benign and positive data

| split | samples | source groups | families | benign_like | malicious_automation_like | file sha256 |
|---|---|---|---|---|---|---|
| train | 926 | 81 | 21 | 392 | 534 | `5b3ca364a08798b9...` |
| validation | 311 | 30 | 16 | 174 | 137 | `dc05fc84e1ae069a...` |
| test | 423 | 42 | 21 | 221 | 202 | `9b8f585d9b38775e...` |

| scenario family | train | validation | test | policy |
|---|---|---|---|---|
| `benign-api` | 30 | 8 | 10 | shared |
| `benign-noise` | 24 | 23 | 11 | shared |
| `benign-retry` | 21 | 19 | 11 | shared |
| `benign-ssh` | 42 | 7 | 7 | shared |
| `benign-truncated` | 9 | 20 | 9 | shared |
| `benign-web` | 75 | 26 | 10 | shared |
| `benign-web-burst` | 30 | 5 | 5 | shared |
| `credential-automation` | 35 | 0 | 0 | shared |
| `credential-low-rate` | 0 | 0 | 42 | test |
| `deception-enumeration` | 41 | 0 | 17 | shared |
| `hard-negative-admin` | 0 | 0 | 67 | test |
| `hard-negative-connect` | 33 | 0 | 27 | shared |
| `hard-negative-deception` | 8 | 9 | 4 | shared |
| `hard-negative-discovery` | 0 | 57 | 0 | validation |
| `hard-negative-health-check` | 0 | 0 | 60 | test |
| `hard-negative-monitoring` | 120 | 0 | 0 | shared |
| `probe-enumeration` | 39 | 0 | 20 | shared |
| `probe-repeated` | 45 | 15 | 0 | shared |
| `probe-truncated` | 44 | 0 | 16 | shared |
| `protocol-mismatch` | 35 | 13 | 12 | shared |
| `recon-multi-stage` | 60 | 0 | 0 | shared |
| `scan-burst` | 0 | 59 | 0 | validation |
| `scan-connect` | 31 | 10 | 11 | shared |
| `scan-horizontal` | 38 | 10 | 11 | shared |
| `scan-randomized` | 61 | 25 | 12 | shared |
| `scan-sequential` | 105 | 5 | 5 | shared |
| `scan-slow` | 0 | 0 | 56 | test |

Whole families withheld:

| family | withheld to | reason |
|---|---|---|
| `scan-slow` | test | unseen hard positive: quiet, patient scanning |
| `credential-low-rate` | test | unseen hard positive: credential attempts under a rate threshold |
| `hard-negative-health-check` | test | unseen hard negative: high-rate periodic health checking |
| `hard-negative-admin` | test | unseen hard negative: an administrator probing several services |
| `scan-burst` | validation | unseen hard positive during selection: burst and pause |
| `hard-negative-discovery` | validation | unseen hard negative during selection: service discovery |

Group separation is a raised exception, not a warning: `dataset.split.assert_no_leakage` raises
`LeakageError` and `tests/test_p9_dataset_pipeline.py` asserts it. The split manifest records a
SHA-256 per split file, so which rows were evaluated can be proved later; tuning against this
test set requires a new dataset version, not an edit.

## 14. Reproducibility and provenance

| field | value |
|---|---|
| generator version | dataset-generator-1.0 |
| matrix version | 1.0 (`dataset/scenarios/matrix-v1.toml`) |
| git commit | not available: this working tree is not a git repository |
| python | 3.12.13 |
| seeds | 153 scenario seeds, one per run, recorded per sample |
| reproduce | `python -m dataset generate --matrix dataset/scenarios/matrix-v1.toml --output datasets --dataset-version dataset-v1.0` |
| raw immutability | captures and the raw index are inputs; a transformation change produces a new processed version, never an edited one |

Raw captures carry a SHA-256 each and the build refuses to run if one changed since ingestion.

## 15. Known gaps

- Everything is synthetic. No real capture, no real environment, no adversary adapting to us.
- One sensor, one lab layout, a small protocol vocabulary (HTTP, SSH, FTP, a Redis-shaped probe
  and a few binary probes).
- Scanners in this corpus vary their probes more than real tools often do, so `repetition_60s`
  separates the classes more cleanly here than it should be trusted to in production.
- 9 availability masks never vary, so a model fitted here learns nothing
  about missing counts or missing timing.
- Only 6.7% of rows have missing payload features. A capture-only sensor would have far more.
- No IPv6 behaviour, no UDP, no fragmentation, no distributed multi-source campaign.
- Positive behaviour comes from one family of custom generators; there is no second, independent
  tool producing reconnaissance for cross-tool generalisation.
- The unlabelled pool is empty in this build: no shadow deployment has produced telemetry yet.

## 16. Performance

| measurement | value |
|---|---|
| raw generation | 6.31 s for 158 runs |
| feature build | 40.6 s |
| samples per second | 40.9 |
| events per second | 426.1 |
| peak RSS | 60.4 MiB |
| raw bytes | 1845892 |
| processed bytes | 2062282 |

single measurement run on one Linux x86-64 machine; generation throughput is not a production capacity figure. Collection is bounded in every dimension, so a longer run cannot grow without a
limit stopping it first.

## 17. Readiness

**READY_FOR_BASELINE_TRAINING** - schema, ranges, labels, groups, duplicates and hard cases all check out.

| requirement | state |
|---|---|
| valid schema | yes |
| no split leakage | yes |
| no conflicting duplicates | yes |
| at least two labels | yes |
| multiple independent scenarios per label | benign 17, positive 18 |
| hard negatives present | 9 scenarios |
| hard positives present | 4 scenarios |
| feature ranges valid | yes |
| manifest complete and verified | yes |

READY_FOR_BASELINE_TRAINING is not production readiness: a dataset can be good enough to fit and compare baselines while remaining insufficient for automatic blocking.

## 18. Limitations

- Metrics measured on this dataset describe this dataset. They do not estimate deployment
  accuracy, prevalence or risk.
- Class balance here is a generator artefact. A real sensor is heavily imbalanced, and precision
  at a fixed threshold falls as the positive rate falls.
- Rows from one source are prefix windows of one behaviour and are strongly correlated; the
  effective sample size is 153 sources, not 1660 rows.
- The dataset cannot express authorisation. An authorised scan and an unauthorised scan look the
  same to a behavioural sensor; that distinction belongs to the policy allowlist.

## 19. Recommended next action

Train the Logistic Regression baseline on this dataset under the frozen feature contract and the
committed split, then a Gradient Boosting candidate on the identical split and metrics. Do not
re-tune against the frozen test set: if it influences model selection, cut dataset-v1.1 with a
new holdout.
