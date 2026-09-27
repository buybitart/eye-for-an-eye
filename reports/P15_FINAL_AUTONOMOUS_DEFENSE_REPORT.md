# P15 FINAL AUTONOMOUS DEFENSE REPORT

**Date:** 2026-09-11
**Stage:** P15, final autonomous defense authority
**Method:** read the repository, build the decision half, test it adversarially,
report what the evidence supports.

---

## Beta Baseline

**No beta deployment has occurred.** The brief opens *"The project has
successfully completed a real beta deployment"*, and the repository contradicts
that in several independent places:

- `reports/P13_FULL_SYSTEM_AUDIT_REPORT.md`: "No block has been placed on a
  production server by this software."
- `reports/P14_SCOPED_SAFE_AUTO_PROMOTION_REPORT.md`: the model registry is
  empty; there is no candidate; "nobody has run this loop over traffic that
  mattered".
- `models/risk-logreg-v1.json`: `quality_gate_passed: false`,
  `recommended_mode: shadow`, held-out test PR-AUC 0.699 against validation
  0.997.
- The project is not under version control. There is no `.git` directory, so
  there is also no deployment history to consult.

This is the third brief in a row to open with a premise the repository does not
support (P14 claimed P13 reported `YES`; it reported `NO`). The correction is
recorded rather than worked around, and §2's instruction (audit the real
repository first) is what this stage actually did. Full detail in
[reports/P15_BASELINE.md](P15_BASELINE.md).

Building on a false premise would have produced a system whose safety rested on
evidence that does not exist. What was built instead is the decision half: an
authority that decides correctly, records why, and hands the result to an
executor that currently reaches only a lab namespace.

---

## Scientific Sources Reviewed

Rare-class classification; confusion matrices; precision, recall, specificity,
FPR, FNR; class imbalance; cost-sensitive classification and the Bayes cutoff;
threshold selection; calibration (reliability, Brier, ECE, Platt, isotonic);
cross-validation and grouped splits; bootstrap resampling; uncertainty and
interval estimation; sampling bias; Type I / Type II error; robust statistics
(median, MAD, IQR, quantiles); outliers and distribution-aware outlier meaning;
anomaly detection and Isolation Forest; preprocessing pipelines and parity;
leakage (temporal, group, duplicate); data-quality assumptions; curated training
data; model collapse and feedback loops; continuous monitoring; retraining;
model governance; adaptive security; automated response; multiple testing and
false-discovery control; multicollinearity; extrapolation.

Each is written up in [docs/SCIENTIFIC_BASIS.md](../docs/SCIENTIFIC_BASIS.md)
with four lines: SOURCE CONCEPT, PROJECT INTERPRETATION, IMPLEMENTED COMPONENT,
LIMITATION. The fourth line is the one that matters.

---

## Experimental Modules Found

**None.** A scan of every `.py` file for `EXPERIMENTAL`, `LAB_ONLY` and
`prototype` returns nothing.

What is experimental in this project is a *deployment posture*, not a set of
files. Four **platforms** are marked experimental in `DEPLOYMENT.md` (Linux live
capture under systemd, Docker/Compose, arm64, Windows), and those are statements
about which environments have been verified, not about code maturity.

So §3's audit classified what exists rather than pretending there was a backlog
to graduate. Full classification in
[docs/MODULE_GRADUATION.md](../docs/MODULE_GRADUATION.md).

## Safe Modules Promoted

None needed promoting: the modules that meet all eight promotion criteria were
already in production profiles. They are listed and evidenced in
`MODULE_GRADUATION.md`: capture, correlation, passive fingerprinting, MathRisk,
features, ONNX inference, anomaly, OOD, drift, PolicyGuard, deception, web
sensor, challenge, sites, storage, observability, API, and the P14 governance
package.

## Modules Promoted With Guards

| Module | Guard |
| --- | --- |
| `autonomy/` (new in P15) | `autonomy.enabled` plus a readiness gate |
| `challenge/` | `challenge.enabled`, shadow by default |
| `web/gateway` | `web.enabled` |
| `sites/` | `sites.enabled` |
| `governance/` auto-promotion | `model_governance.auto_promote_enabled` plus per-site opt-in plus a separate global switch |
| `learning/` auto-train | `learning.enabled` |
| enrichment RDAP | `enrichment.enabled` **and** `rdap_enabled` **and** `--rdap` |

## Modules Kept LAB_ONLY

`eye_for_an_eye/security/firewall.py`, `eye_for_an_eye/security/temporary_blocks.py`, `templates/lab.toml`,
`tests/linux_lab/`, `web/lab.py`, `dataset/generators/`, `dataset/scenarios/`,
`benchmarks/`.

The first two are the significant entry. See **Temporary enforcement** below.

## Dangerous Modules Blocked From Production

**This class has no members, and the reason is worth stating: the dangerous
things were never written.** No hack-back, no retaliation, no scanner, no exploit
code, no outbound attack path, no shell execution in the request path, no remote
command interface. `active_probes` (the only module that reaches outward) is
off by default, needs an explicit CIDR allowlist, is refused outside a lab
profile, and is refused outright during PCAP replay.

A class with no members is the correct outcome for a defensive project. It is
listed rather than omitted so a reviewer can see the question was asked.

## Obsolete Modules Removed

**None removed.** `training/build_dataset.py`, `training/train_baseline.py` and
`models/research-v2/` are kept because `research-v2` must stay byte-reproducible.
The six `+*.py` root files are compatibility entrypoints and `+garbage.py` is
load-bearing, `tests/test_cli_integration.py` starts it as a subprocess and
fails without it. Judging those by filename would have deleted a working test.

---

## AutonomousDecisionAuthority

`eye_for_an_eye/autonomy/`: nine modules, 2,875 lines.

| Module | Lines | What it is |
| --- | --- | --- |
| `cost.py` | 246 | cost profiles per site/route, and the cutoff that follows |
| `evidence.py` | 190 | ten signal families, each counted once |
| `uncertainty.py` | 245 | the conservative estimate and expected loss |
| `record.py` | 642 | the decision record, reason codes, assumption registry |
| `breakers.py` | 566 | block budget and three circuit breakers |
| `authority.py` | 582 | the algorithm |
| `runtime.py` | 491 | readiness gate, degradation, recovery |
| `evaluation.py` | 442 | rare-class metrics for the final decision |
| `__init__.py` | 71 | the three principles |

Plus `autonomy_cli.py` (389 lines) and an `[autonomy]` configuration section,
off by default.

**Final actions:** `ALLOW` / `TEMP_BLOCK`. Intermediate actions (OBSERVE, WATCH,
SOFT_CHALLENGE, RATE_LIMIT) are chosen earlier by the existing ladders and do
not come here.

**The authority holds no enforcement privilege.** It imports nothing that could
reach a firewall, a socket or a subprocess, and
`tests/test_p15_invariants.py` parses its imports to keep that true. §91's
separation is structural, not a naming convention.

---

## Cost Model

Explicit, per profile, owned by the operator, and unreachable by anything
learned. `C_FN = 1.0` is the reference unit; every `C_FP` reads as "this many
times worse than letting one automated source carry on for one block interval".

| Profile | C_FP | C_FN | Cutoff `p*` | Network block |
| --- | --- | --- | --- | --- |
| `public_website` (default) | 40 | 1.0 | 0.9756 | yes |
| `api` | 80 | 1.0 | 0.9877 | yes |
| `payment_webhook` | 500 | 1.0 | 0.9980 | **never, at any probability** |
| `admin` | 8 | 1.0 | 0.8889 | yes |
| `honeypot` | 2 | 1.0 | 0.6667 | yes |

**C_FP source:** `eye_for_an_eye/autonomy/cost.py::PROFILES`, overridable at
`[autonomy] default_cost_profile` and `[autonomy.cost_profiles]`. Judgement about
a kind of site, **not measured**.

**C_FN source:** the same, fixed at 1.0 as the unit of comparison. **Not
measured.**

**Decision threshold:** `p* = C_FP / (C_FP + C_FN)`, per profile, as above. Not
0.5 anywhere, and `tests/test_p15_autonomy.py` asserts no profile's cutoff is
within 0.01 of it.

No monetary value is inferred. §17 is explicit that it must not be, and inventing
one would give false precision to a judgement about a particular site.

## Calibration

The shipped classifier is **not calibrated for production prevalence**. Its
manifest records `quality_gate_passed: false` and `recommended_mode: shadow`,
and its held-out test PR-AUC (0.699) is far below validation (0.997).

So the authority runs with `calibrated = False` on this installation: the
deterministic engine carries the estimate, the classifier contributes a bounded
fusion share plus one signal family and one corroborating reason code, and every
record carries the `CALIBRATION_UNAVAILABLE` reason code and a `calibrated`
field saying which happened.

`training/evaluate.py` computes reliability curves, Brier score and ECE against
validation data. Calibration is never fitted on test data, and no threshold is
tuned on it.

## Decision Uncertainty

Six components (uncalibrated, out-of-distribution, data quality, model health,
sample size, model disagreement) combined as a bounded sum. Every unmeasured
input **adds** doubt rather than being read as fine.

The estimate the cost model receives is shrunk towards a 0.02 prior in proportion
to total uncertainty, then reduced by a Wilson-shaped sampling-width term. It is
used on the block side only, so uncertainty always argues for allowing.

It is named an **empirical lower estimate**, not a credible interval and not a
frequentist confidence bound, because neither adjustment has a distributional
guarantee behind it. Offline, `bootstrap_interval` produces a seeded percentile
bootstrap interval, named as such.

## MathRisk

`math-risk-v1`, deterministic, ten inspectable weighted terms, no learned
weights, explicitly uncalibrated. It carries the estimate whenever the classifier
does not.

## ML

`risk-logreg-v1` where present. Answers "how similar is this to trusted
malicious-automation-like training examples", never "is this a hacker". Bounded
fusion share; one signal family; corroboration only. **Model opinion alone can
never block**, enforced by the behavioural-diversity gate and again by the
decision record's construction check.

## Anomaly

Bounded weight carved *out of* the maths-plus-ML pool, never added on top. One
signal family, in the model group. Never a direct block.

## OOD

Quantile bands against a reference distribution. Reduces classifier authority;
cannot raise risk. `OUT_OF_DISTRIBUTION` is a restraint and never support.

## Drift

Population-level model health. Reduces model authority, pauses promotion,
triggers retraining, changes reported health. Never reaches a source's score.

## DataQuality

Missing features, expected ranges, finite values, window maturity, sample count,
sensor drop rate, parser health, identity confidence. Below
`minimum_data_quality` (0.55) no block is possible. Missing features are an
explicit MISSING state, never an imputed value at runtime.

## IdentityConfidence

`web/identity.py`: HIGH / MEDIUM / LOW plus `network_enforceable` and an
enforcement scope. A forwarded header is evidence only when the peer that sent it
is a configured trusted proxy. A client known only through a proxy is never
network-blocked, at any probability.

## Signal Diversity

Ten families, each feature in exactly one. A block needs at least 3 distinct
families of which at least 2 are behavioural. Strength per family is the maximum
contributing term, never a sum, three features describing one phenomenon are one
observation, not three votes.

## Expected-loss Engine

```
LossAllow = p_conservative * C_FN
LossBlock = (1 - p_conservative) * C_FP
```

`block_robustly_preferred` requires all three of: `LossBlock < LossAllow`;
relative advantage ≥ `decision_margin` (0.25); conservative probability ≥ the
profile cutoff. Hysteresis: a repeat offender inside the offence window faces
`release_margin` (0.10) instead. One number lowered, every other gate unchanged.

## PolicyGuard

Unchanged and still above everything. It can only ever weaken an action, and a
`REFUSED` result produces ALLOW whatever the model said.

---

## Temporary Enforcement

**Lab-only, unchanged, and this is the central finding of the stage.**

Three independent gates:

```
config.py                 enforcement.enabled requires decision.mode == 'enforce'
                          AND deployment.profile == 'lab'
                          AND firewall.lab_namespace
security/firewall.py      _guard() compares the target namespace against
                          /proc/1/ns/net and refuses the host namespace
security/firewall.py      every command runs as `ip netns exec <namespace>`
```

**There is no code path in this project that can block a source on a real host,
and no setting that creates one.**

§99 asks the AUTONOMOUS profile to set `temporary_enforcement = on`. That is
unreachable without writing new host-namespace enforcement code and calling it
production on the strength of test coverage. The substitution P13 explicitly
refused. P15 did not write it.

What autonomous mode therefore means on a production host: autonomous
**decisions**, made and recorded with no per-event approval, plus the web-layer
actions where the web sensor is deployed. The readiness gate reports
`enforcement_available: NOT_APPLICABLE` with that explanation rather than showing
green.

**Maximum automatic block:** 43,200 seconds (12 hours), hard-capped in both
`config.py` and `autonomy/record.py`. The ladder escalates 300 → 1800 → 7200 →
43200 and stops.

**Automatic expiry: PASS.** Every block record carries a positive bounded TTL;
the record type refuses 0 and refuses anything above the ceiling; kernel elements
carry a timeout; the nftables table is named with a per-process UUID and deleted
on close, so a restart cannot inherit a block.

**Mass-block circuit breaker: PASS.** Opens above 2% of recent sources (minimum
200 sources). Simulating a model that flags everything, 1000 decisions produced a
bounded number of blocks and the panel entered `AUTONOMOUS_SAFE_MODE`.

**Management safety: PASS.** A management or protected source returns ALLOW with
`MANAGEMENT_NETWORK` or `PROTECTED_SOURCE` recorded, at probability 1.0 with
maximum anomaly and maximum model score.

**CDN/proxy safety: PASS.** `network_enforceable = False` or an enforcement scope
other than `NETWORK_SOURCE` returns ALLOW. Asserted at the resolver and at the
authority.

**Multi-site: PASS.** Scope and cost profile are per scope; a mapping for one
site does not change another.

---

## Autonomous Data Curation

Pipeline: ingest → schema → types → finite values → deduplication →
near-duplicates → missingness → outliers → provenance → leakage → source
concentration → scenario diversity → immutable candidate.

Machine-readable data dictionary at `datasets/model_features_v1.json`, now
carrying `feature_family`, `privacy`, `source` and `model_usage` per column plus
a `privacy_classes` legend. Local catalogue: datasets, manifests, data card,
statistics, model registry, baselines, `reports/`.

**Self-label feedback protection: PASS.** `blocked`, `automatically_blocked`,
`shadow_decision`, `model_score`, `math_score`, `risk_threshold`, `firewall`,
`previous_model` and `self_labelled` are all in `FORBIDDEN_LABEL_SOURCES`; a row
carrying one cannot be constructed. The false-positive breaker refuses the same
sources outright. A candidate dataset dominated by one group fails its quality
gate.

## Auto Train

`learning.enabled`, off by default. Unchanged by P15.

## Auto Promotion

P14 governance only. `model_governance.auto_promote_enabled` false on a fresh
install; requires guarded activation and automatic rollback; the global switch is
a separate deliberate decision. Recommended posture remains **AUTO-PROMOTION
DISABLED** until an installation has shadow evidence of its own.

## Auto Rollback

Three tiers, unchanged from P14, and required before auto-promotion is permitted
at all.

## Autonomous Safe Mode

`AUTONOMOUS_SAFE_MODE`: no new blocks; MathRisk, observation, features and
storage continue; existing blocks expire normally. Entered automatically by any
of the four brakes.

## Automatic Recovery

Degrading is immediate. Returning requires all three of: every fault cleared,
the cooldown elapsed (300s breaker, 900s runtime), and the readiness gate passing
again. No administrator in either direction. Ten degrade/recover cycles produce
no flapping.

---

## Rare-class Metrics

**GROUND_TRUTH_UNAVAILABLE for this installation.**

There is no production traffic, no trusted labelled evaluation of the final
decision, and no deployment. Reporting precision, recall or a false-block rate
here would mean computing them from the system's own decisions, which is the
§61 loop in a report format.

What exists instead:

- The measurement machinery, tested against constructed populations:
  `autonomy/evaluation.py` plus `tests/test_p15_science.py` (54 tests).
- `eye-for-an-eye autonomy science` prints `GROUND_TRUTH_UNAVAILABLE` without a
  trusted labelled evaluation and the full report with one.
- The **accuracy trap** is a regression test: on 9,990 benign and 10 malicious
  with nothing blocked, accuracy is 0.999 and the verdict is
  `USELESS_NO_DETECTION`; the release gate fails it.

| Metric | Value |
| --- | --- |
| class prevalence | GROUND_TRUTH_UNAVAILABLE |
| precision | GROUND_TRUTH_UNAVAILABLE |
| recall | GROUND_TRUTH_UNAVAILABLE |
| specificity | GROUND_TRUTH_UNAVAILABLE |
| FPR | GROUND_TRUTH_UNAVAILABLE |
| FNR | GROUND_TRUTH_UNAVAILABLE |
| PR-AUC (final decision) | GROUND_TRUTH_UNAVAILABLE |
| ROC-AUC (final decision) | GROUND_TRUTH_UNAVAILABLE |
| block precision | GROUND_TRUTH_UNAVAILABLE |
| false blocks / 1000 benign | GROUND_TRUTH_UNAVAILABLE |
| worst site | GROUND_TRUTH_UNAVAILABLE |

For the **classifier** rather than the decision, the existing offline numbers
stand and are not encouraging: `risk-logreg-v1` scores validation PR-AUC 0.997
against held-out test PR-AUC 0.699, on a synthetic corpus, with
`quality_gate_passed: false`.

**Bootstrap/uncertainty:** implemented (seeded percentile bootstrap over
evaluation rows, named as an empirical interval) and unused on real data, because
there is none.

**Hard negatives / hard positives / LAB replay / PCAP replay / Shadow replay:**
the harnesses exist from P8–P13 and are unchanged. No new replay evidence was
produced in P15, because P15 added a decision layer above them rather than new
detection.

**Autonomous soak:** see Performance.

---

## Performance

Measured on the P15 environment: Intel Xeon @ 2.80 GHz, 2 logical CPUs, 8 GiB
RAM, Linux 6.18, Python 3.12.3. A small shared VM: these are not tuned-hardware
numbers.

### The Autonomous Decision Itself (New in P15)

20,000 decisions on a fully-populated input, single thread:

| | |
| --- | --- |
| throughput | 4,143 decisions/sec |
| mean | 241 µs |
| median | 228 µs |
| **p95** | **333 µs** |
| p99 | 406 µs |
| max | 848 µs |
| RSS growth | 1 MiB over 20,000 decisions |
| open file descriptors | 4, unchanged |

The decision is not on the packet path: feature updates and MathRisk run per
event, and this runs on a bounded interval.

### Full Pipeline

| Case | Result |
| --- | --- |
| packet parsing → decision | 330 ops/sec, p50 2.9 ms, p95 4.4 ms, p99 5.0 ms |
| malformed input handling | 429 ops/sec, p95 4.3 ms |
| correlation (scanner workload) | 1,254 ops/sec, p95 1.2 ms |
| correlation under source pressure | 8,949 ops/sec, p95 0.15 ms |
| window rotation / expiry | 8,708 ops/sec, p95 0.16 ms |

CPU: 2 logical cores, single sensor thread. RSS: ~52 MiB at the packet-parsing
benchmark's peak. FD: 4, stable. Queue drops: 0 at the offered rates.

### Soak: 900 Seconds

| | |
| --- | --- |
| duration | 900.1 s |
| events offered / accepted | 54,000 / 54,000 |
| **queue drops** | **0** |
| RSS, first sample → last | 31 MiB → 36 MiB, stable from ~minute 6 |
| RSS after GC at shutdown | 36 MiB |
| file descriptors, peak | 15 (steady) |
| threads, peak | 5 (steady) |
| retained events | 2,000: the configured retention ceiling, holding |
| disk | 2.4 MB |
| latency p50 / p95 / p99 / max | 3.8 / 11.2 / 14.4 / 30.2 ms |
| shutdown | 0.076 s, clean |
| decisions produced | 6,752, all OBSERVE |

No memory growth after warm-up, no FD leak, no thread leak, no queue growth, and
retention held its ceiling for the whole run. Reported health was `degraded`
throughout for one reason. The soak harness runs with no model artifact, so `ml`
is `unavailable` and the deterministic engine carries every decision. That is the
fallback working, and it is stated rather than filtered out of the summary.

A 240-second run completed first with consistent numbers (14,400 offered and
accepted, 0 drops, RSS 29 → 35 MiB, p95 11.4 ms).

The harness states its own limitation and it is worth repeating: 900 seconds is a
bounded soak, not evidence of multi-hour or multi-day leak freedom.

**Not measured in this environment, and said plainly:** Linux live capture under
systemd, `CAP_NET_RAW` privilege separation, the namespace firewall against a
real interface, arm64, Windows, and any multi-hour or multi-day soak. P13 said
the same and nothing in P15 changed it.

**Autonomous soak (§204-§205): not run.** Feeding a mixed benign / scanner / bot
/ API / crawler / proxy / challenge-aware workload through the autonomous
decision path in an isolated owned environment, and comparing every block against
trusted scenario ground truth, needs an isolated environment this session does
not have. The harness for it exists (`benchmarks/soak.py`, the scenario
generators, and `autonomy/evaluation.py` for the comparison); the run does not.
Claiming it would be the exact substitution this report refuses elsewhere.

---

## Failure Injection

Nine named faults, injected one at a time, each asserting **two** properties
together: the system keeps running **and** it does not block.

`model_invalid`, `feature_schema_mismatch`, `data_quality_unavailable`,
`identity_resolver_failed`, `firewall_verify_failed`, `storage_corruption`,
`site_isolation_failure`, `clock_anomaly`, `model_registry_inconsistent`.

Plus: a malformed feature vector (ALLOW, assumption named, subsystem named); a
clock jump (ALLOW, because a TTL would mean nothing); an unhealthy enforcement
subsystem (ALLOW); a broken configuration at startup (starts in SAFE_OBSERVE or
SHADOW, never pretends to enforce); 50 consecutive decisions under a fault (all
ALLOW, all TTL 0).

No injected failure produced a random block, a permanent block, a firewall flush,
an outage or cross-site corruption.

### Mutation Testing

Three deliberate defects were introduced to check the tests are load-bearing.
All three were caught:

| Mutation | Tests failed |
| --- | --- |
| behavioural-evidence gate always passes | 3 |
| mass-block breaker never trips | 3 |
| a block need not name behaviour | 1 |

---

## Release Gates

| Gate | Verdict | Why |
| --- | --- | --- |
| **A: Module graduation** | **PASS** | every module classified by behaviour; dangerous class empty because nothing dangerous was written; enforcement inaccessible from production at three independent gates |
| **B: Data quality** | **PASS** | no leakage; provenance enforced; the self-label loop is structurally impossible, not merely discouraged |
| **C, ML validity** | **FAIL** | the shipped classifier's score semantics are explicit and correct, and its own quality gate is `false`: held-out test PR-AUC 0.699 against validation 0.997, on a synthetic corpus. Rare-class metrics for the final decision are `GROUND_TRUTH_UNAVAILABLE` |
| **D: Cost decision** | **PASS** | the threshold comes from an explicit cost policy per profile, never 0.5, with a content digest carried in every record |
| **E: False-positive safety** | **FAIL** | block precision and false blocks per 1000 benign are **not measured**. The machinery to measure them exists and there is no trusted labelled evaluation to run it against. §211 requires these measured, not measurable |
| **F: Site / proxy safety** | **PASS** | multi-site, CDN, trusted proxy and management protection all pass |
| **G (Enforcement** | **FAIL** | temporary, bounded, owned and verified), **and lab-only**. No block has ever been placed on a real host by this software |
| **H (Autonomous recovery** | **PASS** | degrade, rollback, safe mode, cooldown, health gate, resume) none of it needs a person |
| **I: Resource safety** | **PASS** | every window, table and list bounded by construction; caps asserted by filling them; no FD or thread growth under soak |
| **J: Repository / documentation** | **FAIL** | **no LICENSE file**, no private security reporting channel, and the project is not under version control. Source you can read is not open source |

---

## AUTONOMOUS_READY: **NO**

Four critical gates fail. §216 is explicit that any critical gate failure means
`AUTONOMOUS_READY = NO` and that it must not be hidden, so it is stated first and
not qualified.

## Final Status: **AUTONOMOUS_LAB**

Not `NOT_READY`: the decision authority is complete, tested adversarially,
documented, and correct in every case the suite can construct. Not
`AUTONOMOUS_BETA`: that word requires a beta, and there has not been one. Not
`AUTONOMOUS_PRODUCTION_CANDIDATE`: that requires measured false-block evidence
and a path from a decision to a real firewall rule, and neither exists.

`AUTONOMOUS_LAB` is what the evidence supports: a system that can decide
autonomously, in a lab, with its enforcement half structurally confined there.

---

## The Direct Questions

| Question | Answer |
| --- | --- |
| Human approval required for individual traffic decisions | **NO** |
| Human approval required for temporary block | **NO** |
| Human approval required for unblock | **NO** |
| Human approval required for automatic technical rollback | **NO** |
| Can a model bypass PolicyGuard | **NO** |
| Can ML rewrite hard safety policy | **NO** |
| Can blocked traffic become automatic training truth | **NO** |
| Can the autonomous system perform hack-back | **NO** |

One clarification on the second and third rows, because the bare answers would
mislead: no human approves a temporary block or an unblock, **and** on a
production host the block reaches no real firewall. The autonomy is real; the
enforcement is lab-confined.

---

## What a Second Clean-checkout Validation Would Show

§218 asks for `git diff --stat`, and it is unavailable: **the project has never
been under version control.** There is no `.git` directory, so there is no diff,
no history, and (the one silver lining) no secret can be in any history.

Initialising version control is recorded below as a release blocker, and it is
also the reason the second full validation from a clean checkout could not be
run: there is nothing to check out. What was run instead, twice, is the complete
suite from the working tree, before and after the documentation changes, with
identical results.

### Final Test Counts

```
2,074 tests collected
2,044 passed, 30 skipped, 8,365 subtests passed
ruff: all checks passed
scripts/security_scan.py: exit 0
```

The 30 skips are all "research dataset/artifacts are not distributed in the
source archive" and one namespace-lab guard.

### New in P15

```
eye_for_an_eye/autonomy/__init__.py          71   the three principles
eye_for_an_eye/autonomy/cost.py             246   cost profiles, cutoffs
eye_for_an_eye/autonomy/evidence.py         190   ten signal families
eye_for_an_eye/autonomy/uncertainty.py      245   conservative estimate, expected loss
eye_for_an_eye/autonomy/record.py           642   decision record, reason codes, assumptions
eye_for_an_eye/autonomy/breakers.py         566   budget and three circuit breakers
eye_for_an_eye/autonomy/authority.py        582   the algorithm
eye_for_an_eye/autonomy/runtime.py          491   readiness gate, degrade, recover
eye_for_an_eye/autonomy/evaluation.py       442   rare-class metrics for the decision
eye_for_an_eye/autonomy_cli.py              389   readiness/status/policy/explain/science/enable

tests/test_p15_autonomy.py                  698   88 tests
tests/test_p15_invariants.py                463   45 tests, the fourteen invariants
tests/test_p15_science.py                   546   54 tests
tests/test_p15_runtime.py                   400   36 tests
tests/test_p15_docs.py                      244   25 tests

docs/AUTONOMOUS_MODE.md                           what it means, how to enable
docs/AUTONOMOUS_DECISION.md                       the algorithm, gate by gate
docs/COST_SENSITIVE_POLICY.md                     why the cutoff is not 0.5
docs/DECISION_UNCERTAINTY.md                      the conservative estimate
docs/AUTONOMOUS_FAILURE_RECOVERY.md               brakes, safe mode, recovery
docs/AUTONOMOUS_SAFETY_INVARIANTS.md              the fourteen
docs/AUTONOMOUS_DATA_CURATION.md                  labels, collapse, leakage
docs/SCIENTIFIC_BASIS.md                          source/interpretation/component/limitation
docs/MODULE_GRADUATION.md                         the §3 classification
reports/P15_BASELINE.md                           the §2 baseline
```

### Changed in P15

```
eye_for_an_eye/config.py          + AutonomyConfig, + validation, redaction
eye_for_an_eye/cli.py             + the `autonomy` command
dataset/schema.py                 + feature_family, privacy, source, model_usage
datasets/model_features_v1.json   regenerated (also picked up P12's `domain`)
docs/SCHEMA_COMPATIBILITY.md      + three P15 version constants
docs/P0_P12_STATUS.md             + P14 and P15 sections
README.md                         + "Working automatically", status rows, links
CHANGELOG.md                      + P14 and P15 entries
```

---

## Release Blockers (Owner Action, Carried Forward)

1. **No LICENSE file.** Source you can read is not open source. Gate J fails on
   this alone.
2. **No private security reporting channel.** `SECURITY.md` exists; a monitored
   address or process does not.
3. **Not under version control.** No history, no diff, no attribution, no
   bisect, and no way to do a clean-checkout validation.

Also outstanding from earlier stages: third-party PDFs sitting in the project
folder, and a decision about the Russian-language files in `docs/history/`.

---

## What Would Move This to AUTONOMOUS_BETA

In order, and none of it is code:

1. Run in shadow on one real site for weeks, and read the decisions.
2. Produce a trusted labelled evaluation of the **final decision**, reviewed
   outcomes, a signed capture with a sidecar, or a controlled scenario, large
   enough to clear the 500-benign / 50-positive minimum.
3. Measure block precision and false blocks per 1000 benign sources against it.
4. Then, and only then, consider whether a host-namespace enforcement path is
   worth writing.

The decision half is built. What it is missing is not more code. It is
evidence, and evidence comes from deployment.

---

## Closing

The system does not think *"AI score high, therefore block."* It asks what the
source did, how many independent signals agree, whether the data is complete,
whether the client identity is reliable, whether the traffic is inside the known
distribution, whether the model is healthy, how uncertain the estimate is, what a
false block costs here, what allowing costs, whether the advantage survives the
uncertainty, and whether PolicyGuard permits it. Only then: ALLOW, or TEMP_BLOCK.

Unknown is not malicious. Anomaly is not malicious. OOD is not malicious. Drift
is not malicious. A bot is not automatically malicious. A high ML score is not
proof. A blocked source is not ground truth. A challenge failure is not ground
truth. An IP is not a person. Accuracy is not enough. AUC is not enough. More AI
is not automatically better. More training data is not automatically better.

Autonomy is not the removal of safety controls. Autonomy means the safety
controls themselves operate automatically, and this stage built those controls
first, which is why the answer to `AUTONOMOUS_READY` is `NO` and why that answer
is the honest one.
