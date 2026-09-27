# P15.2 DECISION RELIABILITY CLOSURE REPORT

**Date:** 2026-09-12
**Cycle:** P15.2 — decision calibration, generalization and false-positive closure
**Predecessor:** [P15_1_FINAL_REPORT.md](P15_1_FINAL_REPORT.md), unedited

P15.1 ended with a defender that blocked nothing at all. P15.2 found two reasons
for that, not one, repaired both, and measured the result on a corpus no decision
was tuned against.

**The decision layer now works.** On the locked test it blocked 22 malicious
sources and **zero** of 565 benign ones. Block precision 1.0. False blocks per
1000 benign: 0.0, with a 95% upper bound of 5.31 from the rule of three, because
observed zero is not proven zero.

**It does not generalise.** On the four scenario families no fitted component has
ever seen, recall is **0.000**. Nothing false was blocked there either, so this
is a limit on usefulness rather than on safety — but it is a limit, it is the
thing §5 made a first-class problem, and no policy written before the test says
it is acceptable.

So Gate E passes and Gate C does not.

**Baseline commit:** `0dc93ba` (P15.1 handover note)
**Freeze commit:** `ef7aa3f` — the locked test had not been scored by anything in it

---

## Trusted dataset

Four corpora from one scenario matrix, separated by a seed salt that enters every
scenario seed and the source-address shuffle. No scenario seed and no run index
is shared between any two of them.

| Role | Corpus | Salt | Rows | Sources | SHA-256 (head) |
| --- | --- | --- | --- | --- | --- |
| development | `dataset-eval-v1` | *(none)* | 7,581 | 709 | `00ad973cf396` |
| calibration | `dataset-cal-v1` | `p15.2-calibration` | 7,580 | 709 | `cf3815ec3b05` |
| calibration 2 | `dataset-cal2-v1` | `p15.2-calibration-2` | 7,522 | 709 | *(in the freeze record)* |
| **locked test** | `dataset-test-v1` | `p15.2-locked-test` | 7,568 | 709 | `1871d6e2e67e` |

Full manifests, per-family counts, time ranges, feature schema versions and
cross-corpus duplicate counts: `reports/P15_2_EVIDENCE_FREEZE.json`, written
before anything was fitted.

**Sources (locked test):** benign **565**, malicious **144**, windows **7,568**
before exclusions and **7,421** scored.
**Scenario families:** 27 — 13 benign (6 of them hard negatives) and 14 malicious.

Excluded from the locked test: 4 rows whose feature vector appears under both
labels, and **143** rows bit-identical to a window in a corpus something was
fitted on (§96). Dropping those can only lower a score; keeping them would have
made the test easier in exactly the direction that flatters a memorising model.

**Final locked test untouched before freeze:** **YES.** It was generated, its
manifest was recorded, and it was not scored, inspected or replayed until after
`ef7aa3f`.

**Aggregation:** **max over a source's windows.** Not chosen for the metric —
chosen because it is what the runtime does. Windows arrive one at a time, each is
decided on its own, and a source is blocked the moment any window crosses. A mean
would describe a system that waits for the whole session and then decides on the
average, which would flatter a scanner that is loud once and quiet afterwards.
Detection time is measured from the first window that crossed, so nothing later
is consulted (§57).

**Prevalence:** 0.203 malicious by source in this corpus. That is not a public
website's prevalence and the report does not claim it transfers — see *Cost and
prevalence* below.

---

## ROOT-CAUSE ANALYSIS

### P15.1 units bug

The cost-sensitive cutoff is `C_FP / (C_FP + C_FN)`: the *probability* of
maliciousness at which blocking becomes the cheaper error. The value compared
against it was `MathRisk`, an uncalibrated heuristic score on its own scale. Both
are floats in [0, 1]; nothing at the call site said which quantity was which; the
comparison had no meaning in either direction.

P15.1 diagnosed it and made `CALIBRATION_UNAVAILABLE` a hard gate rather than
lowering the cutoff. P15.2 supplies the missing quantity and makes the
substitution unrepresentable: `eye_for_an_eye/decision/scores.py` gives every
number on the path a type carrying its semantics, and `require_probability`
accepts only `CalibratedProbability`. It refuses a bare `float` as firmly as it
refuses a `RiskScore`, because the bug was never somebody passing the wrong
wrapper — it was a float arriving from a fallback branch with nothing to mark it.

### Decision-ranking degradation cause

Measured by ablation on the development corpus, one transformation at a time:

| Stage | window ROC-AUC | source ROC-AUC | median | fraction exactly 0 |
| --- | --- | --- | --- | --- |
| `math_risk` raw | 0.775 | 0.827 | 0.0347 | 0.000 |
| `model_score` raw | 0.828 | 0.911 | 0.0816 | 0.000 |
| `anomaly_score` raw | 0.782 | 0.652 | 0.3312 | 0.146 |
| after shrinkage only | 0.712 | 0.791 | 0.0247 | 0.000 |
| after the sampling-width term only | 0.661 | 0.815 | 0.0000 | **0.644** |
| conservative, calibration assumed | 0.643 | 0.802 | 0.0000 | 0.699 |
| conservative, 500+ observations assumed | **0.765** | **0.826** | 0.0188 | 0.000 |
| full conservative estimate | 0.615 | 0.772 | 0.0000 | 0.750 |
| **the decision variable as shipped** | **0.626** | **0.783** | 0.0000 | 0.726 |

Spearman against raw `MathRisk`: shrinkage-only **0.873**, width-only **0.403**,
the shipped decision variable **0.308**.

The width term is the rank destroyer, and the row that names the cause is the
one that assumes 500+ observations: with the observation count taken out of the
width, the conservative estimate returns to raw `MathRisk`'s ordering (0.765 /
0.826). Every point of lost discrimination was the width term's dependence on
how many packets happened to be in the window.

**Why that was wrong.** A Wilson correction bounds a proportion estimated from
`n` observations. The proportion here is P(malicious | evidence); its sample size
is the number of *calibration examples* supporting the estimate — thousands. The
code used `observations`, the packets in the window — tens. The interval was two
orders of magnitude too wide.

### A second cause, which calibration alone would not have fixed

The shrinkage and the cost cutoffs were chosen independently and are
arithmetically incompatible. At a probability of **exactly 1.0**:

| total uncertainty | highest reachable conservative estimate | clears |
| --- | --- | --- |
| 0.00 | 1.000 | everything |
| 0.02 | 0.980 | admin, honeypot, public_website |
| 0.05 | 0.951 | admin, honeypot |
| 0.15 | 0.853 | honeypot |
| 0.30 | 0.706 | honeypot |
| **0.60** — the value the gates permit | **0.412** | **nothing** |

A realistic mature window on this corpus, with calibration available, carries
total uncertainty 0.115 and reaches **0.854** at p = 1.0 — below `public_website`
at 0.9756 and `api` at 0.9877. No evidence, however strong, could clear both the
uncertainty gate and the cost cutoff. This is written down separately from the
units error because folding the two together would make the second invisible.

**The repair.** A validated calibrator carries its own Wilson lower bound over
its own fitting sample — `conservative_knots`, equal-count score bands, made
non-decreasing by a running maximum. The cost comparison uses that bound. The
legacy shrinkage still governs every uncalibrated decision, and an uncalibrated
decision cannot block at all because `calibrated_estimate` gates above the
arithmetic. Nothing was weakened: a better-founded bound was added to a path that
previously had none. Every record carries both numbers and a `bound_source`
field.

### Classifier generalization problem

P15.1 reported the shipped classifier at ROC-AUC **0.517** on withheld scenario
families and read it as "the classifier does not generalise at all". That number
is real and it is about a different corpus. `risk-logreg-v1` was trained and
evaluated on `synthetic-behavior-v3`, whose 30 scenario names (`backup_client`,
`cdn_origin_fetch`, `reverse_proxy`, `software_updater`, …) do not appear in
today's generator registry at all.

Scored against the calibration corpus — an entirely different corpus built by a
later generator — the same artifact reaches **0.914 per source** (0.833 per
window). Both numbers are true. P15.1 quoted only the discouraging one, and this
report corrects that.

What P15.2 measured directly is more damning for *retraining*, not for the
shipped model. Refitting the same family on the development corpus:

| Candidate | seen window / source | **unseen window / source** |
| --- | --- | --- |
| A — logistic regression, refit (C = 0.1, grouped CV 0.894) | 0.992 / 0.996 | **0.098 / 0.480** |
| A2 — gradient boosting, bounded | 0.998 / 1.000 | **0.323 / 0.521** |
| B — `MathRisk`, deterministic | 0.774 / 0.798 | 0.748 / 0.926 |
| C — `MathRisk` + classifier fusion | 0.879 / 0.918 | 0.907 / 1.000 |
| shipped classifier | 0.817 / 0.898 | 0.912 / 0.999 |
| reference — P15.1 decision variable | 0.699 / 0.845 | **0.304 / 0.424** |

Candidate A scores **0.098** on unseen families — materially *anti-correlated*,
ranking unseen malicious below unseen benign. A2 has the same disease in a
different model family, which answers §27's question: it is the data, not the
model family. Retraining on this corpus produces scenario memorisation, and the
evidence for that is strong enough that no retrained model was promoted.

Note also the reference row: the P15.1 decision variable itself scores 0.424 per
source on unseen families — worse than chance.

### Leakage found

**YES**, and it was excluded rather than tolerated.

* 143 locked-test rows were bit-identical to a window in a corpus something was
  fitted on. Dropped.
* 4 locked-test rows carry a feature vector that appears under both labels.
  Dropped — ground truth does not exist at that resolution.
* Group separation verified: no source group appears in two splits of any
  corpus, and no scenario seed or run index is shared between corpora.
* Provenance exclusion re-verified: the model feature list is the production
  one, which excludes `source_type`, scenario id, capture id, site id, domain,
  address, source hash and label source by construction rather than by a list
  anybody maintains.
* `site_group` is `None` for every row in every corpus, so §61's per-profile
  breakdown **cannot be produced from this evidence**. Stated rather than
  approximated.

---

## CANDIDATES

Measured on the calibration corpus, which no candidate was fitted on. Source
level, all families:

| Candidate | ROC-AUC | PR-AUC |
| --- | --- | --- |
| `MathRisk` (B) | 0.821 | 0.819 |
| shipped classifier | 0.914 | 0.840 |
| current old fusion (P15.1 decision variable) | 0.769 | 0.691 |
| A — logistic refit | 0.919 | 0.885 |
| A2 — gradient boosting | 0.934 | 0.819 |
| C — `MathRisk` + classifier | 0.928 | 0.855 |

**Selected architecture: B — calibrated `MathRisk`, isotonic.**

**Why**, against §64's criteria rather than by best PR-AUC:

* **Generalisation.** B is the only candidate whose seen and unseen numbers are
  close (0.798 / 0.926 per source). A and A2 collapse. C and the classifier
  score well but their unseen numbers are measured on families the *classifier*
  has also never seen under any name, so they are not the clean comparison they
  look like.
* **Gate C passability.** The classifier's own quality gate is `false`, and §27
  says do not promote it. ONNX parity cannot be run at all: the corpus
  `test_p8_onnx_parity.py` compares against is not committed, so 8 tests skip.
  A probability path that runs through that artifact inherits both problems.
  `MathRisk` is pure Python, so parity is Python-to-Python and exact.
* **Simplicity and explainability.** `MathRisk` is deterministic with no learned
  weights, every term inspectable. The calibrator is a 44-knot monotone table.
  Nothing in the probability path can memorise a generator because nothing in it
  is fitted to features at all.
* **Coupling.** A calibrator for `MathRisk` declares an empty `model_version` and
  is compatible with any model, because `MathRisk` has no weights that can be
  retrained under it. A classifier calibrator is bound to one model version and
  becomes `CALIBRATION_UNAVAILABLE` the moment that model changes.
* **Latency.** p95 of 0.009 ms, against 0.018 ms for `MathRisk` itself.

§71 and §72 anticipate this exactly: no supervised candidate generalises well
enough to be forced into production, a calibrated deterministic model does the
job, and ML stays auxiliary. `MathRisk` itself is unchanged — §17 — and
`P(malicious | MathRisk)` is a different value with a different name.

The cost is recall: the classifier route reached 0.303 on the development
holdout against B's 0.152, at the same zero false blocks. That is a real
sacrifice, made for a gate the classifier route could not clear, and it is
recorded here rather than smoothed over.

---

## CALIBRATION

**Probability source:** `math_risk`
**Calibration method:** isotonic (pool-adjacent-violators), with a sigmoid fitted
and compared
**Calibration dataset:** `dataset-cal-v1` + `dataset-cal2-v1`, 15,097 windows,
3,580 positive. Two corpora because the bound's width is set by how many examples
land in each score band; one corpus produced a bound of 0.9724 against a cutoff
of 0.9756, refusing confident detections by a hair of interval width. The answer
to an interval that is too wide is more examples, not a lower cutoff. The locked
test was not consulted before that decision.
**Quality holdout:** the development corpus's validation and test buckets, 3,432
windows — fitted on by nothing.

| | Brier (holdout) | ECE (holdout) | Brier (in-fold) | ECE (in-fold) |
| --- | --- | --- | --- | --- |
| sigmoid | 0.1152 | 0.0766 | 0.1070 | 0.0807 |
| **isotonic** | **0.1058** | **0.0182** | 0.0968 | 0.0002 |

Isotonic wins out of fold as well as in fold, which is the comparison §36 asks
for. The sigmoid's reliability table shows the logistic shape is simply wrong
here: it claims 0.44 where 0.72 is observed, and 0.56 where 1.00 is observed.

**Reliability** (isotonic, holdout): monotone across all ten bins, with the top
bin holding 242 windows at a claimed 0.988 against an observed 1.000.

**Discrimination before and after** (§37): window ROC-AUC 0.773 → 0.800. A
monotone map cannot reorder anything; the small gain is isotonic pooling of
ties. Calibration destroyed no ranking.

**Calibration/runtime parity: PASS.** Max absolute difference between the
in-memory artifact and the same artifact reloaded from JSON the way production
loads it: **0.000e+00** over 3,000 windows, on both the probability and the
bound. Digest stable across the round trip. `MathRisk` across freshly
constructed engines: **0.000e+00**. There is no ONNX in the probability path.

**Probability semantics: VALID**, with the boundary stated: the estimate is
calibrated for the prevalence it was fitted at, and the interval bounds sampling
error in the calibration data and nothing else.

---

## GENERALIZATION

Locked test, source level:

| | benign sources | positive sources | recall | false blocks / 1000 | block precision |
| --- | --- | --- | --- | --- | --- |
| **seen families** | 414 | 120 | **0.183** | 0.0 | 1.000 |
| **unseen families** | 151 | 24 | **0.000** | 0.0 | undefined |

**Worst positive scenario:** `credential-low-rate` (unseen) — 6 sources, 0
blocked. Its maximum calibrated probability is **1.000** and its maximum
conservative bound is **0.9724**, against a cutoff of 0.9756. The system ranks it
correctly and the interval refuses it by 0.0032.

**Worst benign scenario:** `hard-negative-monitoring` — 26 sources, 946 windows,
0 blocked, maximum bound 0.107. There is no benign family under strain anywhere.

**Hard negatives** (six families, 229 sources, all benign, all scored): 0 blocked.
The two that come closest are `hard-negative-admin` (unseen, 105 sources) and
`hard-negative-deception`, both at a maximum bound of **0.9443** — below the
cutoff with real margin, on the unseen side included.

**Hard positives:** `deception-enumeration` 8/8, `recon-multi-stage` 8/8,
`credential-automation` 6/6 — all at 100% of sources. `scan-slow` 0/8,
`credential-low-rate` 0/6, `scan-burst` 0/10, `probe-repeated` 0/8,
`probe-truncated` 0/8, `scan-horizontal` 0/12.

`scan-horizontal`, `probe-repeated` and `probe-truncated` top out at a bound of
0.102–0.143: `MathRisk` genuinely cannot see them. The rest reach 0.9724 or
0.9949 and are refused by a gate, not by the probability — see below.

---

## FINAL SOURCE-LEVEL DECISION

Locked test, `dataset-test-v1`, scored once.

| | ALLOW | TEMP_BLOCK |
| --- | --- | --- |
| actual benign | 565 | **0** |
| actual malicious | 122 | **22** |

**N benign:** 565
**N positive:** 144
**Prevalence:** 0.2031
**TEMP_BLOCK total:** 22
**True TEMP_BLOCK:** 22
**False TEMP_BLOCK:** 0
**Precision:** 1.000
**Recall:** 0.1528
**Specificity:** 1.000
**FPR:** 0.000
**FNR:** 0.8472
**PR-AUC:** 0.8009
**ROC-AUC:** 0.8598
**Block precision:** 1.000
**False blocks / 1000 benign:** 0.0
**Expected loss:** every block was correct, so the realised false-block cost is
0 × C_FP. The realised false-allow cost is 122 × C_FN = 122 units against a
theoretical floor of 0 and an allow-everything baseline of 144.

**Bootstrap intervals** — 2,000 resamples, resampling unit **source group**, never
windows (§47), because forty windows of one scanner are one piece of evidence:

| | 2.5% | 97.5% |
| --- | --- | --- |
| recall | 0.0966 | 0.2109 |
| false positive rate | 0.000 | 0.000 |
| block precision | 1.000 | 1.000 |
| false blocks / 1000 benign | 0.000 | 0.000 |

**Zero events, bounded honestly (§48).** No false block was observed on 565
benign sources. The rule of three gives a 95% upper bound of **0.0053**, or
**5.31 false blocks per 1000 benign sources**. Observed zero is not proven zero
and is not reported as such anywhere in this document.

**Detection time (§56, §57):** of the 22 detected sources, the first block came
after a median of **2 windows** and **29.3 seconds** of observation (min 1 window
/ 15.9 s, max 4 windows / 47.5 s). Only evidence available at that window was
used. **0 benign sources were blocked at any point**, which is also §58's answer:
long-running legitimate automation did not accumulate its way into a block.

**NON_DEGENERATE_DECISION_GATE: PASS** — 22 blocks, 22 correct, 0 false, recall
0.153. Neither trivial system could have reached this: allow-all fails on
`true_blocks == 0` before the false-block ceiling is consulted, and block-all
fails on `false_positive_rate >= 1`.

---

## WINDOW-LEVEL DIAGNOSTICS

Reported separately and never mixed with the table above.

| | ALLOW | TEMP_BLOCK |
| --- | --- | --- |
| actual benign | 5,636 | 0 |
| actual malicious | 1,616 | 169 |

Benign 5,636; positive 1,785; prevalence 0.2405; precision 1.000; recall 0.0947;
specificity 1.000; FPR 0.000; FNR 0.9053; block precision 1.000; false blocks per
1000 benign 0.0.

Window recall (0.095) is lower than source recall (0.153) and that is the correct
relationship: a scanner is blocked on the window where the evidence arrives, and
its earlier quiet windows are correctly allowed. Gate C and Gate E are judged at
the **source** level, because that is what a block applies to.

**The separation at the cutoff is clean.** 392 windows produced a conservative
bound at or above 0.9756. **All 392 were malicious. None was benign.**

---

## COST POLICY

**Cost profiles unchanged: YES.** `public_website` 40.0, `api` 80.0,
`payment_webhook` 500.0, `admin` 8.0, `honeypot` 2.0, all against `C_FN = 1.0`.
Pinned by `tests/test_p15_2_decision.py`.

**Any threshold manually lowered to get PASS: NO.** Every `DecisionGates` value,
every cost profile and all four `ReleaseThresholds` are at their P15 values, and
three separate tests assert it. The cutoff is still `C_FP / (C_FP + C_FN)`,
derived rather than tuned, and it was not touched until the probability that
feeds it existed.

**Decision margin:** unchanged. Its effect is visible in the gate table below as
`MARGIN_NOT_MET`, which appears on no window that cleared the cutoff on the
locked test — the margin is not what is limiting recall.

**Gate effects (§51, §52)**, counted over the 392 windows whose bound cleared the
cutoff, which is the only population a gate can be said to have stopped:

| Gate | true-positive windows suppressed | false-positive windows prevented |
| --- | --- | --- |
| `INSUFFICIENT_SIGNAL_DIVERSITY` | **196** | 0 |
| `ASSUMPTION_FAILED` (window maturity) | 43 | 0 |
| `INSUFFICIENT_OBSERVATION_TIME` | 30 | 0 |
| `INSUFFICIENT_OBSERVATIONS` | 18 | 0 |

Read that honestly: on this corpus the evidence-diversity gate is the single
largest brake on recall and it prevented **zero** false blocks, because no benign
window ever reached the cutoff for it to stop. It was kept anyway. §51 and §52
say measure the effect and do not remove the gate to raise recall, and the reason
holds independently of this corpus: "the maths agreed with itself" is not three
independent witnesses, and this corpus is not the Internet.

`scan-connect`, `scan-randomized` and `scan-sequential` all reach a bound of
0.9949 — above the cutoff — and are blocked on no source. The diversity gate is
why.

**DataQuality-gate effect:** no window that cleared the cutoff was refused for
data quality; the gate's work happens earlier, in the maturity rows above.

**OOD-gate effect:** no window that cleared the cutoff was refused as out of
distribution. 94.8% of development windows scored `IN_DISTRIBUTION` and the rest
`BORDERLINE`; none was `OUT_OF_DISTRIBUTION`. OOD raises uncertainty and reduces
model authority; it never raises malicious probability (§22), and a test asserts
that higher OOD cannot make blocking easier.

**Prevalence sensitivity (§38, §39)** — analysis only, no label altered, no
artifact refitted. Applying a prior correction on the odds scale to the holdout:

| assumed prevalence | median probability | windows ≥ 0.9756 |
| --- | --- | --- |
| 0.20 (this corpus) | 0.0974 | 175 |
| 0.05 | 0.0222 | 158 |
| 0.01 | 0.0043 | 141 |
| 0.002 | 0.0009 | 125 |

The top of the range survives a hundred-fold reduction in assumed prevalence:
125 windows still clear the `public_website` cutoff at 0.2% prevalence. The
median collapses, as it should. **The calibrated probability is calibrated for
the prevalence it was fitted at and this report does not claim it is universally
valid** — but the detections it produces are not an artifact of a convenient base
rate.

---

## MODEL PACKAGE

**Active model (probability authority):** none. `MathRiskEngine`, `math-risk-v1`,
deterministic, no learned weights.
**Calibrator:** `models/mathrisk-cal-v1-isotonic.json` — isotonic, source
`math_risk`, `model_version` empty (model-independent by construction), 15,097
samples / 3,580 positive, 1,434 knots, 44 conservative knots, 60,113 bytes.
**Hash:** `9b18fee8b6245617278feb305d083d29bd0f48e74adf741a67fd53b7d6fcf2a6`
**Feature schema:** 1 — 18 behaviour features and 18 availability masks.
**Distribution reference:** `models/risk-logreg-v1-distribution.json`, used for
the OOD gate only; it cannot raise a probability.
**Model manifest:** `risk-logreg-v1` remains the shipped classifier, in shadow.
Its manifest is unchanged: `quality_gate_status: PROVISIONAL`,
`quality_gate_passed: false`, `recommended_mode: shadow`,
`recommended_shadow_only: true`, `threshold_authority: DecisionFusion and
PolicyGuard`.
**ONNX parity:** `NOT_RUN` for the classifier — 8 tests skip because the corpus
they compare against is not committed. Unchanged since P15, and it no longer
gates the decision, because the classifier holds no probability authority.
**Quality gate (classifier): FAIL**, and it was not promoted.
**Recommended mode:** the classifier stays shadow/auxiliary. The calibrated
deterministic path carries the probability.

Three other calibrators were fitted and are committed for comparison:
`mathrisk-cal-v1-sigmoid`, `classifier-cal-v1-sigmoid`,
`classifier-cal-v1-isotonic`. None is referenced by the frozen candidate.

---

## ENFORCEMENT REGRESSION

Re-run as root against a real kernel, `nft` v1.0.9, after every decision-layer
change.

**Real-kernel enforcement tests: 61 passed**, plus 48 security-invariant tests in
the same run — **109 passed, 51,587 subtests, 0 failed**. `nft list ruleset` is
empty afterwards; no veth or namespace left behind.

**veth real connection test: PASS** — a real TCP connection completes, stops when
the block goes on, and completes again when it comes off.
**TTL: PASS** — 12-hour ceiling unchanged, kernel timeout on every element.
**Management safety: PASS.**
**Proxy/CDN safety: PASS** — `HOST_NETWORK` remains the only scope, and a record
that is not network-enforceable still cannot produce a request.
**Mass-block breaker: PASS.**

No enforcement code was redesigned. §75 and §76 satisfied.

One measurement change worth naming: the replay now advances the authority's
clock by 60 s per window. The block budget is a rate limit, and a replay that
puts thousands of windows through it in a few seconds of wall clock spends it on
the tenth block — `BLOCK_BUDGET_EXHAUSTED` appeared on 745 of 863 malicious
windows in the development holdout. That measured the harness rather than the
system. The budget is not disabled, and it appears in the gate table when it
binds.

---

## RELEASE GATES

| Gate | Verdict | Evidence |
| --- | --- | --- |
| **A — Module graduation** | **PASS** | the new modules classified: `decision/scores` and `decision/calibration` are SAFE_TO_PRODUCTIONIZE (they hold no privilege and take no action), `training/` remains offline measurement. The dangerous class is still empty and the enforcement classifications are untouched |
| **B — Data quality** | **PASS** | four group-aware corpora, no source in two splits, 143 duplicate rows excluded from the locked test, provenance exclusion re-verified, the self-label loop still structurally impossible. 19 replay-harness tests plus 63 new ones |
| **C — ML validity** | **FAIL** | probability semantics correct, calibration valid, parity exact, no leakage, quality gate applied — and **unseen-scenario recall is 0.000**. §70's last condition is that hard scenario results are acceptable *under explicit policy*, and no policy written before the test says zero detection on novel behaviour is acceptable. Writing one now is what §66 and §74 forbid |
| **D — Cost decision** | **PASS** | the cutoff is still derived from an explicit per-profile cost policy, never 0.5, with a content digest in every record — and it is now applied to the quantity it was always defined over |
| **E — False-positive safety** | **PASS** | §73's five conditions, all met: block precision **measured** at 1.000; false blocks per 1000 benign **measured** at 0.0 with a rule-of-three upper bound of 5.31; detection non-degenerate (22 true blocks, `NON_DEGENERATE`); hard negatives tested (6 families, 229 sources, 0 blocked); uncertainty reported by source-group bootstrap |
| **F — Site / proxy safety** | **PASS** | unchanged and re-asserted. A per-profile breakdown could not be produced — `site_group` is `None` throughout the corpora — and that is stated rather than approximated |
| **G — Enforcement** | **PASS** | 109 real-kernel tests, ruleset clean, no redesign |
| **H — Autonomous recovery** | **PASS** | unchanged; degrade, safe mode, cooldown, health gate and resume all still pass |
| **I — Resource safety** | **PASS** | the calibrator adds a 60 KB read-only table and no state at all: p95 0.009 ms, peak RSS 40.3 MiB for 3,000 windows. Nothing unbounded was introduced (§118) |
| **J — Repository / documentation** | **PASS** | five science pages updated with a precise account of both root causes; a P15-era doc test that pinned a caveat which had stopped applying to the whole page was rewritten to pin both halves rather than the page reverted |

### AUTONOMOUS_READY

**NO.** §121 permits no exceptions, and Gate C fails.

### Final status

**AUTONOMOUS_LAB.**

Not `AUTONOMOUS_BETA`: still no evaluable beta evidence.
Not `AUTONOMOUS_PRODUCTION_CANDIDATE`: Gate C fails.

The status is unchanged from P15.1 and the system underneath it is not. P15.1's
defender could not block anything for any reason. This one blocks 22 of 144
malicious sources with perfect precision, zero false blocks on 565 benign
sources, and a median detection time of 29 seconds — and it cannot yet be shown
to do anything at all about behaviour it has not seen before.

### P16_PROD_ASSEMBLY_READY

**NO**, because §122 ties it to `AUTONOMOUS_READY`.

---

## Remaining blockers

1. **Unseen-scenario recall is 0.000.** The blocker. Three of the four withheld
   families rank at the top of the range — `credential-low-rate` reaches a
   calibrated probability of 1.000 — and are refused by an interval 0.0032 too
   wide, or by the diversity gate. The fix is more calibration evidence in the
   upper bands and more *behavioural* evidence in those families, not a lower
   cutoff.
2. **The evidence-diversity gate suppressed 196 true-positive windows and
   prevented 0 false positives** on this corpus. It was kept, correctly. Whether
   requiring two behavioural families is the right bar is a question for
   deployment evidence, and this corpus cannot answer it.
3. **`MathRisk` cannot see three malicious families at all** — `scan-horizontal`,
   `probe-repeated`, `probe-truncated` top out at a bound of 0.102–0.143. A
   deterministic engine has a ceiling, and this is it.
4. **Per-site and per-profile results could not be produced.** `site_group` is
   `None` for every row. §61 and §63 cannot be answered from this evidence.
5. **ONNX parity remains NOT_RUN** for the classifier. It no longer gates the
   decision, and it will gate any future attempt to give ML probability
   authority.
6. **Calibration is fitted at 20% prevalence.** The top of the range survives a
   correction to 0.2%, the median does not, and no deployment has been measured.
7. Unchanged from P15.1: beta evidence `BETA_REPORTED_BY_OWNER`; private security
   reporting prepared but not enabled; firewalld and Docker coexistence untested;
   live capture under systemd, `CAP_NET_RAW`, arm64, Windows and multi-hour soak
   all still NOT_MEASURED; owner decisions on reference PDFs, agent instruction
   files and OTF drafts outstanding.

---

## TESTS

**passed:** 2,160 (development tree, as `e4etest` with `umask 022`)
**failed:** 0
**skipped:** 64
**subtests:** 56,984

Plus, as root against a real kernel: **109 passed, 0 failed, 51,587 subtests**
(`test_p15_1_enforcement.py` + `test_p15_invariants.py`).

New in P15.2: `tests/test_p15_2_scores.py` (31 tests — the units contract, the
artifact loader, monotonicity, the Wilson sample size, numeric safety) and
`tests/test_p15_2_decision.py` (32 tests — the calibrated bound, every restraint,
the cost cutoff, the non-degeneracy gate, and the numbers that were not allowed
to move).

One of those tests found a real defect before it shipped: `min(1.0, nan)` returns
1.0 in Python, so a NaN score was being clamped into total certainty of
maliciousness — the worst possible value. The calibrator now refuses a non-finite
score, and `calibrate()` turns the refusal into `CALIBRATION_UNAVAILABLE` rather
than an exception.

---

## PERFORMANCE

3,000 locked-test windows through the frozen probability path:

| stage | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- |
| `MathRisk` | 0.0131 ms | 0.0178 ms | 0.0381 ms | 0.0729 ms |
| **calibrator** | **0.0066 ms** | **0.0092 ms** | 0.0236 ms | 0.0466 ms |
| decision authority | 0.2214 ms | 0.3191 ms | 0.4421 ms | 0.5696 ms |

**decision p95:** 0.319 ms
**calibration p95:** 0.009 ms — about half of `MathRisk` and 3% of the decision
itself, which is what §117 asks calibration to be
**CPU:** 1.19 s user+sys for 3,000 windows
**RSS:** 40.3 MiB peak

---

## Evidence

### `git status`

```
On branch main
nothing to commit, working tree clean
```

### `git log --oneline -10`

```
7f97b57 P15.2: final report — Gate E PASS, Gate C FAIL, AUTONOMOUS_LAB
741d0d4 P15.2: locked-test result, science docs, and the last schema entry
ef7aa3f P15.2: freeze the candidate before the locked test is read
0dc93ba P15.1: repository handover note
5624d96 P15.1: refresh the git evidence in the final report
12e2a89 P15.1: correct the suite counts in the final report
124d70f P15.1: final report — AUTONOMOUS_LAB, P16_PROD_ASSEMBLY_READY NO
6af8800 P15.1: prove the block stops packets, and make the ranking table reproducible
d3e17fb P15.1: production readiness evidence and enforcement closure
6e0f6fe Initial commit: Eye for an Eye 0.8.0rc1 (P0-P15)
```

Seven commits: P15.1's five, the freeze, and the three P15.2 commits after it.
The listing was taken after this report was committed.

### `git diff --stat 0dc93ba..HEAD`

```
 .gitignore                             |   11 +
 dataset/cli.py                         |   11 +-
 dataset/scenarios/__init__.py          |   33 +-
 docs/AUTONOMOUS_DECISION.md            |   18 +
 docs/COST_SENSITIVE_POLICY.md          |   25 +
 docs/DECISION_UNCERTAINTY.md           |   86 +-
 docs/MODEL_GOVERNANCE.md               |   27 +
 docs/SCHEMA_COMPATIBILITY.md           |    6 +
 docs/SCIENTIFIC_BASIS.md               |   22 +
 eye_for_an_eye/autonomy/authority.py   |   29 +-
 eye_for_an_eye/autonomy/evaluation.py  |   61 +
 eye_for_an_eye/autonomy/uncertainty.py |   60 +-
 eye_for_an_eye/decision/calibration.py |  570 +++
 eye_for_an_eye/decision/scores.py      |  270 ++
 models/classifier-cal-v1-isotonic.json | 3362 ++++++++++++++++++
 models/classifier-cal-v1-sigmoid.json  |  178 +
 models/mathrisk-cal-v1-isotonic.json   | 5926 ++++++++++++++++++++++++++++++++
 models/mathrisk-cal-v1-sigmoid.json    |  190 +
 reports/P15_2_EVIDENCE_FREEZE.json     |  889 +++++
 reports/P15_2_FINAL_REPORT.md          |  710 ++++
 reports/P15_2_LOCKED_TEST.json         | 2249 ++++++++++++
 tests/test_p15_2_decision.py           |  314 ++
 tests/test_p15_2_scores.py             |  279 ++
 tests/test_p15_docs.py                 |   32 +-
 training/calibrate.py                  |  171 +
 training/candidates.py                 |  541 +++
 training/decision_replay.py            |  112 +-
 training/evaluation_design.py          |  330 ++
 training/p15_2_evaluation.py           |  391 +++
 29 files changed, 16870 insertions(+), 33 deletions(-)
```

### The exact evaluation commands

Corpora — the recipe is committed, the traffic is not:

```
python -m dataset generate --matrix dataset/scenarios/matrix-eval-v1.toml \
    --output datasets/cal-v1  --dataset-version dataset-cal-v1  --seed-salt p15.2-calibration
python -m dataset generate --matrix dataset/scenarios/matrix-eval-v1.toml \
    --output datasets/cal2-v1 --dataset-version dataset-cal2-v1 --seed-salt p15.2-calibration-2
python -m dataset generate --matrix dataset/scenarios/matrix-eval-v1.toml \
    --output datasets/test-v1 --dataset-version dataset-test-v1 --seed-salt p15.2-locked-test
```

Freeze record, calibrators, locked test:

```
python -c "from training.evaluation_design import freeze; \
    freeze(out='reports/P15_2_EVIDENCE_FREEZE.json')"
python -c "from training import calibrate; body, fitted = calibrate.build(); \
    [calibrate.write(fitted, s, m) for s in ('math_risk','model_score') \
     for m in ('sigmoid','isotonic')]"
python -c "from training import p15_2_evaluation as P; \
    body = P.run(out='reports/P15_2_LOCKED_TEST.json'); print(P.render(body))"
```

Suites:

```
.venv/bin/python -m pytest tests/ -q                         # as e4etest, umask 022
.venv/bin/python -m pytest tests/test_p15_1_enforcement.py \
    tests/test_p15_invariants.py -q                          # as root, real kernel
.venv/bin/ruff check .
```

Clean clone, fresh venv on `/usr/bin/python3.12`, after the final commit:
**2,136 passed, 88 skipped, 0 failed.** The 24 tests that pass in the
development tree and skip here are the generated-corpus and research-artifact
ones, which is the same difference P15.1 measured. No test depends on anything
outside the clone.

Raw output: `reports/P15_2_LOCKED_TEST.json`,
`reports/P15_2_EVIDENCE_FREEZE.json`.

---

## See also

- [P15_1_FINAL_REPORT.md](P15_1_FINAL_REPORT.md) — unedited
- [P15_2_LOCKED_TEST.json](P15_2_LOCKED_TEST.json) — every number above
- [P15_2_EVIDENCE_FREEZE.json](P15_2_EVIDENCE_FREEZE.json) — the corpora as frozen
- [../docs/DECISION_UNCERTAINTY.md](../docs/DECISION_UNCERTAINTY.md) — the two bounds
- [../docs/COST_SENSITIVE_POLICY.md](../docs/COST_SENSITIVE_POLICY.md) — the cutoff, and twice not being given a probability
- [../docs/MODEL_GOVERNANCE.md](../docs/MODEL_GOVERNANCE.md) — a package includes its calibrator
