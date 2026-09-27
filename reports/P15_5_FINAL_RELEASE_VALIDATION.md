# P15.5 FINAL INDEPENDENT RELEASE VALIDATION

Baseline commit:
`4cf3bc9` — P15.4's HEAD, after the schema-assumption fix. The baseline record is
`reports/P15_5_BASELINE.json`, committed at `b6cb5b2`.

Freeze commit:
`550df02`

Locked test policy:
`reports/P15_5_TEST_POLICY.json`, `p15.5-test-policy-v1`, digest
`d48a6696efd24be35fec6a24230542f3859b1180a8e42ed86363cf98e4012dfe`. Committed
before the locked corpus was generated.

Locked corpus:
`dataset-p15-5-locked-v1`, from `dataset/scenarios/matrix-p15-5-locked-v1.toml`,
seed salt `p15.5-locked`. 749 source groups, 12283 rows, 11811 scored after
dropping 470 duplicates of a fitting corpus and 2 vectors carrying both labels.

Locked corpus hash:
`4aaa00f15d848f5688caa1a5108950a1edb92dca7d8b381ed8b161a5a2ae21bb`

Scored once:
YES. `reports/P15_5_LOCKED_TEST.json` is the only scoring of this corpus. Three
defects found in the *measuring instrument* afterwards were fixed for safety and
the corpus was **not** rescored (§25, §26); they are set out under PRODUCTION
HEALTH below.

--------------------------------
SCHEMA COMPATIBILITY
--------------------------------

Current feature schema:
2 — 23 features, 46 tensor columns.

Supported schemas:
1 and 2, from `decision.features.MODEL_SCHEMAS`. Every consumer now asks
`compatibility.FEATURE_SCHEMA.supports(version)` rather than expressing the
question itself.

Literal schema pins in decision path:
0 of 9 modules. The audit found a third copy of the P15.4 defect that the P15.4
tripwire could not see: `FeatureTransformer.project` read `if schema != 1: raise`
— the one function every model feed passes through. It now resolves the target
order from `MODEL_SCHEMAS`, verified byte-identical to the old implementation
over 300 random vectors. `config.py` pinned the deception catalogue to `!= 2` and
`anomaly.py` pinned the model manifest to `!= 1`; both now ask the contract.

Upgrade simulation:
PASS. `tests/test_p15_5_compatibility.py` registers schema N+1 as a *reordering*
of the current columns — a width check alone would pass a reordering and produce
confident nonsense — and takes a full decision through it to TEMP_BLOCK, with an
unservable schema as the negative control.

--------------------------------
WHOLE-SYSTEM SMOKE
--------------------------------

Normal browser:
PASS — 7 windows, 0 blocked.

Authenticated batch API:
PASS — 12 windows, 168 authentication outcomes through the ledger, 0 blocked.
Both halves are required: not blocked is trivial to achieve by not looking.

Credential spray:
PASS — AUTH_BEHAVIOR 1.0.

Brute force:
PASS — AUTH_BEHAVIOR 1.0, math risk 0.772, and a validated EnforcementRequest.

Scanner/recon:
PASS — math risk 0.828, calibrated 1.0, TEMP_BLOCK, EnforcementRequest built.

AuthLedger wiring:
PASS.

Auxiliary ML wiring:
PASS — one projection function, used by the runtime and by replay.

Calibrator:
PASS — invoked on every window, finite probability, version recorded.

Maturity:
PASS — evaluated for every window; STANDARD_MATURE reached.

PolicyGuard:
PASS.

EnforcementRequest:
PASS — address, TTL 300, decision id, 8 reason codes, and no `command` field in
the serialised value the privileged helper parses.

§41: this is a wiring result. No number in this section is evidence about
detection quality.

--------------------------------
CALIBRATION
--------------------------------

Formula:
`math-risk-v4`, unchanged. `family-scores-v1` and `evidence-composition-v1`
unchanged.

Calibrator:
`mathrisk-cal-v4-isotonic`, sha256
`98a678348623f77368baea00f3ea3161a4cfeea7a16b3af38a6dc9c65d779513` as recorded in
the test policy. Isotonic on the measurement, not by habit: it wins out of fold
on both Brier and ECE, and neither method overfits — both score better out of
fold than in it.

Independent sources:
9072 fitted examples, 3152 positive, twelve corpora — the four from P15.4 plus
eight new ones from an API-enriched matrix. Source unit, not window.

Brier:
0.026227 (sigmoid 0.029005)

ECE:
0.023017 (sigmoid 0.026486)

Maximum conservative bound:
0.994779, from a top score band holding 732 malicious sources and **no benign
source**. It was 0.981951 from 209.

PUBLIC WEBSITE cutoff:
0.975610

API cutoff:
0.987654

API autonomous TEMP_BLOCK:
SUPPORTED.

The plan was committed at `29e3f4c`, before the first of the eight corpora
existed. It predicted 722 top-band sources; the fit produced 732. The target was
600 rather than the arithmetic minimum of 308, because a clean band of 308 clears
the cutoff and a single benign example in it returns the bound to 0.981956 — and
the matrix carries 250 benign API sources per corpus precisely to give that
example every chance. The band came out clean anyway. No cutoff was touched:
0.987654 is the number it has been since P15.1.

--------------------------------
LOCKED EVALUATION
--------------------------------

Benign sources:
546

Positive sources:
203

Seen positive sources:
142

Unseen positive sources:
61

TEMP_BLOCK total:
120

True TEMP_BLOCK:
120

False TEMP_BLOCK:
0

Precision:
1.0

Recall:
0.591133

Specificity:
1.0

FPR:
0.0

FNR:
0.408867

Block precision:
1.0

False blocks / 1000 benign:
0.0

95% upper bound:
5.495 per 1000 benign sources (rule of three after zero events in 546). The
bootstrap over independent source groups gives recall [0.524, 0.661] and false
blocks [0.0, 0.0].

Detection latency:
2 windows median (min 1, max 19); 22.1 seconds of observation median (min 10.2,
max 441.3).

--------------------------------
GENERALIZATION
--------------------------------

Unseen positive recall:
0.540984, against 0.612676 seen. The gap is 0.072 and the unseen sample is 61
sources, so the interval on it is wide; what matters more is that unseen
detection is not zero while seen detection is not, which is the failure mode the
gate exists for.

Worst block-eligible observable family:
Seven at 0.0: `composite-decoy-recon`, `composite-paced-breadth`,
`probe-enumeration`, `probe-repeated`, `protocol-mismatch`, `scan-horizontal`,
`scan-slow`. `probe-repeated` is classified IN_SCOPE_PARTIALLY_OBSERVABLE and is
not counted against Gate C.

Critical zero-detection families:
6 — the list above without `probe-repeated`. This is what fails Gate C, and the
reasons are three different things:

* **The evidence does not reach the bar.** `composite-paced-breadth` (0.925),
  `protocol-mismatch` (0.925), `scan-horizontal` (0.925) and
  `composite-decoy-recon` (0.819) land in bands whose conservative bound is below
  the cutoff they were judged against. `COST_ALLOW_PREFERRED` and
  `MARGIN_NOT_MET` on every window. Not a defect; the cost model declining to act
  on evidence it cannot bound above the threshold.
* **The observation floor.** `scan-slow` reaches a bound of 0.994779 — the top
  band — and is refused by `INSUFFICIENT_OBSERVATIONS` on all 140 windows. This
  is the largest known coverage gap, documented in `docs/LIMITATIONS.md` since
  P15.3, and the floor was not lowered.
* **`probe-enumeration`** at 0.925 with 5 sources, the smallest family in the
  corpus.

Withheld benign result:
`withheld-backup-sweep` — 18 sources, **0 blocked**, maximum conservative bound
0.818836. A nightly backup agent producing breadth, volume, regularity and
persistence at once while authenticating successfully on every service it
touches: the hardest benign case in the corpus and the first honest benign
producer of the `(NETWORK_RATE, PORT_BREADTH)` interaction. It was never in any
fitting corpus.

Withheld positive result:
`withheld-credential-drift` — 14 sources, **14 blocked**, rate 1.0. One valid
credential walked across services: a success, then breadth, then failures from the
principal that just succeeded, single-principal so the strongest authentication
signal is withheld from it. Also never in any fitting corpus.

--------------------------------
PER PROFILE
--------------------------------

**These are outcomes grouped by profile, not outcomes decided per profile.** See
PRODUCTION HEALTH: every decision in this benchmark was priced at the
`public_website` cutoff of 0.975610 regardless of the site it belonged to, because
`replay_sample` passed a constant scope and an unmapped scope resolves to the
default profile. The grouping is still informative — it says where the false
blocks would have landed, and there were none — but the cutoff column below is
the profile's cutoff and *not* the one that was applied.

PUBLIC WEBSITE:
200 sources (142 benign, 58 positive). Recall 0.569, block precision 1.0, 0.0
false blocks per 1000.

API:
267 sources (204 benign, 63 positive). Recall 0.683, block precision 1.0, 0.0
false blocks per 1000.

ADMIN:
191 sources (144 benign, 47 positive). Recall 0.617, block precision 1.0, 0.0
false blocks per 1000.

HONEYPOT:
48 sources (20 benign, 28 positive). Recall 0.536, block precision 1.0, 0.0 false
blocks per 1000.

PAYMENT WEBHOOK:
43 sources (36 benign, 7 positive). Recall 0.0, 0.0 false blocks per 1000.
Predeclared TEMP_BLOCK_NOT_SUPPORTED: the cost policy permits no network block on
this profile at any probability, a decision taken in P15.1. §29 — zero recall here
is the policy working.

--------------------------------
HARD NEGATIVES
--------------------------------

authenticated batch API:
26 sources, 0 blocked, maximum bound 0.029545. §31 holds: the family that
`math-risk-v3` blocked 21 of 22 sources of sits at the bottom of the scale.

service account:
22 sources, 0 blocked, 0.029545.

stale credential:
20 sources, 0 blocked, 0.029545. §32 holds — one principal failing repeatedly for
ten minutes is not treated as credential spray.

admin login mistakes:
26 sources, 0 blocked, 0.029545.

crawler:
20 sources, 0 blocked, 0.029545.

monitoring:
28 sources, 0 blocked, 0.029545.

`hard-negative-batch-api` 18 sources 0 blocked, and `withheld-backup-sweep` 18
sources 0 blocked at 0.818836 — the only benign family anywhere near the scale,
and still nowhere near the cutoff.

--------------------------------
PRODUCTION HEALTH
--------------------------------

Silent component failures:
0 of 7 audited. NOT_CONFIGURED and UNAVAILABLE are now distinct states and are
never merged. `ReplayComponents.open` used to set a failed anomaly load back to
`None` — the value meaning "nobody asked for one" — so a broken artifact and an
absent one produced identical health; that is fixed, a broken reference
distribution reports the same way, and a classifier that loads and then fails
every prediction is reported UNAVAILABLE rather than HEALTHY. The soak confirmed
the rule holds in the live engine too: a default configuration enables the anomaly
model with no artifact and the engine counts `anomaly_model_unavailable_total`.

Assumption-failure suppression health:
PASS. `ASSUMPTION_FAILED` suppressed 252 true-positive windows in this benchmark,
which is the shape P15.4 had, so it was investigated rather than noted. The only
failed assumption anywhere in the run is `minimum_sample_mature` — the documented
observation floor — and it fires on benign and malicious alike: 217 windows of
`hard-negative-connect`, 184 of `hard-negative-admin`, 153 of `benign-web`. §39's
signal agrees: dominant share 0.234 against a threshold of 0.9, state OK. The same
signal reports DEGRADED at share 1.0 on a synthetic reproduction of the P15.4
defect, so it separates the two cases rather than crying wolf on either.

Startup self-check:
PASS. Two synthetic vectors traverse MathRisk, the calibrator and the authority;
the quiet one is allowed and the loud one reaches TEMP_BLOCK, nothing is enforced.
Runs from `doctor` and from the autonomy readiness gate as a critical check.
Wiring only (§41).

Doctor:
PASS, on the clean clone. It also stopped reporting `feature_schema_version: 1`,
which it had said since P15.4 while the schema in force was 2 — an operator-facing
health field stating something false about its own build.

**Three defects in the measuring instrument, found by this benchmark.** None is a
defect in the candidate; all three make a measurement mean something other than it
appears to, which is worse than a wrong number because a wrong number invites
checking. Fixed for safety, corpus not rescored (§25, §26), tests added.

1. **Every decision was priced at the same cutoff.** `replay_sample` set
   `scope='GLOBAL'` and `CostPolicy.scope_profiles` is empty by default, so every
   window of every locked benchmark since P15.1 was decided at `public_website`'s
   0.975610 whatever site it belonged to. The API eligibility question this cycle
   spent eight corpora on was never actually asked at the API cutoff.
2. **The generalisation gate checked the wrong pair** — P15.4's withheld constant
   — so it failed for a bookkeeping reason while P15.5's own pair sat in the same
   results at 0/18 and 14/14. The gate's FAIL in
   `reports/P15_5_LOCKED_TEST.json` is this, not a substantive finding.
3. **The withheld pair counted as `seen`.** `familiarity` reads the training-split
   holdout list, which knows nothing about the `withheld.` prefix, so the only two
   families that had never been near a fitting corpus were excluded from the
   unseen aggregate — understating the number a generalisation claim rests on.

**A fourth finding, larger than the three above, and not a measurement problem.**
`reports/P15_5_BASELINE.json` records it from the call graph rather than from
prose: `DecisionInputs` and `HostEnforcer` are constructed **nowhere** in
`eye_for_an_eye/`, `AutonomousDecisionAuthority` only by its own factory, and
`decision/engine.py` does not import `autonomy` at all. The running sensor reaches
the firewall through the older P0–P14 ladder — `DecisionFusion` → `PolicyGuard` →
`TemporaryBlocks.block(source, seconds)` — which uses an uncalibrated fused risk
and `config.decision.block_threshold`. There is also no configuration setting for
the calibrator path.

Everything P15.1 through P15.5 has measured — cost policy, maturity, calibrated
probability, conservative bound, decision record, TTL ladder, mass-block breaker —
is reachable from the offline replay harness and the read-only CLI commands, and
is not assembled by the shipped runtime. `docs/AUTONOMOUS_MODE.md` tells an
operator to set `[autonomy] enabled = true` and restart the service; `config.py`
validates that section and nothing consumes it.

The whole-system smoke test demonstrates that the components compose correctly. It
does not demonstrate that a running sensor composes them, and this report does not
claim it.

--------------------------------
ONNX
--------------------------------

Parity:
PASS — 18 passed on the clean clone with the declared `[ml]` extra. One skip:
`tests/test_p15_3_onnx_parity.py` records a `math-risk-v3` fixture and the engine
is v4; the fixture needs rebuilding and that is a known, stated skip rather than a
silent one.

Auxiliary classifier health:
Not configured in the evaluated runs. When configured it is fed through the single
projection function; the replay path sent 46 columns to a 36-column model between
the schema-2 change and the P15.4 refit, and both halves now use
`FeatureTransformer.project` with a permanent parity test.

Authority:
AUXILIARY. The classifier is never the probability a block rests on; the candidate's
`probability_source` is `math_risk`.

--------------------------------
ENFORCEMENT
--------------------------------

Real-kernel tests:
61 passed, 50301 subtests, with `E4E_RUN_HOST_FIREWALL=1` as root.

Real TCP block/unblock:
PASS — a real connection succeeds, the block lands, the connection stops, the
block is released, the connection succeeds again.

TTL:
PASS — an expiring block restores traffic without anybody acting.

Cleanup:
PASS — no nftables table remains after the suite, and unrelated tables are left
alone (asserted by two dedicated tests as well as by inspection).

Management safety:
PASS — unchanged, and `reports/P15_4_BASELINE.json` still enforces the protected
networks, allowlist and trusted proxies by digest.

CDN/proxy safety:
PASS — unchanged, enforced in three independent places.

Mass-block breaker:
PASS — and visibly working: it suppressed 360 true-positive windows in the locked
benchmark, where the replay clock compresses every source into a few minutes.

--------------------------------
RESOURCE HEALTH
--------------------------------

RSS:
26.0 MB at start, 60.3 MB at end, 4.5% growth between the first and second halves
of a 90-second run — an allocator that grew once and settled, not one that is
leaking.

FD:
4, flat. Minimum 4, maximum 4.

queues:
Not applicable to the offline soak; the engine ran in-process with no capture
queue. 35,290 events produced 35,290 decisions with no error.

drops:
0.

`history_entries` reads 0 and is reported without being interpreted: the
generators stamp captures at a fixed historical epoch and the TTL cache expires
against the wall clock, so nothing here is evidence about the cache bound.

--------------------------------
RELEASE GATES
--------------------------------

A Module Graduation:
PASS

B Data Quality:
PASS

C Decision / ML Validity:
FAIL — six critical observable block-eligible families at zero detection. Score
semantics, schema compatibility, formula/calibrator binding, calibration quality,
leakage exclusion, non-degeneracy and the whole-system smoke all pass; the
detection condition does not.

D Cost Decision:
PASS, with a stated limitation: the cost model demonstrably drove every decision
(`COST_BLOCK_PREFERRED`, `COST_ALLOW_PREFERRED`, `MARGIN_SATISFIED`,
`MARGIN_NOT_MET` throughout) and no block occurred below a cutoff, but per-profile
cutoffs were not exercised — see PRODUCTION HEALTH.

E False-Positive Safety:
PASS — 0 false blocks in 546 benign sources, block precision 1.0, 95% upper bound
5.495 per 1000, two new withheld hard negatives scored for the first time, every
authentication hard negative at the bottom of the scale, non-degenerate positive
detection, and no per-profile false-positive rate above zero.

F Site / Proxy Safety:
PASS

G Enforcement:
PASS

H Autonomous Recovery:
PASS

I Resource Safety:
PASS

J Repository / Documentation:
PASS

AUTONOMOUS_READY:
NO

Final status:

AUTONOMOUS_LAB

Not `AUTONOMOUS_BETA`: no beta evidence exists, and §20's classification cannot be
applied to evidence that was never collected. Not
`AUTONOMOUS_PRODUCTION_CANDIDATE`: Gate C fails, and separately the autonomous
decision stack is not assembled by the shipped runtime.

P16_PROD_ASSEMBLY_READY:
NO

Remaining blockers:

1. **The autonomous decision path is not wired into the running sensor.** The
   largest finding of this cycle and the one that changes what every earlier
   result means: P15.1 through P15.5 measured a pipeline that exists in the replay
   harness. This is prior to any question about detection quality.
2. **Six critical families at zero detection**, from three distinct causes — four
   whose evidence lands below the cutoff they were judged against, one refused by
   the observation floor despite reaching the top band, and one very small family.
   None is a formula defect and none was chased; §19 held and `math-risk-v4` is
   unchanged.
3. **The observation floor still refuses a patient source.** `scan-slow` reaches a
   0.994779 conservative bound and is refused on all 140 windows. Documented since
   P15.3, unchanged, and now measured on a benchmark where everything else works.
4. **Per-profile cutoffs have never been exercised.** Every locked benchmark since
   P15.1 priced every decision at `public_website`. Corrected in the harness; no
   measurement has yet been taken through it.
5. **No configuration setting for the calibrator path**, so a deployment has
   nowhere to put the artifact a conservative bound depends on.
6. **No independent evidence.** Every number in this report comes from synthetic
   corpora built by the same generators the system was designed against.

§48, Outcome B. One or more critical gates fail, so the next action is **real
independent Shadow/beta evidence collection, not another scenario-tuning cycle**.
Blocker 1 has to be closed before that collection can mean anything, because a
shadow deployment of the current runtime would exercise the P0–P14 ladder and
produce no evidence at all about the decision path this cycle validated.

---

## What this cycle established, plainly

The complete product is connected — component to component, packet to firewall
request — and every seam between two parts is now checked by something that fails
the build when it breaks. That was the objective, and the smoke test, the contract
matrix, the compatibility contract, the self-check and the suppression alarm are
what carry it.

The measurement is honest and, on this benchmark, good: 120 blocks, all correct,
none against a benign source, out of 203 positives and 546 benign. Against P15.4's
zero blocks and zero recall it is a different system, and the difference is one
integer comparison plus a calibrator with enough evidence behind it.

And the product still cannot do any of it, because the runtime does not assemble
the stack. That finding is the reason this report exists in the form it does, and
it is worth more than the numbers above it.

---

## Exact commands

```bash
# §1 baseline, before anything was touched
python -m training.p15_5_baseline

# §11-§13 the calibration plan, committed at 29e3f4c before any corpus existed
python -m training.p15_5_calibration_plan

# §12 the eight predeclared calibration corpora
for i in 1 2 3 4 5 6 7 8; do
  python -m dataset generate --matrix dataset/scenarios/matrix-p15-5-cal-v1.toml \
    --output "datasets/p15-5-cal${i}-v1" \
    --dataset-version "dataset-p15-5-cal${i}-v1" --seed-salt "p15.5-calibration-${i}"
done

# §16 the observability reclassification, before the corpus existed
python -c "from training import observability as o; \
  o.write('reports/P15_5_OBSERVABILITY.json'); o.write_markdown('docs/BEHAVIOR_OBSERVABILITY.md')"

# §5-§7 the whole-system smoke, and §45 the bounded soak
python -m training.p15_5_smoke
python -m training.p15_5_soak

# §13 one fit, on twelve corpora
python -c "
from training import calibrate
from eye_for_an_eye.decision import calibration as cal
body, fitted = calibrate.build(refresh=True, **calibrate.P15_5_PLAN)
[calibrate.write(fitted, s, m) for s in ('math_risk', 'model_score')
 for m in (cal.SIGMOID, cal.ISOTONIC)]"

# §15, §21 the acceptance standard, after the fit and before the corpus
python -m training.p15_5_test_policy

# --- freeze: 550df02 ---

# §23 the locked corpus
python -m dataset generate --matrix dataset/scenarios/matrix-p15-5-locked-v1.toml \
  --output datasets/p15-5-test-v1 --dataset-version dataset-p15-5-locked-v1 \
  --seed-salt p15.5-locked

# §25 scored exactly once
python -c "from training import p15_5_evaluation as E; \
  E.run(out='reports/P15_5_LOCKED_TEST.json')"

# tests
python -m pytest tests/ -q                                                  # as e4etest, umask 022
E4E_RUN_HOST_FIREWALL=1 python -m pytest tests/test_p15_1_enforcement.py -q  # as root

# §42 clean clone, fresh venv, no development datasets
umask 022 && git clone . /tmp/e4e-p15-5-clean && cd /tmp/e4e-p15-5-clean
rm -rf datasets/p15-4-* datasets/p15-5-* datasets/cal-v1 datasets/cal2-v1 \
       datasets/eval-v1 datasets/gen-test-v2 datasets/test-v1
python3.12 -m venv .venv && .venv/bin/pip install -e ".[capture,enrichment,test,ml,ml-training]"
.venv/bin/python -m pytest tests/ -q
```

## See also

- `reports/P15_5_BASELINE.json` — what was frozen, and what the runtime assembles
- `reports/P15_5_CALIBRATION_PLAN.json` — how much evidence, decided beforehand
- `reports/P15_5_CALIBRATION.json` — the single fit
- `reports/P15_5_TEST_POLICY.json` — the acceptance standard
- `reports/P15_5_SMOKE.json` — the whole-system wiring result
- `reports/P15_5_SOAK.json` — ninety seconds of watching for accumulation
- `reports/P15_5_LOCKED_TEST.json` — the scored run
- `docs/LIMITATIONS.md` — the observation floor and the calibration-width rule
