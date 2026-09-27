# P14 SCOPED SAFE AUTO-PROMOTION REPORT

**Date:** 2026-09-11
**Verified on:** Linux 6.18.44 x86_64, Intel Xeon @ 2.80 GHz, 2 logical CPUs,
8.4 GB RAM, Python 3.12.3, run as an unprivileged user with `umask 022`.

---

## Before anything else: the premise

The brief states that P13 reported `P14_AUTO_PROMOTION_READY: YES`.

**It reported `NO`.** The P13 report is in this directory and says so, with five
reasons.

§0 anticipates exactly this and instructs: re-run the readiness checks, and if a
prerequisite fails, stop rather than lower the requirement. Doing that surfaced a
distinction the single flag was hiding, and that distinction is what made this
stage possible to complete honestly:

| | Question | Answer |
| --- | --- | --- |
| **Mechanical readiness** | do hashes validate, scopes hold, activation stay atomic, rollback work, restart recover, sites stay isolated, state stay bounded? | **PASS** — 13/13 prerequisites, 44 checks |
| **Evidence readiness** | has any of this run on real traffic, with trusted labels, under a model that passes its own gate? | **NO** — unchanged |

P13's `NO` was the second kind. §0's checklist is entirely the first kind. So the
governance machinery was built and tested in full, and **ships disabled**, which
§4, §98 and §143 require regardless. The thing P13 said no to — switching this on
over production traffic — is not something implementing P14 forces, and nothing
in this report authorises it.

Full detail: `reports/P14_BASELINE.md`.

---

## The required report

```
P13 readiness:                     PASS (mechanical) / NO (evidence, unchanged)
Model governance:                  eye_for_an_eye/governance/ (11 modules, 3 212 lines)
Governance policy version:         model-governance-v1, digest b4949c39d25ce20c
Auto-promotion default:            OFF
Global auto-promotion:             OFF, and a separate switch
Site auto-promotion:               implemented, opt-in by site name
Sites enabled:                     none
ACTIVE:                            none (the registry is empty on this install)
CANDIDATE:                         none
Candidate eligibility:             not assessable — there is no candidate
Offline gate:                      PASS (implemented and tested; no candidate to run it on)
Shadow gate:                       PASS (implemented and tested)
Hard negatives:                    PASS (implemented and tested)
Hard positives:                    PASS (implemented and tested)
Block precision gate:              PASS (system-level, through the full stack)
False-block gate:                  PASS (tightest budget in the policy)
OOD:                               advisory only; never a refusal or a rollback
Drift:                             advisory only; never a refusal or a rollback
Candidate health:                  PASS (only HEALTHY may auto-promote)
Resource gate:                     PASS (latency, memory, load time, artifact size)
Promotion state machine:           11 states, explicit transition table
Transactional activation:          PASS
Crash recovery:                    PASS (every phase, one unambiguous resolution)
Guarded activation:                2 stages before full authority
Stage 1 action ceiling:            WATCH
Stage 2 action ceiling:            RATE_LIMIT
Post-promotion comparison:         PASS (previous model in a reference role)
Auto-rollback:                     PASS (technical, resource, trusted-quality)
Last known good:                   PASS
Emergency freeze:                  PASS (manual and automatic)
Model safe mode:                   PASS
Rollback-loop prevention:          PASS (ROLLED_BACK leads only to QUARANTINED)
Training/promotion separation:     PASS
Site isolation:                    PASS
Global/site scope:                 PASS
Upgrade default safety:            PASS
Clean install default safety:      PASS (installed and verified, not only asserted)
```

**Tests: 1798 passed, 30 skipped, 4461 subtests** (1828 collected, 93 files).
264 of them are P14. `ruff` clean. `scripts/security_scan.py` exit 0.

---

## What "PASS (implemented and tested)" means here, and does not

Every gate above is implemented, has tests that break when the gate is broken,
and has been exercised against synthetic evidence built to pass and then
perturbed one field at a time. Two of them were mutation-tested: deliberately
disabling the action ceiling and the observation requirement each failed the
tests that exist to catch exactly that.

None of them has ever judged a real candidate on real traffic, because there is
no candidate and the registry on this install is empty. A gate that works on
constructed evidence is a gate that works on constructed evidence. That is the
honest ceiling of what this stage could establish, and it is why the
recommendation at the bottom is what it is.

---

## Architecture

```
                      TRAINING AUTHORITY
                 creates a candidate; may do nothing else
                              │
                              ▼
                    EVALUATION AUTHORITY
            offline reports, shadow reports, reviewed outcomes
                              │
                              ▼
  ┌───────────────── PROMOTION AUTHORITY ─────────────────┐
  │                                                       │
  │  ModelGovernanceEngine.assess()   pure; changes nothing│
  │       ├─ integrity      → QUARANTINED on failure      │
  │       ├─ compatibility                                │
  │       ├─ health                                       │
  │       ├─ governance     (scope, freeze, cooldown,     │
  │       │                  budgets, rollback target)    │
  │       ├─ sufficiency    → NEED_MORE_DATA when unproven│
  │       ├─ benign safety  ← tightest budgets            │
  │       ├─ security quality                             │
  │       ├─ generalization (OOD, drift — advisory only)  │
  │       └─ resource cost                                │
  │                    ↓                                  │
  │      PromotionAssessmentRecord (immutable, addressed) │
  │                    ↓ ELIGIBLE only                    │
  │  PromotionActivator.promote()   the only writer       │
  │       lock → verify → journal → warm up → switch      │
  │                    ↓                                  │
  │            GUARDED_ACTIVE_STAGE_1                     │
  │              ceiling: WATCH                           │
  │                    ↓ observations, never time         │
  │            GUARDED_ACTIVE_STAGE_2                     │
  │              ceiling: RATE_LIMIT                      │
  │                    ↓                                  │
  │                 ACTIVE                                │
  └───────────────────────┬───────────────────────────────┘
                          │
              PostPromotionMonitor.evaluate()
              technical / resource / quality
                          │
                    ROLLED_BACK → QUARANTINED
                          │
  ══════════════════════════════════════════════════════════
              ENFORCEMENT AUTHORITY (PolicyGuard)
        unchanged; decides what evidence may cause, and is
        not reachable from anything above this line
```

The line at the bottom is the one that matters. Promotion changes **which model
provides evidence**. It never changes what evidence is allowed to cause.

---

## Findings and decisions worth recording

**1. The gates are multi-dimensional by construction, not by convention.** There
is no code path from one improved metric to a promotion. `decide()` looks at
integrity first, then blocking failures, then unproven gates — so a candidate
whose F1 improved while its false blocks doubled is `NOT_ELIGIBLE`, and there is
a test named after that case.

**2. `NEED_MORE_DATA` is a first-class verdict, not a soft no.** Quality gates
read `trusted_outcomes` and nothing else. Five million unlabelled feature vectors
produce `NEED_MORE_DATA`, verified. Collapsing this into `NOT_ELIGIBLE` would
teach an operator to read "we could not tell" as "it regressed"; collapsing it
into `ELIGIBLE` would let volume authorise a promotion.

**3. Three existing invariants had to be narrowed, and narrowing them was the
delicate part of this stage.** `test_p9_invariants` and `test_p13_integration`
asserted that no configuration field anywhere contained `auto_promote`, and that
only the registry CLI could call `promote`. Both were true and useful statements
about a system with no governance engine. Deleting them would have thrown away
the properties that still hold, so each was narrowed to its surviving half and a
*stronger* companion test added:

- `test_the_training_and_dataset_packages_cannot_change_the_active_model` — the
  property that always mattered was never "one call site", it was "not from
  training";
- `test_the_activator_is_the_only_new_promotion_authority` — the set of things
  that can promote is asserted exactly, so a third one cannot appear quietly.

**4. Four documented claims became false the moment the setting existed**, and
all four were fixed in the same change that created it: `retraining.py`'s
docstring, `config.py`'s `LearningConfig` docstring, `learning status`'s
"there is no setting that turns this on", and `MULTI_SITE_MODELS.md`. P13 found
three defects of exactly this shape — documentation that had quietly stopped
matching the code — and this is the first stage where they were caught in the
same commit rather than an audit later.

`test_site_docs.py` had a test requiring the multi-site page to say "there is no
setting that turns it on". It was rewritten rather than deleted, because a test
that requires a document to repeat a claim the code has outgrown is a test
defending a lie.

**5. The denial-versus-claim problem recurred a third time**, so it was fixed
properly. A documentation test asserting `'attack' not in body` fails on the page
that says *"drift is never evidence of an attack"* — and the tempting fix is to
delete the sentence. `tests/denial.py` now does this once, with the reasoning
written down, and `test_p14_docs` uses it for the §155 forbidden sentences, which
`AUTO_PROMOTION.md` quotes in order to reject.

**6. A fresh install cannot auto-promote even if the flag were on.** The registry
is empty, so there is no rollback target, and §58 refuses a promotion without
one. This falls out of the design rather than being arranged, and it means the
dangerous configuration is unreachable until an operator has registered and
promoted at least one model by hand.

---

## Safety mechanisms, and where each lives

| Mechanism | Module | What it prevents |
| --- | --- | --- |
| Explicit scope, never inferred | `policy.AutoPromoteSettings.allows` | one site's decision reaching another |
| Global as a separate switch | same | a shared model promoted on one site's evidence |
| Worst-site evaluation | `engine._generalization_gates` | an aggregate hiding the site that got worse |
| Rollback target required | `engine._governance_gates` | an irreversible automatic change |
| Cooldown and daily budgets | same | model churn |
| One transition per scope | `activation.ScopeLock` + journal | two promotions racing |
| Load and warm up before switching | `activation.promote` step 6 | a pointer moved to a model that will not load |
| Atomic pointer write | `registry._write_atomic` | a half-written pointer |
| Promotion journal | `journal.PromotionJournal` | an ambiguous state after a crash |
| Guarded ceiling | `guarded.clamp` | a new model blocking anybody on day one |
| Evidence-based advancement | `guarded.evaluate_advance` | a quiet site granting authority for free |
| Technical rollback | `monitor._technical` | a broken model staying |
| Resource rollback | `monitor._resource` | a model making the site slow |
| Quality rollback | `monitor._quality` | a model blocking real visitors |
| Rollback-loop prevention | `lifecycle.TRANSITIONS` | promote/regress/promote oscillation |
| Freeze and safe mode | `store.GovernanceStore` | repeated autonomous change under uncertainty |
| Policy digest | `policy.GovernancePolicy.digest` | a threshold edit retroactively authorising a verdict |

---

## Performance

`benchmarks/bench_governance.py`. Single process, one core, no network.

```
Governance assessment (45 gates)   p50   326 us    p95   415 us    p99   544 us
Post-promotion monitor             p50    15 us    p95    26 us    p99    47 us
Guarded action ceiling             p50  0.41 us    p95  0.46 us    p99  0.70 us
Activation (lock→journal→switch)   p50  5.64 ms    p95  6.93 ms    p99  8.10 ms
Rollback                           p50  2.62 ms    p95  3.15 ms    p99  4.05 ms
RSS growth across the run          3.7 MB
CPU                                1.33 s
```

The only one of these on a per-decision path is the guarded ceiling, at **0.41
microseconds**. That is the number that had to be small, and it is.

Activation excludes the real model load, which is injected as a warmup callable
so the transaction can be tested without an ONNX file. The 5.6 ms is governance
overhead *around* a load, not the load itself — the load is the dominant cost in
production and is bounded separately by `max_model_load_seconds` (30 s).

**Dual inference overhead was not measured**, because the reference-role
comparison is wired as an interface and not yet connected to a live second
session. Stated rather than estimated.

---

## Tests

```
1798 passed, 30 skipped, 4461 subtests   (1828 collected, 93 files)
```

| File | Cases | Covers |
| --- | --- | --- |
| `test_p14_readiness.py` | 45 | §0 — the 13 mechanical prerequisites |
| `test_p14_governance.py` | 78 | lifecycle, policy, every eligibility gate |
| `test_p14_activation.py` | 54 | transaction, journal, crash recovery, guarded stages |
| `test_p14_rollback.py` | 31 | the three rollback tiers, and the two non-triggers |
| `test_p14_operations.py` | 32 | CLI, store, metrics, default-off regressions |
| `test_p14_docs.py` | 24 | §155 forbidden sentences, threshold accuracy |
| `test_p13_degraded_modes.py` | +8 | §145 governance failure injection |

The 30 skips are unchanged from P13: a generated artifact not distributed in the
source archive, or the isolated-Linux namespace lab.

**Two mutations were introduced deliberately and both were caught**: making the
action ceiling a no-op failed 1 test; removing the observation requirement from
stage advancement failed 3, including the clock-jump case.

---

## Acceptance criteria

All 46 items in §159 are met. The ones worth calling out because they are easy to
claim and hard to check:

- **fresh-install default is OFF** — verified by running the real installer to a
  temporary prefix and reading the generated configuration, which does not
  contain the section at all;
- **package upgrade does not enable it** — a pre-P14 configuration file, an empty
  one, and every shipped example all load with it off; a missing section and a
  section saying `false` are the same behaviour by construction;
- **trusted-label insufficiency produces NEED_MORE_DATA** — tested with five
  million unlabelled vectors;
- **OOD does not equal attack / drift does not equal attack** — tested in both
  the eligibility engine and the rollback monitor, in both directions;
- **training process cannot promote** — checked by parsing every file in
  `training/` and `dataset/` for a promotion call or a governance import;
- **auto-promotion cannot modify firewall policy** — checked by parsing the
  governance package's imports.

---

## Known limitations

**This has never run over production traffic.** Not one promotion, not one
guarded stage, not one rollback, on a server anybody depends on. Everything above
was exercised against constructed evidence.

**The thresholds are not measured.** Every number in the policy is a starting
point chosen to be conservative by people without deployment data.
`PROMOTION_POLICY.md` says so at the top, and the source says so at each one.

**The reference-role comparison is an interface, not a running second session.**
`GuardedObservation` records what a comparison would produce; connecting it to a
live previous-model session is not done. Post-promotion disagreement is therefore
measurable in principle and unmeasured in practice.

**The evidence adapters are not wired to the pipelines.** `OfflineEvidence` and
`ShadowEvidence` are typed inputs the engine consumes. Populating them from
`training/evaluate_model.py` and the candidate shadow ledger is a small piece of
plumbing that is deliberately not done here, because doing it would make the
system capable of assessing a real candidate — which is a step that should follow
a decision to use this, not precede it.

**`mypy` was not run**, as in P13: it is in the optional `quality` extra and is
not installed in this environment. CI runs it; this report does not claim it
passes.

**The soak test does not cover governance.** The 900-second soak from P13 was not
re-run against a guarded model, because there is no model to guard.

---

## Recommended deployment

```
AUTO-PROMOTION DISABLED
```

Not "site-scoped experimental", and deliberately not the next rung up.

The machinery is complete, tested and defensible. The evidence is not there, and
the gap is not a code gap: no candidate exists, the registry is empty, the
shipped model fails its own quality gate, and nobody has run any part of this
loop over traffic that mattered. A recommendation of "site-scoped experimental"
would be a statement about the code, and an operator would reasonably read it as
a statement about the risk.

The order in §158 is the right one, and the project is at its first step:

```
P14 installed  →  auto-promotion OFF  →  observe a normal candidate lifecycle
```

Nothing after that second arrow has happened yet.

---

## Final safety statement

```
Can a candidate directly control promotion?                      NO
Can training directly change ACTIVE?                             NO
Can auto-promotion directly change firewall policy?              NO
Can one site auto-promote another site's model?                  NO
Is the previous known-good model recoverable?                    YES
Can serious technical regression trigger rollback?               YES
Can one unlabelled event trigger quality rollback or promotion?  NO
```

---

## `git diff --stat`

**Not available. The project is not under version control.**

There is no `.git` directory in the Windows working copy. This was found during P13
while trying to produce the same command, and nothing has changed since. The
consequence for this stage is worth stating: **a 3 212-line package that decides
when a security tool changes its own model has been written without a single
reviewable diff.** For a feature whose entire safety argument is "you can read
the gates", that is a real gap in what a reviewer can check, and it is an owner
action rather than an engineering one.

The file-by-file summary below is the substitute.

---

## Files changed

### New — the governance package (3 212 lines)

| File | Lines | What it is |
| --- | --- | --- |
| `governance/__init__.py` | 50 | the four authorities, and why they are apart |
| `governance/lifecycle.py` | 172 | 11 states, one transition table, three load-bearing edges |
| `governance/policy.py` | 375 | every threshold, frozen, versioned, content-addressed |
| `governance/evidence.py` | 269 | the only things that can influence a promotion |
| `governance/assessment.py` | 283 | the immutable record; four verdicts; no score decides |
| `governance/engine.py` | 522 | the gates, in the order that makes the order a safety property |
| `governance/journal.py` | 303 | what was happening when the power went out |
| `governance/guarded.py` | 293 | ceilings, observation, evidence-based advancement |
| `governance/activation.py` | 341 | the ten-step transaction; the only writer |
| `governance/monitor.py` | 291 | three rollback tiers, and the two non-triggers |
| `governance/store.py` | 313 | history, audit log, freeze switch |
| `governance_cli.py` | 394 | status, policy, assess, history, audit, freeze, unfreeze |

### New — tests (2 691 lines) and tooling

`test_p14_readiness.py` (551), `test_p14_governance.py` (684),
`test_p14_activation.py` (607), `test_p14_operations.py` (315),
`test_p14_rollback.py` (282), `test_p14_docs.py` (228), `tests/denial.py` (56),
`benchmarks/bench_governance.py`.

### New — documentation

`docs/AUTO_PROMOTION.md` (simple English, §154), `docs/MODEL_GOVERNANCE.md`
(precise), `docs/GUARDED_ACTIVATION.md`, `docs/AUTO_ROLLBACK.md`,
`docs/MODEL_SAFE_MODE.md`, `docs/PROMOTION_POLICY.md`, `reports/P14_BASELINE.md`.

### Modified

| File | Change |
| --- | --- |
| `config.py` | `ModelGovernanceConfig`, off by default; validation refuses promotion without guarded activation or rollback; `LearningConfig` docstring corrected |
| `cli.py` | `model governance` dispatch |
| `learning_cli.py` | reads the governance setting instead of printing "there is no setting that turns this on" |
| `decision/promotion.py` | docstring narrowed: this module still promotes nothing, but the project now has something that can |
| `observability/metrics.py` | 20 bounded governance metrics, no high-cardinality labels |
| `docs/MULTI_SITE_MODELS.md` | the P14 section, replacing a claim that stopped being true |
| `docs/SCHEMA_COMPATIBILITY.md` | 9 new version constants, each with its mismatch behaviour |
| `README.md`, `config.example.toml` | the optional feature, and the settings, both off |
| `tests/test_p9_invariants.py` | two invariants narrowed, two stronger ones added |
| `tests/test_p13_integration.py` | one invariant narrowed to its surviving half |
| `tests/test_p13_degraded_modes.py` | 8 governance failure-injection cases (§145) |
| `tests/test_site_docs.py` | doc test rewritten rather than deleted |

---

## Conclusion

P14 gives this project more autonomy, and the constraints grew faster than the
autonomy did: eleven modules of governance, and the feature ships off.

The part worth defending is not that automatic promotion works. It is that a
candidate cannot influence its own promotion, that a promoted model cannot block
anybody on its first day, that every path back is shorter than the path forward,
and that when the system does not know what happened it says so and stops.

What it still lacks is the only thing code cannot supply: somebody running it.
