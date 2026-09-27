# P15.1 PRODUCTION READINESS CLOSURE REPORT

**Date:** 2026-09-12
**Cycle:** P15.1, production readiness evidence and enforcement closure
**Predecessor:** [P15_FINAL_AUTONOMOUS_DEFENSE_REPORT.md](P15_FINAL_AUTONOMOUS_DEFENSE_REPORT.md), unedited
**Baseline matrix:** [P15_1_BASELINE.md](P15_1_BASELINE.md)

P15.1 closed the licence, version-control, clean-clone and host-enforcement
blockers, and measured what P15 could not. The measurement is the story of this
cycle, and it is not the one anybody wanted: **the autonomous authority blocks
nothing at all**, and the reason is an arithmetic error that had been in the
decision path since P15 shipped it.

Two gates still fail. They fail on evidence, and no threshold was moved.

---

## MIT License

**PASS.**

`LICENSE` holds the standard MIT text, unmodified. `pyproject.toml` carries
`license = "MIT"`, `license-files = ["LICENSE"]` and the author metadata;
`MANIFEST.in` includes it in the sdist. `THIRD_PARTY_NOTICES.md` records the one
copyleft dependency (`scapy`, GPL-2.0-only, in the optional `capture` extra)
and notes that the base package has `dependencies = []`.
`scripts/license_audit.py` reads installed distribution metadata and flags
copyleft, so the notice file can be checked rather than believed.

**Creator:** Aliaksandr Zasinets
**Copyright:** Copyright (c) 2026 Aliaksandr Zasinets
**SPDX:** `MIT`

## Git Initialized

**YES.**

Branch `main`, five commits, working tree clean. Nothing has been pushed
anywhere and no remote is configured.

Before the first commit: a secret scan (keys, tokens, credentials, `.env`), a
privacy review, a generated-file sweep and a `.gitignore` review. Excluded and
still excluded: runtime databases and `*.jsonl`, shadow telemetry, the generated
corpora (`datasets/raw/`, `datasets/processed/`, `datasets/eval-v1/`), training
caches, build and release output, the maintainer's third-party reference PDFs,
and every credential pattern.

**Commit signing: `COMMIT_SIGNING_NOT_CONFIGURED`.** `commit.gpgsign` is
`false` and no `user.signingkey` is set. No signing credential was generated.

The repository was created in a temporary build environment, so it travels to
the project machine as a git bundle. `P15_1_REPOSITORY_HANDOVER.md` says how to
restore it and which route writes to existing files.

## Clean Clone

**PASS.**

```
git clone <repo> cleanclone
/usr/bin/python3.12 -m venv .venv
.venv/bin/pip install -e ".[test,capture,ml,enrichment]"
.venv/bin/python -m pytest tests/ -q
```

**2,071 passed, 88 skipped, 0 failed**, against 2,095 passed / 64 skipped in
the development tree, 2,159 collected in both. The 24 tests that pass there and
skip here are exactly the ones that need generated corpora or research model
artifacts, which are deliberately not committed. No test depends on anything
outside the clone.

One finding worth stating: with the `enrichment` extra absent, two P1 provider
tests **fail** rather than skip. They are not development-tree dependencies (
they are optional-dependency dependencies), but a test that hard-fails on a
missing optional extra is a packaging honesty problem, and it is recorded here
rather than repaired inside a release-evidence cycle.

## Beta Evidence

**OWNER_REPORTED_ONLY.**

Verdict `BETA_REPORTED_BY_OWNER`, per §41. The full reconciliation is in
[BETA_EVIDENCE.md](BETA_EVIDENCE.md): owner statement on one side, repository
evidence on the other, neither accepted over the other. No sanitised derived
beta artefact exists in the repository, so there is nothing to evaluate, and
`BETA_EVIDENCE_VERIFIED` is not written anywhere.

No raw private traffic was imported.

---

## Trusted Decision Dataset

`dataset-eval-v1`, built from `dataset/scenarios/matrix-eval-v1.toml`: 27
controlled scenario groups, generated offline, deterministic from its seeds.
Labels come only from `controlled_scenario`, `manual_review` and
`trusted_fixture`. The corpus format cannot hold a label derived from this
system's own block, allow, model score or math score, `DatasetSample` raises on
construction, and `tests/test_p15_1_replay.py` pins that.

Rows dropped before scoring: 5, for `identical_vector_under_both_labels`. The
same bounded window appearing under both labels, where ground truth does not
exist at the resolution the system can see.

**Benign samples:** 565 sources / 5,785 windows
**Positive samples:** 144 sources / 1,791 windows

Both clear §6's minimum of 500 benign and 50 positive. The §6 values were
checked against the real implementation before being relied on, and no threshold
was lowered to reach them; `MAX_RUNS_PER_SCENARIO` went from 32 to 64 and a
third RFC 5737 documentation range joined the source pool, which changes how
much traffic can be generated and changes no gate.

Hard negatives (§8), all benign, all scored: `hard-negative-monitoring` (26
sources), `-health-check` (18), `-admin` (105), `-discovery` (28), `-connect`
(17), `-deception` (35); 229 sources, 2,954 windows.

Hard positives (§9), all malicious, all scored: `scan-slow`, `scan-randomized`,
`credential-low-rate`, `protocol-mismatch`, `deception-enumeration`,
`probe-truncated`, `recon-multi-stage`: plus the rest of the scan and probe
families.

No public target was contacted at any point.

## Final-decision Metrics

Replayed through the complete system to the final ALLOW / TEMP_BLOCK (§7), not
to a score. Per source, which is the unit a block applies to:

| | ALLOW | TEMP_BLOCK |
| --- | --- | --- |
| actual benign | 565 | **0** |
| actual malicious | 144 | **0** |

**precision:** undefined. No positive decisions
**recall:** 0.000
**specificity:** 1.000
**FPR:** 0.000
**FNR:** 1.000
**PR-AUC:** 0.699 (per source) / 0.515 (per window)
**ROC-AUC:** 0.783 (per source) / 0.626 (per window)
**block precision:** undefined, block precision of an empty set is not a number
**false blocks / 1000 benign:** 0.0
**bootstrap interval:** FPR [0.000, 0.000]; false blocks/1000 [0.000, 0.000];
block precision `null`. 400 percentile resamples over evaluation rows. The
interval is an empirical resampling interval and is labelled as one, not a
frequentist confidence interval.

**Usefulness:** `USELESS_NO_DETECTION`. **Release gate:** `FAIL`.

The false-positive numbers are true and they are worthless: a system that never
blocks has a perfect false-block rate. Reporting 0.0 without that sentence next
to it would be the most dishonest thing in this report.

Full working: [P15_1_DECISION_EVALUATION.md](P15_1_DECISION_EVALUATION.md),
raw output `P15_1_DECISION_EVALUATION.json`.

### Why Zero

A units error. The cost-sensitive cutoff is `C_FP / (C_FP + C_FN)`. A
*probability* of maliciousness at which blocking becomes the cheaper mistake.
When no calibrated estimate was available, P15's code fell back to comparing
`MathRisk`, an uncalibrated score on its own scale, against that number. The
comparison has no meaning in either direction.

`CALIBRATION_UNAVAILABLE` is now a hard gate: no calibrated estimate, no block,
at any score. `tests/test_p15_autonomy.py` asserts that `math_risk = 1.0` still
returns ALLOW. This makes the system block *less* than before, which is the
correct direction for a fix to a measurement error, and it is a strengthening
rather than the relaxation §45 forbids.

It is not only the threshold. The decision variable ranks worse than its own
inputs: conservative probability reaches ROC-AUC 0.626 per window and 0.783 per
source, where raw `MathRisk` reaches 0.775 / 0.827 and the classifier
0.828 / 0.911. The shrinkage is monotone in value but not rank-preserving across
different observation counts, so the pipeline loses ordering information at the
step that decides.

## Classifier

**old model:** `risk-logreg-v1`. The shipped and only model
**old quality gate:** `PROVISIONAL`; `quality_gate_passed: false`; the manifest's
own `recommended_mode` is `shadow` and `recommended_shadow_only` is `true`
**candidate:** none. No model was trained in P15.1
**candidate quality gate:** n/a
**active production model:** `risk-logreg-v1`, shadow-only by its own manifest;
`threshold_authority` is `DecisionFusion and PolicyGuard`. The model never
selects an action
**ONNX parity:** `NOT_RUN`. `tests/test_p8_onnx_parity.py` skips (8 tests)
because the training corpus it compares against is not committed. Unchanged
since P15; not a regression, and not evidence either. What *was* exercised: the
ONNX artifact answered 7,576 of 7,576 replay windows with zero failures, which
is evidence that it loads and scores, and no evidence at all about parity with
the sklearn original.

**The generalisation number** was already in
`models/risk-logreg-v1-evaluation.json` and had never reached a summary: on the
four withheld scenario families, ROC-AUC **0.517**: chance. Held-out test
ROC-AUC is 0.829 and PR-AUC 0.699, on a split that shares scenario families with
training. At threshold 0.5 on the withheld families the model produces 619 false
blocks per 1000 benign sources.

No retraining was attempted, and the reason is stated rather than implied:
calibration is the binding constraint, a better-ranking uncalibrated model would
not have produced a single additional block, and tuning against the frozen test
set is forbidden by §10.

---

## Production Enforcement

**implemented:** YES, `eye_for_an_eye/security/{enforcement,host_firewall,firewall_helper,host_enforcer}.py`
**privilege separation:** PASS
**nftables ownership:** PASS
**management safety:** PASS
**proxy/CDN safety:** PASS
**TTL:** PASS
**maximum automatic TTL:** **43,200 s (12 hours)**, unchanged from P15, not raised
**mass-block breaker:** PASS
**apply/verify:** PASS
**crash safety:** PASS
**clean restart:** PASS

The authority holds no firewall handle (`tests/test_p15_1_enforcement.py` parses
its imports). What crosses the privilege boundary is an `EnforcementRequest`
carrying an address, a family, a scope, a lifetime, a decision id and reasons,
and **no command field**. A privileged helper that accepted a command from an
unprivileged process would be a remote shell with extra steps. An unknown field
is refused rather than ignored. The helper re-validates against its own copy of
the configuration immediately before writing, because the interesting failure is
not "the guard was wrong" but "the guard ran five minutes ago".

Ownership is an owner comment, not a name: a table called `e4e_x` this
installation did not create is refused, not adopted. There is no `flush` in any
module, and a test AST-parses every file to keep it that way. Neighbour tables
survive apply, cleanup, and every injected failure.

**And the block stops packets.** Every other enforcement test verifies that an
element is in a set the kernel agrees exists with a timeout it is counting down.
Three tests added in this cycle verify the thing that claim is *for*: a veth pair
into a throw-away namespace, a real listener, a real TCP connection. It
completes; the block goes on; it times out; the block comes off; it completes
again. A second test lets an eight-second block expire with nobody acting and
watches traffic return on the kernel's schedule. A third blocks one address and
confirms a different one keeps its access.

Off on a fresh installation, behind `enforcement.host_enabled`, and a package
upgrade cannot turn it on. Configuration validation refuses it without a
protected network, refuses both enforcement paths at once, refuses it without
the decision engine, and refuses it under the `lab` profile.

**Where it was tested:** a disposable container this session owns and can lose,
with a real kernel and `nft` v1.0.9. Not on any management connection, not on a
production host, and not on the machine anybody is reading this on. §28 and §39
are satisfied: controlled deployment evidence, no live Internet target.

**What was not tested, and is not claimed:** coexistence with **firewalld** and
with **Docker's** live rules on a host that runs them. The isolation property is
tested against a neighbour table this project created, which is the same
mechanism and not the same evidence. Also untested: multi-hour operation, and any
host that is not this container.

## Autonomous Recovery

**PASS.**

Degrade, safe mode, cooldown, health gate and resume, with no administrator in
either direction. Degrading is immediate; returning needs the fault cleared, the
cooldown passed and the readiness gate to pass again. Four brakes: block budget,
mass-block breaker, a false-positive breaker fed only by trusted evaluation, and
a technical breaker for nine named subsystem faults, any of which opens
`AUTONOMOUS_SAFE_MODE`: no new blocks, everything else continues, existing blocks
expire on their own. Covered by `tests/test_p15_runtime.py` and
`tests/test_p15_autonomy.py`, and now also end to end against a real kernel.

---

## Release Gates

| Gate | Verdict | Evidence |
| --- | --- | --- |
| **A: Module graduation** | **PASS** | every module classified by behaviour; the four new security modules classified in `MODULE_GRADUATION.md` as PRODUCTIONIZE_WITH_GUARDS; the dangerous class still empty; the lab namespace path's three gates unchanged and still asserted |
| **B (Data quality** | **PASS** | no leakage; group-aware splits; provenance enforced; the self-label loop is structurally impossible) the corpus format raises on a label sourced from this system's own decision, and 19 new tests pin the measurement harness against scoring one |
| **C: ML validity** | **FAIL** | §37 offers two routes and neither is satisfied. The classifier is not validated: `quality_gate_passed: false`, and ROC-AUC 0.517 on withheld scenario families. The deterministic fallback is not validated either: measured at recall 0.000, it is inert rather than validated, and a system that never acts has not demonstrated that it acts correctly |
| **D: Cost decision** | **PASS** | the threshold comes from an explicit per-profile cost policy, never 0.5, with a content digest in every record. Strengthened this cycle: the policy can now only be applied to a calibrated probability, which is the quantity it was always defined over |
| **E: False-positive safety** | **FAIL** | now **measured** rather than unmeasurable, on 565 trusted benign and 144 trusted positive sources. False blocks per 1000 benign: 0.0. Block precision: **undefined**, because there are no blocks. §38 requires both measured; one of them cannot exist yet |
| **F, Site / proxy safety** | **PASS** | multi-site, CDN, trusted proxy and management protection pass, and now at the enforcement layer too: `HOST_NETWORK` is the only scope that exists, a record that is not network-enforceable cannot produce a request at all, and the helper refuses a trusted proxy against its own configuration |
| **G, Enforcement** | **PASS** | §39's list, item by item: a real-host implementation exists, is privilege separated, is bounded at 12 hours and by a block budget and an entry ceiling, is ownership-isolated by owner comment, was tested on a realistic owned environment against a real kernel with automatic expiry demonstrated and management and proxy protections passing, and a real TCP connection that stops when the block goes on. Controlled deployment evidence, which §39 states is sufficient |
| **H (Autonomous recovery** | **PASS** | degrade, rollback, safe mode, cooldown, health gate, resume) none of it needs a person |
| **I: Resource safety** | **PASS** | every window, table and list bounded by construction; caps asserted by filling them; the enforcement path adds its own entry ceiling, verified against the kernel by filling it |
| **J, Repository / documentation** | **PASS** | §40's four items: MIT LICENSE exists; the git repository exists; the private security disclosure workflow is prepared and documented; documentation matches real behaviour. The README no longer claims blocking is lab-only, because that stopped being true this cycle, and the P15-era test that pinned the old sentence was rewritten to pin the new facts rather than the README reverted to match it |

### AUTONOMOUS_READY

**NO.**

### Final Status

**AUTONOMOUS_LAB.**

Not `AUTONOMOUS_BETA`: no evaluable beta evidence exists. Not
`AUTONOMOUS_PRODUCTION_CANDIDATE`: Gates C and E fail. P15's conclusion stands,
for a better-understood reason than P15 had.

### P16_PROD_ASSEMBLY_READY

**NO.**

§43's test is whether public packaging would hide an unresolved critical runtime
safety problem. It would. Packaging this now ships a defender that, on the only
trusted evaluation that exists, detects nothing, and the danger is not the
nothing, which is safe. It is that "0.0 false blocks per 1000 benign" reads like
a result, and would be quoted as one by somebody who stopped reading before the
recall line.

The repository is ready for P16 in every mechanical respect: licence, version
control, clean clone, security workflow, documentation. The measurement is not.

---

## Remaining Blockers

1. **No calibrated probability estimate.** This is the one that matters. The
   cost-sensitive policy is defined over a probability, and nothing in the
   pipeline produces one. Until something does, the correct behaviour is the
   current behaviour: refuse to block.
2. **The classifier does not generalise.** ROC-AUC 0.517 on withheld scenario
   families. Calibrating a model that ranks at chance on unseen behaviour would
   produce well-calibrated noise.
3. **The decision variable ranks worse than its inputs.** The conservative
   estimate is not rank-preserving across different observation counts. It must
   not be reused anywhere a ranking matters, and it is currently the only thing
   the decision sees.
4. **Beta deployment remains `BETA_REPORTED_BY_OWNER`**, owner input needed:
   sanitised derived artefacts, or an explicit statement that none exist.
5. **Private security reporting is prepared, not enabled**, owner action: turn
   on GitHub Private Vulnerability Reporting once a repository exists. No email
   address was invented. `scripts/release_check.py` blocks release until
   `SECURITY.md` stops saying `OWNER_ACTION_REQUIRED`.
6. **Untested coexistence** with firewalld and Docker on a host that runs them.
7. **Still NOT_MEASURED from P15:** live capture under systemd, `CAP_NET_RAW`
   separation, arm64 and Windows, multi-hour soak.
8. **Owner decisions outstanding:** third-party reference PDFs in the project
   folder, Russian-language files in `docs/history/`, agent instruction files,
   and seven unsubmitted OTF grant drafts. All are `.gitignore`d or committed
   only locally; none is published.
9. **Two P1 provider tests fail rather than skip** when the optional `enrichment`
   extra is absent.

Nothing in this report was marked PASS without evidence, and the two gates that
fail were not talked into passing.

---

## Evidence

### `git status`

```
On branch main
nothing to commit, working tree clean
```

### `git log --oneline -5`

```
12e2a89 P15.1: correct the suite counts in the final report
124d70f P15.1: final report — AUTONOMOUS_LAB, P16_PROD_ASSEMBLY_READY NO
6af8800 P15.1: prove the block stops packets, and make the ranking table reproducible
d3e17fb P15.1: production readiness evidence and enforcement closure
6e0f6fe Initial commit: Eye for an Eye 0.8.0rc1 (P0-P15)
```

Five commits is the whole history: the initial safe commit and four P15.1
commits. The listing above was taken after this report was committed, so it
includes the commits that carry it; the diffstat below is still measured from
the initial safe commit.

### `git diff --stat 6e0f6fe..HEAD`

```
 .gitignore                                 |   6 +
 CHANGELOG.md                               |  84 +++
 README.md                                  |  38 +-
 dataset/scenarios/__init__.py              |  25 +-
 dataset/scenarios/matrix-eval-v1.toml      | 262 +++++++++
 docs/HOST_ENFORCEMENT.md                   | 200 +++++++
 docs/MODULE_GRADUATION.md                  |  17 +
 docs/SCHEMA_COMPATIBILITY.md               |   5 +
 eye_for_an_eye/autonomy/authority.py       |  19 +-
 eye_for_an_eye/autonomy/runtime.py         |  53 +-
 eye_for_an_eye/config.py                   |  52 ++
 eye_for_an_eye/security/enforcement.py     | 207 +++++++
 eye_for_an_eye/security/firewall_helper.py | 169 ++++++
 eye_for_an_eye/security/host_enforcer.py   | 175 ++++++
 eye_for_an_eye/security/host_firewall.py   | 404 ++++++++++++++
 reports/BETA_EVIDENCE.md                   | 130 +++++
 reports/P15_1_BASELINE.md                  |  82 +++
 reports/P15_1_DECISION_EVALUATION.json     | 502 +++++++++++++++++
 reports/P15_1_DECISION_EVALUATION.md       | 282 ++++++++++
 reports/P15_1_FINAL_REPORT.md              | 503 +++++++++++++++++
 tests/p15_1_replay_fixtures.py             |  64 +++
 tests/test_p15_1_enforcement.py            | 853 +++++++++++++++++++++++++++++
 tests/test_p15_1_replay.py                 | 237 ++++++++
 tests/test_p15_autonomy.py                 |  19 +
 tests/test_p15_docs.py                     |  35 +-
 tests/test_p15_invariants.py               |  42 +-
 training/decision_replay.py                | 469 ++++++++++++++++
 training/decision_replay_cli.py            | 121 ++++
 28 files changed, 5023 insertions(+), 32 deletions(-)
```

The `LICENSE`, `pyproject.toml`, `MANIFEST.in`, `SECURITY.md`,
`THIRD_PARTY_NOTICES.md` and `scripts/` licence changes are not in this range:
they were made before the repository existed and are part of `6e0f6fe`.

### The Exact Tests Executed

**Full suite, development tree, as `e4etest` with `umask 022`**; as root the
hardened ONNX artifact reader refuses a file owned by another user, so running
as root would have hidden real coverage behind a false skip:

```
.venv/bin/python -m pytest tests/ -q
2095 passed, 64 skipped, 3 warnings, 55931 subtests passed in 135.34s
```

**Enforcement suite, as root, against a real kernel**, with `nft` v1.0.9 and
`iproute2` present:

```
.venv/bin/python -m pytest tests/test_p15_1_enforcement.py -q
61 passed, 47438 subtests passed in 22.91s
```

`nft list ruleset` is empty afterwards, and no veth or namespace is left behind.

The two runs are complementary rather than redundant. Run as `e4etest`, the
enforcement module reports **27 passed, 34 skipped**: the structural half runs
and the kernel half skips, loudly, naming what is missing. Those 34 are the bulk
of the full suite's 64 skips; the rest are generated-corpus and research-artifact
tests. Run as root, all 61 execute. Neither run alone covers the module, which
is why both are listed.

**Clean clone**, fresh venv on `/usr/bin/python3.12`:

```
git clone <repo> cleanclone
/usr/bin/python3.12 -m venv .venv
.venv/bin/pip install -e ".[test,capture,ml,enrichment]"
.venv/bin/python -m pytest tests/ -q
2071 passed, 88 skipped, 55931 subtests passed in 125.54s
```

Re-run on the final commit, `124d70f`. An earlier clean clone at `d3e17fb`
reported 2,049 passed / 85 skipped; the difference is the 22 replay-harness and
reachability tests added since.

**Lint:**

```
.venv/bin/ruff check .
All checks passed!
```

**Release check** (expected to fail; it is the release gate, not a test):

```
.venv/bin/python scripts/release_check.py --artifacts <dir>
release_ready: false
  RELEASE BLOCKER: private security reporting channel unconfirmed
  RELEASE BLOCKER: systemd service lifecycle under hardening = not_verified
  RELEASE BLOCKER: Docker read-only non-root Compose smoke = not_verified
  RELEASE BLOCKER: representative labelled shadow evidence for production enforcement = not_available
  + the five build artifacts, which are produced at release time
```

The licence blocker that appeared in this list at P15 is gone.

**The trusted evaluation**, reproducible from a clean checkout:

```
python -m dataset generate --matrix dataset/scenarios/matrix-eval-v1.toml \
    --output datasets/eval-v1 --dataset-version dataset-eval-v1
python -m training.decision_replay_cli \
    --corpus datasets/eval-v1/processed/dataset-eval-v1/samples.csv \
    --json reports/P15_1_DECISION_EVALUATION.json
```

Re-run on the final tree and compared byte for byte against the stored report:
identical confusion matrices, identical ROC-AUC and PR-AUC, identical drop
counts. The replay holds no state and the corpus is deterministic from its seeds.

**The readiness gate**, on a default configuration:

```
AUTONOMOUS_READY: NO
Blocked by: protected_networks
Recommended mode: SHADOW
```

---

## See Also

- [P15_1_BASELINE.md](P15_1_BASELINE.md): the blocker matrix this cycle worked from
- [P15_1_REPOSITORY_HANDOVER.md](P15_1_REPOSITORY_HANDOVER.md): how to restore the repository, and what was kept out of it
- [P15_1_DECISION_EVALUATION.md](P15_1_DECISION_EVALUATION.md): the measurement
- [BETA_EVIDENCE.md](BETA_EVIDENCE.md): owner statement against repository evidence
- [P15_FINAL_AUTONOMOUS_DEFENSE_REPORT.md](P15_FINAL_AUTONOMOUS_DEFENSE_REPORT.md): unedited
- [../docs/HOST_ENFORCEMENT.md](../docs/HOST_ENFORCEMENT.md)
- [../docs/MODULE_GRADUATION.md](../docs/MODULE_GRADUATION.md)
