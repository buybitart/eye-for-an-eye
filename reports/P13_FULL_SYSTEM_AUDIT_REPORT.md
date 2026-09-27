# P13: Full-system Integration Audit, Reliability and Public-beta Hardening

**Date:** 2026-09-11
**Scope:** P0–P12 as one system. No new features.
**Verified on:** Linux 6.18.44 x86_64, Python 3.12.3, 2 logical CPUs, 8.4 GB RAM,
run as an unprivileged user with `umask 022`.

---

## Headline

P13 was not asked to build anything. It was asked to find out whether thirteen
stages of correct components add up to a working system. They very nearly do:
and the gap was exactly the shape this stage exists to find.

**The learning loop had been terminating at step one.** `decision/engine.py` read
`ood_result.ood_score`, an attribute that does not exist. The `AttributeError`
was raised inside a `try` whose `except` swallows everything (correctly, because
collecting training material must never interrupt defending), so every review
queue offer was abandoned silently. A counter incremented. Nothing else looked
wrong. No samples reached a person, so no labels, so no dataset, so no candidate
model. Every component of P9 passed its own tests the whole time.

**`model rollback` did not reach a running sensor.** The registry moved, the
audit trail recorded it, the CLI said "done", and the sensor process went on
using the withdrawn model indefinitely, because `ModelResolver` cached each
site's resolution with no expiry and nothing in the codebase ever called
`invalidate()`. The emergency lever moved and nothing at the far end of it did.

**The security gate was red and nothing in the test suite was looking.**
`scripts/security_scan.py` exits non-zero on an unreviewed Bandit finding and had
been doing so since `decision/registry.py` acquired an `os.chmod(..., 0o755)`
that was never entered in the review register. The only signal was a CI run.

**And the project is not in version control at all.** There is no `.git`
directory in the Windows working copy, which is why this report has no
`git diff --stat`, and which sits underneath a CHANGELOG, a release script and
three CI workflows that all assume a repository.

Twelve findings in total: ten fixed, one withdrawn as a false positive on
re-examination, one an owner action. Three release blockers remain, none of them
fixable by an engineer alone.

---

## The Required Lines

```
Tests:              1522 passed, 30 skipped, 2824 subtests   (1552 collected, 87 files)
Lint (ruff):        PASS
Privacy:            PASS
Secret scan:        PASS   (working tree; Git history NOT scanned, see below)
One-command install: PASS  (installed, verified, re-run, uninstalled, purged)
CI:                 PASS   (configuration reviewed; every step reproduced locally except mypy)
Bandit gate:        PASS   (7 findings, all reviewed, each with a written reason)
Soak (900 s):       PASS   (54 000 events offered, 54 000 accepted, 0 dropped)
LICENSE:            MISSING, RELEASE BLOCKER
Version control:    ABSENT, no .git in the project directory
P14_AUTO_PROMOTION_READY: NO
```

---

## Findings

Severity is about consequence, not effort.

### 1. CRITICAL: The Review Queue Received Nothing Whenever OOD Was Working

`eye_for_an_eye/decision/engine.py`. The offer read `ood_result.ood_score`; the
field is `score`. `OODResult` is a slotted frozen dataclass, so the access raised
rather than returning `None`, and the raise happened inside the swallow.

The swallow is right and stays. What was missing was any way to tell a permanent
failure from a transient one, so the engine now also records
`review_queue_last_error`. A counter can say something failed a thousand times;
only a message can say what.

**Fixed.** `tests/test_p13_integration.py` asserts the end-to-end property (a
sample a person should see reaches the queue) rather than the components, and an
AST test reads `engine.py` and checks that every attribute it reads off a result
object actually exists. That second test is the one that catches the *next* typo.

### 2. HIGH: `model rollback` Did Not Reach a Running Sensor

`eye_for_an_eye/sites/models.py`. `ModelResolver._cache` had no expiry, and
`invalidate()` was called by nothing in the codebase. Rollback runs in a separate
CLI process, so an in-process hook could never have been the mechanism.

**Fixed.** `resolve()` now stamps each cached entry with the stat fingerprint of
the pointer files the answer depends on, and rebuilds when they change. Two
`stat` calls per resolve. That is the right price: the alternative was an
emergency lever that silently did nothing until somebody thought to restart the
service, during the incident it exists for.

### 3. HIGH: The Security Gate Was Failing and Only CI Could See It

`security/bandit-reviewed.json` had no entry for
`decision/registry.py:280` (`B103`), so `scripts/security_scan.py` exited 1.

Reviewing it surfaced a second problem: the register compared whole records for
equality, so an entry could carry nothing but a hash. **A register of accepted
security findings that cannot say why any of them was accepted is not a review.**

**Fixed.** The scan now matches on identity and requires a non-empty `reason`;
an entry without one does not count as reviewed, so a finding cannot be silenced
by adding a hash. All seven findings are now recorded with their reasoning, six
false positives explained, and the `chmod` accepted on its merits (0o755 on a
model-version directory a sensor running as another user must read; no write bits
for group or other, and `onnx_model._read` refuses any artifact with
`st_mode & 0o022` regardless). The suite now runs the gate.

### 4. MEDIUM: A Model That Would Not Load Reported Only `ValueError`

`eye_for_an_eye/decision/onnx_model.py`. All twenty-odd refusals: corrupt file,
hash mismatch, wrong feature schema, bad permissions, unsupported operator,
oversized tensor, were indistinguishable to an operator whose classifier had
stopped answering, which is precisely when they need to know which.

The reason the class name was used alone is real: an arbitrary exception message
can carry a filesystem path. **Fixed** narrowly: `SAFE_REASONS` lists this
module's own fixed strings, none of which interpolates anything, and only those
pass through. Anything from onnxruntime, json or the OS still reports its class
alone. Two AST tests keep the list from rotting in either direction.

### 5. MEDIUM: Two Configuration Settings That Do Nothing, Described as if They Do

`learning.auto_train` and `learning.auto_prepare_dataset` exist, default to
`false`, and **are read by no code that could act on them**. Meanwhile
`decision/retraining.py` opened with "There is no `auto_train` setting in this
project", `config.py` said turning it on "lets the system ... train a candidate
model", `docs/RETRAINING.md` annotated it "train a candidate without being
asked", and `learning status` printed a bare `OFF`, which an operator reads as
"wired up, currently off".

Inert is safe in one direction and misleading in the other: nobody turns
automatic training on by accident, but somebody who sets it `true` and believes
the system is retraining itself is wrong and finds out late. Denying the setting
exists is how that stays hidden.

**Fixed** by making all four places say the same true thing: reserved, not
honoured. A test asserts the inertness the words depend on, by checking which
modules mention each name at all, so wiring one up forces the words to be
revisited.

### 6. MEDIUM: Three Documents Described a P0–P9 System

`docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` and
`docs/SECURITY_REVIEW_SCOPE.md` had **zero** coverage of P10, P11 and P12.
The web sensor, the challenge and multi-site profiles. That is most of the code
written since P9 and nearly all of the attacker-facing surface. An auditor
following `SECURITY_REVIEW_SCOPE.md` would have reviewed none of it.

The same document also had the feature tensor at 34 columns (it is 36) and the
test count at 353 (it is 1552).

**Fixed.** Architecture gains the second pipeline (access log, gateway, site
resolution) drawn beside the packet one, because the difference between a
component that cannot break a website and one that can is the point. The threat
model gains a section per stage and three trust-boundary rows. The review scope
gains priorities 11, 12 and 13 and four new falsifiable claims, and states that
an earlier revision would have led an auditor to review none of the new surface.

### 7. MEDIUM: Cross-site Evidence Eviction Was First-seen, Not Least-recently-used

`eye_for_an_eye/sites/engine.py`. A source rotating through more than 4 096
addresses would have evicted the evidence for the source actively probing,
exactly the entry worth keeping. **Fixed** (re-insert on touch, so dictionary
order really is LRU, matching what `WebSourceTable` already did).

### 8. MEDIUM: `ModelResolver`'s Cache Was Unbounded

`resolve()` accepts any string. Nothing today passes a `Host`-derived id, but a
future caller that did would have made it attacker-keyed. **Fixed:** bounded at
256 sites. The bound belongs in the resolver, not in its callers.

### 9. LOW: Evicted Web Sources Were Forgotten Only on `poll()`

`eye_for_an_eye/web/sensor.py`. **Fixed:** `evaluate()` calls `_forget_evicted()`
as well.

### 10. LOW: The Legacy Corpus `label_source` Was Outside the Accepted Vocabulary, Silently

`training/build_dataset.py` emits
`synthetic_scenario_intent_not_observed_verdict`, which is not in
`ALLOWED_LABEL_SOURCES`. That is *correct* (the current validator should refuse
a v2 corpus), but nothing said so, so the next person to meet it would have had
to guess whether it was deliberate, and the obvious "fix" (widening the accepted
tuple) would have weakened a gate to tidy a name.

**Fixed** by stating it: `LEGACY_LABEL_SOURCES` names the value, the generator's
docstring explains why changing it would defeat the only reason that file still
exists, and four tests hold the two vocabularies disjoint.

### 11. LOW: Benchmark Reports Described the Wrong Operating System

`benchmarks/common.py` hardcoded `kernel_settings` as `'Windows defaults; no
tuning; Linux sysctl not applicable'` and filled `physical_ram_bytes` only on the
Windows path, so every benchmark report produced on Linux carried a null RAM
figure and a sentence about Windows. `benchmarks/soak.py` hardcoded "30 seconds
is a short soak" into the limitations of a run of any length.

A performance baseline whose environment block describes a different machine is
not a baseline anyone can compare against. **Fixed**: both now report the run
that actually happened.

### 12. HIGH (Owner Action): The Project Is Not Under Version Control

the Windows working copy contains no `.git` directory. Found at the end of the audit,
while trying to produce the `git diff --stat` this report is supposed to end
with.

Nothing in the tree contradicts it (the repository cleanup record refers to
"after the first commit"), but the consequences are not small. Nothing has ever
been reviewed as a diff. Nothing can be bisected. The release build, the package
smoke test and three CI workflows are all written around `actions/checkout` and
have nothing to check out. For a project whose pitch to a reviewer is "the source
is small enough to read completely", the absence of any history is a real gap in
what that reviewer can verify.

The one piece of good news is the secret question: nothing has been committed, so
nothing is in any history, so nothing needs rotating on that account.

**Not fixed here.** Initialising a repository is an owner decision, what the
first commit contains, what stays out, whether an existing history is imported.
See the `git diff --stat` section for what must happen if one is.

### WITHDRAWN: The Anomaly Docstring Is Accurate

Flagged during the audit as an overclaim: `anomaly.py` says the score "can never,
on its own, reach a blocking decision" while `policy.py` adds
`anomaly_weight * anomaly_score` to the evidence. Re-reading the arithmetic, the
claim is true and stronger than it looked: `anomaly_weight` (0.10) is **carved
out of** the maths+ML pool, not added on top (the remaining weights are scaled
by `(pool - anomaly_weight) / pool` first), so evidence with an anomaly model
present can never exceed what it would have been without one. A perfect anomaly
score alone reaches 0.10, and `PolicyGuard` separately refuses ML-assisted
enforcement below `minimum_math_risk` (0.80).

**Not a defect.** The docstring now shows the arithmetic so the next reader can
check it in thirty seconds instead of re-deriving it, but nothing about the
behaviour changed. Recorded here because an audit that only reports its hits is
not reporting its accuracy.

---

## Release Gates

| Gate | Result | Evidence |
| --- | --- | --- |
| **A. Tests** | **PASS** | 1522 passed, 30 skipped, 2824 subtests, 87 files. Every skip is a generated artifact not distributed in the source archive, or the isolated-Linux namespace lab. No skip hides a failure. |
| **B. Lint and static analysis** | **PARTIAL** | `ruff` clean across `eye_for_an_eye tests scripts benchmarks training dataset`. **`mypy` could not be run here**: it is in the optional `quality` extra and is not installed in this environment. CI runs it; this report does not claim it passes. |
| **C. Security** | **PASS** | `scripts/security_scan.py` exit 0: 7 Bandit findings, all reviewed with written reasons; 0 secret-pattern hits. `scripts/verify_systemd.py` exit 0. |
| **D. Reliability under failure** | **PASS** | 37 injected-failure cases in `tests/test_p13_degraded_modes.py`. Gateway fails open on a raising sensor, a raising challenge service, malformed cookies, hostile `Host` headers and nonsense risk values. Doctor completes with unreadable storage. No failure path raises risk. |
| **E. Drills** | **PASS** | 19 cases in `tests/test_p13_drills.py`: model rollback start to finish, site rollback isolation, configuration migration from a pre-P10 file. The site-rollback drill is what found finding 2. |
| **F. Installation** | **PASS** | Run here, not just in CI: `--help`, `--dry-run` (created nothing), a real install to a temporary prefix, `--version`, `config validate`, `doctor` all-healthy, `check_safe_defaults.py` confirmed, a second install that left the config byte-identical, uninstall that kept data, `--purge` that removed it. |
| **G. Documentation** | **PASS** | Three stale architecture/security documents brought up to P12. `docs/P0_P12_STATUS.md` and `docs/SCHEMA_COMPATIBILITY.md` added, both mechanically checked. Doc tests: 54 passing across the challenge and multi-site sets. |
| **H. Open source** | **FAIL** | **No LICENSE file**: source you can read is not open source. **And no repository:** there is no `.git` directory in the project folder, so nothing has been committed, reviewed as a diff, or made checkoutable by the CI that assumes it. |

---

## Privacy Audit

**PASS.** No claim in the documentation was found that the code does not support.

* **What reaches disk.** Source IP, port, destination, timestamp, classification
  and bounded metadata, in the local SQLite store. `docs/PRIVACY.md` line 63 says
  plainly: "The source IP address **is** stored." No payload, body, cookie,
  `Authorization` header or raw packet bytes.
* **Pseudonymisation where it matters.** The review queue HMACs source keys with
  a per-install secret and **refuses to open without one** rather than storing
  raw addresses, verified by injecting an empty secret path and asserting the
  queue stays closed.
* **Retention exists in code**, not only in prose: `storage.retention_seconds`,
  batched deletion, incremental vacuum, and a `retention_backlog` degraded state
  when it cannot keep up.
* **Nothing leaves the machine by default.** Every `connect` in the package goes
  to loopback or a Unix socket. `onnxruntime` telemetry is explicitly disabled in
  both the inference and benchmark paths. The one egress path (RDAP enrichment)
  requires `enrichment.enabled` *and* `rdap_enabled`, both `false`, plus an
  explicit `--rdap` flag, and `docs/PRIVACY.md` says so in its first paragraph.
* **Site identity never becomes a model feature.** `site_group`, `site_id`,
  `domain`, `host` and `profile_type` are all in `NEVER_MODEL_INPUT`.

## Secret Scan

**PASS, with a stated limitation.** No `.pem`, `.key`, `.env`, `id_rsa`,
`credentials.json` or `*.secret` file exists in the tree. No hardcoded credential
matches in any config, script, Dockerfile or workflow. `.gitignore` covers all of
those patterns plus runtime-written secret paths. Generated secrets are created
at install time with `O_EXCL` and mode `0600`, and are never printed.

**Git history was not scanned, because there is none.** The project directory
contains no `.git` at all. See the `git diff --stat` section below. The
project's own scanner states the matching limitation in its output
(`"scope": "working source; no Git history available or scanned"`).

Per §50, the requirement therefore inverts rather than disappearing: nothing has
been committed, so no secret sits in any history and none needs rotating on that
account, but **if this tree is ever imported into a repository that already has
history, that history must be scanned before publishing, and any secret found
there must be rotated; deleting the current file is not enough.** No evidence of
a committed secret was found in the working tree.

---

## Performance and Reliability Measurements

All single process, one core of two, no network, synthetic traffic. These
describe this machine and this configuration, not a deployment.

**Soak, 900 seconds** (`benchmarks/soak.py`):

```
offered            54 000 events
accepted           54 000        (0 dropped, 0 shed)
threads            1 -> 1        (no leak)
open handles       4 -> 4        (no leak)
RSS                29.1 MB -> 36.5 MB -> 34.6 MB after gc
latency            p50 3.59 ms   p95 12.76 ms   p99 16.36 ms   max 27.14 ms
shutdown           0.077 s
health at end      degraded (ml unavailable, correctly reported)
```

RSS grew about 5.5 MB over fifteen minutes and gave 1.9 MB back to a collection.
That is bounded, and fifteen minutes is not evidence about fifteen hours. The
soak says so itself now, in its own limitations, with the duration it actually
ran.

**Multi-site under a flood** (`benchmarks/bench_sites.py`):

```
quiet site sources    40 before, 40 after, 0 evictions
busy site evictions   197 952
200 000 invented Host values -> 4 sites (unchanged), unknown bucket 256 sources
throughput            79 591 events/s (1 site), 88 366 events/s (10 sites)
memory                one global ceiling shared across sites, not multiplied
```

**Challenge request path** (`benchmarks/bench_challenge.py`):

```
request with valid token   p50 39.93 us   p95 67.91 us   p99 84.68 us
challenge response         p50 28.04 us   p95 49.03 us   p99 69.22 us
response size              838 bytes
state at capacity          10 000 contexts, 943.7 bytes each
```

**Training/runtime parity** (`tests/test_p13_schemas.py`, new): the shipped
logistic regression recomputed in float64 against the onnxruntime float32 graph
over 22 spanning tensors, worst absolute difference within `1e-5`. The existing
parity tests need the research dataset and skip for anyone working from the
source archive; this one runs from a clean checkout, which is the case that
matters for a security review.

**Not measured:** the full-stack inference baseline (`benchmarks/p7_inference.py`)
requires the research dataset, which is not distributed. Stated rather than
estimated.

---

## The Shipped Model, Stated Plainly

```
recommended_mode      shadow
quality_gate_passed   false
validation PR-AUC     0.997
test PR-AUC           0.699   (held-out scenario families)
ONNX parity           passed, max abs diff 3.6e-07
```

The distance between 0.997 and 0.699 is the whole story: very good at the
scenario families it saw, considerably less good at ones it did not, which is
what a synthetic corpus buys and why the gate says no. It ships so the pipeline
around it can be exercised end to end, and it ships in shadow.

---

## Release Blockers

1. **No LICENSE file.** `pyproject.toml` declares no license expression and
   carries the comment `# RELEASE BLOCKER: maintainer must supply LICENSE and an
   approved SPDX license expression`. A licence has **not** been invented here.
   When one is added, `MANIFEST.in` needs `include LICENSE` or the sdist will not
   ship it, `tests/test_p13_degraded_modes.py` fails and says so at that point.
2. **No private security reporting channel.** Carried forward from
   the repository cleanup record; an owner decision, not an engineering task.
3. **The project is not under version control.** No `.git` directory exists in
   the Windows working copy. Everything downstream of a repository (CI, the release
   build, review as diffs, bisection, the "read the source" pitch) assumes one.

None is fixable by an engineer alone, and none has been worked around.

## Other Open Owner Actions (Unchanged From P12)

Move the third-party PDFs out of the project folder; decide what happens to the
Russian files in `docs/history/`; decide whether `AGENTS.md`,
`SECURITY_AGENT.md`, `SKILL.md` and `clean-code-policy.md` belong in a public
repository; scan Git history for secrets if this tree is imported into an
existing repository.

**Downgraded:** "set the executable bit on the install scripts" is no longer an
action. The README documents `sh scripts/install.sh`, which works whether or not
the mode bit survives an archive, and CI invokes it the same way. A test now
checks that if the README ever switches to `./scripts/install.sh`, the bit
becomes required.

---

## `+*.py` and Generated Directories (§92–§96)

Nothing was deleted. The six `+`-prefixed root files are compatibility
entrypoints classified in the repository cleanup record, and at least one is
load-bearing: `tests/test_cli_integration.py` starts `+garbage.py` as a
subprocess. `MANIFEST.in` ships them deliberately. The generated directories
present in this working copy (`build/`, `__pycache__/`, `.pytest_cache/`,
`.ruff_cache/`, `eye_for_an_eye.egg-info/`, `.p5-check/`, `.venv/`) are each
covered by `.gitignore`.

---

## A Note on Running the Tests

**Run the suite as a normal user.** As root, the hardened artifact reader
correctly refuses model files owned by another user
(`st_uid not in (0, os.geteuid())`), and several P7 tests fail for that reason
alone. During this audit that behaviour was briefly mistaken for a defect. The
guard is right; the invocation was wrong. This is now stated in
`docs/P0_P12_STATUS.md` and `docs/SECURITY_REVIEW_SCOPE.md`.

---

## `git diff --stat`

**Not available, and the reason turned out to matter.**

The audit ran on a staged working copy, so the first explanation was simply that
the copy is not a repository. Checking the project directory itself
(the Windows working copy) at the end of the audit gave the real one: **there is no
`.git` directory there either. This project has never been committed to version
control.**

Nothing in the repository contradicts that. The repository cleanup record says
"after the first commit", and `.gitignore`, `.gitattributes` and the GitHub
workflows are all written in anticipation, but it is worth stating rather than
leaving as an inference from a missing command, because three things follow from
it.

**It is a release-readiness gap in its own right.** There is a CHANGELOG, a
ROADMAP, a release build script, a package smoke test and three CI workflows
built around `actions/checkout`, and no repository for any of it to run against.
Nothing has been reviewed as a diff, and nothing can be bisected. For a project
whose pitch is "read the source, it is small enough", the absence of history is
a real gap in what a reviewer can check.

**It is the best possible answer to the secret-history question.** §50 asks what
to do if a secret appears to have been committed. Nothing has been committed, so
no secret is in any history and none needs rotating on that account. The
requirement inverts: initialise the repository from this tree, and **do not
import it into a repository that already has history without scanning that
history first**.

**It is why `git diff --stat` is absent from this report** rather than
reconstructed. The file-by-file summary below is the substitute, and the 30
files listed are every file whose contents changed during P13.

## Files Changed

### New: Documentation

| File | Lines | What it is |
| --- | --- | --- |
| `docs/P0_P12_STATUS.md` | 264 | Every feature marked IMPLEMENTED / PARTIAL / EXPERIMENTAL / LAB_ONLY / DOCUMENTATION_ONLY / MISSING, with test counts and reasoning. Enforcement is LAB_ONLY regardless of coverage, because coverage is not deployment evidence. |
| `docs/SCHEMA_COMPATIBILITY.md` | 100 | What happens when each of ~40 version constants meets an older value. Separates the ones that gate behaviour from the ones that are labels on a report. |

### New: Tests

| File | Lines | Cases | What it covers |
| --- | --- | --- | --- |
| `tests/test_p13_integration.py` | 475 | 34 | The review queue end to end; result-object attribute reachability by AST; drift and OOD reducing authority rather than raising risk; reserved settings; the legacy label vocabulary; the security gate being green on this tree. |
| `tests/test_p13_degraded_modes.py` | 497 | 37 | §117–§118. One injected failure per case: does it still work, does it say so, does it stay calm. |
| `tests/test_p13_drills.py` | 323 | 19 | §128–§130. Model rollback, site rollback isolation, configuration migration; each written as the sequence an operator performs, with state inspected between steps. |
| `tests/test_p13_schemas.py` | 213 | 10 | §6 and §8. The compatibility matrix cannot go stale; training and runtime agree, checked from a clean checkout. |

### Modified: The Fixes

| File | Change |
| --- | --- |
| `eye_for_an_eye/decision/engine.py` | Finding 1. `ood_result.score`, plus `review_queue_last_error`. |
| `eye_for_an_eye/sites/models.py` | Findings 2 and 8. Pointer-fingerprint invalidation so a rollback reaches a running process; cache bounded at 256 sites. |
| `eye_for_an_eye/sites/engine.py` | Finding 7. Cross-site eviction is now true LRU. |
| `eye_for_an_eye/web/sensor.py` | Finding 9. `_forget_evicted()` on `evaluate()` as well as `poll()`. |
| `eye_for_an_eye/decision/onnx_model.py` | Finding 4. `SAFE_REASONS` and `_reason()`: our own fixed strings reach the operator, foreign messages report a class name only. |
| `scripts/security_scan.py` | Finding 3. Identity matching plus a required `reason`; a hash alone no longer silences a finding. |
| `security/bandit-reviewed.json` | Finding 3. Seven findings, each with its reasoning written out. |
| `benchmarks/common.py` | Finding 11. Real CPU, RAM and kernel description on Linux. |
| `benchmarks/soak.py` | Finding 11. Limitations describe the run that happened. |

### Modified: Accuracy

| File | Change |
| --- | --- |
| `eye_for_an_eye/decision/retraining.py` | Finding 5. Stops denying that `auto_train` exists; explains why the correction matters more than the sentence did. |
| `eye_for_an_eye/config.py` | Finding 5. Both settings marked RESERVED and not honoured, with why they are kept rather than deleted. |
| `eye_for_an_eye/learning_cli.py` | Finding 5. `learning status` no longer prints a bare `OFF`; JSON gains `auto_train_status`. |
| `eye_for_an_eye/decision/anomaly.py` | Withdrawn finding. Shows the carve-out arithmetic so the claim is checkable. |
| `training/schema.py` | Finding 10. `LEGACY_LABEL_SOURCES`, deliberately disjoint from the accepted set. |
| `training/build_dataset.py` | Finding 10. Docstring explains why its `label_source` must not be "fixed". |
| `docs/ARCHITECTURE.md` | Finding 6. The second pipeline: access log, gateway, site resolution. Four additions to "what the architecture does not do". |
| `docs/THREAT_MODEL.md` | Finding 6. Sections for P10, P11, P12 and three trust-boundary rows. |
| `docs/SECURITY_REVIEW_SCOPE.md` | Finding 6. Priorities 11–13, claims 9–12, corrected sizes (36 columns, 1 552 tests). |
| `docs/RETRAINING.md` | Finding 5. The reserved settings, in the operator's document. |
| `README.md` | Links "What actually works", the review scope and the compatibility matrix. |
| `CHANGELOG.md` | A P13 section. The file had been stuck at "Unreleased (P11)" through two stages. |
| `tests/test_p7_onnx.py` | Deadline assertion updated for the richer error reason. |
| `tests/test_retraining_advice.py` | `test_there_is_no_auto_train_setting` renamed: the name was a lie; what it checks is that this module never assigns it. |

---

## `P14_AUTO_PROMOTION_READY: NO`

Not close, and the reasons are not about code quality.

1. **The loop has never run.** Until this audit its first step was broken: no
   sample reached a person, so no label, no dataset, no candidate. It is fixed
   and tested, and it has still never been driven by traffic from a server
   anybody depends on. Automating the end of a pipeline whose beginning has never
   carried real data would be automating an assumption.

2. **The gate the automation would depend on currently says no.** The shipped
   model has `quality_gate_passed: false` and a held-out PR-AUC of 0.699. A
   promotion gate is only a safety mechanism if the thing it gates is otherwise
   good enough to promote; here it is correctly refusing, and an automatic
   promoter would have nothing to promote.

3. **The corpus is synthetic.** Reproducible, leakage-checked, documented; and
   generated. The 0.997/0.699 gap is what that costs. Automatic promotion on
   synthetic-only evidence would ship a model chosen by a proxy for the problem.

4. **No deployment evidence at all.** Enforcement is LAB_ONLY. No block has been
   placed on a production server by this software. Automatic promotion decides
   what gets blocked; the manual version of that decision has never been
   exercised in anger.

5. **Two things that were "obviously fine" were not.** A review queue that
   received nothing for months and a rollback that did not reach the running
   process both passed every component test. Both were found by asking
   whole-system questions, and both sat directly on the path P14 would automate.
   That is the strongest available argument for doing P13 before P14, and it
   argues equally for waiting now.

**What would change the answer**, roughly in order: a real deployment running the
full loop in shadow with a person labelling; a corpus with non-synthetic rows; a
candidate that passes the quality gate on held-out families; a rollback drill
executed on a running system rather than in a test; and enough operating history
that "the gate passed" means something an operator would bet a website on.

`auto_promote` remains absent from the configuration entirely. A name that does
not exist cannot be set by accident, and that is the right state until every item
above has an answer.

---

## Conclusion

The system works. Ten real defects were found and fixed, three of them in places
where every component was individually correct and the integration was not,
which is the failure mode P13 exists to find and the reason it was worth doing
before P14 rather than after.

What stands between this and a public beta is not engineering. It is a LICENSE
file, a private security reporting address, and a first commit. All three need
the owner.
