# Changelog

## 0.8.0rc2 — Public Beta

Pushing 0.8.0rc1 to a public repository ran this project's continuous integration
in public for the first time, and two jobs went red. This release is that repair
and nothing else. No detection logic, threshold, calibration, model, policy guard,
enforcement path or configuration default changed, and no validation claim moved:
real-world validation of autonomous blocking is still pending and automatic
blocking is still off after installation.

0.8.0rc1 stays published and its failed CI run stays visible. It is the evidence
that these were real problems.

### Fixed

* **`install-smoke` asserted the opposite of the correct answer.** The job ran
  `eye-for-an-eye doctor` as a plain command under `set -e`, which asserts exit 0.
  `doctor` exits 7 when any component is degraded, and on a fresh install of the
  safe profile that is the required answer rather than a fault: no calibrator, no
  access log and no web secret are configured, because the installer does not
  invent deployment-specific artifacts. The expectation held only while the
  installed profile was `website`, which has no `[autonomy]` section and so
  nothing to degrade; it was not updated when the installed default became
  `production-shadow`. The job now asserts exit 7 **and** that the degraded set is
  exactly those three gaps, so a regression that degrades the database, the
  configuration, the security policy or file permissions still fails it. A test
  now ties the installed profile and the CI expectation together, because reading
  either alone could not have revealed the conflict.
* **The release archives and the repository shipped different bytes.** 40 files
  were stored in Git with LF, as `.gitattributes` requires, while every archive
  carried CRLF for those same files -- three systemd units, three configuration
  templates, seven runtime modules and five fixtures among them -- because the
  archives were built from a working copy checked out on Windows. Two people
  installing the same version received different bytes, and the SHA-256 of a
  source file in the Debian package did not match the same file in the repository.
  The release root, the repository and a fresh clone now agree.
* **The clean-clone gate had never cloned.** It was a copy of the release root
  with `git init` run inside it, so it measured the tree it was copied from and
  could not see a difference introduced by checkout. It is a real `git clone` now.
* **22 lint findings**: unused imports and two redundant f-string prefixes. One of
  them was not safe to remove mechanically -- `MAX_ENTRY_BYTES` is re-exported
  from `autonomy.journal`, which the journal's own tests import it from -- and it
  is restored with an explicit marker saying so.
* **A duplicate test method**, defined twice in one class with identical bodies, so
  only the second ever ran.
* **A benchmark's timed callable** closed over a variable the enclosing function
  later deleted. It worked only because the timing helper calls it immediately; it
  is now self-contained.
* **A missing type annotation** that `mypy` reports. Nobody had seen it because
  the lint step runs first and stopped the job before `mypy` ran.
* **A version bump could reach some files and not others.** The version is written
  in three spellings for three packaging systems; a test now requires them to
  agree, so a wheel named rc2 cannot contain a command that prints rc1, and the
  container job cannot build one image tag and run another.

## 0.8.0rc1 — Public Beta

The first release meant to be downloaded and installed by somebody who did not
write it. The version string has not moved since it was introduced; what changed
is that there is now a way to get the software, install it, and use it without
reading the source.

Automatic blocking is still off after installation, and real-world validation of
autonomous blocking is still pending. See
[docs/VALIDATION_STATUS.md](docs/VALIDATION_STATUS.md).

### Added

* **A Linux release archive and a Debian package.** The archive unpacks into one
  directory with `START_HERE.md` and `install.sh` at the top. The package installs
  under `/usr` on Ubuntu 24.04 and derivatives whose system Python is 3.12, with
  the systemd units present and disabled and no configuration under `/etc`.
* **`eye-for-an-eye setup` asks what to watch** and checks the answer — that the
  access log exists, can be read, and is in the format the reader parses. Nobody
  edits a configuration file by hand to get started.
* **A beginner command surface:** `setup`, `start`, `status`, `stop`, `demo`,
  `check-install`, and `easy <action>` for the short answers. The expert commands
  mean exactly what they always meant.
* **Windows beginner launchers** for install, start, status, demo, stop and
  uninstall. Windows can watch a website log and run the demo; packet capture and
  blocking are Linux only, and the documentation says so rather than implying
  parity.
* **`SHA256SUMS` over every release artifact**, and a CycloneDX 1.6 SBOM.
* **An install receipt**, so `status`, `check-install` and `uninstall` know what
  this machine has instead of guessing at it.

### Fixed

* The Linux installer and the beginner commands disagreed about where the
  configuration lives, so a **successful** install was followed by *"a settings
  file exists — NO"*, and `start` told a Linux user to double-click a Windows
  `.cmd` file.
* `easy uninstall` reported success on Linux for work it had not done.
* `status` failed with an errno on every fresh install instead of saying
  `NOT RUNNING`; `doctor` and `status` without `--config` reported on built-in
  defaults rather than on this machine's configuration.
* The beginner guide named an access-log format the reader cannot parse, which
  would have produced a sensor that runs happily and sees nothing.
* The Linux installer defaulted to a profile with no `[autonomy]` section, so a
  Linux install ran no decision path while a Windows install ran the full one in
  shadow. Both now install `production-shadow`.
* An error message named a command that has never existed.
* The release builder required exactly three configuration templates and the
  project has had six since the production profiles were added.

### Known limitations

* Real-world validation of autonomous blocking is **pending**.
* Not tested: live packet capture, `CAP_NET_RAW`, the namespace firewall, the
  systemd units under a running systemd, distributions other than Ubuntu 24.04.
* The release artifacts are **not signed**. Verify `SHA256SUMS` instead.
* Downgrading is not tested.

---

The entries below are development-phase records, kept as history. They were
written before the version above was prepared for release, and their `Unreleased`
headings refer to the phase that produced them rather than to a pending release.
Their measurements are not restated or revised here.

## Unreleased (P15.1) — evidence, enforcement, and a units error

The cycle that measured what P15 had built. The headline is not a feature: on a
trusted labelled corpus of 709 sources, **the autonomous authority blocked
nothing at all**, and the cause was an arithmetic mistake nobody had noticed.

### Fixed

**An uncalibrated score was being compared against a probability.** The
cost-sensitive cutoff is `C_FP / (C_FP + C_FN)` — the *probability* of
maliciousness at which blocking becomes the cheaper error. When calibration was
unavailable, P15 fell back to comparing `MathRisk`, an uncalibrated score on its
own scale, against that number. The two are not the same quantity, and the
comparison was meaningless in both directions.

The repair is a hard gate, not a rescue: `CALIBRATION_UNAVAILABLE` now refuses
the block outright, and a test asserts that `math_risk = 1.0` still yields
`ALLOW`. This makes the system block *less*, which is the correct direction for
a fix to a measurement error — §45 forbids solving a model problem by lowering a
gate, and it equally forbids solving it by keeping a comparison that does not
type-check.

### Added

**A real-host enforcement path**, off on a fresh installation, behind
`enforcement.host_enabled`. Privilege separated end to end: the decision
authority holds no firewall handle, `PolicyGuard` can only weaken an action, and
what crosses the boundary is an `EnforcementRequest` carrying an address, a
family, a scope, a lifetime, a decision id and reasons — **and no command
field**. A privileged helper in a separate process validates all of it again
against its own copy of the configuration before writing. Blocks live in one
nftables table per installation, marked with an owner comment; a table with the
right name and the wrong owner is refused rather than adopted. Every element
carries a kernel timeout, so a sensor that dies never leaves a permanent block
behind. 61 tests, the kernel half run against a real `nft` on a disposable
machine. See [docs/HOST_ENFORCEMENT.md](docs/HOST_ENFORCEMENT.md).

**`training/decision_replay.py` and its CLI** — the measurement P15 could not
make. It replays a trusted labelled corpus through the complete decision path to
the final `ALLOW` / `TEMP_BLOCK` and reports rare-class metrics for the *action*,
per window and per source. Three assumptions are stated and all three make the
result harder, not easier: every source is treated as directly connected and
network-enforceable, every source is replayed cold with no offence history, and
labels come only from `controlled_scenario`, `manual_review` and
`trusted_fixture`. Predictions are never used as labels.

**A licence.** MIT, Copyright (c) 2026 Aliaksandr Zasinets, with SPDX metadata,
sdist inclusion, `THIRD_PARTY_NOTICES.md` and `scripts/license_audit.py`.

**Version control.** A local repository on `main`, with the ignore rules
reviewed against secrets, runtime databases, telemetry, generated corpora and
private reference material before the first commit. Nothing is pushed anywhere.
`COMMIT_SIGNING_NOT_CONFIGURED`.

### Measured

`reports/P15_1_DECISION_EVALUATION.md`: 565 benign and 144 malicious sources,
7,576 windows, **0 blocks**. Recall 0.000. False blocks per 1000 benign 0.0 —
true, and true because nothing is blocked. Block precision is undefined for the
same reason. Verdict `USELESS_NO_DETECTION`.

The ranking analysis says this is not only a threshold problem. The conservative
probability the decision runs on reaches ROC-AUC 0.626 per window and 0.783 per
source, where its own inputs reach more: raw `MathRisk` 0.775 / 0.827 and the
classifier 0.828 / 0.911. The shrinkage is not rank-preserving across different
observation counts, so the pipeline *loses* ordering information at the step
that decides.

And `models/risk-logreg-v1-evaluation.json` already contained a number nobody
had put in a summary: ROC-AUC **0.517** on the four withheld scenario families.
Chance. The 0.997 validation figure comes from a split sharing scenario families
with training, and the report's own limitations section says so.

### Not changed, deliberately

The 12-hour block ceiling, the cost profiles and their cutoffs, every gate
threshold, and the release thresholds in `ReleaseThresholds`. The lab namespace
path is untouched — the host path is new code beside it, not a relaxation of it.
No threshold was moved to obtain a pass, and the gates that still fail, fail on
evidence: **Gate C** (no validated classifier and no validated deterministic
fallback) and **Gate E** (block precision undefined because there are no blocks).

`AUTONOMOUS_READY` remains **NO**.

## Unreleased (P15) — autonomous decision authority

### Added

**`eye_for_an_eye/autonomy/` — the final ALLOW / TEMP_BLOCK authority.** One
explicit, auditable algorithm, holding no enforcement privilege: it imports
nothing that could reach a firewall, and a test parses its imports to keep that
true. Seven modules — `cost` (per-site cost profiles and the cutoff that follows
from them), `evidence` (ten independent signal families, each counted once),
`uncertainty` (the conservative estimate and expected loss), `record`
(`AutonomousDecisionRecord`, stable reason codes, the assumption registry),
`breakers` (block budget and three circuit breakers), `authority` (the algorithm),
`runtime` (readiness gate, automatic degradation and recovery), plus `evaluation`
(rare-class metrics for the final decision, in pure Python).

**A cost-sensitive cutoff instead of 0.5.** Five profiles — `public_website`
(0.9756), `api` (0.9877), `payment_webhook` (0.9980, and never a network block at
any probability), `admin` (0.8889), `honeypot` (0.6667). Costs are relative
weights with `C_FN = 1.0` as the unit; no monetary value is inferred, and no
learned component can write to them. Every decision record carries the cost
policy's content digest, so a decision taken under different numbers stays
identifiable.

**Three validations that could have been prose and are not.** A `TEMP_BLOCK`
record with no behavioural reason code raises — "BLOCK because the AI score was
0.93" cannot be represented in this system. An `ALLOW` with no reason raises. A
block carrying any restraining code raises, because a refusal means the answer
was ALLOW.

**Four brakes.** A block budget (10/minute, 500 active), a mass-block breaker
(2% of recent sources, with shadow decisions counted), a false-positive breaker
fed only by trusted evaluation — it refuses the system's own decisions outright
— and a technical breaker for the nine named subsystem faults. Any of them opens
`AUTONOMOUS_SAFE_MODE`: no new blocks, everything else continues, existing blocks
expire.

**Automatic degradation and recovery.** Degrading is immediate; returning needs
the fault cleared, a cooldown passed, and the readiness gate to pass again. No
administrator is involved in either direction.

**`eye-for-an-eye autonomy`** — `readiness`, `status`, `policy`, `explain`,
`science`, `enable`. `enable` runs the gate and prints the configuration to add;
it does not edit the file. `science` prints `GROUND_TRUTH_UNAVAILABLE` without a
trusted labelled evaluation, which is the honest answer and the usual one.

**`[autonomy]` configuration, off on a fresh install**, with `mode = "shadow"`.
Validation refuses an unknown cost profile, hysteresis pointing the wrong way,
and autonomy without the decision engine.

**Documentation:** `AUTONOMOUS_MODE.md`, `AUTONOMOUS_DECISION.md`,
`COST_SENSITIVE_POLICY.md`, `DECISION_UNCERTAINTY.md`, `SCIENTIFIC_BASIS.md`,
`MODULE_GRADUATION.md`, `AUTONOMOUS_FAILURE_RECOVERY.md`,
`AUTONOMOUS_SAFETY_INVARIANTS.md`, `AUTONOMOUS_DATA_CURATION.md`.

**Tests:** `test_p15_autonomy` (88), `test_p15_invariants` (45, including §195's
fourteen), `test_p15_science` (54), `test_p15_runtime` (36), `test_p15_docs` (25).

### Changed

**The feature dictionary now carries an evidence family and a privacy class.**
`datasets/model_features_v1.json` gains `feature_family`, `privacy`, `source` and
`model_usage` per column, plus a `privacy_classes` legend. Regenerating it also
picked up `domain`, which P12 added to `NEVER_MODEL_INPUT` after the file was
last written.

### Not changed, deliberately

**Enforcement is still lab-only.** Three independent gates keep it there: the
configuration refuses `enforcement.enabled` outside a lab profile with a named
namespace, the firewall backend compares the target namespace against
`/proc/1/ns/net` and refuses the host, and every command runs under
`ip netns exec`. P15 did not write host-namespace enforcement code, because
graduating it would have meant calling test coverage deployment evidence — the
substitution P13 explicitly refused. Autonomous mode on a production host means
autonomous *decisions*, and the readiness gate says so.

## Unreleased (P14) — scoped safe auto-promotion and model governance

### Added

**`eye_for_an_eye/governance/` — eleven lifecycle states, an explicit transition
table, and an assess-only engine of 45 gates that is separate from the
activator.** Nothing reaches ACTIVE except through GUARDED_ACTIVE; ROLLED_BACK
leads only to QUARANTINED; leaving QUARANTINED requires an operator.

**Guarded activation.** A candidate entering service does so under a reduced
action ceiling, and advancing needs observed evidence rather than elapsed time.

**Automatic rollback in three tiers**, and a promotion journal that freezes
promotion rather than resolving an unreadable file to "nothing was happening".

**`[model_governance]` configuration, every switch off.** Auto-promotion requires
guarded activation and automatic rollback; the global switch is a second
deliberate decision, not a detail of the first.

**`eye-for-an-eye model governance`** — status, policy, assess, history, audit,
freeze, unfreeze. No command promotes anything.

### Result

Shipped disabled. The recommended deployment posture is `AUTO-PROMOTION
DISABLED` until an installation has shadow evidence of its own.

## Unreleased (P13) — full-system integration audit

### Fixed

**The review queue received nothing whenever out-of-distribution scoring was
working.** `decision/engine.py` read `ood_result.ood_score`, which does not
exist; the attribute error was raised inside a `try` whose `except` swallows
everything, so every offer was abandoned silently while a counter incremented
and nothing else looked wrong. The learning loop's first step is "a sample
reaches a person", so the whole loop had been terminating at step one. The
engine now also records `review_queue_last_error`, because a counter alone
cannot tell an operator what went wrong.

**`model rollback` did not reach a running sensor.** `ModelResolver` cached each
site's resolution with no expiry and no invalidation signal, and nothing in the
codebase called `invalidate()`. Rollback is run from a separate CLI process, so
a sensor already running went on using the withdrawn model indefinitely while
the registry, the audit trail and the CLI all reported the rollback as done.
`resolve()` now checks the pointer files' stat fingerprint — two `stat` calls —
and rebuilds when they change.

**A model that would not load reported only `ValueError`.** All twenty-odd
refusals in `onnx_model.py` — corrupt file, hash mismatch, wrong feature schema,
bad permissions, unsupported operator — were indistinguishable. The module's own
fixed strings now travel with the class name; anything raised by onnxruntime,
json or the OS still reports its class alone, because an arbitrary exception
message can carry a filesystem path.

**The security gate was failing and nothing in the suite looked.**
`scripts/security_scan.py` exits non-zero on an unreviewed Bandit finding, and
`decision/registry.py` had acquired an `os.chmod(..., 0o755)` that was never
entered in the review register. The mode is correct and is now reviewed and
recorded with its reasoning; the register can carry a reason at all, which it
could not before; and the gate is checked by the test suite rather than only by
CI.

**Cross-site evidence eviction was first-seen, not least-recently-used.** A
source rotating through more than 4 096 addresses would have pushed out the
evidence for the source actively probing. **`ModelResolver`'s cache was
unbounded.** **`web/sensor.py` forgot evicted sources only on `poll()`, never on
`evaluate()`.**

### Changed

`decision/retraining.py` said "there is no `auto_train` setting in this
project". There is: `learning.auto_train` and `learning.auto_prepare_dataset`
both exist, both default to `false`, and **neither is read by any code that
could act on it**. They are now described as reserved and not honoured — in the
module, in `config.py`, in `docs/RETRAINING.md` and in `learning status`, which
no longer prints a bare `OFF` that reads as "wired up, currently off".

`docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` and `docs/SECURITY_REVIEW_SCOPE.md`
described a P0–P9 system. They now cover the web sensor, the challenge and
multi-site profiles, which between them are most of the code written since P9
and nearly all of the attacker-facing surface. `SECURITY_REVIEW_SCOPE.md` also
had the tensor width wrong (34, not 36) and the test count out by a factor of
four.

### Added

`docs/P0_P12_STATUS.md`: every feature marked IMPLEMENTED, PARTIAL,
EXPERIMENTAL, LAB_ONLY, DOCUMENTATION_ONLY or MISSING, with test counts and the
reasoning. `docs/SCHEMA_COMPATIBILITY.md`: what happens when each of the forty
version constants meets an older value. `tests/test_p13_integration.py`,
`tests/test_p13_degraded_modes.py`, `tests/test_p13_drills.py` and
`tests/test_p13_schemas.py`: failure injection, the rollback, site-rollback and
configuration-migration drills, a training/runtime parity check that runs from a
clean checkout, and a matrix check that fails when a new version constant is
added without documenting it.

### Still a release blocker

There is no LICENSE file. Source you can read is not open source.

## Unreleased (P11) — public release preparation

### Added
`eye-for-an-eye setup`: one command that writes a safe configuration, creates the persistent
deception secret when the profile needs one, creates the data directories and the empty local
database, and prints a short first-run summary. It defaults to Shadow Mode and never touches the
firewall. `eye-for-an-eye model status`: a short, plain report of the local model. A `website`
setup profile (`eye_for_an_eye/templates/website.toml`): the passive sensor deployment with the
settings a web server owner wants — shadow decisions, enforcement off, active probes off,
local-only API and metrics, seven-day retention. `scripts/install.sh` and `scripts/uninstall.sh`:
a tested one-command install with `--help`, `--dry-run`, `--local`, `--system`, `--prefix`,
`--data-dir`, `--profile`, `--wheel` and `--no-setup`, and removal with an explicit `--purge` for
data. `.gitattributes` and `.editorconfig`. A repository cleanup record, since superseded for
public readers by `docs/RELEASE_CONTENTS.md`, and a documented `docs/history/` for archived
development records.

### Changed
All public documentation rewritten in simple (A2-level) English, replacing mixed
Russian/English text: `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, a new `ROADMAP.md`, and the
`docs/` set including new `AI.md`, `MATH_MODEL.md`, `SELF_LEARNING.md`, `DATASET.md` and
`PRIVACY.md`. The old `INSTALLATION.md` is now `docs/INSTALL.md`. `doctor` reports an unconfigured
optional model as `NOT_CONFIGURED` instead of `DEGRADED`, so a fresh install exits 0. The secret
scanner covers `dataset/`, `tests/`, `benchmarks/` and `security/`, and looks for key, `.env` and
dataset-secret files. `.gitignore` now excludes generated datasets, benchmark results, large
validation manifests, local caches and the maintainer's third-party PDFs.

### Fixed
`scripts/install.sh --dry-run` no longer fails with "neither uv nor pip is available": a dry run
never creates the virtual environment it was checking for. Four tests that read generated data
(`datasets/raw/`, `datasets/processed/`) now skip instead of failing when that data is absent, so
the full suite is green on a clean checkout: `tests/test_p10_dataset_sources.py` (two tests) and
`tests/test_p9_dataset_pipeline.py` (leakage and test-set immutability). Added
`scripts/check_safe_defaults.py`, which asserts the nine passive defaults and is used by the new
`install-smoke` CI job. Corrected the ONNX class names in `docs/AI.md`: the model contract uses
`benign-like` / `malicious-automation-like`, while dataset labels use the underscored form.

### Verified
Clean checkout (383 files, 3.5 MB, only committed files) on Linux as a non-root user:
one-command install exits 0, `doctor` exits 0, `demo` exits 0, all nine safe defaults confirmed,
no firewall rule created, re-install idempotent, uninstall keeps data unless `--purge`.
Test suite: 323 passed / 31 skipped in the full working tree, 301 passed / 53 skipped / 0 failed
in the clean checkout. `ruff` clean; security scan reports no unreviewed findings and no secrets.

### Security
Two release blockers remain open and are stated in the README, `SECURITY.md` and
`docs/RELEASE.md`: no LICENSE file has been chosen, and no private security reporting channel
exists. Automatic blocking remains lab-only: it refuses the host network namespace.

## Unreleased (P10) — dataset-v1: LAB, PCAP and shadow telemetry

### Added
Three-source dataset pipeline behind one production FeatureVector path. `DatasetSample` gains
`source_type` (LAB / PCAP / SHADOW_REVIEWED / SHADOW_UNLABELED), `capture_group`, `split` and a
structured `provenance` record; `dataset/provenance.py` states each source's label authority and
grouping key. New: live loopback LAB collector running real sessions against `SelectorServer` and
`DeceptionEngine`; a packet-level capture generator varying TTL, IP ID, TCP options, window size,
segmentation, retransmission, reordering and IPv6; a PCAP capture corpus with per-capture sidecar
labels including deliberately unlabelled captures; bounded default-deny shadow collection into an
unlabelled pool with pseudonymous grouping; cross-source duplicate detection; per-source feature
distributions with PSI-style shift and range coverage; source-type, rate, packet-size and
timestamp leakage checks; out-of-distribution detection and a behaviourally prioritised review
queue; manual review recording annotation, confidence and review timestamp. Ships `dataset-v1`
(2334 rows, 1982 supervised eligible, 352 unlabelled) with a frozen test split, a data card and
`reports/DATASET_V1_REPORT.md`.

### Changed
The readiness gate now also requires a PCAP contribution, a leakage report and a test holdout, and
reports automatic enforcement readiness separately and always as NO. Splits group by the key each
source needs — scenario run, whole capture, pseudonymous source — and unreviewed shadow telemetry
is excluded from every supervised split. Build output is deterministically shuffled so row
position cannot stand in for a label.

### Fixed
A capture whose response packets could not be marked (truncated capture, or a capture with several
clients) turned the sensor's own addresses into sources; destinations are now identified from what
SYN packets point at. Conflicting-label detection ignores unlabelled rows, which assert nothing.

### Security
Live lab sessions are refused unless the bind address is loopback and the deception source
allowlist is narrow and non-global — enforced by production config validation, not only by dataset
code. Captures are read from disk and never retransmitted. Shadow export keeps the mathematical
score, model score, fused risk and action as analysis-only metadata and refuses them as label
sources at three layers; the pseudonymisation secret and the unlabelled pool are git-ignored.

## Unreleased (P9) — dataset generation, collection and validation

### Added
Offline `dataset` package: versioned `DatasetSample` and dataset/split manifests, a validator
with a readiness gate (`NOT_READY` / `ENGINEERING_ONLY` / `READY_FOR_BASELINE_TRAINING`), a
safety layer that validates scenario targets with `ipaddress` and enforces hard bounds, seeded
behaviour generators for benign, hard-negative, malicious-automation and hard-positive
scenarios, a PCAP renderer, ingestion through the production packet parser and correlation
engine, statistics, leakage analysis (port, timing, generator fingerprint, single-feature
separation), deterministic group split with whole-family holdouts, sanitised Shadow Mode export
into an unlabelled pool, manual review export, and a `python -m dataset` CLI. Ships
`dataset-v1.0` (1660 windows, 35 scenarios, 153 sources), `datasets/model_features_v1.json`,
`datasets/stats_v1.json`, a data card and a dataset report.

### Changed
The model feature contract now lives in `dataset.schema`, which is upstream of training;
`training.schema` re-exports it so there is one definition rather than two.

### Fixed
Truncated captures made the parser stop marking response packets, so the sensor's own addresses
could appear as sources; feature collection now emits rows only for the client a scenario
describes. Conflicting-label detection no longer treats an unlabelled row as a contradiction.

### Security
Dataset generation is offline by construction: loopback or an explicit lab allowlist only,
documentation-range addresses in every trace, no transmission, no exploitation, no destructive
payload and no real credential. Shadow export is default-deny and pseudonymous; its secret and
the unlabelled pool are git-ignored. A decision this system made is refused as a label source
at three layers.

## Unreleased (P8) — first ONNX risk baseline

### Added
Frozen `risk-logreg-v1` model feature contract over feature schema1 (34 fitted of 36
tensor columns; `previous_risk` and its mask excluded and exported with weight zero).
Versioned dataset format (`datasets/<version>/` CSV plus `dataset_manifest.json` with
per-file SHA-256), a deterministic 30-family synthetic corpus with hard negatives and
hard positives, `validate_dataset()` covering columns, schema, ranges, mask semantics,
labels, duplicates, class distribution and group leakage, group-aware splitting with
leakage as a raised exception, a controlled LogisticRegression grid, threshold and
block-precision evaluation, calibration, coefficient and false positive/negative
analysis, feature ablation, shadow replay with model/math disagreement capture, CPU
inference benchmark, model card, training report and P8 tests.

### Changed
Dataset labels must come from an independent source; `label_source` values derived
from this system's own decisions are rejected by the loader and the validator.
Manifests may carry measured documentation fields; the production contract fields
stay immutable after export.

### Security
Training stays offline: no Internet, no cloud ML, no external API, no downloaded
dataset, no production traffic without an explicit export. No raw payload, header
bytes, credential material or identity column enters the model. The first model
ships with `quality_gate_passed=false` and `recommended_mode=shadow`; no automatic
firewall blocking is enabled and no model is promoted.

## 0.8.0-rc.1 / Python package 0.8.0rc1 — unreleased (P7)

Local numeric feature schema1, independent MathRisk, isolated CPU ONNX with
manifest/hash checks and deadlines, bounded asynchronous inference, fusion and
PolicyGuard, default shadow decisions, replay/explanation commands, offline LR/GBT
training/evaluation, fixed regression corpus and isolated temporary nftables sets.
No cloud AI, runtime training, model download or automatic model promotion.
Optional ML failure preserves intake; production enforcement remains unapproved.
Config1/event3/DB2 remain compatible; new decision_record carries decision_version1.
See docs/P7_COMPLETION_REPORT.md for measured results and limitations.

## 0.7.0-rc.1 / Python package 0.7.0rc1 — unreleased (P6)

### Added
Unified run, config init/migrate/effective sources, profiles, local demo, local
upgrade check; JSON operational envelopes and exit codes; config schema1;
safe sensor/honeypot/lab templates; migration plan/apply with backup; restore
to new database and retention-only prune; packaging/reproducibility/SBOM/checksum
scripts; Linux/Compose/systemd CI, release gates and operator documentation.

### Changed
New run/config validation requires a versioned file. Config/status/doctor default
to plain text with explicit --json; doctor warnings return7. Application version
0.6.0→0.7.0rc1; event3/DB2/catalogue2 unchanged. Minimal container has no optional
capture/enrichment packages, uses pinned base digests and requires mounted secret.

### Fixed
Pre-start storage compatibility guidance; bind failures identify the listener
and free owned resources. Schema migration preserves expired rows until an
explicit retention pass or normal runtime maintenance.

### Security
Egress-disabled validation forbids RDAP/active probes, sensor disallows active
probes. POSIX mounted secret must not be accessible to other users. No firewall
automation/public management default. Project license and private reporting
channel remain release blockers.

### Deprecated
Legacy +*.py wrappers for new deployments; maintained through P6, removal no
earlier than0.9.0 with a separate announcement. Unversioned config remains
accepted only by transitional entrypoints/read-only diagnostics.

### Removed
None.

## 0.6.0 — P5 baseline
Bounded load shedding, fair reads, batched SQLite, performance workloads and
measurements. Historical evidence: docs/P5_COMPLETION_REPORT.md.
