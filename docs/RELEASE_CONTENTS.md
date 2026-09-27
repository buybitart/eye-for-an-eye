# What is in the release, and what is not

The public repository is assembled from a larger development tree by
`scripts/build_prod.py`. That script is the assembly rather than a description
of it: every published path is named in one list, every excluded category in
another with its reason, and the build fails if an excluded category reaches
the release root. This page is that script in prose.

## Included

| Directory | What it is |
|---|---|
| `eye_for_an_eye/` | the software |
| `tests/` | the test suite, including its fixtures |
| `docs/` | the documentation |
| `models/` | the bundled model and calibrator artifacts, with their manifests |
| `dataset/` | dataset *tooling*: schema, validators, generators |
| `training/` | training and evaluation tooling |
| `benchmarks/` | benchmark harnesses and their recorded baselines |
| `deploy/` | systemd units and deployment configuration examples |
| `scripts/` | install, uninstall, build, security scan, release checks |
| `security/` | the reviewed static-analysis baseline |
| `requirements/` | pinned requirement sets |
| `.github/` | continuous integration |
| `reports/` | four records the documentation cites, and the model card |

Plus the public root: `README.md`, `START_HERE.md`, `LICENSE`, `SECURITY.md`,
`CONTRIBUTING.md`, `CHANGELOG.md`, `ROADMAP.md`, `THIRD_PARTY_NOTICES.md`,
`pyproject.toml`, the four example configurations, and the usual dotfiles.

### The entry points at the root

| File | What it is |
|---|---|
| `START_HERE.md` | the first page a person who is not a developer should read |
| `install.sh`, `uninstall.sh` | the Linux doors. Each hands over to its counterpart in `scripts/`; neither holds installation logic of its own |
| `Install-EyeForAnEye.cmd` and five siblings | the Windows launchers, double-clicked |

`install.sh` and `uninstall.sh` sit at the top because that is where somebody
looks after unpacking an archive or opening the repository. Before P18 the Linux
installer was two directories down while six Windows launchers sat at the root,
on a project whose primary platform is Linux.

### The six `+`-prefixed files

`+garbage.py`, `+ip_id.py`, `+nat.py`, `+proto.py`, `+services.py` and
`+uptime.py` are compatibility entry points kept since P1. Each is eleven lines
and calls the real CLI; none holds an implementation.

They remain at the root for two reasons. `tests/test_cli_integration.py` starts
`+garbage.py` as a subprocess, so a release root without it has a test suite that
cannot run. And four published phase reports cite these paths, which a
documentation check verifies — moving them would mean either rewriting a
historical measurement or excusing the check.

`+garbage.py` is the only one that is LAB_ONLY. The command behind it is bounded
four ways — loopback bind, loopback peer, a byte budget, and connection and
duration caps — which `eye_for_an_eye/network/listeners.py` enforces. See
[MIGRATION_FROM_LEGACY.md](MIGRATION_FROM_LEGACY.md) for what replaced each one.

## Models and the calibrator

Bundled artifacts are JSON and ONNX. **There is no pickle or joblib artifact**,
and none will be added: loading one executes whatever it contains, which is not
a property a defensive tool should have.

Each artifact has a manifest recording its version, the feature schema it is
bound to, the feature order, and a SHA-256 of the model file. The loader checks
that hash before the model is used, and refuses an artifact whose ownership or
permissions would let another account modify it. `models/README.md` and
`models/MODEL_CARD_risk-logreg-v1.md` describe what each one was fitted on.

The calibrator is not enabled by default. Neither production profile ships with
a `calibrator_path` filled in for shadow; the autonomous profile names one and
will not validate until the file is there, because a block decided without a
calibrated probability is a block decided on a number that is not a probability.

## Excluded, and why

| Category | What | Why |
|---|---|---|
| GENERATED_EXCLUDE | `datasets/` — 11,470 files, 710 MB | generated corpora. The generators, schema, validators and data cards are published; the corpora are rebuilt rather than shipped |
| GENERATED_EXCLUDE | build output, `__pycache__`, test and linter caches, `*.egg-info` | derived from the source |
| LOCAL_ONLY | virtual environments, the development tree's Git history, local score dumps | belong to one machine |
| PRIVATE | funding-application drafts | not product documentation |
| DEVELOPMENT_ONLY | development-assistant instructions, internal engineering policy, most phase reports | internal working material |
| SENSITIVE_DATA | `*.sqlite3`, `*.jsonl`, captured traffic outside test fixtures | a deployment's own evidence is its own |
| SECRET | `*.secret`, `.env` | none were found; the pattern is a guard, not a report |

One phase report is excluded for a reason worth stating separately: it quotes
the development machine directly — account names, absolute paths, the exact
privileged commands a run was made with. Its conclusions are in
[VALIDATION_STATUS.md](VALIDATION_STATUS.md); sanitising it line by line would
have left a report whose commands reproduce nothing.

## Captured traffic

No real traffic is published. The only capture files in the repository are
small synthetic fixtures under `tests/fixtures/`, generated by
`tests/fixtures/p2/generate.py`, which writes only into its own directory and
records SHA-256 checksums and a `synthetic` marker in its manifest. They exist
because the offline analysis path needs something to parse in a test.

A deployment's own decision journal and shadow export are never published by
this project and should not be published by an operator without review: they
are pseudonymous, and pseudonymous is not anonymous.

## Runtime state

Nothing in the repository is runtime state. Event databases, journals, exports,
status files and logs are created by a running deployment in the directory it
is configured to use, and `.gitignore` covers all of them.

## Lab-only tooling

Two things ship and are not production features.

**The lab namespace enforcement path.** `enforcement.enabled` pins the whole
installation to a disposable network namespace. It is off in every shipped
profile without exception, and the configuration refuses it together with host
enforcement, because one set of protected networks cannot describe two places
to enforce in.

**The `garbage` entry point.** A deprecated experiment that returns filler
bytes to a peer which connected to it. It is bounded four ways and the bounds
are in `eye_for_an_eye/network/listeners.py` rather than in this sentence: it
refuses a non-loopback bind address, refuses a non-loopback peer, stops at a
byte budget, and stops at a connection count and a duration. It additionally
requires `--lab`, TCP, and deception enabled. It reaches nothing outward, it is
off in both production profiles, and it is published because the test suite
exercises it — a release whose own tests cannot run is not a release.

Neither is an offensive capability and neither should be enabled on a host
serving real users.

## See also

* [Data and models](DATA_AND_MODELS.md) — provenance of what is bundled
* [Validation status](VALIDATION_STATUS.md) — what has been tested, and how
* [Release](RELEASE.md) — how a release is built, checked and published
