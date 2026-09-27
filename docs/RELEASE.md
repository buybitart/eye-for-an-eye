# Release Process and Gates

This page explains how a release build is made and checked, and which gates
(checks that must pass) still need to be closed before a public release. It
is for maintainers and release engineers.

## What This Process Does Not Do

No workflow here publishes packages or container images, creates a public
release, or assumes any signing keys exist. The source code snapshot has no
`.git` history in it, so a clean tree, a revision, and a tag cannot be
verified from inside it. Before publishing, a maintainer must import this
snapshot into their own versioned repository and review the diff (the set of
changes) there first.

## The 5 Release Steps

1. Approve the LICENSE file and its SPDX metadata (a standard way of naming a
   software licence), and approve a private reporting channel for
   `SECURITY.md`. Neither of these exists yet. See the release blockers
   below.
2. Select one clean, already-reviewed commit (a saved code change). Update
   the app version, the `CHANGELOG`, and the dependency lockfile. The Python
   version number `0.7.0rc1` (in PEP 440 format, Python's version standard)
   maps to `0.7.0-rc.1` in SemVer format (a different, widely used version
   standard). Four other version numbers stay independent of this app
   version and of each other: the event schema is version 3, the database
   schema is version 2, the catalogue is version 2, and the config schema is
   version 1.
3. Run the CI (continuous integration) pipeline on Linux with Python 3.12:
   the regression test suite, the linter and `mypy` (a static type checker),
   a reviewed Bandit scan (a security scanner for Python code) and a
   source-pattern secret scan, and a dependency audit. The secret scan only
   checks for narrow, known text patterns in the source code. It does not
   check the git history, and it does not measure text randomness
   ("entropy") to find secrets a pattern might miss.
4. Run a Docker smoke test: the container must run as a non-root user, with
   a read-only filesystem, inside the internal Compose setup. Also run the
   manual namespace and systemd jobs by hand, on a disposable (throwaway)
   Linux machine. Check any skipped tests by hand. A skipped test is not the
   same as a passed gate.
5. Build the release package twice, and run a smoke test on the installed
   wheel (a Python package file) outside of the source checkout folder.

```sh
uv run --frozen python scripts/build_release.py --output release-artifacts
uv run --frozen python scripts/package_smoke.py release-artifacts/eye_for_an_eye-0.7.0rc1-py3-none-any.whl
uv run --frozen python scripts/release_check.py --artifacts release-artifacts
```

## Reproducible Builds

The output directory for `build_release.py` must be new and empty. The build
sets a fixed `SOURCE_DATE_EPOCH` (an environment variable that fixes
timestamps, so two builds produce identical files). The sdist's (source
distribution's) gzip and tar file metadata is made canonical (put into one
fixed, standard form) right after `setuptools` generates it.

Both the wheel file and the canonical sdist file must produce the exact same
hash (fingerprint) across two separate builds, in the same environment. This
project does not claim reproducibility across different operating systems or
build backends. No source file, private database, or secret is ever modified
or copied into the release artifacts. The wheel package contains the three
starter configuration templates.

## What Goes in the Release Bundle

A release bundle contains: the wheel file, the sdist file, a CycloneDX 1.6
inventory (a standard list of the optional runtime dependencies), a
`SHA256SUMS` file (hashes of every artifact), and build evidence (logs
proving how the build was made).

A container release needs more on top of that: the image digest (its unique
fingerprint), an OS-package SBOM (software bill of materials. A full list of
installed system packages), and a vulnerability scan. The builder and
runtime versions are pinned (fixed) in the `Dockerfile`. The Python SBOM does
not describe container layers that were never built, or the underlying OS
libraries.

## The Validation Record

**For the current validation status of this project, read
[VALIDATION_STATUS.md](VALIDATION_STATUS.md).** That page ships with this
repository and is the one to cite.

The gates above are recorded by whoever runs them, on the machine they ran them
on, in a local file at `release/validation.json`. That file is **not part of
this repository**. It describes one machine at one point in the development
history, and publishing it would put a record measured against a different tree
in front of a reader as though it described this one. If you are cutting your
own release you write it; if you are reading this repository you will not find
one, and that is correct.

`scripts/release_check.py` reads that record and fails the whole release if the
licence, a contact address, the evidence, or the artifacts are missing, or if
any hash does not match. Run from a fresh clone, with no record written, it
reports the absence as a blocker rather than passing: missing evidence is a
failure, never fabricated success. It is a final safety check, not a
replacement for actually running CI.

The check is expected to be red today. The platform gates above are not yet
verified, and a source snapshot without Git history records that absence as a
failure too.

## Signing and Publishing

Artifact checksums are only useful if you already trust the manifest
(the list) that contains them. Signing keys are not configured yet, never
invent a signature or an attestation (a signed claim of authenticity) that
does not actually exist.

Uploading, publishing, or tagging a release are separate actions. Each one
needs its own, separate decision by a maintainer. When the CI pipeline
stores build artifacts (`upload-artifact`), that only saves evidence for
validation. It is not the same as making a public release.

## Licence Metadata

Package metadata follows the [PyPA specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
(the Python Packaging Authority's standard). The SPDX licence field is
deliberately left empty, until the project owner chooses a licence.
`[OWNER INPUT REQUIRED]`

## See Also

* [OPERATOR_CHECKLIST.md](OPERATOR_CHECKLIST.md): the release blockers,
  from an operator's point of view.
* [INSTALL.md](INSTALL.md): how the released package gets installed.
* [SECURITY_DEPLOYMENT.md](SECURITY_DEPLOYMENT.md): the security boundary
  this deployment relies on.
* [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md): known limits of this
  project as a whole.
