# Distribution

How people would find and get the software. Only real channels are listed. No
partnership is claimed, because none exists.

## Current State

Nothing is published anywhere.

| Channel | Status |
| --- | --- |
| Public source repository | **Not published.** No public URL exists. |
| Python package index | **Not published.** No package name is reserved. |
| Container registry | **Not published.** A `Dockerfile` exists in the tree. |
| Linux distribution packages | **Not published.** A real `.deb` is built and tested; it is in no archive and no PPA. |
| Website | None. |

Nothing invents a URL. What exists is a set of artifacts, built and verified, with
nowhere yet to put them.

## The Artifacts That Exist

Every one is built from the release root that `scripts/build_prod.py` assembles,
so what is published is what was verified. None is signed, because this project
has no signing key.

| Artifact | Built by | What it is for |
| --- | --- | --- |
| `eye-for-an-eye-<version>-linux-x86_64.tar.gz` | `scripts/build_linux_tarball.py` | The primary Linux path. Usable without the repository. `START_HERE.md` and `install.sh` at the top |
| `eye-for-an-eye_<version>-1_all.deb` | `scripts/build_deb.py` | Ubuntu 24.04 and derivatives whose system Python is 3.12 |
| `Eye-for-an-Eye-<version>-Windows.zip` | `scripts/build_windows_zip.py` | The Windows beginner path: website-log monitoring and the demo |
| `eye_for_an_eye-<version>-py3-none-any.whl`, `.tar.gz` | `scripts/build_release.py` | The Python package, for anyone who wants it directly |
| `sbom.cdx.json` | `scripts/build_release.py` | A CycloneDX 1.6 inventory of the optional runtime dependencies |
| `SHA256SUMS` | `scripts/build_release.py --checksums-only` | Hashes of every artifact above |

Each builder verifies its own output against the release root rather than
asserting it: the tarball and the Windows archive compare every member
byte-for-byte, and the Debian package is read back out of the built `.deb`.

Honest limitation: a checksum proves a file did not change between publication and
download. It does not prove where the file came from. There is no signing
infrastructure, and none is claimed.

## Planned Channels

### 1. A Public Source Repository

The main channel. It is where the code, the documentation, the issue tracker and
the releases live.

`[OWNER INPUT REQUIRED]`: which hosting service, and the URL.

### 2. Release Artefacts

The artifacts listed above, attached to a release rather than committed to the
repository.

`[OWNER ACTION]`: release signing. Until a key exists, the release page must say
the artifacts are unsigned and point at `SHA256SUMS`.

### 3. A Python Package Index

`pipx install eye-for-an-eye` would be the nicest install path. It requires
reserving a name and publishing, neither of which has happened.

Until then the documented one-command install is the installer script, which is
tested.

### 4. A Container Image

The `Dockerfile` and `docker-compose.lab.yml` exist. If an image is published,
the defaults must stay: non-root where possible, no `--privileged`, no
management port exposed, persistent storage, and Shadow Mode.

### 5. Communities

Places where the intended users actually are:

* Self-hosting and small-VPS communities.
* Open-source security communities.
* Digital security trainers and helpdesks who support small media and civil
  society organisations.

The third group is the one that matters for the intended beneficiaries, and it
is also the one where an unproven tool does the most harm if it is oversold. The
project should approach them **after** Objective 4 in
the project objectives, with real shadow results, not before.

### 6. Partners

**None.** No organisation has agreed to anything. This section stays empty until
that changes.

## How the Software Would Be Promoted

Honestly, and with the limitations first:

* "Automatic blocking is lab-only" appears in the README, not in a footnote.
* "The model is for watching, not blocking" appears next to every mention of the
  model.
* "No production deployments yet" is stated in the project status.

An unproven security tool that is promoted as proven is worse than no tool. For
the intended users it could be dangerous.

## Documentation as Distribution

The documentation is in simple English because the intended users often do not
read English as a first language and are not security engineers. Translation is
listed as a welcome contribution in [CONTRIBUTING.md](../CONTRIBUTING.md).

## What Is Deliberately Not a Channel

* No bundling with a hosting control panel that installs it silently.
* No "curl the internet into a shell" instruction pointing at a URL that does
  not exist.
* No app store or marketplace listing that hides the project status.

## See Also

* [Users](USERS.md)
* [Sustainability](SUSTAINABILITY.md)
* [Release process](RELEASE.md)
