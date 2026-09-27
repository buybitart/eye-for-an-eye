# Release Notes

## Eye for an Eye 0.8.0 RC2: Public Beta

**Mark this release as a pre-release.** The version is a release candidate and
the posture is public beta. It is not stable, and the reason is in
[Known limitations](#known-limitations) rather than in a disclaimer.

Eye for an Eye is an open-source security tool for Linux websites and servers. It
watches network and web traffic, scores how each source behaves over time using
mathematical behaviour analysis and an optional local machine-learning model, and
records what it saw. It runs entirely on the machine it protects: no cloud
service, no account, no API key.

---

### Supported Platforms

| System | Status |
| --- | --- |
| Ubuntu 24.04 LTS, x86_64 | Supported and tested |
| Ubuntu 24.04 LTS, other architectures | Expected to work, not tested |
| Debian 12, Debian 13 | Release archive only, because their system Python is not 3.12 |
| Other Linux with Python 3.12 | Expected to work, not tested |
| Windows 11 x64 | Website-log monitoring and the demo only |

Python **3.12** exactly. Not 3.11, not 3.13.

The Debian package depends on `python3.12` and will refuse to install where that
interpreter is absent. That refusal is correct; use the release archive, whose
installer can obtain a 3.12 of its own.

---

### What You Get

**Safe Monitoring, out of the box.** Installing sets up the `production-shadow`
posture: the whole analysis path runs, decides and records evidence, and enforces
nothing. Automatic blocking is off. No firewall rule is changed. No service is
started or enabled.

**A beginner path that does not require Python knowledge.** Download, check the
checksum, install, `eye-for-an-eye setup`, `eye-for-an-eye start`,
`eye-for-an-eye status`. No `git`, no `pip`, no virtual environment, no root, and
no editing a configuration file by hand.

**`eye-for-an-eye setup` asks what to watch** and checks the answer. It checks that the
access log exists, that it can be read, and that its first line is in the format
the reader parses. A log in the wrong format is refused with the command that
fixes it, rather than accepted into a sensor that would silently see nothing.

**Two traffic sources**, and they are not equally easy. A web server access log
works on Linux and Windows and needs no privileges. Packet capture is Linux only
and needs a separate helper holding `CAP_NET_RAW`.

**Autonomous Mode exists and is deliberately hard to start.** It refuses until the
operator has named the networks it must never block, the calibrator is present and
healthy, and the readiness checks pass. It is Linux only.

---

### What Changed Since 0.8.0 RC1

0.8.0 RC1 was the first push to a public repository, and publishing it ran this
project's own continuous integration in public for the first time. Two jobs went
red. Nothing they found was a defect in detection, in the decision path, or in any
safety control; all of it was source hygiene and one stale assertion in the
workflow itself. RC2 is that work, and nothing else.

RC1 remains published, and its failed CI run remains visible. It is the evidence
that these problems were real, and removing it would only make the record less
useful.

**What was wrong, exactly:**

* **The `install-smoke` job asserted the opposite of the correct answer.** It ran
  `eye-for-an-eye doctor` as a plain command, which asserts exit 0. `doctor` exits
  7 when any component is degraded, and on a fresh install of the safe profile
  that is the required answer: no calibrator, no access log and no web secret are
  configured yet, because the installer does not invent deployment-specific
  artifacts. The job's expectation was written when the installed profile was
  `website`, which has no `[autonomy]` section and so had nothing to be degraded
  about; when the installed default became `production-shadow`, the expectation
  was not updated with it. The job now asserts exit 7 *and* which components are
  degraded, so a real regression elsewhere still fails it.
* **22 lint findings**, all unused imports and two redundant f-string prefixes,
  plus one duplicate test method and one genuine fragility in a benchmark, where a
  timed callable closed over a variable the enclosing function later deleted.
* **One missing type annotation** that `mypy` reports. It had never been seen
  because the lint step runs first and stopped the job before `mypy` ran.
* **Line endings.** 40 files were stored in Git with LF, as `.gitattributes`
  requires, while the release archives carried CRLF for the same files, because
  the archives were built from a working copy that had been checked out on
  Windows. Two people on the same version received different bytes. The release
  root, the repository and a fresh clone are now byte-identical.

**What did not change:** no detection logic, no threshold, no calibration, no
model, no policy guard, no enforcement path, no configuration default, and no
validation claim. Real-world validation of autonomous blocking is still pending
and automatic blocking is still off after installation.

---

### New in the 0.8.0 Release Candidates

* A Linux release archive, `eye-for-an-eye-0.8.0rc2-linux-x86_64.tar.gz`, usable
  without the development repository, with `START_HERE.md` and `install.sh` at the
  top of it.
* A Debian package, `eye-for-an-eye_0.8.0~rc2-1_all.deb`, installing under `/usr`
  with the systemd units present and disabled and no configuration under `/etc`.
* `SHA256SUMS` for every artifact, and a CycloneDX 1.6 SBOM.
* The installer records what it installed, so `status`, `check-install` and
  `uninstall` know what this machine has instead of guessing at it.
* `eye-for-an-eye status` answers `NOT RUNNING` when nothing is running, instead
  of reporting an error about a missing file.
* `eye-for-an-eye doctor` and `status` read the configuration this computer
  actually has when no `--config` is given, and say which file they read.
* `eye-for-an-eye easy uninstall` removes what was installed and reports
  accurately when it cannot find it.

---

### Known Limitations

**Real-world validation of autonomous blocking is pending.** Automatic blocking
has never run against real Internet traffic. What it would block, and how often it
would be wrong, is unmeasured. See
[VALIDATION_STATUS.md](VALIDATION_STATUS.md).

**Detection coverage is incomplete and fails the project's own gate.** On the
project's own generated test data it blocks 120 sources of 203 with no false
blocks in 546 benign sources, and detects nothing at all in six of the behaviour
families it is meant to cover.

**Not tested:** live packet capture, the namespace firewall, `CAP_NET_RAW`,
original destination lookup, the systemd units under a running systemd, and
container health probes. These need an isolated Linux lab.

**The release artifacts are not signed.** This project has no signing key.
Verify the published SHA-256 sums instead:

```sh
sha256sum -c SHA256SUMS
```

**Downgrading is not tested.** Do not assume an older version can read a newer
database or decision journal.

---

### Installing

```sh
sha256sum -c SHA256SUMS
tar xzf eye-for-an-eye-0.8.0rc2-linux-x86_64.tar.gz
cd eye-for-an-eye-0.8.0rc2
sh install.sh
eye-for-an-eye setup
eye-for-an-eye start
```

Ubuntu 24.04 can use the package instead:

```sh
sudo apt install ./eye-for-an-eye_0.8.0~rc2-1_all.deb
```

Full instructions: [INSTALL_LINUX.md](INSTALL_LINUX.md). First steps:
[START_HERE.md](../START_HERE.md).

---

### Security

Report vulnerabilities privately through GitHub Private Vulnerability Reporting.
Do not open a public issue. See [SECURITY.md](../SECURITY.md).

---

### Licence

MIT. Copyright (c) 2026 Aliaksandr Zasinets. Third-party licences are listed
separately in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
