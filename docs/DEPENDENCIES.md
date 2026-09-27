# Dependency Baseline

This page lists the software dependencies the project uses, and how their versions were chosen and checked. Read this if you install, package, or audit the project.

## Current Dependencies

The API, metrics, redaction (removing private data), and backup features use only Python's standard library: `selectors`, `sqlite3` (a small file-based database), JSON, and dataclasses. The project did not add FastAPI, OpenTelemetry, or a Prometheus client as dependencies (outside libraries). The current task is small and read-only, so it does not need a bigger framework. The versions of earlier dependency providers stay the same. The package version and the lock file (a file that records exact dependency versions) were updated to 0.5.0. The editable install was done offline, with an isolated build, using the existing cache.

The package was updated to version 0.5.0. The deception feature uses only the standard library: it needs no SSH server library, no SQL library, and no regex-generator library. The dependency versions from earlier stages stay the same. The lock file's metadata and the editable install were updated offline. The fingerprinting, correlation, PCAP (packet capture file), and calibration features use the standard library plus Scapy (a network packet library), which is already installed. The synthetic (made-up) test data and benchmarks run directly from the checked-out code. The localhost deception benchmark does not need Scapy at all.

## Python, Build Tool, and Lock File

The runtime is CPython (the standard Python) version 3.12. It was tested with version 3.12.14 on Windows. SQLite version 3.53.1 comes bundled inside that Python runtime. The file `pyproject.toml` limits Python to the range `>=3.12,<3.13`. The file `.python-version` fixes the exact version to 3.12.14. Install with **uv** (a Python package tool) version 0.12.10, using the command `uv sync --locked --all-extras`. A clean, separate environment was rebuilt from `uv.lock`; this lock file stores the exact versions of every indirect (transitive) dependency, plus SHA-256 checksums for each package file. The build backend is setuptools version 84.0.0. Note: the Python interpreter itself and SQLite are not tracked inside this dependency lock file.

## Key Provider Versions

Key dependency versions from the earliest stage of the project stay the same: Scapy 2.7.0, maxminddb 3.1.1, and ipwhois 1.3.0. The code that normalizes GeoIP (location-by-IP) and RDAP (a registry lookup protocol) data lives in separate "adapter" modules, and is covered by contract tests. The ASN (Autonomous System Number, an ID for a network) is now stored as an integer, with range checking. The MMDB (MaxMind database) file is separate operator-supplied data. It is not bundled with the package. Its result includes the source, version, modification time, and build date, in a way that does not depend on the file's path. A missing database is allowed; the system then reports "unavailable." The p0f feature (guessing an operating system from network traffic) uses the Scapy adapter plus an external signature database. The project does not claim any specific accuracy for guessing operating system identity.

## About the Old Lock File

The file `requirements-p0.lock`, mentioned below, is from the project's early history. It is not the current way to install the project. For a new environment, use [DEPLOYMENT.md](DEPLOYMENT.md). Docker image tags are fixed by version number, but the registry digests (exact image fingerprints) and a real Linux image build have not yet been checked. No vulnerability scan or attestation (a signed proof of origin) has been done. Having checksums (hashes) does not mean there are no security vulnerabilities.

## Earlier Project Decisions

This was checked on 2026-09-06 and 2026-09-07, on Windows 11, with CPython 3.12.14. The command `pip check` found no conflicts. The versions listed in `requirements-p0.lock` come from a real, installed, and tested environment. This file is a snapshot of constraints, without checksums. It is not a promise that these versions work everywhere.

| Old dependency / feature | Decision made | How it was checked |
| --- | --- | --- |
| `netaddr` (library for IP addresses and ranges) | Replaced with Python's own `ipaddress` library | Validation and policy tests; checked correct IPv4/IPv6 formatting |
| `rstr` (library for random text banners) | Removed from the running code; replaced with fixed, unchangeable byte profiles | Regression tests for sizes, HTTP, HMAC, and a fresh process |
| `maxminddb-geolite2` (bundled GeoLite database) | Replaced with `maxminddb>=3.1,<4` plus a database file the operator must supply and update | Installed version 3.1.1; normalization and failure tests done; no real database was provided during testing |
| `scapy-p0f` (passive OS fingerprinting) | Replaced with `scapy.modules.p0f`, inside `scapy>=2.7,<2.8`, wrapped in its own adapter | Installed version 2.7.0; real parser and matcher code tested, plus a custom synthetic (made-up) database; using two adapters does not change the shared global `p0fdb` |
| `ipwhois` (WHOIS lookups during capture) | Kept `ipwhois>=1.3,<2`, but only as an optional RDAP lookup, run in an isolated worker process | Installed version 1.3.0; tested with a fake provider for success, exceptions, timeouts, and cancellation; no real registry was queried |
| Scapy packet capture | Made an optional extra called `capture` | Tested with artificial IPv4/IPv6 packets and PCAP replay; the real live capture backend was not tested |
| Tests / linting | pytest, plus optional Ruff (a code checker) | Installed versions 9.1.1 and 0.16.6; ran the full regression test suite and Ruff |

The core of the project does not depend on any third-party library. `pyproject.toml` states Python `>=3.11`, because TOML config files are read using Python's own standard `tomllib` library. Running the full test suite needs the `capture` extra installed: the contract tests deliberately do not replace the installed Scapy library with a fully fake mock object. Python 3.11 and Linux have not been separately tested yet.

The allowed Scapy version range is limited to one minor version line. The adapter code uses specific Scapy pieces: `p0fKnowledgeBase`, `packet2p0f`, `TCP_Signature`, and `tcp_find_match`. Contract tests check the exact shape of what these functions return. If this dependency is ever updated, these tests must be run again. A MEDIUM confidence label only means the signature matched. It is not a calibrated (tuned and measured) accuracy for guessing the operating system. The p0f signature database itself is not included with the project. The operator is responsible for where it comes from and for keeping it updated.

The MaxMind database reader takes a file path from the operator; it never updates itself automatically. This avoids depending on a bundled database that could go out of date. The RDAP lookup settings `depth=0` and `retry_count=0` limit how far it follows links. The parent process sets an overall deadline, because the library's own timeout setting alone does not limit the whole DNS and HTTP chain. If something goes wrong, only the child process for that one lookup job is killed.

## Primary Sources Checked

- [Nmap Probe file format](https://nmap.org/book/vscan-fileformat.html): covers the transport type, C-style byte escape codes, how delimiters are chosen, and the `no-payload` setting. This project's code only reads the Probe payload part of this format. It never runs the `match` regular expressions from it.
- [Scapy installation](https://scapy.readthedocs.io/en/latest/installation.html): lists separate live-capture requirements for each operating system. To build the contract adapter, the actual source code of the installed Scapy 2.7.0 was also read directly.
- [MaxMind DB Python reader](https://maxminddb.readthedocs.io/en/latest/): covers the external MMDB file format and a reader that manages its own open and close lifecycle (a "context manager").
- [ipwhois RDAP](https://ipwhois.readthedocs.io/en/latest/RDAP.html): covers its API and lookup settings.

A full dependency vulnerability scan, a CI test matrix (testing across many configurations), and supply-chain checksum verification have not been done. This early stage does not claim that having newer versions, by itself, guarantees there are no vulnerabilities.

## See Also

- [DEPLOYMENT.md](DEPLOYMENT.md): how to install the project in a new environment
- [INSTALL.md](INSTALL.md): install steps
- [SECURITY_REVIEW_SCOPE.md](SECURITY_REVIEW_SCOPE.md): what a security review should cover
