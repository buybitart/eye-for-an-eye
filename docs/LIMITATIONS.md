# Known Limitations

This page lists what the project does not support yet, and what has not been checked or measured. Read this before you deploy the project, or before you trust any detection result.

## Support Boundary

For the full platform and status table, see [DEPLOYMENT.md](DEPLOYMENT.md). Linux x86_64, Python 3.12, unprivileged CLI use, demos, and offline regression tests have been checked. WSL2 (Windows Subsystem for Linux) is not the same as a native production capture setup, and it is not the same as a real systemd endurance ("soak") test. There is no local Docker engine available for testing. The namespace tests need `nft` (the nftables firewall tool) and a separate, disposable, privileged test setup. The container image, its healthcheck, and the systemd lifecycle have not yet been accepted as production-ready. A license file is present. The private channel for reporting security issues is documented in [SECURITY.md](../SECURITY.md) and is **not yet available**: it is GitHub Private Vulnerability Reporting, which is a per-repository setting the owner enables once the repository is published, and the repository is not published. That remains a **release blocker**, and the distinction matters. A reporter who follows a channel that does not exist discloses to nobody while believing they have disclosed to someone.

The project does not have: hot reload or SIGHUP-based reload, automatic updates, a dashboard or TUI (text user interface), a support bundle (a packaged diagnostics file), or a production host-network container. The source code secret scanner does not scan Git history. This working copy has no Git metadata at all. The application's egress (outbound traffic) policy is not the same as an operating-system firewall. No performance guarantees are made for other hardware or deployment setups beyond what was already measured.

## Analysis Limitations From Earlier Testing

This section covers the fingerprinting and correlation analysis. It was tested on Windows, with CPython 3.12.14, and fixed dependency versions: Scapy 2.7.0, maxminddb 3.1.1, and ipwhois 1.3.0. The Python package version was 0.3.0. No external network capture data sets were downloaded, and no real GeoIP, registry, or ICMP lookups were made.

### Visibility and Uncertainty

- One sensor only sees its own part of the traffic. A source IP address is not the same as a person or an organization. NAT (address sharing), shared proxies, and spoofing (faking an address) all break that link.
- Guesses based on TTL (IPv4) or Hop Limit (IPv6) depend on a configured "prior" (an assumed starting value). There is no certainty about the real operating system, and the real network path length is not measured.
- The IPv4 IP ID field is not a counter of someone else's total traffic. Fragmented packets and "atomic" datagrams (which do not normally use this field) are excluded from the statistical history. A result labeled `random_like` does not prove the sender really uses a random number generator.
- The TCP timestamp rate estimate is limited by the single flow, the number of samples, and how long the capture ran. It cannot give a real boot time, a real IP address, a VPN identity, or match a person across different IP addresses.
- A p0f match only confirms that a signature is compatible. It does not prove an exact identity. Fuzzy matches, errors, and a missing database are all shown clearly. The accuracy of these signatures in real production traffic has not been measured.
- A GeoIP result is only an estimate of where an IP address is. An RDAP result shows the registered network, not a person. The database build time and lookup time do not guarantee that every field is up to date, and none of this describes where a real person lives.
- The correlation feature's stored state is limited in size. Under overload, eviction, or a sample limit, the system can miss real detections (false negatives). Event counts become only lower-bound estimates, and confidence levels drop. All scoring is a hand-written heuristic. It is not calibrated (tuned and measured) against real data.
- The "credential-like" flag only comes from a limited check of the start (prefix) of the data. Passwords, Authorization headers, and raw payloads are never stored. Encrypted or unusual formats may not be recognized at all. Short-lived, keyed digests are not shared identifiers between different processes.
- A real TCP 3-way handshake can only be confirmed when both directions of traffic are visible. The incoming-only capture helper cannot guarantee this. A listener that accepts connections only confirms connections it actually accepted. Reactions to a banner message, or a continued conversation, are only visible when that exchange was actually captured.
- The following are not supported: putting a full TCP stream back together (reassembly), checksum verification, IPv6 fragment reassembly, decrypting ESP (IPsec encrypted traffic), and jumbogram packets (very large IPv6 packets). Unsupported or broken (malformed) data is always clearly marked as such.
- The number of feature events has grown over time. The older JSONL (line-based JSON log) sampling method can drop some records. When SQLite storage is turned on, it receives events regardless of log sampling. The `analyze-pcap` command uses a separate, paced writer that never samples (drops) events.
- The metrics and benchmarks do not describe any protection against link saturation or a SYN flood attack. The memory accounting and the `tracemalloc` tool are not the same as a full measurement of native RSS (real process memory) or cgroup limits.

### Safe Offline Command-Line Tool

```text
python -m eye_for_an_eye analyze-pcap tests/fixtures/p2/scan.pcap
python -m eye_for_an_eye analyze-pcap sample.pcap --output new-results.jsonl
python -m eye_for_an_eye analyze-pcap sample.pcap --storage-path lab-results.sqlite3
```

This CLI command never opens a listener, a raw socket, or worker threads. It never does RDAP lookups, active probing, or applies firewall rules. If a config file has any of these policies turned on, the CLI rejects it. On Linux, the default check still requires running as a non-root user with no special capabilities. The output file must be new. The command never overwrites an existing file. The config file, and the PCAP file's header and first record, are checked before the database even starts.

The tool supports classic PCAP version 2.4, with either microsecond or nanosecond timing, Ethernet frames (with up to 2 VLAN tags), raw IPv4/IPv6, and Linux "cooked" capture format versions 1 and 2. The newer PCAPNG format is explicitly not supported. The reader limits: total input size (default 512 MiB), each included record (1 MiB), number of packets (100,000), and output size (64 MiB). These limits can be set from the CLI, but each has a hard maximum it cannot exceed. A broken (malformed) packet produces a `parse_error` or a partial result. A file with a broken overall PCAP structure makes the CLI exit with an error. Reaching the packet or output limit gives an incomplete result and exit code 1. Timestamps are stored as floating-point numbers or datetimes, which limits real replay accuracy, nanosecond precision is not guaranteed.

Offline labels are deterministic: the same input data and config always produce the same labels. However, event UUIDs (unique IDs) and the short-lived HMAC values differ between runs. An older PCAP command for `ip_id`/`nat`/`uptime` checks still exists, but use `analyze-pcap` for a full, complete evaluation.

### Synthetic Test Data and Benchmark

```text
python -B tests/fixtures/p2/generate.py
python -c "import json; from eye_for_an_eye.calibration import evaluate_corpus; print(json.dumps(evaluate_corpus('tests/fixtures/p2/corpus.json'), indent=2))"
python -B -m benchmarks.p2_pipeline --events 1000 --sources 10000 --output benchmarks/p2-baseline.json
```

The generator script only writes its own small, local test fixtures. The manifest file records SHA-256 checksums and marks the source as synthetic (made-up). The loader never reads files outside the test-data folder. Running the evaluation produces a confusion matrix, precision, recall, FPR/FNR values, and a flag `calibrated=false`. The saved result is at [benchmarks/p2-calibration.json](../benchmarks/p2-calibration.json). These numbers, based on just two test labels, cannot be applied to real Internet traffic.

The benchmark first measures CPU use and latency for one fully filled source window. Then it measures Python memory allocations for 10,000 active sources, all within the TTL time limit. Then it measures the full offline pipeline: parsing, fingerprinting, correlation, and serialization. It never sends any real packets on a network interface. In this paced offline mode, the input drop rate is always zero. A separate "sample-drop rate" instead shows how often old samples get pushed out of the size-limited buffer. Native RSS memory use, and live-capture queue loss, are not measured by this benchmark. Results are saved in [benchmarks/p2-baseline.json](../benchmarks/p2-baseline.json) and were described in a phase record that is not published; see [history/README.md](history/README.md).

### A Patient Source Can Stay Under the Observation Gate (P15.3)

A block requires at least `minimum_observations` (20) events **within one
decision window**. A source that spreads its activity thinly enough never
accumulates twenty events in any single window, whatever it does across a whole
session.

This was measured rather than theorised. On the development corpus a slow port
scan reaches a conservative probability of 0.981 (past the `public_website`
cutoff of 0.976) with five distinct evidence families and three behavioural
ones, and is still not blocked, because the window carrying that evidence held
fifteen observations rather than twenty. Every other gate agreed the source was
malicious. The count gate is what refused, and by the rule as written it refused
correctly.

**The gate has not been lowered and must not be.** Twenty observations is this
project's stated floor for acting against a stranger, and moving it because a
scenario sits just underneath would be fitting a safety threshold to a test. The
real gap is narrower than the number: the floor counts events *in a window*
while the evidence it guards is already accumulated *across a session*,
`persistence_900s` spans fifteen minutes and the count gating it spans one.
Closing that means accumulating observations per source in the correlation
engine. That is a design change, and it belongs in a cycle that commits its
acceptance test before measuring, not in an edit to a threshold.

Until then: **a sufficiently patient source is not blocked automatically.**
Detection, scoring, decision records and alerting all still work; the autonomous
network block is the part withheld. This is the largest known coverage gap in
autonomous enforcement.

### Authentication Outcome Is Invisible Inside TLS (P15.4)

Eye for an Eye watches traffic arriving at one host and the replies that host
sends back. For a cleartext protocol the outcome of an authentication attempt is
right there in one of them (`530 Login incorrect`, `HTTP/1.1 401`), and for
anything inside TLS it is not there at all.

This is not a gap better parsing can close. It is where the sensor stands. A
deployment that terminates TLS at a reverse proxy, or integrates at the
application, can supply a real answer; a passive sensor watching an encrypted
session cannot, and `decision/auth.py` returns `UNKNOWN` and means it. `UNKNOWN`
is never read as failure, and success is never invented.

There is a second, narrower limit inside the observable case. A principal
pseudonym is derived only from the plainly non-secret identifier of a cleartext
command (`USER <name>`), never from an `Authorization` header, because that value
is a live secret and deriving a stored value from it is a trade this project does
not make. The cost is real and was measured: failed-principal diversity is the
strongest authentication evidence available, and over HTTP it is unavailable, so
credential stuffing there has to be carried by failure volume alone.
`training/observability.py` predeclares `positive-web-stuffing` as
`IN_SCOPE_PARTIALLY_OBSERVABLE` for exactly that reason, written down before the
corpus was scored rather than after.

### Calibration Volume Decides Which Profiles Can Be Blocked at All (P15.4)

A block requires a conservative lower bound on P(malicious), not a point
estimate, and that bound is a Wilson interval over the calibration data's own
examples. Its width depends on how many examples land in each score band. A
fact about the evidence available, not about the traffic being judged.

P15.4 fits the calibrator on **sources** rather than windows, because the cost
model prices a wrongly blocked source and a block is taken the first time any one
of a source's windows crosses. Measured on the development corpus, the fraction
of benign *sources* crossing a cutoff is 8.5 to 12.1 times the fraction of benign
*windows* crossing it, so a window-fitted probability understated the risk of the
action it authorised by roughly an order of magnitude.

Correcting the unit divides the example count by however many windows a source
produces, and that widens every interval. Fitted on two calibration corpora the
bound saturated at **0.9644**, above the `admin` cutoff of 0.8889 and the
`honeypot` cutoff of 0.6667, below `public_website` at 0.9756 and `api` at
0.9877. With that artifact **no autonomous block was possible on a public website
or an API at any score**: not because the evidence was weak, but because there
was not enough calibration data to bound it.

The response to an interval that is too wide is more examples, never a lower
cutoff. So which profiles a given calibrator can act on is a property of how much
calibration data it was fitted on, and an operator refitting on their own traffic
should expect the same arithmetic: **a small calibration set means the strict
profiles cannot be blocked at all.** That is the system refusing to act on
evidence it cannot bound, which is the intended behaviour, and it is much better
to know that is what is happening than to meet it as an unexplained absence of
blocks.

### Every P15 Number Comes From Synthetic Traffic (P15.5, P15.5R)

**The wiring defect this section used to describe is closed.** It is kept here,
rather than deleted, because it is the reason to distrust a component test, and
because a limitations page that quietly drops a limitation it once had teaches a
reader nothing.

What P15.5 found, mechanically, from the call graph rather than from prose
(recorded in the P15.5 baseline, a development-phase artifact that is not
published here): `DecisionInputs` and `HostEnforcer` were
constructed **nowhere** in `eye_for_an_eye/`, and `decision/engine.py` did not
import `autonomy` at all. Every component was correct and every unit test passed;
the shipped runtime reached the firewall by the older path (`DecisionFusion` →
`PolicyGuard` → `TemporaryBlocks.block(source, seconds)`) on an uncalibrated
fused risk. `docs/AUTONOMOUS_MODE.md` told an operator to set `[autonomy] enabled
= true`; `config.py` validated that section and nothing consumed it.

P15.5R assembled it. `decision/engine.py` now builds the autonomous pipeline from
configuration, `autonomy/pipeline.py` constructs both `DecisionInputs` and
`HostEnforcer`, `autonomy.calibrator_path` exists and is required before
`mode = "autonomous"` will validate, and the path was traced end to end to a real
kernel. The P15.5R runtime-integration report records the closure and the
evidence for it.

**What this means for the numbers, which is the part that has not changed.**
Everything P15.1 through P15.5 measured is a property of a synthetic corpus. The
runtime now assembles the path those measurements described, so a shadow
deployment would produce evidence about the decision path, but no such
deployment has run, and this repository holds no evidence from real traffic about
false-block rates, hard negatives, profile behaviour on a real site, or
multi-hour resource behaviour. `docs/SHADOW_VALIDATION_PLAN.md` states what that
evidence would have to be and how much of it is needed; until it exists,
autonomous production blocking stays off, and no result here should be read as a
statement about the Internet.

### Per-Profile Cutoffs Have Never Been Exercised (P15.5)

`training/decision_replay.replay_sample` passed a constant `scope='GLOBAL'` until
P15.5, and `CostPolicy.scope_profiles` is empty by default, so an unmapped scope
resolves to the default profile. Every window of every locked benchmark since
P15.1 was therefore priced at `public_website`'s cutoff of 0.975610 whatever site
it belonged to.

The per-profile tables in the P15.4 and P15.5 reports are outcomes *grouped* by
profile rather than *decided* per profile. They still say where a false block
would have landed (and in P15.5 there were none anywhere), but the cutoff column
is the profile's cutoff and not the one that was applied. The API eligibility
question P15.5 spent eight calibration corpora on was never actually asked at the
API cutoff of 0.987654.

The scope now comes from the corpus's declared profile and the evaluation maps
each profile name to itself. No measurement has yet been taken through it.

### Platform Checks

The following are **NOT VERIFIED IN CURRENT ENVIRONMENT**: Linux `CAP_NET_RAW` and `SO_PEERCRED` permissions, live packet capture with BPF (Berkeley Packet Filter, a packet-filtering technology), systemd and cgroups, real nftables redirect/expiry/rollback behavior, and building or running the Docker image. The opt-in namespace tests from an earlier stage still exist in the test suite, but they are skipped on Windows. The host's firewall was never changed during any of this testing.

Before moving further, the project needs: a realistic, properly authorized data set; a review of the feature thresholds and false-positive rates; a controlled Linux deployment; and real measurements of live capture, packet loss, and memory (RSS) use. None of this starts automatically. It must be done deliberately.

## See Also

- [DEPLOYMENT.md](DEPLOYMENT.md): supported platforms and deployment methods
- [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md): project-wide risks and limits
- [CONFIDENCE.md](CONFIDENCE.md): how confidence levels work
- [CORRELATION.md](CORRELATION.md): how correlation and scoring work
- [SECURITY_REVIEW_SCOPE.md](SECURITY_REVIEW_SCOPE.md): what a security review should cover
