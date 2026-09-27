# Security review scope

This page is written for an independent security auditor. It says what the
system is, where the trust boundaries are, and what to attack first.

There has been **no external independent security audit**. Internal review only:
author review, Bandit static analysis with reviewed exceptions pinned by code
hash, a narrow secret scan, and `pip-audit`.

## Size

Measured on 2026-09-11.

| Area | Lines of Python |
| --- | --- |
| `eye_for_an_eye/` (the service) | about 19 300 |
| `dataset/` (offline) | about 5 100 |
| `training/` (offline) | about 3 300 |
| `benchmarks/` (offline) | about 2 100 |
| `scripts/` | about 400 |
| `tests/` | about 17 400 lines, 1 552 tests (1 522 pass, 30 skip) |

The service roughly tripled between P9 and P12 — the web sensor, the challenge
and multi-site profiles are most of the growth, and all three are attacker-facing
in a way the earlier code was not. Priorities 11, 12 and 13 below are new for
that reason, and an auditor with limited time should read them before some of
the lower-numbered ones.

It is still small enough to read completely.

The 30 skips are a generated dataset or model artifact that is not distributed
in the source archive, or the isolated-Linux namespace lab, which needs
`E4E_RUN_NAMESPACE_LAB=1` and a machine you own. **Run the suite as a normal
user:** as root, the artifact reader correctly refuses model files owned by
another user and several P7 tests fail for that reason alone.

## Trust boundaries

```text
[ hostile network ]
        |  packets                          <-- boundary 1
[ capture helper: CAP_NET_RAW, no analysis ]
        |  bounded JSON over a Unix socket  <-- boundary 2
[ analysis process: unprivileged ]
        |  float32[1,36] over a pipe        <-- boundary 3
[ inference process: model, no network ]
        |
[ analysis process ]
        |  parsed literals only             <-- boundary 4
[ nftables in a named namespace: lab only ]

[ analysis process ] -- redaction --> [ SQLite / JSONL / read-only API ]  <-- boundary 5
```

## Priority 1: the packet parsing path

The highest-value target. Attacker-controlled bytes reach parsing code.

* `eye_for_an_eye/network/capture.py`, `capture_helper.py`
* `eye_for_an_eye/offline.py` (PCAP reading)
* `eye_for_an_eye/fingerprint/`

Look for: memory growth on malformed frames; parser confusion between the helper
and the analysis side; frame-size cap bypass; truncated and overlapping segments;
IPv6 extension header handling; anything that makes the helper do work
proportional to attacker input.

Note: the helper runs with `CAP_NET_RAW` and can see credentials in traffic.

## Priority 2: the IPC boundary

* Peer-UID checking on the Unix socket.
* Length and version validation of each message.
* Behaviour when the helper is replaced by a hostile process with the expected
  UID.
* Behaviour when the socket path is pre-created or symlinked.

## Priority 3: the enforcement path

* `eye_for_an_eye/security/firewall.py`, `temporary_blocks.py`
* `eye_for_an_eye/decision/policy.py` (`PolicyGuard.protected`)

Look for: any way to reach the host network namespace; any way to get a
protected address blocked (IPv4-mapped IPv6, unusual literals, proxy handling);
table ownership verification; behaviour when the local interface list cannot be
read; the read-back-and-verify step after adding an entry; cleanup when the
process dies.

Confirm the negative: no shell, no string interpolation of network data into a
command, no global flush, no modification of a table the process does not own.

## Priority 4: the model boundary

* `eye_for_an_eye/decision/onnx_model.py` (`read_artifacts`, `_read`)
* `eye_for_an_eye/decision/worker.py`

Look for: manifest checks that can be bypassed; TOCTOU between the hash check
and the load; symlink and network-path handling; the size cap; what a hostile
ONNX file can do to ONNX Runtime; process isolation and timeout enforcement;
whether a model result can ever bypass `minimum_math_risk`.

## Priority 5: redaction

* `eye_for_an_eye/security/redaction.py`

This is the privacy control. Look for any path that writes to storage, logs or
the API without passing through it. Try to get a payload, a password, a cookie,
a token or an `Authorization` header into the database or a log line.

Check the regular expressions for catastrophic backtracking on attacker input.

## Priority 6: the read-only API

* `eye_for_an_eye/api/server.py`, `api/models.py`
* `eye_for_an_eye/storage/reader.py`

Look for: authentication bypass; Host and Origin handling behind a proxy; query
budget bypass; cursor handling and the 300-second redaction cursor; whether SQL
or paths can leak to a client; resource use of a hostile query.

## Priority 7: deception

* `eye_for_an_eye/deception/engine.py`, `protocols.py`, `policy.py`
* `eye_for_an_eye/network/listeners.py`

Confirm the negatives: no shell, no command execution, no file serving, no
outbound connection. Then look for: state growth per connection; byte and
message limits; source allowlist bypass; the HMAC profile selection and what
leaking the secret allows; whether a decoy can be made to bind a protected port.

## Priority 8: storage

* `eye_for_an_eye/storage/sqlite.py`, `lifecycle.py`

Look for: writer lease handling with two instances; migration safety; retention
enforcement under pressure; behaviour when the disk fills; whether the volatile
fallback can leak unredacted data.

## Priority 9: the installer and packaging

* `scripts/install.sh`, `scripts/uninstall.sh`
* `pyproject.toml`, `MANIFEST.in`, `uv.lock`, `requirements/runtime.txt`
* `Dockerfile`, `docker-compose.lab.yml`, `deploy/systemd/`

Look for: anything the installer does that the documentation does not state;
path handling with spaces and unusual characters; whether `--dry-run` is
faithful; whether re-running can damage an existing install; whether the
uninstaller can delete something it did not create.

Confirm the negatives: no firewall change, no service enabled or started, no
port exposed, no root needed in the default path.

## Priority 10: the offline pipelines

* `dataset/safety.py` — the target validation that must never allow a public
  address.
* `dataset/collectors/`, `training/`

These do not run in production, but a compromise here poisons a future model.

## Priority 11: the request-time gateway and the challenge (P11)

**This is the only code in the project that sits in front of a live request.**
Everything else observes after the fact. It is therefore the only place where a
bug can take a website off the air, and it should be read before the lower
priorities even though it is numbered after them.

Read: `eye_for_an_eye/web/gateway.py`, `eye_for_an_eye/challenge/token.py`,
`eye_for_an_eye/challenge/policy.py`, `eye_for_an_eye/challenge/service.py`,
`eye_for_an_eye/challenge/page.py`.

Try to falsify:

* that `WebGateway.handle` cannot raise, for any input, including a malformed
  cookie, an oversized token, a hostile `Host` header and a broken collaborator;
* that the signing secret cannot reach JavaScript, HTML, a cookie or browser
  storage;
* that a token minted for site A does not verify for site B;
* that token parsing is strict — canonical unpadded base64url only, with no
  accepted alternative encoding of the same token (the fuzzing suite found three
  malleability bugs here, so this is not hypothetical);
* that a challenge outcome cannot become a label, and cannot reach TEMP_BLOCK.

## Priority 12: `Host` resolution and site isolation (P12)

Read: `eye_for_an_eye/sites/identity.py`, `eye_for_an_eye/sites/engine.py`,
`eye_for_an_eye/sites/profile.py`, `eye_for_an_eye/sites/state.py`.

Try to falsify:

* that no request can create a site;
* that an unmatched `Host` lands in a shadow-mode bucket with no powers;
* that site identity — site id, domain, `Host`, profile type — never reaches the
  model as a feature;
* that one site's web counters cannot be read from another site;
* that a flood against one site cannot evict a quiet site's state;
* that a host-wide network block requires explicit per-site configuration.

Note the limit the design accepts rather than solves: sites share one process.

## Priority 13: the access-log parser (P10)

Read: `eye_for_an_eye/web/nginx.py`, `eye_for_an_eye/web/event.py`,
`eye_for_an_eye/web/identity.py`.

Every field here is attacker-chosen. Try to falsify that the parser is bounded
in time and memory for any line, that a forwarded header from an untrusted peer
is ignored, and that a proxied client is never network-enforceable.

## Out of scope

* Cryptographic review of a protocol design. There is no custom protocol.
* Web application vulnerabilities. There is no web application, only a read-only
  local JSON API.
* Anything needing a Windows production deployment. Windows is development only.

## Environments needed

Most of the interesting surface needs Linux with elevated rights in a throw-away
environment:

```sh
sudo env E4E_RUN_NAMESPACE_LAB=1 /path/venv/bin/python -B \
    -m pytest tests/linux_lab/ -q
```

**NOT VERIFIED IN CURRENT ENVIRONMENT:** Linux live capture, the namespace
firewall, `CAP_NET_RAW`, original destination lookup, systemd hardening,
container health probes.

## What the project claims, for an auditor to falsify

1. No network traffic leaves the machine by default.
2. No payload, password, cookie, token or `Authorization` header is ever stored
   or logged.
3. A model file alone can never cause a block.
4. Enforcement cannot touch the host network namespace.
5. No network data ever becomes a shell command.
6. Every queue, cache and store is bounded.
7. The running service contains no training code.
8. The model receives no identity feature: no address, country, ASN, provider,
   hostname, site id, domain or `Host` value.
9. The challenge gateway cannot raise, for any input. Every failure path ends in
   "let the request through".
10. A challenge result is evidence and never a label, in either direction.
11. No request can create a site, and an unconfigured `Host` gets no powers.
12. There is no `auto_promote` setting anywhere in the configuration. Promotion
    requires a person and a passing quality gate at the registry itself.

Each is intended to be checkable by reading the code.

**Claims 9 to 12 are new since the last revision of this page**, and cover the
web sensor, the challenge and multi-site profiles — which between them are most
of the code written since P9 and nearly all of the attacker-facing surface. An
earlier revision of this document described a P0-P9 system and would have led an
auditor to review none of it.

## See also

* [Threat model](THREAT_MODEL.md)
* [Architecture](ARCHITECTURE.md)
* [Risks and limitations](RISKS_AND_LIMITATIONS.md)
* [SECURITY.md](../SECURITY.md)
