# Module Graduation

Which parts of this project are ready for production, which are not, and why.

Classified by behaviour. A module is judged by what it does at a call boundary,
never by its filename or by which directory it lives in.

## The Classes

| Class | Means |
| --- | --- |
| **SAFE_TO_PRODUCTIONIZE** | defensive, bounded, local, reversible, testable, observable, fail-safe, resource-limited |
| **PRODUCTIONIZE_WITH_GUARDS** | the same, but only behind a named gate that an operator sets deliberately |
| **KEEP_LAB_ONLY** | correct, tested, and not validated anywhere it would matter |
| **OBSOLETE** | superseded; kept only for reproducibility |
| **DANGEROUS_NEVER_PRODUCTION** | would be unsafe in production at any setting |

The promotion rule (§4): a module may enter production only if it is defensive,
bounded, locally controlled, reversible, testable, observable, fail-safe and
resource-limited, and performs no uncontrolled activity against remote systems.
All eight, not most of them.

## The Surprising Result First

**This project has no modules marked experimental.** A scan of every `.py` file
for `EXPERIMENTAL`, `LAB_ONLY` and `prototype` returns nothing.

What is experimental here is a *deployment posture*, not a set of files. Four
**platforms** are marked experimental in `DEPLOYMENT.md` (Linux live capture
under systemd, Docker/Compose, arm64, Windows), and those are statements about
which environments have been verified, not about code maturity.

So this page classifies what actually exists, rather than pretending there is a
backlog of experimental modules to graduate.

---

## SAFE_TO_PRODUCTIONIZE

Already in production profiles, and they meet all eight criteria.

| Module | Evidence |
| --- | --- |
| `network/` capture, IPC, listeners | bounded queues, `SO_PEERCRED` on both sides of the helper socket, byte and time caps, drop-newest under pressure |
| `correlation/` | bounded table, TTL, fair eviction |
| `fingerprint/` p0f, IP-ID, uptime | passive only; descriptive, never an identity, never a blocking input on its own (§142) |
| `decision/math_risk` | deterministic, explainable, every term inspectable, no learned weights (§24) |
| `decision/features` | one shared transformer used by training and runtime (§69) |
| `decision/onnx_model` | the only `onnxruntime` importer; killable subprocess, hardened artifact reader, deadline |
| `decision/anomaly` | bounded additive weight carved out of the pool, never additive on top (§26) |
| `decision/ood` | reduces classifier authority, cannot raise risk (§27) |
| `decision/drift` | population-level; cannot reach a source's score (§28) |
| `decision/policy` PolicyGuard | can always say no; above everything |
| `deception/` | see the limits table below |
| `web/` sensor and parser | reads a log after the fact; cannot break a request |
| `challenge/` | fails open on every path; HMAC per site; never a label (§61) |
| `sites/` | no request creates a site; per-site state; bounded |
| `storage/`, `observability/`, `api/` | bounded, loopback-only, read-only API |
| `governance/` (P14) | assess-only engine; separate activator; off by default |

### Deception, Against the §8 Limit List

Three profiles exist: `ssh-banner-v2`, `ftp-control-v2`, `http-static-v2`.
Every §8 limit is implemented, and `ProtocolSession` takes the **minimum** of the
profile limit and the global limit, so a profile cannot widen a bound:

connection timeout, idle timeout, total session timeout, maximum request bytes,
maximum response bytes, maximum messages, maximum state transitions, global
concurrency cap, per-source concurrency cap, response-byte budget, rate limit.

The prohibitions hold structurally. `deception/` contains no `subprocess`, no
`eval`, no `exec`, no filesystem write, and no database connection, checked by
scanning the package, not by reading its documentation.

**SMTP, Redis-RESP and MySQL handshake deception do not exist.** §7 lists them as
graduation candidates; there is nothing to graduate. Writing three new protocol
emulators during a final hardening stage would add attack surface that no
evidence supports, so they stay unimplemented and are recorded here as such.

---

## PRODUCTIONIZE_WITH_GUARDS

Safe, and behind a gate an operator sets on purpose.

| Module | The guard | Why it needs one |
| --- | --- | --- |
| `challenge/` | `challenge.enabled`, shadow by default | the only code in front of a live request |
| `web/gateway` | `web.enabled` | same |
| `sites/` | `sites.enabled` | adds `Host` as an untrusted input |
| `governance/` auto-promotion | `model_governance.auto_promote_enabled`, plus per-site opt-in and a separate global switch | changes what the system blocks without being asked |
| `learning/` auto-train | `learning.enabled` | consumes CPU the sensor needs |
| `enrichment` RDAP | `enrichment.enabled` **and** `rdap_enabled` **and** `--rdap` | the only path that sends anything off the machine |
| **`decision/autonomy`** (new in P15) | `decision.autonomous`, plus a readiness gate | computes ALLOW/TEMP_BLOCK without per-event approval |
| **`security/host_firewall`, `security/firewall_helper`, `security/host_enforcer`** (new in P15.1) | `enforcement.host_enabled`, off on a fresh installation, plus a validator that refuses it without a protected network | the only code in this project that can deny a stranger access to a real service |
| **`security/enforcement`** (new in P15.1) | none needed | the request vocabulary and the protected-network check. It holds no privilege and writes nothing; it is the thing that *describes* a block |

---

## KEEP_LAB_ONLY

Correct and tested. Not validated anywhere it would matter.

### `eye_for_an_eye/security/firewall.py` and `eye_for_an_eye/security/temporary_blocks.py`

**This is the important entry on the page.**

The code is good: its own nftables table with a per-process UUID owner comment,
verified after every write, TTL-bounded, never flushing or reading the host
ruleset, revalidating protected addresses at the side-effect boundary.

It stays LAB_ONLY because it has never blocked anything on a real server, and
because the restriction is structural rather than configured:

```
config.py:633          enforcement.enabled requires profile == 'lab'
                       AND firewall.lab_namespace
firewall.py:60-62      _guard() compares the target namespace against
                       /proc/1/ns/net and refuses the host namespace
firewall.py:71         every command runs as `ip netns exec <namespace>`
```

Three independent gates. **There is no code path in this project that can block a
source on a real host**, and no setting that creates one.

P15 does not change this. Graduating it would mean writing new host-namespace
enforcement code and calling it production on the strength of test coverage,
which is the substitution P13 explicitly refused: *coverage is not deployment
evidence*.

What P15 does instead is build the decision half. An authority that decides
ALLOW or TEMP_BLOCK correctly, records why, and hands the result to an executor
that currently reaches only a namespace. §91 requires those two to be separate
anyway.

| Other LAB items | Why |
| --- | --- |
| `templates/lab.toml` | loopback-only, 10-second cap, "DO NOT USE ON PUBLIC INTERNET" |
| `tests/linux_lab/` | needs `E4E_RUN_NAMESPACE_LAB=1` and a machine you own |
| `web/lab.py` | request-shape fixtures |
| `dataset/generators/`, `dataset/scenarios/` | offline corpus generation |
| `benchmarks/` | load generation, soak, fuzzing; offline, no external targets |

---

## OBSOLETE

Kept for reproducibility, not for use.

| Item | Why it stays |
| --- | --- |
| `training/build_dataset.py`, `training/train_baseline.py` | frozen P7 generators; `research-v2` must stay byte-reproducible |
| `models/research-v2/` | superseded artifacts, referenced by the above |
| `docs/history/` | archived development records |

**Not obsolete, despite appearances:** the six `+*.py` root files are
compatibility entrypoints, and `+garbage.py` is load-bearing,
`tests/test_cli_integration.py` starts it as a subprocess and fails without it.
Judging those by filename would have deleted a working test.

---

## DANGEROUS_NEVER_PRODUCTION

**Nothing in this repository is in this class, and the reason is worth stating:
the dangerous things were never written.**

There is no hack-back, no retaliation, no scanner, no exploit code, no outbound
attack path, no shell execution anywhere in the request path, and no remote
command interface. `active_probes` (the only module that ever reaches outward)
is off by default, requires an explicit CIDR allowlist, and is refused outright
when a PCAP is being replayed.

A class with no members is the correct outcome for a defensive project. It is
listed rather than omitted so that a reviewer can see the question was asked.

---

## Graduation Decisions Made in P15

| Decision | Class | Reason |
| --- | --- | --- |
| `decision/autonomy` (new) | PRODUCTIONIZE_WITH_GUARDS | decides only; has no enforcement privilege; behind `decision.autonomous` and a readiness gate |
| `security/temporary_blocks` | KEEP_LAB_ONLY (unchanged) | no host-namespace path exists, and no deployment evidence justifies writing one |
| deception protocols | SAFE (unchanged) | every §8 limit already implemented and enforced by minimum-of-two composition |
| SMTP / Redis / MySQL deception | not implemented | new attack surface with no evidence behind it |
| `+*.py` entrypoints | keep | one is load-bearing; the others are documented compatibility shims |

## Graduation Decisions Made in P15.1

P15's entry above says a host path does not exist and no evidence justifies
writing one. P15.1 wrote one, as **new code beside** the lab modules rather
than as a relaxation of them, and with evidence rather than in place of it.

| Decision | Class | Reason |
| --- | --- | --- |
| `security/enforcement` (new) | PRODUCTIONIZE_WITH_GUARDS, no guard of its own | the request vocabulary: an address, a family, a scope, a lifetime, a decision id, reasons; and no command field. It cannot act |
| `security/host_firewall` (new) | PRODUCTIONIZE_WITH_GUARDS | one owned table, timeout sets only, apply-then-verify, no `flush` anywhere, and a real dropped TCP connection as evidence |
| `security/firewall_helper` (new) | PRODUCTIONIZE_WITH_GUARDS | the privileged side, in its own process, re-validating against its own copy of the configuration |
| `security/host_enforcer` (new) | PRODUCTIONIZE_WITH_GUARDS | the unprivileged side; refuses any record that is not a network-enforceable block |
| `eye_for_an_eye/security/firewall.py`, `eye_for_an_eye/security/temporary_blocks` | KEEP_LAB_ONLY (**unchanged**) | the namespace path is untouched. Its three gates still hold, and a test still asserts each |
| `training/decision_replay` (new) | offline measurement, not shipped behaviour | reads a corpus, writes a report, holds no state and takes no action |

## How to Re-run This Audit

```
grep -rn "EXPERIMENTAL\|LAB_ONLY\|prototype\|DANGEROUS" --include=*.py eye_for_an_eye/
eye-for-an-eye doctor
eye-for-an-eye autonomy readiness
```

`tests/test_p15_invariants.py` encodes the classifications that must not drift:
that nothing in `deception/` can reach a shell, that the firewall backend still
refuses the host namespace, and that no production profile enables enforcement.

## See Also

- [P0_P12_STATUS.md](P0_P12_STATUS.md): feature-level status with test counts
- [AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md)
- [AUTONOMOUS_SAFETY_INVARIANTS.md](AUTONOMOUS_SAFETY_INVARIANTS.md)
- [DEPLOYMENT.md](DEPLOYMENT.md): which platforms are verified
