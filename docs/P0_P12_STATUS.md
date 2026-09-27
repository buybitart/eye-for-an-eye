# What Actually Works: P0 to P12

This page exists because "implemented" is a word with too much range in it. A
feature can have a module, a test suite and a documentation page and still be
something no operator should switch on. Somebody deciding whether to run this on
a server that matters needs the difference stated, not implied.

Every entry below carries one of six words. They are not grades. They are
statements about how far a thing has been taken.

| Word | Means |
| --- | --- |
| **IMPLEMENTED** | Works, is tested, and is safe to use as documented. |
| **PARTIAL** | The main path works. Named pieces of it do not. |
| **EXPERIMENTAL** | Works, but the evidence is thin. Use in shadow; do not depend on it. |
| **LAB_ONLY** | Exercised only in an isolated lab. Not validated on a real server. |
| **DOCUMENTATION_ONLY** | Described, designed, and not built. |
| **MISSING** | Not built, and in some cases deliberately so. |

Verified on 2026-09-11 against the working tree, running the suite as a
non-root user:

```
1522 passed, 30 skipped, 2824 subtests   (1552 collected, 87 test files)
ruff: clean
scripts/security_scan.py: exit 0
```

The 30 skips are all one of two honest reasons: a generated dataset or model
artifact that is not distributed in the source archive, or the isolated-Linux
namespace lab, which requires `E4E_RUN_NAMESPACE_LAB=1` and a machine you own.
Neither is a silenced failure. **Run the suite as a normal user**: as root, the
artifact reader correctly refuses model files owned by anyone else, and several
P7 tests fail for that reason alone.

---

## The Short Version

Everything that *observes* is implemented. Everything that *acts on the network*
is lab-only or off. Everything that *learns on its own* is deliberately missing.

That ordering is the design, not an accident of what got finished first.

---

## By Stage

### P0-P1: Foundation, Capture, Privileges, Storage

**IMPLEMENTED.** Configuration with validation, bounded event intake, the
privilege-separated capture helper, the SQLite store with migrations, retention
and a disk envelope, and the systemd deployment.

Tests: `test_p1_foundation` (8), `test_p1_storage` (10), `test_p1_firewall` (6),
`test_p1_privileges_ipc` (4), `test_p1_providers` (2), `test_p1_deployment` (1),
`test_capture` (5), `test_listeners` (11), `test_config` (5).

Note on the firewall module at this stage: the *code* is implemented and tested;
the *use* of it is covered under enforcement below and is LAB_ONLY.

### P2: Correlation and Fingerprinting

**IMPLEMENTED.** The bounded correlation table, source sequences, the p0f
adapter, IP-ID and uptime observation, and offline PCAP replay.

Tests: `test_p2_correlation` (14), `test_p2_fingerprints` (11),
`test_p2_offline` (7), `test_fingerprints` (7), `test_p0f_contract` (2),
`test_probes` (16).

### P3: Deception Profiles

**IMPLEMENTED**, and on by default in `sensor` mode, which answers nothing.
Finite, bounded, non-interactive service profiles with a privacy projection at
the telemetry boundary.

Tests: `test_p3_engine` (15), `test_p3_protocols` (5), `test_p3_catalogue` (2),
`test_p3_storage` (3), `test_profiles` (9).

### P4-P5: API, Metrics, Logging, Backpressure

**IMPLEMENTED**, all off by default. Local-only HTTP API, Prometheus-style
metrics, bounded JSONL logging, load shedding and batched storage.

Tests: `test_p4_api` (11), `test_p4_metrics` (2), `test_p4_events_logging` (4),
`test_p4_storage_operations` (6), `test_p5_backpressure` (3),
`test_p5_storage_batch` (4), `test_p5_performance_contracts` (2),
`test_p5_benchmark_smoke` (1), `test_cache` (8).

### P6: Release Operations

**IMPLEMENTED.** Backup and restore, storage lifecycle, migration planning,
release build and package smoke.

Tests: `test_p6_release_operations` (27).

### P7: Decision Engine and the Local ONNX Boundary

**IMPLEMENTED.** The deterministic mathematical engine, the feature schema, the
fusion and policy guard, and the killable subprocess that owns the only
`onnxruntime` import in the project.

Tests: `test_p7_decisions` (23), `test_p7_onnx` (8), `test_p7_features` (3),
`test_p7_replay` (2).

The mathematical engine has never depended on a model. A deployment with no
model file is a supported configuration, not a degraded one.

### P8 Reliability: OOD, Drift, Model Health, Anomaly

**IMPLEMENTED** as a mechanism. The reference distribution, out-of-distribution
scoring, population drift, model health and the unsupervised anomaly model all
work and are tested against the rule that matters: unknown is not malicious.
Neither drift nor OOD can raise risk; both can only reduce how much authority
the classifier is given.

Tests: `test_p11_reliability` (43), `test_p11_anomaly` (20),
`test_p8_model_manifest` (6).

### The Shipped Classifier: EXPERIMENTAL

`models/risk-logreg-v1` is shipped, and its own model card records why it should
not be trusted to act:

```
recommended_mode:      shadow
quality_gate_passed:   false
validation PR-AUC:     0.997
test PR-AUC:           0.699      (held-out scenario families)
ONNX parity:           passed, max abs diff 3.6e-07
```

The distance between 0.997 and 0.699 is the whole story. The model is very good
at the scenario families it saw and considerably less good at ones it did not,
which is exactly what you would expect from a synthetic corpus and exactly why
the gate says no. It is shipped so that the pipeline around it can be exercised
end to end, and it is shipped in shadow.

### P9: Dataset Pipeline, Review Queue, Training Jobs

**IMPLEMENTED**, with one qualification recorded below.

Tests: `test_p9_dataset_pipeline` (9), `test_p9_dataset_safety` (10),
`test_p9_dataset_schema` (6), `test_p9_invariants` (20), `test_review_queue`
(49), `test_review_queue_engine` (11), `test_training_jobs` (47),
`test_training_bridge` (23), `test_dataset_candidate` (27),
`test_candidate_shadow` (31), `test_model_registry` (42),
`test_retraining_advice` (30).

**Qualification.** Until the P13 audit, the review queue received nothing at
all whenever out-of-distribution scoring was working. One wrong attribute name
inside a `try` block whose `except` swallows everything meant the offer was
abandoned every time, silently, while the failure counter incremented and
nothing else looked wrong. The learning loop's first step is "a sample reaches a
person"; that step was broken, so no labels, so no dataset, so no candidate.
Fixed, with the end-to-end property now asserted rather than the components.

Treat the loop as **PARTIAL until a real deployment has run it**: every stage is
implemented and tested, and none of it has ever been driven by traffic from a
server somebody depends on.

### P10: Web Sensor

**IMPLEMENTED**, off by default. Nginx access-log parsing, client identity
behind trusted proxies, per-source web behaviour and the action ladder up to
WATCH.

Tests: `test_web_parser` (57), `test_web_identity` (30), `test_web_behaviour`
(24), `test_web_enforcement_safety` (24), `test_p10_dataset_sources` (13).

The sensor reads a log, which means it sees a request only after the server has
already answered it. That is why it cannot break a website: it never touches one.

### P11: Adaptive Web Challenge

**IMPLEMENTED**, off by default, shadow by default.

Tests: `test_challenge_policy` (50), `test_challenge_token` (42),
`test_challenge_service` (41), `test_challenge_flow` (38),
`test_challenge_lab` (35), `test_challenge_cli` (35),
`test_challenge_docs` (26), `test_challenge_integration` (26),
`test_challenge_fuzzing` (23), `test_p11_setup_cli` (17).

The ladder stops at RATE_LIMIT. A challenge result is evidence and never a
label: failing one cannot make a source malicious and passing one cannot make it
benign. The fuzzing suite found three genuine token-malleability bugs that no
hand-written case would have reached.

### P12: Multi-site Profiles

**IMPLEMENTED**, off by default (`sites.enabled = false`), every site starting
in shadow.

Tests: `test_site_identity` (46), `test_site_profile` (42), `test_site_baseline`
(39), `test_sites_cli` (37), `test_site_models` (36), `test_site_engine` (33),
`test_site_docs` (28), `test_site_dataset` (22), `test_site_state` (21).

Measured, not asserted: under a 200,000-request flood against one site, a quiet
site held 40 sources before and 40 after, with zero evictions charged to it, and
200,000 invented `Host` values created no sites and left the unknown bucket at
its 256-source ceiling.

**Not isolated, and documented as such:** sites share one process. A host-wide
network block reaches every site on the machine, which is why a site must be
explicitly configured before it may ask for one, and why it is off in every
profile template.

### P13: The Audit Itself

Not a feature, so it has no status word. It added four test files that ask
whole-system questions rather than component ones, and they are listed here
because the stage counts above do not otherwise account for them.

Tests: `test_p13_degraded_modes` (37) (one injected failure per case;
`test_p13_integration` (34)) the failures that hide behind a caught exception;
`test_p13_drills` (19) (model rollback, site rollback, configuration migration;
`test_p13_schemas` (10)) the compatibility matrix and training/runtime parity.

Two defects found there had passed every component test for months: a review
queue that received nothing, and a rollback that never reached the running
process. See [reports/P13_FULL_SYSTEM_AUDIT_REPORT.md](../reports/P13_FULL_SYSTEM_AUDIT_REPORT.md).

### P14 Model Governance: IMPLEMENTED, OFF BY DEFAULT

Eleven lifecycle states with an explicit transition table; an assess-only engine
of 45 gates, separate from the activator; guarded activation under a reduced
action ceiling; automatic rollback in three tiers; a journal that freezes
promotion rather than resolving an unreadable file to "nothing was happening".

`model_governance.auto_promote_enabled` is false on a fresh install, a package
upgrade cannot turn it on, the global switch is a second deliberate decision, and
enabling promotion without guarded activation or without automatic rollback is
refused by configuration validation.

Tests: `test_p14_governance`, `test_p14_activation`, `test_p14_rollback`,
`test_p14_readiness`, `test_p14_operations`, `test_p14_docs`.
See [reports/P14_SCOPED_SAFE_AUTO_PROMOTION_REPORT.md](../reports/P14_SCOPED_SAFE_AUTO_PROMOTION_REPORT.md).

### P15 Autonomous Decision Authority: IMPLEMENTED, OFF BY DEFAULT

A final ALLOW / TEMP_BLOCK authority with a cost-sensitive cutoff, a conservative
probability estimate, ten independent evidence families, an assumption registry,
four circuit breakers, a readiness gate, and automatic degradation and recovery.
Nothing in it can enforce: the authority holds no firewall handle and imports
nothing that could acquire one.

`autonomy.enabled` is false on a fresh install and `mode` is `shadow`. The
readiness gate refuses an installation with no protected networks configured.

**What autonomous mode is on a production host.** Autonomous *decisions*, made
and recorded without per-event approval, plus the web-layer actions where the web
sensor is deployed. Autonomous *enforcement* stays lab-only, for the reason in
the next section, and the readiness gate reports that rather than implying
otherwise.

Tests: `test_p15_autonomy` (88), `test_p15_invariants` (45, including the
fourteen safety invariants), `test_p15_science` (54), `test_p15_runtime` (36),
`test_p15_docs` (25).
See [reports/P15_FINAL_AUTONOMOUS_DEFENSE_REPORT.md](../reports/P15_FINAL_AUTONOMOUS_DEFENSE_REPORT.md).

---

## Enforcement: LAB_ONLY

The firewall integration is implemented and tested, `enforcement.enabled`
defaults to `false`, and the only places a temporary block has ever been
exercised are an isolated network namespace and a container lab.

No block has been placed on a production server by this software. Until that
changes, enforcement is LAB_ONLY regardless of how much test coverage it has,
coverage is not deployment evidence, and saying otherwise to somebody choosing a
tool for a server they cannot afford to lose would be a lie with consequences.

Tests: `tests/linux_lab/` (3, skipped unless `E4E_RUN_NAMESPACE_LAB=1`).

---

## Deliberately Missing

**Automatic model promotion: MISSING, by design.** There is no
`auto_promote` setting anywhere in the configuration, because a name that does
not exist cannot be set by accident. Promotion requires a person and a passing
quality gate at the registry itself. This is P14's question, not P13's.

**`learning.auto_train` and `learning.auto_prepare_dataset`: RESERVED, not
honoured.** Both names exist and default to `false`. No code path reads either
one to start anything. Setting either to `true` changes no behaviour in this
release. They are kept so that a future release wiring them up cannot silently
inherit a value an operator set expecting something else. `learning status` says
this in those words.

**Hack-back, retaliation, active response beyond deception; MISSING, and will
stay missing.** The name of the project is a description of what attackers do,
not a description of what this software does.

---

## Known Limits That No Amount of Testing Removes

* **No at-risk user has run this.** The design choices follow from thinking
  about independent media and small NGOs running their own servers. None of them
  has used it. That gap closes by talking to operators, not by writing more code.
* **The corpus is synthetic.** Reproducible, documented, leakage-checked; and
  generated. The held-out test PR-AUC above is what that costs.
* **One process.** Multi-site is separation of state and policy, not a sandbox.
* **Bus factor of one.**
* **No external security audit.** `docs/SECURITY_REVIEW_SCOPE.md` names the
  eight claims an auditor should try to falsify, in priority order.
* **Licensing is settled.** MIT, Copyright (c) 2026 Aliaksandr Zasinets, declared
  in `LICENSE` and in `pyproject.toml`. One optional dependency (scapy) is
  GPL-2.0-only; see `THIRD_PARTY_NOTICES.md` before bundling it.

## See Also

* [ARCHITECTURE.md](ARCHITECTURE.md): how the parts fit together
* [THREAT_MODEL.md](THREAT_MODEL.md): what this defends against, and what it does not
* [LIMITATIONS.md](LIMITATIONS.md) and [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md)
* [SECURITY_REVIEW_SCOPE.md](SECURITY_REVIEW_SCOPE.md): where an auditor should start
