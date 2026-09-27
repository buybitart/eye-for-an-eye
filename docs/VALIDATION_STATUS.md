# Validation status

This page says what has been tested and how. It exists so that no other page in
this repository has to be read generously.

Four words are used, and they mean different things:

* **Implemented** — the code exists and runs.
* **Controlled-tested** — exercised by this repository's own test suite, on
  synthetic input, in a clean environment, and where marked on a real Linux
  kernel in an isolated network namespace.
* **Real-world validation pending** — no independent evidence from a long
  running deployment on real traffic exists yet.
* **Lab only** — present, bounded, and not for a production deployment.

Nothing here is evidence about traffic that has not arrived. A controlled test
establishes that the software does what it says on the input it was given; it
does not establish how often that is the right thing to do on the Internet.

## The matrix

| Component | Implemented | Unit tested | Integration tested | Clean-clone tested | Controlled-kernel tested | Real-world validated |
|---|---|---|---|---|---|---|
| Network and web analysis | PASS | PASS | PASS | PASS | N/A | PENDING |
| Correlation, FeatureVector, authentication context | PASS | PASS | PASS | PASS | N/A | PENDING |
| Evidence families and composition | PASS | PASS | PASS | PASS | N/A | PENDING |
| MathRisk v4 | PASS | PASS | PASS | PASS | N/A | PENDING |
| Calibrated probability | PASS | PASS | PASS | PASS | N/A | PENDING |
| Auxiliary ONNX model | PASS | PASS | PASS | PASS | N/A | PENDING |
| Anomaly, out-of-distribution, drift | PASS | PASS | PASS | PASS | N/A | PENDING |
| Evidence maturity gates | PASS | PASS | PASS | PASS | N/A | PENDING |
| Expected loss and cost profiles | PASS | PASS | PASS | PASS | N/A | PENDING |
| Autonomous decision authority | PASS | PASS | PASS | PASS | PASS | PENDING |
| PolicyGuard | PASS | PASS | PASS | PASS | PASS | PENDING |
| Decision journal | PASS | PASS | PASS | PASS | N/A | PENDING |
| Shadow export | PASS | PASS | PASS | PASS | N/A | PENDING |
| Site and profile resolution | PASS | PASS | PASS | PASS | N/A | PENDING |
| Temporary host enforcement | PASS | PASS | PASS | PASS | PASS | PENDING |
| Automatic block expiry | PASS | PASS | PASS | PASS | PASS | PENDING |
| Management-network protection | PASS | PASS | PASS | PASS | PASS | PENDING |
| Trusted proxy and CDN protection | PASS | PASS | PASS | PASS | PASS | PENDING |
| Mass-block circuit breaker | PASS | PASS | PASS | PASS | N/A | PENDING |
| Safe mode and recovery | PASS | PASS | PASS | PASS | N/A | PENDING |
| Model governance and rollback | PASS | PASS | PASS | PASS | N/A | PENDING |
| Controlled retraining | PASS | PASS | PASS | PASS | N/A | PENDING |
| Bounded deception | PASS | PASS | PASS | PASS | N/A | PENDING |
| False-positive rate on real traffic | — | — | — | — | — | **PENDING** |

"N/A" means a kernel test would answer nothing about that component; only the
enforcement path touches the kernel.

## What the controlled-kernel row means

On a real Linux kernel, in an isolated network namespace, the test suite
demonstrates the whole path end to end: input reaches the runtime, the runtime
decides, and a real TCP connection that succeeded before the decision fails
after it and succeeds again when the block expires. The same tests demonstrate
that a source inside a protected management network is refused as a block
candidate, that a client seen only behind a trusted proxy does not cause the
proxy's address to be blocked, and that in shadow mode no host enforcer is
constructed at all.

Those tests are in this repository and run with
`E4E_RUN_HOST_FIREWALL=1 pytest tests/test_p15_5r_runtime_enforcement.py tests/test_p15_1_enforcement.py`
as root, in an environment you are willing to have a firewall rule created in.
They are skipped by default.

## The row that is empty, and why

**False-positive rate on real traffic has no evidence at all.** Every number
this project has published about detection comes from a synthetic corpus. That
is enough to say the software behaves as designed; it is not enough to say how
often blocking a source would be the wrong thing to do on your site.

`docs/SHADOW_VALIDATION_PLAN.md` states what would close that row: roughly
3,000 independent reviewed benign sources from a real deployment, with a
false-would-block rate whose 95% upper bound sits at or below one per thousand.
Until that evidence exists, autonomous blocking should be treated as
experimental and requiring validation on the site it will run on.

This is why production Shadow exists and why it is the recommended first
deployment: it produces exactly that evidence, on your traffic, without
blocking anybody.

## Distinctions this project keeps

These are not pedantry. Each one is a mistake that would otherwise be easy to
make while reading a result:

* an ML score is not a probability;
* MathRisk is not a probability;
* an anomaly is not an attack;
* out-of-distribution is not malicious;
* drift is not an attack;
* a bot is not an attacker;
* an IP address is not a person;
* a block is not ground truth — the system's own decision is never used as a
  label for training or for measuring itself;
* observation is not attribution.

## See also

* [Shadow validation plan](SHADOW_VALIDATION_PLAN.md) — what real evidence has
  to be, and how much of it
* [Limitations](LIMITATIONS.md) — what this project does not do, and what has
  not been measured
* [Autonomous mode](AUTONOMOUS_MODE.md) — the decision path, and how to stop it
* [Generalization policy](GENERALIZATION_POLICY.md) — what a synthetic result
  does not say
