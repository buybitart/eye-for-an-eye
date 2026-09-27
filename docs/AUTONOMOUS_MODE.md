# Autonomous mode

What it means, what it does not mean, and how to turn it on.

## What "autonomous" means here

After an administrator switches it on, ordinary protection decisions need no
human approval. The system watches traffic, builds features, evaluates the
deterministic risk engine and the local models, decides ALLOW or TEMP_BLOCK,
expires its own blocks, notices when its own components are unwell, retrains
candidate models, promotes or rolls them back under P14 governance, and cleans
up after itself.

**Autonomy is an operational property. Accuracy is an empirical property.**
They are different claims and this page keeps them apart. Nothing on this page,
and nothing the software prints, says the decisions are correct — only that
nobody has to approve each one.

The corollary matters just as much: turning autonomy on does not remove any
safety control. It means the safety controls run automatically too. The circuit
breakers, the budget, the readiness gate and the automatic fallback are all part
of what autonomous mode *is*.

## The three modes

| Mode | Decisions | Enforcement | When |
| --- | --- | --- | --- |
| `SHADOW` | computed and recorded | never | the default; a new site, a new model, or an installation earning evidence |
| `SAFE_OBSERVE` | computed and recorded | no new blocks; existing ones expire | automatically, when something the decision depends on is unwell |
| `AUTONOMOUS` | computed and acted on | within the block budget and the circuit breakers | after an administrator enables it and the readiness gate passes |

Shadow mode does not go away when autonomous mode arrives. It is where a new
model or a new site starts, and it is where the system falls back to when it
should not be trusted with a decision.

## Turning it on

```
eye-for-an-eye doctor
eye-for-an-eye autonomy readiness
eye-for-an-eye autonomy enable
```

`autonomy enable` runs the readiness gate and, if every critical check passes,
prints the configuration to add. **It does not edit your configuration file.**
That is deliberate: the setting that lets this software block people without
being asked should be one you typed.

```toml
[autonomy]
enabled = true
mode = "autonomous"
default_cost_profile = "public_website"
calibrator_path = "<path to the calibrator>"
```

`calibrator_path` is required in autonomous mode and the configuration will not
load without it. An autonomous block is taken against a calibrated probability
and its conservative bound; with no calibrator the authority refuses every block
with `CALIBRATION_UNAVAILABLE`, and the visible symptom would be a healthy
sensor that never blocks anything. `autonomy enable` prints the path already in
your configuration, or an empty line marked REQUIRED if there is none.

Then restart the service and check:

```
eye-for-an-eye autonomy status
```

## The readiness gate

`eye-for-an-eye autonomy readiness` answers one question — can this installation
be autonomous — and answers it with evidence. Each check is PASS, FAIL or
NOT_APPLICABLE, critical checks are marked, and **one critical failure means
`AUTONOMOUS_READY: NO`**. Nothing downgrades a failure to a warning because the
rest looks green.

| Check | Critical | What it means |
| --- | --- | --- |
| `config_valid` | yes | the configuration validates |
| `autonomy_configured` | yes | the decision engine is on and autonomy has a mode |
| `feature_schema` | yes | the tensor has the shape the schema implies and no two columns share a name. It pinned the literals 1 and 36 until P15.4, which made it a tripwire for the wrong thing — it would have failed a correct schema change and passed a schema whose column names had silently collided |
| `math_engine` | yes | the deterministic engine evaluated a vector, not merely imported |
| `model_available` | only if `ml.required` | a classifier, or the deterministic fallback |
| `cost_policy` | yes | a cost profile applies, and its cutoff is printed |
| `protected_networks` | yes | management networks are configured |
| `block_circuit_breaker` | yes | the budget and ceilings are usable |
| `rollback_available` | no | there is a model to go back to |
| `site_resolver` | no | site identifiers resolve uniquely |
| `storage` | no | there is room for state and retention |
| `enforcement_available` | no | **see below** |
| `decision_pipeline` | yes | two synthetic vectors reach the end of the chain — MathRisk, the calibrator, the authority — and the quiet one is allowed while the loud one is eligible to block. Wiring only: it says the gates are connected and nothing about whether real traffic would be judged correctly |
| `clock_sane` | yes | a TTL means what it says |

### The enforcement check, and the two paths it is about

Autonomous *decisions* run anywhere. Autonomous *enforcement* needs a path from
a decision to a firewall rule, and there are two of them, off separately.

**The lab namespace path** (`enforcement.enabled`) ends inside a Linux network
namespace on a machine you own, and three independent gates keep it there:

```
config.py          enforcement.enabled requires deployment.profile = "lab"
                   AND firewall.lab_namespace
firewall.py        the backend compares the target namespace against
                   /proc/1/ns/net and refuses the host namespace
firewall.py        every command runs as `ip netns exec <namespace>`
```

**The host path** (`enforcement.host_enabled`) can place a bounded temporary
block on the machine this software is protecting. It is off on a fresh
installation, a package upgrade cannot turn it on, it refuses the `lab` profile,
and it refuses to run at all without a configured management network. It writes
to one nftables table this project owns, through a separate privileged helper
that accepts an address and a lifetime and never a command. Full description:
[HOST_ENFORCEMENT.md](HOST_ENFORCEMENT.md).

So `enforcement_available` reports NOT_APPLICABLE on a deployment that has
turned neither on — which is every deployment until an administrator decides
otherwise — and it is not a statement that the capability is absent.

This page used to say there was no code path in this project that could block a
source on a real host. That was true when it was written and stopped being true
when the host path was built; the sentence is recorded here because a reader who
remembers it would act on it. What is still true is the part that matters: the
host path is off until you turn it on, and turning it on is the single most
consequential setting in the configuration file.

**Autonomous host blocking is not validated.** It has been exercised against a
real kernel on a disposable machine and never against real traffic.
[SHADOW_VALIDATION_PLAN.md](SHADOW_VALIDATION_PLAN.md) says what evidence would
be needed before anyone argues for turning it on, and until that evidence exists
and has been reviewed, the answer is no.

## What it does without being asked

- decides ALLOW or TEMP_BLOCK, and records why
- expires every block on its own schedule
- decays risk and offence history
- enters safe mode when a component fails, and comes back when it recovers
- prepares datasets and trains candidate models when `learning.enabled`
- promotes and rolls back models under P14 governance when enabled there
- runs retention and housekeeping

## What it never does

- create a permanent block (there is no value of the TTL field that means forever)
- block a protected or management source
- block a client known only through somebody else's proxy or CDN
- block on model opinion alone
- treat its own decisions, or a challenge outcome, as a training label
- reach outward: no hack-back, no scanning, no retaliation — none of it is written
- send anything to a cloud service or an LLM to decide

## Stopping it

Three things, and they do different jobs. All are local; no network is involved
in any of them.

**Release every block now.** The privileged helper deletes the one table this
installation owns and nothing else:

```
python -m eye_for_an_eye.security.firewall_helper --config <file> cleanup
```

**Stop it taking new decisions.** Set `[autonomy] enabled = false` — or
`[enforcement] host_enabled = false` to keep the decisions and stop the
blocking — and restart the service. Blocks already placed keep expiring on their
own; nothing is permanent at any layer, and 12 hours is the longest any of them
can last.

**It also stops itself.** When a component the decision depends on becomes
unwell the runtime moves to `SAFE_OBSERVE` on its own: no new blocks, everything
else still running, existing blocks still expiring. See
[AUTONOMOUS_FAILURE_RECOVERY.md](AUTONOMOUS_FAILURE_RECOVERY.md).

There is **no command that disarms a sensor already running** — stopping new
decisions needs a configuration change and a restart. That is a real limitation
and it is written here rather than papered over: an earlier version of this page
documented `eye-for-an-eye autonomy disable`, which has never existed. The
kill switch that exists is the one above.

None of this contradicts autonomous operation. It is operational safety, and an
autonomous system without a way to stop it is not safer, only less recoverable.

## See also

- [AUTONOMOUS_DECISION.md](AUTONOMOUS_DECISION.md) — the algorithm, gate by gate
- [COST_SENSITIVE_POLICY.md](COST_SENSITIVE_POLICY.md) — why the cutoff is not 0.5
- [DECISION_UNCERTAINTY.md](DECISION_UNCERTAINTY.md) — the conservative estimate
- [AUTONOMOUS_FAILURE_RECOVERY.md](AUTONOMOUS_FAILURE_RECOVERY.md) — degrading and returning
- [BACKPRESSURE.md](BACKPRESSURE.md) — what happens when the disk is slow or full
- [SHADOW_VALIDATION_PLAN.md](SHADOW_VALIDATION_PLAN.md) — what a real deployment must show before anyone argues for turning blocking on
- [AUTONOMOUS_SAFETY_INVARIANTS.md](AUTONOMOUS_SAFETY_INVARIANTS.md) — the fourteen
- [MODULE_GRADUATION.md](MODULE_GRADUATION.md) — what is production and what is lab
