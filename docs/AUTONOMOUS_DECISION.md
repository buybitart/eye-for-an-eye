# The Autonomous Decision

One algorithm, in an order anybody can audit. This page is that order.

## The Question It Answers

ALLOW or TEMP_BLOCK. Nothing softer: OBSERVE, WATCH, SOFT_CHALLENGE, RATE_LIMIT
are chosen earlier, by the ladders in the network and web sensors, and they do
not come here. This is the last decision, the one with a firewall rule at the end
of it, and it is the only one this module makes.


## Every Number the Decision Used, Named in the Record

§89: the score conversion is not hidden. A record carries `math_risk`,
`model_score`, `calibrated_probability`, `conservative_probability`,
`legacy_conservative_probability`, `bound_source`, `calibration_version`,
`ood_status`, `data_quality`, `loss_allow`, `loss_block`, `threshold` and the
cost policy digest.

`bound_source` is the one to read first. `calibration_wilson` means the decision
rested on a Wilson lower bound over the calibrator's own fitting sample.
`shrinkage` means it rested on the P15 heuristic estimate, and an estimate from
that path cannot produce a block, because `calibrated_estimate` gates above it.

Two numbers rather than one, because a reader who wants to know how much the
P15.2 repair changed a given decision should be able to see it in the record
instead of re-deriving it.

## The Chain

```
FeatureVector
     |
     +-----------+
     |           |
  MathRisk      ML
     |           |
     +-----+-----+
           |
        Anomaly
           |
          OOD
           |
     DataQuality
           |
  IdentityConfidence
           |
      Persistence
           |
     EvidenceModel
           |
   ExpectedLossEngine
           |
 AutonomousDecisionAuthority
           |
       PolicyGuard
           |
      ALLOW / TEMP_BLOCK
```

**No ONNX model bypasses this chain.** The classifier contributes a bounded share
of the evidence, one signal family, and one corroborating reason code. It is
never the whole case for a block, and a decision record that tried to be one is
refused at construction.

## The Order, and Why

```
protected or management?           -> ALLOW
can we act on this address at all? -> ALLOW
is the data good enough?           -> ALLOW
is the evidence enough?            -> ALLOW
does the cost model prefer a block,
  by a margin, under uncertainty?  -> and only then TEMP_BLOCK
otherwise                          -> ALLOW
```

The cheap, certain refusals come first, not for speed, for honesty. Asking
"what does the model think?" about a management address or a CDN edge is asking a
question whose answer must not matter, and a system that computes it anyway will
eventually find a way to use it.

## Every Gate

| Gate | Refused with | Why |
| --- | --- | --- |
| protected / management | `PROTECTED_SOURCE`, `MANAGEMENT_NETWORK` | locking out an operator is the one unrecoverable failure |
| identity confidence | `IDENTITY_UNCERTAIN` | blocking the wrong machine is worse than not blocking |
| network enforceable | `NOT_NETWORK_ENFORCEABLE` | the address belongs to a proxy carrying everyone else |
| enforcement scope | `SHARED_PROXY_RISK` | same, one step earlier |
| data quality | `INSUFFICIENT_DATA_QUALITY` | incomplete features are not a weak case, they are no case |
| observations | `INSUFFICIENT_OBSERVATIONS` | acting on a handful of events is acting on noise |
| observation time | `INSUFFICIENT_OBSERVATION_TIME` | so is acting on two seconds of them |
| signal diversity | `INSUFFICIENT_SIGNAL_DIVERSITY` | one family is a misconfigured probe as often as an attack |
| behavioural evidence | `MODEL_ONLY_EVIDENCE` | two models agreeing about one vector is one opinion |
| out of distribution | `HIGH_OOD` | the classifier knows less here, so it counts for less |
| model health | `MODEL_UNHEALTHY` | a degraded model advises; it does not drive |
| drift | `DRIFT_DEGRADED` | population health, not source guilt |
| model agreement | `MODEL_DISAGREEMENT` | disagreement is uncertainty, not the maximum of the two |
| uncertainty | `UNCERTAINTY_HIGH` | a point estimate is not enough to act on |
| cost | `COST_ALLOW_PREFERRED` | expected loss favours allowing |
| margin | `MARGIN_NOT_MET` | a noise-sized advantage is not a reason |
| profile permission | `NETWORK_BLOCK_NOT_PERMITTED` | some routes are never network-blocked at any probability |
| assumptions | `ASSUMPTION_FAILED` | something the decision needed did not hold |
| enforcement health | `ENFORCEMENT_UNHEALTHY` | a rule that cannot be verified is not a rule |
| PolicyGuard | `POLICY_GUARD_REFUSED` | PolicyGuard sits above this and its refusal is final |
| existing lease | `EXISTING_BLOCK_LEASE` | this source is already blocked |
| circuit breakers | `MASS_BLOCK_FREEZE`, `FALSE_POSITIVE_FREEZE`, `TECHNICAL_FREEZE`, `BLOCK_BUDGET_EXHAUSTED` | see [AUTONOMOUS_FAILURE_RECOVERY.md](AUTONOMOUS_FAILURE_RECOVERY.md) |
| autonomy switch | `AUTONOMY_DISABLED` | it is simply off, and the record says so plainly |

Gates do not return early. Every reason not to block is collected, so an ALLOW
answers "why not?" completely rather than naming whichever gate was checked
first.

## Signal Families

Ten families, and a feature belongs to exactly one:

`NETWORK_RATE`, `PORT_BREADTH`, `PROTOCOL_BEHAVIOR`, `HTTP_DISCOVERY`,
`AUTH_BEHAVIOR`, `TIMING`, `PERSISTENCE`, `DECEPTION_INTERACTION`,
`ML_CLASSIFIER`, `ANOMALY`.

The first eight describe what the source *did*. The last two describe what a
model *thinks*, which is a different kind of statement.

A family contributes at most once no matter how many features describe it.
`connections_60s`, `requests_60s` and `burst_10s` all say "a lot of traffic
arrived". That is one observation seen three ways, and counting it three times
is how a system talks itself into confidence it has not earned. Strength per
family is the **maximum** contributing term, never the sum.

A block needs at least 3 distinct families, of which at least 2 must be
behavioural.

## ALLOW Is Not "Benign"

ALLOW means: *this source is not currently eligible for an autonomous temporary
block.* It is not a verdict of innocence, it does not whitelist anything, and it
is never a training label. The system keeps watching, the softer actions remain
available, and the next window is judged on its own evidence.

Equally, TEMP_BLOCK is not proof of anything. A blocked source is not ground
truth, and no part of the learning pipeline may treat it as one.

## The Decision Record

Every decision (both actions) produces an `AutonomousDecisionRecord` carrying
the scope and site, a pseudonymous source identifier, the feature schema version,
MathRisk and its top contributions, web risk, the model version and whether its
output was a calibrated probability or a score, anomaly and OOD scores, drift
status, data quality, identity confidence, the signal families, persistence,
both expected losses, the cost policy version and digest, the threshold, every
safety gate, the PolicyGuard result, the action, the block TTL, and stable
reason codes.

Three validations are enforced at construction rather than documented:

1. **A block must name behaviour.** A record with `TEMP_BLOCK` and no behavioural
   reason code raises. "BLOCK because the AI score was 0.93" cannot be
   represented in this system.
2. **An ALLOW must name a reason.** Allowing is a decision, and "nothing
   happened" is not an explanation.
3. **A block carries no restraining code.** If any gate refused, the answer is
   ALLOW; a record that blocked *and* recorded a refusal would mean something
   overrode a gate, and nothing can.

Read one:

```
eye-for-an-eye autonomy explain decision.json
```

## Assumptions

Every decision relies on things that are usually true: the feature schema is
compatible, the artifact validated, the client identity is resolvable, the sample
is mature, a cost profile applies, enforcement can verify a rule, the clock has
not jumped. These are named in an `AssumptionRegistry`, checked, and recorded.

**An assumption nobody checked is not a satisfied one.** Unchecked counts as
failed where a block is concerned, and a failed assumption produces an ALLOW that
names it and the subsystem responsible.

## Hysteresis

A source already blocked inside the offence window faces the lower
`release_margin` rather than the full `decision_margin`, so a borderline source
does not flap in and out of enforcement on adjacent windows. It lowers one number
and nothing else: every other gate applies at full strength, so a repeat offender
with weak evidence is still allowed.

## Block Duration

Escalating and capped: 300s, 1800s, 7200s, 43200s, and never beyond 43200s
whatever the offence count. Offence history decays out of the window on its own.
There is no permanent ban and no value of any field that means forever.

## Timing

The decision is not on the packet path. Feature updates and MathRisk are cheap
and run per event; ONNX inference, anomaly scoring, OOD and this authority run
on a bounded interval. Drift, training and clustering never run per event.

## See Also

- [COST_SENSITIVE_POLICY.md](COST_SENSITIVE_POLICY.md)
- [DECISION_UNCERTAINTY.md](DECISION_UNCERTAINTY.md)
- [AUTONOMOUS_SAFETY_INVARIANTS.md](AUTONOMOUS_SAFETY_INVARIANTS.md)
- [AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md)
