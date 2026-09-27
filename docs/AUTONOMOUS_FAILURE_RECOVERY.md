# Autonomous Failure and Recovery

What happens when something breaks, and how the system comes back without being
asked.

## The Failure That Matters

Not a bad block: a *correlated* bad block. A model that degrades, a feature
pipeline that starts emitting zeros, a NAT that suddenly carries a conference's
worth of traffic: none of these produce one mistake. They produce the same
mistake against every source at once, each one individually well-supported by
the evidence, because the evidence itself is what went wrong. By the time a
person notices, the site is unreachable.

So there are four brakes, and they are deliberately dumb. **None of them looks at
whether a block was correct**. That judgement is exactly what has failed. They
look at rate, at share, at externally established outcomes, and at whether the
machinery underneath is working.

## The Four Brakes

### The Block Budget

Caps new autonomous blocks per minute (10) and blocks held at once (500). A rate
limit on the system's own certainty. Exceeding it is `ENFORCEMENT_DEGRADED`:
no new blocks until the window moves on.

### The Mass-block Circuit Breaker

Watches the *share* of recently seen sources under an autonomous block. Expecting
a fraction of a percent and seeing a fifth of everything is not a discovery, it
is a fault. Default ceiling 2% of recent sources, evaluated only once at least
200 distinct sources have been seen, three blocks out of five sources is not a
60% catastrophe.

**Shadow decisions count towards the share.** §51 is about the distribution of
decisions, and a model that *would have* blocked a fifth of the Internet is
exactly what shadow mode exists to catch before anybody promotes it.

### The False-positive Circuit Breaker

Opens when trusted evaluation shows benign sources being blocked: more than 1.0
false blocks per 1000 benign sources, over at least 500 trusted benign examples.

The word carrying this one is *trusted*. It accepts outcomes only from a
controlled lab scenario, a signed PCAP sidecar label, a deterministic harness or
a reviewed evaluation. **Feeding it the system's own decisions is refused
outright**, not discouraged. A false-positive breaker trained on its own blocks
would confirm whatever it was already doing.

With no trusted outcomes it reports `GROUND_TRUTH_UNAVAILABLE`, not zero. Zero is
a measurement; the absence of one is not.

### The Technical Circuit Breaker

Not statistical at all. A corrupt artifact or a jumped clock does not make the
next decision *less accurate*. It makes it meaningless. Named faults:

`model_invalid`, `feature_schema_mismatch`, `data_quality_unavailable`,
`identity_resolver_failed`, `firewall_verify_failed`, `storage_corruption`,
`site_isolation_failure`, `clock_anomaly`, `model_registry_inconsistent`.

## AUTONOMOUS_SAFE_MODE

When any breaker opens, the runtime enters safe mode. In safe mode:

- **no new autonomous blocks**
- MathRisk continues
- observation, features, correlation and the web sensor continue
- storage continues if healthy
- **existing temporary blocks expire normally**

Freezing means stopping new mistakes, not holding old ones. A safe mode that also
held existing blocks would turn a transient fault into an outage.

## Degrading

Immediate and automatic. The moment a fault is recorded the runtime is in
`SAFE_OBSERVE`, because the alternative is acting on a broken measurement. No
administrator is waited for, and none is needed.

## Recovering

Automatic too, and deliberately slow. Three conditions, all of them:

1. **The fault is gone.** Every technical fault resolved, every breaker
   permitting.
2. **The cooldown has passed.** 300s for a breaker, 900s for the runtime by
   default. A breaker that closed the instant a metric dipped back over its
   threshold would flap, and the measurement that degraded the system is usually
   the same one that just wobbled.
3. **The readiness gate passes again.** Not the gate that passed at startup. A
   fresh one, now.

The sequence, end to end:

```
problem detected
  -> block freeze
  -> rollback candidate or model, if the fault was a model fault
  -> reload LAST_KNOWN_GOOD
  -> doctor checks
  -> continue in shadow
  -> health returns
  -> cooldown elapses
  -> readiness gate passes
  -> autonomous decisions resume
```

No step in that chain needs a person.

## What No Failure May Cause

§161, asserted by `tests/test_p15_runtime.py`:

- a random block
- a permanent block
- a firewall flush
- a website outage
- cross-site corruption

Each failure-injection test breaks one thing and asserts two properties
together: the system keeps running, **and** it does not block. Either alone is
worthless. A system that survives a corrupt model by carrying on and blocking
people has failed in the expensive direction; a system that stops working is not
protecting anything.

## Reading the State

```
eye-for-an-eye autonomy status
```

shows the mode, the brake state, the block budget, each breaker with its reason
and cooldown, and the false-block rate (or `GROUND_TRUTH_UNAVAILABLE`).

Metrics, all bounded, no address or path as a label:

```
autonomous_decisions_total
autonomous_allow_total
autonomous_block_total
autonomous_block_suppressed_total
block_budget_utilization
block_circuit_breaker_total
autonomous_safe_mode_total
```

## Stopping It by Hand

`[autonomy] enabled = false` and a restart, which stops new decisions; or
`[enforcement] host_enabled = false` and a restart, which keeps the decisions
and stops the blocking. Existing blocks keep expiring on their own, and the
privileged helper's `cleanup` verb releases them all now. Local, no cloud in the
path.

There is no command that disarms a sensor already running: this page used to
document `eye-for-an-eye autonomy disable`, which has never existed.
[AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md) has the three ways that do work.

## See Also

- [AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md)
- [MODEL_SAFE_MODE.md](MODEL_SAFE_MODE.md): the model-level equivalent
- [AUTO_ROLLBACK.md](AUTO_ROLLBACK.md)
- [SHADOW_MODE.md](SHADOW_MODE.md)
