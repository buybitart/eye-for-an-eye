# Generalization Policy

What Eye for an Eye claims to generalise to, what it does not, and what counts
as a failure. Written before the P15.3 locked benchmark existed, so that
acceptance is a standard rather than a description of whatever happened.

## What Generalization Means Here

**Reasoning from behavioural primitives rather than from remembered scenarios.**

A system that has learned "traffic shaped like `scan/sequential/50-ports`" has
memorised a generator. A system that has learned "many distinct ports, in order,
on one host, sustained" has learned something that exists outside this project's
test fixtures and will still be true of a tool nobody has written yet.

The test of the difference is a behaviour family no fitted component has seen:
not a new seed, not a new source, a **new composition of primitives**. If
detection survives that, the system is reasoning. If it does not, it was
matching.

Three things this explicitly does **not** claim:

* **Generalisation to the Internet.** Every corpus is synthetic and produced by
  this project's own generators. Holding a family out measures generalisation
  across compositions of the primitives those generators implement. It does not
  measure generalisation to real traffic, and no result in any report may be
  read that way.
* **Detection of behaviour the sensor cannot observe.** See below.
* **Detection of novel behaviour that shares no primitive with anything known.**
  A deterministic engine reasons from the evidence families it has. A genuinely
  new phenomenon needs a new observation, not a better weight.

## Behaviour Classes in Product Scope

Eye for an Eye protects **one host**, from **one sensor**, watching **network
and web traffic arriving at that host**. In scope:

| Class | Example | Observable because |
| --- | --- | --- |
| port breadth | sequential, randomised, slow and bursty scans | destination ports reach this host |
| address breadth | one service across several addresses of this host | those addresses are this host's |
| protocol misuse | a request shaped for another service | the request arrives here |
| repetition | the same probe, repeatedly | the payload digest is computed here |
| authentication automation | credential-shaped requests | the request shape is visible |
| persistence | the same source over a long window | correlation state is per source |
| deception interaction | contact with a decoy this host runs | the decoy is ours |
| rate | volume of connection attempts | they arrive here |

Out of scope, by architecture:

| Class | Why |
| --- | --- |
| breadth across hosts this sensor does not protect | the packets never arrive |
| activity inside an authenticated session | the sensor reads traffic shape, not application state |
| anything requiring correlation with another organisation's telemetry | there is no such feed and there will not be one |
| volumetric denial of service | stated in `LIMITATIONS.md`; a packet filter on the target is the wrong place to solve it |

## Observability Classes

`docs/BEHAVIOR_OBSERVABILITY.md` classifies every scenario family. The classes
and their consequences:

**`IN_SCOPE_OBSERVABLE`**: the evidence reaches the sensor and the feature
schema can represent it. Detection failure is a real generalisation failure. It
must be fixed in the evidence and may never be reclassified because it turned
out to be hard.

**`IN_SCOPE_PARTIALLY_OBSERVABLE`**: some evidence is unavailable by
construction. A truncated capture has no payload, so payload digests, credential
shapes and protocol-family classification cannot contribute. Evaluated only on
the signals that survive.

**`OUT_OF_SCOPE`**: the behaviour happens where this sensor is not. Documented,
never faked. Zero detection is the correct result and not a failure.

**`INVALID_TEST_SCENARIO`**: the label cannot be justified. None is currently
so classified.

## Expected Action Per Class

Detection and enforcement are separate questions (§54), and a family can be
correctly recognised as suspicious without being eligible for a network block.

| Class | Expected action |
| --- | --- |
| `IN_SCOPE_OBSERVABLE`, malicious, `TEMP_BLOCK_ELIGIBLE` | `TEMP_BLOCK` when every safety gate is satisfied; otherwise a softer action and a record saying which gate refused |
| `IN_SCOPE_PARTIALLY_OBSERVABLE`, malicious | `TEMP_BLOCK` is permitted on the surviving evidence, and its absence is not by itself a Gate C failure |
| `OUT_OF_SCOPE` | no action expected |
| benign, any class | `ALLOW`. A false `TEMP_BLOCK` is the most expensive error this system can make |
| any class, `payment_webhook` profile | **never** a network block, at any probability. Policy outranks arithmetic, and its absence is not a detection failure (§42, §62) |
| any class, client behind a proxy or CDN | never a network block. The address belongs to infrastructure carrying everyone else |

## What Constitutes a Gate C Failure

Gate C fails if **any** of these is true.

1. **A critical in-scope observable family, eligible for `TEMP_BLOCK`, is
   detected on zero sources.** Aggregate recall may not hide it. "Critical" means
   malicious and `IN_SCOPE_OBSERVABLE`: every malicious family in the corpus
   qualifies unless `BEHAVIOR_OBSERVABILITY.md` classified it otherwise before
   the test.
2. **Unseen-family recall is zero** while seen-family recall is not. That is the
   signature of memorisation, and it is the thing this cycle exists to rule out.
3. **Probability semantics are wrong**: an uncalibrated quantity reaching the
   cost arithmetic, a calibrator applied to a model it was not fitted against, a
   non-finite value producing an action.
4. **Generalisation is not measured**: a report that omits the seen/unseen
   split, the per-family table or the worst family has not demonstrated
   anything, whatever its headline.
5. **Leakage is found** and not excluded: a locked-test row that also appears in
   a corpus something was fitted on, or a source group spanning splits.
6. **Runtime parity fails** for the production probability path.

Gate C does **not** fail because:

* supervised ML remains auxiliary. The product needs a correct decision system,
  not a classifier with authority (§79). A calibrated deterministic path that
  satisfies this policy is a pass.
* an `OUT_OF_SCOPE` family is undetected.
* a `TEMP_BLOCK`-ineligible profile produced no blocks.
* recall is low. There is no recall target here, and inventing one after seeing
  a result would be the same error in the opposite direction. What is required is
  *non-zero detection of each critical family*, not a number.

## What Constitutes a Gate E Failure

Unchanged from P15.2, and P15.3 may not trade one gate for the other:

* block precision or false blocks per 1000 benign not measured on trusted ground
  truth;
* a degenerate decision: allow-all or block-all;
* hard negatives untested;
* uncertainty unreported, or observed zero reported as proven zero.

## The Rule That Makes This a Policy

Acceptance criteria written after a result are not criteria. If the locked test
shows a family at zero detection, the only permitted responses are to fix the
evidence and build a new test, or to record Gate C as FAIL. Reclassifying that
family as out of scope after the fact is forbidden, and a reviewer should treat
any such reclassification in a later cycle as a finding in itself.

## See Also

- [BEHAVIOR_OBSERVABILITY.md](BEHAVIOR_OBSERVABILITY.md): the per-family classification
- [LIMITATIONS.md](LIMITATIONS.md)
- [COST_SENSITIVE_POLICY.md](COST_SENSITIVE_POLICY.md): the cutoff this policy does not touch
- [../reports/P15_2_FINAL_REPORT.md](../reports/P15_2_FINAL_REPORT.md): the result that made this cycle necessary
