# Cost-sensitive policy

Why the cutoff is 0.976 and not 0.5.

## 0.5 is not a decision boundary

It is the number people reach for when they have not asked what a mistake costs.
A classifier outputs 0.5 at the point where the two classes are equally likely,
which would be the right place to act only if the two mistakes were equally bad.
In security they are not comparable, and on a public website they are not close.

**Blocking somebody who did nothing wrong** denies a real person a real service.
They cannot tell you, cannot appeal, and in most cases will not come back. It
lands hardest on people using unusual networks, unusual clients, shared
addresses and assistive technology — that is, on exactly the people a
distribution-based system finds unusual.

**Allowing a scanner to continue** means it continues, against a system that is
already rate-limiting it, already challenging it where the web layer is
deployed, and already watching it.

Those are different sizes of wrong. The cutoff follows from that, not from a
round number.


## The cutoff is a probability, and twice it was not given one

Precise history, because it is useful engineering history rather than an
embarrassment.

**P15** compared `p*` against `MathRisk`. `p*` is a probability of maliciousness;
`MathRisk` is an uncalibrated heuristic score on its own scale. Both are floats
in [0, 1]. The comparison had no meaning in either direction, and it survived
review because nothing at the call site said which quantity was which.

**P15.1** replayed a trusted labelled corpus through the whole system and found
the consequence: the system blocked nothing at all, on any scenario. It disabled
autonomous blocking on an uncalibrated estimate rather than lowering the cutoff
to make blocks appear — `CALIBRATION_UNAVAILABLE` became a hard gate.

**P15.2** supplies the missing quantity. A validated calibrator maps a score to
P(malicious | score) and carries a Wilson lower bound over its own fitting
sample; the cost comparison uses that bound. `decision/scores.py` gives every
number on the path a type, and the one function that needs a probability accepts
only the type that is one — a bare float included, because the P15.1 bug was a
float arriving from a fallback branch with nothing to mark it.

None of the numbers on this page changed in any of those cycles.

## The cost matrix

```
                    actual benign     actual malicious automation
ALLOW                     0                      C_FN
TEMP_BLOCK              C_FP                       0
CHALLENGE           challenge cost           challenge cost
RATE_LIMIT          rate-limit cost          rate-limit cost
```

Correct outcomes cost zero, which keeps the arithmetic simple and the two
numbers that matter visible. The intermediate actions are not free — a challenge
asks a real person to wait — because an expected-loss calculation that treated
them as costless would reach for them constantly.

## The costs are weights, not money

`C_FN = 1.0` is the reference unit throughout. Every `C_FP` reads as *"this many
times worse than letting one automated source carry on for one block interval"*.

Nothing here is a currency value, and none of it is derived from measurement.
Inventing a monetary figure would give false precision to what is a judgement
about a particular site — the kind of number that survives three copy-pastes and
arrives somewhere as a fact.

## The cutoff

From the simplest cost matrix:

```
p* = C_FP / (C_FP + C_FN)
```

## The shipped profiles

| Profile | C_FP | Cutoff | Network block | For |
| --- | --- | --- | --- | --- |
| `public_website` | 40 | 0.9756 | yes | a site with real human readers; the default |
| `api` | 80 | 0.9877 | yes | programmatic clients; no browser challenge to fall back to |
| `payment_webhook` | 500 | 0.9980 | **never** | payment callbacks, health checks, anything whose failure is an incident |
| `admin` | 8 | 0.8889 | yes | an administrative interface with a small known client set |
| `honeypot` | 2 | 0.6667 | yes | a deception service with no legitimate public clients |

Every number is a judgement about a *kind* of site, made without deployment data.
An operator who changes one is exercising their own judgement, not correcting an
error.

`payment_webhook` is the one worth pausing on. Its `network_block_permitted` is
false, so it refuses an autonomous network block *at any probability*, including
1.0. The cost of breaking a payment integration is not a number you trade against
reconnaissance; observation and rate limiting remain.

## The cutoff is a floor, not a decision

Reaching `p*` means the arithmetic no longer favours allowing. That is a
necessary condition and nowhere near a sufficient one. Everything in
[AUTONOMOUS_DECISION.md](AUTONOMOUS_DECISION.md) still applies afterwards, and
each gate can refuse.

Two more things stand between the cutoff and an action:

**The margin.** `decision_margin` (0.25 by default) is how much better blocking
has to be, as a fraction of the larger loss. A small advantage is noise.

**The conservative estimate.** The comparison is made against a deliberately
pessimistic reading of the probability, never the optimistic one. See
[DECISION_UNCERTAINTY.md](DECISION_UNCERTAINTY.md).

## What this means in practice

On the default `public_website` profile, an autonomous network block requires a
calibrated probability near 0.999, several hundred observations, complete data,
an in-distribution sample, a healthy undrifted model and four independent
evidence families — because a conservative estimate must still clear 0.9756
after uncertainty has been subtracted from it.

**This makes an autonomous network block on a public website a rare event by
construction.** That is the arithmetic doing what it was asked to do, not a bug
to be tuned away. The ordinary load is carried by the softer actions: observe,
watch, challenge, rate limit. Blocking is what happens when the evidence is
overwhelming and cheap to be wrong about.

## Per-scope profiles

```toml
[autonomy]
default_cost_profile = "public_website"

[autonomy.cost_profiles]
"SITE:payments" = "payment_webhook"
"SITE:api" = "api"
"SITE:admin" = "admin"
```

An unmapped scope gets the default, and the default is the most protective of the
general-purpose profiles rather than the most permissive: a site nobody
configured is a site nobody thought about.

## Nothing learned can rewrite the costs

The cost model is operator configuration. No training job, no governance
decision, no model artifact and no runtime component writes to it. A component
that could adjust the price of its own mistakes would be grading its own work.

Every decision record carries the cost policy version *and a digest of its
contents*, so a decision taken under the old numbers stays identifiable. "Why was
this blocked?" is asked weeks later, and the answer depends on what a false block
was deemed to cost at the time.

```
eye-for-an-eye autonomy policy
```

## See also

- [AUTONOMOUS_DECISION.md](AUTONOMOUS_DECISION.md)
- [DECISION_UNCERTAINTY.md](DECISION_UNCERTAINTY.md)
- [SCIENTIFIC_BASIS.md](SCIENTIFIC_BASIS.md)
