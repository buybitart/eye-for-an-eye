# Site Baselines

A baseline is a statistical description of one site's ordinary traffic: how
fast, how broad, how many errors, which methods.

It exists so that "unusual" can mean something different on an API than on a
blog, without anyone training a model per website.

## The First Day Is Not Normal

The tempting shortcut is to watch a new site for a day and call whatever it saw
normal. It is wrong for one reason: **attackers are present during the first
observation too.** Every scanner probing the site while the baseline is being
built gets recorded as ordinary, and the finished baseline is precisely blind to
the traffic it should catch.

So a baseline never becomes active by the passage of time. It is built as a
candidate, and something has to accept it.

## States

| State | Meaning |
| --- | --- |
| `MISSING` | no baseline exists for this site |
| `LEARNING` | a candidate is being built and does not have enough data |
| `VALIDATING` | a candidate is complete and waiting for a decision |
| `ACTIVE` | in use |
| `STALE` | in use, but old enough to be trusted less |
| `DEGRADED` | in use, with a known problem |

While a site is `MISSING` or `LEARNING`, the answer to "is this unusual?" is
`INSUFFICIENT_DATA`. Not "no", which nobody checked. Not "yes", which would make
every visitor to a new site look like an attack.

## Enough Data

A candidate needs at least **200 windows** from at least **20 distinct
sources**.

The second number matters as much as the first. Two hundred windows from one
client describe that client's habits, not the site's traffic.

## Where the Data Came From

Recorded, never inferred:

| Provenance | Confidence | Meaning |
| --- | --- | --- |
| `lab` | 1.0 | generated in a controlled lab |
| `pcap` | 0.9 | a reviewed capture |
| `reviewed_shadow` | 0.8 | production traffic a person looked at |
| `observed` | 0.5 | production traffic nobody checked |

`observed` is usable and it is labelled. A baseline built from it carries a note
saying nobody has confirmed an attacker was absent, because **no alert is not
the same as benign**.

## The Active Baseline Does Not Drift

New traffic is never folded into the active baseline. That is the same poisoning
problem as training on your own decisions: an attacker applying pressure slowly
moves the definition of normal towards their own behaviour, and nothing looks
wrong while it happens.

Instead:

```
production statistics  →  candidate  →  comparison  →  activation
```

Activation is a deliberate act. Before it, you get a comparison against the
current baseline, and a candidate much wider than the active one is flagged:
widening the definition of normal is exactly how a baseline is poisoned.

## Versioning

Every baseline has a version and a content digest. The digest follows the
content, not the name, so two baselines can be compared without trusting what
they were called.

Stored: quantiles (p50, p90, p99, max, mean), sample count, source count, time
range, provenance. Not stored: individual observations. A baseline is six
numbers per statistic, not a copy of your traffic.

## Ageing

An active baseline older than thirty days becomes `STALE`. It is still usable
and it is trusted less. Sites change: a redesign, a new client, a campaign.

## Commands

```bash
eye-for-an-eye sites baseline main
eye-for-an-eye sites drift main
```

Drift is measured against **this site's** baseline. Another site's traffic
changing does not make this site drifted.

## What a Baseline Is Not

Being outside a baseline is not evidence of an attack. It means this site is
doing something it does not usually do, which happens for many innocent reasons
: a launch, a link from a popular page, a new integration. It is one input among
several, and it is never a label.
