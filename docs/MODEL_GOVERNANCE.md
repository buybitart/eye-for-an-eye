# Model governance

The precise version of [AUTO_PROMOTION.md](AUTO_PROMOTION.md). This page is for
someone reviewing the design or reading the code.

## The claim

Automatic promotion here is not a model selecting itself. It is a deterministic
policy accepting an artifact after a fixed list of named gates, on evidence
produced by something other than the artifact.

If that claim is false anywhere, the feature is not safe, so the rest of this
page is the places it could be false and what stops it.


## A model package includes its calibrator, or it is not a package

§87 and §88. A classifier's raw output is a score. What the decision path needs
is a probability, and the thing that turns one into the other is a separate
artifact fitted against *that* model's scores.

So a promotable package is five things together: the classifier, its calibrator,
the feature contract, the reference distribution and the manifest. Promote the
model alone and the calibrator silently keeps mapping the old model's scores —
every number it emits wrong in a way that looks entirely reasonable.

The artifact carries `model_version` and `Calibrator.calibrate` refuses a
mismatch by returning nothing, which the decision path reads as
`CALIBRATION_UNAVAILABLE` and therefore as "no autonomous block". A refusal, not
an exception: the decision path must degrade, never crash.

A calibrator fitted on `MathRisk` is the one exception, and it is a property of
the quantity rather than a shortcut. `MathRisk` is deterministic and has no
weights that can be retrained under its calibrator, so its artifact declares an
empty `model_version` and `requires_model` says so.

Artifacts are JSON — two floats for a sigmoid, bounded numeric knots for an
isotonic map — validated on load for finiteness, range, monotonicity and digest.
Nothing unpickles anything. A calibrator is a thing production reads from disk,
and a file format that can execute is not one to read from disk.

## Four authorities

| Authority | May | May not |
| --- | --- | --- |
| Training | create a candidate | judge it, promote it, or touch the registry pointer |
| Evaluation | measure a candidate | decide what the measurements mean |
| Promotion | choose which validated artifact is ACTIVE | change what an ACTIVE model is allowed to do |
| Enforcement (`PolicyGuard`) | decide what evidence may cause | choose which model provides it |

`eye_for_an_eye/governance/` is the third. It cannot import the registry, the
firewall, `subprocess` or `os` — checked by a test that parses the module rather
than reading its prose, because a promise about imports that nothing verifies is
a promise about the past.

## The artifact cannot influence its own promotion

Three structural facts, in order of how much they carry.

**The policy is a frozen value the model never sees.** `GovernancePolicy` is a
frozen dataclass built from configuration. No code path computes a threshold from
model output. There is no tuning, adaptive budget or learned gate anywhere in
this package, and §87 keeps policy tuning out of this stage entirely.

**Manifest claims are metadata, not evidence.** A manifest asserting
`precision = 1.0` establishes nothing. Every quality number the engine reads
comes from an evaluation report produced independently, and the fields that come
from the manifest — schema version, scope, declared hash — are claims the engine
*verifies* rather than accepts.

**The engine returns a record and changes nothing.** `assess()` is pure with
respect to the system. Activation is a separate authority that accepts only a
record whose every blocking gate passed. A bug in the gates can refuse a good
model; it cannot promote a bad one.

## Four verdicts, kept distinct

| Verdict | Means | Why it is its own answer |
| --- | --- | --- |
| `ELIGIBLE` | every gate passed, and gates needing ground truth had it | — |
| `NOT_ELIGIBLE` | a gate failed on the evidence available | a judgement was made |
| `NEED_MORE_DATA` | no gate failed; a gate needing ground truth lacked it | **the question was not answered.** Collapsing this into NOT_ELIGIBLE teaches an operator to read "we could not tell" as "it regressed"; collapsing it into ELIGIBLE lets unlabelled traffic authorise a promotion |
| `QUARANTINED` | the artifact is not what it claims to be | not a quality trade-off. A bad hash is not a metric that can be balanced against a good one |

## The order gates are evaluated in

This is a safety property, not an implementation detail.

```
integrity     → is this artifact what it claims to be?      failure ⇒ QUARANTINED
compatibility → does it fit the system that will run it?
health        → does it work?
governance    → are we allowed to change anything now?
sufficiency   → is there enough evidence for this conversation?
benign safety → does it harm more ordinary visitors?
security      → does it still catch what the current model catches?
```

Integrity outranks every metric: a corrupt artifact with perfect numbers is
quarantined. A real regression outranks a missing measurement: "we could not
measure X" never excuses "Y regressed".

Benign safety is evaluated before security quality and carries the tightest
budgets in the policy. A candidate that catches more scanners while blocking more
ordinary visitors is not an improvement, and the visitors it blocks are
disproportionately people on unusual networks, unusual clients and unusual
schedules — the ones least able to get a block lifted.

## Ground truth

Gates that make a claim about quality read `trusted_outcomes` and nothing else.
Trusted means controlled lab, trusted labelled capture, reviewed shadow, or a
trusted fixture. Unlabelled shadow statistics can establish health, stability,
compatibility and how *different* two models are. They cannot establish that one
of them is more often right, at any volume. Five million unlabelled feature
vectors produce `NEED_MORE_DATA`, and there is a test that says so.

## Scope

Every promotion names `GLOBAL` or `SITE:<site-id>`. Never ambiguous, never
inferred.

Site scope is the preferred first target because its blast radius is one website.
Global scope is gated by a second switch, off by default, because the shared base
model reaches every site on the machine including ones whose operator never opted
in.

A global candidate is judged by its **worst** site, not by an aggregate (§74). An
average that improves while one small site gets much worse is exactly what an
average hides, and the small site is usually the one with nobody watching it.

Site identity remains what P12 made it: governance metadata, never a classifier
feature.

## The lifecycle

```
TRAINED → VALIDATED → SHADOW → ELIGIBLE → PENDING_ACTIVATION → GUARDED_ACTIVE → ACTIVE
                        ↑         │                                  │
                        └─────────┘                            ROLLED_BACK
                    (stale under a                                   │
                     changed policy)                            QUARANTINED
```

The transitions are a table in `governance/lifecycle.py`, not conditions spread
through the code. Three edges carry most of the weight:

- **nothing reaches `ACTIVE` except through `GUARDED_ACTIVE`.** There is no edge
  from `ELIGIBLE`, or from anywhere else. Enforced by the absence of an edge
  rather than by a rule somebody has to remember;
- **`ROLLED_BACK` leads to `QUARANTINED`, not back to `VALIDATED`.** This is
  where the promote/regress/rollback/re-promote oscillation is prevented;
- **leaving `QUARANTINED` requires an operator.** Automatic quarantine is cheap
  and reversible. Automatic release is neither.

## Policy versioning and staleness

The policy carries `model-governance-v1` *and* a SHA-256 digest of its own
contents. The version names the shape; the digest catches every threshold change,
including the one somebody forgets to mention.

Every assessment records the digest it was reached under. An assessment whose
digest does not match the current policy is stale, and a stale assessment
authorises nothing — the candidate goes back to `SHADOW` and is assessed again.
Changing a threshold cannot retroactively promote anything (§29).

## Bounds

| Bound | Default | Why |
| --- | --- | --- |
| Promotion cooldown | 7 days | churn is its own failure mode |
| Promotions per day | 2 | per installation |
| Promotions per scope per day | 1 | — |
| Concurrent promotions | 1 | activation costs memory and CPU; twenty at once is an outage |
| Consecutive failures before freeze | 3 | repeated failure means something another attempt will not fix |

## What promotion cannot do

It cannot add or remove a firewall rule. It cannot change a PolicyGuard
threshold, a challenge setting or a rate limit. It cannot delete a dataset, a
review label, a training job or an evaluation record. It cannot promote without a
rollback target. It cannot skip the guarded stages. It cannot be reached from the
read-only API, which exposes no promotion route and cannot import the registry.

## Known limits

- **No deployment evidence.** This has never run over production traffic.
- **The thresholds are not measured.** See
  [PROMOTION_POLICY.md](PROMOTION_POLICY.md).
- **Shadow evaluation cannot reproduce every production case.** That is the
  premise guarded activation exists to handle, not a gap in it.
- **Quality rollback is slow by construction.** It needs reviewed evidence, and
  review takes time. Technical rollback is fast; quality rollback is not, and
  pretending otherwise would mean rolling back on ambiguous single events.

## See also

- [AUTO_PROMOTION.md](AUTO_PROMOTION.md) — the same thing in simple English
- [GUARDED_ACTIVATION.md](GUARDED_ACTIVATION.md)
- [AUTO_ROLLBACK.md](AUTO_ROLLBACK.md)
- [MODEL_SAFE_MODE.md](MODEL_SAFE_MODE.md)
- [PROMOTION_POLICY.md](PROMOTION_POLICY.md)
- [MODEL_REGISTRY.md](MODEL_REGISTRY.md), [MODEL_PROMOTION.md](MODEL_PROMOTION.md),
  [MODEL_ROLLBACK.md](MODEL_ROLLBACK.md) — the manual lifecycle, still supported
