# Decision Uncertainty

A point estimate is not enough to act on, and this page says what is done instead.

## The Problem

A malicious probability of 0.98 from forty observations of a source unlike
anything the model was trained on, with a sensor dropping events, is not the same
claim as 0.98 from four thousand observations of familiar traffic on a healthy
model. A decision procedure that treated them identically would be acting on the
arithmetic while ignoring everything that determines whether the arithmetic means
anything.

## The Six Components

Each is in [0, 1], where 0 means no reason for doubt.

| Component | Raised by |
| --- | --- |
| `uncalibrated` | the classifier's output is a score, not a probability |
| `out_of_distribution` | the sample is outside what the model was fitted on |
| `data_quality` | missing features, immature windows, a sensor dropping events |
| `model_health` | drift, inference failures, a degraded artifact |
| `sample` | too few observations to say much |
| `disagreement` | models that disagree materially |

They combine as a **bounded sum**, not a product. Doubts add up, and a product
would let one perfect component wash out four bad ones.

**An unmeasured signal adds doubt rather than being read as fine.** Every input
may be `None`, meaning "not measured", and every `None` raises uncertainty. A
measurement nobody took is not a good measurement.

## The Conservative Estimate

Two adjustments, both in the direction of allowing:

**1. Shrinkage towards the prior.**

```
p_shrunk = (1 - u) * p + u * prior
```

where `u` is the total uncertainty and `prior` is 0.02. At full uncertainty the
estimate is the base rate, which is the honest answer when nothing is known. The
prior is deliberately low: the rare class is rare, and an estimate that collapsed
towards "probably malicious" when it knew nothing would be the opposite of
conservative.

**2. A sampling-width subtraction.** A Wilson-style lower-bound width, large with
few observations and shrinking as they accumulate. With no observations at all the
width is the whole range, which collapses the estimate to zero.

The result is used for the **block** side of the comparison, which means
uncertainty always argues for allowing and never for blocking. It is monotone:
more uncertainty never produces a higher number, and there is a test for that.

## The Sample Size That Width Was Computed Over Was the Wrong One

P15.2 measured what this procedure could reach, and the answer was: not enough
to act on, ever.

A Wilson correction bounds a proportion estimated from `n` observations. The
proportion here is P(malicious | evidence). Its sample size is the number of
*calibration examples* supporting that estimate (thousands. The width above was
computed over `observations`, the number of packets in the window) tens. The
interval was two orders of magnitude too wide, and three quarters of all windows
were floored at exactly zero by it.

The shrinkage compounded that. At a probability of exactly 1.0, on a mature
window with the total uncertainty this project's own corpus produces, the
conservative estimate reaches **0.854**, against a `public_website` cutoff of
0.9756 and an `api` cutoff of 0.9877. The gates permit a block at total
uncertainty 0.60, where the same estimate cannot exceed **0.412**. The
uncertainty budget and the cost cutoffs were chosen independently and were
arithmetically incompatible: no evidence, however strong, could clear both.

Calibration alone would not have fixed this, which is why it is written down
separately from the units error rather than folded into it.

## The Bound a Calibrated Decision Uses Instead

A calibrator built by `decision/calibration.py` carries **conservative knots**: a
monotone Wilson lower bound on P(malicious | score), estimated per score band
over the calibration data's own examples. Same correction, right sample size.

```
p_lower = wilson_lower(positives in this band, examples in this band)
```

The bands are equal-count rather than equal-width, because scores pile up near
zero on this kind of evidence and equal-width bands would estimate the
interesting end of the range from a handful of points. The result is made
non-decreasing by a running maximum: a dip would say that more evidence of
maliciousness supports a weaker claim.

Now the name is earned. This *is* a Wilson score interval on a real binomial
proportion, and the report says so without hedging. What it is not is a
statement about a source the calibration data never resembled, which is what
the OOD gate, the diversity gate and the maturity gate are for.

An artifact with no conservative knots produces no autonomous block. A point
estimate is not a reason to deny a stranger a service.

## Naming Each of Them Correctly

Two bounds, two different claims, and they must not borrow each other's
authority.

The **shrinkage** is *not* a credible interval and not a frequentist confidence
bound. It is an *empirical lower estimate* built from two documented,
deliberately crude adjustments, neither of which has a distributional guarantee
behind it. Calling it a confidence interval would be borrowing authority the
implementation has not earned. It is conservative in direction, which is the
property that matters on a path that cannot block anyway.

The **calibration bound** is a Wilson score interval on a binomial proportion,
and that name is accurate: a real proportion, a real sample size, the standard
interval. What it bounds is sampling error in the calibration data. It is not a
statement about a source that data never resembled, and nothing here should be
read as one.

## Which Bound Applies When

| Situation | Bound used | Can it block? |
| --- | --- | --- |
| no calibrator | the shrinkage above | no, `CALIBRATION_UNAVAILABLE` gates first |
| calibrator, no conservative knots | the shrinkage above | in practice no |
| calibrator with conservative knots | the calibration Wilson bound | yes, if every other gate agrees |

The shrinkage was not removed. It still governs every uncalibrated decision, and
every uncalibrated decision is refused before the arithmetic is consulted, so
nothing was weakened: a better-founded bound was added to a path that previously
had none. Every record carries both numbers and a `bound_source` field saying
which one the decision rested on.

The same care applies to the offline metrics. `bootstrap_interval` produces a
**percentile bootstrap interval** over the evaluation rows, with an explicit
seed so a report is reproducible. It is named as an empirical interval from
resampling, not as an exact frequentist guarantee.

## When the Classifier Is Not Calibrated

A score is not a probability. If the classifier is uncalibrated, feeding its
output into an expected-loss calculation as though it were one is a category
error that produces confident nonsense.

So: `calibrated` is False, the deterministic mathematical engine carries the
estimate, the classifier's opinion survives only as a bounded fusion share, one
signal family and one corroborating reason code, and the record says which
happened, in the `calibrated` field and the `CALIBRATION_UNAVAILABLE` reason
code.

Calibration, where it is fitted, uses validation data. Never test data, and never
the data a threshold was chosen on.

## Expected Loss

```
LossAllow = p * C_FN
LossBlock = (1 - p) * C_FP
```

with `p` always the conservative estimate, so the comparison is made against the
version of the evidence least favourable to blocking.

`block_robustly_preferred` (the only arithmetic result that can lead to an
action) requires all three of:

1. `LossBlock < LossAllow`
2. the relative advantage is at least `decision_margin`
3. the conservative probability is at least the cost profile's cutoff

And everything that passes that still has to clear evidence diversity, data
quality, identity confidence, model health, the block budget and PolicyGuard.

## Robust Statistics

Security data is heavy-tailed. A high value alone is not malicious, and
`mean ± 3σ` is not a general definition of an outlier, on a distribution with a
long tail it fires constantly on legitimate traffic.

Where the project summarises a distribution it uses quantiles and bands rather
than a mean and a standard deviation: the OOD reference is built from p01, p05,
p95 and p99 with an observed range, and a sample is placed in a band rather than
scored against a Gaussian. Outlier meaning depends on the distribution, and the
distribution is the site's own.

## See Also

- [COST_SENSITIVE_POLICY.md](COST_SENSITIVE_POLICY.md)
- [AUTONOMOUS_DECISION.md](AUTONOMOUS_DECISION.md)
- [SCIENTIFIC_BASIS.md](SCIENTIFIC_BASIS.md)
- [CONFIDENCE.md](CONFIDENCE.md): evidence and confidence kept apart
- [DISTRIBUTION.md](DISTRIBUTION.md): the OOD reference and its bands
- [DRIFT.md](DRIFT.md): population drift and model health
