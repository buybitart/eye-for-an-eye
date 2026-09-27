# Scientific basis

Which idea from the literature each part of this system rests on, how this
project interprets it, where it is implemented, and — the part that matters most
— what the interpretation does not give you.

Every entry has four lines. The fourth is the honest one.

---

## Rare-class classification

**Source concept.** When one class is a small fraction of the data, a classifier
optimised for overall error learns to predict the majority class. Standard
results: accuracy is uninformative, precision and recall must be reported
separately, and PR curves are more informative than ROC curves.

**Project interpretation.** Malicious automation is the rare class on every real
website. Every evaluation reports the rare-class metrics and never accuracy
alone.

**Implemented component.** `autonomy/evaluation.py` (`DecisionMetrics`,
`usefulness`, `release_gate`), `training/evaluate.py` (`point_metrics`,
`ranking_metrics`, `threshold_table`).

**Limitation.** The prevalence in any evaluation set here is a property of that
set, not a measurement of any deployment. A site's real prevalence is unknown,
which is why precision is reported across a sweep rather than as one number.

---

## The accuracy trap

**Source concept.** On a 99.9%/0.1% split, a constant-negative classifier scores
99.9% accuracy.

**Project interpretation.** A model that never fires is useless however good its
accuracy, and so is one that fires on everything. Both are named verdicts, not
footnotes.

**Implemented component.** `usefulness()` returns `USELESS_NO_DETECTION` or
`USELESS_BLOCKS_EVERYTHING`; `release_gate()` fails either.
`tests/test_p15_science.py::TestTheAccuracyTrap` asserts the excellent accuracy
first, then the refusal.

**Limitation.** The verdict needs trusted labels. With none, it returns `UNKNOWN`
— which is honest and is also not a safety net.

---

## Confusion matrix, precision, recall, specificity

**Source concept.** Four cells; every rate is a ratio of two of them.

**Project interpretation.** The matrix is built for the **final TEMP_BLOCK
decision**, not for the classifier. A model with excellent ranking can still
produce an unacceptable false-block rate once thresholds, gates and cost profiles
have had their say.

**Implemented component.** `autonomy/evaluation.py::confusion`, `evaluate`.

**Limitation.** It measures a decision procedure against labelled examples. It
says nothing about traffic that procedure has never seen.

---

## Cost-sensitive classification and the Bayes cutoff

**Source concept.** With costs `C_FP` and `C_FN` and zero cost for correct
outcomes, the expected-loss-minimising threshold is
`p* = C_FP / (C_FP + C_FN)`.

**Project interpretation.** There is no universal threshold and 0.5 is not one.
Costs are per site and per route, owned by the operator, and expressed as
relative weights with `C_FN = 1.0` as the unit.

**Implemented component.** `autonomy/cost.py` (`CostProfile.threshold`,
`PROFILES`), `autonomy/uncertainty.py::ExpectedLoss`.

**Limitation.** The costs are judgements, not measurements. The arithmetic is
exactly as good as the numbers put into it, and this project has no deployment
data from which to derive them. Changing one is exercising judgement, not
correcting an error.

---

## Type I and Type II error

**Source concept.** A false positive and a false negative are different errors
with different consequences, and a test's design chooses which to make rarer.

**Project interpretation.** The asymmetry is the whole design. A false block
denies a real person a real service, silently and without appeal. A false allow
means a scanner continues against a system that is still rate-limiting,
challenging and watching it. Abstention resolves to ALLOW.

**Implemented component.** The gate order in `autonomy/authority.py`; the
conservative estimate used on the block side only.

**Limitation.** This makes false negatives more common than a symmetric system
would. That is a deliberate trade, and a site with a genuinely different cost
structure should say so in its cost profile rather than expect the default to
suit it.

---

## Calibration

**Source concept.** A classifier score is not a probability unless it has been
calibrated. Reliability curves, Brier score and expected calibration error
measure how far off it is; Platt scaling and isotonic regression correct it.

**Project interpretation.** A score fed into an expected-loss calculation as
though it were a probability produces confident nonsense. When calibration is
unavailable the output is named `model_score`, the deterministic engine carries
the estimate, and the decision record says which happened.

**Implemented component.** `training/evaluate.py` (reliability, Brier, ECE);
`autonomy/authority.py::_probability`; the `calibrated` field and the
`CALIBRATION_UNAVAILABLE` reason code.

**Limitation.** Calibration fitted on validation data describes that data's
prevalence. Production prevalence differs, and a calibrated probability is not
automatically transportable to a site the calibration set did not represent.

---

## Uncertainty and interval estimation

**Source concept.** A point estimate without a spread is not a basis for a
decision. Wilson intervals for proportions; the bootstrap for statistics with no
closed form.

**Project interpretation.** Runtime uses a conservative *empirical lower
estimate*: shrinkage towards a low prior in proportion to measured uncertainty,
then a Wilson-shaped sampling-width subtraction. Offline uses a percentile
bootstrap with an explicit seed.

**Implemented component.** `autonomy/uncertainty.py`;
`autonomy/evaluation.py::bootstrap_interval`.

**Limitation.** Stated plainly in the code: the runtime quantity is **not** a
credible interval and not a frequentist confidence bound. Neither adjustment has
a distributional guarantee behind it. It is conservative in direction, which is
the property the decision needs, and calling it anything more would be borrowing
authority the implementation has not earned.

---

## Class imbalance handling

**Source concept.** Class weighting, undersampling, oversampling and synthetic
minority generation each trade bias for variance differently.

**Project interpretation.** Weighting is preferred over invented rows. Any
resampling is training-split only; validation and test keep realistic
prevalence. SMOTE is not enabled by default.

**Implemented component.** `training/train_logreg.py` (class weight search),
`dataset/split.py`, the training manifest.

**Limitation.** Weighting changes the operating point, which changes what
calibration means. The two have to be evaluated together, and a weight chosen on
a lab corpus is a lab-corpus weight.

---

## Cross-validation and held-out evaluation

**Source concept.** Model selection on the same data used to report performance
produces optimistic results. Grouped splits are needed when observations are
correlated.

**Project interpretation.** Selection uses validation; the test split is locked.
Splits are grouped by source, scenario, capture, site and time, because security
observations from one run are not independent draws.

**Implemented component.** `dataset/split.py`, `training/split.py`,
`dataset/leakage.py`.

**Limitation.** Grouped splitting reduces optimism; it does not create realism. A
model evaluated only on generated scenarios has been evaluated on generated
scenarios.

---

## Generalization under distribution shift

**Source concept.** A model's error on data drawn from its training distribution
bounds nothing about its error under *shift*. The literature separates several
kinds — covariate shift, label shift, domain shift — and the one that matters
here is closest to **compositional** or **systematic** generalization: the test
distribution is built from the same primitives as the training distribution,
arranged in combinations the training distribution never contained. Random
held-out rows cannot measure it, because a random row is drawn from the same
arrangement. Only withholding whole *groups* can.

**Project interpretation.** Four instruments, each answering a question the one
before it cannot.

*Whole-family holdout.* `dataset/split.py` withholds entire scenario families
from every fitted component — model and calibrator alike — rather than
withholding runs of familiar behaviour. A system that has learned "traffic shaped
like `scan/sequential/50-ports`" has memorised a generator; one that has learned
"many distinct ports, in order, sustained" has learned something that will still
be true of a tool nobody has written yet. Only family holdout separates the two.

*Compositional holdout.* P15.3 added six families that are new *compositions* of
primitives the corpus already contained — slow pacing with port breadth and
address breadth; credential shapes without concentration; decoy contact followed
by enumeration. No new primitive and no new generator behaviour: a combination
never shown. This is the sharpest test of reasoning-versus-matching that
synthetic data can produce.

*Hard-negative holdout.* Generalization is not only detecting an attack nobody
demonstrated; it is also not blocking a legitimate client nobody demonstrated.
Three of the six new families are *benign* compositions of the same primitives,
one for each term the risk formula weights. This turned out to be the instrument
that mattered: a legitimate authenticated batch client, blocked on 21 of its 22
sources by a defect present since `math-risk-v1` and invisible to two earlier
cycles whose corpora contained no such client. A benchmark that only tests
attacks measures half of generalization and reports it as the whole.

*Predeclared acceptance.* `docs/GENERALIZATION_POLICY.md` and
`reports/P15_3_TEST_POLICY.json` are committed before the benchmark is generated,
and the verdict is computed by code rather than read off a table. Acceptance
criteria written after a result are not criteria, and the cheapest guard against
writing them is to make the standard executable and commit it first.

**Sample independence.** Windows from one source are not independent
observations. Recall, precision and false-block rate carry percentile bootstrap
intervals resampled over **source groups**, never over windows. Thousands of
correlated windows must not pretend to be thousands of examples — which is the
P15.2 root cause in general form, where a Wilson interval was computed over the
packet count in a window rather than over the calibration sample.

**Calibration support.** A conservative bound is only as tight as the number of
calibration examples in the band it comes from, and narrowing it with *duplicate*
windows would be fraud with extra steps. The response to an interval that is too
wide is more independent sources, never a lower cutoff.

**Implemented component.** `dataset/split.py::HOLDOUT`,
`dataset/generators/composite.py`, `training/observability.py`,
`training/test_policy.py`, `training/p15_3_evaluation.py`,
`training/evaluation_design.py::CORPORA`.

**Limitation.** This measures generalization across compositions of the
primitives *this project's own generators implement*. It does not measure
generalization to real Internet traffic and no result may be read that way. A
genuinely novel phenomenon sharing no primitive with anything known needs a new
observation, not a better weight.

---

## Data leakage

**Source concept.** A feature that encodes the answer produces excellent offline
metrics and no field performance.

**Project interpretation.** Identity, provenance and every prior decision are
permanently excluded from the model input, by name, with reasons. Temporal
leakage is treated as a first-class case.

**Implemented component.** `dataset/schema.py::NEVER_MODEL_INPUT`,
`dataset/leakage.py`, `training/validation.py`.

**Limitation.** An exclusion list catches the columns somebody thought of. A
subtle proxy for the label inside a permitted feature would not be caught by a
name list — which is why `dataset/leakage.py` also looks for near-perfect
separation and generator fingerprints.

---

## Anomaly detection and Isolation Forest

**Source concept.** Isolation Forest isolates points with few random splits;
unusual points are isolated quickly. It is unsupervised and answers "how
unusual", not "how malicious".

**Project interpretation.** Anomaly is bounded evidence carved *out of* the
maths-plus-ML pool rather than added on top, so it can shift where evidence comes
from and cannot inflate the total. It never blocks on its own.

**Implemented component.** `decision/anomaly.py`, the bounded `anomaly_weight` in
`DecisionFusion`, the `ANOMALY` family in `autonomy/evidence.py`.

**Limitation.** Unusual is not malicious, and the cases that matter are exactly
the ones where legitimate traffic is unusual: a nightly backup, a new analytics
crawler, a monitoring probe, a migration. The design assumes the anomaly score is
sometimes wrong about ordinary things.

---

## Out-of-distribution detection

**Source concept.** A model's outputs are unreliable on inputs unlike its
training distribution. A high score on a far-OOD input is extrapolation.

**Project interpretation.** OOD reduces classifier authority and can never raise
suspicion. High OOD suppresses a block rather than supporting one.

**Implemented component.** `decision/ood.py` (quantile bands from the reference
distribution), `distribution_confidence` in the fusion, the `HIGH_OOD` restraint.

**Limitation.** The reference distribution is built from whatever was observed
when it was built. A site whose legitimate traffic changes shape will look
out-of-distribution to it — which costs detection, not availability, and that is
the correct direction for this trade.

---

## Concept drift

**Source concept.** The relationship between features and labels changes over
time; population-level statistics reveal it before labelled performance does.

**Project interpretation.** Drift is model health. It reduces model authority,
pauses automatic promotion, triggers retraining and changes reported health. It
never reaches a source's score.

**Implemented component.** `decision/drift.py`, `model_health`, the
`DRIFT_DEGRADED` restraint, the P14 governance freeze.

**Limitation.** Population drift and a change in attack mix look the same from
here. The response is the same either way — trust the model less — which is safe
and is not diagnosis.

---

## Robust statistics

**Source concept.** Means and standard deviations are not robust on heavy-tailed
data. Median, MAD, IQR and quantiles are.

**Project interpretation.** Security traffic is heavy-tailed. Distributions are
summarised by quantiles and bands, not by `mean ± 3σ`, and a high value alone is
never an outlier verdict.

**Implemented component.** `decision/distribution.py` (p01/p05/p95/p99 plus
observed range), `decision/ood.py` band assignment,
`autonomy/evaluation.py` percentile bootstrap.

**Limitation.** Quantiles need enough observations to be stable. Below the
configured minimum the answer is `INSUFFICIENT_REFERENCE`, which is honest and
also means no distribution opinion at all.

---

## Model collapse and feedback loops

**Source concept.** Training a model on its predecessor's output narrows the
distribution and amplifies its errors.

**Project interpretation.** The system's own decisions are never labels. Lineage
is tracked, provenance shares are bounded, and a candidate dataset dominated by
one group fails its quality gate.

**Implemented component.** `dataset/schema.py::FORBIDDEN_LABEL_SOURCES`,
`dataset/candidate.py` (`IntakeLimits`, `quality_gate`, `Lineage`).

**Limitation.** Bounding provenance share limits collapse; it does not prevent a
slow shift driven by which traffic a site happens to receive. That is why
baselines are governed rather than continuously absorbed.

---

## Continuous monitoring and model governance

**Source concept.** A deployed model needs monitoring, versioning, staged
rollout and rollback, because offline validation cannot cover production.

**Project interpretation.** An eleven-state lifecycle, an assess-only engine
separate from the activator, guarded activation with a reduced action ceiling,
automatic rollback with three tiers, and a promotion that is refused outright if
there is nothing to roll back to.

**Implemented component.** `eye_for_an_eye/governance/` (P14).

**Limitation.** Governance decides whether a candidate *may* be promoted. It
cannot tell whether the candidate is better in ways the evidence does not cover,
and `NEED_MORE_DATA` is a common and correct answer.

---

## Cost-sensitive automated response

**Source concept.** Automated response systems are evaluated on the cost of their
actions, not on detection counts alone.

**Project interpretation.** The objective is to minimise expected security loss
subject to availability, false-block, resource and safety constraints — not to
block as many suspicious sources as possible.

**Implemented component.** `autonomy/authority.py`, `autonomy/breakers.py`,
`autonomy/evaluation.py::release_gate`.

**Limitation.** "Expected" is doing real work in that sentence. The expectation
is taken over a probability this system estimated, under costs an operator
assigned, against a prevalence nobody has measured.

---

## Adaptive security and safe exploration

**Source concept.** Bandits and reinforcement learning optimise sequential
decisions by trading exploration against exploitation.

**Project interpretation.** Exploration means sometimes taking the action you
believe is wrong, to learn. Blocking a real visitor is not a safe action to take
experimentally, so `TEMP_BLOCK` is never an exploratory arm and no RL component
has firewall authority. If such a thing is built here it stays lab-only, against
an offline simulator, over a non-destructive action set.

**Implemented component.** The absence of one, asserted by
`tests/test_p15_invariants.py::TestNoLLMAndNoReinforcementLearningInTheDecisionPath`.

**Limitation.** This forgoes whatever an online learner might have discovered. It
is a deliberate trade: the failure mode of safe exploration on real users is
someone losing access to a service they paid for.

---

## Large language models

**Source concept.** LLMs are effective at summarisation and explanation.

**Project interpretation.** They may help a person write documentation or read a
report, offline. They have zero enforcement authority, network data is never sent
to one, and nothing in the runtime imports a client for one.

**Implemented component.** The absence of one, asserted by the same test.

**Limitation.** None worth claiming. This is a restriction, not a capability.

---

### Interval estimation for a proportion

**Source concept.** Wilson, 1927: a score interval for a binomial proportion,
better behaved than the normal approximation at small `n` and near 0 or 1.

**Project interpretation.** The proportion is P(malicious | score band), and its
sample size is the number of *calibration examples* in that band. A calibrator
carries the resulting lower bound as monotone knots, and the cost comparison uses
the bound rather than the point estimate.

**Implemented component.** `decision/calibration.wilson_lower`,
`conservative_knots`, and `Calibrator.lower`.

**Limitation.** The interval quantifies sampling error in the calibration data
and nothing else. It says nothing about a source the calibration corpus never
resembled — that is what the OOD, diversity, maturity and data-quality gates are
for. P15 applied this same correction to the number of packets in an observation
window, which is not the sample size of this estimate; the interval was two
orders of magnitude too wide and the system blocked nothing for two cycles.

---

## A closing note on what this page is

Every entry above describes an *interpretation* — a choice about how to apply a
result to this system. The results are established; the choices are this
project's, made without deployment data, and each one could reasonably have been
made differently.

Nothing here is evidence that the system's decisions are correct. It is evidence
that the decisions were designed deliberately, with the known failure modes
named. Those are different claims, and this project keeps them apart.

## See also

- [COST_SENSITIVE_POLICY.md](COST_SENSITIVE_POLICY.md)
- [DECISION_UNCERTAINTY.md](DECISION_UNCERTAINTY.md)
- [AUTONOMOUS_DECISION.md](AUTONOMOUS_DECISION.md)
- [AUTONOMOUS_DATA_CURATION.md](AUTONOMOUS_DATA_CURATION.md)
- [MODEL_EVALUATION.md](MODEL_EVALUATION.md)
- [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md)
