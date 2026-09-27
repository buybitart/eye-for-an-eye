# Shadow validation plan

What a real shadow deployment has to produce before anyone argues that
autonomous host blocking should be turned on, how much of it is needed, and how
it will be read.

Written before the data exists. That is the point: a plan written afterwards is
a description of whatever happened, and a bar you can move is not a bar.

## The standing position

**Production autonomous host blocking stays disabled.** Nothing in this
document changes that, and running this plan does not change it either. It ends
in evidence and a review, and the review is a separate act performed by someone
who did not build the system.

Shadow mode is the supported way to run Eye for an Eye today. It is not a
staging area on the way to something better; for most deployments it is the
final state, and a shadow deployment that never enables blocking has lost
nothing.

## The question this plan answers

Every accuracy number this project has comes from traffic it generated itself.
`docs/GENERALIZATION_POLICY.md` says so plainly: holding out a behaviour family
measures generalisation across compositions of primitives our own generators
implement, and **it does not measure generalisation to real traffic**. No
synthetic corpus can, however large.

So the question is narrow and it is the only one a shadow deployment can
settle:

> On this deployment's own traffic, how often would the system have blocked a
> source that a person, looking at the evidence, calls benign?

That is the release metric (`docs/MODEL_EVALUATION.md`, §166), and it is the
one number no benchmark in this repository can produce.

Three questions this plan explicitly does **not** answer:

* **How well it detects.** Recall on real traffic needs real attacks that
  someone has labelled, and a site that has enough of those to measure recall
  has a bigger problem than this plan.
* **Whether it generalises to other deployments.** A result from one site is
  about one site. Two sites are two results, not a trend.
* **Whether the thresholds are right.** The cost model is a judgement about a
  particular deployment and stays the operator's (`docs/COST_SENSITIVE_POLICY.md`).

## Where it may run

Owned systems only:

* a host the operator owns and administers;
* a local test client, or a lab the operator owns;
* a site the operator is responsible for, running in shadow mode.

No arbitrary Internet target, no third-party system, no traffic solicited from
anyone. The sensor is passive in shadow mode — it watches traffic that was
already arriving — and nothing in this plan generates traffic towards a machine
the operator does not own.

## What is collected

The shadow export, one row per decision, written by the running sensor
(`docs/BACKPRESSURE.md` says how to turn it on and what it costs). Each row
carries, derived from the decision the runtime already made:

| Group | Fields |
|---|---|
| identity | `source_pseudonym`, `site_pseudonym`, `scope`, `profile_type` |
| time | `timestamp_bucket` (coarsened to the hour), `bucket_seconds` |
| evidence | observation count and seconds, data quality, per-feature contributions, `math_risk`, evidence families, diversity counts, band |
| computation | calibrated and conservative probability, calibration version, OOD and drift status, model health, uncertainty, gates, failed assumptions |
| cost | threshold, decision margin, `loss_allow`, `loss_block`, cost policy digest |
| outcome | `would_action`, `actual_action`, `shadow`, `enforcement_withheld`, `reason_codes` |
| context | `component_health` at the moment of the decision |
| ground truth | `review.label`, `review.label_source`, `review.label_confidence` — always empty |

Not collected, at any setting: addresses, payloads, request bodies, headers,
credentials, cookies, tokens. The export is local, and moving it anywhere is
the operator's deliberate act.

Timestamps are coarsened to the hour because an exact time and a stable
pseudonym together are a re-identification tool even though neither is one
alone, and nothing in the analysis below needs better than an hour.

## Ground truth comes from a person, and never from the system

The three `review` fields ship empty and this software never fills them. The
reason is stated in `eye_for_an_eye/autonomy/evaluation.py` and it is the single
most important rule in this document:

> A system decision is never ground truth. `would_action` is not a label,
> `actual_action` is not a label, "it was blocked" is not a label, and "it
> passed a challenge" is not a label.

Deriving labels from decisions produces a number that measures how
self-consistent the system is, which is always excellent and always worthless.
The accepted label sources are fixed in code
(`autonomy/breakers.TRUSTED_OUTCOME_SOURCES`):

| Source | What it is | What it is good for |
|---|---|---|
| `lab_scenario` | traffic the operator generated on purpose, in their own lab | known positives; never a benign population |
| `signed_pcap_sidecar` | a capture with a label file from a controlled collection | both classes, small volumes |
| `deterministic_harness` | a test client the operator runs against their own host | known positives and known benign automation |
| `reviewed_evaluation` | a person read the evidence and decided | the only source that scales to real traffic |

For a shadow deployment on live traffic there is one realistic source:
`reviewed_evaluation`. That is human work, and the sampling design below exists
to make the amount of it proportional to the number of blocks rather than to
the volume of traffic.

### The review must be blinded

A reviewer shown `would_action`, `reason_codes` or `evidence_band` before
deciding is a reviewer whose label is partly the system's decision. Labels
gathered that way are contaminated, and the contamination flatters the system
in exactly the direction the metric is meant to test.

So before any review begins, the rows must be projected into a **blinded view**
that carries the evidence and drops the decision:

* **kept** — `source_pseudonym`, `timestamp_bucket`, `scope`, `profile_type`,
  observation count and seconds, data quality, per-feature contributions,
  evidence families and diversity counts, OOD and drift status;
* **removed** — `would_action`, `actual_action`, `enforcement_withheld`,
  `reason_codes`, `evidence_band`, `math_risk`, every probability, every cost
  field, `failed_assumptions`, `component_health`;
* **order** — rows shuffled, so position carries nothing.

The reviewer writes `BENIGN`, `MALICIOUS_AUTOMATION` or `UNLABELED` and a
confidence, and labels are joined back to decisions by `decision_id`
afterwards. `UNLABELED` is a first-class answer and reviewers should use it
freely; a forced label is worse than no label.

The projection is in the tree, so a review does not begin with somebody writing
an ad-hoc script that leaks `would_action` by accident:

```text
eye-for-an-eye autonomy review shadow-export.jsonl --seed 20260919 --json
```

It reads the export, drops every decision field, shuffles the rows and writes
`label: null`. The keep-list is exhaustive and anything unrecognised is dropped,
so a field added to the export later is invisible to the reviewer until someone
deliberately lists it. `eye_for_an_eye/autonomy/review.py` names exactly what is
withheld, and `tests/test_p15_5r_review_view.py` asserts a block and an allow
are indistinguishable in the view.

Joining the labels back, and the sampling frame in the analysis below, remain
the operator's own step.

## How much evidence, and where that number comes from

The release gate in `autonomy/evaluation.py` already states the bar — it was
written before this cycle and is not being chosen now to fit a result:

| Threshold | Value |
|---|---:|
| `max_false_blocks_per_1000_benign` | 1.0 |
| `min_block_precision` | 0.95 |
| `min_benign_sample` | 500 |
| `min_positive_sample` | 50 |

The two sample floors are floors for **computing** a number, not sample sizes
that can **establish** the two thresholds above them. That distinction is
where most validation plans quietly go wrong, so here is the arithmetic.

### Benign sources

Suppose the true false-block rate is *p* and the deployment observes *n*
independent benign sources with **zero** false blocks. The probability of that
outcome is (1 − *p*)^*n*, so the one-sided 95% upper bound on *p* is the value
satisfying (1 − *p*)^*n* = 0.05, that is *p* = 1 − 0.05^(1/*n*) ≈ 3/*n* for
small *p*.

| Benign sources, zero false blocks | 95% upper bound |
|---:|---:|
| 500 | 5.97 per 1000 |
| 1,000 | 2.99 per 1000 |
| 2,000 | 1.50 per 1000 |
| **2,995** | **1.00 per 1000** |
| 5,000 | 0.60 per 1000 |

So the gate's floor of 500 benign sources, with a perfect result, is consistent
with a true rate six times the ceiling it is being checked against. **The
validation target is 3,000 labelled benign sources**, because that is the
smallest number at which a clean run actually supports the claim the threshold
makes. Any observed false block widens the interval, and the plan does not get
to round it back down.

### Blocked sources

The same arithmetic on the other side. With *k* blocked sources and zero of
them wrong, the 95% lower bound on block precision is 0.05^(1/*k*):

| Blocked sources, zero wrong | 95% lower bound on precision |
|---:|---:|
| 50 | 0.942 |
| 58 | 0.950 (just below) |
| **59** | **0.950** |
| 100 | 0.970 |

**The validation target is 60 blocked sources**, reviewed in full. Fifty — the
gate's floor — cannot reach 0.95 even with a flawless result.

### Duration

**This plan does not say "N days is sufficient", and no reader should quote it
as if it did.** Duration is not the requirement; the source counts above are.
The number of days follows from the deployment's own traffic:

```text
days ≈ 3000 / (distinct sources seen per day)
```

Count distinct `source_pseudonym` values per day from the export itself for the
first week, then compute it. A site seeing 400 distinct sources a day needs
about eight days; a site seeing 40 needs seventy-five, and should ask whether
this evidence is obtainable there at all.

Three conditions apply to whatever window that produces:

1. **At least seven consecutive days**, whatever the arithmetic says, so the
   window contains every day of the week. Traffic on a Sunday is not traffic on
   a Tuesday, and a five-day window that happens to hit the count can miss a
   weekend batch job entirely. This is a coverage requirement, not a sample-size
   one.
2. **No configuration change inside the window.** A changed threshold, cost
   profile, model or feature schema ends the window and starts a new one. The
   export carries `cost_policy_digest`, `calibration_version`,
   `math_version` and the feature schema version in every row precisely so this
   can be checked rather than remembered.
3. **The window is declared before it starts and not extended to improve the
   result.** Extending a window because the number came out wrong is how a
   validation becomes a search.
4. **The export must not rotate away its own evidence.** See below; this is the
   condition most easily missed, because nothing announces it.

### The export is a ring, and a long window can outlive it

The shadow export is written through the bounded writer in
`eye_for_an_eye/autonomy/bounded_jsonl.py`, which exists to stop evidence
collection filling a disk. Its defaults keep **four files of 20,000 records
inside a 32 MiB ceiling, and then delete the oldest**.

That is correct behaviour for a log and a hazard for a validation window. An
export row carries feature contributions, gates, uncertainty and cost detail, so
it runs to a few kilobytes; the byte ceiling is reached well before the record
ceiling, at roughly ten thousand rows. A window long enough to see 3,000
distinct sources will often produce more than that — and when it does, the
earliest part of the window is deleted, the analysis counts what survived, and
every number it prints is arithmetically perfect and about the wrong period.

Three things follow:

* **Read the whole set, not the live file.** `export.jsonl` is the newest of up
  to four; `autonomy evidence` and `autonomy freeze` read `export.jsonl.3`
  through `export.jsonl` together, and a script that opens the live path alone
  is reading the last quarter of the window.
* **Size or drain it deliberately.** Either raise the export's limits for the
  window, or copy completed rotations out of the directory on a schedule. Both
  are the operator's decision and neither happens on its own.
* **Record when the window began.** `autonomy freeze --started-at` compares the
  declared start against the oldest surviving row and says so when the window
  lost its beginning. Without it that loss is invisible, because the files that
  remain are intact.

A window whose evidence is known to be incomplete is a FAIL and not an
INSUFFICIENT_EVIDENCE. The two describe different remedies: a short window is
answered by collecting more, and a window that lost part of itself cannot be.

## What counts as a result

Four outcomes, and three of them are not a pass.

**INSUFFICIENT_EVIDENCE.** Fewer than 3,000 labelled benign sources, or fewer
than 60 reviewed blocked sources, or ground truth absent. This is the default
and the most likely outcome of a first window. It is not a pass with a caveat.

**FAIL.** Any of:

* the 95% upper bound on false blocks per 1000 benign sources exceeds 1.0;
* the 95% lower bound on block precision falls below 0.95;
* the decision is degenerate — everything blocked, or nothing blocked. An
  allow-all system scores a perfect false-block rate and has protected nobody;
  `non_degenerate_gate` fails it and this plan does too;
* a component was DEGRADED or UNAVAILABLE for a material part of the window and
  the decisions taken under it were not excluded;
* the journal or export dropped rows during the window, so the evidence is
  incomplete in a way nobody can quantify.

**PASS, and it means one thing only.** The evidence is consistent with a false
block rate at or below 1 per 1000 benign sources *on this deployment, during
this window, under this configuration*. It is not a statement about next month,
about another site, or about traffic that did not arrive.

**INVALID.** The window was extended, the configuration changed inside it,
labels were derived from system output, or the review was not blinded. There is
no partial credit here; the evidence is discarded and the window is rerun.

### On pre-declaring a convenient threshold

The thresholds above are not new. They are in `ReleaseThresholds` and have been
since the decision authority was written, with their own docstring saying they
are operator policy and that none of them is a measured value. What this plan
adds is the **sample size required to decide them**, and that number is derived
from the thresholds rather than chosen to be reachable — which is why it is
three thousand and not five hundred.

If 3,000 benign sources cannot be reached at a deployment, the honest outcome
is INSUFFICIENT_EVIDENCE and autonomous blocking stays off there. Lowering the
requirement so a particular site can pass would make the bar a function of the
site, which is the opposite of a bar.

## The analysis

Given the labelled rows:

1. **Join** labels to decisions by `decision_id`. Rows whose label is
   `UNLABELED` count towards what was seen and towards nothing else.
2. **Aggregate to sources, not decisions.** One source produces many decisions
   over a window and they are not independent. A source is a false block if any
   decision about it in the window has `would_action = TEMP_BLOCK` and its
   label is `BENIGN`.
3. **Stratify.** Review every blocked source. Review a random sample of the
   rest, drawn before any of them is looked at. Estimate the benign population
   as the fully-reviewed blocked stratum plus the sampled stratum weighted by
   its sampling fraction, and carry that weighting into the interval. Reviewing
   only the interesting rows and reporting the result as if the whole
   population had been reviewed is the commonest way this metric is overstated.
4. **Compute** false blocks per 1000 benign sources, block precision, and the
   95% interval for each, and run `release_gate`.
5. **Break out by scope and cost profile.** A rate that is fine globally and
   terrible on one `SERVICE:` scope is a finding, not an average.
6. **Report prevalence.** Precision depends on how common the positive class
   is, so the report carries the prevalence sweep rather than a single number
   (`prevalence_sweep`, §168).

### The commands that do it

The analysis is committed code, run from the command line, against files whose
hashes are written down first. A result that exists only in somebody's notebook
is a result nobody can check.

```text
eye-for-an-eye autonomy preflight > startup-evidence.json
eye-for-an-eye autonomy evidence EXPORT [--labels PACK]
eye-for-an-eye autonomy crosscheck JOURNAL --export EXPORT [--sample N]
eye-for-an-eye autonomy review EXPORT > pack.jsonl
eye-for-an-eye autonomy freeze EXPORT --labels PACK --segment ID \
    --commit SHA --started-at UNIXTIME [--journal JOURNAL] > freeze.json
eye-for-an-eye autonomy result freeze.json --labels PACK [--root DIR]
```

`preflight` is run before the window and its output kept with it. It constructs
the pipeline and reads that, rather than reporting what the configuration file
said, because a file that says `mode = "shadow"` and a pipeline that came up in
another state are different facts and only the second one meets traffic. It
reports the component health, whether this configuration would attach a host
enforcer, which cost profile each configured site actually resolves to, and
whether the evidence directories are writable. A configured site that resolves
to the deployment default is warned about: that is correct behaviour for a site
nobody priced, and indistinguishable from a site somebody meant to price and did
not — and it would put that site's decisions under the wrong heading in the
per-profile breakdown below without anything saying so.

`crosscheck` joins the decision journal and the shadow export by `decision_id`
and reports where they describe the same decision differently. Both are written
from one outcome in one call, so they cannot disagree — which is the reason to
check, because that was equally true of every component the P15.5 finding was
about. Run it periodically during the window with `--sample`; a sampled result
says it was one.

`evidence` counts what a period holds and deliberately prints no rate: a rate
over a window that is still growing invites somebody to watch it move and stop
collecting when it looks right. `review` produces the blinded pack a person
labels from. `freeze` hashes the files and records the build, the configuration
and the counts at that instant. `result` re-hashes everything the freeze named
before it counts anything, so a number computed from evidence that changed after
it was frozen fails the window instead of appearing beside a PASS — and it exits
non-zero on anything that is not a PASS, so a script cannot walk past
INSUFFICIENT_EVIDENCE by not reading the text.

`--root` exists because evidence is normally analysed somewhere other than the
machine that wrote it; it re-bases the manifest's paths without changing what is
being checked.

### Assumptions, stated because the interval depends on them

The intervals above assume sources are independent, that a reviewer's label is
correct, and that behaviour is stationary across the window. All three are
approximations. Sources behind one NAT or one cloud provider are correlated;
reviewers are wrong sometimes, and more often on the hard cases that matter
most; traffic is not stationary across a month. Each of these makes the true
uncertainty wider than the stated interval, none makes it narrower, and the
report must say so rather than presenting the arithmetic as the whole answer.

## The review

The evidence pack is:

* the shadow export for the declared window, unmodified;
* the labels, with their source and the blinded view the reviewer saw;
* the configuration in force, including the cost policy digest and every
  version the rows carry;
* the computed metrics, the intervals and the `release_gate` verdict;
* the component health timeline for the window;
* this plan, so the reader can check what was promised against what was done.

It is reviewed by someone who did not build the system and who can rerun the
analysis from the rows. A review that only reads the summary is not one.

Nothing in the pack should require trusting the runtime's own arithmetic: every
number in it is recomputable from the exported rows.

## What this can never establish

* That the system is safe on a deployment it has not run on.
* That it will stay within the bound after the traffic changes, the model
  changes, or a new site is added — `docs/MODEL_GOVERNANCE.md` governs those,
  and each is a new window.
* That the reviewer's labels are right. They are the best available ground
  truth and they are not truth.
* That blocking is a good idea at this deployment. That remains a judgement
  about what a false block costs there, and it stays with the operator.

## See also

* [Shadow mode](SHADOW_MODE.md) — how to run it
* [Backpressure](BACKPRESSURE.md) — turning the export on, and what it costs
* [Autonomous mode](AUTONOMOUS_MODE.md) — the readiness gate and the kill switch
* [Model evaluation](MODEL_EVALUATION.md) — the metrics and why accuracy is not one
* [Generalization policy](GENERALIZATION_POLICY.md) — what a synthetic result does not say
* [Cost-sensitive policy](COST_SENSITIVE_POLICY.md) — why the cutoff is not 0.5
