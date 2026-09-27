# Monitoring and Evaluation

This page defines how the project measures whether it works. It separates
**measured today** from **not yet measured**.

## Rule: No Vanity Metrics

GitHub stars, download counts, lines of code and the number of AI features are
not evidence of impact. They may be recorded as secondary numbers. They never
appear as a success indicator.

The indicators below are security outcomes and user outcomes.

## Detection Quality

| Indicator | How it is measured | Status |
| --- | --- | --- |
| Block precision | Of the sources the system would block, how many were really hostile. Held-out test set, group split. | Measured on the dataset. **Not measured on production traffic.** |
| False blocks per 1000 benign sources | Count of benign sources reaching `TEMP_BLOCK`, scaled. | Measured on the dataset. **Not measured on production traffic.** |
| Recall on held-out families | Detection on scenario families never seen in training. | Measured. |
| Time to detection | Seconds from the first observation to each state. Unreached states stay unreached, never zero. | Measured offline. |
| Model quality on held-out PCAP | The model on capture data only. | Measured. |
| Maths and model disagreement rate | How often the two engines disagree strongly. | Measured, recorded per decision. |

The gap in this table is the whole point of Objective 4 in
the project objectives: every "measured" here means measured on data the
project generated itself.

## Dataset Quality

| Indicator | Status |
| --- | --- |
| Number of independent scenario families | Measured, in the dataset manifest. |
| Leakage checks: port, timing, generator, source type, single feature | Measured every build. |
| Cross-source duplicates | Measured. |
| Distribution shift between sources (PSI-style) | Measured. |
| Share of rows that are unlabelled | Measured. |
| Reproducibility: identical hashes on a clean rebuild | Verified. |

## Runtime Behaviour

| Indicator | How | Status |
| --- | --- | --- |
| ONNX inference latency | Benchmark, and a runtime timing metric. | Measured. |
| Memory use | Benchmark suite. | Measured on one machine. |
| CPU use | Benchmark suite. | Measured on one machine. |
| Event drop rate | `events_dropped_total`, shed counters. | Measured live. |
| Storage write failures | `storage_write_failures_total`. | Measured live. |
| Temporary block expiry correctness | Read-back of kernel expiry, plus the namespace lab test. | Measured in the lab. |

## Adoption and Usability

These need users. The project has none, so none of them has a value yet.

| Indicator | How it would be measured |
| --- | --- |
| Installation success rate | Volunteers report success or the step where they stopped. Opt-in. |
| Time from download to running in Shadow Mode | Timed with volunteers. |
| Number of successful deployments | Reported voluntarily. Never collected automatically. |
| Install problems reported | Issue tracker. |
| Documentation problems reported | Issue tracker. |
| Whether users keep it running after a month | Asked, not measured remotely. |

**There is no telemetry and there will be none.** Every user number depends on
someone choosing to tell the project. That makes these numbers weaker and it is
the correct trade for this software.

## Security Process

| Indicator | Status |
| --- | --- |
| Security bugs found and fixed | Tracked. Internal review only so far. |
| External audit findings and fixes | **Zero, because no external audit has happened.** |
| Unreviewed static-analysis findings | Currently 0, gated in the checks. |
| Secrets in the repository | Currently 0. Git history not scanned, because there is none. |
| Dependency vulnerabilities | `pip-audit` in the checks. |

## Test Coverage

The suite has 353 passing tests and 3 skipped, which need an authorised Linux
lab. A percentage coverage number is deliberately not used as a success
indicator: it measures lines executed, not risks covered. What is tracked
instead is whether each security claim in
[Security review scope](SECURITY_REVIEW_SCOPE.md) has a test that would fail if
the claim broke.

## How Results Get Published

* The data card and the model card carry the dataset and model numbers.
* Reports in `reports/` carry the evaluation detail.
* Negative results are published too. A model that fails a gate is reported as
  failing, not quietly retrained until it passes.

## What Would Make the Project a Failure

Stated in advance, so it cannot be redefined later:

* It blocks real readers of real sites and the operators cannot tell why.
* Nobody can install it without help.
* The model performs no better than the mathematical engine alone.
* Its own presence makes a server less safe.

## See Also

* [Model evaluation](MODEL_EVALUATION.md)
* [Benchmarking](BENCHMARKING.md)
* [Risks and limitations](RISKS_AND_LIMITATIONS.md)
