# Model Evaluation (Research Only, "P7")

This page reports the measured numbers from an earlier research phase (called "P7") that tested two candidate machine-learning models on synthetic data. It is for developers and reviewers who want the real numbers behind the **SHADOW ONLY** recommendation, not a claim about real-world performance.

## The Dataset Used for This Test

This evaluation used a synthetic (artificially generated, not real) dataset called `synthetic-behavior-v2`. It has 6534 rows, from 288 source groups.

The held-out test set (data set aside and never used for training) has 1854 rows from 93 sources (24 benign, 69 with attack-like intent). A "source group" always stays fully inside one split (train, validation, or test); it is never spread across more than one. This stops a model from training on a source and then being tested on an almost-identical copy of it, which would make the test look easier than it really is.

**No real labelled capture was used for this evaluation. Every row is synthetic.**

## The Two Candidate Models

Two candidate models were compared: a **logistic baseline** and a **Gradient Boosting** model (a model built from many small decision trees). Here is what each measurement means, in plain words:

* **Precision**: of everything the model called "malicious," what fraction really was.
* **Recall**: of everything that really was malicious, what fraction the model actually caught.
* **F1**: one combined number that balances precision and recall.
* **False positive rate**: how often the model wrongly called a benign source "malicious."
* **ROC AUC**: a 0-to-1 score for how well a model can tell the two classes apart, across every possible decision threshold; 1.0 means perfect separation on this test data.
* **PR AUC**: a similar idea, but focused on the harder precision/recall trade-off.
* **Brier score**: how far off a model's confidence numbers are from the real outcomes, on average. Lower is better.
* **ECE (10 bins)**: "expected calibration error." It checks whether a model that says "I am 90% sure" is actually right about 90% of the time, by sorting predictions into 10 groups and comparing. Lower means the confidence numbers can be trusted more.

| Metric | Logistic baseline | Gradient Boosting |
|---|---:|---:|
| Precision | 1.000000 | 1.000000 |
| Recall | 0.659624 | 1.000000 |
| F1 | 0.794908 | 1.000000 |
| False positive rate | 0.000000 | 0.000000 |
| ROC AUC | 0.983890 | 1.000000 |
| PR AUC | 0.992308 | 1.000000 |
| Brier score | 0.205176 | 0.000016 |
| ECE (10 bins) | 0.223900 | 0.003971 |

A **confusion matrix** shows counts in this order: `[[true negatives, false positives], [false negatives, true positives]]`. Here:

* Logistic: `[[576, 0], [435, 843]]`
* Gradient Boosting: `[[576, 0], [0, 1278]]`

Per-class numbers, calibration detail, and feature importance are in [evaluation.json](../models/research-v2/evaluation.json).

## Which Candidate Was Picked, and Why

The research candidate chosen was `gradient_boosting-research-v1` (11108 bytes). On the validation data (data used to pick a model, kept separate from the final test), the false positive rate was tied at zero for both models, but the Gradient Boosting model's validation recall was 1.0000, against 0.991667 for the logistic model.

This choice was made using **validation** data, not the **test** data, keeping the final test numbers honest, because they were never used to help choose the model. The logistic model stays as the simpler baseline, at 748 bytes.

Both candidates were also checked for **export accuracy**: how closely the exported ONNX file's answers match the original scikit-learn (a Python machine-learning library) model's answers, on the same held-out rows. The largest difference found was 0.00000012 for the logistic model and 0.000000006 for the Gradient Boosting model. Both far below the required limit of 0.00001.

## Why a Perfect Test Score Does Not Mean a Perfect Model

**The Gradient Boosting model's perfect score on this synthetic test does not prove it will work on real traffic.** The data generator gave several attack families distinctive patterns in a few features (like anomaly count, credential count, and port sequence). A real, authorised port scanner, a proxy server, or an administrator's own tool could look similar to those patterns, and get wrongly flagged.

No **Platt scaling** or **isotonic regression** was applied to these models. These are two standard ways to fix a model's confidence numbers so they better match true probabilities. They were not used here because this small, synthetic dataset does not give enough evidence to justify them.

**The scores from both models are explicitly uncalibrated.** The Brier score and calibration (reliability) results above describe only this synthetic dataset. They are not a claim about real-world accuracy.

## Decisions After Fusion and PolicyGuard

This section looks past the raw model score, at what Eye for an Eye's full decision pipeline (fusion plus PolicyGuard, see [DECISION_ENGINE.md](DECISION_ENGINE.md)) would actually have done.

"Would-block" means: how many sources would have reached `TEMP_BLOCK` if this had run for real. "Block precision" means: of everything the pipeline would have blocked, how many were genuinely malicious.

| Mode | Would-block sources | Correct / labelled would-block | Block precision | False-positive blocks |
|---|---:|---:|---:|---:|
| math_only | 8 | 8 / 8 | 1.000 | 0 / 24 benign |
| logistic | 21 | 21 / 21 | 1.000 | 0 / 24 benign |
| gradient_boosting | 21 | 21 / 21 | 1.000 | 0 / 24 benign |

Using the Gradient Boosting model, the highest state each source ever reached was: `OBSERVE` for 24 sources, `WATCH` for 46, `RATE_LIMIT` for 2, and `TEMP_BLOCK` for 21.

Out of 69 truly malicious sources, only 21 were actually blocked: a source-level block recall of 21/69 = 30.43%. This is much lower than the model's own classification recall (100%, from the table above), **on purpose**. The independent evidence gates described in [DECISION_ENGINE.md](DECISION_ENGINE.md) intentionally hold back a strong action unless there is enough separate, solid evidence.

No benign source reached even `WATCH` in these test scenarios. **With no real-world labels available, the block precision in a real deployment remains unknown.**

The pipeline also records how often the math score and the machine-learning score disagreed: with the Gradient Boosting model, "math score low, machine-learning score high" happened 439 times, and "math score high, machine-learning score low" happened 0 times; with the logistic model, these were 2 and 0. These disagreement counts are kept as an auditable field inside every `decision_record`, and the pipeline **never automatically favours the machine-learning score** over the math score when they disagree.

## Time to Reach Each State

This section measures, in seconds, how long it took a source to first reach each state; counted from the moment the first usable feature could be built (after 4 observations), not from when capture started. A dash (`: `) means that state was never reached. If a source jumped straight to `TEMP_BLOCK`, it still counts as having reached the lower states along the way. Full minimum, maximum, and reached-count numbers are in [shadow.json](../models/research-v2/shadow.json).

| Scenario | Sources | WATCH mean | RATE_LIMIT mean | TEMP_BLOCK mean | Would block |
|---|---:|---:|---:|---:|---:|
| browser | 3 | - | - | - | 0 |
| monitoring | 3 | - | - | - | 0 |
| reverse_proxy | 3 | - | - | - | 0 |
| backup | 3 | - | - | - | 0 |
| health_checker | 3 | - | - | - | 0 |
| software_updater | 3 | - | - | - | 0 |
| administrator | 3 | - | - | - | 0 |
| load_balancer | 3 | - | - | - | 0 |
| sequential_scan | 3 | 0.000 | 4.737 | 7.645 | 3 |
| credential_burst | 3 | 0.785 | (|) | 0 |
| protocol_abuse | 3 | 0.000 | (|) | 0 |
| slow_scan | 18 | 0.000 | 446.487 | 446.487 | 15 |
| random_ports | 3 | 0.000 | 10.024 | - | 0 |
| low_rate_credentials | 18 | 40.048 | (|) | 0 |
| burst_pause | 3 | 0.000 | 406.403 | 406.403 | 3 |
| distributed_sources | 18 | 0.000 | (|) | 0 |

Slow scans took hundreds of seconds to build enough evidence, and 3 of them were never blocked at all. Random-port scans reached `RATE_LIMIT` in two of three sources, but never a block. The credential, protocol-abuse, and distributed-source scenarios often stayed stuck at `WATCH`, because the evidence from a single source alone was not enough. This is expected: sparse traffic spread across many addresses cannot be reliably tied back to one source by a single, independent sensor like this one.

## CPU Speed Test

This test used CPython 3.12.14 (the Python interpreter), running on CPU only, on one session thread, on Linux running inside WSL2 (Windows Subsystem for Linux) on an x86_64 machine with 8 logical CPUs. The timings include the normal checks Eye for an Eye runs on every input and output tensor.

* "Warm single calls": 10,000 repeated single predictions.
* "Batch8 calls": 2,000 repeated predictions, each covering a batch of 8 at once.
* "Isolated IPC calls": 1,000 predictions made the same way production does, through inter-process communication (IPC), meaning the model runs in a separate process and answers are sent back over a pipe.

In this experiment, a batch never had to wait for more items to arrive, so this number does not reflect how batching would behave under real, uneven traffic. RSS (Resident Set Size, a measure of memory actually used by a running program) here is a single sample, not a true peak, and the "benchmark parent" RSS figure also includes memory used by offline training libraries that a real deployment does not load.

| Platform / candidate / path | p50 ms | p95 ms | p99 ms | sources/s |
|---|---:|---:|---:|---:|
| Linux / logistic / single_validated | 0.0241 | 0.0286 | 0.0495 | 26758 |
| Linux / logistic / batch8_validated | 0.0794 | 0.1002 | 0.1859 | 79741 |
| Linux / logistic / isolated_ipc | 0.1487 | 0.2711 | 0.3742 | 5434 |
| Linux / gradient_boosting / single_validated | 0.0246 | 0.0417 | 0.0564 | 23059 |
| Linux / gradient_boosting / batch8_validated | 0.0820 | 0.1429 | 0.1998 | 74638 |
| Linux / gradient_boosting / isolated_ipc | 0.1488 | 0.2612 | 0.3496 | 5344 |
| Windows / logistic / single_validated | 0.0296 | 0.0327 | 0.0475 | 28414 |
| Windows / logistic / batch8_validated | 0.1015 | 0.1048 | 0.1367 | 72621 |
| Windows / logistic / isolated_ipc | 0.2133 | 0.2439 | 0.2951 | 4720 |
| Windows / gradient_boosting / single_validated | 0.0298 | 0.0329 | 0.0458 | 28373 |
| Windows / gradient_boosting / batch8_validated | 0.1029 | 0.1069 | 0.1799 | 71043 |
| Windows / gradient_boosting / isolated_ipc | 0.2068 | 0.2252 | 0.2818 | 5294 |

("p50", "p95", "p99" mean: half of all calls, 95% of all calls, and 99% of all calls finished at or under this time.)

On Linux, the Gradient Boosting model's separate child process used 79.17 MiB of RSS memory. The main benchmark process's sampled RSS was 182.51 MiB. Measured CPU time was 0.440 seconds for the 10,000 direct calls, 0.210 seconds for the 2,000 batches, and 0.100 seconds inside the child process for the 1,000 IPC calls. These are raw process CPU-time numbers, not percentages of a deployed server's CPU.

Batching improves total throughput, but it adds extra per-call bookkeeping work, and a real deployment would need a policy for how long to wait for a batch to fill up. Eye for an Eye's current version keeps single-source inference and does not add such a wait. This benchmark does **not** measure real network packet throughput, and it does not guarantee any particular hardware performance level.

A separate interval experiment sent 1200 events across 20 sources over 6 seconds of simulated event time. This gave 120, 60, and 40 decision opportunities at the 1-, 2-, and 5-second interval settings. The kept decision history used 20,871 bytes for those 20 sources. This measured only the math-scoring and correlation scheduling. It does **not** benchmark real network intake together with machine-learning under load.

The raw measurement files are here: [Linux](../models/research-v2/benchmark-linux.json), [Windows](../models/research-v2/benchmark-windows.json).

**Recommendation: SHADOW ONLY.** Before any limited real deployment: get real, permitted, labelled traffic; measure real source-level false positives and calibration on it; and review the policy thresholds again.

## See Also

* [DECISION_ENGINE.md](DECISION_ENGINE.md): the fusion and gate logic scored in this evaluation.
* [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md): how the pipeline this page measures fits together.
* [MODEL_TRAINING.md](MODEL_TRAINING.md): how these candidate models were trained.
* [ONNX_MODEL.md](ONNX_MODEL.md): the model file format used here.
* [SHADOW_MODE.md](SHADOW_MODE.md): running a model this way, without enforcement.
* [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md): known limits of these results.
* [MONITORING_EVALUATION.md](MONITORING_EVALUATION.md): ongoing monitoring once a model is deployed.
