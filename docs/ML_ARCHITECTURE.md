# Local Decision Architecture

This page shows how a network event moves through Eye for an Eye, from the raw event to a saved decision. It is for developers who want the big picture before reading the detailed pages about each step.

## The Pipeline, Step by Step

One event moves through these steps, in order:

1. The event is normalised (put into a standard shape).
2. It joins the existing bounded sliding time windows from an earlier part of the project, called "P2."
3. A `FeatureVector` (version 1) is built from those windows (see [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md)).
4. `FeatureTransformer` turns the raw numbers into 0-to-1 numbers.
5. Two scorers run **independently**: the math model (MathRisk) and a CPU-only ONNX machine-learning model.
6. Fusion combines both scores into one risk value (see [DECISION_ENGINE.md](DECISION_ENGINE.md)).
7. PolicyGuard checks the gates and rules and decides the final action.
8. The result is saved as a `decision_record`.
9. If this is a lab setup with the firewall manager enabled, an isolated, self-owned, temporary network namespace rule set may be applied (see [FIREWALL.md](FIREWALL.md)).

## What Never Happens in This Pipeline

* No cloud AI service is called.
* No remote reputation service is checked.
* Eye for an Eye never talks to, or coordinates with, another running copy of itself.
* No model is ever downloaded automatically.
* Optional "P0" enrichment (extra network lookups) is configured completely separately. It is not one of the machine-learning features, and its default network access (called "egress") is turned off.
* Training happens entirely outside the production package (the "wheel," a standard Python package format). Nothing in the running service trains a new model, or promotes one to active use, on its own.

## Two Ways an Event Can Reach the Pipeline

The same event-analysis code is shared by two different sources: live traffic (called `EventRuntime`) and offline replay of a saved capture file (a PCAP file).

Live intake only ever accepts a bounded (limited) number of events at a time, never an unlimited stream. The part of the pipeline that reads these events computes a math-only decision on a fixed timer per source. By default, this timer runs every 2 seconds.

There is a separate component called the **ML dispatcher**. It owns:

* a bounded queue for pending machine-learning requests (64 by default, 256 at most),
* a bounded queue for finished results,
* a bounded list ("ledger") of requests still waiting for an answer,
* and exactly one child process.

That one child process owns the ONNX risk model and its one CPU inference session. Only one prediction runs at a time. The current version of this project (called "P7") does not allow more than one at once.

## Why One Event Can Produce Two Decision Records

The very first live decision record for an event may show the machine-learning status as "pending," using only the math-only fallback score in the meantime.

When the machine-learning answer is ready, Eye for an Eye writes a **second** `decision_record`, using the same `supporting_event_id` and the same event timestamp as the first one. This second record is combined with the risk history that came *before* it, not with its own earlier, provisional "pending" score.

If a machine-learning answer finishes after a newer decision has already been made for that same source, it is simply discarded. Eye for an Eye never goes back and rewrites an older decision.

Offline replay, from a saved capture file, works differently: it always waits for the bounded machine-learning answer at each interval, so it produces exactly one decision per interval, never two.

Because of this difference, when you compare live mode and offline replay, compare the number of **source decisions** (one real conclusion, for one source), not the raw count of `decision_record` rows; live mode can create two rows for what is really one decision.

## Timeouts and Shutdown

One machine-learning prediction has a default deadline of 200 milliseconds. The time a request spends simply waiting in the queue also counts against this same 200-millisecond budget.

Starting the model up has its own, separate deadline: 15 seconds.

If a timeout happens, or if the internal communication pipe between the main process and the model's child process breaks, the child process is stopped (terminated), and the math model keeps working on its own. A failed child process is not restarted over and over in an unlimited loop.

Any pending request whose deadline has already passed simply expires, and the decision falls back to the math-only score. This means an overload never blocks the whole pipeline. It just falls back to the math score.

On shutdown, Eye for an Eye stops accepting new work, stops the child process, and then waits at most 1 more second for the dispatcher itself to finish, after the child process has already been shut down. Regular packet handling never pauses to wait for the ONNX model. It always moves on immediately.

## Caching and Bounded Memory

The result cache uses this key: `model_version + SHA256(schema_version, float32_tensor)`. SHA-256 is a one-way scrambling function (a "hash"). Here it scrambles the feature numbers into a fixed-length fingerprint. An IP address is never part of this cache key.

| Cache | Default size | Entry lifetime | Memory budget |
|---|---:|---:|---:|
| ML result cache | 256 entries | 10 seconds | 2 MiB |
| Decision history | 4096 entries | 12 hours | 8 MiB |

The older "P2" sample caches keep their own, separate size and count limits, unaffected by the two caches above.

A source's identity (for example, its IP address) stays in local event metadata. It is never turned into part of a feature tensor, and it is never used as a metric label. Every queue in this pipeline has a fixed upper size, none of them can grow without limit.

## Health and Metrics

The machine-learning health check reports: overall status, whether a model is currently loaded, the model's version, and its feature schema version.

If the machine-learning model becomes unavailable, this lowers ("degrades") the overall reported health, but it does **not** stop Eye for an Eye from accepting new events; the math model can still run alone. If the configuration sets `ml.required = true`, a failed machine-learning startup becomes fatal, and Eye for an Eye will not start at all.

A fixed set of metrics is always tracked: the number of inferences run, their total and average duration, the number of failures, a count for each of the four actions (`OBSERVE`, `WATCH`, `RATE_LIMIT`, `TEMP_BLOCK`), how often policy overruled the action fusion first proposed, how often math and machine-learning disagreed, how many "would block" decisions happened in shadow mode, and how many blocks were actually enforced.

There is no per-IP metric label, and no metric label set that can grow without a limit.

## See Also

* [DECISION_ENGINE.md](DECISION_ENGINE.md): the fusion and policy steps in this pipeline.
* [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md): the numbers this pipeline builds and uses.
* [ONNX_MODEL.md](ONNX_MODEL.md): the machine-learning model and how it is loaded safely.
* [MODEL_EVALUATION.md](MODEL_EVALUATION.md): measured performance of this pipeline.
* [SHADOW_MODE.md](SHADOW_MODE.md): running the full pipeline without enforcing its decisions.
* [ENFORCEMENT.md](ENFORCEMENT.md): what happens after a decision, if enforcement is on.
* [ARCHITECTURE.md](ARCHITECTURE.md): how this pipeline fits into the whole project.
* [CONFIGURATION.md](CONFIGURATION.md): the settings mentioned on this page.
