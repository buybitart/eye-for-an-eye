# Performance: what was measured

This page shows the speed numbers that were actually measured, and the four
code changes that came out of them. Read it if you plan capacity, or if you want
to know what a number here does and does not promise.

All numbers come from the Windows host described below and from synthetic
workloads. They are not a promise about your machine.

* All 50 comparisons: recorded in a phase measurement note that is not published; see [history/README.md](history/README.md)
* Raw JSON: regenerate with `python -m benchmarks.run`; the results directory is not published (see [RELEASE_CONTENTS.md](RELEASE_CONTENTS.md))
* How it was measured: [Benchmarking](BENCHMARKING.md)
* Planning numbers: [Capacity](CAPACITY.md)

## The headline numbers

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Offline packet/s, median 3 | 423.345 | 510.178 | +20.51% |
| Packet p95 ms | 2.741 | 2.905 | +5.96% |
| Scanner correlation updates/s | 732.171 | 1891.726 | +158.37% |
| Correlation p95 ms | 2.238 | 0.780 | -65.15% |
| SQLite single rows/s | 180.141 | 185.539 | +3.00% |
| SQLite rows/s, opt-in batch 8 | 180.141 | 1250.32 | +594.08% |
| SQLite rows/s, opt-in batch 32 | 180.141 | 3451.30 | +1815.89% |

"p95" means: 95 out of 100 runs were at least this fast.

### How to read the batch numbers

The batch test used 100 rows that were built in advance, a separate temporary
database, and `synchronous=FULL`. `synchronous=FULL` means SQLite waits for the
disk on every commit.

This is **not** a promise of durable end-to-end events per second. Real work
also includes correlation, event expansion, logging, queueing and disk
contention.

Two more warnings:

* The batch-32 sample was only 4 transactions. That is a very small sample for
  tail latency.
* Under a paced workload, a batch of 8 often closes on the timer before eight
  records arrive.

## The four changes

### 1. Cache the redaction key decision

Baseline profile: 1.33 million generator calls and 1.24 million `lower()` calls.
Checking the same metadata keys again and again took a real share of
serialisation time.

The cache stores only the true/false decision, for 1024 keys of up to 64
characters. Longer keys are checked without the cache. Values are never cached.
Typed safe metadata and every redaction rule stay in place.

Result: an isolated later packet run reached 496.38/s, against a baseline median
of 423.345/s. The trade-off is one small fixed cache. Changing keys cannot grow
memory without a limit. After the change: 194 tests and 154 subtests passed.

### 2. Make the correlation Sample immutable

Baseline `deepcopy`: 401,295 calls, 0.446 s self time and 1.359 s cumulative in
an instrumented packet run.

`Sample` is now a frozen slots object holding only scalar values. Its
`__deepcopy__` returns the same object. Mutable containers are still copied.
This uses the copy protocol described in the
[Python documentation](https://docs.python.org/3.12/library/copy.html).

Result: a separate later scanner run reached 1868.34/s; the final median was
1891.73/s. The trade-off is that the "scalar fields only" contract must be kept.
A test checks the field types, the frozen behaviour, and that mutable cache
containers stay isolated. After the change: 195 tests and 154 subtests passed.

### 3. SQLite batches

Baseline storage profile: `sqlite execute` 1.116 s self time over 2054 calls. A
benchmark-only test with transaction sizes 1, 8 and 32 gave 184.7, 1324.8 and
3420.1 rows/s.

A production `write_batch` was added. Maximum 32, default 1. `max_batch_delay_ms`
default 10, capped at 50. Single owner, one atomic transaction. Duplicate IDs
stay immutable. Redaction, retention, disk reserve, critical metadata fallback
and the shutdown flush all stay in place. `synchronous=FULL` stays on.

The trade-off: up to 32 pending records sit outside the queue. A crash can lose
them. The delay is checked between bounded handlers. It is not a real-time
deadline for a disk that has stopped answering. See the
[SQLite WAL page](https://www.sqlite.org/wal.html) for the transaction and
checkpoint trade-offs. After the change: 198 tests and 154 subtests passed, plus
extra tests for failure and backpressure.

### 4. Configurable load shedding

This one is about controlled degradation. It is **not** a speed claim.

With `runtime.load_shedding = true`:

| Priority | Allowed up to |
| --- | --- |
| LOW | 75% of both queue budgets |
| NORMAL | 90% |
| HIGH | the hard cap |

FIFO order and drop-newest behaviour stay the same. Nothing has to be searched
for or pushed out of the queue.

| Priority | Examples |
| --- | --- |
| LOW | `connection_closed`, `enrichment_result` / `completed` |
| HIGH | detection and correlation, credential and anomaly, runtime, storage and parse errors, audit and shutdown |
| NORMAL | everything else |

Enrichment admission is suppressed from the low watermark upwards. The existing
policy moves to degraded or observe-only under queue or storage pressure.
Critical counters are updated before admission. The new metrics have fixed
names. The default is `false`.

A test with 64 slots accepted 48 LOW, then 9 NORMAL, then 7 HIGH. At the hard
cap even HIGH is refused. After the change: 201 tests and 154 subtests passed.

## What is still slow, and why we left it

Final profile: `bounded_value` 0.293 s self, regex search 0.231 s, cache size
accounting 0.198 s, `deepcopy` 0.091 s over 75,807 calls.

Redaction, validation and the counted byte limits stay. Removing them is not
treated as an optimisation. There is no zero-copy work, no disabling of the
garbage collector, and no new runtime dependency.

### The API on 50,000 rows

| Query | p95 |
| --- | ---: |
| First page | 73.531 ms |
| Deep cursor | 12.907 ms |
| Source filter | 1.402 ms |

`EXPLAIN` confirms an `event_time` range scan plus a temporary `ORDER BY`
B-tree. The code already uses a sequence keyset. There is no `OFFSET`.

The cost depends on the time range you ask for. A page of 20 rows does not mean
that only 20 rows were scanned.

No index was added. The current result stays inside the query deadline. Choosing
a different plan would need paired wide, narrow and selective benchmarks first.

### The concurrency model was not changed

It stays: one `SelectorServer`, one analysis and SQLite owner, and bounded
enrichment workers.

Fast TCP handles about 900 connections/s. That is clearly above the baseline
single-row writer at about 180 rows/s. So the listener was not shown to be the
main bottleneck. A rewrite to asyncio, a thread pool or multiprocessing is
therefore not needed, and no comparison document is needed either. There are no
comparison numbers for implementations that do not exist. No kernel tuning was
applied.

## CPU cost and complexity

"O(N)" is the usual notation for how work grows with input size.

| Path | Work and limits |
|---|---|
| Probe matching | O(P×L) worst case, P≤4096, L≤65536; loader aggregate payload ≤1 MiB, input ≤8 MiB. Transport filter, exact and prefix only, no regex and no difflib. Near-match p95: 2.313 ms at 4096×256 bytes; 0.145 ms at 16×65536 |
| Source lookup | Average O(1) OrderedDict lookup; `get` deep-copies bounded containers. Byte accounting and copying are O(N) in the source samples |
| Window update | Bounded samples per source: N=64 here, default 256, cap 512, windows ≤4. O(W×N) scans; bounded sorts of single summaries are possible |
| Expiry | Lazy per-key expiry; `len(cache)` scans S entries, O(S), cap 10k here (config cap 100k). Snapshot once per second. A 1k expiry storm took about 0.38 ms; a full 100k event run stayed under the cap. There is no claim of O(1) for full expiry |
| Profile choice | HMAC over a fixed-size address and port key, then a catalogue lookup; the catalogue is small and fixed; no cache is needed |
| FSM | Cumulative caps on requests, responses, messages and transitions; HTTP and SSH regexes run on bounded frames; simple character classes, no nested ambiguous repeats |
| Redaction and JSON | Depth 5, max 24 members per level, strings 256, key 64 on output, event 4096 bytes; raw ingestion upstream is bounded. The `SECRET_VALUE` and JWT checks look only at a bounded prefix. Oversized in-process Python objects are not a network contract |
| API pagination | Indexed filter plus a top-page sort may read M matching retained rows, not O(page size); a VM deadline plus bounded returned rows and bytes apply. Summary scan sample ≤10k. Byte-budget response assembly repeats the JSON prefix and may be O(K²), with K≤500 and response ≤64 KiB; it was not found to be a dominant hotspot |
| Queue admission | O(1) in entry count and serialised bytes; the optional priority reserve does not scan the queue |

Timeouts, the safe UDP receive-only default, schema validation, the confidence
model and the parser caps all stay in force. No benchmark asked for any of these
limits to be relaxed.

## See also

* [Benchmarking method](BENCHMARKING.md)
* [Capacity planning](CAPACITY.md)
* [Storage](STORAGE.md)
* [Metrics](METRICS.md)
