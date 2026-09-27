# Benchmarks: How to Repeat Them (P5)

This page says how the P5 speed measurements were made and what they do and do
not prove. Read it if you want to repeat the numbers or check them yourself.
All numbers come from **one laptop**. They are not a promise for your machine.

## Order of Work

1. Run the unchanged P4 test suite: **193 passed, 2 skipped, 154 subtests**.
2. Run the P4 operational sanity check.
3. Only then: profile, change, verify.

There is no git directory in this tree. Before any change, the SHA256 and the
content of **163 files** were saved to a local `.p5-check/baseline.json`. A
portable copy of the hashes is in
the baseline manifest that `python -m benchmarks.run` writes into `benchmarks/results/`, which is generated rather than published.

The starting production SHA256 was
`20e0de6e9aee3cd5021091f32a58499f0631425b91630657d6fa264d2a61d4ee`. This is a
snapshot of files. It is not a made-up commit id.

## The Machine

| Item | Value |
| --- | --- |
| OS | Windows 11, build 22635 |
| Python | CPython 3.12.14 |
| CPU | Intel i5-1135G7 @ 2.40 GHz, 4 physical / 8 logical cores |
| RAM | 16,895,107,072 bytes |
| Libraries | Scapy 2.7.0, ipwhois 1.3.0, maxminddb 3.1.1 |

Every other version is written in each JSON result file.

SQLite used WAL with `synchronous=FULL` and 4096-byte pages. (SQLite is the
small file database. WAL is its write-ahead log, a second file that holds new
writes.) Kernel and socket options were not changed.

A read-only `netsh` snapshot is stored in the manifest: RSS enabled, autotuning
normal, ECN and timestamps disabled, RTO 1000 ms, SYN retries 4.

Not tested on this host: `TCP_DEFER_ACCEPT`, `epoll`, Linux `sysctl` values and
Unix file-descriptor limits. Windows handle counts include more object types
than sockets. Context-switch counters were not collected.

Commands and limits are in the [benchmarks README](../benchmarks/README.md).
Seed 20260908, catalogue v2. Private and TEST-NET addresses are used as
synthetic metadata. Sockets bind only to `127.0.0.1`. No internet, no firewall
and no live capture were used.

## The Workload Profiles

| Profile | What actually ran |
|---|---|
| A normal | TCP, 10 requests per second with pacing; on localhost this is one real source |
| B scanner | 4 synthetic sources, 128 destination ports; short connections and 300 correlation updates |
| C distributed | 100/1k/10k/50k/100k events; up to 50k different source metadata, retained cap 10k |
| D idle | 10, 100, 128 sockets; configured cap 128, with no automatic step to 500/1000 |
| E malformed | Short IP/TCP, binary FSM input; probe near-match cases up to 1 MiB of DB payload |
| F conversation | HTTP request, FTP 5 commands, SSH identification; all catalogue profiles are called, and the table shows the last profile of each family |
| G mixed | 400 paced base events plus derived results, WAL writer, 2 API clients, 1 scraper; separately a 250-row endpoint and a 50k-row reader |

## What Each Measurement Really Measures

**Offline packet loop.** It decodes 64 pre-built SYN byte sequences and runs
`PacketObserver` → fingerprint events → bounded serialization → correlation. It
measures 300 packets (1000 in the full run) from 16 sources.

Scapy p0f runs by default with no external database. Real match, no-match and
fuzzy cases are tested separately against a synthetic database written for this
project. The fuzzy TTL-distance fixture checks the returned status, not the
identity of a real operating system. ACK and UDP return error or UNKNOWN, as the
adapter contract says. The cost of an external fingerprint catalogue is **not**
established.

**Protocol conversations per second** means building and running a finite state
machine in memory. It is **not** wire connections per second. The loopback
listener is measured separately.

**Provider measurements** include process spawn and timeout. `core_emit` means
admission into the queue, not durable throughput.

**Storage.** `SQL_candidates` was an early experiment made before production
batching. It has no full error or retention contract. The final
`production_batches` figure measures the real `SQLiteStore.write_batch`.

## How Comparable the Numbers Are

Packet parsing, scanner correlation and production storage each got **3
unprofiled runs before and after**, and the median is reported.

* Baseline packet throughput: 421.5–429.1 per second.
* Final packet throughput: 505.7–512.9 per second.

For all other modules there was a **single run**. Those are exploratory
evidence. No confidence interval and no universal speed-up factor is claimed.

### The API Outlier

The first final API mixed p95 was **25.615 ms**, which is worse than the initial
baseline of **9.216 ms**. That artifact was kept, not deleted.

A second check alternated the exact old source tree (its hash matched) with the
current tree: P4 gave 11.460 / 8.305 ms and P5 gave 7.389 / 7.569 ms. This did
not confirm a stable regression.

The editable distribution metadata seen during replay refers to the installed
P5 package. The `executed_version` and `source_sha256` fields show which tree
really ran.

### The Excluded Large-table Run

The first `final-api_large.json` is marked `valid=false`. A wrong fixture
timestamp made all queries return nothing. It is excluded from the report.

The fixed `final-api_large-50k.json` checks that pages are not empty and stores
real query plans. It is extra coverage. There is **no** matching pre-P5
large-table measurement. Reader and API indexes were not changed.

### Profiles

Profile files hold the top 30 entries by cumulative time, self time and call
count. `cProfile` shows hotspots but adds its own overhead. The allocation
sample of 32 packets is measured separately from throughput. See the
[Python profiling guidance](https://docs.python.org/3.12/library/profile.html).

## Regression Checks

The stable smoke test checks budgets, repeatability, atomic rollback, state
copying, the queue and shutdown. It makes **no** throughput assertions. The full
regression suite runs after every optimization.

The offline `report --check` looks only at repeated main workloads:

| Check | Threshold |
| --- | --- |
| Throughput | not below -15% |
| p95 latency | not above +20% |
| Packet RSS | not above +15% |

These are **investigation thresholds**, chosen with margin against the spread we
see today. They are not an SLA and not a CI gate that fails on noise.

For a deployment: repeat at least 3 runs on the same disk type, the same CPU and
power profile, and the same Python. Do not run benchmarks in parallel. Check
that the workload, the configuration and the source hashes all match.

If a value goes past a threshold: keep the failing run, alternate the old and
new versions, then profile only the part you confirmed.

## Long Runs (Soak)

Soak scripts exist for 15 to 59 minutes. What actually ran here was **40 seconds
and 60 seconds**.

Compare the state after the correlation buffer is filled (16 × 64 samples) and
after 2k-row retention. The script saves RSS, handles, threads, queue depth,
database size and latency once per second, both before shutdown and after
garbage collection.

Growth in an RSS cache and memory kept by the allocator are **not** a leak. And
a stable short run does **not** prove there is no leak over many hours.

## The Autonomous Decision Path (P15.5R §23)

`--case autonomous` answers one question: what does attaching the P15 decision
stack cost the runtime that carries it? Four configurations run back to back in
one child over the same 3,000-event workload, so the only thing that differs is
how much of the stack is attached:

| Case | What is attached |
|---|---|
| `legacy` | autonomy off: `DecisionFusion` then `PolicyGuard` |
| `authority` | the P15 authority, nothing persisted |
| `journal` | ... and the canonical decision journal |
| `journal_and_export` | ... and the analytic shadow export |

No enforcer is attached in any of them. Measuring one would measure process
spawn on this machine and nothing about the decision path.

### Two Decision Densities, Because One Number Would Hide the Answer

The autonomous path runs once per decision **window**, not once per packet:
`DecisionEngine.observe` refuses to evaluate a source again until
`decision.interval_ms` has passed. A single average over a realistic stream
therefore hides both the per-packet cost (almost nothing) and the per-decision
cost (not nothing).

**`interval_ms = 0`**: every event is a decision window. Deliberately the
densest possible stream and not a realistic one. 3,000 events, 3,000 decisions:

| Case | seconds | events/s | p50 ms | p95 ms | vs legacy | added ms/decision |
|---|---:|---:|---:|---:|---:|---:|
| `legacy` | 4.348 | 690.0 | 1.471 | 1.564 | 1.000x | -- |
| `authority` | 5.630 | 532.8 | 1.904 | 1.994 | 1.295x | 0.427 |
| `journal` | 6.220 | 482.3 | 2.105 | 2.192 | 1.431x | 0.624 |
| `journal_and_export` | 6.434 | 466.3 | 2.173 | 2.271 | 1.480x | 0.695 |

**The shipped 2,000 ms interval**: 3,000 events, 8 decisions. This is what a
stream at this event rate pays, and it is not a claim about any other event
rate:

| Case | seconds | events/s | p50 ms | p95 ms | vs legacy |
|---|---:|---:|---:|---:|---:|
| `legacy` | 2.684 | 1117.8 | 0.912 | 0.976 | 1.000x |
| `authority` | 2.707 | 1108.1 | 0.912 | 0.980 | 1.009x |
| `journal` | 2.712 | 1106.4 | 0.915 | 0.988 | 1.010x |
| `journal_and_export` | 2.703 | 1110.0 | 0.913 | 0.983 | 1.007x |

A per-decision figure is withheld below 100 decisions: the difference of two
wall-clock totals divided by 8 is run-to-run variance wearing a unit.

So the complete autonomous path costs about **0.7 ms per decision** here, and at
the shipped interval the difference against the non-autonomous path sits inside
the noise. Both numbers are ALLOW-path costs: no window in this workload reached
TEMP_BLOCK, and a block is journalled a second time after the enforcement
attempt.

### Where the Time Goes

A profiled run (`--profile`, which writes its profile JSON under `reports/`)
puts `pipeline.decide` at roughly 8% of cumulative time. The dominant cost on
this path is `TTLCache._size` (the correlation engine's byte accounting), not
the decision stack. Profiled throughput is never the unprofiled baseline.

### The Machine These Numbers Came From

| Item | Value |
| --- | --- |
| OS | Linux-6.18.44-fc-v37-x86_64-with-glibc2.39 |
| Python | 3.12.3 |
| CPU | Intel(R) Xeon(R) Processor @ 2.80GHz, 2 logical |
| RAM | 8,422,264,832 bytes |

Raw JSON: [../reports/P15_5R_PERFORMANCE.json](../reports/P15_5R_PERFORMANCE.json).
Repeat with:

~~~text
python -m benchmarks.run --case autonomous --full --output <your-file>.json
python -m benchmarks.run --case autonomous --profile --output <your-profile>.json
~~~

## See Also

* [Capacity and internal targets](CAPACITY.md)
* [Performance](PERFORMANCE.md)
* [Backpressure](BACKPRESSURE.md)
* [Limitations](LIMITATIONS.md)
