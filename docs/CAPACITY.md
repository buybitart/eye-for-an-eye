# Capacity and Internal Targets

This page lists how much load was actually measured, and what was **not**
measured. Read it before you plan a deployment size. Every number here comes
from one Windows laptop, so treat it as a starting point, not a promise.

## The Measuring Machine

Intel i5-1135G7, 4 physical / 8 logical cores, about 15.7 GiB RAM.

Installed RAM is not the same as the memory the sensor uses. The workloads were
not pinned to 1, 2 or 4 vCPUs. So you cannot scale these numbers up or down by
cores or by GiB. That kind of straight-line guess is not supported here.

## What Was Measured

| Placement / workload | What was established |
|---|---|
| This host, in-memory SYN pipeline, 16 sources | 505.7–512.9 packets/s in short runs, median p95 2.905 ms |
| This host, scanner correlation, 4 repeated sources | 1888–1912 updates/s at 64 samples per source; this is not a figure for the 256-sample default |
| This host, standalone SQLite | Single row about 180–186 rows/s; batch 8 about 1232–1298 rows/s; batch 32 about 3394–3499 rows/s |
| This host, finite TCP listener | Configured 128 concurrent sockets, 8 generator workers; 10 / 100 / 128 idle levels checked |
| This host, mixed runtime soak | 60 offered events/s for 60 s, 16 sources, correlation + SQLite + API + metrics; 3600 accepted, 0 queue or storage failures |
| 1 vCPU / 1 GiB | Not measured; no events/s or connection count is promised |
| 2 vCPU / 4 GiB | Not measured |
| 4 vCPU / 8 GiB | Not measured; this laptop is not the same as a VM of that size |

## A Starting Working Point

On a similar host, **60 base events per second** is a working point confirmed by
a short soak, with margin against the individual stages. It is not the upper
capacity and it is not a long-term SLA.

Write batching of 8 events with a 10 ms delay makes sense for write-heavy load.
The default stays at **1**. Batching means some events wait in memory, so you
have to decide how much pending data you can afford to lose.

## One Input Is Not One Row

Each incoming packet or event can create several stored records.

A rough rule: the sustainable base rate is limited by the smaller of the
measured parser/analysis rate and the writer rows/s, divided by the real number
of records per input.

In the P4 operational workload, 400 base events produced 432 rows. That is a
factor of **1.08**. Other packet workloads expand by a different factor. Do not
put a raw rows/s number in where you meant packets/s.

## Memory

### Correlation

| Inputs | RSS | Retained sources |
| ---: | ---: | ---: |
| 1k | 30.15 MB | 1000 |
| 10k | 42.16 MB | 10000 |
| 50k | 43.41 MB | 10000 |
| 100k | 43.78 MB | 10000 |

After 100k inputs there were 90k evictions. Accounted source bytes settled near
**15.53 MB**. For a sparse source with one sample that is about 1.55 kB
accounted per source. A source filled to 64 or 256 samples costs more and runs
into the total byte cap. This is **not** the RSS cost of any source you like.

### Queues

A burst of 64 held about 34.2 kB of accounted serialized data, and 236 of 300
inputs were rejected, as expected.

Production queue defaults are 1024 events / 4 MiB. Store pending is at most 32
records × 4096 serialized bytes, plus bounded Python objects.

The correlation 32 MiB figure is an **accounted value budget**. It does not
promise that the whole process stays inside 32 MiB of RSS. Importing Scapy
raises packet-worker RSS to roughly 58 MB.

### Idle TCP

The raw idle TCP JSON has the RSS delta per connection at each level. The
generator sockets live in the same process, and the allocator keeps its arenas,
so that delta is not the clean cost of one server connection. The practical
limit checked here is **128**. Levels of 500 and 1000 were not run.

### The 60-second Soak

* Last 21 samples: RSS 40.8–43.2 MB, queue 0 on the per-second snapshots, 5
  threads while running, storage holding 2000 rows.
* After shutdown and garbage collection: RSS 40.0 MB, 171 handles, 1 thread.
* In 6 separate lifecycle runs the post-GC count stayed at 170 handles, with RSS
  37.54–37.58 MB after warm-up.

The difference of one handle between the two scenarios is fine: the soak has a
second endpoint. A cold count of 157–159 is not a steady baseline.

## Targets for the Next Run of the Same Workload

| Internal target | Basis and limit |
|---|---|
| Offline SYN pipeline p95 <= 3.5 ms | 2.9 ms was seen; excludes disk and network; 64 samples per source |
| Fast single loopback listener p99 <= 10 ms | Short listener-only workload; check parallel and overload separately |
| API mixed, small DB, p95 <= 35 ms | Covers all stored ordinary and replay runs, including the 25.6 ms outlier |
| 50k-row first page p95 <= 100 ms | 73.5 ms measured; the default query deadline still applies |
| No queue or storage drops at 60 base events/s | Done for 60 s; a 15–59 minute deployment soak is still needed |
| Listener shutdown <= 2 s, runtime <= configured 10 s | Checked with 128 active sockets (~0.03 s) and the mixed soak (~0.17 s); a stuck kernel IO is not a realtime guarantee |

## Estimating a Burst

With a backlog of Q, an arrival rate of λ and a measured drain rate of μ, the
queue fills in about `Q / (λ − μ)` seconds when λ is bigger than μ.

Count both queue budgets (events and bytes) and the record expansion, not just
the number of slots. The opt-in LOW/NORMAL reserve kicks in before the hard cap,
so watch the counters and the admission failures.

## Still Unverified

Long soak runs, live capture, Linux network namespaces and small VM profiles
are all separate checks. None of them is covered by the numbers above.

## See Also

* [Benchmarks: how to repeat them](BENCHMARKING.md)
* [Performance](PERFORMANCE.md)
* [Limitations](LIMITATIONS.md)
