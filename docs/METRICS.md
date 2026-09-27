# Metrics

This page lists the metrics (numbers about system health and activity) that
Eye for an Eye can export. Read this page if you want to watch the sensor
with a tool like Prometheus, or if you want to know what each metric name
means.

## New Metrics in P5

Phase P5 adds these metrics:

* `storage_batches_total`: how many times the system tried to flush (write
  out) a batch of events.
* `storage_pending_events`: how many events are in a batch that has not
  been written yet.
* `events_shed_low_total`, `events_shed_low_normal_total`,
  `events_shed_high_total`: early refusals. These count events turned away
  on purpose, based on a priority system, before they even join the queue.
* `enrichment_suppressed_backpressure_total`: enrichment lookups skipped
  because the system was under too much load.

Drops caused by a hard cap, a closed queue, or shutdown are all counted in
the general `events_dropped_total` metric. The "shed" counters above only
count refusals caused by crossing a load watermark (a load level that
triggers a response). Even HIGH-priority events get no special exception
from the hard cap. None of these new metrics carry dynamic labels, Prometheus
labels are extra tags on a metric, and these metrics do not use them.

## Batching and Timing

When batch size is greater than 1, `storage_write_duration_seconds` measures
the time to flush (write out) the whole batch, not just one event.
`storage_writes_total` still counts each accepted record on its own.

The handler histogram (a metric that tracks how long something takes) shows
the analysis and flush work for the current incoming event. It does not show
the full wait time until one specific record is safely durable (saved to
disk in a way that survives a crash). By default, batch size is 1, so the
older, simpler meaning of this metric still applies.

## The Metrics Endpoint

`GET /metrics` is served on its own loopback port, `8778`. "Loopback" means
the port only answers requests from the same machine, using address
`127.0.0.1`. It returns data in Prometheus text format version 0.0.4, and
every metric name starts with the prefix `e4e_`.

This endpoint is off by default. See [API](API.md) for how to turn it on and
configure it. The format includes a `TYPE` line and plain numeric samples.
Metric names are fixed in advance, and none of them carry labels. This means
sources, event IDs, credentials, URLs, and ASNs (Autonomous System Numbers,
which identify networks on the internet) never create new, per-value metric
series.

See the [Prometheus exposition
specification](https://prometheus.io/docs/instrumenting/exposition_formats/)
for the full format.

```yaml
scrape_configs:
  - job_name: eye-for-an-eye
    scrape_interval: 5s
    scrape_timeout: 2s
    static_configs:
      - targets: ["127.0.0.1:8778"]
    # If api.token_file is set, also add authorization.credentials_file
    # pointing to a protected token file inside your Prometheus environment.
```

The loopback address belongs to the network namespace of the process doing
the scraping (collecting the metrics). If your scraper runs in a different
container, you need a proxy or network setup made just for this. Publishing
a host port does not make a container's loopback address reachable
from outside that container.

## Metric Families

The table below omits the `e4e_` prefix for readability. Add it back when
using the real metric name.

| Family without e4e_ | Meaning |
| --- | --- |
| connections_accepted_total / rejected_total / active | Real connections seen by the sensor's `SelectorServer`. Operational HTTP connections (to the API or metrics endpoint) are not counted here |
| packets_received_total | Packet observations created by analysis. Not the same as a physical network-card packet count |
| packet_parse_errors_total | Errors from the attached capture analyzer |
| events_created_total / events_dropped_total | Base and derived records created / events dropped because the queue said "drop the newest one", plus records left undrained at shutdown |
| queue_depth / queue_bytes | The current size of the bounded queue |
| source_state_entries / cache_entries / cache_evictions_total | P2 per-source state, and the bounded caches attached to it |
| fingerprint_results_total / fingerprint_errors_total | Fingerprinting telemetry, and unavailable-or-error results |
| correlation_results_total | Derived P2 records offered for storage |
| deception_connections_total / responses_total / response_bytes_total | P3 interaction records emitted, and the real response length in bytes |
| enrichment_requests_total / enrichment_failures_total | Enrichment provider jobs started / unavailable enrichment results |
| storage_writes_total / storage_write_failures_total | Accepted write outcomes / failed writes or unavailable-storage fallback |
| storage_retained_events / storage_bytes / storage_pressure | Rows kept in storage; total bytes across the database, WAL, and SHM files (SQLite's write-ahead log and shared-memory files); pressure level, where 0 = NORMAL, 1 = WARNING, 2 = CRITICAL |
| log_suppressed_total / log_dropped_total / log_errors_total | Repeated errors hidden by suppression / drops from sampling, a full queue, or disk problems / writer or start-up errors |
| api_requests_total / api_errors_total / metrics_errors_total | Parsed API requests; storage, query, or start-up errors; metrics start-up errors |

## Timing Metrics

Timings are shown as pairs: `handler_duration_seconds_sum` /
`handler_duration_seconds_count`, `enrichment_duration_seconds_sum` /
`_count`, and `storage_write_duration_seconds_sum` / `_count`. Each pair
gives a running total of time, and a running count of observations. There
are no quantiles or buckets (no percentile breakdowns). To get an average
duration over a time window, divide `rate(sum)` by `rate(count)`.

The handler timing includes analysis, storage, and putting the event on the
logger's queue. It does not include the whole life of a TCP connection.
Storage timing includes the time to hit a bounded refusal, if one happens.
Enrichment timing only covers completed worker jobs. All durations are
measured with a monotonic clock. A clock that only ever moves forward, so
it cannot be fooled by the system clock being changed.

## Older Metric Names (Aliases)

These P1 metric names are kept as aliases, so older dashboards keep
working: `storage_written_total`, `storage_failures_total`,
`handler_latency_seconds`, `enrichment_latency_seconds`,
`parse_errors_total`, and `response_bytes_total`.

The event counter counts up to the point where an event is admitted to the
queue. A telemetry drop after that point does not mean the number of wire
packets (raw network packets) is unknown. A failed storage write increases
its own separate counter. It is not counted as a queue drop. Logs can be
sampled (only some kept) with zero loss on the SQLite side.

## General Notes

Counters reset to zero on restart. The running system publishes gauges
(point-in-time values) about once per second. The storage row-count and
byte-count gauges are updated by the writer after each write and after
maintenance work. The SQL and HTTP endpoints never compute new sets of
source labels on their own. In short: these counters are useful signals, but
they are not a durable ledger (a permanent record) of everything that ever
happened.

## What to Watch, as an Operator

Watch for:

* growth in `events_dropped_total`, `storage_write_failures_total`, or
  `log_errors_total`
* sustained (long-lasting) high queue use
* `storage_pressure` greater than 0
* readiness reported as `false`

Exact thresholds and SLOs (Service Level Objectives, target numbers for how
well the system should perform) need to come from a separate P5
measurement exercise. That measurement has not been run yet.

## See Also

* [API](API.md)
* [Observability](OBSERVABILITY.md)
* [Storage](STORAGE.md)
* [Logging](LOGGING.md)
