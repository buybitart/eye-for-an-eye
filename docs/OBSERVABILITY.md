# P4 Observability

"Observability" means being able to see what a running system is doing.
This page explains the event format, and the health checks, that Eye for an
Eye offers. Read this page if you operate the sensor and want to monitor it.

## How Events Flow Through the System

Version 0.5.0 adds two separate read-only consumers to the existing
`EventRuntime`: one for the HTTP API, and one for Prometheus metrics. A
"consumer" here is a piece of code that reads events without changing them.

Capture and listener code creates `NetworkEvent` objects. The analysis
consumer runs the P2 correlation logic (matching related events together),
writes the only copy that goes into SQLite, and passes cleaned
("sanitized") records into a separate JSONL queue. P3 interaction telemetry
(data about deception interactions) follows this same path.

The API and the metrics endpoint each run in their own bounded selector
thread. A "selector thread" is a thread that watches several network
connections at once. Neither of these threads ever calls back into the
capture or deception code.

## The Event Schema (Version 3)

The event schema is the fixed shape of every event record. Version **v3**
contains these fields: `schema_version`, `event_id`, a UTC `timestamp`,
`sensor_id`, `event_type`, `src_ip`/`src_port`, `dst_ip`/`dst_port`,
`transport`, `observations`, `hypotheses`, `enrichment`, `classification`,
`confidence`, `deception`, and `limitations`.

* `observations` are measured facts.
* `hypotheses` are conclusions that still carry uncertainty.
* `classification` and `confidence` come from stored P2 behavior data.
* `deception` holds the profile name, the catalogue version, the service
  family, and limited metadata about the interaction.
* `enrichment` never rewrites the original event; it is added information,
  not a correction.

A "deserializer" is code that reads saved data back into objects. This
deserializer accepts old schema versions v1 and v2, converts them to v3, and
adds `legacy_schema_v1` or `legacy_schema_v2` into the event's `limitations`
field. Any version, type, or field it does not recognize is rejected.

The largest allowed serialized event is 4096 ASCII bytes. If an event would
be bigger, optional sections are removed and the event is marked with
`record_limit`. This is a limit on what can be sent and stored. It is not a
promise that every observation will always be kept.

## Event Types

The [`EventType`](../eye_for_an_eye/event_types.py) catalogue is the single
place that lists the fixed "wire names" (the names events use in transit
and storage) for every event type.

For backward compatibility, some internal names are kept as their old wire
names: `CONNECTION_ACCEPTED` is still sent as `connection`, `PACKET_OBSERVED`
as `network_observation`, and `FINGERPRINT_RESULT` as
`fingerprint_observation`. The other active types include:
`service_probe`, `protocol_command`, `protocol_probe`, `protocol_anomaly`,
`credential_attempt`, `correlation_result`, `deception_connection`,
`deception_response`, `connection_closed`, `enrichment_result`,
`parse_error`, `runtime_warning`, and `storage_error`.

A type being reserved in the catalogue does not mean the running system
always creates that kind of record. When the queue is already full, queue
drops are still counted by a metric, instead of adding more load to an
already overloaded queue.

## Health and Readiness

`GET /health` checks liveness: whether the process is alive and working.
It checks that the analysis worker is running, that its heartbeat (a
regular "still running" signal) is younger than 5 seconds, and that shutdown has
not started.

`GET /ready` checks readiness: whether the sensor can currently take in
new data. It checks liveness, plus whether the enabled capture, listeners,
queue, and correlation logic are available, and whether the item or byte
budget of the queue is not completely used up.

Both responses include `status`, `live`, `ready`, `components`, and
`limitations`. HTTP status code 503 is returned whenever the checked
attribute (`live` or `ready`) is false.

The possible status values are:

* `HEALTHY`: all enabled components are working correctly
* `DEGRADED`: some function is partly lost, but the system still works
* `UNAVAILABLE`: a required part of sensor intake has failed
* `DISABLED`: this component was never turned on; it is not a failure

A failure in storage, enrichment, the API, metrics, or logging lowers the
overall status, but does not by itself stop intake (accepting new events).
Listener heartbeats are also checked; if a required capture component fails,
readiness becomes false.

Worker deadlock detection here is a heartbeat-based heuristic (an
educated guess based on a missed signal), not formal proof that no deadlock
(a stuck, frozen state) exists.

## How the Health Snapshot Updates

The health snapshot updates about once per second, outside of the main
event-handling path. Long processing can delay this update; the heartbeat
lets you notice if a worker has stopped. Queue drops are counted as
accumulated loss for the whole process, so an older component's status may
still show as degraded even after it recovers. Readiness reflects the load
level from the most recent snapshot, not the current instant.

There is also an atomic status file. "Atomic" means it is written in one
safe step, so a reader never sees a half-written file. This file stores the
older P1 health and metrics data, plus a new `operational` field with `live`
and `ready` values. Use the HTTP endpoints, or the `operational` field, for
any new health checks you build. The older CLI `health` command is kept
only for compatibility, and it uses stricter P1 storage rules. The CLI
`status` command rejects the file if it is older than 5 seconds.

## What Happens When Something Fails

If the API or metrics endpoint fails to bind (start listening) on its port,
this produces a `runtime_warning` event, increases a fixed error counter,
and marks that optional component as unavailable. An invalid configuration
is rejected before the system even starts.

If SQLite cannot be opened or accessed, the system falls back to a bounded,
volatile (memory-only) mode: it keeps only the last 256 minimal records,
with no replay and no durability (no guarantee they survive a restart). A
foreign or future database schema is explicitly rejected. This kind of
deployment mistake never turns into a silent, automatic migration.

A write error does not cause endless retries. The counters
`storage_write_failures_total` and `fallback_events` show how much
persistence (permanent storage) was lost. The logger suppresses repeated
errors, so a disk error does not flood memory (RAM) with duplicate log
lines. If the shutdown time budget runs out, any events still left in the
queue are dropped, and this is counted.

## See Also

* [API](API.md)
* [Metrics](METRICS.md)
* [Logging](LOGGING.md)
* [Storage](STORAGE.md)
* [Operations](OPERATIONS.md)
