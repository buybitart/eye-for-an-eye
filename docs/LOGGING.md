# Structured logging and redaction

This page explains how Eye for an Eye writes log lines, and how it removes
secrets from those lines before they are saved. Read this page if you run the
sensor and want to know what goes into your logs.

## How logging works

The `EventLogger` writes log lines in JSONL format. JSONL means "JSON Lines":
one JSON object per line, one line per event. Lines are placed on a bounded
queue first. A "bounded queue" is a waiting line with a fixed maximum size, so
it cannot grow forever. A separate background thread, called the daemon
writer, takes lines off the queue and writes them to disk.

Every line has these fields:

* a UTC timestamp
* a level (for example, info or warning)
* a component name
* an event
* the event schema version, which is `v3` today

Right now, the component field for core events is always `sensor`. The exact
part of the code that produced the event is shown by two other fields instead:
`event_type` and `metadata`.

Each line is limited to 4096 ASCII bytes. The newline character at the end is
added separately and does not count toward that limit. If writing to stdout
(the standard output stream) fails or hangs, this does not block new events
from coming in. When the logger shuts down, it checks with a time limit
("bounded close") and reports if the writer thread is stuck.

## What gets removed (redaction)

"Redaction" means removing or hiding sensitive data before it is stored or
shown. One shared piece of code does this job:
[redaction.py](../eye_for_an_eye/security/redaction.py). It runs at four
points: when an event is turned into text, when it is saved to SQLite (a
small file-based database), when it is sent back through the API, and when it
is written to the log.

By field name, this code removes: `payload`, `raw`, `text`, `credential`,
`authorization`, `cookie`, `password`, `passwd`, `token`, `secret`,
`session`, and `api_key`. The only fields that are kept, on purpose, are
typed and known to be safe: `payload_length`, `credential_attempts`, and
`credential_like_attempt`. The system never stores a full payload (the raw
data sent by a client) or a full password.

There is also a P3 "sanitized preview" feature. It is opt-in, meaning it is
off unless you turn it on, and it follows its own extra P3 privacy policy.

## Limits on redaction

Field names are not the only safety check. The logger also scans the text of
each string for markers such as `Authorization`, `Cookie`, `Set-Cookie`,
`password`, `passwd`, `api_key`, `secret`, `token`, `session`, and
JWT-like values. A JWT is a common type of access token. If the logger finds
one of these markers, it replaces the whole value with `[redacted]`.

Other limits keep log lines small and safe:

* A field can hold at most 256 characters.
* A key name can hold at most 64 characters.
* A list or object can hold at most 24 items per level.
* Nesting can go at most 5 levels deep.

If a value goes over these limits, it is marked `[truncated]` or
`[depth limit]` instead of being cut silently. Binary data (data that is not
plain text) is replaced with `[bytes omitted]`.

The JSON writer uses a setting called `ensure_ascii`. This escapes control
characters, so an attacker cannot use them to fake a second log line or to
send a hidden terminal command through the logs.

This redaction is heuristic, meaning it works from patterns, not perfect
understanding. It cannot recognize every possible secret if there is no
context to hint at it. Because of this, code that produces events must only
send the metadata fields that are allowed, and must never put a credential
into a new, unlisted field. The validated event format only carries safe
things: IP addresses, limited ID values, and timestamps. Never pass full
configuration files or environment variables into an event's observations.

## Flood control (flood budget)

```toml
[logging]
file = ""
queue_size = 512
events_per_second = 100.0
per_source_per_second = 5.0
per_event_type_per_second = 100.0
repeated_window = 1.0
max_bytes = 5000000
backups = 2
min_free_bytes = 1048576
```

The logger uses "token buckets" to limit how fast events can be logged. A
token bucket is a simple rate limiter: it allows a burst of events at first,
then settles into a steady rate. There are separate limits for the whole
system, for each source, and for each event type.

There are two small caches to track repeats:

* the source cache holds up to 10,000 entries, or 4 MiB, whichever comes
  first
* the suppression cache holds up to 1,024 entries, or 1 MiB

If the same `parse_error`, `runtime_warning`, or `storage_error` repeats for
the same source, it is suppressed (hidden after the first one) during the
`repeated_window`. This also applies to sanitized observations. The event ID
and timestamp do not stop this grouping — they are ignored for this check.
The counts `suppressed_count` and the exported metric `log_suppressed_total`
track how many repeats were hidden. An event type the system does not
recognize is rejected.

Rate sampling only affects the JSONL log file. It does not affect what is
saved to SQLite. If the log queue is full, new events are dropped.

Before writing, the file writer checks how much free disk space is left. If
free space is below `min_free_bytes`, the line is skipped, and this is
counted under `disk_pressure_drops`.

The `max_bytes` and `backups` settings limit log rotation. Rotation means
that once a file reaches `max_bytes`, it is renamed and a new file is
started; only `backups` old files are kept. The total disk budget is roughly
`(backups + 1) * max_bytes`, plus the size of one extra long line per file.
There is no guarantee of free space if another program is also writing to
the same disk at the same time.

## Recommended setup

If you run the sensor under systemd (the Linux service manager), leave
`file = ""`. This sends output to journald, systemd's own logging service,
instead of a file. Let journald's own retention and quota settings, chosen
by the operator, control storage. The provided templates already send
stdout and stderr to the journal.

If you run the sensor in a container, send output to stdout and let your
container runtime's log rotation and storage driver handle it. Use a
separate storage volume for the SQLite database. The application itself
does not set host journal quotas or container log quotas — that is the
operator's job.

If you run the sensor by itself, without systemd or a container, setting
`file` turns on a `RotatingFileHandler`. This writes UTF-8 text, keeps files
under the maximum size, and keeps a limited number of backups. You, the
operator, must prepare the directory and its permissions (its access
control list, or ACL) yourself — the application does not create these
permissions automatically.

Existing P1 error details, and the newer fixed error messages, never include
the raw request, a bearer token, the persistent deception key, or any
provider credentials.

## See also

* [Observability](OBSERVABILITY.md)
* [Metrics](METRICS.md)
* [Storage](STORAGE.md)
* [Privacy](PRIVACY.md)
