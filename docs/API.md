# Read-only HTTP API

This page explains the local HTTP API (phase P4). The API only reads data. It
can never change a setting, start a scan or touch a firewall. Read this page if
you want to look at stored events with `curl` or a small script.

## What it is built from

The server uses only the Python standard library. It uses `selectors`, which is
a built-in way to watch many sockets at once. No web framework was added.

One API thread runs short requests, one after another. A second thread serves
the metrics endpoint. Both endpoints are **off by default**. Both bind to
`127.0.0.1`, so only your own machine can reach them.

## Turn it on

```toml
[storage]
enabled = true
path = "events.sqlite3"
[api]
enabled = true
bind_address = "127.0.0.1"
port = 8777
docs_enabled = false
redact_ip = false
[metrics]
enabled = true
bind_address = "127.0.0.1"
port = 8778
```

```text
python -m eye_for_an_eye proto --config sensor.toml
curl --fail http://127.0.0.1:8777/health
curl --fail http://127.0.0.1:8777/ready
curl --fail "http://127.0.0.1:8777/api/v1/events?limit=20&transport=tcp"
```

## The endpoints

All of them are `GET`.

| GET endpoint | Response |
| --- | --- |
| /health | Liveness, component states; 503 if live=false |
| /ready | Sensor intake readiness; 503 if ready=false |
| /version | Application/event/catalogue/DB versions; configured data mtime/size, with no secret paths |
| /api/v1/events | EventResponse page, next_cursor, window |
| /api/v1/events/{event_id} | One sanitized event; 404 if it is not there |
| /api/v1/sources | SourceSummary page, bounded aggregates, partial, next_cursor |
| /api/v1/sources/{source} | Summary for that IP; 404 if the window holds no events |
| /api/v1/detections | Stored classification/score/confidence/reasons/window/supporting_event_ids/limitations |
| /api/v1/stats | Events last minute/hour, top 10 ports, type/classification counts, queue drops, storage size, fallback count |

## How to read the numbers

* The source classification comes from the **last stored P2 classification** in
  the chosen sample. The API does not run correlation again.
* A score is **not** a probability. An IP address is **not** an identity.
* If there is not enough data, `classification` is `null` and `confidence` is
  `UNKNOWN`.
* Runtime and unknown fields are left out of the list of IP sources.

## Limits

| Setting | Default | Hard ceiling / behaviour |
| --- | --- | --- |
| api.max_page_size | 100; a request with no limit returns up to 20 | 500 |
| api.max_response_bytes | 65536 | 65536, HTTP headers included |
| api.max_query_seconds | 0.2 s | 1 s; SQLite progress cancellation |
| api.max_range_seconds | 604800 s | 7 days; the default query window is 1 hour |
| api.max_scan_rows | 5000 | 10000 for aggregates |
| api.requests_per_second | 20 | 1000; token bucket plus accept admission |
| api.max_connections | 16 | 32; one request per connection |
| HTTP request | 8192 bytes | URI 2048, up to 12 query fields |
| Connection deadlines | first byte/idle 1 s, total 2 s | They do not replace the SQL deadline; the handler runs on the API thread |

SQLite is the small file database that stores events. WAL is its write-ahead
log: a second file that holds new writes.

## Filters and paging

Filters you can use:

| Filter | Accepted value |
| --- | --- |
| from / to | ISO8601 with a timezone |
| event_type | Wire value from the catalogue |
| transport | tcp / udp / icmp / icmpv6 / other / unknown |
| classification | P2 label |
| confidence | UNKNOWN / LOW / MEDIUM / HIGH |
| source | IP literal |
| destination_port | Integer |

An unknown or repeated parameter, a negative cursor, a page that is too big or
a window that is too long all return **400**.

Events and detections come back in reverse ingestion order. To get the next
page, send `next_cursor` back as `cursor` and keep the same `from` and `to`. A
page can be smaller than `limit` because of the byte budget. One single record
that does not fit in the envelope returns **413**.

## What "partial" means

Source summaries only aggregate the newest `max_scan_rows` rows in the window.
`partial=true` means the counts are **lower bounds**. Paging walks the sources
of that bounded sample, not the whole history in the database. The source
cursor is separate and is opaque to the client.

With `redact_ip=true` the API uses random handles with a TTL of 300 s, up to 512
entries or 1 MiB. An expired cursor returns 400. Data can change between
requests because of new writes or retention, so the sample can change too. There
is no snapshot isolation between pages.

Stats are marked partial as well. The minute and hour counts follow the chosen
window and filters. If the client narrows `from`, the missing rows are not
counted. Live gauges are a snapshot, so they lag a little. The API does not hold
one long reader transaction across requests.

## Access and HTTP rules

* `GET` only. HTTP/1.0 or HTTP/1.1. Origin-form URL. No request body, no
  keep-alive, no pipelining.
* CORS is off. An `Origin` header is rejected. There is no wildcard CORS.
* `Host` must be the configured bind literal or localhost. This stops a browser
  from reaching the API through a made-up DNS name (DNS rebinding).
* A reverse proxy must rewrite `Host` to the upstream loopback endpoint and
  remove the browser `Origin` only after it has checked access itself.

Optional `api.token_file` holds 32–256 printable bytes with no spaces. Then
`Authorization: Bearer` protects both the API and metrics. The check uses
constant-time comparison. No cookies are used. The token never goes into a URL
or a log. Store the file as a protected deployment secret and limit its ACL.
Changing the token needs a restart.

TLS, mTLS, OIDC and RBAC are **not** part of P4. Use an external proxy for them.

Binding to a non-loopback address needs `allow_insecure_non_loopback=true` in
that section and prints a startup warning. That flag only allows plain HTTP on
purpose. It does not set up TLS. Do not publish operational ports as deception
listeners.

IP masking hides the last 8 IPv4 bits or the last 64 IPv6 bits in the response,
including addresses inside nested strings. It is a limited view. It is not a
guarantee of anonymity and it does not protect the SQLite file.

## Errors

| Situation | Code |
| --- | --- |
| Storage disabled or unavailable, or SQL deadline hit | 503 |
| Missing or wrong token | 401 |
| Bad Origin or Host | 403 |
| Any method except GET | 405 |
| Rate limit | 429 |
| Response too large | 413 |
| Bad query | 400 |

Error bodies use a fixed error code. They never contain a traceback, SQL, a
config dump or a secret path. The number of accepted sockets is capped, so
under overload the server may close the TCP connection before any HTTP
response.

## OpenAPI

`api.docs_enabled=true` serves a small `/openapi.json` with the list of routes.
There is no interactive UI. It is not a full generated schema for an SDK. The
explicit dataclass models live in
[models.py](../eye_for_an_eye/api/models.py).
