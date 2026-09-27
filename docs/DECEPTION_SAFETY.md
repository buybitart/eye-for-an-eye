# Deception Safety and Validation

This page explains the safety limits built into the deception feature (a fake service that talks to attackers), and how those limits are tested. Read this before you enable deception anywhere outside a lab.

## What Deception Does and Does Not Do

The deception system watches the incoming client conversation. It only sends back reviewed, limited-length protocol responses, over an accepted TCP socket (a network connection). It never does any of the following: crashing the scanner, exploiting the client, causing remote out-of-memory or CPU exhaustion, sending infinite data streams, sending malicious files, calling back to the client, or "hacking back." This stage does not add a tarpit (a trick that deliberately slows down a connection to waste an attacker's time). An older experimental "garbage" feature is kept separate from the real services. It stays turned OFF, only works on loopback (the local computer only), and has its own final, global limits.

## Enforced Limits

The global limits from an earlier stage stay in place: 256 TCP connections total, 8 connections per source by default, a rate limit on accepting new connections, a size-limited event queue and SQLite database (a small file-based database), and a total time budget for shutdown. Each session uses whichever is smaller: the profile's limit or the global limit, for requests, responses, and time. Response bytes are counted as a running total, including the greeting message. If a send is only partly done, the system remembers where it stopped and does not resend the same data twice. FTP messages are limited to 12 lines, HTTP and SSH to 1. "Transition budgets" (how many protocol steps are allowed) are limited to 40 for standard profiles.

An optional, predictable delay ("jitter") is OFF by default. If turned on, it adds 10 to 150 milliseconds. It never extends the idle or total time limits. When a socket is ready to write but delayed, the system does not "busy spin" (loop wastefully checking again and again). Instead it waits, and can cancel that wait, for at most 10 milliseconds per loop. There is no multi-minute hold, and no background worker thread per client.

UDP (a network protocol) stays receive-only — the system never calls `sendto` to answer. If someone sets `udp_responses=true`, the config is rejected. This stage never turns on UDP responses, even in the lab. There is no need to worry about an "amplification ratio" (attackers using a service to make small requests turn into big replies), because the application's response size for UDP is always zero.

Real ports and management ports are not allowed for decoy services to bind to. When a redirect is required, the system never falls back to a made-up destination. The Linux IPv4 feature `SO_ORIGINAL_DST` (it recovers the real destination address after a redirect) has been tested with mock (fake, simulated) tests only. Real Linux behavior, IPv6/UDP redirects, and working together with real nftables (Linux's firewall system) are **NOT VERIFIED IN CURRENT ENVIRONMENT**. Required redirects for IPv6 and UDP are clearly not supported.

## Payload Privacy

A "secret pattern" layer scans only a limited prefix (start) or line of data, looking for markers like Authorization headers, cookies, passwords, tokens, API keys, and USER/PASS/AUTH-style text. This is only a rough guess ("heuristic") that an attempt happened. It is not proof that real login details were sent.

Raw bytes never go into the telemetry (the collected monitoring data), even when no pattern matches. A data "preview" feature is OFF by default. An optional `safe_preview` setting only shows a known command type (class), plus a fixed marker showing that something was left out. All arguments, URLs, headers, bodies, and client identification strings are excluded. Binary input is never turned into free-form log text. Unknown commands are logged only as UNKNOWN, UNSUPPORTED, or INVALID, without the client's original text.

By default, the USER field is shown as `[redacted]` (hidden). An optional setting can hash the username using HMAC-SHA256 (a keyed hash), in its own separate context, with a secret key that stays the same over time. This hash is a sensitive pseudonym (a stand-in name) — it is not proof of someone's real identity. Password (PASS) content is never hashed and never stored. When a frame is recognized as credential-like, the system does not create a probe digest for it. Other, limited probes may get a short-lived, process-local HMAC value, used only to spot repetition, as described in [CORRELATION.md](CORRELATION.md).

## Incomplete Requests and Memory

Bytes from an incomplete request stay briefly in a small memory buffer, until the data is parsed or the connection closes. Python (the programming language used) does not guarantee secure ("cryptographic") memory erasure. The operator (the person running the system) must separately protect core dumps, process memory, and endpoint metadata. The synthetic (fake, made-up) profile never creates real credentials or honeytokens (fake bait accounts), and never gives access to any real system.

## Tests and How to Reproduce Them

```text
uv run --locked --all-extras pytest -q -p no:cacheprovider
uv run --locked --all-extras ruff check eye_for_an_eye tests benchmarks --no-cache
uv run --locked --all-extras python -B -m benchmarks.p3_deception --connections 100 --idle 100 --output benchmarks/p3-baseline.json
```

The test suite for this feature covers: real loopback HTTP, FTP, and SSH conversations; starting a fresh CLI process and restarting it; storing credential events in a temporary SQLite database without their content; parsing fragmented data, invalid lengths, and binary input; cumulative (running-total) bytes, messages, and transitions; 100 idle clients at once; a "reconnect storm" (many fast reconnects); oversized or slow clients; rejecting bad telemetry; a full event queue; a real writer stalling; steady overload and recovery; and shutdown.

A seeded (repeatable) local fuzz test generates 480 limited-size inputs, used only against our own parsers (code that reads data). While handling requests that look malicious, tests forbid the code from touching real networks, files, subprocesses, or DNS — those are all blocked (mocked) during the test. All tests finish in finite time: the loopback test server has a maximum duration, client sockets have deadlines, and threads have join deadlines. A benchmark worker is limited by a parent "watchdog" timer of 40 seconds. On Windows, a TCP EOF (end of data) or an RST (reset) on failure both count as an acceptable way to close a connection.

The benchmark (performance test) measures: connections per second; full loopback latency at the p50, p95, and p99 percentiles (including time waiting in the queue); actual response bytes sent; dropped items from the queue; connections happening at the same time; the process's CPU use, RSS (real memory use), handle count, and thread count; and shutdown time. Separate `handler_latency` fields measure 100 calls to `ProtocolSession.feed` for HTTP, FTP, and SSH, without counting setup or the telemetry queue. The client and server run inside the same worker process, so the RSS change per connection includes both the client's and the runtime's memory use. SQLite and disk output are turned off during the throughput benchmark run; storage slowdown is tested separately. An early version of this benchmark used a memory-tracing tool called `tracemalloc`, which slowed the idle workload down to its normal deadlines. The final "native RSS" benchmark run does not use `tracemalloc`.

The following have not been confirmed here: a live workload using real traffic redirection, Linux resource and capability tests, running under Docker or systemd, real-world Internet accuracy, and a long-running "soak" (endurance) test. The phase record with those results is not published; see [history/README.md](history/README.md).

## See also

- [DECEPTION.md](DECEPTION.md) — how the deception feature works
- [ENFORCEMENT.md](ENFORCEMENT.md) — how (and whether) the system takes action
- [PRIVACY.md](PRIVACY.md) — what data is kept, redacted, or discarded
- [LIMITATIONS.md](LIMITATIONS.md) — known limits of the project
