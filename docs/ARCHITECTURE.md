# Architecture

This page shows the parts of Eye for an Eye and how data moves between them.
Read it if you want to know what runs where, and what each part may and may not
do.

## The Pipeline

```text
Internet traffic
      |
      v
Traffic capture              (helper with CAP_NET_RAW, or a saved capture file)
      |
      v
Event normalisation          (one NetworkEvent shape, schema 3)
      |
      v
Bounded queue                (1024 events / 4 MiB, drop-newest)
      |
      v
Correlation                  (per source, windows of 10 s, 60 s, 900 s)
      |
      v
Feature extraction           (FeatureVector, schema 1, 18 values + 18 flags
                              = a 36-column float32 tensor)
      |
      +---------------------+
      |                     |
      v                     v
Maths risk engine       Local ONNX model      (optional, separate process)
      |                     |
      +----------+----------+
                 |
                 v
          Decision fusion
                 |
                 v
            Policy guard                      (can always say no)
                 |
     +-----------+-----------+---------------+
     |           |           |               |
     v           v           v               v
  OBSERVE      WATCH     RATE_LIMIT      TEMP_BLOCK
                                          (lab only)
                 |
                 v
       Local storage (SQLite) + bounded JSONL log
```

## The Second Pipeline: Websites

Everything above starts with a packet. Since P10 there is a second intake that
starts with a line in an Nginx access log, and since P11 a third position that
sits in front of a live request. They are worth drawing separately, because the
difference between them is the difference between a component that cannot break
a website and one that can.

```text
Nginx access log                          a live HTTP request
      |                                          |
      v                                          v
Log parser            (P10)              Web gateway          (P11)
      |  bounded, every field                    |  fails open on every path
      |  attacker-chosen                         |
      v                                          v
Client identity       (P10)              Challenge policy     (P11)
      |  trusted proxies only                    |  budgeted, shadow by default
      v                                          v
Site resolution       (P12)              A response plan
      |  Host -> configured site,                 (PASS / CHALLENGE / RATE_LIMIT)
      |  or the unknown-site bucket
      v
Per-site web state    (P12)   ----> web risk (web-math-risk-v2)
      |  never shared between sites               |
      v                                          v
Per-site baseline and policy      OBSERVE -> WATCH -> SOFT_CHALLENGE
                                           -> RATE_LIMIT -> TEMP_BLOCK
```

Three things about this half are load-bearing.

**The sensor cannot break a website.** It reads a log, so it sees a request only
after the server has already answered it.

**The gateway can**, which is why every path in it is caught and every failure
means "let the request through". A security component that turns its own bug
into a site-wide error page has caused a worse outage than the scanner it was
watching for.

**Risk comes from history; the challenge applies to the request in hand.** The
gateway never computes risk itself. It asks the policy a question about one
request and returns a plan; something else decides what to do with the plan, and
in shadow mode the plan says PASS with a note about what would have happened.

Web behaviour is per site. Network-layer evidence is about the *machine* and is
shared between sites on purpose: a source that scanned ports 22, 80, 443 and
3306 has told you something that does not stop being true when you look at it
from another site. A host-wide network block, by the same logic, reaches every
site on the machine, so a site must be explicitly configured before it may ask
for one.

## The Parts

### Capture

Two ways in:

* **Live capture helper.** A small process holds `CAP_NET_RAW` and nothing else.
  It opens one capture socket, without promiscuous mode, and sends a short JSON
  snapshot of each packet over a Unix socket. It does not open the database, and
  it does not do fingerprinting, enrichment or deception.
* **Offline capture file.** `analyze-pcap` reads a `.pcap` file from disk. No
  socket is opened at all.

The analysis process is unprivileged. It accepts input only from the expected
UID, checks the length and version of every message, and decodes the packet
without a raw socket.

The helper can see credentials in captured traffic, so it stays a sensitive
boundary. See [Privileges](PRIVILEGES.md).

### Event Normalisation

Every input becomes one `NetworkEvent` (schema 3): time in UTC, source and
destination, transport, event type, classification, confidence, and separated
`observations`, `hypotheses` and `enrichment` sections.

Redaction happens here and at every later boundary. Payloads, passwords,
cookies, tokens and `Authorization` headers never get past it.

### Bounded Queue

Events are serialised, then queued. The default limit is 1024 events or 4 MiB.
The strategy is **drop-newest**: the producer never waits for the consumer. On
overflow, counters go up and health becomes degraded. Nothing grows without a
limit.

### Correlation

One consumer groups events by source address and by time window. It counts
things like: how many ports, how many destinations, how regular the timing was,
how long the source kept coming back.

The result is a derived record. It is written **after** the base event, and it
is never fed back into the engine as new input.

See [Correlation](CORRELATION.md).

### Feature Extraction

The counts become a `FeatureVector`: 18 numbers plus 18 "do we know this value?"
flags. Each number has a ceiling and a shape, so everything ends up between
0 and 1.

There is exactly **one** transformation function. Training and the running
system both call it. See [Feature schema](FEATURE_SCHEMA.md).

### Maths Risk Engine

A fixed logistic formula with 10 weights. Always available. Explains itself by
listing how much each behaviour number contributed.

See [The maths engine](MATH_MODEL.md).

### Local ONNX Model

Optional. Runs in a **separate process** with a 200 ms timeout, one inference at
a time, at most 64 waiting. It gets 34 numbers and returns a score and a
confidence. If it is missing, slow or unhealthy, the maths engine carries on
alone.

See [How the AI works](AI.md).

### Decision Fusion

The two scores are joined by weight. The model's weight depends on its
confidence: at 50/50 confidence its weight is zero, and that weight returns to
the maths engine. Old risk decays over time, and the higher of "fresh" and
"decayed" wins.

### Policy Guard

The guard can lower an action but never raise one. It refuses a strong action
when:

* the source is loopback, unspecified, multicast, link-local, a local interface,
  a management network, an allowlist entry or a trusted proxy;
* there is not enough data (samples, seconds, or independent behaviour
  categories);
* data quality is below the limit;
* the maths engine does not agree;
* the model confidence is too low;
* the two engines disagree strongly;
* the sensor itself is unhealthy.

See [Decision engine](DECISION_ENGINE.md).

### Deception

Optional decoy TCP ports. Answers come from a fixed, finite catalogue. There is
no shell and no command execution. The response policy is synchronous and does
not depend on classification. See [Deception](DECEPTION.md).

### Enforcement

**Lab only.** Temporary blocks are written into a random, owned nftables table
inside a named, throw-away Linux network namespace. The backend refuses the host
network namespace. Entries have a kernel expiry, so they disappear on their own.

See [Enforcement](ENFORCEMENT.md).

### Storage

One SQLite writer, WAL mode, with retention by age, count and bytes. Readers use
separate read-only connections. Two instances must never share one database
path. See [Storage](STORAGE.md).

### API and Metrics

A read-only HTTP API and a Prometheus metrics endpoint, both on `127.0.0.1` by
default, both on their own threads. If either fails, event intake keeps running.

See [API](API.md) and [Metrics](METRICS.md).

### Dataset and Training Pipelines

These are **not** part of the running service. They live in `dataset/` and
`training/` and you run them by hand, offline.

See [Dataset](DATASET.md) and [Controlled self-learning](SELF_LEARNING.md).

## Start and Stop

Start: read config → check privileges → open storage → start optional workers →
open listener or capture.

Stop: stop intake → close sockets and capture → stop provider jobs → close the
queue and drain it → checkpoint and close the database → close the logger.

There is one shared shutdown budget (10 seconds by default). systemd limits the
whole control group to 12 seconds. If the operating system stalls on disk I/O,
the flush can still fail. In that case the exit code and health report say so.
Delivery is never claimed as guaranteed.

## What the Architecture Does Not Do

* It never turns a network event into a shell command.
* It never lets a model file grant firewall rights.
* It never sends traffic to a cloud service.
* It never feeds its own decisions back in as training data.
* It never creates a site from a request. Sites come from configuration.
* It never gives the model an identity feature: no address, country, ASN,
  provider, hostname, site id, domain or `Host` value.
* It never promotes a model on its own. There is no `auto_promote` setting
  anywhere in the configuration, because a name that does not exist cannot be
  set by accident.
* It never lets a challenge result become a label. Failing one cannot make a
  source malicious; passing one cannot make it benign.

## See Also

* [Threat model](THREAT_MODEL.md)
* [Service profiles](SERVICE_PROFILES.md)
* [Observability](OBSERVABILITY.md)
* [Limitations](LIMITATIONS.md)
