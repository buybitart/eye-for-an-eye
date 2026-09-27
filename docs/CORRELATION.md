# Event Correlation and Behavior Rules

This page explains how the system links network events together and gives them a behavior label, such as scanner, bot, or suspicious. Read this if you look at correlation results, or if you tune detection thresholds.

The CorrelationEngine (the part of the code that finds patterns) groups events by sensor ID plus the observed source address. It does not group by person or by process. Forwarded, NAT, proxy, or shared addresses can mix together different clients. Spoofed (faked) addresses can split one real behavior into many different addresses. So the result is only a hypothesis about behavior seen locally. It is not proof about a real actor.

## Time Windows and Memory

The default sliding time windows are 60 seconds and 900 seconds. There can be at most 4 windows. Each window must be between 1 and 3600 seconds. The TTL (how long data is kept) must cover the longest window. The system's clock is a "watermark": it only moves forward, based on capture or event timestamps. Events that arrive out of order, but still inside the time horizon, are sorted correctly. Events that arrive too late are dropped, and a counter called `late_events` counts them. If test data (an "operator corpus") has timestamps in the future, the system trusts them as capture metadata.

One limited-size buffer holds samples for all windows together. Its limits are: `max_sources=10000`, `max_events_per_source=256`, `max_bytes=32 MiB` (mebibytes). Three quarters of that byte budget goes to the "source cache" (data about each address). One quarter goes to "distributed groups" (up to 1024 of them). The buffer uses TTL (a time limit) and LRU (Least Recently Used — old items are removed first) to stay small, and it tracks its own memory use in code fields. Short-lived copies of data, and the real memory used by the running program (native RSS), need separate, outside limits. This stored state never contains payload data or passwords.

When a limit is reached, old samples are removed and lost. Counters called `sample_drops` and cache counters show this in the running status and in the offline summary report. After this happens, event counts are only a lower estimate — the real number could be higher. After a sample limit is hit, the confidence level drops to LOW at most, and "targeted-hypothesis" is not allowed. A "capped" (limited) flag stays on that source's data until it expires or is removed.

A directed connection is identified by a `FlowKey`, which has fixed fields: source IP, source port, destination IP, destination port, and transport protocol (like TCP or UDP). For ICMP and ICMPv6 traffic, the port fields are empty (`None`). Evidence about connections (`FlowEvidence`) has its own separate limits: TTL, LRU, and 4 MiB of memory. The system only marks a `completed_handshake` (a full TCP connection setup) after it sees a SYN packet, then a matching SYN-ACK packet, then a matching ACK packet. A single ACK packet alone does not count as a handshake. The live capture helper only sees incoming local packets, so it may not see the full exchange between both sides.

## What Is Measured

| Feature name | What it means |
| --- | --- |
| `unique_destination_ports` / `unique_destinations` | How many different ports or hosts were seen, inside the limited time window. |
| `unique_protocol_probes` / `probe_family_diversity` | How many known "probe templates" (test patterns tools use to scan) matched, and how many different probe "families" (prefix groups) were recognized. |
| `connection_attempts` | The number of captured SYN packets, or connections the listener accepted. This does not see every attempt — it is a partial view. |
| `completed_handshakes` | A connection accepted by the operating system kernel, or a full 3-step TCP handshake that was fully observed. |
| `max_probe_repetition` | How many times the same short-lived HMAC (a keyed hash used to compare data safely) digest repeats, not counting flagged retransmissions or duplicate packets. |
| `inter_arrival_mean_seconds` / `CV` | The average time between useful samples (or between attempts, if there is no payload), and the CV (coefficient of variation — how much that timing varies). |
| `sequential_port_fraction` / `repeated_sequence` | The share of ports that are next to each other in number, and whether a 2-to-4-step pattern repeats. |
| `credential_attempts` / `protocol_anomalies` | Simple true/false counters. They never store any actual username or password content. |
| `response_continuations` / `retry_observations` | Data the client sent after it saw a response, and repeated TCP sequence numbers that look like retries. |
| `observed_span_seconds` / `attempts_per_second` | How long the behavior was observed for, and the number of attempts divided by the length of the time window. |

The classifier (the part that decides the label) does not add TTL or p0f confidence into these scores. An OS fingerprint guess is never used as proof of bad intent. A duplicate network capture and a real retry can look exactly the same to the system. Packet payloads (the actual data inside packets) are not reassembled into a full stream. A listener only sees a limited prefix (the start) of a request. Encrypted credentials are usually not recognized at all.

## Saving Payload Repetition Without Storing Credentials

The `PayloadFeatures` code checks at most 4096 bytes of a payload for patterns that look like login credentials. It only saves a true/false flag and a count — never the actual content. When it recognizes a credential-like attempt, it does not create a digest (hash) for it. For all other limited payloads, it uses HMAC-SHA256 (a keyed hashing method) with a new random key each time the analysis starts. This key is never stored or logged. This means the digests cannot be used as an identity, and cannot be matched across restarts or between different sensors. A flag called `inspection_limited` shows that this checking was cut short.

The setting `min_probe_evidence` controls how many bytes are needed before a match counts. Its default is 8 bytes. When the data matches a known probe template, the system reports it only as "Nmap-compatible probe; tool identity unknown." (Nmap is a well-known network scanning tool, but a match does not prove Nmap was used.) A prefix match is not a probability that Nmap was used — any client could send data that matches one of these templates. The format for these probe templates is described in the [Nmap reference](https://nmap.org/book/vscan-fileformat.html).

## Explainable Scoring Rules

The weight values live in the setting `correlation.weights`. You can override some of them using a TOML config file or environment variables; overrides are merged in by name. Unknown weight names, or values outside 0–100, are rejected. Every score is capped between 0 and 100, and none of them are probabilities. The way features are normalized (scaled) is a fixed rule written by hand for this stage of the project. It is not a model trained on data.

| Term | Default weight | Normalization / gate |
| --- | --- | --- |
| port_breadth | 25 | ports / 16, capped at 1; needs at least 4 ports |
| host_breadth | 35 | destinations / 16, capped at 1; needs at least 4 hosts |
| probe_diversity | 15 | matched template names / 4, capped at 1 |
| connection_rate | 10 | attempts per second compared to 20/60, capped at 1 |
| sequential_ports | 15 | share of neighboring ports, when breadth is at least 4 |
| anomalies | 20 | anomalies / 3, capped at 1 |
| credentials | 25 | credential events / 3, capped at 1 |
| persistence | 20 | span / focused_seconds, capped at 1; needs at least 8 events |
| repeated_probe | 15 | repetition / 6; needs at least 3 for "suspicious", at least 6 for "bot" |
| timing_regular | 20 | CV <= 0.15, needs at least 8 events |
| sequence_repeat | 15 | a 2-to-4-step pattern repeats at least 3 times |

The system checks these labels in this order: local focus, then scanner, then bot, then suspicious, then noise.

- **targeted-hypothesis**: needs at least 12 events, a span of at least 300 seconds, at most 2 different ports or hosts, at least 3 credential or anomaly events, and a suspicion score of at least 25. This label is never used if a sample limit was hit. Confidence is always LOW. It only means "locally persistent / focused behavior against this sensor." It says nothing about whether the same source is targeting other systems too.
- **scanner**: needs at least 8 different ports or hosts, two non-zero scan-related terms, and a scan score of at least 40. This can catch a slow, sequential scan over the longer 900-second window, even when the shorter 60-second window is not enough to see it.
- **bot**: needs at least 6 repeated digests, plus consistent timing and sequence patterns, and a bot score of at least 35. This means the behavior *looks like* a bot. It is not proof that bot software was actually used.
- **suspicious**: needs at least 3 credential or anomaly events, and a suspicion score of at least 25. Confidence is LOW.
- **noise**: not enough matching evidence was found. Confidence is UNKNOWN. This is not a verdict that the client is safe.

MEDIUM confidence is only possible when several scanner or bot signals agree with each other. If a sample limit was hit, it drops back down to LOW. HIGH confidence is never given.

Every result includes: reasons showing which rules contributed, up to 8 supporting event IDs, the window's start time, end time and length in seconds, feature counts, and known limitations. The system sends out a new result whenever the label changes, or at least every 5 seconds. The final offline summary report recalculates the last active windows again, regardless of that 5-second interval.

## Distributed Pattern Detection

There is a separate, size-limited cache for groups. A group is defined by: sensor, a similar digest or template, and the destination IP, port, and transport protocol. When at least 5 different source addresses appear in the same time window and match, the system reports `distributed_scan_pattern` with LOW confidence. The score is `source_count × 5`, capped at a maximum — it is not a probability. This pattern can also come from common client software, or from spoofing (faking addresses). The system never concludes that this is the same attacker or the same botnet owner.

Results calculated this way are saved as a `correlation_result`. They are never fed back into the engine as new input. Classification never controls network responses or the firewall by itself. The live running system uses the same size-limited queue as before. The offline "paced" mode uses the same `EventAnalysis` code, but without background worker threads and without sampling.

## Evaluation

The file [calibration.py](../eye_for_an_eye/calibration.py) reads a local test-data list called a "manifest" (version 1). Each entry has: an id, a pcap file (a saved network capture), its SHA-256 checksum, expected labels, other metadata, and a source. All file paths must stay inside the test-data folder. The manifest file must be 1 MiB or smaller, hold at most 256 samples, and each classic PCAP file must be 512 MiB or smaller. The system never downloads anything automatically.

Labels apply to the last active source and window. The system computes a confusion matrix (a table comparing predicted labels to real labels) and one-vs-rest precision, recall, FPR (false positive rate), and FNR (false negative rate). When a calculation would divide by zero, the result is `null` instead. If a source or window was never observed, the result is `unobserved`. Distributed group detection is checked with separate behavior tests. To label test data at the group level, the schema (data format) would need a new version.

The synthetic (artificially made) test fixtures are only "contract checks" — they check that the code behaves as expected. They are not a realistic data set for tuning the system. Weights are never trained automatically. An example of how to reproduce these tests, and the benchmark results, are in [LIMITATIONS.md](LIMITATIONS.md).

## See also

- [CONFIDENCE.md](CONFIDENCE.md) — how confidence levels work
- [FINGERPRINTING.md](FINGERPRINTING.md) — how TTL and p0f based fingerprinting works
- [LIMITATIONS.md](LIMITATIONS.md) — known limits of the analysis
- [MATH_MODEL.md](MATH_MODEL.md) — the math behind scoring and the model
