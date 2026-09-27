# Fingerprinting

This page explains what the sensor reads from packet headers. It also explains
how careful the system is about what those numbers mean. Read it if you want to
know why the tool almost never says "this is Windows" or "this is a VPN".

## Three different things

The code keeps three things apart:

| Word | Meaning |
| --- | --- |
| Observation | A number we read from the packet. It is a fact. |
| Hypothesis | A guess built on top of that number. It may be wrong. |
| Attribution | Naming a person, a company or an owner. The system never does this. |

A `FingerprintResult` holds `feature`, `status`, `observations`, `hypothesis`,
`confidence`, `evidence` and `limitations`.

Confidence belongs to the hypothesis only. If a result has no hypothesis, a
confidence of `UNKNOWN` does not mean the bytes we read are unknown. It means
there is no guess to rate.

## How a result is stored

The runtime writes one `fingerprint_observation` event per feature:

* measurements go into `observations`,
* `hypothesis`, `confidence` and `evidence` go into `hypotheses`,
* limits go on the top level of the record.

The base event is always written before the fingerprint results. The
`NetworkEvent` schema stays at v2. The `transport` field now separates `tcp`,
`udp`, `icmp`, `icmpv6` and `other`. Every result must fit inside the shared
JSON size boundary.

## Short captures

`capture_truncated` means the bytes we have are shorter than the length written
in the IP or transport header.

There are two possible reasons: our own snapshot limit, or the packet was cut on
the wire. We cannot tell which. So a truncated record is **not** treated as proof
that the source sent a strange packet.

When the body is incomplete:

* the body is not hashed,
* p0f is skipped,
* header fields we did read are still kept as separate measurements, with a
  limitation attached.

## TTL and IPv6 hop limit

TTL ("time to live") is a small counter in the IP header. Each router lowers it
by one. IPv6 calls the same idea "hop limit".

`ttl_fingerprint` reports only one measurement: `observed_ttl` (for IPv6,
`observed_hop_limit`).

Everything else is a hypothesis: `initial_ttl_candidates`, `estimated_hops`,
`ambiguity` and `os_hint=None`.

* Default start values: 32, 64, 128, 255.
* Up to 16 other values are allowed.
* Default `max_hops` is 32. This is a **configured assumption**. It is not a
  network standard and it is not proof of the real route.

Examples:

* TTL 51 leaves one candidate, 64, and 13 assumed hops.
* TTL 31 with `max_hops=64` leaves two candidates, 32 and 64.

Several candidates are never collapsed into one. If no candidate fits, the result
is `UNKNOWN`. No operating system is ever named from a TTL value.

`ttl_observation` is kept as a P0 compatibility view. The current pipeline uses
the split result.

## TCP header and options

A bounded parser reads up to 60 bytes of the TCP header. It reads window size,
flags, sequence and acknowledgment numbers, MSS, window scale, SACK-permitted and
SACK blocks, TSval and TSecr, option order, and odd reserved or flag values.

Unknown option kinds are stored as plain numbers.

A bad length, a cut header, a duplicated single-use option or an invalid scale
gives a `partial` result marked `malformed`. Missing fields are never filled in
with a guess.

`option_order` holds the sequence of option codes. When the shared JSON limiter
cuts the list to 24 items, `option_order_codes` keeps the full sequence as one
short string.

Malformed options are never used for timestamp state or for a p0f hypothesis.
Quirks describe the header. They do not describe an operating system or an
intent. The option meanings follow
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html).

## IPv4 IP ID

`IpIdTracker` keeps up to 32 samples per directed flow key. The limit can be set
from 3 to 128. The cache also has a time limit and byte and entry limits.

The result holds zero rate, constant rate, monotonic rate, the modular delta
distribution, wrap candidates and the sample count.

The behaviour names `constant`, `mostly_monotonic`, `irregular` and `random_like`
are hypotheses with LOW or UNKNOWN confidence.

Rules and limits:

* A packet that arrives out of order does not update the history.
* A large modular delta only marks a possible reorder or a change of generator.
* `random_like` needs several different deltas. It is not a randomness test.
* DF atomic datagrams and fragments are left out of the sequence.
* The system does not compute how much other traffic a host sent, and it does not
  decide from the ID field whether a scan was targeted or wide.

This matches the narrow job the ID field actually has, which is fragmentation.
See [RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.html).

## TCP timestamps

State is kept per directed flow: up to 8 samples, hard maximum 32, with a time
limit, an LRU cache and a 16 MiB byte budget.

Stored values: TSval, TSecr, the timestamp delta, the wall-clock delta and a wrap
candidate. Frequency, stability and offset behaviour stay in the hypothesis.

At least three samples in a row are needed. The frequency is the median of the
rates between neighbouring samples, with a tolerance of 10% or 1 Hz. This is a
simple consistency check, not a calibrated clock model.

An offset jump or a reorder does not become a new estimate. A SYN starts a new
window, and a retransmitted SYN may reset it. Capture gaps, clock drift and wrap
ambiguity stay recorded as limitations.

The system does not derive an absolute boot time and does not link addresses to
one identity. Timestamp offsets can differ per connection; see
[RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html).

## p0f

p0f is a known method for matching a TCP handshake against a database of known
signatures. The project keeps the Scapy 2.7.0 adapter and does not replace that
dependency.

Five states are kept apart: `matched`, `unmatched`, `error`, `unavailable` and
`unsupported`.

Measurements include the fuzzy flag, the signature label and version, and the
SHA-256 hash of the operator's database. The hypothesis holds class, name,
flavor and distance.

* An exact match gets at most MEDIUM confidence.
* A fuzzy match gets LOW.
* A missing or empty database, or an exception, gets a clear reason. There is no
  fallback to TTL.

Contract tests use the real Scapy parser and matcher with a small synthetic
database of our own. The content of a production p0f database, its accuracy and
the effect of middleboxes have **not** been checked. The SHA-256 is computed at
startup. Reloading the database while running is not supported.

## Path and enrichment

`path_characteristics` stores the observed inbound TTL or hop limit, plus an
optional reply TTL from an active probe. `nat_hypothesis` is always `UNKNOWN`.

The older difference-of-assumed-hops idea was removed. Asymmetric routing, ICMP
filtering, tunnels, different starting TTL values, load balancers, proxies and
carrier-grade NAT all break it, so no NAT or VPN conclusion is drawn.

For enrichment:

* GeoIP is described as an estimate of where an IP address is, nothing more.
* RDAP describes a registered network, not a person.
* The ASN number, the prefix or network name, the provider, the data version and
  the data timestamp are stored apart from any identity field.
* The data timestamp is the time of the lookup. It is not the date on which every
  registry fact was last true.

The offline `analyze-pcap` command does not run enrichment at all.

## IPv6

For IPv6 the code reads the hop limit, the flow label, the order of extension
headers, and the fragment header (32-bit identification, offset and M flag).

The IPv4 IP ID result returns `unsupported` for IPv6.

The extension header walk stops after eight headers. A malformed or truncated
chain is marked as such. Fragment reassembly, ESP plaintext and jumbograms are
not implemented. Missing transport fields are never invented. IPv6 meanings are
not copied from IPv4; see
[RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html).

## What this data cannot prove

The current data does not prove a person, the owner of a botnet, the real address
behind a VPN, or the wider intent of a source.
