# Web Enforcement

What a web decision is allowed to cause, and what it can never cause.

Status: **Beta.** Shadow Mode is the recommended deployment. There is no
web-layer blocking in this release.

## The Ladder

The same four steps the network side uses:

```text
OBSERVE  ->  WATCH  ->  RATE_LIMIT  ->  TEMP_BLOCK
  0.40        0.70        0.88
```

Nothing jumps straight to a block.

## Shadow Mode

On by default. The system decides and records; it enforces nothing.

```text
Web behaviour risk: 0.89
Decision: TEMP_BLOCK
Enforced: NO
Reason: shadow mode: nothing was enforced
```

Run it this way first. Read what it would have done. The false positives you find
in a week of shadow are the ones you would otherwise have found by taking your
site off the air.

## What Can Never Happen

### A Proxy Is Never Blocked

If a client reached us through a trusted proxy or CDN, the address we know is not
the machine that would be hit by a network block. The proxy would be, and the
proxy is carrying everyone else.

```text
Decision: RATE_LIMIT (proposed TEMP_BLOCK)

Reduced because:
  - the client is behind a proxy; blocking its address at the network layer
    would hit the proxy and every other visitor behind it
```

Structural, not configurable. It is a regression test.

### Thin Evidence Is Never Acted On

Fewer than 20 requests means the strongest available action is WATCH. Acting on a
handful of requests is acting on noise.

### An Uncertain Identity Is Never Acted On

If the client address could not be established (a proxy that sent no forwarded
address, an unparseable header) the strongest available action is WATCH. Not
knowing who did something is a reason to be careful, not a reason to guess.

### Poor Data Quality Is Never Acted On

Dropped log lines, a very short window, a partly trusted proxy chain: each lowers
data quality, and below the configured minimum the strongest action is WATCH.

### Localhost and Management Networks

Loopback, the sensor's own addresses and configured management networks are never
acted on. Before enabling enforcement, put your own address in
`enforcement.management_networks`: `web doctor` warns when it is empty.

## The Policy Can Only Weaken

Every rule in the policy reduces the action. None can raise one. This is tested
exhaustively across every combination of proposed action, identity confidence,
enforceability, observation count and data quality: **216 combinations, none of
which produces a stronger action than was proposed.**

A bug in that function should cost detection, never availability.

## Enforcement Scope

| Scope | Meaning | Available |
| --- | --- | --- |
| `NETWORK_SOURCE` | the address is the machine that connected | yes |
| `WEB_CLIENT` | the address is a client behind somebody's proxy | recorded only |
| `SESSION` | one session rather than an address | not implemented |
| `SERVICE` | one protected service | not implemented |

Only `NETWORK_SOURCE` can lead to a network-level action, and only in a lab
configuration with enforcement explicitly enabled.

## Web-layer Blocking

**Not implemented, deliberately.**

Adding it means generating web server configuration and reloading Nginx. That is
only acceptable if it is atomic, bounded, validated with `nginx -t` before every
reload, and rollback-safe. Until it is all four, a `RATE_LIMIT` decision is
recorded and not applied.

Half-implemented dynamic configuration rewriting is a good way to take a site
down, which is the outcome this whole layer exists to avoid.

## Temporary, Never Permanent

Network blocks, where enabled at all, follow the existing rules:

* first offence is short
* repeats lengthen, up to a maximum
* every block expires on its own
* the offence counter decays after `enforcement.offense_decay_seconds`

There is no permanent automatic ban. One public address can be an office, a
mobile network or a university.

## Overload

If the machine is under pressure, the site comes first. Optional work is shed in
this order:

```text
optional enrichment  ->  candidate model inference  ->  anomaly frequency
->  optional web events  ->  basic maths keeps running
```

Web events are dropped and counted rather than queued without bound. The
protection must not become the denial of service.

## Related

* [REVERSE_PROXY.md](REVERSE_PROXY.md): why a proxy is never blocked
* [ENFORCEMENT.md](ENFORCEMENT.md): the network-side rules
* [SHADOW_MODE.md](SHADOW_MODE.md): running without enforcing
