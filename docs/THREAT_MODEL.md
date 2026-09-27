# Threat Model

This page explains what Eye for an Eye protects against, what it does not protect against, and what risks remain even when everything works correctly. Read this before you rely on it for any security decision. (This project was built in stages, named P0, P1, P2, and so on: later stages add features on top of earlier ones.)

## Multi-site Profiles (P12)

P12 lets one installation protect several websites on the same machine, each
with its own settings and its own idea of normal traffic. It is **off by
default**. Turning it on adds one important new untrusted input: the `Host`
header, which the client chooses.

- A site is **never created from a request**. Sites come from your configuration
  file and nothing else. A request whose `Host` matches no configured domain
  goes into a bucket called `unknown-site`, which is in shadow mode, cannot
  challenge, cannot rate limit and cannot ask for a network block. A client that
  invents 200,000 host names creates zero sites.
- The site name, the domain and the `Host` header are **never given to the model
  as inputs**. A classifier that could see which site a request was for would
  learn "traffic to the admin site is suspicious", which is a fact about your
  configuration, not about the visitor.
- Web behaviour is kept per site. One site's counters never reach another's.
- Network-layer evidence about the *machine* (a port scan, for example) is
  deliberately shared between sites, because it is true of the machine and stays
  true when you look at it from another site.

**What still goes wrong.** Sites share one process. This is separation of state
and policy, not a sandbox: a bug that crashes the process affects every site. And
a host-wide network block reaches **every site on the machine**, which is why a
site must be explicitly configured before it may ask for one, and why no profile
template allows it. See [CROSS_SITE_SECURITY.md](CROSS_SITE_SECURITY.md).

## Web Challenge (P11)

P11 adds the only part of this system that sits **in front of** a request rather
than reading about it afterwards. That makes it the only part that can break a
website, so the rules around it are strict.

- It is **off by default** and starts in shadow mode.
- Every path that could fail is caught, and the answer to a failure is always
  "let the request through". A security component that turns its own bug into a
  site-wide error page has caused a worse outage than the scanner it was
  watching for.
- The signing secret is **never** placed in JavaScript, HTML, a cookie or
  browser storage. Tokens are signed with HMAC-SHA256 using a key derived per
  site, so a token minted for one site does not verify for another.
- A challenge result is **evidence, not a verdict**. Failing one cannot make a
  source malicious; passing one cannot make it benign. The ladder stops at
  RATE_LIMIT and a challenge outcome alone can never reach a block.

**What still goes wrong.** A determined automated client can pass the challenge.
One of the lab fixtures is a patient scanner that passes every time, and it is
there to keep that fact in front of anyone reading the tests. Clients that cannot
hold cookies (some feed readers, some command-line tools, some assistive
technology) cannot answer a challenge at all, which is why API-shaped sites do
not issue them. See [CHALLENGE_SECURITY.md](CHALLENGE_SECURITY.md).

## Web Sensor (P10)

P10 reads an Nginx access log. It sees a request only after the server has
already answered it, which is why it cannot break a website: it never touches
one.

- The client address comes from the trusted-proxy resolver and nothing else. A
  forwarded header from an untrusted peer is ignored.
- A client behind a proxy is never network-enforceable, because blocking the
  proxy would remove every visitor behind it.
- Log lines are untrusted input: request paths, methods, user agents and
  referrers are all attacker-chosen, and are parsed with bounded parsers.

**What still goes wrong.** A log the sensor cannot read is a sensor that sees
nothing, and the difference between "no attacks" and "no data" has to be read
from the health output rather than assumed. See [WEB_PROTECTION.md](WEB_PROTECTION.md).

## Read-only API and Metrics (P4)

The P4 stage of the project adds a read-only "operational attack surface": new network endpoints, but ones that can only read data, never change anything.

- The API (a way for other programs to ask the sensor for data) and the metrics endpoint (a way to read performance numbers) each use their own port on `127.0.0.1` (loopback, only the same machine can connect).
- Both have limited budgets for sockets (open connections), requests, queries, and responses, so they cannot use unlimited resources.
- Both check the `Host` header on incoming requests, turn off CORS (Cross-Origin Resource Sharing, a browser security feature), and can require a bearer token (a secret access key), though this is optional.
- SQL (the database query language) is only reachable through a fixed whitelist of filters, using read-only database connections. There is no endpoint for running arbitrary code, reading arbitrary files or SQL, changing the firewall, scanning networks, or injecting packets.
- Making these endpoints reachable from outside the local machine ("non-loopback") needs an explicit "insecure" override, and shows a warning when used.

See [API](API.md) for details.

The API reader, and the separate metrics selector, do not run inside the intake callback (the code path that receives new network events), so heavy API traffic cannot slow down event collection. If the API becomes overloaded ("saturation"), it can become slower or less available, but it cannot create unlimited worker threads. Neither the filesystem nor the operating system's I/O (input/output) offers hard real-time guarantees; some resource control is still up to how you deploy the system. The API's "IP masking" feature only changes how an address is *shown* to a reader. It does not make a visitor anonymous, and it does not make the SQLite database file itself confidential. A "redaction heuristic" (an automatic guess at what looks like a secret, so it can be hidden) adds to the fixed rules already set for each data field, but it cannot guarantee it will catch every unknown kind of secret.

## Fake Service Protocols (P3)

P3 extends the incoming TCP conversation with limited parsers for HTTP, FTP, and SSH (see [Service Profiles](SERVICE_PROFILES.md)). The handler code that runs these fake services cannot touch the network, files, or run other programs on its own. Bytes, time, number of messages, and number of transitions are all limited by the chosen profile and by global policy. If telemetry (event data) is rejected, if the system is under heavy load, or if the original destination is unknown, the fake service simply stops responding.

The pseudonym (a fake, repeatable ID) used for usernames is built with HMAC, a keyed hash function used to create a code that is hard to fake, using its own long-lived secret. A separate "probe digest" only lasts for the current running process. These pseudonyms are sensitive, but they are not a real identity. The classification decisions made in P2 (see below) never cause the system to send more outbound network traffic.

[DECEPTION_SAFETY.md](DECEPTION_SAFETY.md) describes the exact boundaries and tests for P3.

## Fingerprinting and Classification (P2)

P2 adds handling of untrusted source and timing patterns, limited classic PCAP (packet capture) records, and labels written by the operator. An observed network address is never treated as a real identity. Matching results and scores are not probabilities.

Separate HMAC digests use a key that only lasts for the current process. Recognized login attempts, such as a guessed username or password, are never hashed; they are only stored as a flag and a count. A "state cap", a limit on how much the system tracks, lowers confidence and blocks any "targeted hypothesis". A guess aimed at one specific attacker. Classification never controls network responses or the firewall.

See [LIMITATIONS.md](LIMITATIONS.md) for more detail.

## Assets (What We Are Protecting)

- The sensor and listener staying available and able to run
- The limited amount of memory and disk space the system uses
- The correctness ("integrity") of what it observes
- The deception profiles staying consistent over time
- The HMAC secret
- The management ports, and the ports of any real services on the same machine
- Other people's firewall tables (rule sets): the tool must never damage them

A source IP address and a fingerprint never confirm who a real person is, or where traffic truly comes from, when NAT (Network Address Translation) or a VPN (Virtual Private Network) is involved.

## Trust Boundaries

| Boundary | Untrusted input | Control | Residual limitation (what can still go wrong) |
| --- | --- | --- | --- |
| TCP/UDP intake | Slow clients, connection resets, large or empty packets | A selector, limits of 256/8 connections, first/idle/total deadlines, byte caps, UDP is receive-only | A kernel-level SYN flood (a type of network flood attack), or a saturated network link, still needs OS/network-level protection |
| Parser and estimators | Bytes, broken options, quoted headers, timestamps out of order | Bounded parser and state, choosing the outer header, UNKNOWN/LOW results, the p0f adapter (p0f guesses a computer's operating system from its traffic patterns) | Accuracy is not calibrated; the native libraries used here are not a security sandbox |
| Capture helper to analysis | Corrupted frames, or another local program pretending to send them | A protected Unix directory, `SO_PEERCRED` checks on both sides (confirming which user sent the data), frame/time limits, JSON format | If someone compromises the allowed system user, that is still a compromise of a trusted input source |
| Intake to consumers | An endless stream of events, a slow disk | A queue limited by count and by bytes, a drop-newest policy, counters and health checks | Data can still be lost; the system does not promise durable delivery or exactly-once processing |
| External data provider to runtime | Timeouts, exceptions, large or incomplete content | Killable child processes, capped IPC (inter-process communication), caching, negative caching, backoff | A deadline does not replace a memory limit for native memory allocation inside a child process |
| Storage | A growing number of events, a reader holding the WAL file open, a second writer | Retention rules, a maximum page count, transaction reserve space, checkpoints, an OS-level writer lock | The database is one file on the local filesystem; an administrator or process that ignores the lock is outside this trust model |
| Config and secret | Wrong types, wrong file permissions, accidental disclosure of values | Setting priority CLI > ENV > TOML, validation before any file access, hiding secrets in `config show`, file/env references | Operator config files and access to the secret file are trusted; the operator sets the OS-level access rules (ACL) |
| Firewall | Shell injection, overlap with real services, firewall table name collisions, crashing the listener | Runs only inside a named lab network namespace, fixed argument lists, validated values, its own firewall table, protected ports, readiness checks, an expiring lease | The readiness check only proves a port answers over TCP; it does not cryptographically prove which process answered. This behaviour on real Linux systems has not been separately verified here |
| Access log to web sensor (P10) | Attacker-chosen paths, methods, user agents, referrers, forged forwarded headers, very long lines, control characters | Bounded parsers, size caps, client identity only from the trusted-proxy resolver, a proxied client is never network-enforceable | A log the sensor cannot read produces silence that looks like calm; the difference is only visible in the health output |
| HTTP request to challenge gateway (P11) | Malformed or oversized cookies, forged or replayed tokens, hostile `Host` headers, clients that cannot hold cookies | Fails open on every path, strict canonical base64url, HMAC-SHA256 with a per-site derived key, a clock guard, budgets, ladder ceiling at RATE_LIMIT | A patient automated client can pass the challenge; some legitimate clients cannot answer one at all |
| `Host` header to site resolution (P12) | Any host name a client chooses, injected CR/LF, control characters, unbounded cardinality | Sites come only from configuration, no request can create one, unmatched hosts go to a shadow-mode `unknown-site` bucket with no powers, site identity is never a model input | Sites share one process: this is state and policy separation, not a sandbox |

The privileged capture process (the one with elevated permission to read raw packets) does not contain the SQLite writer, does not do registry lookups, and does not run any deception callback. On Linux, by default, the analysis process refuses to run as root, and refuses to keep any elevated capabilities. The setting `runtime.enforce_unprivileged=false` is an explicit escape hatch, kept only for old lab experiments; the standard deployment templates never use it. The Windows version of this permission model has not been verified. The Linux protections described here do not apply there.

## Data Kept in Storage

Raw payload previews from the earliest version (P0) are no longer recorded. What remains in storage is addresses, ports, timestamps, and limited metadata, and these can still be sensitive. When SQLite storage is turned on, the default retention is one day, or 100,000 events, whichever comes first, inside a limited disk-space budget. SQLite itself does not encrypt data. If you need encryption, you must add host access policy or volume encryption yourself, outside the application.

## Secret Handling

The HMAC secret is never included in the source code, in a container image, or in the output of `config show`. A public test value, `bytes(range(32))`, only appears in regression tests and lab fixtures, never in a real deployment. Changing the secret, or changing the catalogue version, changes how profiles map to endpoints; this is a controlled, intentional change. A fake service's banner does not guarantee it matches the real kernel's TCP fingerprint.

## What This Project Does NOT Do

The following are explicitly **not** implemented:

- "Hacking back" at an attacker
- Deliberately crashing a scanner
- Exhausting a client's resources
- Acting as an external scanner
- Automatic banning of addresses
- A web UI (user interface)
- Changing the host machine's own firewall

The lab network-namespace test setup has no default route, and it does not connect its virtual network interface (`veth`) to any real host network interface.

You must still separately verify real permissions, kernel and `nftables` (`nft`, the Linux firewall tool) behaviour, and your own deployment environment. See [DEPLOYMENT.md](DEPLOYMENT.md).

## See Also

- [Limitations](LIMITATIONS.md)
- [Risks and limitations](RISKS_AND_LIMITATIONS.md)
- [Deception safety](DECEPTION_SAFETY.md)
- [Deployment](DEPLOYMENT.md)
- [API](API.md)
