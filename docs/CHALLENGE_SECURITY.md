# Challenge security

Threats to the challenge subsystem, what is done about each, and what is left
over. The last column is the important one: every mitigation here has a limit,
and a security document that does not say where the limits are is not much use.

## Token design

| | |
| --- | --- |
| Scheme | `challenge-v1` |
| Signature | HMAC-SHA256, from Python's `hmac` and `hashlib` |
| Key derivation | HKDF-SHA256 (RFC 5869), per site, from one local master secret |
| Payload | version, issued at, expires at, level — 10 bytes, fixed layout |
| Nonce | 12 random bytes |
| Encoding | base64url |
| Comparison | `hmac.compare_digest` — constant time |
| Default lifetime | 15 minutes (maximum 60 minutes) |
| Clock skew allowed | 60 seconds |

The payload is a fixed `struct` layout, not JSON and not a serialised object.
There is no parser to confuse: a token is either exactly the right length with a
valid MAC, or it is refused.

## Threats

### Token replay

**Impact.** A stolen token lets somebody skip a challenge.

**Mitigation.** Short lifetime, site scope, and — this is the point — the token
grants nothing. It is not authentication. It does not log anyone in, does not
carry a session, and does not bypass any authorisation the application does. The
most a stolen token buys is not being asked a question the thief could have
answered anyway.

**Remaining.** Tokens are bearer tokens for their lifetime. Within 15 minutes, a
token shared between clients works for all of them. This is accepted: binding
tokens tightly to an address breaks mobile users, NAT and IPv6 privacy
addresses, and the thing being protected is not worth that cost.

### Cookie theft

**Impact.** Same as replay.

**Mitigation.** `HttpOnly`, so no script can read it. `Secure` when the site is
HTTPS. `SameSite=Lax`. Short `Max-Age`.

**Remaining.** A client with malware on it has bigger problems than this cookie.

### Challenge flood

**Impact.** An attacker triggers challenges to exhaust CPU or memory.

**Mitigation.** Tokens are stateless — signing one stores nothing. The context
table is bounded (10,000 by default) with TTL and LRU eviction. There is a
per-client hourly budget, a per-second whole-site budget, and a minimum time
between challenges to one client. Signing costs about 11 microseconds and the
response is 838 bytes.

**Remaining.** A flood still costs something. When the global budget is spent,
challenges stop being issued and the system falls back to watching and rate
limiting — the site stays up, but the challenge signal is unavailable while the
flood lasts.

### Challenge loop

**Impact.** A client that cannot keep cookies is asked forever, and never
reaches the site. This is an outage for that user.

**Mitigation.** `attempts_since_pass` is counted. After `max_attempts` (3 by
default) the system stops asking and decides on the evidence it has. There is
also a minimum interval between challenges and an hourly cap per client.

**Remaining.** A client that blocks cookies will see up to three challenges
before the system stops. Those requests are extra work for that user. The LAB
`challenge_loop_bot` fixture exists to keep this bounded, and it is one of the
first things to check after changing budget settings.

### Open redirect

**Impact.** The challenge page sends clients wherever an attacker says — a
phishing tool hosted on the site it defends.

**Mitigation.** The return target must be a local path. Absolute URLs,
protocol-relative URLs (`//host`), `javascript:`, `data:`, `vbscript:`, `file:`,
`blob:` and `mailto:` are all rejected, as are `/\` and control characters. A
rejected target becomes `/`. The path is length-bounded.

**Remaining.** A client is returned to the site's home page rather than where it
was going when the target is rejected. That is a small loss and the trade is
deliberate.

### Cross-site scripting on the challenge page

**Impact.** An XSS hole in the security tool.

**Mitigation.** Nothing attacker-controlled reaches the HTML at all. The return
target travels in a `Location` header, percent-encoded; it is never written into
the page. The page is static with no JavaScript, and carries
`Content-Security-Policy: default-src 'none'` and `frame-ancestors 'none'`.

**Remaining.** None known for the page itself. The header value is still
attacker-influenced, which is why it is validated and encoded.

### Proxy spoofing

**Impact.** A client sends `X-Forwarded-For` to impersonate another address, or
to make the system act against a third party.

**Mitigation.** The P10 resolver. Forwarded headers are read only when the
immediate peer is a configured trusted proxy, and the chain is walked from the
right, stepping over addresses that are themselves trusted proxies. A forwarded
header from an untrusted peer is ignored entirely.

**Remaining.** If you configure a trusted proxy range that is wider than your
actual proxies, this protection is gone. Configure it narrowly.

### Blocking a CDN

**Impact.** One scanner behind a CDN gets the CDN's address blocked, and the
whole site goes off the air. This is the worst thing this software could do.

**Mitigation.** Any client resolved through a proxy is `network_enforceable =
False` and can never reach TEMP_BLOCK. A challenge *can* still be sent, because
it travels over HTTP to the one client that asked for it — it is safe exactly
where a network block is not.

**Remaining.** Rate limiting a proxied client is applied by client identity, not
by address. If your proxy does not pass a usable client address, all its clients
look like one client, and the system will say so rather than guess.

### Shared addresses and false positives

**Impact.** An office, a university or a mobile carrier NAT looks like one very
busy client, and ordinary people get challenged.

**Mitigation.** Challenges are proportionate and cheap, and the review queue
gives extra priority to exactly this shape — an ordinary-looking client that has
been challenged repeatedly without passing (see [§44 handling in
`review_priority`](../eye_for_an_eye/challenge/service.py)).

**Remaining.** Real. This is the main reason to run in shadow mode first and
look at the numbers.

### CDN caching a challenge

**Impact.** A shared cache stores one client's challenge and serves it to
everyone. The site breaks for all users.

**Mitigation.** Every challenge response is `Cache-Control: no-store`, plus
`Pragma: no-cache`.

**Remaining.** A misconfigured CDN that ignores `no-store` will still break. If
your CDN is configured to cache aggressively regardless of origin headers, do
not enable active challenges until that is fixed.

### Secret leakage

**Impact.** Anyone with the secret can mint tokens.

**Mitigation.** The secret is generated locally, must be at least 32 bytes, must
not be readable by other users (`chmod 600`, checked and refused otherwise), is
never logged, never enters a dataset, never goes in Git, and never appears in
CLI output or a health document. `challenge doctor` checks the permissions.
Per-site keys are derived with HKDF, so one site's key does not reveal another's.

**Remaining.** Anyone who can read the file, or who has root, has the secret.
Rotation is supported: set `previous_secret_file` and tokens signed with the old
key keep working until they expire.

### Model feedback loop

**Impact.** The model decides a client is suspicious → a challenge is shown →
"was challenged" becomes a feature → the model learns to reproduce its own
earlier decision. The model gets more confident and no more correct.

**Mitigation.** `challenge_presented` is deliberately excluded from anything a
model trains on, and this is written down in the code that produces the features
rather than left as folklore. Challenge outcomes are never labels: a failed
challenge does not make a row malicious and a passed one does not make it benign.
The only thing that writes a label is a person answering a review queue entry.

**Remaining.** Outcome features (passed, failed, continued after passing) are
still downstream of a decision the system made. Any future model that uses them
needs a temporal design and a leakage check. Until then they are policy features
only, and `auto_promote` remains `false`.

### Availability failure

**Impact.** The challenge subsystem breaks and takes the website with it. This
would be a worse outage than the attack it was watching for.

**Mitigation.** Every entry point catches its own failures, counts them, and
returns "do not challenge" — which means the request proceeds normally. A
misconfiguration produces a disabled service that explains itself, not a crash.
The gateway's `handle` cannot raise. This is asserted by tests that break each
entry point deliberately.

**Remaining.** The subsystem can be silently useless if it is failing on every
request. Watch `challenge_subsystem_errors_total`, and `challenge status` shows
the last error.

## Timing

Rejecting a malformed token costs about 1.4 microseconds; verifying a
well-formed one costs about 12. That difference is observable, and it reveals
whether a token was the right shape — not whether a signature was correct. The
signature comparison itself is constant time. Rejecting garbage cheaply is
deliberate: a verifier that costs more to refuse than to accept is a
denial-of-service amplifier.

## What is not implemented, on purpose

- No CAPTCHA, and no dependency on any CAPTCHA provider.
- No browser fingerprinting: no canvas, no WebGL, no audio, no font probing.
- No proof-of-work. It would heat phones and drain batteries to buy very little.
- No JavaScript in the default challenge.
- No third-party requests of any kind.
- No public API, no remote challenge service, no cloud callback.
- No hack-back and nothing that consumes a remote client's resources.
