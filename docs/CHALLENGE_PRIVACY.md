# Challenge Privacy

What the challenge subsystem stores, what it does not, and why.

## The Token

A challenge token contains four numbers and a random nonce:

| Field | Bytes | What it is |
| --- | --- | --- |
| version | 1 | the token scheme, currently 1 |
| issued at | 4 | a unix timestamp |
| expires at | 4 | a unix timestamp |
| level | 1 | which challenge was asked |
| nonce | 12 | random |
| signature | 32 | HMAC-SHA256 |

That is the whole token. It is a fixed binary layout, not JSON.

It does **not** contain:

- a username, an email address, or an account identifier,
- an IP address, in plain text or otherwise,
- a session token or anything from your application,
- a URL, a path, or anything about what the client asked for,
- a tracking identifier of any kind,
- anything derived from the browser beyond the site it was issued for.

A token cannot be linked to a person, and two tokens issued to the same client
cannot be linked to each other: the nonce is random and nothing in the payload
is stable across issues.

## No Fingerprinting

The challenge does not read anything from the browser. Specifically, there is
no canvas fingerprinting, no WebGL fingerprinting, no audio fingerprinting, no
font enumeration, no screen or timezone probing, and no JavaScript at all in the
default challenge.

Browser entropy is never used as an identity. There is no plan to add it.

## No Third Parties

The challenge page loads nothing from anywhere. No fonts, no analytics, no
images, no scripts, no CAPTCHA service. The page is under a kilobyte of static
HTML with `Content-Security-Policy: default-src 'none'`.

No request leaves your server as part of a challenge.

## Challenge State

The system keeps a small record per client while it is being challenged:

| | |
| --- | --- |
| Keyed by | the resolved client address from the P10 resolver |
| Contains | counts: presented, passed, failed, timed out, attempts since a pass, requests and suspicious requests since a pass, and up to 16 recent timestamped outcomes |
| Size | about 940 bytes |
| Capacity | 10,000 clients, then least-recently-used eviction |
| Lifetime | 1 hour, then expiry |

It does not contain paths, headers, cookies, tokens, user agents, or request
content. It is counts and times.

The key is an address, which in some jurisdictions is personal data. It is held
for at most an hour, is not written to disk by the challenge subsystem, and is
not used to identify anyone. See below.

## An Address Is Not a Person

The system never treats an address as a user identity. Addresses are shared: NAT,
carrier-grade NAT, office networks, VPNs, CDNs and university networks all put
many people behind one address. A challenge is attached to a web client context,
not to a human being, and nothing in this system claims otherwise.

## What Is Written Down

Logs record that a challenge was issued, valid, invalid, expired, rate limited,
or that the subsystem failed. They record counts and reasons.

They never record:

- a full token,
- the secret,
- a cookie,
- a password or an `Authorization` header,
- a request body.

Central redaction removes the challenge cookie if it appears anywhere in a
header, an error, or a debug log, and there are tests for that. The gateway's
own explanation strips `Set-Cookie` before it can reach a log or a terminal.
A token in a bug report is a live bypass.

## Metrics

Challenge metrics are counters and one duration. There are no labels carrying an
address, a path, a token or a user agent. A token as a metric label would be a
working bypass sitting in a scrape endpoint, readable by anyone who can reach
`/metrics`.

## Datasets

Challenge outcomes may be stored as bounded numeric features. They are never
labels: a failed challenge does not mark a row malicious and a passed one does
not mark it benign. See [Challenge security](CHALLENGE_SECURITY.md) on the
feedback loop, and [Self-learning](SELF_LEARNING.md) on how a label is actually
produced. A person answering a review queue entry, and nothing else.

## The Secret

One local file, at least 32 bytes, `chmod 600`, never in Git, never in a log,
never in CLI output, never in a dataset. Per-site keys are derived from it with
HKDF, so hosting several sites on one server does not mean sharing one key
between them.

## What You Should Tell Your Users

If you publish a privacy notice, the accurate version is short:

> This site sometimes checks that your browser can complete an ordinary web
> request. The check sets a temporary cookie that expires within the hour. It
> contains no information about you, it is not used for advertising or
> analytics, and nothing is sent to any other company.
