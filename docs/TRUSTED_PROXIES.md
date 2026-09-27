# Trusted proxies and challenges

How the challenge subsystem behaves behind a reverse proxy or a CDN.

The rules for *resolving* a client address are in
[Reverse proxies, CDNs and client identity](REVERSE_PROXY.md), and they are
unchanged in P11. This page covers what is new: what a challenge does with the
result.

## The one-line version

A challenge is safe behind a proxy. A network block is not.

## Why they are different

A network block acts on an address. Behind a CDN, that address is the CDN, and
the CDN is carrying every other visitor to your site. Blocking it takes the site
off the air for everyone.

A challenge is an HTTP response. It travels back down the same connection the
request came in on, through the proxy, to the one client that asked. Nobody else
sees it.

So the ceilings are different:

| | Direct client | Behind a trusted proxy |
| --- | --- | --- |
| OBSERVE | yes | yes |
| WATCH | yes | yes |
| SOFT_CHALLENGE | yes | **yes** |
| RATE_LIMIT | yes | yes, by client identity |
| TEMP_BLOCK | yes | **never** |

Every proxied client is `network_enforceable = False`, and the web sensor caps
the action at RATE_LIMIT with a reason that says why. This is a regression test,
not a convention: `test_challenge_lab.py` and `test_web_enforcement_safety.py`
both check it, and one of them checks the control case too — a *direct* scanner
must still reach TEMP_BLOCK, or the test proves nothing.

## Configuration

```toml
[web]
enabled = true
trust_forwarded_headers = true
trusted_proxy_networks = ["203.0.113.0/24", "2001:db8::/32"]
```

Set `trusted_proxy_networks` to your actual proxies and nothing else. This list
is the entire basis for believing a forwarded header. If it is wider than your
real proxy set, anyone inside the extra range can claim to be anyone.

With no trusted proxies configured, forwarded headers are read and ignored, and
the address that actually connected is used. For a directly exposed server that
is correct.

## Challenge state is per client, not per proxy

Each resolved client gets its own challenge context. Twelve clients behind one
CDN address are twelve contexts, not one.

This matters more than it sounds. If challenge state were keyed by the proxy
address, one scanner behind a CDN would spend the whole site's budget, put every
other visitor into a challenge loop, and drive the shared context to a
rate-limit decision. The LAB fixtures check exactly this: a scanner and an
ordinary browser arriving through the same CDN address end with different risk
scores, and the ordinary one is never challenged.

## When the proxy does not tell you who the client is

If a proxy forwards nothing usable, every client behind it resolves to the same
address, with `MEDIUM` or `LOW` confidence.

The system does not guess. It says so:

- data quality drops, which lowers the strongest available action,
- `LOW` confidence caps the action at WATCH and refuses a challenge outright —
  a challenge is attached to a client, and if you do not know which client,
  there is nothing to attach it to,
- `proxy_identity_uncertain_total` counts it.

If you see that counter rising, fix the proxy configuration. Until it is fixed,
the web layer is watching an aggregate and cannot act safely, which is the
correct behaviour but not a useful one.

## CDN caching

A challenge response is meant for one client. Every one is sent with
`Cache-Control: no-store` and `Pragma: no-cache`.

If your CDN is configured to cache aggressively and ignore origin cache headers,
**do not enable active challenges** until that is changed. A cached challenge
served to every visitor is a site-wide outage, and it is the failure mode most
likely to be discovered by your users rather than by you.

Check this before stage 3 of the deployment sequence in
[Progressive defense](PROGRESSIVE_DEFENSE.md).

## Cookies through a proxy

The challenge cookie is set on your site's domain by your origin, so it travels
like any other cookie your application sets. Two things to check:

- **HTTPS termination.** If the proxy terminates TLS and talks to the origin
  over plain HTTP, `cookie_secure = true` is still correct: the cookie's
  `Secure` attribute is about the browser's connection, not the origin's.
- **Cookie stripping.** Some CDN configurations strip cookies on cached routes.
  On those routes the challenge cannot work, and clients will be asked up to
  `max_attempts` times before the system gives up. Add such routes to
  `no_challenge_path_prefixes`.

## Checking it

```
eye-for-an-eye challenge doctor
```

The "Trusted proxy" section reports whether proxies are configured and which
networks are trusted. `eye-for-an-eye web doctor` covers the identity side in
more detail.
