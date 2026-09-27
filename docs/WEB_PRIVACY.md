# Web privacy

Web telemetry is more sensitive than packet metadata. A URL is not just a
resource name — it can be a password reset token, an account id, an email
address, a search term, or the title of a document somebody is reading.

So this page says exactly what is kept.

Status: **Beta.**

## Never stored, at any setting

```text
Authorization headers      cookies and Set-Cookie
session tokens             request bodies
passwords and form data    API keys
```

This is not a default. There is no configuration that turns it on. A log line
containing one of these fields is **dropped whole**, and `web doctor` reports it
so the operator can fix the log format that is currently writing credentials to
disk.

## Not stored by default

| Thing | Default | Setting |
| --- | --- | --- |
| the full request path | not stored | `web.store_raw_path` |
| query string values | not stored | `web.store_query_values` |

Turning either on is recorded by `web doctor` as `DEGRADED` with the reason, so
it is visible rather than forgotten.

## What is kept instead

Derived numbers, which are what behaviour analysis actually needs.

From the path:

```text
path_depth          how many segments
path_length         how long
path_entropy        does it look generated
extension_category  static, document, script, archive, other, none
sensitive_category  configuration, admin, backup, version_control, cms,
                    database_admin
path_key            a keyed digest, for counting repeats
```

From the query string:

```text
query_present            was there one
query_length             how long
query_parameters         how many
query_encoded_ratio      how much percent-encoding
query_duplicate_parameters
```

From the User-Agent:

```text
agent_present   was one sent
agent_length    how long
agent_family    declared_browser, declared_bot, declared_tool, other
agent_digest    for counting changes
```

The User-Agent string itself is never kept. Neither is the Host name — only a
digest, so many different Host values can be counted without the names being
stored.

## The path key

Repeated-path detection needs to know "the same thing again", not "what thing".

`path_key` is an HMAC of the normalised path under a local secret, truncated to
16 hex characters. It says a source asked for the same resource nine times. It
does not say which resource.

The secret is a local file that is never committed and never leaves the machine.
Without it, no key is produced and repeat counting is simply disabled.

**It is a counting key, never a model feature.** A digest carries no meaning a
model could learn from, and letting one in would be a way for the model to
memorise a site rather than learn behaviour.

## Addresses

A client address is kept, because acting on behaviour requires knowing whose
behaviour it is. Two things follow from that:

* an address is **a source, not a person** — one address can be an office, a
  mobile network, a university, or a CDN carrying thousands of people;
* an address behind a proxy is never blocked at the network layer, precisely
  because of the above ([REVERSE_PROXY.md](REVERSE_PROXY.md)).

## Log injection

Every string that comes from a request is stripped of control characters and
length-bounded before anything is done with it.

A User-Agent containing `\r\n` cannot produce a second line in a report, a log or
a terminal. This is tested.

## Retention

Per-source behavioural state is bounded and expires:

| Bound | Default |
| --- | --- |
| sources tracked | 4096 |
| requests kept per source | 512 |
| distinct paths counted per source | 64 |
| how long a quiet source is kept | 30 minutes |

Nothing accumulates. A source that stops being seen is dropped.

Your web server's own access log is a separate thing with its own retention.
Eye for an Eye reads it; it does not copy it, and it does not keep a second
archive of your web traffic.

## What a stored event looks like

```json
{
  "at": "2026-09-10T12:00:00Z",
  "client": "198.51.100.7",
  "identity_confidence": "HIGH",
  "method": "GET",
  "status": 404,
  "path_depth": 1,
  "path_length": 5,
  "path_entropy": 0.387,
  "extension": "other",
  "sensitive": ["configuration"],
  "query": {"query_present": true, "query_parameters": 2, "query_length": 19},
  "agent": {"agent_present": true, "agent_family": "declared_tool"},
  "contents": "behavioural metadata only; no path, no query values, no header, no body, no credential"
}
```

The request that produced it was:

```text
GET /wp-admin/../.env?token=secret123&x=1
User-Agent: curl/8.5
```

`secret123` is not in the event. Neither is `.env`, `curl/8.5`, or the path.

## Related

* [PRIVACY.md](PRIVACY.md) — the project's wider privacy position
* [NGINX.md](NGINX.md) — what the log format requests
* [WEB_PROTECTION.md](WEB_PROTECTION.md) — what the data is used for
