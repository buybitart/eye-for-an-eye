# Web Protection

Eye for an Eye can watch how sources use your website, and use that as evidence
alongside network behaviour.

**It is not a web application firewall.** It does not look for exploits, does not
carry a signature database, and does not replace Nginx, Apache, Caddy, your
application's own authentication, or a mature WAF. It answers a different
question: *what is this source doing, and does it look like a person or a
script working through a list?*

Status: **Beta.** Shadow Mode only is the recommended deployment.

## The Short Version

Eye for an Eye can read safe request data from a local web server.

It does not need the request password or body.

It looks at behaviour over time. For example, many missing pages and repeated
probes can increase risk.

## What It Can See

Behaviour, over three windows: ten seconds, one minute, fifteen minutes.

| Family | Example |
| --- | --- |
| RATE | requests per minute |
| PATH DISCOVERY | how many different resources, how many were missing |
| AUTHENTICATION | failed sign-ins and how many of the attempts failed |
| HTTP ERRORS | share of 404, 403, 401 and other client errors |
| METHOD BEHAVIOUR | methods this service does not expect |
| TIMING | how regular the gaps between requests are |
| SESSION | no referer, no user agent, no static assets |
| PROTOCOL QUALITY | many Host values, unknown methods |
| PERSISTENCE | how long this has continued |

Evidence has to be **diverse** before it counts for much. A high request rate on
its own is a busy client. A high rate *and* many distinct paths *and* almost
everything missing *and* metronomic timing *and* fifteen minutes of it is a
different claim.

## What It Will Not Do

**It never blocks on one URL.** There is no rule anywhere that says
`if path == "/.env": block()`. One request to a sensitive path is a probe, an
administrator, a monitoring check, or somebody's bookmark. It is evidence, and
in this project one piece of evidence is never a decision.

**It never treats a bot as automatically bad.** Monitoring, uptime checkers,
search crawlers and API clients are automation you want. The label is
*suspicious automation-like behaviour*, not *bot*.

**It never trusts a User-Agent.** Anything can claim to be Googlebot. It is one
low-confidence feature and it can never allow or deny on its own.

## HTTPS

This matters and is often glossed over elsewhere.

**Packet capture cannot see inside HTTPS.** If traffic is encrypted when it
reaches the network sensor, there is no path, no method and no status code in it
, only that a connection happened, and how big and how often.

So web behaviour comes from where the traffic is already decrypted: the web
server or reverse proxy that terminates TLS, through its access log. That is
what the web sensor reads.

The project does not claim otherwise anywhere. If a tool tells you it inspects
HTTP inside HTTPS from packet capture alone, it is either terminating TLS
somewhere or it is wrong.

## How It Fits With the Network Sensor

```text
        website traffic
              |
    +---------+---------+
    |                   |
 network sensor     web sensor
    |                   |
 network features   HTTP features
    |                   |
    +---------+---------+
              |
        combined evidence
              |
     maths + model + anomaly
              |
      out-of-distribution / data quality
              |
           policy
              |
  OBSERVE / WATCH / RATE_LIMIT / TEMP_BLOCK
```

HTTP behaviour is evidence. It does not replace network behaviour, and it does
not get its own separate firewall.

Cross-layer is where it earns its place: a source that scans several TCP ports,
finds the web server, and then works through a hundred URLs is moderately
suspicious on each layer alone and clearly suspicious taken together.

## Safety

Two rules protect availability, and both are structural rather than
configurable.

**A client behind a proxy is never blocked at the network layer.** See
[REVERSE_PROXY.md](REVERSE_PROXY.md). Blocking a CDN address takes the site off
the air for everyone behind it, so the strongest action available there is a
rate limit.

**Nothing unbounded is stored.** A source can request a million distinct URLs. It
will cost the same as sixty-four, because paths are counted in a fixed-size ring
of digests and never stored. The protection must not become the outage.

## Getting Started

```bash
eye-for-an-eye web log-format     # the Nginx log_format to install
eye-for-an-eye web doctor         # is it set up correctly and safely?
eye-for-an-eye web status         # is it receiving anything?
eye-for-an-eye web sources        # which sources are being watched
eye-for-an-eye web incident <ip>  # one source, in full
```

Full walk-through: [WEBSITE_QUICKSTART.md](WEBSITE_QUICKSTART.md).

## Defaults

| Setting | Default |
| --- | --- |
| web analysis | off until you enable it |
| Shadow Mode | on |
| network blocking | off |
| web-layer blocking | not implemented |
| trusted proxy networks | none, forwarded headers ignored |
| storing full paths | off |
| storing query values | off |
| storing credentials or bodies | never, at any setting |

## Known Limits

* Only Nginx JSON access logs are read. The event model is generic; Apache and
  Caddy readers are not implemented.
* Authentication outcomes need the application to log them. Without that, the
  authentication family stays empty.
* There is no web-layer blocking. A rate limit is recorded as a decision; nothing
  applies it at the web server.
* WebSocket and HTTP/2 stream behaviour beyond what the access log records is not
  analysed.
* All thresholds are provisional and not yet supported by production data.

## Related

* [NGINX.md](NGINX.md): the integration
* [REVERSE_PROXY.md](REVERSE_PROXY.md): client identity and CDN safety
* [HTTP_FEATURES.md](HTTP_FEATURES.md): every feature and what it means
* [WEB_PRIVACY.md](WEB_PRIVACY.md): what is stored and what is not
* [WEB_ENFORCEMENT.md](WEB_ENFORCEMENT.md): what can and cannot be acted on
