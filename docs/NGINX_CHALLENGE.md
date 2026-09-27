# Nginx and the challenge

How the challenge fits alongside the P10 Nginx integration.

Read [Nginx integration](NGINX.md) first. Nothing there changes: Eye for an Eye
still reads a local JSON access log, still never edits your configuration, and
still never reloads Nginx.

Status: **Beta.** Shadow mode only is the recommended deployment.

## The honest position

P10 reads a log. A log is written *after* Nginx has answered the request, so the
P10 sensor cannot change what a client receives — which is why it is safe by
construction.

A challenge has to be decided while the request is still in flight. That is a
different position in the request path, and wiring it in means putting something
between Nginx and your site. This release provides the decision logic and the
response, tested end to end, and does not ship an Nginx module.

**What is implemented and tested:**

- the full decision: whether to challenge this request, and why not when the
  answer is no,
- the token: signing, verification, expiry, site scope, rotation,
- the response: status, headers, cookie, page,
- shadow mode, which needs no Nginx change at all,
- the `WebGateway` object that takes one request and returns one plan.

**What you have to wire up yourself:** the code that calls `WebGateway.handle`
for each request and acts on the plan.

Anyone telling you a one-line Nginx snippet makes this work has not tried it on
a site that people use.

## Start in shadow mode — no Nginx change needed

```toml
[challenge]
enabled = true
mode = "shadow"
secret_file = "/etc/eye-for-an-eye/challenge.secret"
site_id = "example.com"
```

In shadow mode the system decides everything and sends nothing. It needs only
the access log it already reads. Run it here first and look at the numbers:

```
eye-for-an-eye challenge stats
```

The number that decides whether to go further is how often ordinary traffic
would have been challenged. If it is not very close to zero, the thresholds are
wrong for your site, and no amount of Nginx configuration will fix that.

## Creating the secret

```bash
sudo install -d -m 750 /etc/eye-for-an-eye
head -c 48 /dev/urandom | base64 | sudo tee /etc/eye-for-an-eye/challenge.secret > /dev/null
sudo chmod 600 /etc/eye-for-an-eye/challenge.secret
sudo chown eye-for-an-eye:eye-for-an-eye /etc/eye-for-an-eye/challenge.secret
```

Then check it:

```bash
eye-for-an-eye challenge doctor
```

It refuses a secret shorter than 32 bytes, and refuses one that other users can
read. That refusal disables challenges; it does not stop the sensor.

## Wiring up an active challenge

Two shapes work. Both keep the rule from §65: **no Internet-facing control
endpoint.**

### Option A: in your application

If your site is an application you control, call the gateway from your
middleware. This is the simplest correct option, because your application
already knows the request.

```python
from eye_for_an_eye.challenge.service import from_config
from eye_for_an_eye.web.gateway import WebGateway
from eye_for_an_eye.web.identity import ClientResolver

gateway = WebGateway(
    resolver=ClientResolver(config.web.trusted_proxy_networks),
    challenge=from_config(config),
    sensor=sensor)

def middleware(request):
    plan = gateway.handle(
        peer=request.peer_address,
        method=request.method,
        path=request.path,
        forwarded=request.headers.get('X-Forwarded-For'),
        cookie=request.cookies.get('__efae_challenge'))
    if plan.plan == 'CHALLENGE':
        return Response(plan.status, plan.headers, plan.body)
    if plan.plan == 'RATE_LIMIT':
        return Response(plan.status, plan.headers, plan.body)
    return continue_normally(request)
```

`handle` never raises. If anything inside it fails, the plan says `PASS` and the
request goes through. That behaviour is not incidental — it is asserted by tests
that break each entry point on purpose.

### Option B: a local responder behind `auth_request`

If you cannot change the application, Nginx's `auth_request` can ask a local
service. The service must bind to a Unix socket or loopback only, and must
answer one question and nothing else.

```nginx
location / {
    auth_request /_efae;
    error_page 401 = @efae_challenge;
    # ... your normal configuration
}

location = /_efae {
    internal;                       # never reachable from outside
    proxy_pass http://unix:/run/eye-for-an-eye/challenge.sock:/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
}
```

Three things must be true of that service:

- it binds to a Unix socket or `127.0.0.1`/`::1`, never a public address;
- it answers only the challenge question — it is not an administrative endpoint,
  and it exposes no commands;
- if it is down, the site stays up. Set `proxy_next_upstream` and your
  `error_page` handling so that an unreachable responder means "allow", not
  "500". Test this by stopping the responder and loading the site.

That last point is the one people get wrong. A security component that returns
500 to every visitor when it fails has caused a worse outage than the scanner it
was watching for.

## Never reload without validating

Whatever you change:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Never reload without `nginx -t` first. Eye for an Eye will not do either for you,
and will not edit your configuration.

## Caching

Challenge responses are sent with `Cache-Control: no-store`. If Nginx or a CDN in
front of it is configured to cache regardless of origin headers, a challenge
meant for one client will be served to everyone and the site will break. Check
this before enabling active challenges — see
[Trusted proxies](TRUSTED_PROXIES.md).

## Rolling back

Challenges are off by default and disabling them is one line:

```toml
[challenge]
enabled = false
```

No Nginx change is needed to turn them off if you used option A. If you used
option B, remove the `auth_request` line and reload after `nginx -t`.
