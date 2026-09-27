# Website Quick Start

Watching a website with Eye for an Eye, in order, with nothing enabled that
could take your site down.

Status: **Beta.** Shadow Mode only.

## What You Need

* a Linux server running Nginx
* permission to edit Nginx configuration and reload it
* Python 3.12 or newer

## What This Will and Will Not Do

It will read a local access log and tell you which sources look like automated
probing.

It will **not** block anything. Automatic blocking is off, web-layer blocking is
not implemented, and Shadow Mode is on.

## 1. Install

```bash
python3 -m pip install --user eye-for-an-eye
```

Or from a checkout:

```bash
python3 -m pip install --user .
```

## 2. Create the Website Profile

```bash
eye-for-an-eye setup --profile website
```

This writes a configuration with safe defaults: shadow mode on, blocking off,
active probing off, local API bound to localhost only.

## 3. Add the Log Format

```bash
eye-for-an-eye web log-format
```

Copy what it prints into a file you own:

```bash
sudo nano /etc/nginx/conf.d/eye-for-an-eye.conf
```

Add one line to your site's `server` block:

```nginx
access_log /var/log/nginx/eye-for-an-eye.log eye_for_an_eye;
```

Check and reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Never reload without `nginx -t` first.

## 4. Let the Log Be Read

The analyser must not run as root just to read a log.

```bash
sudo usermod -a -G adm eye-for-an-eye
```

## 5. Make a Local Key

Lets repeated paths be counted without the path being stored.

```bash
head -c 48 /dev/urandom | base64 | sudo tee /etc/eye-for-an-eye/web.secret
sudo chmod 600 /etc/eye-for-an-eye/web.secret
```

## 6. Configure

```toml
[web]
enabled = true
source_type = "nginx"
access_log_path = "/var/log/nginx/eye-for-an-eye.log"
secret_file = "/etc/eye-for-an-eye/web.secret"

# Leave empty if your server is directly exposed.
# If you are behind Nginx, a load balancer or a CDN, read REVERSE_PROXY.md first.
trusted_proxy_networks = []
```

## 7. Check It

```bash
eye-for-an-eye web doctor
```

Expected:

```text
Web integration:
HEALTHY

Access log:
HEALTHY — /var/log/nginx/eye-for-an-eye.log

Log format:
HEALTHY (20 of 20 sampled lines parsed)

Trusted proxy:
Not configured

Privacy:
behavioural metadata only

Enforcement:
off — automatic blocking is off; web decisions are recorded only
```

"Trusted proxy: Not configured" is correct for a directly exposed server. If you
are behind a proxy, see step 9.

## 8. Watch

```bash
eye-for-an-eye web status      # is it receiving anything
eye-for-an-eye web sources     # which sources, and what they scored
eye-for-an-eye web incident <address>   # one source, in full
```

A real incident looks like this:

```text
WEB INCIDENT

Source:
198.51.100.77

Requests:
120

Unique paths:
111

Not found:
100% of responses

Sensitive probes:
10 across 1 categories

Web risk:
0.78

Decision:
RATE_LIMIT

Reasons:
  - 111 different paths in 60 seconds, 100% of responses were not found
  - 100% of responses were client errors (100% not found)
  - about 120 requests per minute
  - 5 independent kinds of evidence agree

Reduced because:
  - shadow mode: nothing was enforced
```

## 9. If You Are Behind a Proxy or CDN

**Read [REVERSE_PROXY.md](REVERSE_PROXY.md) before this step.** Getting it wrong
is silent in both directions.

```toml
[web]
trusted_proxy_networks = ["203.0.113.0/24"]
```

List only the networks your own proxy uses. Never a wide public range: anyone
inside it could then claim to be any address.

A client behind a proxy is never blocked at the network layer, whatever it does.
That would hit the proxy and everyone else behind it.

## 10. Run It for a Week

Then read what it *would* have done.

Look for sources it scored highly that you recognise: your monitoring, your
uptime checker, your own API client, a crawler you want. If any of those scored
above WATCH, adjust before considering enforcement:

* an API using PUT or DELETE → add them to `web.expected_methods`
* monitoring from a known address → add it to `enforcement.allowlist`

## 11. Optional: Prepare the Challenge, in Shadow Mode

Instead of blocking a client the system is unsure about, it can ask it a
question. See [CHALLENGE.md](CHALLENGE.md) for what that means.

Challenges are off by default. Preparing them in shadow mode is safe: the system
decides everything and sends nothing, so you can read the numbers before anyone
is affected.

Create a local secret:

```bash
sudo install -d -m 750 /etc/eye-for-an-eye
head -c 48 /dev/urandom | base64 | sudo tee /etc/eye-for-an-eye/challenge.secret > /dev/null
sudo chmod 600 /etc/eye-for-an-eye/challenge.secret
```

Then:

```toml
[challenge]
enabled = true
mode = "shadow"
secret_file = "/etc/eye-for-an-eye/challenge.secret"
site_id = "example.com"
```

Set `site_id` to something stable that identifies this site. It is not the
`Host` header. A client controls that header, so using it as a cryptographic
scope would let a client pick its own key.

Check it:

```bash
eye-for-an-eye challenge doctor
```

Read the "Never challenged" list it prints. If your API, your sign-in flow or
your health check is not on it, add it before going any further:

```toml
[challenge]
api_path_prefixes = ["/v2/"]
no_challenge_path_prefixes = ["/-/live", "/sso/"]
```

After a week:

```bash
eye-for-an-eye challenge stats
```

The number that matters is how often ordinary traffic would have been
challenged. It should be very close to zero. If it is not, the thresholds are
wrong for your site. Fix that before you send a single real challenge.

## What Next

Enabling automatic blocking is a separate decision with its own risks, and this
release does not recommend it for a public website. Read
[WEB_ENFORCEMENT.md](WEB_ENFORCEMENT.md) first.

Sending real challenges is also a separate decision. Read
[PROGRESSIVE_DEFENSE.md](PROGRESSIVE_DEFENSE.md) for the staged sequence, and
[NGINX_CHALLENGE.md](NGINX_CHALLENGE.md) for what wiring one up actually
involves.

## If Something Is Wrong

| Symptom | Cause |
| --- | --- |
| `Access log: UNAVAILABLE` | wrong path, or not readable by the service user |
| `Log format: UNAVAILABLE` | the log is not JSON, so reinstall the log_format |
| `sensitive_fields` reported | your log format is writing credentials; remove them |
| `web status` shows 0 lines | Nginx has not written since the sensor started |
| every client looks like one address | you are behind a proxy; see step 9 |
| `Challenge: DISABLED` | challenges are not enabled; this is the default |
| `Secret: DEGRADED` | run `chmod 600` on the secret file |
| `Site scope: NOT_CONFIGURED` | set `challenge.site_id` if this server hosts more than one site |

## Related

* [WEB_PROTECTION.md](WEB_PROTECTION.md)
* [NGINX.md](NGINX.md)
* [REVERSE_PROXY.md](REVERSE_PROXY.md)
* [WEB_PRIVACY.md](WEB_PRIVACY.md)
* [CHALLENGE.md](CHALLENGE.md)
* [PROGRESSIVE_DEFENSE.md](PROGRESSIVE_DEFENSE.md)
* [API_CLIENTS.md](API_CLIENTS.md)
* [TRUSTED_PROXIES.md](TRUSTED_PROXIES.md)
