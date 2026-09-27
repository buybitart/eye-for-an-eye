# Nginx Integration

Eye for an Eye reads a local Nginx access log written in JSON.

It does **not** parse HTTP itself. Nginx already does that, correctly, and has
for years. Writing a second HTTP parser here would add an attack surface and gain
nothing.

Status: **Beta.** Nginx is the only implemented reader.

## What It Changes

Nothing, unless you do it yourself.

Eye for an Eye never edits your Nginx configuration, never reloads Nginx, and
never writes into `/etc/nginx`. `eye-for-an-eye web log-format` prints text; you
install it, you run `nginx -t`, you reload.

## Step 1: The Log Format

```bash
eye-for-an-eye web log-format
```

It prints:

```nginx
log_format eye_for_an_eye escape=json
    '{'
    '"time":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"forwarded_for":"$http_x_forwarded_for",'
    '"method":"$request_method",'
    '"uri":"$uri",'
    '"args":"$args",'
    '"status":$status,'
    '"bytes_sent":$bytes_sent,'
    '"request_length":$request_length,'
    '"request_time":$request_time,'
    '"protocol":"$server_protocol",'
    '"host":"$host",'
    '"user_agent":"$http_user_agent",'
    '"referer":"$http_referer"'
    '}';
```

Put it in the `http` block, then add one line to the site:

```nginx
access_log /var/log/nginx/eye-for-an-eye.log eye_for_an_eye;
```

Keep it in a file you own, so nothing here touches a large shared config:

```text
/etc/nginx/conf.d/eye-for-an-eye.conf
```

Then, always:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Why These Fields

Every one is used. Nothing is requested "just in case".

| Field | Used for |
| --- | --- |
| `time` | ordering and window boundaries |
| `remote_addr` | the peer that connected. The anchor for client identity |
| `forwarded_for` | the client, **only** if the peer is a trusted proxy |
| `method` | method behaviour |
| `uri` | derived features only; the path itself is not stored |
| `args` | shape only: how many parameters, how long; never the values |
| `status` | error ratios |
| `bytes_sent`, `request_length` | response and request size |
| `request_time` | timing |
| `protocol`, `host` | protocol quality, virtual host enumeration |
| `user_agent` | presence, length and broad family; never the string |
| `referer` | present or absent only |

`escape=json` matters. Without it a User-Agent containing a quote breaks the line
and the request is lost.

## What Must Not Be Logged

```text
$http_authorization    $http_cookie    $sent_http_set_cookie
request body           any form field  any password
```

A line carrying one of these is **dropped whole**, and `web doctor` reports it as
`UNAVAILABLE` with what to fix. Silently stripping it would hide the real problem:
your access log is currently writing credentials to disk, where backups and log
shipping will pick them up.

## Step 2: Permissions

The web sensor needs to read the log. It must **not** run as root to do it.

```bash
sudo usermod -a -G adm eye-for-an-eye     # Debian and Ubuntu
sudo setfacl -m u:eye-for-an-eye:r /var/log/nginx/eye-for-an-eye.log
```

Use whichever your distribution prefers. The point is least privilege: reading a
log file is not a reason to give a process the whole machine.

## Step 3: Configuration

```toml
[web]
enabled = true
source_type = "nginx"
access_log_path = "/var/log/nginx/eye-for-an-eye.log"
secret_file = "/etc/eye-for-an-eye/web.secret"
trusted_proxy_networks = []      # see REVERSE_PROXY.md before filling this in
```

The secret is a local key that lets repeated paths be counted without the path
being kept:

```bash
head -c 48 /dev/urandom | base64 | sudo tee /etc/eye-for-an-eye/web.secret
sudo chmod 600 /etc/eye-for-an-eye/web.secret
```

## Step 4: Check It

```bash
eye-for-an-eye web doctor
```

It checks the log exists and is readable, that the format parses, that no
credential field is present, whether trusted proxies are configured, whether the
secret is present and private, and whether enforcement is set up safely. It
changes nothing.

## Log Rotation

Handled, and worth explaining because it is where log readers usually fail
silently.

Rotation is detected by **inode**, not by name, logrotate's default renames the
file the reader is holding open, so a reader watching only the path keeps reading
a file nobody writes to any more, forever, without an error.

Truncation (`copytruncate`) is detected separately: same inode, but the file is
now shorter than where we were reading.

On either, the reader drains what is left of the old file, reopens, and counts a
rotation. `web status` shows the count.

No special logrotate configuration is needed.

## Bounds

| Bound | Value | Why |
| --- | --- | --- |
| line length | 16 KB | a line longer than this is not Nginx's |
| lines per poll | 2000 | a burst must not starve the network sensor |
| path length | 2048 | attacker-controlled |
| query length | 2048 | attacker-controlled |
| path segments | 32 | attacker-controlled |
| user agent | 512 | attacker-controlled |

Anything over a bound is truncated or the line is dropped and counted. Nothing
grows with what a client sends.

## Other Web Servers

The event model is generic. Apache and Caddy readers are **not implemented**;
their status is planned, not experimental, because no code exists for them yet.

Any source that can produce the same JSON fields will work through the same
reader.

## Related

* [REVERSE_PROXY.md](REVERSE_PROXY.md): read this before setting trusted proxies
* [WEB_PRIVACY.md](WEB_PRIVACY.md): what is kept
* [WEBSITE_QUICKSTART.md](WEBSITE_QUICKSTART.md): the whole setup in order
