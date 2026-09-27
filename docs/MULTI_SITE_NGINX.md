# Multi-site and Nginx

How several Nginx server blocks map to several Eye for an Eye sites.

Read [NGINX.md](NGINX.md) first. Nothing there changes: Eye for an Eye still
reads a local JSON access log, still never edits your configuration, and still
never reloads Nginx.

## One Log, Several Sites

You do not need one log per site. The log format already records `$host`, and
that is what the site resolver matches against your configuration.

```nginx
log_format eye_for_an_eye escape=json
    '{'
    '"time":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"forwarded_for":"$http_x_forwarded_for",'
    '"method":"$request_method",'
    '"uri":"$uri",'
    '"status":$status,'
    '"host":"$host",'
    ...
    '}';
```

Run `eye-for-an-eye web log-format` for the exact text, install it, check it
with `nginx -t`, and reload it yourself.

Separate log files per site work too. Both arrangements resolve the same way,
because the site comes from the host field and not from which file the line was
in.

## Mapping Server Blocks to Sites

```nginx
server {
    server_name example.org www.example.org;
    access_log /var/log/nginx/eye-for-an-eye.log eye_for_an_eye;
}

server {
    server_name api.example.org;
    access_log /var/log/nginx/eye-for-an-eye.log eye_for_an_eye;
}
```

```toml
[sites.profiles.main]
profile = "website"
domains = ["example.org", "www.example.org"]

[sites.profiles.api]
profile = "api"
domains = ["api.example.org"]
```

Every `server_name` you want protected must appear in exactly one site's
`domains`. A domain in two sites is refused at startup.

## `$host` and `$http_host`

Use `$host`. Nginx sets it from the request line or the `Host` header, and
normalises to lowercase without the port.

Either way the value is client-controlled, and the resolver treats it as such:
it is a lookup key, never an identity. A value that matches nothing goes to the
bounded `unknown-site` bucket.

## The Default Server Block

If you have a catch-all `server` block, traffic to unconfigured hostnames
reaches it and appears in the log with whatever host the client sent. Those
requests land in `unknown-site`.

That is the intended behaviour, and it is why `sites.default_site` is empty by
default. Setting it makes unmatched traffic run under a real site's policy,
which `sites doctor` flags. A scanner sweeping hostnames should not be judged
by your main site's rules.

## Do Not Discover Sites From Traffic

Eye for an Eye will not add a site because it saw a hostname. Unknown hosts
appear constantly (scanners sweep them), and treating traffic as a source of
configuration is how an attacker gets to create entries in your security
config.

Setup may read your local Nginx configuration and *propose* sites for you to
confirm. Proposals come from files on your disk, never from requests.

## Certificates

A certificate's subject alternative names can suggest which hostnames you serve,
and that is a reasonable hint during setup. It is not authoritative: a
certificate may cover hostnames you no longer serve, or omit ones you do. The
configuration is what decides.

## Behind a Proxy or CDN

Unchanged from P10 and P11. See [TRUSTED_PROXIES.md](TRUSTED_PROXIES.md). Two
sites behind the same trusted proxy resolve their clients independently, and
neither can get the proxy's address blocked.

## Checking

```bash
eye-for-an-eye sites doctor
```

It prints the domain map, flags any site with no domains (such a site can never
match anything), and flags a configured default site.
