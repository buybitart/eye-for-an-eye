# Multi-site

One Eye for an Eye server can protect more than one website.

Each website has its own security profile. A normal request rate can be
different for each site. The system keeps web behaviour separate. Network
behaviour can still help protect the full server.

Status: **Beta.** Off by default. Shadow mode for every new site.

## Why sites are not all the same

A blog and an API do not look alike, and neither is doing anything wrong.

| | Blog | API | Admin panel |
| --- | --- | --- | --- |
| Requests a minute | tens | hundreds or thousands | a handful |
| Different paths | many | very few | very few |
| Cookies | yes | usually not | yes |
| Missing pages | some | few | almost none |

Five hundred requests a minute is an ordinary Tuesday for the API and a serious
event on the admin panel. One threshold cannot describe both, and a system that
uses one will be wrong about at least one of them all the time.

So each site gets its own settings, its own idea of normal, and its own state.

## What is separate, and what is shared

**Separate, per site:** web behaviour counters, baselines, thresholds and
policy, challenge keys, drift, out-of-distribution reference, dataset scope.

**Shared, on purpose:** the engine, the base model, the global safety limits,
and network-layer evidence about the machine.

That last one is worth a sentence. A source scanning ports 22, 80, 443 and 3306
has told you something about the *server*, and that does not stop being true
when you look at it from a different website. Throwing it away in the name of
isolation would make a multi-site install worse at detection than a single-site
one, for no benefit. So evidence is separated by kind rather than discarded:

```
HOST_NETWORK_EVIDENCE   about the machine — shared
SITE_WEB_EVIDENCE       about one site's HTTP traffic — never shared
```

## Sites come from your configuration, never from a request

A `Host:` header is a string the client writes. If a site could be identified
from it, a client could pick which site's policy applied to it, which site's
cryptographic key signed its token, and could invent a new site per request.

So the header is used for exactly one thing: looking up an entry in your table.
A miss is a miss — the request goes to one bounded `unknown-site` bucket, which
is a single bucket and not a new site per host.

See [CROSS_SITE_SECURITY.md](CROSS_SITE_SECURITY.md).

## Turning it on

Multi-site is off by default, and a single-site owner never needs it. Nothing in
this page applies until you add a `[sites]` section.

```toml
[sites]
enabled = true

[sites.profiles.main]
profile = "website"
domains = ["example.org", "www.example.org"]

[sites.profiles.api]
profile = "api"
domains = ["api.example.org"]
```

`example.org` is a placeholder. Use your own domains.

Then:

```bash
eye-for-an-eye sites list
eye-for-an-eye sites doctor
```

Every new site starts in shadow mode. Adding a second site never switches on
blocking, challenges or rate limiting.

## Commands

```
eye-for-an-eye sites list              every site, one line each
eye-for-an-eye sites show <site>       one site, in full
eye-for-an-eye sites doctor            is the configuration correct and safe
eye-for-an-eye sites baseline <site>   what this site's normal looks like
eye-for-an-eye sites drift <site>      has this site's traffic moved
eye-for-an-eye sites models <site>     which model answers for this site
```

All of them read. None changes enforcement or reloads anything.

## Limits

| | |
| --- | --- |
| Sites | 32 by default, hard maximum configurable |
| Sources across all sites | 8192, shared |
| Reserved per site | 64 sources it can always claim |
| Maximum per site | 2048 |

More sites divide one budget rather than multiplying it. Measured: ten sites and
twenty sites use the same memory at the same ceiling.

## What this is not

This is not hosting-provider multi-tenancy. It has been tested with up to twenty
sites on one machine, which is the shape it was built for: a VPS with a handful
of websites on it. There is no isolation boundary between sites beyond the ones
described here — they share a process, and an operator who can configure one can
configure all of them.

## Further reading

- [Site profiles](SITE_PROFILES.md) — website, API, admin
- [Site baselines](SITE_BASELINES.md) — what normal means per site
- [Multi-site models](MULTI_SITE_MODELS.md) — which model answers for which site
- [Cross-site security](CROSS_SITE_SECURITY.md) — the threats and the limits
- [Multi-site Nginx](MULTI_SITE_NGINX.md) — server blocks and mapping
- [Site datasets](SITE_DATASETS.md) — per-site data, and the leakage it invites
