# Site profiles

A profile is a starting configuration. You pick the one that describes your
site, and sensible settings follow.

Profiles are **not** labels. `admin` does not mean "dangerous" and `api` does
not mean "trusted". They are never a training label and never an input to a
model — see [SITE_DATASETS.md](SITE_DATASETS.md) for why that matters.

## The four shapes

**WEBSITE** — a normal site people visit with a browser. Pages, static files,
sessions, crawlers. Many different paths is ordinary here. Browser challenges
work, so they are available.

**API** — machine clients. High request rates, very few endpoints, JSON, usually
no cookies. A browser challenge cannot be answered by a client that does not run
one, so it is off; suspicious API clients are watched and rate limited instead.

**ADMIN** — small, quiet, sensitive. A handful of known paths and a login. Path
breadth and authentication failures mean much more here than on a public site,
so the thresholds sit lower.

**MIXED** — a site that is several of these at once. Deliberately the least
opinionated: when a site is many things, tight thresholds are wrong for part
of it.

**CUSTOM** — nothing assumed. You set what you want.

## What each one starts with

| | website | api | admin | mixed |
| --- | --- | --- | --- | --- |
| Expected requests/minute | 240 | 1200 | 60 | 600 |
| Expected distinct paths | 40 | 12 | 10 | 60 |
| Expected error ratio | 10% | 5% | 2% | 12% |
| Watch threshold | 0.40 | 0.40 | 0.30 | 0.40 |
| Challenge threshold | 0.45 | — | 0.38 | 0.45 |
| Rate limit threshold | 0.70 | 0.70 | 0.60 | 0.70 |
| Block threshold | 0.88 | 0.88 | 0.85 | 0.88 |
| Browser challenge | yes | no | yes | yes |

These numbers are reasoned, not calibrated. No traffic study stands behind them.
They are a starting point for shadow mode, and you should expect to change them
once you have looked at your own numbers.

Every profile starts in **shadow mode**, with rate limiting off and host-wide
network blocking not allowed. Adding a site never switches anything on.

## Choosing and changing

```toml
[sites.profiles.api]
profile = "api"
domains = ["api.example.org"]
```

Override anything you like on top of the template:

```toml
[sites.profiles.api]
profile = "api"
domains = ["api.example.org"]
expected_requests_per_minute = 3000
block_threshold = 0.92
```

A misspelled setting is **refused**, not ignored. Silently dropping
`watch_treshold` would leave you believing you had tightened a site when you
had not, and nothing in the running system would contradict you.

## What a site cannot change

A site override adjusts that site's own behaviour. It cannot reach past the
global safety limits: memory bounds, protected networks, firewall ownership,
process limits, or automatic model promotion.

This is structural rather than checked — those things are not fields on a site
profile, so there is nothing to override. Naming one in a site's table is an
error.

```
GlobalSafetyPolicy  →  SitePolicy  →  Decision
```

A badly configured site must not make the whole sensor unsafe.

## The profile type is yours to set

The system does not change a site's profile because its traffic changed. An API
that starts serving HTML is still whatever you configured; only the behaviour
baseline adapts, and only in the controlled way described in
[SITE_BASELINES.md](SITE_BASELINES.md).

Automatic reclassification would mean an attacker who changes how they use your
site can change which policy applies to it.

## Routes

Each site can name routes that behave differently:

```toml
[sites.profiles.main]
profile = "website"
domains = ["example.org"]
api_path_prefixes = ["/v2/"]
no_challenge_path_prefixes = ["/sso/", "/-/live"]
```

Prefixes, not regular expressions, and bounded: at most 64 prefixes, each at
most 200 characters. A pathological route list is a slow path on every request
the site serves.

See [API_CLIENTS.md](API_CLIENTS.md) for which routes are never challenged by
default.
