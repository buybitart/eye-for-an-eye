# API clients and routes that must not be challenged

A browser challenge works because a browser stores a cookie and repeats the
request. Most non-browser clients do neither. Sending one a challenge does not
test it — it breaks it.

## Routes that are never challenged by default

| Prefix | Profile | Why |
| --- | --- | --- |
| `/api/` | API | JSON clients do not run a cookie and redirect flow |
| `/graphql` | API | same |
| `/login`, `/auth/`, `/oauth/` | AUTH | a redirect in the middle of a sign-in flow loses state |
| `/webhook`, `/webhooks/` | WEBHOOK | machine-to-machine; nothing to answer with |
| `/health`, `/healthz` | HEALTH | a failing check looks like an outage |
| `/.well-known/` | — | certificate issuance and discovery must keep working |

`eye-for-an-eye challenge doctor` prints this list for your configuration, so
you can check it rather than trust this table.

## Adding your own

```toml
[challenge]
# Treated as API routes: never challenged, still watched.
api_path_prefixes = ["/v2/", "/internal/", "/rpc"]

# Never challenged, for any other reason.
no_challenge_path_prefixes = ["/checkout/callback", "/sso/"]
```

Prefixes, not regular expressions. A big regular expression configuration is
hard to reason about and easy to get subtly wrong, and the cost of a mistake
here is a broken site.

## What happens to a suspicious API client instead

It is still watched, still scored, and can still be rate limited or blocked on
strong evidence. It just is not sent an HTML page it cannot use.

An API client that is genuinely abusing an endpoint reaches RATE_LIMIT and
TEMP_BLOCK by the same behavioural evidence as anything else. Skipping the
challenge rung means one fewer piece of evidence, which means the decision rests
on behaviour alone. That is the right trade for a client that could never have
answered the question.

## Unsafe methods are never challenged

POST, PUT, PATCH and DELETE are never sent a redirect challenge, on any route,
whatever the risk. A challenge replays the request, and replaying a POST can
submit a form twice or charge a card twice.

A suspicious POST is watched or rate limited instead. There are two independent
checks for this — the policy refuses the method, and the gateway refuses again
before building a response — because getting it wrong means duplicate purchases.

## Do not identify clients by User-Agent

The route policy is configuration, not detection. It does not read the
`User-Agent` header to decide what kind of client something is, and neither
should you when you configure it.

A `User-Agent` is a string the client chooses. Anything that trusts it can be
lied to for free — a scanner that calls itself `Googlebot` gets whatever
`Googlebot` gets. Behaviour is the signal; configuration is how you tell the
system about routes that are yours.

## Crawlers

There is no crawler allowlist, and crawler names are not trusted.

A well-behaved crawler produces behaviour that scores low: it requests pages
that exist, at a reasonable rate, over time. It does not need special treatment
to be left alone, and the LAB `crawler` fixture checks that it is.

If you want a specific crawler exempted, exempt the routes it uses, or verify it
yourself at the application layer and configure accordingly. Do not ask this
system to believe a header.

## Health checks

Configure your health-check route explicitly. It is in the default list, but if
yours is at `/-/live` or `/status/internal`, the system does not know that.

```toml
[challenge]
no_challenge_path_prefixes = ["/-/live"]
```

## Checking your configuration

```
eye-for-an-eye challenge doctor
```

Under "Never challenged" it prints every prefix that is exempt, defaults and
yours together. Read that list before switching `mode` to `"active"`.
