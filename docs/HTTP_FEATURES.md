# HTTP features

Every web feature, what it means, and why a single one is never enough.

Status: **Beta.** All ceilings and weights are provisional.

## Families

Features are grouped so that evidence has to be *diverse* before it counts. The
score rewards independent families agreeing, not one family shouting.

```text
RATE               PATH_DISCOVERY     AUTHENTICATION
HTTP_ERRORS        METHOD_BEHAVIOUR   TIMING
SESSION            PROTOCOL_QUALITY   PERSISTENCE
```

## The features

Every value is bounded. The ceiling is the point where a feature has said as
much as it can; beyond it the value saturates rather than dominating.

### RATE

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `requests_10s` | 60 | requests in the last ten seconds |
| `requests_60s` | 300 | requests in the last minute |
| `requests_900s` | 2000 | requests in the last fifteen minutes |
| `request_rate_per_minute` | 240 | rate over the minute window |

Rate alone is deliberately weak. A CDN, a monitoring system, a load test or a
search crawler all produce high rates legitimately.

### PATH_DISCOVERY

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `unique_paths_60s` | 40 | distinct resources in a minute |
| `unique_paths_900s` | 64 | distinct resources over fifteen minutes |
| `path_request_ratio` | 1 | how many requests were to something new |
| `repeated_path_ratio` | 1 | how many were repeats |
| `path_entropy_mean` | 1 | do the paths look generated |
| `sensitive_probe_count` | 12 | requests to sensitive categories |
| `sensitive_category_count` | 6 | how many different categories |

Many paths is not enumeration. A crawler visits many paths and **finds** them.
What separates enumeration is that most of the guesses fail.

### AUTHENTICATION

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `failed_auth_60s` | 20 | failed sign-ins in a minute |
| `failed_auth_900s` | 60 | failed sign-ins over fifteen minutes |
| `auth_failure_ratio` | 1 | share of attempts that failed |

These need your application to log an authentication outcome. Without it the
family stays empty, which is honest: the system cannot see what it was not told.

Passwords are never involved. Usernames are not stored.

### HTTP_ERRORS

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `http_404_ratio` | 1 | share of responses that were not found |
| `http_401_ratio` | 1 | share unauthorised |
| `http_403_ratio` | 1 | share forbidden |
| `http_4xx_ratio` | 1 | share of all client errors |
| `http_5xx_ratio` | 1 | share of server errors |
| `http_2xx_ratio` | 1 | share that succeeded |

**5xx is not attacker proof.** It usually means your application has a bug, is
overloaded, or was just deployed. It is kept as a feature but weighted for what
it is, and service health is a separate concern from security state.

### METHOD_BEHAVIOUR

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `method_diversity` | 6 | how many distinct methods |
| `unexpected_method_ratio` | 1 | share the service does not expect |

What counts as unexpected depends on the application. An API that uses PUT and
DELETE should say so:

```toml
[web]
expected_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"]
```

Otherwise its normal traffic reads as method probing.

### TIMING

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `interval_mean_60s` | 60 | mean gap between requests |
| `interval_cv_60s` | 2 | how much that gap varies |
| `interval_entropy_60s` | 1 | how predictable the gaps are |
| `burst_10s` | 1 | share of the minute in the last ten seconds |

Low variation is the clearest automation signal there is. A person browsing
produces irregular gaps; a loop does not. Entropy is included because a script
that randomises its delay still produces a *distribution* unlike a person's.

### SESSION

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `static_resource_ratio` | 1 | share that were assets |
| `no_referer_ratio` | 1 | share with no referer |
| `no_user_agent_ratio` | 1 | share with no user agent |
| `agent_change_rate` | 1 | how often the user agent changed |

A browser loading a page pulls CSS, JavaScript, images and fonts. A script asking
only for HTML does not. Each signal is weak on its own — an API client looks
exactly like a script — so the whole family carries a small weight.

### PROTOCOL_QUALITY

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `host_diversity` | 8 | distinct Host values from one source |
| `unknown_method_count` | 10 | requests using an unrecognised method |

Many Host values from one source is virtual host discovery.

### PERSISTENCE

| Feature | Ceiling | Meaning |
| --- | --- | --- |
| `persistence_900s` | 900 | seconds from first to last request |
| `active_windows` | 3 | how many windows have activity |

Slow and patient is still a pattern. One unusual request every five seconds for
fifteen minutes is reconnaissance, and a rate detector alone would miss it
entirely.

## How the score is built

`web-math-risk-v1` is a weighted sum of ten terms through a logistic curve. No
model, no training, no opaque number.

| Term | Weight |
| --- | --- |
| `path_enumeration` | 1.6 |
| `http_errors` | 1.5 |
| `auth_failure` | 1.5 |
| `sensitive_probing` | 1.2 |
| `request_rate` | 1.0 |
| `automation_timing` | 1.0 |
| `method_anomaly` | 0.8 |
| `persistence` | 0.7 |
| `session_quality` | 0.6 |
| `host_enumeration` | 0.5 |
| `evidence_diversity` | 0.9 |

The largest single weight is 1.6. With a bias of -4.0, one maximal term alone
reaches about 0.35 — below WATCH. **No single signal can reach a strong action.**
Three families agreeing is where it starts to mean something.

`evidence_diversity` is separate on purpose: independent families agreeing is
itself evidence, and making it a visible term is better than hiding it inside the
weights.

## Measured behaviour

The score for each scenario in the test suite:

| Scenario | Score | Band |
| --- | --- | --- |
| one failed login | 0.03 | OBSERVE |
| browser page load (30 assets) | 0.06 | OBSERVE |
| health checker | 0.08 | OBSERVE |
| admin panel use | 0.15 | OBSERVE |
| API client, 240 req/min | 0.18 | OBSERVE |
| legitimate crawler, 120 paths | 0.18 | OBSERVE |
| broken frontend asset, 120 404/min | 0.29 | OBSERVE |
| low-and-slow probe | 0.64 | WATCH |
| method probing | 0.64 | WATCH |
| credential spraying | 0.66 | WATCH |
| sensitive file probing | 0.76 | RATE_LIMIT |
| path enumeration | 0.83 | RATE_LIMIT |
| enumeration + sensitive probing | 0.94 | TEMP_BLOCK |

Thresholds: WATCH 0.40, RATE_LIMIT 0.70, TEMP_BLOCK 0.88.

The gap between the worst benign case (0.29) and the weakest suspicious one
(0.64) is what the design is for.

## Explanations

Every score comes with sentences containing real numbers:

```text
Decision: RATE_LIMIT

Reasons:
  - 111 different paths in 60 seconds, 100% of responses were not found
  - 100% of responses were client errors (100% not found)
  - 10 requests across 1 sensitive path categories
  - about 120 requests per minute
  - 5 independent kinds of evidence agree
```

Never "AI found hacker".

## Related

* [WEB_PROTECTION.md](WEB_PROTECTION.md) — the wider picture
* [MATH_MODEL.md](MATH_MODEL.md) — the network-side equivalent
* [WEB_ENFORCEMENT.md](WEB_ENFORCEMENT.md) — what a score is allowed to cause
