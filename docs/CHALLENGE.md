# Web challenge

Eye for an Eye does not always block a suspicious client.

It can first send a small local web challenge. The challenge gives the system
more information. A failed challenge does not prove an attack. A passed
challenge does not make a client trusted forever.

Status: **Beta.** Shadow mode is the recommended deployment. Off by default.

## The short version

Some clients look suspicious, but not suspicious enough to block. Blocking them
would be wrong often. Ignoring them would be wrong too.

So the system asks a question instead.

The question is small: *can this client complete an ordinary web flow?* An
ordinary browser answers it by itself, in a moment, with no puzzle and no
clicking. Most clients never see it at all.

The answer is evidence. It is not proof of anything.

## What a challenge is

1. The client asks for a page.
2. The system decides the evidence is real but not strong enough to act on.
3. The system sends a small page and a short-lived cookie.
4. The browser stores the cookie and asks for the page again.
5. The cookie is valid, so the request continues normally.

That is the whole flow. There is no puzzle, no image, no CAPTCHA, no
fingerprinting, and no work for the computer to do.

## What a challenge is not

A challenge does **not** prove:

- that the client is a person,
- that the client is safe,
- that the client is not an attacker,
- who the client is.

A capable script can pass this challenge. That is expected, and it is fine,
because passing is not the point. The point is that behaviour after passing is
still watched — and a scanner that passes a challenge and then goes back to
guessing paths has told the system something useful about itself.

## The ladder

```
OBSERVE  →  WATCH  →  SOFT_CHALLENGE  →  RATE_LIMIT  →  TEMP_BLOCK
```

A challenge sits between watching and rate limiting. It is the first action that
costs the client anything, and it is the cheapest one that does.

| Action | Web risk | What happens |
| --- | --- | --- |
| OBSERVE | below 0.40 | nothing |
| WATCH | 0.40 to 0.45 | counted, nothing sent |
| SOFT_CHALLENGE | 0.45 to 0.70 | a challenge, if one can be sent |
| RATE_LIMIT | 0.70 to 0.88 | slowed down |
| TEMP_BLOCK | 0.88 and above | blocked for a bounded time |

These numbers are defaults for this release. They are not calibrated against
real traffic, and you should expect to change them.

## When a challenge is not sent

Most of the time. A challenge is refused when:

- the client already holds a valid token,
- risk is below the floor — a challenge costs the user something,
- risk is above the ceiling — there is already enough evidence to act,
- the method is not safe to redirect (POST, PUT, PATCH, DELETE),
- the route does not use challenges (API, auth, webhook, health),
- the client passed one recently,
- the client has been asked too many times already,
- the per-client or whole-site budget is spent,
- the client address is not reliable enough to attach a challenge to,
- the challenge subsystem is not working.

Every refusal is recorded with its reason. If you are wondering why a client was
not challenged, `eye-for-an-eye challenge doctor` and the decision record will
tell you.

## Shadow mode

The default when you first switch challenges on.

In shadow mode the system decides everything exactly as it would in active mode,
records what it would have done, and sends nothing. Nobody is inconvenienced and
you get the numbers you need to decide whether to go further.

```toml
[challenge]
enabled = true
mode = "shadow"
```

Look at the challenge rate for ordinary traffic before you change `mode` to
`"active"`. If it is not very close to zero, the thresholds are wrong for your
site.

## What it costs

Measured locally, on one core, with the LAB fixtures:

| | |
| --- | --- |
| Normal request, no challenge | about 11 microseconds |
| Request carrying a valid token | about 34 microseconds |
| Building a challenge response | about 20 microseconds |
| Challenge page size | 838 bytes |
| Challenge state, per client | about 940 bytes |

For a challenged client the real cost is one extra request.

## Commands

```
eye-for-an-eye challenge status    is it on, in which mode, how is it doing
eye-for-an-eye challenge doctor    is it set up correctly and safely
eye-for-an-eye challenge stats     outcomes and budget
eye-for-an-eye challenge test      sign a token locally and check it
```

None of these send a request, change Nginx, or change enforcement. None of them
ever prints a secret or a token.

## Further reading

- [Progressive defense](PROGRESSIVE_DEFENSE.md) — why an action ladder
- [Challenge security](CHALLENGE_SECURITY.md) — threats and what is done about them
- [Challenge privacy](CHALLENGE_PRIVACY.md) — what is stored and what is not
- [Nginx integration](NGINX_CHALLENGE.md) — how to wire it up
- [API clients](API_CLIENTS.md) — routes that must not be challenged
- [Trusted proxies](TRUSTED_PROXIES.md) — CDNs, and how not to break your site
