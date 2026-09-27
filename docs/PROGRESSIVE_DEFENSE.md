# Progressive defense

Why there is a ladder of actions instead of a line between allowed and blocked.

## The problem with two answers

A system with only "allow" and "block" has to decide, for every client, which
mistake it prefers. Block too eagerly and real people cannot use the site.
Block too reluctantly and the tool does nothing.

Neither setting is right, because the underlying evidence is not binary. Most
suspicious-looking traffic is somewhere in the middle: a client doing something
odd, on evidence that would not convince a person either.

So the system has more than two answers.

```
OBSERVE
    ↓
WATCH
    ↓
SOFT_CHALLENGE
    ↓
RATE_LIMIT
    ↓
TEMP_BLOCK
```

Each rung costs the client a little more and requires a little more evidence.

## What each rung means

**OBSERVE** — nothing is happening. The vast majority of traffic.

**WATCH** — something is worth counting, but not worth doing anything about.
Nothing is sent. The client cannot tell.

**SOFT_CHALLENGE** — the evidence is real and does not settle the question, so
ask one. This is the first action a client can notice, and it is the cheapest
one that produces new information. It costs an ordinary browser one extra
request and no attention at all.

**RATE_LIMIT** — slow the client down. Reversible, and it does not take the
client off the site.

**TEMP_BLOCK** — refuse, for a bounded time. Only on strong evidence, and never
for a client whose address is not the machine that connected to us.

## The rule that matters most

**Weakening is always allowed. Strengthening needs evidence.**

Every policy rule in the web sensor can only move an action *down* the ladder.
That is a deliberate structural choice: a bug in that code costs detection, and
never availability. There is no path through the policy that makes an action
stronger than the risk score justified.

Three things reduce an action:

- too few requests to judge (fewer than 20),
- data quality below the configured floor,
- an address that is not the machine that connected — this one caps at
  RATE_LIMIT, because blocking a proxy hits everyone behind it,
- an unreliable client address.

## Challenge evidence can move an action, within a limit

Challenge history is the one thing that can push a client *up* the ladder, and
it is capped.

- Passing a challenge, on its own, changes nothing. A capable script can pass.
- Passing and then behaving normally for a while lowers the action by one rung.
- Passing and then continuing to probe raises it by one. This is the useful
  signal: it rules out the innocent explanation.
- Repeated recent failures raise it by one. Failures decay with time.

Challenge evidence stops at **RATE_LIMIT**. It can never reach TEMP_BLOCK on its
own, because the innocent explanations for failing a challenge are ordinary —
scripting switched off, a privacy browser, a cookie blocker, a bad connection —
and "did not complete a challenge" must not become "is malicious" by a side
door. A client already above that rung got there on behavioural evidence, and
challenge history neither raises nor lowers it.

## Deploy it in stages

Do not switch everything on at once.

1. **Decision shadow.** The sensor runs, decisions are recorded, nothing is
   enforced. This is the P10 default.
2. **Challenge shadow.** Challenge decisions are made and recorded; no challenge
   is sent. Read the challenge rate for ordinary traffic.
3. **Active challenge, no automatic blocking.** Challenges are really sent.
   Nothing is blocked.
4. **Challenge and rate limiting.**
5. **Bounded temporary blocking**, if the numbers from the earlier stages
   justify it.

Each stage should run long enough to produce numbers you trust. The measurement
that decides whether to move on is not the scanner detection rate — it is how
often ordinary traffic is affected.

## What none of this proves

A rung on this ladder is a decision about one client's behaviour in one time
window. It is not a claim about who the client is, whether a person is involved,
or whether anything malicious happened. Those are not questions this system can
answer, and it does not try.
