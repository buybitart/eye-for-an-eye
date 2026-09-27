# Host enforcement

Temporary defensive blocks on the machine Eye for an Eye is protecting.

**Off on a fresh installation.** A package upgrade cannot turn it on. Turning it
on is the single most consequential setting in the configuration file: it is the
one that lets this software deny somebody access to a real service without being
asked.

## What it does

Places a bounded, temporary, inbound source block in **one nftables table this
project owns**, and nothing else.

| | |
| --- | --- |
| table | `inet e4e_<installation>`, with an owner comment |
| sets | two, `blocked_ipv4` and `blocked_ipv6`, both `flags timeout` |
| chain | one, `input`, filter hook, priority 10, **policy accept** |
| rules | two, dropping traffic from an address in the matching set |
| maximum TTL | **43,200 s (12 hours)**, unchanged since P15 |
| ladder | 300 s → 1800 s → 7200 s → 43,200 s, then stops |

Policy accept matters: the chain drops what is in the set and gets out of the
way. It cannot become a default-deny firewall by accident.

## What it will never do

- Flush a ruleset. There is no `flush` in the enforcement code, and a test scans
  every module for one.
- Delete, replace or read a table it does not own. Ownership is an owner comment,
  not a name, so a table called `e4e_x` that this installation did not create is
  refused rather than adopted.
- Touch Docker's tables, firewalld's policy, or an operator's own rules.
- Block loopback, an unspecified/multicast/link-local address, an address of this
  host, a configured management network, an allowlisted source, or a trusted
  proxy.
- Create a permanent block. There is no value of the TTL field that means
  forever, at any layer.
- Reach outward. There is no hack-back, no scanning and no outbound action of any
  kind in this project.

## The privilege boundary

```
AutonomousDecisionAuthority          unprivileged, holds no firewall handle
        |
        v
PolicyGuard                          can only ever weaken an action
        |
        v
EnforcementRequest                   address, family, scope, TTL, decision id,
        |                            reasons -- and no command field
        v
firewall_helper (separate process)   privileged, validates again, refuses again
        |
        v
owned nftables table                 timeout sets only
```

The request vocabulary is the safety property. It says *which address, for how
long, why, under which decision*. It does not say what to run. A privileged
helper that accepted a command from an unprivileged process would be a remote
shell with extra steps.

An unknown field is **refused, not ignored** — a field the helper does not
understand is either newer than it, or an attempt to smuggle one in.

The helper validates protection against its own copy of the configuration,
immediately before writing, even though PolicyGuard already refused protected
sources upstream. The interesting failure is not "the guard was wrong"; it is
"the guard ran five minutes ago and the configuration changed".

## Turning it on

```toml
[decision]
enabled = true

[enforcement]
host_enabled = true
management_networks = ["203.0.113.0/24"]   # where YOU administer this machine
trusted_proxies = ["10.0.0.0/8"]
```

Configuration validation refuses the combination if:

- there is no protected network — *"a host that can be locked out of itself is
  not one this may act on"*;
- `enforcement.enabled` (the lab namespace path) is also set — pick one;
- the decision engine is off;
- the deployment profile is `lab` — that profile uses the namespace path.

Then check:

```
eye-for-an-eye autonomy readiness
```

The `enforcement_available` check reports whether this machine can actually use
the path: Linux, `nft` installed, protected networks configured.

## Operating it

```
python -m eye_for_an_eye.security.firewall_helper --config <file> status
python -m eye_for_an_eye.security.firewall_helper --config <file> verify
python -m eye_for_an_eye.security.firewall_helper --config <file> reconcile
python -m eye_for_an_eye.security.firewall_helper --config <file> cleanup
```

`dry-run` takes a request on stdin, validates it against the live ruleset with
`nft -c`, and writes nothing. A dry run that only printed a string would tell you
what the code intended, not what the kernel would accept.

## Apply, then verify

A block is not a block because `nft` exited zero. After every write the backend
re-reads the set from the kernel and confirms the element is present with a
timeout inside the requested bound. A failed verification is reported as a failed
block, because the alternative is a system that believes it is defending
something it is not.

Verification stops at the ruleset, so the test suite goes one step further and
checks the thing the ruleset is *for*: a real TCP connection from a real source
address, which completes before the block and times out during it. "The element
is in the set" and "the packet does not arrive" are different claims, and only
the second one is a firewall.

## Crash safety

Every element carries a **kernel timeout**. If the sensor dies and never comes
back, the kernel expires the blocks on schedule with nobody's help.

The table name is stable per installation, so a restarted sensor can find its own
work again — `reconcile` adopts the table if the owner comment matches, reports
every live element with the expiry the kernel is already counting down, and
flags any element without a bounded timeout.

The name is stable here and per-process in the lab backend, and the difference is
deliberate: a lab table must never be inherited, and a host table must never be
orphaned.

## What is tested, and where

`tests/test_p15_1_enforcement.py`, 61 tests. The structural half runs anywhere.
The kernel half needs Linux, `nft` and root, and skips loudly otherwise; it was
run on a disposable container that the session could lose. Three of those also
need `iproute2`, and say so when it is missing.

| Property | How it is tested |
| --- | --- |
| **a blocked source cannot reach a service** | a veth pair into a throw-away namespace, a real listener, a real TCP connection: it completes, the block goes on, it times out, the block comes off, it completes again |
| **an expiring block restores traffic by itself** | nothing calls release; the connection starts completing again on the kernel's schedule |
| **a block is about one address** | a different source keeps its access while one is blocked |
| element carries a kernel timeout | read back from the kernel, every family |
| a block expires on its own | a two-second block, watched until it is gone |
| repeat blocks do not duplicate | a set holds an address once |
| unrelated tables survive | a neighbour table is created, checked after apply and after cleanup |
| a foreign table is refused | same name, different owner comment: refused, not deleted |
| two installations coexist | separate tables, neither adopts the other |
| management address refused | through the real helper, real config |
| trusted proxy refused | same |
| loopback refused | same |
| `host_enabled = false` refused | code existing is not permission |
| a request with a `command` field | refused at parse |
| mass-block budget bounds the kernel | 59 attempts, budget 5, exactly 5 elements |
| the operator keeps their access | 39 management addresses refused while others are blocked |
| restart reconciliation | a fresh backend adopts the same table |
| dry run writes nothing | ruleset compared before and after |
| missing `nft`, invalid rule, failed verification, table removed underneath | each reported; ruleset intact after every one |

## What is *not* tested

Coexistence with **firewalld** and with **Docker's** live rules on a host that
actually runs them. The isolation property is tested against a neighbour table
this project created, which is the same mechanism, and it is not the same
evidence. Do not read the table above as a compatibility claim for those two.

Multi-hour operation, and any host that is not this container.

## Site scope

There is none, and pretending otherwise would be the dangerous kind of
convenience. A host packet filter sees addresses. A website behind a CDN or a
reverse proxy is a client of somebody else's infrastructure, and the address in
the request belongs to the proxy carrying everyone else.

So `HOST_NETWORK` is the only enforcement scope that exists, and a decision whose
`enforcement_scope` is anything else — or whose `network_enforceable` is false —
cannot produce a request at all. For those, use the web layer: challenge, rate
limit, or ALLOW and keep watching.

## See also

- [AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md)
- [AUTONOMOUS_SAFETY_INVARIANTS.md](AUTONOMOUS_SAFETY_INVARIANTS.md)
- [ENFORCEMENT.md](ENFORCEMENT.md) — the P7 lab namespace path
- [TRUSTED_PROXIES.md](TRUSTED_PROXIES.md)
- [../reports/P15_1_FINAL_REPORT.md](../reports/P15_1_FINAL_REPORT.md)
