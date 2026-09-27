# Enforcement: The Lab Namespace Path (Lab Only)

**Read this first: this page is about one of two blocking paths.** The one
described here, `enforcement.enabled`, works only inside an isolated Linux test
lab and cannot manage your real firewall. The other one,
`enforcement.host_enabled`, can place a bounded temporary block on a real host
and is described in [HOST_ENFORCEMENT.md](HOST_ENFORCEMENT.md). Both are off on
a fresh installation and each is turned on separately.

The production recommendation is Shadow Mode only.

Status: **Experimental / Lab-only**, for the path on this page.

## What "Lab Only" Means Here

Blocking is done with `nftables`, the Linux firewall system. But the backend
refuses to run in your machine's main network namespace.

A network namespace is a separate, private copy of the network stack. The code
reads `/proc/1/ns/net` and compares it with the namespace it was told to use. If
they are the same, it stops with a permission error.

So the code cannot block traffic to your real server, even by mistake. That is
on purpose, and it is the honest state of this feature today.

## What Is Required to Switch It On

All four, together:

```toml
[deployment]
profile = "lab"

[decision]
mode = "enforce"

[enforcement]
enabled = true

[firewall]
lab_namespace = "e4e-lab-..."     # a named, throw-away namespace
```

The redirect firewall (`firewall.enabled`) is a separate P1 feature and does not
need to be on. No new privileged service is installed. Namespace administration
needs a separately authorised lab operator.

## What It Does, Exactly

Each instance creates:

* one nftables table with a random name and an ownership comment,
* two size-limited timeout sets, one for IPv4 and one for IPv6,
* two rules on the input chain.

Then, for each block:

* the address is a parsed literal, never text pasted into a command,
* the duration is an integer from 1 to 43200 seconds,
* the entry is read back after it is written,
* it must have a real kernel expiry before the system records `enforced = true`.

Default limit: 1024 live entries. The kernel set size also limits it.

## Blocks Are Always Temporary

```text
first offence      ->  5 minutes
second             ->  30 minutes
third              ->  2 hours
fourth and later   ->  12 hours
```

These come from `enforcement.block_seconds`. After
`enforcement.offense_decay_seconds` (6 hours by default) with no new offence,
the counter resets.

Risk itself also fades:

```text
R(t) = R0 * 2^(-t / half_life)
```

with a half life of 60 seconds by default. In plain words: **old risk gets
smaller with time. One old event must not keep an address blocked forever.**

## Who Is Never Blocked

Before every final block, the code checks the address against:

* loopback, unspecified, multicast and link-local ranges,
* the local interface addresses, read inside the target namespace,
* `enforcement.management_networks`,
* `enforcement.allowlist`,
* `enforcement.trusted_proxies`.

IPv4-mapped IPv6 addresses are normalised first, so `::ffff:10.0.0.1` and
`10.0.0.1` are the same address.

If the local interface list cannot be read, **no** block is made. The guard also
runs earlier, inside the decision engine. The final check exists because a stale
assumption must never be allowed to grant a block.

## What It Never Does

* No global flush.
* No change to a table it does not own.
* No change to Docker or firewalld rules.
* No unbounded rule creation, one per address.
* No permanent ban.
* It never deletes an existing table to clear a name collision.

At shutdown it deletes only its own verified table. If cleanup fails or the
process dies, kernel entries still expire on their own. An empty owned table may
be left behind for the lab operator to review. No broad cleanup is attempted.

## What Each Action Really Does

| Action | Effect |
| --- | --- |
| `OBSERVE` | Nothing. Recorded. |
| `WATCH` | Nothing. Recorded with more attention. |
| `RATE_LIMIT` | **Observation only today.** Recorded, not applied. |
| `TEMP_BLOCK` | Drops traffic arriving at this namespace's input, for a time. |

`TEMP_BLOCK` does not affect arbitrary routed traffic and does not affect the
host.

Any failure (no firewall, a failed command, a failed verification, capacity
reached, or a refusal) records `enforced = false`. The decision is still
written down.

## The Manual Firewall Commands

There is no `enforcement enable` command. Firewall work is deliberately manual
and separate, so it can never be a side effect of something else:

```sh
eye-for-an-eye firewall dry-run  --config lab.toml   # show what would change
eye-for-an-eye firewall apply    --config lab.toml   # make the change
eye-for-an-eye firewall verify   --config lab.toml   # check it is still right
eye-for-an-eye firewall rollback --config lab.toml   # undo it
```

Always run `dry-run` first and read the output.

## The Lab Test

An opt-in test creates three disconnected namespaces with private links. It
checks that shadow mode leaves nftables unchanged, that IPv4 and IPv6 entries
and expiry work, that local and management protection really holds, and that an
unrelated table is identical before and after cleanup.

```sh
sudo env E4E_RUN_NAMESPACE_LAB=1 /path/venv/bin/python -B \
    -m pytest tests/linux_lab/test_p7_temporary_blocks.py -q
```

Run it only in an authorised, throw-away Linux lab. It ran on Ubuntu under WSL2
with nft 1.1.6. It validates the namespace mechanism. It does **not** validate
production blocking quality, and it is not a production architecture.

This lab also found and fixed a real bug: in libnftables JSON, `timeout` and
`expires` are in seconds, not netlink milliseconds.

## Before You Ever Enable This

1. Run Shadow Mode for days and read every would-be block.
2. Put your own address and your management network in
   `enforcement.management_networks`.
3. Add your monitoring and uptime services to `enforcement.allowlist`.
4. Add your reverse proxy to `enforcement.trusted_proxies`, or every visitor
   will look like one address.
5. Keep a way in that does not depend on this machine's network.

## See Also

* [Shadow Mode](SHADOW_MODE.md)
* [Firewall](FIREWALL.md)
* [Decision engine](DECISION_ENGINE.md)
* [Limitations](LIMITATIONS.md)
