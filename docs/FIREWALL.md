# Firewall manager

This page describes the P1 firewall manager. It writes nftables rules that send some traffic to a decoy listener, for research and testing. It is for developers and lab operators who plan to use it.

**This works only in an isolated test lab. It does not manage your real firewall.** Read this whole page before you run any of these commands.

**nftables** is the Linux firewall framework this manager uses. A **network namespace** is a private, separate network stack inside one Linux machine — like a small, isolated copy of the network, cut off from the real one.

## The safety line

These rules keep the manager from ever touching a real, production firewall:

* Nobody calls the manager automatically. It is never called from the listener or from the event pipeline. A person has to run it by hand, every time.
* There is no "apply to this host" mode. It only ever works inside a named, prepared lab namespace.
* Every real `nft` command runs through a fixed, fully-written-out list of arguments: `ip netns exec <e4e-lab-name> …`. No shell is used to build the command, so text coming from the network can never sneak into it.
* The configuration file must turn the firewall on, name the lab's network namespace, and list the exact IPv4 destination addresses and decoy ports to use. Those addresses must not be addresses that are reachable from the public internet.
* Before running, the manager checks the namespace's ID (its "inode," a Linux bookkeeping number) against the very first namespace on the machine, found at `/proc/1/ns/net`. That first namespace is the real host namespace, and the manager refuses to run inside it.

## Commands

```text
python -m eye_for_an_eye firewall dry-run --config deploy/firewall.lab.toml
```

`dry-run` only prints text to the screen. It changes nothing. It works even on Windows, and it never reads anything from a real firewall.

The other commands, `apply`, `verify`, and `rollback`, use this same command pattern. They are allowed **only** inside a prepared, isolated Linux lab.

The example configuration file (`deploy/firewall.lab.toml`) describes one lab network layout. Having this file does **not** give you permission to apply that same layout to a real host.

## What the manager owns

The manager owns exactly one nftables table, named `ip eye_for_an_eye`. This table carries a comment showing who owns it, and a digest (a short fingerprint) of the configuration that created it.

* If a table with that same name already belongs to something else, `apply` and `rollback` both refuse to run.
* The manager never flushes (empties) the whole ruleset.
* It never changes chains or tables that belong to other software.
* It does not save or restore the whole host's firewall ruleset — only its own one table.

Running `apply` again replaces only the manager's own table, in one single atomic step (an operation that either fully happens or does not happen at all), and refreshes the lease (see below). The policy's meaning stays the same, but its internal rule IDs and lease time may change.

## Before a redirect starts

Before adding a redirect rule, the manager first makes a TCP readiness check: it tries to connect to the configured decoy listener inside the lab namespace, to make sure it is actually there and ready.

* Management ports, real service ports, and the listener's own port are all protected — they can never overlap with the decoy port set.
* The manager's own rule chain also has a `return` rule for those protected ports, so traffic to them is left alone.
* The redirect only ever covers the destination addresses and TCP decoy ports listed in the configuration — nothing else.
* The decoy listener must accept the redirected traffic on the addresses of the network interface it listens on. In the lab test setup, it binds to `0.0.0.0` (meaning "all addresses"), but only inside the isolated namespace.

A successful TCP connection during this check does not prove which real process answered on the other end. That is a known limit of this readiness check.

## The lease

The redirect rule set has a kernel timeout, called its **lease**. The default lease is 30 seconds. The allowed range is 5 to 300 seconds.

* Every `apply` hands out a lease with a fixed end time. Nothing renews it automatically in the background.
* If the manager process or the listener process dies, no new redirects can start once the lease runs out.
* While a lease is still alive, existing NAT and connection-tracking entries in the kernel may keep working on their own, even without the manager running.
* Real service ports and management ports are never included in the decoy port set.

## verify and rollback

`verify` is read-only: it never changes anything. It checks the table's structure, its rule chain, its match conditions, its verdict (accept/redirect/etc.), its ports, its expiry time, and whether the listener is ready.

`verify` reports a status of `degraded` when the lease has already expired, when a different, unexpected redirect is found in place, or when the listener fails its check.

If a check fails right after an `apply`, the manager rolls back to **having no redirect table of its own at all**. It does not attempt to restore an older version of its own policy — that feature does not exist.

## IPv6

IPv6 redirection is deliberately **unsupported**. Any IPv6 firewall address is rejected during configuration validation, and a table created in the `ip` (IPv4) family never touches IPv6 traffic at all.

Offline IPv6 observation (just watching, not redirecting) is covered by separate tests elsewhere in the project. That does not mean IPv6 firewall policy is supported here — it is not.

## Tests

The test file `tests/test_p1_firewall.py` covers: the rule-building logic, that running `apply` twice in a row gives the same result (idempotence), rollback behaviour against a fake backend, refusal when the readiness check fails or when a table name collides with another one, protection of reserved ports, resistance to tampering, and behaviour after a lease has expired. These tests use a fake backend — they do not replace evidence gathered from a real Linux system.

The test file `tests/linux_lab/test_namespace_firewall.py` builds three real network namespaces: a client, a sensor/router, and a service. They are joined only by veth links (a type of virtual network cable between namespaces), with no default route and no interface facing the real host network. This test checks a real SSH-like connection, the redirect itself, running `apply` more than once, crash and lease-expiry behaviour, rollback, and that an unrelated ("foreign") table stays untouched. A second test checks a minimal packet-capture capability. Cleanup only removes the specific, randomly-named (UUID) namespaces and processes that the test itself created.

## What is not verified here

On the current Windows development machine, real `nft` commands, real namespaces, real redirects, real lease expiry, and real rollback are all **NOT VERIFIED IN CURRENT ENVIRONMENT**.

The full runbook (step-by-step operating instructions) and the opt-in safety gate for this feature are in [DEPLOYMENT.md](DEPLOYMENT.md).

The command syntax and the timeout design follow the [official nftables reference](https://netfilter.org/projects/nftables/manpage.html). The exact JSON output format of a specific `nft` version still needs to be checked against a real contract run on Linux.

## See also

* [DEPLOYMENT.md](DEPLOYMENT.md) — the runbook and opt-in gate for using this feature.
* [PRIVILEGES.md](PRIVILEGES.md) — what system permissions this and other components need.
* [LAB_TEST_PLAN.md](LAB_TEST_PLAN.md) — the historic test plan that first covered lab-only checks like these.
* [DECEPTION.md](DECEPTION.md) — the decoy listener this manager redirects traffic toward.
* [ENFORCEMENT.md](ENFORCEMENT.md) — the separate, decision-driven blocking system (also lab-only).
* [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md) — known limits of this project as a whole.
