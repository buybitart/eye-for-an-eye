# P1 privilege separation

"Privilege separation" means splitting a system into small parts, and giving
each part only the access it truly needs. This page explains how Eye for an
Eye does that on Linux. Read this page if you deploy the sensor, or if you
review its security design.

The system uses separate executable roles. The application never grants
itself higher privileges on its own — an operator sets these up ahead of
time.

## The three roles

| Role | User / capabilities | What it runs |
| --- | --- | --- |
| Capture helper | A non-root Linux user, with exactly one effective capability: `CAP_NET_RAW` | One capture socket, not in promiscuous mode (it does not read other machines' traffic); local metadata only; a bounded IPC (inter-process communication) sender |
| Analysis / listener | A non-root Linux user, with zero effective capabilities | The parser, fingerprinting, bounded queues, optional lookup processes, SQLite, and the finite (limited, non-endless) deception logic |
| Firewall operator | A separate, explicit CLI process, run by a person, with rights to enter a disposable network namespace | Only a fixed command line: `ip netns exec e4e-lab-* … nft`. This is never triggered automatically from a `NetworkEvent` |

`CAP_NET_RAW` is a Linux capability — a small, named piece of root-like power
— that lets a process build and read raw network packets, without giving it
full root access.

The capture helper refuses to start if its configuration also asks for
storage, enrichment, or active probes. It never runs those components
itself. On Linux, the analysis process refuses to start its writer or
listener if it is running as root or with any capabilities.

The setting `runtime.enforce_unprivileged = false` is kept only as an
explicit lab setting. Production templates require it to be `true`. An old
raw-ICMP experiment is rejected with a clear error message if this setting
is set to `true`. Local tests on Windows confirm the algorithms and the
lifecycle logic, but they do not confirm real Linux capability enforcement
— for that, Linux is required.

## How the two processes talk (IPC)

The capture helper and the analysis process talk over a Unix stream socket.
Each message starts with a 4-byte length value in network byte order,
followed by ASCII JSON text with `schema_version = 1`.

The default maximum message ("frame") size is 8192 bytes, with a hard
ceiling of 16384 bytes. A packet snapshot inside a message is at most 2048
bytes, and shrinks further if the frame budget is smaller. The read deadline
is 0.5 seconds, and the send timeout is 0.2 seconds. A corrupted or
oversized frame causes the connection to that peer to be closed.

This channel never uses Python's `pickle` format. Pickle is a Python data
format that can run arbitrary code when loading untrusted data, so it is
avoided here on purpose. Each side checks the other side's UID (user ID)
using the Linux `SO_PEERCRED` socket option. The standard Python
`multiprocessing` "spawn" method is used inside the trusted analysis
process only for its own known functions — never to accept external pickle
data.

The IPC directory must belong to the analysis process's UID, and must not
be writable by its group or by other users. Its permission mode is `0750`,
and a shared IPC group lets the helper reach the socket. The socket file
itself has mode `0660`. The code never replaces someone else's files or
symbolic links, and never removes an existing, active listener. A stale
(leftover) socket file is only removed after a failed connection attempt
and an ownership check. Note: trusting a specific allowed UID does not
protect you if that UID's account is itself compromised.

## Accounts and systemd units

Systemd unit files live in `deploy/systemd/`. The example accounts are:
`eye-for-an-eye` with UID 10001, `eye-for-an-eye-capture` with UID 10002,
and the group `eye-for-an-eye-ipc` with GID 10000.

As the operator, you must check that these IDs do not collide with existing
accounts, and that the UIDs match what is written in your TOML
configuration file. The listener unit uses systemd's `LoadCredential`
feature to pass the deception secret through the path
`%d/deception.secret`. The capture helper never needs access to this
secret.

## Systemd sandboxing settings

These general restrictions apply: `NoNewPrivileges`, `PrivateTmp`,
`ProtectSystem=strict`, `ProtectHome`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID`,
`LockPersonality`, and `MemoryDenyWriteExecute`. Each of these is a systemd
option that removes one class of ability a process would otherwise have.

The analysis process has an empty `CapabilityBoundingSet` and empty
`AmbientCapabilities` — meaning it can never gain any Linux capability. The
capture helper gets only `CAP_NET_RAW`. Nobody gets `CAP_NET_ADMIN` (the
capability needed to change firewall or routing rules).

Resource limits are: `LimitNOFILE=1024` (max open files), `TasksMax=32` (max
number of tasks/threads), `MemoryMax=256M` for analysis and `128M` for the
helper, and `KillMode=control-group` (stopping the whole group of related
processes together).

## Why each network exception exists

Every allowed exception has a specific reason:

* `AF_PACKET` (raw packet access) is allowed only for the capture helper.
* `AF_INET` / `AF_INET6` (normal IPv4/IPv6 sockets) are needed for metadata
  and socket operations.
* `AF_NETLINK` (a Linux kernel messaging socket type) is allowed so the
  Scapy library can read interface metadata. It does not grant
  `CAP_NET_ADMIN`.
* `AF_UNIX` (local sockets) is needed for IPC.

The analysis process can only write inside its own `StateDirectory` and
`RuntimeDirectory` — systemd-managed folders set aside for it. The capture
process gets no writable state directory at all.

`PrivateNetwork` is not turned on, because it would cut the assigned
capture interface, and the listener, off from the network they need to
watch. The container-based lab environment uses its own separate internal
network instead.

## What is still unverified

The unit files have been checked to match the privilege profiles generated
by the code. However, **the actual systemd runtime behavior, and the real
`CAP_NET_RAW` enforcement, are NOT VERIFIED IN CURRENT ENVIRONMENT.**

Before any real deployment, you should run `systemd-analyze verify`, run
privilege tests in a disposable Linux lab, and check the process's actual
effective capabilities (`CapEff`). See the [upstream systemd execution
directives](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
and the [Linux Unix socket credentials
page](https://man7.org/linux/man-pages/man7/unix.7.html) for background.

## See also

* [Security deployment](SECURITY_DEPLOYMENT.md)
* [Firewall](FIREWALL.md)
* [Threat model](THREAT_MODEL.md)
* [Systemd](SYSTEMD.md)
