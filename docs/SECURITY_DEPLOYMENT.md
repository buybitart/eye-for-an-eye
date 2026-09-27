# Security Deployment Boundary

This page explains what Eye for an Eye protects against, and what it does
not protect against, when you put it on a real network. Read this page
before you deploy the sensor anywhere outside a private lab.

A public-facing server is not automatically safe just because its process
is bounded (limited in size and scope). Before any production use, you
still need platform-level security controls, a threat review, and limits
specific to your own site.

**Do not publish this release candidate (RC) until the licence and a
security contact are in place. These are release blockers**: this project
currently has no licence file and no private channel for reporting security
issues.

## Network Endpoints

| Endpoint | Starter honeypot setting | Purpose |
| --- | --- | --- |
| TCP 1234 | `127.0.0.1` | One finite (limited) deception listener; this is not a management port |
| TCP 8777 | `127.0.0.1` | The read-only API; it can return sensitive metadata |
| TCP 8778 | `127.0.0.1` | Metrics, with a fixed, small set of metric names |
| Unix socket `capture.sock` | `/run/eye-for-an-eye` | Its connecting user (peer UID) is checked; this is not a TCP port |
| SSH 22 / HTTPS 443 and your other real ports | Protected by your own firewall policy's defaults | The application never occupies or redirects these on its own |

`127.0.0.1` means "loopback": only the local machine can connect. By
default, the configuration keeps the API and metrics endpoints off.
Running `config init` turns them on, but only on loopback.

A non-loopback bind (letting other machines connect) is rejected unless
you explicitly set `allow_insecure_non_loopback`. Turning that override on
does **not** add TLS (encryption) or authentication by itself. You still
need a protected proxy or access control in front of it, and an
`api.token_file` if you need one. Never put the API and the deception
listener behind the same public wildcard address without checking each one
separately.

## Reducing Abuse and Probing

UDP responses are turned off, to rule out amplification attacks (attacks
where a small request tricks a server into sending a much bigger response
to a victim). Active raw probes are OFF, and the sensor profile forbids
turning them on. An old NAT "escape hatch" (a special bypass) still exists,
but it is lab-only, and it is not needed for normal observation.

RDAP (a protocol for looking up who owns a domain or IP address) is OFF.
Only an explicit, restricted egress (outbound traffic) setting, combined
with RDAP being turned on, would let the system reach an external registry
or DNS server. GeoIP/MMDB (a local database format for rough
IP-to-location lookups) and p0f (a passive tool for guessing an operating
system from its network traffic) both work fully offline, from local data.
There is no update checker. The application's own egress policy is not a
replacement for an independent, host-level network restriction that you
control.

## Least Privilege

The analysis and listener processes run without root and without any Linux
capabilities. Only a separate capture helper process gets `CAP_NET_RAW` (a
capability that lets it read raw network packets). No service ever
receives `CAP_NET_ADMIN` (the capability needed to change firewall or
routing rules).

You, the administrator, set up the systemd units, directories, and
accounts. You must never run the analysis process as root. The firewall
manager is called separately, by hand, and only touches its own isolated
`e4e-lab-*` network namespace, with validation, ownership checks, a lease,
and rollback support. It is **not** a production host firewall manager.
See [Firewall](FIREWALL.md) for details.

## What Is Stored, and What Is Not

Stored: observed IP addresses, ports, timestamps, protocol metadata,
hypotheses, classifications, and redacted (cleaned) deception activity.

Not stored: password values, raw payloads, and credential headers.

Even with those things removed, this is still sensitive telemetry (data
about real network activity) and should be treated carefully.

The starter storage settings keep data for 1 day, up to 100,000 events, in
a conservative 128 MiB envelope covering the database file plus its WAL and
SHM files (SQLite's write-ahead log and shared-memory files). Logging has
its own separate rotation and retention settings; journald and container
runtimes have their own policies on top of that.

Private state directories use permission mode `0700`. The secret file uses
mode `0600`, or is restricted to a dedicated service group. Backups use
mode `0600`: you, the operator, control their access and how long you keep
them. The application does not provide encryption at rest (encryption of
stored files) on its own. See [Backup and restore](BACKUP_RESTORE.md) for
more.

## Living With Pressure and Uncertainty

Under heavy load, the system may drop some data and fall back to
observe-only mode. Being "ready" does not guarantee that storage is
complete. Correlation results, guessed operating systems, and GeoIP
locations are all hypotheses (educated guesses), never treat them as
proof of who was really responsible (attribution).

Only run this system against traffic and networks that you are allowed to
observe.

## See Also

* [Firewall](FIREWALL.md)
* [Backup and restore](BACKUP_RESTORE.md)
* [Privileges](PRIVILEGES.md)
* [Threat model](THREAT_MODEL.md)
* [Privacy](PRIVACY.md)
