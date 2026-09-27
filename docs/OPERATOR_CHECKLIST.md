# Operator Checklist

This page is a short list of checks. Work through it before you start the
service, after you start it, and when you update it. It is for the person
responsible for the machine that runs Eye for an Eye.

Longer explanations are in [Operations](OPERATIONS.md), [Install](INSTALL.md)
and [Security deployment boundary](SECURITY_DEPLOYMENT.md).

## One Open Release Blocker

* **Licence: settled.** MIT, Copyright (c) 2026 Aliaksandr Zasinets. The full
  text is in `LICENSE`. You may reuse and publish this code under those terms.
  One optional dependency (scapy, for live capture) is GPL-2.0-only and is not
  bundled. See `THIRD_PARTY_NOTICES.md` before you build a container image.
* **Security reporting: not yet available.** The workflow is GitHub Private
  Vulnerability Reporting, and it needs the public repository to exist first.
  See [SECURITY.md](../SECURITY.md).

See [Release](RELEASE.md) for the full list of blockers.

## Before the First Start

* Check the artifact checksums (fingerprints that prove a file has not
  changed). Check the licence and support status. Check the gates for your
  target platform.
* Choose one profile: website, sensor, honeypot, or lab. Each profile watches
  only the network area it is allowed to watch.
* Use a separate user account and a separate Python virtual environment (an
  isolated set of installed packages). Keep the state directory and the
  backup directory private. The runtime user must not be able to write to the
  source code.
* Set `config_version = 1`. Make the capture UID numbers (the user ID that
  reads network packets) match on both sides. Keep the secret key at file
  mode `0600` (readable only by its owner), or pass it in using
  `LoadCredential` (a systemd feature for handing a service a secret safely).
  Keep a backup of the secret.
* Check the real service ports and the management ports. Check the source
  allowlist (the list of addresses allowed to connect). Keep the management
  endpoints on loopback (`127.0.0.1`, meaning "this machine only").
* Turn off active probes, RDAP (a lookup service for who owns a domain or IP
  address), UDP responses, and firewall automation. All of these are off by
  default already, just confirm it. Check that retention (how long data is
  kept) and the resource limits fit this host.
* Run these three commands, with the same config file, the same user account,
  and the same environment the real service will use:

```sh
eye-for-an-eye config validate --config sensor.toml
eye-for-an-eye doctor --config sensor.toml
eye-for-an-eye run --config sensor.toml --check-config
```

`--check-config` checks the inputs and then exits. It never opens a network
socket.

## After the Start

* Check that the status is fresh (recently updated). Check the mode, the
  version, the uptime, the ready flag, and the queue, drop, and storage
  pressure numbers.
* Confirm that one local, allowed event shows up in `events`, in the API, and
  in the SQLite database file (a small, single-file database format).
* Confirm no port is open that you did not expect. Confirm any error from an
  optional data provider is explained in the logs.
* Test a SIGTERM shutdown (a normal "please stop" signal sent to the
  process), a restart, the backup checksum, and a restore into a **new**
  path.

## When You Update

* Keep a backup of the old wheel (a Python package file), the old config
  file, the old secret, and the old database.
* Read the migration plan before you start. See [Storage](STORAGE.md) and
  [Upgrade](UPGRADE.md).
* Stop the writer process first.
* Test that a rollback (going back to the old version) actually works.

## Every Day After That

Starting the service once is not enough. Keep watching, on an ongoing basis:

* disk pressure,
* queue drops,
* journal (log) retention,
* the versions of the optional data providers.

## See Also

* [OPERATIONS.md](OPERATIONS.md): the full operations guide.
* [INSTALL.md](INSTALL.md): how to install the service.
* [SECURITY_DEPLOYMENT.md](SECURITY_DEPLOYMENT.md): the security boundary
  this deployment relies on.
* [RELEASE.md](RELEASE.md): the full release process and its blockers.
* [STORAGE.md](STORAGE.md) and [UPGRADE.md](UPGRADE.md): migration and
  upgrade details.
* [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md): known limits of this
  project as a whole.
