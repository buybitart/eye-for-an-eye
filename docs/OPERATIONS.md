# Operations

This page lists the commands you use every day to start the service, check it,
and read what it saw. It is for the person who runs the service on a machine.

Read [Install](INSTALL.md) first, then [Quickstart](QUICKSTART.md).

## Before you start

* Use CPython 3.12. Use a locked install. See [Install](INSTALL.md).
* Settings for the API, the metrics port and storage live in
  [config.example.toml](../config.example.toml).
* Create the directories and the file permissions first. Then write the config.

The installer does this part for you:

```sh
sh scripts/install.sh
```

`eye-for-an-eye setup` creates the config, the directories and an empty
database. It creates a secret only when the chosen profile needs one. It starts
in Shadow Mode. Shadow Mode means the service watches and scores, but it never
blocks. The installer never changes the firewall. It never enables or starts a
service.

## Start the service

Check the config, then check the machine, then run:

```text
eye-for-an-eye config validate --config sensor.toml
eye-for-an-eye doctor --config sensor.toml
eye-for-an-eye proto --config sensor.toml --status-file status.json
```

The command `python -m eye_for_an_eye <command>` does the same thing.

The service stays in the foreground. It runs until you press Ctrl+C or send
SIGTERM. SIGTERM is the normal "please stop" signal on Linux.

## Look at the service from a second terminal

```text
eye-for-an-eye version --config sensor.toml
eye-for-an-eye status --config sensor.toml
eye-for-an-eye stats --config sensor.toml
eye-for-an-eye events tail --config sensor.toml --limit 20 --transport tcp
eye-for-an-eye storage info --config sensor.toml
eye-for-an-eye model status --config sensor.toml
curl --fail http://127.0.0.1:8777/health
curl --fail http://127.0.0.1:8777/ready
```

For `status` to work, the config you pass must name the same
`runtime.status_file` as the running service. The `--status-file` option above
is only shown for the start command. It is better to set `status_file` once in
the TOML file.

If the status file is missing, too old or too big, `status` returns
`dependency_unavailable` and exits with code 1. It never shows an old snapshot
as if it were live.

## What doctor checks

`doctor` reads and reports. It changes nothing.

| It checks | Notes |
| --- | --- |
| Configuration | Types, values and version |
| Storage directory | Advisory write access only |
| Free disk space | Compared with `storage.max_bytes` |
| Database schema | If the file already exists |
| p0f and MMDB files | Present or not, with file age |
| Analysis capabilities | The unprivileged check, see below |
| Configured ports | It binds and closes them |

The port test only binds and closes. It does not listen, connect or send. A busy
port may belong to a sensor that is already running. Compare with the running
service. Never kill an unknown owner of a port.

`doctor` does not change permissions, the firewall or systemd. It does not use
the Internet. Run it as the same user, with the same config, as the service.
An access check is not a promise that a later write will work.

The Linux analysis check needs an unprivileged user with no effective
capabilities. Capabilities are small pieces of root power that Linux can grant
one by one. `CAP_NET_RAW` (the right to read raw packets) belongs to the
separate capture helper. That helper checks itself at start. `doctor` never
grants a capability. On Windows the Linux capability check is marked as not
checked. A missing optional database makes the report weaker, but it is not a
reason to stop capture.

## Reading events

`events tail` returns one finite, redacted page, newest first, then stops. There
is no endless follow mode. You can use the API filters, a time range and a
cursor. Ctrl+C returns exit code 130.

`stats` returns bounded activity counters, storage info, and `queue_drops` from
a fresh status file. If the status file is not fresh, the value is null and the
limitation is reported.

## Versions

`version` reports the application version 0.8.0rc2, event schema 3, catalogue 2
and database schema 2.

For the operator's own p0f and MMDB files, the data version is unknown by
default. The command shows whether the file is present, its mtime and its size.
It does not show the absolute path. An mtime is the last time the file was
changed on disk. It is not proof of where the file came from, and it is not the
release date of the database.

## Error types

CLI errors use a fixed set of names:

| `error_type` | Meaning |
| --- | --- |
| `configuration_error` | The config is wrong |
| `dependency_unavailable` | Something the command needs is not there |
| `storage_failure` | The database could not be used |
| `permission_failure` | The process does not have the rights it needs |

`doctor` can also report `network_bind_failure_or_port_in_use`.

Runtime errors in parsing, enrichment, storage and start-up have typed telemetry
and counters. An error never dumps a raw request, a config or a secret. The
`error_type` field holds the name of the exception class, not its text, because
the text could be sensitive.

## Running as a service

The systemd analysis and listener templates send stdout and stderr to the
journal. systemd is the Linux service manager; the journal is its log store.
SQLite is kept in a separate `StateDirectory` with `UMask=0077`, so only the
service user can read new files. `RuntimeDirectory` holds the status file, which
is written atomically.

| Role | API port | Metrics port |
| --- | ---: | ---: |
| Listener | 8777 | 8778 |
| Analysis | 8779 | 8780 |

All four are disabled by default. Turn on only the pair you need, in the config
for that role, and keep the ports separate. The journald quota is set by the
operator.

See [systemd](SYSTEMD.md).

## Running in a container

The container writes JSONL logs to stdout. SQLite goes to the
`/var/lib/eye-for-an-eye` volume. The status file goes to `/run/eye-for-an-eye`.

Setting up the API locally does not publish a port by itself. For a collector in
the same namespace, use loopback. For a collector in another namespace, set up a
protected proxy. A build and runtime example is in [Deployment](DEPLOYMENT.md).

Linux, systemd and container execution: **NOT VERIFIED IN CURRENT ENVIRONMENT**.

## Shutdown

Shutdown happens in this order:

1. Stop the operational endpoints.
2. Refuse new intake.
3. Drain the queue until the deadline.
4. Close SQLite and the logger.

If the deadline passes, the records still in the queue are counted as drops. A
permanently stuck output does not hold the process open for ever. A successful
shutdown does not mean that events rejected by the queue or by storage were
saved.

## See also

* [Storage, backup and retention](STORAGE.md)
* [Troubleshooting](TROUBLESHOOTING.md)
* [Operator checklist](OPERATOR_CHECKLIST.md)
* [Configuration](CONFIGURATION.md)
