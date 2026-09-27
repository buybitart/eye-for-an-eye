# Backup, Restore and Data Removal

This page shows how to copy the event database, how to put a copy back, and how
to delete old data. Read it before you change a config, upgrade, or hand the
machine to someone else.

The data lives in SQLite. SQLite is a small database kept in one file. WAL is
its write-ahead log: a second file that holds new writes before they move into
the main file.

## Make a Backup

The tool uses the SQLite online backup API. It makes a copy that is consistent,
and it includes the WAL. The backup command only reads the source, so a live
writer can keep running at the same time.

The destination must be a **new separate file**. It must not be the database,
the WAL, the SHM file or a lock file. The command never overwrites a file.

When it finishes it reports the byte count, `database_schema_version` and a
SHA256 checksum. The CLI envelope is `schema_version` 1. The operation has a
time budget and a byte budget. If it fails, it deletes its own partial output.

```sh
eye-for-an-eye storage info --config sensor.toml --json
eye-for-an-eye storage backup before-change.db --config sensor.toml --json
sha256sum before-change.db
```

Backup works for schema DB1 and DB2. API queries need DB2.

Keep the checksum and the backup in separate places, and limit who can read
them. The database backup does **not** contain these, so copy them too:

* the TOML config file,
* the persistent secret,
* the application artifact and its digest,
* the versions of any external data files you use.

## Restore

1. Stop the service.
2. Pick a **new** `storage.path` in a separate config file. Its parent folder
   must already exist and must be private.
3. Run restore with `--yes`.

Restore never replaces an existing database and never replaces a live database.
A writer lease on the new destination stops two writers from racing each other.
The source file is only read. A DB1 file stays DB1, and you migrate it later as
a separate step if you need to.

```sh
eye-for-an-eye storage restore before-change.db --config restored.toml --yes --json
eye-for-an-eye storage migrate --config restored.toml --json
```

To check the copy offline, compare the row count and the event IDs, and run
`PRAGMA integrity_check` on the restored copy. The test suite does a round trip
and a checksum check. Point the service at the restored config only after these
checks pass. Keep the old database until you accept the result.

## Delete Old Data

Retention limits in the starter config:

| Setting | Starter (sensor) | Lab starter |
| --- | --- | --- |
| retention_seconds | 86400 (1 day) | 3600 (1 hour) |
| max_events | 100000 | 10000 |
| max_bytes | 134217728 (128 MiB) | 16777216 (16 MiB) |

At runtime the service does bounded retention work. If it runs past its budget,
writes can be refused, and it can fall back to storing metadata only.

```sh
eye-for-an-eye storage prune --config sensor.toml --json
eye-for-an-eye storage prune --config sensor.toml --apply --json
```

The first command is a **plan**. It changes nothing. `--apply` needs the writer
to be stopped. It then does one bounded maintenance pass against the configured
retention and row budget. There is no arbitrary SQL and no delete-all. If the
backlog is large, you must run several passes on purpose.

## What Prune Does Not Do

Prune does not promise that the bytes are physically gone. Data can stay in the
SQLite freelist, in filesystem snapshots and in your backups.

For full removal: stop the writer, work out which files belong to this
deployment (database, WAL, SHM, status, log, backups) and delete them with your
operating system tools, following your own policy. The tool never deletes other
directories on its own.

## See Also

* [Storage](STORAGE.md)
* [Docker/Compose lab](DOCKER.md)
* [Upgrade](UPGRADE.md)
