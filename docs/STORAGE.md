# SQLite, Retention, and Backup

This page explains how Eye for an Eye stores events on disk, how it deletes old data (retention), and how to back up or export data. SQLite is a small, file-based database. Read this if you run a sensor with storage turned on, or if you manage backups.

## Batching Writes (P5)

`storage.max_batch_events` defaults to 1, which means each event is saved in its own database transaction (a single, safe write). You can opt in to a value of 8, which was measured for write-heavy loads. The hard maximum is 32, and it can never be set higher than `max_events`.

`max_batch_delay_ms` defaults to 10 milliseconds, and can be set between 1 and 50. A batch closes as soon as it reaches either its record limit or its delay limit, whichever comes first. This delay is checked between bounded (limited) processing steps. It does not limit a kernel-level I/O (input/output) operation that has become stuck.

During a graceful shutdown, any pending (not-yet-saved) batch is flushed until a drain deadline. After that deadline, any records still not saved are counted in `events_dropped_total`, a counter of lost events.

Up to 32 pending records (on top of whatever is already in the queue) can be lost if the process crashes. Each transaction still keeps: atomicity (all-or-nothing writes), single-writer ownership, protection against duplicate IDs, validation and redaction (hiding sensitive fields), retention, disk-space reserve, and the pressure fallback described below. The SQLite setting `synchronous=FULL` (the safest write mode) stays turned on. See [Measurements and tradeoffs](PERFORMANCE.md) for more detail.

## Who Can Read and Write

Storage is turned off by default. When you turn it on, one single `EventRuntime` process owns the SQLite connection, plus an OS-level lock ("lease") on `path.lock`.

The HTTP API and the CLI (command-line tool) act only as readers. They open separate, short-lived, read-only connections (`mode=ro`), with `query_only` turned on, `trusted_schema=OFF`, and a deadline. SQL filters can only be chosen from a fixed whitelist, and all values are "parameterized", safely inserted into the query instead of being pasted in as raw text. The API never accepts raw SQL or a file name from a client. See the [Python sqlite3 API](https://docs.python.org/3.12/library/sqlite3.html).

WAL (Write-Ahead Log) is a SQLite mode that lets you read the database while something else is writing to it. WAL allows readers to work while the writer is active, but a reader that stays open too long can block a "checkpoint". The step that moves changes from the WAL file into the main database file. Because of this, the API never keeps a database connection open between pages of results. SQLite's own timeout is limited, and a "progress handler" checks a monotonic deadline. A clock that never runs backward. Every 1000 internal SQLite operations. This only cancels SQLite's own work cooperatively; it cannot force-stop an OS I/O call that is already stuck. It needs a local filesystem with correct file-locking behaviour. See [SQLite WAL](https://www.sqlite.org/wal.html).

## Schema Migration

The database schema is at version 2, identified by `application_id=0x45344559`. A brand-new database goes through steps 0 → 1 → 2. The step from v1 to v2 adds query columns and five combined ("composite") indexes:

- `observed_at`/`seq`
- `event_type`/`observed_at`/`seq`
- `src_ip`/`observed_at`/`seq`
- `classification`/`observed_at`/`seq`
- `dst_port`/`observed_at`/`seq`

The existing unique index on `event_id`, and the "ingest age" indexes, are kept unchanged.

Migration runs inside one transaction, with rollback (undo) support and a 10-second SQLite progress deadline. Old events are read in batches of 256, converted through the `NetworkEvent` migration step, and get their new indexed metadata filled in. Starting the app again on an already-migrated v2 database does not run the migration a second time.

A corrupted legacy record, a database from a different, unrelated application, a database from a future schema version, the wrong page size, or a budget problem, all of these cause a clear error, and the file is never deleted. The startup time budget is large enough for the 10-second migration to finish.

Before upgrading: stop the writer, and make a checked backup copy, using the SQLite backup API or your installed version's own backup tool. There is no automatic downgrade. To roll back: stop the new runtime, restore a matching pre-upgrade backup into a separate directory, point the config at that new path, and start the old version. Never place a database file on top of a live WAL file. Check the schema version, the row counts, and the database's integrity before you put it back into real use.

## Retention and Disk Pressure

```toml
[storage]
enabled = true
path = "events.sqlite3"
max_events = 100000
retention_seconds = 86400.0
max_bytes = 134217728
busy_timeout = 0.2
cleanup_interval = 5.0
cleanup_batch = 500
pressure_warning = 0.7
pressure_critical = 0.9
```

The setting names from the earlier P1 version are kept: `retention_seconds` equals `retention_days * 86400`, and `max_bytes` is the same idea as the old `max_storage_bytes`. No duplicate alias names were added. Retention (how long data is kept) uses the time an event was received ("ingest time"). The API's own time filter, when you query data, uses the time the event actually happened ("observation timestamp").

Cleanup (deleting old data) is incremental. It happens in small steps, not all at once. Each pass deletes up to `cleanup_batch` expired rows, and up to `cleanup_batch` rows over the count budget. Inserting a new record also triggers a small, limited cleanup step to stay under `max_events`. If there is still a backlog after that, the new record is simply skipped, instead of triggering an unlimited deletion.

Idle maintenance is checked about once a second, and runs no more often than `cleanup_interval`. If you set the interval below 1 second, it is still limited to about once a second by this check. "Incremental vacuum" (the step that reclaims empty space on disk) is limited to 16 pages. Cleanup runs in the analysis/writer thread; the intake side only adds new events to a queue. Even so, heavy writing can still raise queue pressure.

`max_bytes` is a cautious, overall limit that covers the main database file, the WAL file, and the SHM (shared-memory) file together. The main file has its own page limit, which reserves space for the WAL and for transactions, so a checkpoint or a budget guard can stop new writes earlier, before the whole `max_bytes` limit is reached. This limit only works for the application's own writer and readers working together; it cannot control any other, external program that writes to the same SQLite file or its related files.

There are three pressure levels: NORMAL, WARNING, and CRITICAL. The level is calculated from observed disk bytes divided by `max_bytes`, checked before each write. At CRITICAL, optional data (observations, enrichment, and deception details) is dropped. Metadata and the P2 "hypothesis" data are still kept, marked with `storage_pressure_minimal_metadata`. Every change in pressure level is logged, and a metric ("gauge") shows 0, 1, or 2 for the three levels.

If SQLite fails, or the disk limit is reached, the system becomes "degraded": a write-failure counter goes up, and a small, temporary fallback keeps only the last 256 records in memory. This fallback is lost if the process restarts, and it is not available through the normal API history. There is no automatic replay or reopening after a failed startup. The operator must fix the underlying problem and restart the sensor.

## Backup and Export

```sh
python -m eye_for_an_eye storage info --config sensor.toml
python -m eye_for_an_eye storage backup new-backup.sqlite3 --config sensor.toml
python -m eye_for_an_eye events export new-export.jsonl --config sensor.toml --limit 100
python -m eye_for_an_eye events export new-export.csv --config sensor.toml --format csv --limit 100 --max-bytes 1048576
```

Backup uses the standard `sqlite3.Connection.backup` function, working in batches of 64 pages, with a 10-second deadline and a byte budget of `storage.max_bytes`. The destination is always created as a brand-new file. An existing target file, or the live database/WAL/SHM/lock files, are never overwritten. If the copy fails partway, it is deleted, and the source database is left unchanged. A backup made this way is a consistent SQLite snapshot: a plain file copy of the main database file, taken while it is being written to, is not the same thing, and is not safe. See the [SQLite Online Backup API](https://www.sqlite.org/backup.html).

A local export produces one bounded (limited) page of query results, using the same time range and page limit as a normal query (a default of 1 MiB, and a ceiling of 4 MiB) written to a new file. The JSONL (JSON Lines) format contains a sanitized `EventResponse` record per line. The CSV (comma-separated values) format uses fixed, simple columns, and neutralizes spreadsheet-formula prefixes (a security measure against a trick where a cell starting with `=` runs as a formula). The `api.redact_ip` setting, which hides parts of IP addresses, applies here too. The `next_cursor` value in the result lets the operator explicitly ask for the next page. There is no PCAP (packet capture) export.

SQLite and the backup files are not encrypted by the application itself. Keep these files, backups, and volumes in a protected operator directory. New backup and export files use POSIX (Linux/Unix) file mode `0600`, readable and writable only by their owner. This does not replace a Windows ACL (access control list). Setting the runtime's umask and volume ownership correctly is the operator's responsibility.

## See Also

- [Performance measurements](PERFORMANCE.md)
- [Backup and restore](BACKUP_RESTORE.md)
- [Configuration](CONFIGURATION.md)
