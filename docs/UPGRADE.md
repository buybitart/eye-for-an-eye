# Upgrade and Compatibility

This page explains how to safely upgrade Eye for an Eye to a new version, and how to roll back if something goes wrong. Read this before you install a new version over an existing one.

## Version numbers

| App | Config | Event | DB | Catalogue | Python |
| --- | --- | --- | --- | --- | --- |
| 0.6.0 (P5) | unversioned | 3 | 2 | 2 | 3.12 |
| 0.7.0rc1 (P6) | 1 | 3 | 2 | 2 | 3.12 |

"App" is the version of the whole program. "Config", "Event", "DB" (database), and "Catalogue" are separate version numbers for each of those parts. They do not need to match the app version, or each other.

The app version `0.7.0rc1` follows PEP440, a numbering standard used by Python packages. It is the same as `0.7.0-rc.1` in SemVer, another common version-numbering standard. This numeric app version is not the same as any of the schema (data format) version numbers shown above.

P6 does not change the database, event, or catalogue formats used by P5 — they stay exactly the same. The old "schema 1" format, used before P4, is upgraded to schema 2 inside one safe transaction. A database from a future schema version, or from a different, unrelated application, is rejected.

## Upgrade steps

1. Save your old wheel or image digest (a fixed identifier for the exact version), your configuration, your secret, and the versions of any external data files.
2. Install the new wheel into a separate venv (Python virtual environment). The currently running process keeps using the old one, so nothing breaks yet.
3. Run a local-only upgrade check, using your existing config. This step does not download anything.
4. Convert your old, unversioned TOML config file into a new, versioned file, and check that the profile and file paths are still correct.
5. Stop the database writer, and make a checked backup.
6. Look at the storage migration plan. If it looks correct, apply it, with its own separate backup.
7. Run `validate`, `doctor`, and `run --check-config` under the real service user (UID). Then switch to the new venv and config path, and start the service.
8. Check that a local event is recorded, that health checks pass, that storage works, and that a graceful stop and restart both work.

```sh
eye-for-an-eye upgrade check --config old.toml --json
eye-for-an-eye config migrate --config old.toml --output new.toml --profile honeypot
eye-for-an-eye config validate --config new.toml
eye-for-an-eye storage backup before-upgrade.db --config new.toml --json
eye-for-an-eye storage migrate --config new.toml --json
eye-for-an-eye storage migrate --config new.toml --apply --backup before-schema-migration.db --json
```

## Config migration details

Migrating the config keeps your original file untouched. It writes out full, allowed absolute paths. It does not copy any secret values, and it does not apply environment-variable (ENV) overrides during the migration itself. The next time you actually run the app, ENV overrides work again as normal — you can check this with `config show --source`.

The `run` command, and `config validate`, both refuse unversioned config files. Older wrapper scripts, and read-only diagnostic tools, still accept them for now, to help you through the transition.

## Database migration details

The database migration plan shows the current schema version, the target version, whether you need to stop the service and make a backup first, and the bounded (limited) operations it will run. Applying the plan holds the OS-level writer lock for the entire time the backup and migration are running.

The migration itself does not apply retention rules, meaning the settings that delete old data — old rows are kept exactly as they are. The next normal run of the service applies your configured retention as usual. If an SQL or schema-reading error happens, the whole transaction is rolled back (undone), and the pre-migration backup, if it was already created successfully, is kept safe.

## Rolling back

To roll back: stop the new process, and bring back the old venv, config, and secret.

If the old version's reader cannot understand the new schema, restore the matching backup into a **new** path, and point the old config at that new path.

Some important rules:

- Never rename database files while a writer is using them.
- Never copy only the main database file while its WAL (write-ahead log) file is active — copy the database properly, not just the one file.
- Downgrading the schema itself is not supported.
- Going from P6 back to P5 works for the database and catalogue, since they stay compatible. But P5 does not support the newer P6 deployment and config schema, so keep your old config file for this case.
- There is no hot reload, and no `SIGHUP` support. `SIGINT` and `SIGTERM`, the standard stop signals, both trigger a bounded (time-limited) graceful shutdown.

## See also

- [Installation guide](INSTALL.md)
- [Storage](STORAGE.md)
- [Configuration](CONFIGURATION.md)
