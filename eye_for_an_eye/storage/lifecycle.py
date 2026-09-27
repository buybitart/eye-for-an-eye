"""Offline migration/restore lifecycle, with an owned writer lease and new backups."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from .locking import WriterLease
from .operations import backup
from .reader import Reader
from .sqlite import APPLICATION_ID, SCHEMA_VERSION, SQLiteStore


def migration_plan(config):
    path = Path(config.storage.path).resolve()
    current = None
    if path.is_file():
        if path.stat().st_size > config.storage.max_bytes:
            raise sqlite3.DatabaseError('database exceeds configured storage byte budget')
        connection = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=.1)
        try:
            current = connection.execute('PRAGMA user_version').fetchone()[0]
            app = connection.execute('PRAGMA application_id').fetchone()[0]
            if current == 0 and app == 0 and not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table'").fetchone():
                current = None
            elif app != APPLICATION_ID or current not in (1, SCHEMA_VERSION):
                raise sqlite3.DatabaseError('foreign or future database: not modified')
        finally:
            connection.close()
    return {'current_version': current, 'target_version': SCHEMA_VERSION, 'backup_recommended': current == 1,
        'estimated_operations': 'add 8 metadata columns, decode rows in groups of 256, create 5 indexes; 10s migration deadline' if current == 1 else 'none',
        'requires_stopped_writer': current == 1, 'automatic_download': False}


def migrate_database(config, destination):
    plan = migration_plan(config)
    if plan['current_version'] != 1:
        return {'schema_version': 1, 'status': 'no_migration_required', 'plan': plan}
    if not destination:
        raise ValueError('migration --apply requires --backup <new-file>; stop the service first')
    store = SQLiteStore(config.storage)
    result = {}
    def save(connection):
        class OwnedReader:
            path = Path(config.storage.path).resolve()

            @contextmanager
            def connect(self):
                yield connection
        result.update(backup(OwnedReader(), destination, max_bytes=config.storage.max_bytes))
    try:
        store.open(before_migration=save, maintenance=False)
        return {'schema_version': 1, 'status': 'migrated', 'plan': plan, 'backup': result}
    finally:
        store.close()


def restore_new(config, source, *, confirmed=False):
    if not confirmed:
        raise ValueError('restore requires --yes and a new destination in --config; stop the service first')
    destination = Path(config.storage.path).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('restore never replaces an existing/live database; select new storage.path')
    lease = WriterLease(str(destination)+'.lock')
    try:
        lease.acquire()
        result = backup(Reader(source, config.api, allowed_versions=(1, SCHEMA_VERSION)), destination, max_bytes=config.storage.max_bytes)
        return {'schema_version': 1, 'status': 'restored_to_new_database', 'backup': result}
    finally:
        lease.close()


def prune(config, *, confirmed=False):
    if not confirmed:
        return {'schema_version': 1, 'status': 'dry_run', 'retention_seconds': config.storage.retention_seconds,
                'max_events': config.storage.max_events, 'cleanup_batch': config.storage.cleanup_batch,
                'requires_stopped_writer': True}
    plan = migration_plan(config)
    if plan['current_version'] != SCHEMA_VERSION:
        raise ValueError('prune requires existing current schema; run storage migrate first')
    store = SQLiteStore(config.storage)
    try:
        store.open(maintenance=False)
        store.maintenance()
        return {'schema_version': 1, 'status': 'bounded_retention_pass', 'metrics': dict(store.metrics)}
    finally:
        store.close()
