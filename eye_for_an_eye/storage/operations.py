"""Operator-only bounded backup using SQLite's online backup API."""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import time
from .sqlite import APPLICATION_ID, SCHEMA_VERSION


def storage_info(reader):
    with reader.connect() as connection:
        values = {name: connection.execute('PRAGMA ' + name).fetchone()[0]
                  for name in ('user_version', 'page_count', 'freelist_count', 'page_size', 'journal_mode')}
        values['events'] = connection.execute('SELECT count(*) FROM events').fetchone()[0]
    values['bytes'] = sum(path.stat().st_size for path in
                         (Path(str(reader.path) + suffix) for suffix in ('', '-wal', '-shm')) if path.exists())
    return values


def backup(reader, destination, *, max_bytes, timeout=10):
    if not 0 < timeout <= 30 or not 1 <= max_bytes <= 2**40:
        raise ValueError('invalid backup budget')
    target = Path(destination).resolve()
    if target == reader.path or str(target) in (str(reader.path) + suffix for suffix in ('-wal', '-shm', '.lock')):
        raise ValueError('backup must use a separate new path')
    deadline = time.monotonic() + timeout
    created = False
    try:
        with reader.connect() as source:
            source_version = source.execute('PRAGMA user_version').fetchone()[0]
            if source_version not in (1, SCHEMA_VERSION):
                raise sqlite3.DatabaseError('unsupported backup source schema')
            page_size = source.execute('PRAGMA page_size').fetchone()[0]
            def progress(status, remaining, total):
                if time.monotonic() > deadline or total * page_size > max_bytes:
                    raise TimeoutError('backup time or byte budget exceeded')
            # Exclusive creation: existing files are never replaced.
            with target.open('xb'):
                created = True
            target.chmod(0o600)
            with closing(sqlite3.connect(target, timeout=.1)) as output:
                source.backup(output, pages=64, progress=progress, sleep=.01)
                if (output.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID or
                        output.execute('PRAGMA user_version').fetchone()[0] != source_version):
                    raise sqlite3.DatabaseError('backup schema mismatch')
        with target.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        return {'schema_version': 1, 'status': 'complete', 'bytes': target.stat().st_size,
                'database_schema_version': source_version, 'sha256': checksum}
    except (OSError, ValueError, sqlite3.Error):
        if created:
            # Only the exact new operator-selected file is removed on failure.
            target.unlink(missing_ok=True)
        raise
