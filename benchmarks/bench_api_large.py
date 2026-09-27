"""Production keyset reader on a finite large synthetic table; no new index."""
from dataclasses import replace
from pathlib import Path
import tempfile
import time
from benchmarks.common import config, configuration, measure
from benchmarks.workloads import event
from eye_for_an_eye.storage.sqlite import SQLiteStore
from eye_for_an_eye.storage.reader import Reader, Query


def run(full=False):
    settings = config()
    settings.storage.max_batch_events = 32
    count = 50000 if full else 10000
    with tempfile.TemporaryDirectory() as directory:
        settings.storage.path = str(Path(directory) / 'large.db')
        store = SQLiteStore(settings.storage)
        store.open()
        started = time.perf_counter()
        try:
            now = time.time()
            for offset in range(0, count, 32):
                rows = [event(i, sources=1000, stamp=now - 1700000000 - 100 + i / count)
                        for i in range(offset, min(count, offset + 32))]
                if not all(store.write_batch(rows)):
                    raise RuntimeError('large table seed rejected')
            seed_seconds = time.perf_counter() - started
            reader = Reader(settings.storage.path, settings.api)
            base = Query.parse({'limit': '20'}, settings.api)
            results, plans = {}, {}
            for name, query in (('first_page', base), ('deep_cursor', replace(base, cursor=count//10)),
                                ('source_filter', replace(base, source='10.0.0.1'))):
                results[name] = measure(30, lambda i: reader.events(query))
                page, cursor = reader.events(query)
                if not page:
                    raise RuntimeError('large-table query must exercise nonempty rows')
                results[name].update(returned_rows=len(page), next_cursor=cursor)
                index, where, args = reader.where(query)
                with reader.connect() as connection:
                    plans[name] = connection.execute(f'EXPLAIN QUERY PLAN SELECT seq,event_json FROM events INDEXED BY {index} '
                        f'WHERE {where} ORDER BY seq DESC LIMIT ?', (*args, 21)).fetchall()
            results['summaries'] = measure(10, lambda i: reader.summaries(base))
            results['stats'] = measure(10, lambda i: reader.stats(base))
            disk = store.disk_bytes()
        finally:
            store.close()
    return {'configuration': configuration(settings), 'rows': count, 'seed_seconds': seed_seconds,
            'reader': results, 'query_plans': plans, 'disk_bytes': disk,
            'note': 'New P5 coverage, no pre-P5 paired large-table baseline; seq cursor already exists in P4.'}
