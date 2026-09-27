"""Repeat bounded listener/API/storage lifecycles to distinguish startup from leaks."""
import gc
import http.client
from pathlib import Path
import tempfile
from benchmarks.common import config, resources
from benchmarks.bench_api import free_port
from benchmarks.workloads import event
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime


def run(full=False):
    rows = []
    before = resources()
    for cycle in range(6):
        with tempfile.TemporaryDirectory() as directory:
            settings = config()
            settings.storage.enabled = settings.api.enabled = True
            settings.storage.max_batch_events = 8
            settings.storage.path = str(Path(directory)/'cycle.db')
            settings.api.port = free_port()
            runtime = EventRuntime(settings, logger=EventLogger(settings.logging, writer=lambda line: None))
            runtime.start()
            try:
                for index in range(32):
                    runtime.emit(event(index))
                conn = http.client.HTTPConnection('127.0.0.1', settings.api.port, timeout=2)
                try:
                    conn.request('GET', '/health')
                    conn.getresponse().read(65537)
                finally:
                    conn.close()
            finally:
                if not runtime.close():
                    raise RuntimeError('lifecycle shutdown')
            stopped = resources()
        del runtime, conn
        gc.collect()
        rows.append({'cycle': cycle, 'after_close': stopped, 'after_collect': resources()})
    return {'before': before, 'cycles': rows,
        'note': 'Cycle zero warms libraries; compare subsequent post-collection handle/thread counts. RSS need not fall.'}
