import threading
import time
import unittest
from unittest.mock import patch
from eye_for_an_eye.enrichment.providers import normalize_geoip, normalize_whois
from eye_for_an_eye.enrichment.worker import EnrichmentService


def slow_provider(ip, options):
    time.sleep(10)
    return {'status': 'ok'}


def fake_provider(ip, options):
    return {'status': 'not_found'}


def broken_provider(ip, options):
    raise RuntimeError('provider failure')


class EnrichmentTests(unittest.TestCase):
    def test_geoip_absent_fields_and_locale(self):
        self.assertEqual(normalize_geoip(None)['status'], 'not_found')
        self.assertEqual(normalize_geoip({})['status'], 'not_found')
        result = normalize_geoip({'country': {'names': {'en': 'Example'}}})
        self.assertEqual(result['country'], 'Example')
        self.assertIsNone(result['city'])
        self.assertEqual(normalize_whois({'nets': []})['status'], 'not_found')

    def test_disabled_starts_no_threads_or_processes(self):
        worker = EnrichmentService(on_result=lambda *args: None)
        worker.start()
        self.assertFalse(worker.submit('id', '192.0.2.1'))
        self.assertEqual(worker.active_processes, 0)
        worker.close()

    def test_hard_timeout_negative_cache_shutdown(self):
        records = []
        done = threading.Event()
        def result(*args):
            records.append(args)
            done.set()
        worker = EnrichmentService(provider=slow_provider, on_result=result, enabled=True,
                                   workers=1, timeout=.3, queue_size=1)
        worker.start()
        try:
            self.assertTrue(worker.submit('first', '192.0.2.1'))
            self.assertTrue(done.wait(3))
            self.assertEqual(records[0][2]['reason'], 'timeout')
            processes = worker.metrics['started']
            done.clear()
            self.assertTrue(worker.submit('second', '192.0.2.1'))
            self.assertTrue(done.wait(1))
            self.assertEqual(worker.metrics['started'], processes)
        finally:
            worker.close()
        self.assertEqual(worker.active_processes, 0)
        self.assertTrue(all(not thread.is_alive() for thread in worker.threads))

    def test_normal_result(self):
        done = threading.Event()
        records = []
        worker = EnrichmentService(provider=fake_provider, enabled=True, workers=1, timeout=2,
                                   on_result=lambda *args: records.append(args) or done.set())
        worker.start()
        try:
            worker.submit('id', '192.0.2.1')
            self.assertTrue(done.wait(3))
            self.assertEqual(records[0][2]['status'], 'not_found')
        finally:
            worker.close()

    def test_worker_start_failure_is_an_event(self):
        records = []
        done = threading.Event()
        worker = EnrichmentService(provider=fake_provider, enabled=True, workers=1,
                                   on_result=lambda *args: records.append(args) or done.set())
        with patch.object(worker, '_lookup', side_effect=PermissionError('denied')):
            worker.start()
            try:
                worker.submit('id', '192.0.2.1')
                self.assertTrue(done.wait(1))
                self.assertEqual(records[0][2]['reason'], 'worker_start_failed')
            finally:
                worker.close()

    def test_queue_and_workers_bounded_and_running_job_cancelled(self):
        worker = EnrichmentService(provider=slow_provider, enabled=True, workers=1,
                                   queue_size=1, timeout=10, on_result=lambda *args: None)
        worker.start()
        try:
            worker.submit('first', '192.0.2.1')
            deadline = time.monotonic() + 2
            while worker.active_processes != 1 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(worker.active_processes, 1)
            self.assertTrue(worker.submit('queued', '192.0.2.2'))
            self.assertFalse(worker.submit('overflow', '192.0.2.3'))
            self.assertFalse(worker.submit('duplicate', '192.0.2.1'))
            self.assertEqual(worker.queue.qsize(), 1)
            started = time.monotonic()
        finally:
            worker.close()
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(worker.active_processes, 0)
        self.assertEqual(worker.queue.qsize(), 0)
        self.assertEqual(worker.metrics['cancelled_jobs'], 1)
        self.assertTrue(all(not thread.is_alive() for thread in worker.threads))

    def test_provider_exception_triggers_failure_backoff(self):
        records, done = [], threading.Event()
        worker = EnrichmentService(provider=broken_provider, enabled=True, workers=1, timeout=2,
                                   on_result=lambda *args: records.append(args) or done.set())
        worker.start()
        try:
            worker.submit('bad', '192.0.2.1')
            self.assertTrue(done.wait(3))
            self.assertEqual(records[0][2]['reason'], 'provider_error')
            self.assertFalse(worker.submit('next', '192.0.2.2'))
            self.assertEqual(worker.metrics['started'], 1)
        finally:
            worker.close()
