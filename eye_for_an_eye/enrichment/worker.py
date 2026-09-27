"""Bounded jobs with killable lookup processes and bounded parent IPC."""
from collections import Counter
import ipaddress
import json
import multiprocessing
import queue
import threading
import time
from .cache import TTLCache
from .providers import lookup


def _execute(sender, provider, ip, options):
    try:
        result = provider(ip, options)
        data = json.dumps(result, ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(data) > 16384:
            data = b'{"status":"unavailable","reason":"result_too_large"}'
        sender.send_bytes(data)
    except Exception:
        sender.send_bytes(b'{"status":"unavailable","reason":"provider_error"}')
    finally:
        sender.close()


class EnrichmentService:
    def __init__(self, *, provider=None, on_result, enabled=False, workers=4, queue_size=512,
                 timeout=2, cache_entries=10000, cache_ttl=600, negative_ttl=30,
                 provider_options=None):
        if not 1 <= workers <= 16 or not 1 <= queue_size <= 10000 or not 0 < timeout <= 60:
            raise ValueError('invalid worker limits')
        self.provider = provider or lookup
        self.on_result, self.enabled = on_result, enabled
        self.workers, self.timeout, self.negative_ttl = workers, timeout, negative_ttl
        self.options = dict(provider_options or {})
        self.cache = TTLCache(cache_entries, cache_ttl, max_bytes=16_777_216)
        self.queue = queue.Queue(queue_size)
        self.cancel = threading.Event()
        self.threads = []
        self._processes = set()
        self._pending = set()
        self._lock = threading.RLock()
        self.metrics = Counter()
        self._backoff_until = 0.0
        self._started = False

    @property
    def active_processes(self):
        with self._lock:
            return len(self._processes)

    def start(self):
        if self._started or not self.enabled:
            return
        if self.cancel.is_set():
            raise RuntimeError('service is closed')
        self._started = True
        for _ in range(self.workers):
            thread = threading.Thread(target=self._run, name='enrichment-supervisor')
            self.threads.append(thread)
            thread.start()

    def _emit(self, event_id, ip, result):
        try:
            self.on_result(event_id, ip, result)
        except Exception:
            self.metrics['callback_errors'] += 1

    def submit(self, event_id, ip, options=None):
        if not self.enabled or not self._started or self.cancel.is_set():
            return False
        if not isinstance(event_id, str) or len(event_id) > 128:
            raise ValueError('invalid event id')
        ip = str(ipaddress.ip_address(ip))
        cached = self.cache.get(ip)
        if cached is not None:
            self._emit(event_id, ip, cached)
            return True
        with self._lock:
            if ip in self._pending or time.monotonic() < self._backoff_until:
                self.metrics['suppressed'] += 1
                return False
            try:
                job_options = dict(self.options)
                job_options.update(options or {})
                if len(json.dumps(job_options)) > 8192:
                    raise ValueError('job options too large')
                self.queue.put_nowait((event_id, ip, job_options))
                self._pending.add(ip)
                return True
            except queue.Full:
                self.metrics['queue_full'] += 1
                return False

    def _lookup(self, ip, options):
        context = multiprocessing.get_context('spawn')
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(target=_execute, args=(sender, self.provider, ip, options), daemon=True)
        result = {'status': 'unavailable', 'reason': 'timeout'}
        deadline = time.monotonic() + self.timeout
        try:
            process.start()
            sender.close()
            with self._lock:
                self._processes.add(process)
                self.metrics['started'] += 1
            while not self.cancel.is_set() and time.monotonic() < deadline:
                if receiver.poll(min(.05, max(0, deadline - time.monotonic()))):
                    result = json.loads(receiver.recv_bytes(16384))
                    if not isinstance(result, dict) or 'status' not in result:
                        result = {'status': 'unavailable', 'reason': 'invalid_result'}
                    break
                if not process.is_alive():
                    result = {'status': 'unavailable', 'reason': 'worker_exited'}
                    break
            if self.cancel.is_set():
                result = {'status': 'unavailable', 'reason': 'cancelled'}
        except (OSError, EOFError, ValueError, TypeError):
            result = {'status': 'unavailable', 'reason': 'worker_error'}
        finally:
            receiver.close()
            sender.close()
            if process.pid is not None:
                process.join(.05)
                if process.is_alive():
                    process.terminate()
                    process.join(1)
                if process.is_alive():
                    process.kill()
                    process.join(1)
                with self._lock:
                    self._processes.discard(process)
                process.close()
        return result

    def _run(self):
        while not self.cancel.is_set():
            try:
                event_id, ip, options = self.queue.get(timeout=.05)
            except queue.Empty:
                continue
            try:
                started = time.monotonic()
                try:
                    result = self._lookup(ip, options)
                except (OSError, ValueError, RuntimeError):
                    result = {'status': 'unavailable', 'reason': 'worker_start_failed'}
                success = result.get('status') in ('ok', 'measured')
                self.cache.set(ip, result, ttl_seconds=None if success else self.negative_ttl)
                if result.get('status') == 'unavailable':
                    with self._lock:
                        self._backoff_until = time.monotonic() + min(self.negative_ttl, 5)
                self._emit(event_id, ip, result)
                self.metrics['completed'] += 1
                self.metrics['latency_seconds'] += time.monotonic() - started
            finally:
                with self._lock:
                    self._pending.discard(ip)
                self.queue.task_done()

    def close(self, timeout=3):
        self.cancel.set()
        deadline = time.monotonic() + timeout
        for thread in self.threads:
            thread.join(max(0, deadline - time.monotonic()))
        with self._lock:
            self._pending.clear()
        while True:
            try:
                self.queue.get_nowait()
                self.queue.task_done()
                self.metrics['cancelled_jobs'] += 1
            except queue.Empty:
                break
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError('enrichment shutdown exceeded deadline')
