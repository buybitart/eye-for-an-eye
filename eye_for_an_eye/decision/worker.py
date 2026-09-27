"""Bounded admission/cache; aggregate inference is never on packet intake."""
import queue
import threading
import time
from ..enrichment.cache import TTLCache
from .features import FeatureTransformer
from .onnx_model import IsolatedModel, MLResult


class InferenceWorker:
    def __init__(self, config):
        self.config = config
        self.model = IsolatedModel(config)
        self.requests = queue.Queue(maxsize=config.max_pending)
        self.results = queue.Queue(maxsize=config.max_pending)
        self.cache = TTLCache(config.cache_entries, config.cache_ttl_seconds, max_bytes=2_097_152)
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.thread = None

    def start(self):
        if self.thread is not None:
            raise RuntimeError('ML worker already started')
        self.thread = threading.Thread(target=self._run, name='e4e-ml', daemon=True)
        self.thread.start()
        if self.config.required:
            self.ready.wait(self.config.startup_timeout_seconds + 1)
            if self.model.health()['status'] != 'healthy':
                self.close()
                raise RuntimeError('required ML unavailable')

    def _run(self):
        try:
            self.model.load()
            self.ready.set()
            while not self.stop.is_set():
                try:
                    identifier, vector, submitted = self.requests.get(timeout=.05)
                except queue.Empty:
                    continue
                if time.monotonic() - submitted > self.config.inference_timeout_ms / 1000:
                    result = MLResult('degraded', error='queue_deadline')
                else:
                    health = self.model.health()
                    key = (health['model_version'], FeatureTransformer.fingerprint(vector))
                    result = self.cache.get(key)
                    if result is None:
                        # Projected to the schema this artifact was fitted on: a
                        # column added afterwards must never reach a model that
                        # has not seen it.
                        result = self.model.predict(FeatureTransformer.project(
                            vector, health['feature_schema_version']))
                        if result.status == 'healthy':
                            self.cache.set(key, result)
                try:
                    self.results.put_nowait((identifier, result))
                except queue.Full:
                    # Parent expires its bounded pending ledger. Never block shutdown here.
                    continue
        finally:
            self.ready.set()
            self.model.close()

    def submit(self, identifier, vector):
        if self.stop.is_set() or not self.ready.is_set() or not self.model.health()['loaded']:
            return False
        try:
            self.requests.put_nowait((identifier, vector, time.monotonic()))
            return True
        except queue.Full:
            return False

    def close(self):
        self.stop.set()
        self.model.abort()
        if self.thread:
            self.thread.join(1.0)
        return not self.thread or not self.thread.is_alive()
