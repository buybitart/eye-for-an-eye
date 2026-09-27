"""One bounded event consumer owns correlation and SQLite; intake never waits for IO."""
from .event_types import EventType, event_priority
from collections import Counter, deque
from copy import deepcopy
import json
import os
from pathlib import Path
import queue
import sqlite3
import tempfile
import threading
import time
from . import __version__
from .analysis import EventAnalysis
from .compatibility import FEATURE_SCHEMA
from .decision.math_risk import VERSION as MATH_RISK_VERSION
from .decision.policy import POLICY_GUARD_VERSION
from .events import NetworkEvent
from .logging import EventLogger
from .observability.metrics import Metrics, health
from .observability.health import operational_health
from .queues import BoundedQueue
from .storage.sqlite import SQLiteStore


class EventRuntime:
    def __init__(self, config, *, logger=None, mode=None):
        self.config = config.validate()
        self.mode = mode
        self.logger = logger or EventLogger(config.logging)
        self.store = SQLiteStore(config.storage) if config.storage.enabled else None
        self.queue = BoundedQueue(config.runtime.queue_events, config.runtime.queue_bytes,
            priority_enabled=config.runtime.load_shedding, low_watermark=config.runtime.low_priority_watermark,
            normal_watermark=config.runtime.normal_priority_watermark)
        self.registry, self.metrics = Metrics(), Counter()
        self.analysis = EventAnalysis(config)
        self.correlator = self.analysis.correlator
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.thread = None
        self.error = None
        self.drain_deadline = float('inf')
        self.components = {}
        self.enrichment_status = 'disabled' if not config.enrichment.enabled else 'healthy'
        self.storage_started = self.storage_finished = self.storage_latency = 0.0
        self.heartbeat = 0.0
        self._snapshot_lock = threading.Lock()
        self._cached_snapshot = None
        self.endpoints = {}
        self.fallback = deque(maxlen=256)
        self.pending = []
        self.pending_since = 0.0
        self.started_at = time.monotonic()

    def deception_load(self):
        q = self.queue.snapshot()
        pressure = max(q['depth'] / q['max_events'], q['bytes'] / q['max_bytes'])
        now = time.monotonic()
        if self.store:
            age = now - self.storage_started if self.storage_started else 0.0
            latency = self.storage_latency if now - self.storage_finished < 2 else 0.0
            pressure = max(pressure, min(1.0, max(age, latency) / self.config.deception.storage_slow_seconds))
        return {'pressure': pressure, 'failed': bool(self.error) or bool(self.store and self.store.status != 'healthy')}

    def attach(self, **components):
        if set(components) - {'listener', 'capture', 'enrichment', 'path'}:
            raise ValueError('unknown runtime component')
        self.components.update(components)

    def allow_enrichment(self):
        if not self.config.runtime.load_shedding:
            return True
        q = self.queue.snapshot()
        allowed = max(q['depth'] / q['max_events'], q['bytes'] / q['max_bytes']) < self.config.runtime.low_priority_watermark
        if not allowed:
            self.registry.inc('enrichment_suppressed_backpressure_total')
        return allowed

    def emit(self, event):
        try:
            event.sensor_id = self.config.runtime.sensor_id
            encoded = event.to_json()
            NetworkEvent.from_json(encoded)
        except (ValueError, TypeError, AttributeError):
            self.registry.inc('parse_errors_total')
            self.metrics['parse_errors'] += 1
            return False
        self.registry.inc('events_created_total')
        if event.event_type == EventType.PACKET_OBSERVED:
            self.registry.inc('packets_received_total')
        if event.event_type == EventType.FINGERPRINT_RESULT:
            self.registry.inc('fingerprint_results_total')
            if event.observations.get('status') in ('error', 'unavailable'):
                self.registry.inc('fingerprint_errors_total')
        if event.event_type == EventType.DECEPTION_CONNECTION:
            self.registry.inc('deception_connections_total')
        if event.event_type == EventType.DECEPTION_RESPONSE:
            self.registry.inc('deception_responses_total')
            size = event.observations.get('response_length', 0)
            if type(size) is int and size >= 0:
                self.registry.inc('deception_response_bytes_total', size)
        if event.event_type == EventType.ENRICHMENT_RESULT:
            failed = event.enrichment.get('status') == 'unavailable'
            self.enrichment_status = 'degraded' if failed else 'healthy'
            if failed:
                self.registry.inc('enrichment_failures_total')
        accepted = self.queue.put(encoded, len(encoded) + 128, priority=event_priority(event.event_type))
        self.metrics['queued' if accepted else 'dropped'] += 1
        return accepted

    def start(self):
        if self.thread is not None:
            raise RuntimeError('runtime already started')
        self.analysis.start()
        try:
            self.logger.start()
        except (OSError, ValueError):
            self.metrics['logging_start_errors'] += 1
            self.logger.writer = lambda line: None
            self.logger.start()
        self.thread = threading.Thread(target=self._run, name='event-analysis-writer', daemon=True)
        self.thread.start()
        if not self.ready.wait(12) or self.error:
            raise RuntimeError('event/storage startup failed') from self.error
        from .api.server import Endpoint
        for name, section in (('api', self.config.api), ('metrics', self.config.metrics)):
            if section.enabled:
                try:
                    endpoint = Endpoint(self.config, self, metrics=name == 'metrics')
                    self.endpoints[name] = endpoint
                    endpoint.start()
                    if endpoint.status != 'healthy':
                        raise RuntimeError('operational endpoint bind failed')
                    if section.allow_insecure_non_loopback:
                        self.emit(NetworkEvent('runtime', event_type=EventType.RUNTIME_WARNING,
                            observations={'component': name, 'reason': 'explicit_insecure_non_loopback_endpoint'}))
                except (OSError, ValueError, RuntimeError) as exc:
                    self.metrics[name + '_start_errors'] += 1
                    self.registry.inc('api_errors_total' if name == 'api' else 'metrics_errors_total')
                    self.emit(NetworkEvent('runtime', event_type=EventType.RUNTIME_WARNING,
                        observations={'component': name, 'error_code': 'configuration_error' if isinstance(exc, ValueError) else 'network_bind_failure',
                                      'error_type': type(exc).__name__}))

    def _flush_storage(self):
        if not self.pending:
            return
        records, self.pending = self.pending, []
        self.storage_started = time.monotonic()
        previous_pressure = self.store.pressure
        try:
            if self.store.connection is None:
                outcomes = [False] * len(records)
            elif len(records) == 1:
                outcomes = [self.store.write(records[0])]
            else:
                outcomes = self.store.write_batch(records)
        except (OSError, sqlite3.Error) as exc:
            self.store.status, self.store.error = 'degraded', type(exc).__name__
            outcomes = [False] * len(records)
        finally:
            self.storage_finished = time.monotonic()
            self.storage_latency = self.storage_finished - self.storage_started
            self.storage_started = 0.0
            self.registry.observe('storage_write_duration_seconds', self.storage_latency)
            self.registry.inc('storage_batches_total')
        for record, written in zip(records, outcomes):
            if written:
                self.registry.inc('storage_writes_total')
                continue
            self.registry.inc('storage_failures_total')
            self.registry.inc('storage_write_failures_total')
            minimal = NetworkEvent(record.src_ip, record.src_port, record.dst_ip, record.dst_port,
                record.transport, record.event_type, event_id=record.event_id, timestamp=record.timestamp,
                sensor_id=record.sensor_id, classification=record.classification, confidence=record.confidence,
                observations={'minimal_metadata': True}, limitations=['bounded_volatile_storage_fallback'])
            self.fallback.append(minimal.to_json())
            self.logger.emit(NetworkEvent('runtime', event_type=EventType.STORAGE_ERROR,
                observations={'reason': 'bounded_storage_fallback'}))
        if self.store.pressure != previous_pressure:
            self.logger.emit(NetworkEvent('runtime', event_type=EventType.RUNTIME_WARNING,
                observations={'component': 'storage', 'pressure': self.store.pressure}))

    def _run(self):
        try:
            if self.store:
                try:
                    self.store.open()
                except (OSError, sqlite3.Error) as exc:
                    self.store.status, self.store.error = 'unavailable', type(exc).__name__
                    self.metrics['storage_start_errors'] += 1
                    self.logger.emit(NetworkEvent('runtime', event_type=EventType.STORAGE_ERROR,
                        observations={'reason': 'storage_start_failed', 'error_type': type(exc).__name__}))
            self.ready.set()
            updated = 0.0
            while not self.stop.is_set() or not self.queue.empty() or self.pending:
                self.heartbeat = time.monotonic()
                if time.monotonic() >= self.drain_deadline:
                    self.queue.discard()
                    self.metrics['pending_dropped'] += len(self.pending)
                    self.pending.clear()
                    break
                try:
                    remaining = self.config.storage.max_batch_delay_ms / 1000 - (time.monotonic() - self.pending_since)
                    encoded = self.queue.get(timeout=max(0, min(.1, remaining)) if self.pending else .1)
                except queue.Empty:
                    encoded = None
                if encoded is not None or self.analysis.decisions.pending:
                    started = time.monotonic()
                    event = NetworkEvent.from_json(encoded) if encoded is not None else None
                    self.analysis.decisions.healthy = not self.error and not (self.store and self.store.status != 'healthy')
                    # Listener intake has known application drops. Capture/kernel loss remains UNKNOWN.
                    self.analysis.decisions.loss_fraction = (self.metrics['dropped'] / max(1, self.metrics['queued'] + self.metrics['dropped'])
                        if self.components.get('listener') and not self.components.get('capture') else None)
                    # Derived results do not feed correlation or recursively enqueue.
                    records = list(self.analysis.poll())
                    if event is not None:
                        records.extend(self.analysis.process(event))
                    for record in records:
                        if record is not event:
                            self.registry.inc('events_created_total')
                        if record.event_type == EventType.CORRELATION_RESULT:
                            self.registry.inc('correlation_results_total')
                        if self.store:
                            if not self.pending:
                                self.pending_since = time.monotonic()
                            self.pending.append(record)
                            if len(self.pending) >= self.config.storage.max_batch_events:
                                self._flush_storage()
                        self.logger.emit(record)
                    self.registry.inc('handler_latency_seconds', time.monotonic() - started)
                    self.registry.observe('handler_duration_seconds', time.monotonic() - started)
                if self.pending and (time.monotonic() - self.pending_since >= self.config.storage.max_batch_delay_ms / 1000
                                     or self.stop.is_set() and self.queue.empty()):
                    self._flush_storage()
                if time.monotonic() - updated >= 1:
                    if self.store and self.store.connection is not None and time.monotonic() >= self.store.next_cleanup:
                        self.storage_started = time.monotonic()
                        try:
                            self.store.maintenance()
                        finally:
                            self.storage_finished = time.monotonic()
                            self.storage_latency = self.storage_finished - self.storage_started
                            self.storage_started = 0.0
                            self.store.next_cleanup = time.monotonic() + self.config.storage.cleanup_interval
                    self._publish_status()
                    updated = time.monotonic()
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.error = exc
            self.metrics['runtime_errors'] += 1
        finally:
            self.analysis.close()
            self.ready.set()
            if self.pending:
                self.metrics['pending_dropped'] += len(self.pending)
                self.pending.clear()
            if self.store:
                try:
                    if self.store.connection is not None:
                        self.store.maintenance()
                    self.store.close()
                except Exception as exc:
                    self.metrics['storage_close_errors'] += 1
                    self.error = self.error or exc
                    self.store.status = 'unavailable'
            self._publish_status()

    def snapshot(self):
        q = self.queue.snapshot()
        ml_health = self.analysis.decisions.health()
        for name, value in self.analysis.decisions.metrics.copy().items():
            self.registry.set(name, value)
        # P15.5R §38, §49. The autonomous decision path's own counters, bounded
        # by construction: the names come from `ASSUMPTION_NAMES` and a fixed
        # list, so no address, scope or schema number can become a metric label.
        autonomy = self.analysis.decisions.autonomy
        if autonomy is not None:
            for name, value in autonomy.metrics().items():
                self.registry.set(name, value)
        self.registry.set('queue_depth', q['depth'])
        self.registry.set('queue_bytes', q['bytes'])
        self.registry.set('events_dropped_total', q['dropped'] + self.metrics['pending_dropped'])
        for priority in ('low', 'normal', 'high'):
            self.registry.set('events_shed_' + priority + '_total', q['shed'][priority])
        self.registry.set('storage_pending_events', len(self.pending))
        caches = [self.correlator.cache, self.correlator.distributed]
        listener = self.components.get('listener')
        if listener:
            for metric, source in (('connections_accepted_total', 'accepted'), ('connections_rejected_total', 'rejected'),
                                   ('response_bytes_total', 'response_bytes')):
                self.registry.set(metric, listener.metrics[source])
            self.registry.set('connections_active', listener.active_connections)
        capture = self.components.get('capture')
        if capture:
            caches.extend([capture.ids.cache, capture.timestamps.cache, capture.flows.cache])
        self.registry.set('parse_errors_total', self.metrics['parse_errors'] + (capture.errors if capture else 0))
        self.registry.set('packet_parse_errors_total', capture.errors if capture else 0)
        self.registry.set('source_state_entries', len(self.correlator.cache))
        self.registry.set('log_suppressed_total', self.logger.metrics.get('suppressed_count', 0))
        self.registry.set('log_dropped_total', sum(self.logger.metrics.get(key, 0) for key in ('sampled', 'dropped', 'disk_pressure_drops')))
        self.registry.set('log_errors_total', self.logger.metrics.get('write_errors', 0) + self.metrics['logging_start_errors'])
        enricher = self.components.get('enrichment')
        if enricher:
            caches.append(enricher.cache)
            self.registry.set('enrichment_requests_total', enricher.metrics['started'])
            self.registry.set('enrichment_latency_seconds', enricher.metrics['latency_seconds'])
            self.registry.set('enrichment_duration_seconds_sum', enricher.metrics['latency_seconds'])
            self.registry.set('enrichment_duration_seconds_count', enricher.metrics['completed'])
        self.registry.set('cache_entries', sum(len(cache) for cache in caches))
        self.registry.set('cache_evictions_total', sum(cache.metrics['eviction'] for cache in caches))
        if self.store:
            self.registry.set('storage_written_total', self.store.metrics['written'])
            self.registry.set('storage_retained_events', self.store.metrics['retained_events'])
            self.registry.set('storage_bytes', self.store.metrics['disk_bytes'])
            self.registry.set('storage_pressure', {'NORMAL': 0, 'WARNING': 1, 'CRITICAL': 2}[self.store.pressure])
        components = {'ml': ml_health['status'], 'capture': capture.ipc_status if capture else 'disabled',
                      'listeners': ('unavailable' if listener.error else 'healthy') if listener else 'disabled',
                      'correlation': 'unavailable' if self.error else 'healthy',
                      'event_queue': 'unavailable' if self.error else ('degraded' if q['dropped'] else 'healthy'),
                      'storage': self.store.status if self.store else 'disabled',
                      'enrichment': self.enrichment_status,
                      'logging': 'degraded' if self.logger.metrics.get('write_errors', 0) or self.metrics['logging_start_errors'] or self.logger.metrics.get('disk_pressure_drops', 0) else 'healthy',
                      'deception': 'healthy' if listener and self.mode in ('services', 'garbage') and self.config.deception.enabled else 'disabled'}
        for name in ('api', 'metrics'):
            endpoint = self.endpoints.get(name)
            enabled = getattr(self.config, name).enabled
            components[name] = (endpoint.status if endpoint.status == 'disabled' or endpoint.thread and endpoint.thread.is_alive() else 'unavailable') if endpoint else ('unavailable' if enabled else 'disabled')
        deception = getattr(listener, 'deception', None) if listener else None
        if deception and deception.policy.load.mode != 'NORMAL':
            components['deception'] = 'degraded'
        # P15.5R §21, §49. What the decision path is, as distinct from what the
        # sensor is. Kept beside `health` rather than merged into it: the
        # operational health above answers "is this sensor working", and a
        # calibrator that cannot support a block is not a sensor that has
        # stopped working — it is a defender that cannot act, which is a
        # different sentence and deserves its own.
        decision = self.analysis.decisions
        autonomy = decision.autonomy
        decision_status = {'components': decision.component_health(),
                           'feature_schema_version': FEATURE_SCHEMA.current,
                           'math_version': MATH_RISK_VERSION,
                           'policy_guard_version': POLICY_GUARD_VERSION,
                           'autonomous': autonomy.health() if autonomy is not None else
                           {'mode': 'not_configured',
                            'note': 'the P0-P14 fused path decides in this deployment'}}
        return {'schema_version': 1, 'sensor_id': self.config.runtime.sensor_id,
                'application_version': __version__, 'deployment_profile': self.config.deployment.profile,
                'mode': self.mode, 'uptime_seconds': max(0, time.monotonic() - self.started_at),
                'health': health(components), 'metrics': self.registry.snapshot(), 'queue': q,
                'ml': ml_health, 'decision': decision_status,
                'logging': dict(self.logger.metrics), 'correlation': self.correlator.snapshot(),
                'deception': {'mode': deception.policy.load.mode, **deception.metrics} if deception else {'mode': 'disabled'},
                'fallback_events': len(self.fallback), 'storage_pressure': self.store.pressure if self.store else 'NORMAL',
                'running': not self.stop.is_set()}

    def _publish_status(self):
        state = self.snapshot()
        state['operational'] = self._project_health(state)
        with self._snapshot_lock:
            self._cached_snapshot = state
        if not self.config.runtime.status_file:
            return
        temporary = None
        try:
            path = Path(self.config.runtime.status_file)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, prefix='.e4e-', delete=False) as stream:
                temporary = stream.name
                json.dump(state, stream, ensure_ascii=True, allow_nan=False)
            os.replace(temporary, path)
        except OSError:
            self.metrics['status_write_errors'] += 1
        finally:
            try:
                if temporary and Path(temporary).exists():
                    Path(temporary).unlink()
            except OSError:
                self.metrics['status_write_errors'] += 1

    def control_snapshot(self):
        with self._snapshot_lock:
            state = deepcopy(self._cached_snapshot)
        return state if state is not None else self.snapshot()

    def health_response(self):
        state = self.control_snapshot()
        return self._project_health(state)

    def _project_health(self, state):
        listener = self.components.get('listener')
        if listener and ((listener.ready.is_set() and not listener.running) or
                         (listener.running and time.monotonic() - listener.heartbeat > 5)):
            state['health']['components']['listeners'] = 'unavailable'
        return operational_health(state, heartbeat=self.heartbeat,
            worker_alive=self.thread is not None and self.thread.is_alive(), stopping=self.stop.is_set())

    def close(self, timeout=None):
        timeout = self.config.runtime.shutdown_timeout if timeout is None else max(0, timeout)
        deadline = time.monotonic() + timeout
        for endpoint in self.endpoints.values():
            endpoint.close(timeout=min(.5, max(0, deadline - time.monotonic())))
        self.drain_deadline = max(time.monotonic(), deadline - .5)
        self.stop.set()
        self.queue.close()
        if self.thread:
            self.thread.join(max(0, deadline - time.monotonic()))
        logger_closed = self.logger.close(timeout=max(0, deadline - time.monotonic()))
        return logger_closed and not self.error and (self.thread is None or not self.thread.is_alive())
