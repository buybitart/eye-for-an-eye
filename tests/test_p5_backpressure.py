from unittest.mock import Mock
import pytest
from eye_for_an_eye.config import Config
from eye_for_an_eye.event_types import EventType, EventPriority, event_priority
from eye_for_an_eye.events import NetworkEvent, EventPipeline
from eye_for_an_eye.queues import BoundedQueue
from eye_for_an_eye.runtime import EventRuntime


def test_priority_reserves_both_budgets_and_keeps_fifo():
    for max_events, max_bytes, size in ((10, 1000, 1), (1000, 10, 1)):
        q = BoundedQueue(max_events, max_bytes, priority_enabled=True, low_watermark=.7, normal_watermark=.9)
        for i in range(7):
            assert q.put(i, size, priority='low')
        assert not q.put('low', size, priority='low')
        assert q.put(7, size)
        assert q.put(8, size)
        assert not q.put('normal', size)
        assert q.put(9, size, priority='high')
        assert not q.put('high', size, priority='high')
        assert q.snapshot()['shed'] == {'low': 1, 'normal': 1, 'high': 0}
        assert q.snapshot()['dropped'] == 3
        assert [q.get() for _ in range(10)] == list(range(10))
        assert q.snapshot()['bytes'] == 0
        with pytest.raises(ValueError):
            q.put(None, 1, priority='external-label')


def test_default_admission_preserved_and_runtime_counters_survive_shedding():
    q = BoundedQueue(10, 1000)
    assert all(q.put(i, 1, priority='low') for i in range(10))
    assert not q.put(10, 1, priority='high')
    settings = Config()
    settings.runtime.load_shedding = True
    settings.runtime.queue_events = 10
    runtime = EventRuntime(settings)
    provider = Mock()
    pipeline = EventPipeline(runtime, provider)
    for _ in range(9):
        assert pipeline.record(NetworkEvent('127.0.0.1'))
    assert provider.submit.call_count == 7
    assert not pipeline.record(NetworkEvent('127.0.0.1', event_type=EventType.ENRICHMENT_RESULT))
    assert runtime.emit(NetworkEvent('runtime', event_type=EventType.STORAGE_ERROR))
    assert not runtime.emit(NetworkEvent('runtime', event_type=EventType.PARSE_ERROR))
    state = runtime.snapshot()
    assert state['metrics']['events_created_total'] == 12
    assert state['metrics']['events_dropped_total'] == 2
    assert state['metrics']['events_shed_low_total'] == 1
    assert state['metrics']['enrichment_suppressed_backpressure_total'] == 2
    assert event_priority(EventType.CREDENTIAL_ATTEMPT) == EventPriority.HIGH
    assert event_priority(EventType.FINGERPRINT_RESULT) == EventPriority.NORMAL
    assert runtime.close()


def test_watermark_validation():
    settings = Config()
    settings.runtime.low_priority_watermark = .95
    with pytest.raises(ValueError):
        settings.validate()
