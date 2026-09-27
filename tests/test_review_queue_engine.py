"""The review queue as it is actually wired into the running decision engine.

These tests answer one question: can the running system produce a label for
itself? It must not be able to. The engine may put a window in front of a person
and nothing more.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from eye_for_an_eye.config import Config
from eye_for_an_eye.decision.features import FeatureVector, NAMES
from eye_for_an_eye.decision.onnx_model import MLResult
from eye_for_an_eye.decision.review_queue import UNREVIEWED

SECRET = b'0123456789abcdef0123456789abcdef0123456789'


def vector(**overrides):
    values = {name: 0.0 for name in NAMES}
    values.update({'connections_10s': 2.0, 'connections_60s': 6.0, 'connections_900s': 20.0,
                   'ports_60s': 2.0, 'ports_900s': 3.0, 'destinations_60s': 1.0,
                   'families_60s': 1.0, 'interarrival_mean_60s': 10.0, 'persistence_900s': 30.0})
    seconds = overrides.pop('_seconds', 120.0)
    samples = overrides.pop('_samples', 40)
    loss = overrides.pop('_loss', 0.0)
    values.update(overrides)
    return FeatureVector(values=tuple(values[name] for name in NAMES),
                         observation_seconds=seconds, sample_count=samples,
                         loss_fraction=loss)


def queue_config(tmp_path, **overrides):
    secret_file = tmp_path / 'review.secret'
    secret_file.write_bytes(SECRET)
    secret_file.chmod(0o600)
    config = Config()
    config.decision.enabled = True
    config.storage.enabled = False
    config.reliability.review_queue_enabled = True
    config.reliability.review_queue_path = str(tmp_path / 'review-queue.json')
    config.reliability.review_queue_secret_file = str(secret_file)
    for key, value in overrides.items():
        setattr(config.reliability, key, value)
    return config


def build_engine(config):
    from eye_for_an_eye.correlation.engine import CorrelationEngine
    from eye_for_an_eye.decision.engine import DecisionEngine
    engine = DecisionEngine(config, CorrelationEngine(config.correlation), offline=True)
    engine.start()
    return engine


def decide(engine, source, vec, ml=None):
    from eye_for_an_eye.events import NetworkEvent
    base = NetworkEvent(source, timestamp=datetime.now(timezone.utc))
    return engine._record(base, vec, ml or MLResult('unavailable'))


def test_the_queue_is_closed_unless_the_operator_opens_it(tmp_path):
    config = Config()
    config.decision.enabled = True
    config.storage.enabled = False
    engine = build_engine(config)
    assert engine.review_queue is None
    decide(engine, '198.51.100.1', vector(ports_60s=40.0, anomaly_60s=8.0))
    assert engine.metrics['review_queue_offered_total'] == 0


def test_enabling_it_without_a_secret_leaves_it_closed(tmp_path):
    config = Config()
    config.reliability.review_queue_enabled = True
    config.reliability.review_queue_path = str(tmp_path / 'q.json')
    engine = build_engine(config)
    assert engine.review_queue is None
    assert engine.metrics['review_queue_unavailable_total'] == 1


def test_a_short_secret_is_refused(tmp_path):
    secret_file = tmp_path / 'short.secret'
    secret_file.write_bytes(b'too-short')
    config = Config()
    config.reliability.review_queue_enabled = True
    config.reliability.review_queue_path = str(tmp_path / 'q.json')
    config.reliability.review_queue_secret_file = str(secret_file)
    engine = build_engine(config)
    assert engine.review_queue is None
    assert engine.metrics['review_queue_unavailable_total'] == 1


def test_an_ordinary_quiet_source_is_never_queued(tmp_path):
    engine = build_engine(queue_config(tmp_path))
    for index in range(5):
        decide(engine, f'198.51.100.{index}', vector(connections_60s=2.0, ports_60s=1.0))
    assert engine.review_queue.stats()['total'] == 0


def test_a_blocked_source_is_not_queued_just_for_being_blocked(tmp_path):
    """The prohibition, tested through the real engine rather than in isolation."""
    config = queue_config(tmp_path)
    config.decision.mode = 'shadow'
    engine = build_engine(config)
    record = decide(engine, '198.51.100.50',
                    # Extreme means several independent families, not one large
                    # number: under `math-risk-v4` a source is convincing because
                    # breadth, protocol misuse, decoy contact and repeated
                    # authentication failure each say so — and `credentials_60s`
                    # deliberately says nothing at all any more.
                    vector(ports_60s=60.0, anomaly_60s=12.0, deception_60s=30.0,
                           auth_failures_60s=12.0, auth_failure_ratio=0.9,
                           auth_principals_900s=8.0, auth_failure_span_900s=280.0,
                           destinations_60s=25.0, families_60s=6.0, continuation_60s=0.5,
                           connections_60s=200.0, connections_900s=900.0))
    assert record is not None
    assert record.observations['action'] == 'TEMP_BLOCK', 'this fixture is meant to be acted on'
    for entry in engine.review_queue.entries(state=None, limit=100):
        assert entry.state == UNREVIEWED
    assert engine.review_queue.stats()['labelled_by_a_person'] == 0


def test_the_engine_can_only_ever_add_unreviewed_entries(tmp_path):
    engine = build_engine(queue_config(tmp_path))
    scores = [MLResult('healthy', risk_score=value, confidence=0.9,
                       model_version='test', predicted_class='malicious-automation-like')
              for value in (0.05, 0.5, 0.95)]
    for index, ml in enumerate(scores):
        decide(engine, f'203.0.113.{index}', vector(ports_60s=4.0 + index), ml)
    entries = engine.review_queue.entries(state=None, limit=100)
    assert all(entry.state == UNREVIEWED for entry in entries)
    assert engine.review_queue.labelled() == []


def test_a_disagreement_between_the_engines_reaches_the_queue(tmp_path):
    engine = build_engine(queue_config(tmp_path))
    ml = MLResult('healthy', risk_score=0.95, confidence=0.9, model_version='test',
                  predicted_class='malicious-automation-like')
    decide(engine, '203.0.113.99', vector(connections_60s=3.0, ports_60s=1.0), ml)
    entries = engine.review_queue.entries(limit=10)
    assert entries, 'a strong disagreement is exactly what a person should look at'
    assert any('disagree' in reason for reason in entries[0].reasons)
    assert engine.metrics['review_queue_admitted_total'] >= 1


def test_the_queue_file_never_contains_a_source_address(tmp_path):
    engine = build_engine(queue_config(tmp_path))
    ml = MLResult('healthy', risk_score=0.95, confidence=0.9, model_version='test',
                  predicted_class='malicious-automation-like')
    decide(engine, '203.0.113.77', vector(connections_60s=3.0, ports_60s=1.0), ml)
    text = Path(engine.review_queue.path).read_text(encoding='utf-8')
    assert '203.0.113.77' not in text


def test_the_stored_analysis_is_marked_as_context_not_a_label(tmp_path):
    engine = build_engine(queue_config(tmp_path))
    ml = MLResult('healthy', risk_score=0.95, confidence=0.9, model_version='test',
                  predicted_class='malicious-automation-like')
    decide(engine, '203.0.113.66', vector(connections_60s=3.0, ports_60s=1.0), ml)
    entry = engine.review_queue.entries(limit=1)[0]
    assert 'never a label' in entry.analysis_only['note']
    document = json.loads(Path(engine.review_queue.path).read_text(encoding='utf-8'))
    assert 'cannot start training' in document['authority']


def test_a_broken_queue_never_breaks_a_decision(tmp_path):
    engine = build_engine(queue_config(tmp_path))

    class Broken:
        path = tmp_path / 'unused.json'

        def offer(self, **kwargs):
            raise OSError('disk full')

    engine.review_queue = Broken()
    ml = MLResult('healthy', risk_score=0.95, confidence=0.9, model_version='test',
                  predicted_class='malicious-automation-like')
    record = decide(engine, '203.0.113.55', vector(connections_60s=3.0, ports_60s=1.0), ml)
    assert record is not None, 'defending must continue when collecting fails'
    assert record.observations['action'] in ('OBSERVE', 'WATCH', 'RATE_LIMIT', 'TEMP_BLOCK')
    assert engine.metrics['review_queue_failures_total'] == 1


def test_one_noisy_source_cannot_fill_the_queue_through_the_engine(tmp_path):
    engine = build_engine(queue_config(tmp_path, review_queue_per_source=3))
    ml = MLResult('healthy', risk_score=0.95, confidence=0.9, model_version='test',
                  predicted_class='malicious-automation-like')
    for index in range(40):
        decide(engine, '203.0.113.44',
               vector(connections_60s=3.0 + index * 0.4, ports_60s=1.0 + index * 0.3), ml)
    assert engine.review_queue.stats()['largest_single_source'] <= 3
