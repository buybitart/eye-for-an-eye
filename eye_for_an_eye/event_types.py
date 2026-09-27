"""Stable wire names; old names remain aliases in the versioned catalogue."""
from enum import StrEnum


class EventType(StrEnum):
    CONNECTION_ACCEPTED = 'connection'
    CONNECTION_ATTEMPT = 'connection_attempt'
    CONNECTION_REJECTED = 'connection_rejected'
    CONNECTION_CLOSED = 'connection_closed'
    PACKET_OBSERVED = 'network_observation'
    SERVICE_PROBE = 'service_probe'
    PROTOCOL_PROBE = 'protocol_probe'
    PROTOCOL_COMMAND = 'protocol_command'
    PROTOCOL_ANOMALY = 'protocol_anomaly'
    FINGERPRINT_RESULT = 'fingerprint_observation'
    CREDENTIAL_ATTEMPT = 'credential_attempt'
    CORRELATION_RESULT = 'correlation_result'
    SCAN_DETECTED = 'scan_detected'
    BOT_PATTERN = 'bot_pattern'
    DISTRIBUTED_SCAN_PATTERN = 'distributed_scan_pattern'
    SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    DECEPTION_CONNECTION = 'deception_connection'
    DECEPTION_RESPONSE = 'deception_response'
    ENRICHMENT_RESULT = 'enrichment_result'
    ENRICHMENT_COMPLETED = 'enrichment_completed'
    ENRICHMENT_FAILED = 'enrichment_failed'
    QUEUE_DROP = 'queue_drop'
    STORAGE_ERROR = 'storage_error'
    RUNTIME_WARNING = 'runtime_warning'
    PARSE_ERROR = 'parse_error'
    PATH_MEASUREMENT = 'path_measurement'
    PROBE_MATCH = 'probe_match'
    SHUTDOWN_METRICS = 'shutdown_metrics'
    AUDIT = 'audit'
    DECISION = 'decision_record'


CLASSIFICATIONS = frozenset({'noise', 'scanner', 'bot', 'suspicious', 'targeted-hypothesis', 'distributed_scan_pattern'})
CONFIDENCES = frozenset({'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH'})


class EventPriority(StrEnum):
    HIGH = 'high'
    NORMAL = 'normal'
    LOW = 'low'


_HIGH = frozenset({EventType.DECISION, EventType.CORRELATION_RESULT, EventType.SCAN_DETECTED, EventType.BOT_PATTERN,
    EventType.DISTRIBUTED_SCAN_PATTERN, EventType.SUSPICIOUS_ACTIVITY, EventType.PROTOCOL_ANOMALY,
    EventType.CREDENTIAL_ATTEMPT, EventType.QUEUE_DROP, EventType.STORAGE_ERROR, EventType.RUNTIME_WARNING,
    EventType.PARSE_ERROR, EventType.SHUTDOWN_METRICS, EventType.AUDIT, EventType.ENRICHMENT_FAILED})
_LOW = frozenset({EventType.CONNECTION_CLOSED, EventType.ENRICHMENT_RESULT, EventType.ENRICHMENT_COMPLETED})


def event_priority(event_type):
    """Admission policy only; never changes classification or confidence."""
    return EventPriority.HIGH if event_type in _HIGH else EventPriority.LOW if event_type in _LOW else EventPriority.NORMAL
