from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
import ipaddress
import json
import uuid
from .event_types import CLASSIFICATIONS, CONFIDENCES, EventType
from .security.redaction import bounded_value

SCHEMA_VERSION = 3


@dataclass(slots=True)
class NetworkEvent:
    src_ip: str
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    transport: str = 'unknown'
    event_type: str = EventType.PACKET_OBSERVED
    observations: dict = field(default_factory=dict)
    hypotheses: dict = field(default_factory=dict)
    enrichment: dict = field(default_factory=lambda: {'status': 'not_requested'})
    schema_version: int = SCHEMA_VERSION
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sensor_id: str = 'local'
    limitations: list[str] = field(default_factory=list)
    classification: str | None = None
    confidence: str = 'UNKNOWN'
    deception: dict = field(default_factory=dict)

    def __post_init__(self):
        self.event_type = EventType(self.event_type)
        behavior = self.hypotheses.get('behavior', {})
        if self.event_type == EventType.CORRELATION_RESULT and isinstance(behavior, dict) and 'classification' in behavior:
            self.classification = behavior.get('classification')
            self.confidence = behavior.get('confidence', 'UNKNOWN')
        if self.classification is not None and self.classification not in CLASSIFICATIONS:
            raise ValueError('invalid classification')
        if self.confidence not in CONFIDENCES or not isinstance(self.deception, dict):
            raise ValueError('invalid confidence/deception')
        if 'profile_id' in self.observations and not self.deception:
            self.deception = {key: self.observations[key] for key in
                ('profile_id', 'profile_version', 'catalogue_version', 'service_family', 'command_class',
                 'request_length', 'response_length', 'duration', 'load_mode') if key in self.observations}

    def to_dict(self):
        if self.timestamp.tzinfo is None:
            raise ValueError('event timestamp requires timezone')
        record = {item.name: getattr(self, item.name) for item in fields(self)}
        record['timestamp'] = self.timestamp.astimezone(timezone.utc).isoformat()
        for key in ('observations', 'hypotheses', 'enrichment', 'limitations', 'deception'):
            record[key] = bounded_value(record[key])
        record['schema_version'] = SCHEMA_VERSION
        return record

    def to_json(self):
        record = self.to_dict()
        line = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        if len(line) > 4096:
            record.update(observations={'record_truncated': True}, hypotheses={}, deception={},
                          classification=None, confidence='UNKNOWN', enrichment={'status': 'unavailable'},
                          limitations=['record_limit'])
            line = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        if len(line) > 4096:
            raise ValueError('event metadata exceeds frame budget')
        return line

    @classmethod
    def from_json(cls, encoded):
        if not isinstance(encoded, (str, bytes)) or len(encoded) > 4096:
            raise ValueError('invalid event frame size')
        try:
            record = json.loads(encoded)
            if not isinstance(record, dict) or set(record) - {item.name for item in fields(cls)}:
                raise ValueError('unknown event fields')
            if type(record.get('schema_version')) is not int or record['schema_version'] not in (1, 2, SCHEMA_VERSION):
                raise ValueError('unsupported event schema')
            if record['schema_version'] == 1:
                if not isinstance(record.get('limitations', []), list):
                    raise ValueError('invalid legacy limitations')
                record.setdefault('limitations', []).append('legacy_schema_v1')
            elif record['schema_version'] == 2:
                record.setdefault('limitations', []).append('legacy_schema_v2')
            if record['schema_version'] < SCHEMA_VERSION:
                record.setdefault('classification', None)
                record.setdefault('confidence', 'UNKNOWN')
                record.setdefault('deception', {})
            record['schema_version'] = SCHEMA_VERSION
            for key, maximum in (('src_ip', 64), ('event_type', 64), ('sensor_id', 64), ('event_id', 128)):
                value = record.get(key, 'local' if key == 'sensor_id' else None)
                if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(char) < 32 for char in value):
                    raise ValueError('invalid event metadata')
            for key in ('src_ip', 'dst_ip'):
                value = record.get(key)
                if value is not None and value not in ('runtime', 'unknown'):
                    ipaddress.ip_address(value)
            for key in ('src_port', 'dst_port'):
                value = record.get(key)
                if value is not None and (type(value) is not int or not 0 <= value <= 65535):
                    raise ValueError('invalid event port')
            if record.get('transport') not in ('tcp', 'udp', 'icmp', 'icmpv6', 'other', 'unknown'):
                raise ValueError('invalid transport')
            for key in ('observations', 'hypotheses', 'enrichment', 'deception'):
                if not isinstance(record.get(key), dict):
                    raise ValueError('event sections must be objects')
            limitations = record.get('limitations', [])
            if not isinstance(limitations, list) or len(limitations) > 24 or not all(isinstance(item, str) for item in limitations):
                raise ValueError('invalid limitations')
            stamp = datetime.fromisoformat(record['timestamp'])
            if stamp.tzinfo is None:
                raise ValueError('timestamp must include timezone')
            record['timestamp'] = stamp.astimezone(timezone.utc)
            return cls(**record)
        except (KeyError, TypeError, OverflowError, RecursionError) as exc:
            raise ValueError('invalid event schema') from exc


class EventPipeline:
    def __init__(self, sink, enrichment=None):
        self.sink, self.enrichment = sink, enrichment

    def record(self, event):
        accepted = self.sink.emit(event)
        # Never spend enrichment resources on an event rejected by backpressure.
        if accepted and self.enrichment is not None and getattr(self.sink, 'allow_enrichment', lambda: True)():
            self.enrichment.submit(event.event_id, event.src_ip)
        return accepted

    def enriched(self, event_id, ip, result):
        self.sink.emit(NetworkEvent(ip, event_type=EventType.ENRICHMENT_RESULT,
                                   observations={'parent_event_id': event_id}, enrichment=result))
