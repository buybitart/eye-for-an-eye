from dataclasses import asdict, dataclass
import ipaddress
import re
from ..security.redaction import bounded_value


def mask_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return '.'.join(value.split('.')[:3]) + '.xxx' if address.version == 4 else address.exploded[:19] + ':xxxx:xxxx:xxxx:xxxx'
    except ValueError:
        return value


def ip_projection(value):
    if isinstance(value, dict):
        return {ip_projection(key): ip_projection(item) for key, item in value.items()}
    if isinstance(value, list):
        return [ip_projection(item) for item in value]
    if isinstance(value, str):
        exact = mask_ip(value)
        if exact != value:
            return exact
        value = re.sub(r'(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?![\w:])', lambda match: mask_ip(match[0]), value)
        return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', lambda match: mask_ip(match[0]), value)
    return value


@dataclass(frozen=True, slots=True)
class EventResponse:
    schema_version: int
    event_id: str
    timestamp: str
    sensor_id: str
    event_type: str
    src_ip: str
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    transport: str
    observations: dict
    hypotheses: dict
    enrichment: dict
    classification: str | None
    confidence: str
    deception: dict
    limitations: list

    @classmethod
    def from_event(cls, event, redact_ip=False):
        data = event.to_dict()
        response = asdict(cls(**data))
        return ip_projection(response) if redact_ip else response


@dataclass(frozen=True, slots=True)
class DetectionSummary:
    event_id: str
    source: str
    classification: str | None
    score: int | None
    confidence: str
    reasons: list
    window: dict
    supporting_event_ids: list
    limitations: list

    @classmethod
    def from_event(cls, event, redact_ip=False):
        behavior = event.hypotheses.get('behavior', {})
        result = asdict(cls(event.event_id, event.src_ip, event.classification, behavior.get('score'),
            event.confidence, behavior.get('reasons', []),
            {key: event.observations.get(key) for key in ('window_seconds', 'window_start', 'window_end')},
            behavior.get('supporting_events', []), event.limitations))
        result = bounded_value(result)
        result['score_is_probability'] = False
        return ip_projection(result) if redact_ip else result


@dataclass(frozen=True, slots=True)
class SourceSummary:
    source: str
    first_seen: str
    last_seen: str
    events: int
    ports_seen: int
    classification: str | None
    confidence: str


@dataclass(frozen=True, slots=True)
class StatsResponse:
    activity: dict
    queue_drops: int
    storage_size: int
    fallback_events: int


@dataclass(frozen=True, slots=True)
class HealthResponse:
    status: str
    live: bool
    ready: bool
    components: dict
    limitations: list
