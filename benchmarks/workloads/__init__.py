"""Fixed synthetic data. Address diversity is offline metadata, never bind/spoof targets."""
from datetime import datetime, timezone
import random
from benchmarks.common import SEED
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.event_types import EventType

PROFILES = {
    'normal': {'connections_per_second': 10, 'sources': 4, 'payload_bytes': 18},
    'scanner': {'sources': 4, 'ports': 128, 'payload_bytes': 18, 'short_connections': True},
    'distributed': {'sources': 50000, 'events_per_source': 2, 'socket_traffic': False},
    'idle': {'levels': [10, 100, 128], 'connections_limit': 128, 'payload_bytes': 0},
    'malformed': {'short_packets': True, 'invalid_options': True, 'binary_bytes': 256},
    'conversation': {'protocols': ['http', 'ftp', 'ssh'], 'max_messages': 5},
    'mixed': {'writers': 1, 'api_readers': 2, 'metrics_scrapers': 1},
}


def event(index, sources=16, *, stamp=None):
    source = index % sources
    return NetworkEvent(f'10.{source // 65536 % 256}.{source // 256 % 256}.{source % 256}', 30000 + index % 1000,
        '192.0.2.100', 8000 + index % 128, 'tcp', EventType.CONNECTION_ACCEPTED,
        event_id=f'fixed-{index}', timestamp=datetime.fromtimestamp(1700000000 + (index / 1000 if stamp is None else stamp), timezone.utc),
        observations={'completed_handshake': True})


def payloads():
    rng = random.Random(SEED)
    return [b'GET / HTTP/1.0\r\n\r\n', b'SYST\r\n', b'SSH-2.0-Client\r\n',
            bytes(rng.randrange(256) for _ in range(256))]
