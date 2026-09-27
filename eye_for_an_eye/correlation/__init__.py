"""Bounded same-flow counts, without cross-address identity inference."""
from ..event_types import EventType
from ..enrichment.cache import TTLCache


class FlowCounter:
    def __init__(self, entries=10000, ttl=600):
        self.cache = TTLCache(entries, ttl, max_bytes=4_194_304)

    def observe(self, event):
        if event.transport not in ('tcp', 'udp') or event.event_type not in (EventType.CONNECTION_ACCEPTED, EventType.SERVICE_PROBE, EventType.PACKET_OBSERVED):
            return
        key = (event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.transport)
        count = min(self.cache.get(key, 0) + 1, 2**31 - 1)
        self.cache.set(key, count)
        event.observations['same_flow_events_seen'] = count
