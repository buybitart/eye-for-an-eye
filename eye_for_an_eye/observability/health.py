"""Operational health projection; optional UI/metrics failure never disables intake."""
import time


def operational_health(snapshot, *, heartbeat, worker_alive, stopping=False, now=None):
    now = time.monotonic() if now is None else now
    live = bool(worker_alive and heartbeat and now - heartbeat < 5 and not stopping)
    components = dict(snapshot.get('health', {}).get('components', {}))
    components.setdefault('listeners', 'disabled')
    components.setdefault('correlation', 'healthy' if live else 'unavailable')
    components.setdefault('metrics', 'disabled')
    components.setdefault('api', 'disabled')
    required = ('capture', 'listeners', 'event_queue', 'correlation')
    core_failed = not live or any(components.get(name) == 'unavailable' for name in required)
    pressure = snapshot.get('queue', {})
    saturated = (pressure.get('depth', 0) >= pressure.get('max_events', 1) or
                 pressure.get('bytes', 0) >= pressure.get('max_bytes', 1))
    ready = not core_failed and not saturated
    degraded = any(value in ('degraded', 'unavailable') for value in components.values())
    return {'status': 'UNAVAILABLE' if core_failed else 'DEGRADED' if degraded else 'HEALTHY',
            'live': live, 'ready': ready,
            'components': {name: value.upper() for name, value in components.items()},
            'limitations': ['readiness_is_sensor_intake_not_optional_storage_or_api_availability']}
