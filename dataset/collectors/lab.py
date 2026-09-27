"""SOURCE A, event mode: a behaviour plan rendered as production NetworkEvents.

Used for decoy interaction, which the packet capture path cannot express because those events
are produced by the honeypot listener. The observation keys mirror what
`eye_for_an_eye.deception.engine` emits, so the correlation engine sees the same shape it
sees at runtime. Nothing is transmitted and no socket is opened.
"""
from datetime import datetime, timedelta, timezone
from eye_for_an_eye.event_types import EventType
from eye_for_an_eye.events import NetworkEvent

ORIGIN = datetime(2026, 1, 1, tzinfo=timezone.utc)


def events(plan, *, origin=ORIGIN, sensor_id='dataset-lab'):
    """Plan -> ordered NetworkEvents the correlation engine accepts."""
    produced = []
    for index, contact in enumerate(plan.contacts):
        moment = origin + timedelta(seconds=contact.time)
        base = {'profile_id': f'decoy-{contact.port}', 'profile_version': 1, 'catalogue_version': 1,
                'service_family': contact.family or 'unknown', 'connection_id': f'{index:06d}',
                'request_length': len(contact.request), 'response_length': 0,
                'duration': 0.0, 'command_class': contact.command or 'NONE', 'load_mode': 'NORMAL'}
        if contact.shape == 'connect_only':
            # Accepted, never read from. No payload key exists, so every payload-derived
            # feature is missing rather than an observed zero.
            produced.append(NetworkEvent(
                plan.source, None, contact.destination, contact.port, contact.transport,
                EventType.CONNECTION_ACCEPTED, observations={'completed_handshake': True},
                timestamp=moment, sensor_id=sensor_id, event_id=f'{plan.seed}:{index:06d}',
                limitations=['single_sensor_visibility']))
            continue
        if contact.shape == 'handshake':
            produced.append(NetworkEvent(
                plan.source, None, contact.destination, contact.port, contact.transport,
                EventType.DECEPTION_CONNECTION, observations=dict(base, completed_handshake=True),
                timestamp=moment, sensor_id=sensor_id, event_id=f'{plan.seed}:{index:06d}',
                limitations=['synthetic_service_profile', 'single_sensor_visibility']))
            continue
        produced.append(NetworkEvent(
            plan.source, None, contact.destination, contact.port, contact.transport,
            EventType.PROTOCOL_COMMAND,
            observations=dict(base, credential_like_attempt=contact.credential,
                              protocol_anomaly=contact.anomaly,
                              response_continuation=index > 0,
                              protocol_family=contact.family or 'unknown'),
            timestamp=moment, sensor_id=sensor_id, event_id=f'{plan.seed}:{index:06d}',
            limitations=['synthetic_service_profile', 'single_sensor_visibility']))
    produced.sort(key=lambda event: (event.timestamp, event.event_id))
    return produced, {'packets': 0, 'parse_errors': 0, 'events': len(produced), 'transmitted_packets': 0}
