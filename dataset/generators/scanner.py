"""Controlled reconnaissance behaviour. No exploitation, no payload beyond a probe string.

Port ranges deliberately overlap the ports benign scenarios use, so a port alone can never
separate the classes.
"""
from ..safety import SafetyLimits
from . import timing
from .base import Contact, Plan, REQUESTS, SENSOR_ADDRESSES, SERVICE_PORTS, pick_destination, rng, source_address

SCAN_LIMITS = SafetyLimits(max_duration_seconds=300, max_connections=1200, max_packets=8000,
                           max_bytes=1_048_576, max_destinations=16)
# Deliberately overlapping the bodies benign scenarios send, so payload size cannot
# identify the class on its own.
PROBE_BODIES = ('http_get', 'http_head', 'http_status', 'ssh_banner', 'ftp_feat', 'redis_probe',
                'binary_probe', 'generic_probe')


def _plan(scenario_id, group, seed, contacts, parameters, kind='malicious_automation', ingestion='pcap'):
    stream = rng(seed + ':source')
    return Plan(scenario_id=scenario_id, scenario_group=group, label='malicious_automation_like',
                label_source='controlled_scenario', label_confidence='HIGH', seed=seed,
                source=source_address(stream), contacts=contacts, parameters=parameters,
                limits=SCAN_LIMITS, kind=kind, ingestion=ingestion)


def connect_scan(scenario_id, group, seed, *, port_count=40, period=.6, order='sequential'):
    """A connect scan: complete the handshake, send nothing, close. No payload is observed."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    ports = _ports(stream, port_count, order)
    contacts = [Contact(moment, destination, port, 'connect_only')
                for port, moment in zip(ports, timing.jittered(stream, port_count, period), strict=True)]
    return _plan(scenario_id, group, seed, contacts,
                 {'port_count': port_count, 'period': period, 'order': order},
                 'malicious_automation', 'event')


def _ports(stream, count, order='sequential', start=None):
    """Ranges start low enough to include the ordinary service ports benign traffic uses."""
    base = start if start is not None else stream.choice([1, 20, 80, 400, 3300])
    ports = [min(65535, base + index) for index in range(count)]
    if order == 'random':
        # Mix in real service ports so the scan is not a clean arithmetic sequence.
        ports = stream.sample(range(1, 10000), k=count - min(4, count)) + list(
            stream.sample(SERVICE_PORTS, k=min(4, count)))
        stream.shuffle(ports)
    return ports


def sequential_scan(scenario_id, group, seed, *, port_count=50, period=.18, start=None):
    """Ports in order, one connection each, mostly unanswered."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    ports = _ports(stream, port_count, 'sequential', start)
    contacts = [Contact(moment, destination, port, 'syn_only' if stream.random() < .7 else 'syn_reset')
                for port, moment in zip(ports, timing.jittered(stream, port_count, period), strict=True)]
    return _plan(scenario_id, group, seed, contacts, {'port_count': port_count, 'period': period,
                                                      'order': 'sequential', 'start': ports[0]})


def randomized_scan(scenario_id, group, seed, *, port_count=50, period=.2):
    """Same breadth, no ordering signal, so sequential-order features cannot carry the model."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    ports = _ports(stream, port_count, 'random')
    contacts = [Contact(moment, destination, port, 'syn_only' if stream.random() < .65 else 'syn_reset')
                for port, moment in zip(ports, timing.jittered(stream, port_count, period), strict=True)]
    return _plan(scenario_id, group, seed, contacts, {'port_count': port_count, 'period': period,
                                                      'order': 'random'})


def horizontal_scan(scenario_id, group, seed, *, destinations=6, port=445, period=.3):
    """One service, several sensor addresses."""
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    times = timing.jittered(stream, len(targets) * 4, period)
    contacts = [Contact(moment, targets[index % len(targets)], port, 'syn_only')
                for index, moment in enumerate(times)]
    return _plan(scenario_id, group, seed, contacts, {'destinations': len(targets), 'port': port})


def slow_scan(scenario_id, group, seed, *, port_count=14, delay=9.0, order='sequential'):
    """HARD POSITIVE. Quiet and patient. Rate alone must not decide the label."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    ports = _ports(stream, port_count, order)
    contacts = [Contact(moment, destination, port, 'syn_only' if stream.random() < .6 else 'syn_reset')
                for port, moment in zip(ports, timing.paced(stream, port_count, delay), strict=True)]
    return _plan(scenario_id, group, seed, contacts,
                 {'port_count': port_count, 'delay': delay, 'order': order}, 'hard_positive')


def burst_scan(scenario_id, group, seed, *, bursts=4, burst_size=9, inside=.25, pause=40.0):
    """HARD POSITIVE. Burst, long pause, burst; each burst alone looks small."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    times = timing.bursty(stream, bursts, burst_size, inside, pause)
    ports = _ports(stream, len(times), 'random')
    contacts = [Contact(moment, destination, port, 'syn_only')
                for port, moment in zip(ports, times, strict=True)]
    return _plan(scenario_id, group, seed, contacts,
                 {'bursts': bursts, 'burst_size': burst_size, 'pause': pause}, 'hard_positive')


def service_enumeration(scenario_id, group, seed, *, rounds=4, period=.7):
    """Repeated probes across services, with probe diversity and response continuation."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    ports = list(SERVICE_PORTS)
    stream.shuffle(ports)
    contacts, moment = [], 0.0
    for _ in range(rounds):
        for port in ports:
            body = REQUESTS[stream.choice(PROBE_BODIES)]
            shape = stream.choice(('session', 'session', 'exchange', 'request', 'retry_then_request'))
            contacts.append(Contact(moment, destination, port, shape, body,
                                    follow_ups=stream.randrange(0, 3) if shape == 'session' else 0))
            moment += max(.05, period * stream.uniform(.5, 1.5))
    return _plan(scenario_id, group, seed, contacts, {'rounds': rounds, 'ports': len(ports)})


def multi_stage_recon(scenario_id, group, seed, *, sweep=24, probes=10, period=.4):
    """Port exploration, then service probes, then a targeted protocol request. No exploitation."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = []
    ports = _ports(stream, sweep, 'sequential')
    for port, moment in zip(ports, timing.jittered(stream, sweep, period), strict=True):
        contacts.append(Contact(moment, destination, port,
                                'retry_then_request' if stream.random() < .12 else 'syn_only',
                                REQUESTS['http_head'] if stream.random() < .12 else b''))
    moment = contacts[-1].time + 6.0
    open_ports = stream.sample(SERVICE_PORTS, k=min(5, len(SERVICE_PORTS)))
    for index in range(probes):
        port = open_ports[index % len(open_ports)]
        contacts.append(Contact(moment, destination, port, 'exchange', REQUESTS[stream.choice(PROBE_BODIES)]))
        moment += max(.1, period * stream.uniform(1.0, 3.0))
    for index in range(4):
        contacts.append(Contact(moment, destination, open_ports[0], 'session', REQUESTS['http_api'],
                                follow_ups=2))
        moment += stream.uniform(.6, 2.2)
        _ = index
    return _plan(scenario_id, group, seed, contacts, {'sweep': sweep, 'probes': probes})
