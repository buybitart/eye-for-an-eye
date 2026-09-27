"""Controlled benign behaviour, including hard negatives that look hostile."""
from ..safety import SafetyLimits
from . import timing
from .base import Contact, Plan, REQUESTS, SERVICE_PORTS, pick_destination, rng, source_address

BENIGN_LIMITS = SafetyLimits(max_duration_seconds=180, max_connections=600, max_packets=6000,
                             max_bytes=1_048_576, max_destinations=8)


def _plan(scenario_id, group, seed, contacts, parameters, kind='benign', ingestion='pcap'):
    stream = rng(seed + ':source')
    return Plan(scenario_id=scenario_id, scenario_group=group, label='benign_like',
                label_source='controlled_scenario', label_confidence='HIGH', seed=seed,
                source=source_address(stream), contacts=contacts, parameters=parameters,
                limits=BENIGN_LIMITS, kind=kind, ingestion=ingestion)


def connect_probe(scenario_id, group, seed, *, checks=40, period=2.0, port_count=3):
    """HARD NEGATIVE. TCP-connect health checks: open, confirm, close, never send a byte.

    The sensor sees a connection and no payload at all, so payload-derived features are
    missing rather than zero. Both label classes have a connect-only scenario.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    ports = stream.sample(SERVICE_PORTS, k=min(port_count, len(SERVICE_PORTS)))
    contacts = [Contact(moment, destination, stream.choice(ports), 'connect_only')
                for moment in timing.steady(stream, checks, period, .08)]
    return _plan(scenario_id, group, seed, contacts, {'checks': checks, 'period': period,
                                                      'ports': len(ports)}, 'hard_negative', 'event')


def web_client(scenario_id, group, seed, *, requests=14, period=1.1, follow_ups=2, ports=(80, 443, 8080)):
    """Ordinary browsing: a few pages, keepalive follow-ups, occasional idle."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = []
    for moment in timing.human(stream, requests, period):
        body = stream.choice(['http_get', 'http_get', 'http_api', 'http_status'])
        contacts.append(Contact(moment, destination, stream.choice(ports), 'session',
                                REQUESTS[body], follow_ups=stream.randrange(0, follow_ups + 1)))
    return _plan(scenario_id, group, seed, contacts,
                 {'requests': requests, 'period': period, 'ports': list(ports)})


def web_burst(scenario_id, group, seed, *, bursts=3, burst_size=8, ports=(80, 443, 8080)):
    """A page load is a burst of connections. High short-term rate, benign."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, stream.choice(ports), 'exchange', REQUESTS['http_get'])
                for moment in timing.bursty(stream, bursts, burst_size, .12, 9.0)]
    return _plan(scenario_id, group, seed, contacts, {'bursts': bursts, 'burst_size': burst_size})


def ssh_session(scenario_id, group, seed, *, sessions=4, period=12.0):
    """Short interactive sessions: connect, banner, a little traffic, disconnect."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, 22, 'session', REQUESTS['ssh_banner'],
                        follow_ups=stream.randrange(1, 4))
                for moment in timing.human(stream, sessions, period)]
    return _plan(scenario_id, group, seed, contacts, {'sessions': sessions, 'period': period})


def retry_then_success(scenario_id, group, seed, *, attempts=10, period=2.0, ports=(80, 443)):
    """A flaky link: failed connection, retry, backoff, success. Retry is not hostility."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = []
    for moment in timing.jittered(stream, attempts, period):
        port = stream.choice(ports)
        roll = stream.random()
        if roll < .3:
            contacts.append(Contact(moment, destination, port, 'retry_then_request', REQUESTS['http_get']))
        elif roll < .45:
            contacts.append(Contact(moment, destination, port, 'syn_reset'))
        else:
            contacts.append(Contact(moment, destination, port, 'exchange', REQUESTS['http_get']))
    return _plan(scenario_id, group, seed, contacts, {'attempts': attempts, 'period': period})


def ambient_noise(scenario_id, group, seed, *, contacts_count=8, period=7.0):
    """Low-intensity ambiguous traffic: a few failures, an odd port, one malformed request.

    Labelled benign only because the scenario is deliberately benign; ambiguous real traffic
    is never auto-labelled this way.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = []
    for index, moment in enumerate(timing.jittered(stream, contacts_count, period)):
        port = stream.choice(SERVICE_PORTS)
        if index == contacts_count // 2:
            contacts.append(Contact(moment, destination, port, 'request', REQUESTS['http_broken']))
        elif stream.random() < .25:
            contacts.append(Contact(moment, destination, port, 'syn_reset'))
        elif stream.random() < .3:
            # A filtered port drops the SYN silently. Benign clients meet those too.
            contacts.append(Contact(moment, destination, port, 'syn_only'))
        else:
            contacts.append(Contact(moment, destination, port, 'exchange',
                                    REQUESTS[stream.choice(('http_get', 'redis_probe', 'generic_probe'))]))
    return _plan(scenario_id, group, seed, contacts, {'contacts': contacts_count, 'period': period})


def monitoring_agent(scenario_id, group, seed, *, checks=40, period=3.0, ports=(9100, 9090)):
    """HARD NEGATIVE. Very regular timing and an identical repeated request."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    bodies = ('http_metrics', 'http_metrics', 'http_metrics', 'generic_probe', 'binary_probe')
    contacts = [Contact(moment, destination, stream.choice(ports), 'exchange',
                        REQUESTS[stream.choice(bodies)])
                for moment in timing.steady(stream, checks, period)]
    return _plan(scenario_id, group, seed, contacts, {'checks': checks, 'period': period}, 'hard_negative')


def health_checker(scenario_id, group, seed, *, checks=90, period=.8, ports=(8080, 8443)):
    """HARD NEGATIVE. High rate, few ports, short-lived connections, perfectly periodic."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, stream.choice(ports), 'exchange', REQUESTS['http_head'])
                for moment in timing.steady(stream, checks, period)]
    return _plan(scenario_id, group, seed, contacts, {'checks': checks, 'period': period}, 'hard_negative')


def admin_diagnostic(scenario_id, group, seed, *, port_count=5, period=2.5):
    """HARD NEGATIVE. An administrator checking several services by hand. Scan-shaped."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    ports = stream.sample(SERVICE_PORTS, k=min(port_count, len(SERVICE_PORTS)))
    contacts = []
    for port, moment in zip(ports, timing.human(stream, len(ports), period), strict=True):
        body = 'ssh_banner' if port == 22 else 'ftp_feat' if port == 21 else stream.choice(
            ('http_get', 'redis_probe', 'binary_probe'))
        shape = stream.choice(['exchange', 'request', 'syn_reset', 'syn_only', 'retry_then_request'])
        contacts.append(Contact(moment, destination, port, shape,
                                b'' if shape in ('syn_reset', 'syn_only') else REQUESTS[body]))
    return _plan(scenario_id, group, seed, contacts, {'port_count': port_count, 'period': period},
                 'hard_negative')


def service_discovery(scenario_id, group, seed, *, rounds=6, period=6.0, port_count=6):
    """HARD NEGATIVE. Legitimate internal discovery revisiting several ports repeatedly."""
    stream = rng(seed)
    destinations = pick_destination(stream, 2)
    ports = stream.sample(SERVICE_PORTS, k=min(port_count, len(SERVICE_PORTS)))
    contacts = []
    moment = 0.0
    for _ in range(rounds):
        for port in ports:
            body = stream.choice(('http_status', 'redis_probe', 'generic_probe', 'binary_probe'))
            shape = 'syn_only' if stream.random() < .15 else 'exchange'
            contacts.append(Contact(moment, stream.choice(destinations), port, shape,
                                    b'' if shape == 'syn_only' else REQUESTS[body]))
            moment += max(.05, period / max(1, len(ports)) * stream.uniform(.6, 1.4))
    return _plan(scenario_id, group, seed, contacts, {'rounds': rounds, 'ports': len(ports)}, 'hard_negative')
