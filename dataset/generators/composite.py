"""Behaviour built by combining primitives, for measuring generalisation.

Every family here is a **new composition of primitives that already exist
elsewhere in this package**, not a renamed copy of an existing generator (§46,
§47). That is the whole point: a system that has learned
"traffic shaped like `scan/sequential/50-ports`" has memorised a generator, and
a system that has learned "many distinct ports, in order, sustained" has learned
something that will still be true of a tool nobody has written yet. Only a
family assembled from familiar parts in an unfamiliar arrangement can tell the
two apart.

So each generator below states, in its docstring, which primitives it combines
and which it deliberately withholds. A reader should be able to predict what
evidence families ought to react before running anything — and where that
prediction is wrong, the prediction or the engine is at fault, never the label.

The hard negatives matter at least as much as the positives (§48). Three of the
six families here are benign behaviours that compose the *same* primitives as
the malicious ones: sustained volume, address breadth, credential-shaped
requests. Generalisation is not only detecting an attack nobody demonstrated; it
is also not blocking a legitimate client nobody demonstrated.

Nothing here contains a credential, secret, token or command from any real
system, and nothing is sent anywhere. Same rules as every other generator.
"""
from ..safety import SafetyLimits
from . import timing
from .base import (Contact, Plan, REQUESTS, SENSOR_ADDRESSES, SERVICE_PORTS,
                   pick_destination, rng, source_address)
from .deception import DECOY_PORTS

COMPOSITE_LIMITS = SafetyLimits(max_duration_seconds=300, max_connections=900,
                                max_packets=9000, max_bytes=2_097_152,
                                max_destinations=16)


def _plan(scenario_id, group, seed, contacts, parameters, *, label, kind):
    stream = rng(seed + ':source')
    return Plan(scenario_id=scenario_id, scenario_group=group, label=label,
                label_source='controlled_scenario', label_confidence='HIGH', seed=seed,
                source=source_address(stream), contacts=contacts, parameters=parameters,
                limits=COMPOSITE_LIMITS, kind=kind, ingestion='pcap')


def _malicious(scenario_id, group, seed, contacts, parameters):
    return _plan(scenario_id, group, seed, contacts, parameters,
                 label='malicious_automation_like', kind='malicious_automation')


def _benign(scenario_id, group, seed, contacts, parameters):
    return _plan(scenario_id, group, seed, contacts, parameters,
                 label='benign_like', kind='benign')


# --- malicious compositions -------------------------------------------------


def paced_breadth_sweep(scenario_id, group, seed, *, port_count=22, delay=6.0,
                        destinations=3):
    """Slow pacing + wide port breadth + several addresses, all at once.

    Combines: the patient pacing of `scanner.slow_scan`, the port breadth of
    `scanner.randomized_scan`, and the address breadth of
    `scanner.horizontal_scan`. Withholds: rate, sequence, payload.

    Should react on PORT_BREADTH (ports and addresses) and PERSISTENCE. Should
    **not** react on NETWORK_RATE — that is the point. A detector that needs
    rate will miss this, and one that reasons from breadth and persistence will
    not.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    ports = stream.sample(SERVICE_PORTS, k=min(port_count, len(SERVICE_PORTS)))
    ports += [stream.randrange(1024, 49151) for _ in range(port_count - len(ports))]
    stream.shuffle(ports)
    moments = timing.paced(stream, len(ports), delay)
    contacts = [Contact(moment, targets[index % len(targets)], port,
                        'syn_only' if stream.random() < .7 else 'syn_reset')
                for index, (port, moment) in enumerate(zip(ports, moments, strict=True))]
    return _malicious(scenario_id, group, seed, contacts,
                      {'port_count': len(ports), 'delay': delay,
                       'destinations': len(targets)})


def credential_spray(scenario_id, group, seed, *, attempts=26, period=2.2,
                     destinations=4, ports=(21, 110, 3306)):
    """Credential-shaped requests spread thin across addresses and services.

    Combines: the request shapes of `protocol.credential_automation`, the
    address breadth of `scanner.horizontal_scan`, and low rate. Withholds:
    concentration — no single address or port sees enough attempts to look like
    a brute force on its own.

    Should react on AUTH_BEHAVIOR and PORT_BREADTH together. A detector that
    counts credential attempts per destination will see nothing.

    P15.4 gave it the server's reply, for the reason
    `protocol.credential_automation` records at length: a spray is a tool being
    refused, the refusal is in the reply, and until this cycle no scenario could
    write it down. Port 22 became 110 in the same change, because SSH
    authenticates inside its transport — a `USER` line on port 22 is a shape no
    real client produces, and a corpus that has to misrepresent a protocol to
    make a signal appear is testing the wrong thing.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    contacts = []
    for index, moment in enumerate(timing.jittered(stream, attempts, period)):
        contacts.append(Contact(moment, targets[index % len(targets)],
                                ports[index % len(ports)], 'session',
                                REQUESTS[stream.choice(('ftp_user', 'auth_probe',
                                                        'login_probe'))],
                                follow_ups=stream.randrange(0, 2), auth='failure'))
    return _malicious(scenario_id, group, seed, contacts,
                      {'attempts': attempts, 'period': period,
                       'destinations': len(targets),
                       'authentication': 'failure_every_attempt',
                       'credential_content_stored': False})


def decoy_then_enumerate(scenario_id, group, seed, *, decoy_touches=6,
                         port_count=12, period=1.4):
    """Probe a decoy first, then work through real services.

    Combines: the decoy interaction of `deception.decoy_enumeration` and the
    port walk of `scanner.randomized_scan`, in sequence rather than in parallel.
    Withholds: sustained decoy interaction — the decoy phase is short, so a
    detector leaning on decoy contact alone gets a weak signal and has to use
    the breadth that follows.

    Should react on DECEPTION_INTERACTION *and* PORT_BREADTH. This is the
    composition test: two families that the corpus has only ever shown
    separately.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts, moment = [], 0.0
    for index in range(decoy_touches):
        port = DECOY_PORTS[index % len(DECOY_PORTS)]
        contacts.append(Contact(moment, destination, port, 'handshake',
                                command='CONNECT', family=stream.choice(('ftp', 'ssh'))))
        moment += stream.uniform(.4, 1.2)
    ports = stream.sample(SERVICE_PORTS, k=min(port_count, len(SERVICE_PORTS)))
    for port, offset in zip(ports, timing.jittered(stream, len(ports), period), strict=True):
        contacts.append(Contact(moment + offset, destination, port,
                                'syn_only' if stream.random() < .5 else 'handshake'))
    return _malicious(scenario_id, group, seed, contacts,
                      {'decoy_touches': decoy_touches, 'port_count': len(ports)})


# --- benign compositions, which use the same primitives ---------------------


def backup_client(scenario_id, group, seed, *, transfers=70, period=1.1, port=445):
    """HARD NEGATIVE. Sustained high volume to one service, completing everything.

    Combines: the volume of a scanner and the completion of an ordinary client.
    Withholds: breadth. One port, one address, every exchange finished.

    Should react on NETWORK_RATE and PERSISTENCE and nothing else. This is the
    control for the `connections_60s` term P15.3 added — if rate alone can block,
    this family is what it blocks.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, port, 'exchange',
                        REQUESTS['http_api'], follow_ups=stream.randrange(1, 3))
                for moment in timing.steady(stream, transfers, period)]
    return _benign(scenario_id, group, seed, contacts,
                   {'transfers': transfers, 'period': period, 'port': port})


def content_crawler(scenario_id, group, seed, *, requests=46, period=1.6,
                    destinations=3, ports=(80, 443)):
    """HARD NEGATIVE. A polite crawler: many requests, several addresses, one service.

    Combines: the address breadth of `scanner.horizontal_scan` with the request
    shapes and completion of `benign.web_client`. Withholds: port breadth and
    protocol oddity.

    Should react on PORT_BREADTH through addresses, and on NETWORK_RATE. It is
    the control for the destination-breadth re-normalisation P15.3 added: a
    crawler legitimately touches several addresses of the same site.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    contacts = []
    for index, moment in enumerate(timing.human(stream, requests, period)):
        contacts.append(Contact(moment, targets[index % len(targets)],
                                ports[index % len(ports)], 'exchange',
                                REQUESTS[stream.choice(('http_get', 'http_head'))],
                                follow_ups=stream.randrange(0, 2)))
    return _benign(scenario_id, group, seed, contacts,
                   {'requests': requests, 'period': period,
                    'destinations': len(targets)})


def batch_api_client(scenario_id, group, seed, *, bursts=5, burst_size=11,
                     inside=.2, pause=18.0, port=8443):
    """HARD NEGATIVE. Authenticated batch jobs: bursts of credential-shaped calls.

    Combines: the burst timing of `scanner.burst_scan` with the credential
    shapes of `protocol.credential_automation`, on one legitimate service.
    Withholds: breadth and failure — every call completes against a service that
    expects it.

    Should react on AUTH_BEHAVIOR and NETWORK_RATE. It is the control for the
    credential term: a real API client authenticates constantly, and if
    credential shapes alone can block, this family is what it blocks.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, port, 'session',
                        REQUESTS[stream.choice(('ftp_user', 'auth_probe'))],
                        follow_ups=1)
                for moment in timing.bursty(stream, bursts, burst_size, inside, pause)]
    return _benign(scenario_id, group, seed, contacts,
                   {'bursts': bursts, 'burst_size': burst_size, 'port': port,
                    'credential_content_stored': False})
