"""Decoy interaction behaviour, rendered as events rather than packets.

A deception session is produced by the honeypot listener, not by the packet capture path, so
these scenarios are the one part of the corpus that enters the pipeline as NetworkEvents. The
correlation engine, the windowing and the feature extraction are still production code.

Both label classes appear here on purpose: if only hostile sources ever touched a decoy, the
`deception_60s` column would be a perfect label shortcut instead of a behavioural signal.
"""
from ..safety import SafetyLimits
from . import timing
from .base import Contact, Plan, rng, source_address

DECEPTION_LIMITS = SafetyLimits(max_duration_seconds=300, max_connections=400, max_packets=4000,
                                max_bytes=524_288, max_destinations=8)
DECOY_PORTS = (23, 2323, 21, 2121, 3306, 6379)
COMMANDS = ('GREETING', 'BANNER', 'LIST', 'INFO', 'STAT', 'VERSION', 'HELP')
FAMILIES = ('telnet', 'ftp', 'redis', 'mysql')


def _plan(scenario_id, group, seed, contacts, parameters, label, kind):
    stream = rng(seed + ':source')
    return Plan(scenario_id=scenario_id, scenario_group=group, label=label,
                label_source='controlled_scenario', label_confidence='HIGH', seed=seed,
                source=source_address(stream), contacts=contacts, parameters=parameters,
                limits=DECEPTION_LIMITS, kind=kind, ingestion='event')


def decoy_enumeration(scenario_id, group, seed, *, sessions=10, commands=5, period=2.5):
    """Connect, take the banner, keep issuing commands, move to another decoy port."""
    stream = rng(seed)
    destination = f'198.51.100.{stream.randrange(1, 9)}'
    contacts, moment = [], 0.0
    for session in range(sessions):
        port = DECOY_PORTS[session % len(DECOY_PORTS)]
        family = stream.choice(FAMILIES)
        contacts.append(Contact(moment, destination, port, 'handshake', command='CONNECT', family=family))
        moment += stream.uniform(.05, .3)
        for index in range(commands):
            contacts.append(Contact(moment, destination, port, 'request', b'',
                                    command=stream.choice(COMMANDS),
                                    credential=index == commands - 1 and stream.random() < .5,
                                    anomaly=stream.random() < .3, family=family))
            moment += max(.05, stream.uniform(.1, .8))
        moment += max(.2, period * stream.uniform(.6, 1.4))
    return _plan(scenario_id, group, seed, contacts,
                 {'sessions': sessions, 'commands': commands, 'period': period},
                 'malicious_automation_like', 'malicious_automation')


def decoy_brush_past(scenario_id, group, seed, *, touches=4, period=20.0):
    """HARD NEGATIVE. A legitimate client reaches a decoy port once and gives up.

    Without this, touching a decoy would predict the label perfectly and the model would
    learn our own deployment layout instead of behaviour.
    """
    stream = rng(seed)
    destination = f'198.51.100.{stream.randrange(1, 9)}'
    contacts = []
    for moment in timing.human(stream, touches, period):
        port = stream.choice(DECOY_PORTS)
        family = stream.choice(FAMILIES)
        contacts.append(Contact(moment, destination, port, 'handshake', command='CONNECT', family=family))
        if stream.random() < .6:
            contacts.append(Contact(moment + stream.uniform(.05, .4), destination, port, 'request', b'',
                                    command='GREETING', family=family))
    return _plan(scenario_id, group, seed, contacts, {'touches': touches, 'period': period},
                 'benign_like', 'hard_negative')
