"""Protocol-level malicious-automation behaviour: mismatch, repeated probes, credential attempts.

No brute force against any real service, no real credential and no password anywhere. The
credential-like requests are synthetic strings whose only purpose is to exercise the
deterministic `credential_like_attempt` detector; the dataset stores a count, never content.
"""
from ..safety import SafetyLimits
from . import timing
from .base import Contact, Plan, REQUESTS, SERVICE_PORTS, pick_destination, rng, source_address

PROTOCOL_LIMITS = SafetyLimits(max_duration_seconds=300, max_connections=800, max_packets=6000,
                               max_bytes=1_048_576, max_destinations=8)
CREDENTIAL_BODIES = ('ftp_user', 'auth_probe', 'login_probe')


def _plan(scenario_id, group, seed, contacts, parameters, kind='malicious_automation'):
    stream = rng(seed + ':source')
    return Plan(scenario_id=scenario_id, scenario_group=group, label='malicious_automation_like',
                label_source='controlled_scenario', label_confidence='HIGH', seed=seed,
                source=source_address(stream), contacts=contacts, parameters=parameters,
                limits=PROTOCOL_LIMITS, kind=kind, ingestion='pcap')


def protocol_mismatch(scenario_id, group, seed, *, attempts=26, period=.6):
    """HTTP-shaped requests to non-HTTP ports, binary probes, malformed request lines."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    bodies = ('http_broken', 'http_binary', 'redis_probe', 'binary_probe', 'generic_probe',
              'http_head', 'ftp_feat')
    contacts = [Contact(moment, destination, stream.choice(SERVICE_PORTS),
                        stream.choice(('exchange', 'exchange', 'request', 'retry_then_request')),
                        REQUESTS[stream.choice(bodies)])
                for moment in timing.jittered(stream, attempts, period)]
    return _plan(scenario_id, group, seed, contacts, {'attempts': attempts, 'period': period})


def repeated_probes(scenario_id, group, seed, *, attempts=40, period=.5, ports=(80, 443, 8080, 22)):
    """The same probe, over and over. Deliberately close to a monitoring agent."""
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    body = REQUESTS[stream.choice(('http_get', 'http_head', 'http_metrics', 'ssh_banner', 'generic_probe'))]
    contacts = []
    for moment in timing.jittered(stream, attempts, period, .25):
        shape = 'syn_only' if stream.random() < .1 else 'exchange'
        contacts.append(Contact(moment, destination, stream.choice(ports), shape,
                                b'' if shape == 'syn_only' else body))
    return _plan(scenario_id, group, seed, contacts, {'attempts': attempts, 'period': period})


def credential_automation(scenario_id, group, seed, *, attempts=30, period=.8, port=21):
    """Repeated login-shaped requests. Synthetic strings only; no password is generated.

    **P15.4 gave this family the server's reply, which it always implied.** It is
    credential automation: a tool guessing, which means a tool being refused.
    Before P15.4 no scenario could say so, and the only thing distinguishing this
    from a scripted FTP client was that it carried credentials — the quantity
    P15.3 proved says nothing. Under `math-risk-v4` it therefore scored a median
    of 0.000, and the leave-one-scenario-out analysis is where that showed up.

    Two readings were available and only one is honest. Either the label is not
    supportable from what the sensor sees, or the corpus could not express the
    evidence that supports it. It is the second: a guessing tool is refused, the
    refusal is right there in the reply, and the generator predates the ability
    to write it down. Adding it completes the behaviour rather than adjusting
    anything about the engine.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, port, 'session', REQUESTS[stream.choice(CREDENTIAL_BODIES)],
                        follow_ups=stream.randrange(0, 2), auth='failure')
                for moment in timing.jittered(stream, attempts, period)]
    return _plan(scenario_id, group, seed, contacts,
                 {'attempts': attempts, 'period': period, 'port': port,
                  'authentication': 'failure_every_attempt', 'credential_content_stored': False})


def low_rate_credentials(scenario_id, group, seed, *, attempts=12, period=11.0, port=110):
    """HARD POSITIVE. The same idea, slow enough to hide under a rate threshold.

    Refused every time, for the same reason as `credential_automation`, and moved
    from port 22 to 110 for a reason that is not cosmetic: SSH authenticates
    inside its transport, so a passive sensor sees no account name and no
    outcome, and a scenario that pretended otherwise would be testing the engine
    against traffic no real client produces. POP3 is cleartext, uses the same
    `USER`/`PASS` exchange the payload already contains, and is a service that
    really is attacked this way.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, port, 'exchange',
                        REQUESTS[stream.choice(CREDENTIAL_BODIES)], auth='failure')
                for moment in timing.paced(stream, attempts, period)]
    return _plan(scenario_id, group, seed, contacts,
                 {'attempts': attempts, 'period': period, 'port': port,
                  'authentication': 'failure_every_attempt'}, 'hard_positive')
