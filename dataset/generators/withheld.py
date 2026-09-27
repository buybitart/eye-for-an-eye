"""Families withheld from every fitting corpus. §49, §50.

### What "withheld" means here, and why it is a module rather than a note

A generalisation claim is only worth the distance between the thing measured and
the thing fitted. P15.3 added new *compositions* and that was a real improvement,
but every one of them still appeared in a corpus somebody looked at while
choosing thresholds, and "we did not deliberately tune against it" is an
assertion about intent that nobody can check afterwards.

So these two families are withheld structurally. They live in their own module,
they are registered under a `withheld.` prefix, and
`tests/test_p15_4_withheld.py` asserts that no matrix used for training,
calibration or development contains any scenario whose generator starts with
that prefix. A person cannot accidentally fit to them, because putting them in a
fitting matrix turns the suite red. That is a claim a reader can verify by
running something, which is the only kind worth making.

They are scored exactly once, on the locked corpus, at the end (§72).

### Two pairs, one per cycle

P15.4 withheld `mobile_app_sync` and `probe_then_login`, and scored them once on
its locked benchmark. They are therefore **seen** from P15.5 onward, and calling
them unseen a second time would be the bookkeeping that makes a generalisation
claim worthless. P15.5 withholds a new pair, `backup_window_sweep` and
`credential_drift`, and the older pair stays here — same module, same prefix,
still barred from every fitting matrix — because a family that has been scored
once is still not something to fit to.

### The P15.4 pair

`mobile_app_sync` (benign) and `probe_then_login` (malicious) are not variations
of anything above. Each is a new arrangement:

    mobile_app_sync   long idle gaps + authenticated bursts + retry after a drop
                      + genuinely unobservable outcomes, all from one principal
    probe_then_login  a little port probing, then a modest number of failed
                      logins on the service that answered

`probe_then_login` is the compositional-risk case in its purest form (§27).
Neither half is remarkable: six ports is a small sweep, nine failures is a small
number of failures, and a system that scores each family separately and adds
them up will find nothing. Only the co-occurrence — the same source doing both,
in that order, within one window — means anything. Since the interaction terms
are frozen before this family is ever scored, whatever it produces is a
measurement of the interaction design rather than a demonstration of it.

`mobile_app_sync` is its control, and it is the one that will hurt if the
interaction term is too strong: an app that wakes, retries a dropped connection,
and authenticates on several endpoints produces a thin version of the same
co-occurrence with none of the intent.

Same rules as every other generator: no credential, secret, token or command
from any real system, no password generated, nothing transmitted.
"""
from ..safety import SafetyLimits
from . import timing
from .base import (Contact, LAB_PRINCIPALS, Plan, REQUESTS, SENSOR_ADDRESSES, SERVICE_PORTS,
                   pick_destination, rng, source_address, user_command)

WITHHELD_LIMITS = SafetyLimits(max_duration_seconds=600, max_connections=600,
                               max_packets=6000, max_bytes=1_048_576,
                               max_destinations=12)

#: Every generator in this module is registered under this prefix, and the
#: withholding test reads it rather than a hand-kept list, so a family added here
#: later is withheld by construction instead of by somebody remembering.
WITHHELD_PREFIX = 'withheld.'


def _plan(scenario_id, group, seed, contacts, parameters, *, label, kind):
    stream = rng(seed + ':source')
    return Plan(scenario_id=scenario_id, scenario_group=group, label=label,
                label_source='controlled_scenario', label_confidence='HIGH', seed=seed,
                source=source_address(stream), contacts=contacts, parameters=parameters,
                limits=WITHHELD_LIMITS, kind=kind, ingestion='pcap')


def mobile_app_sync(scenario_id, group, seed, *, wakes=6, calls=7, inside=.5,
                    sleep=70.0, port=8443):
    """HARD NEGATIVE, withheld. An app waking, retrying, and syncing.

    Combines: the burst structure of a page load, the long idle gaps of a paced
    sweep, the dropped-connection retry of `benign.retry_then_success`, and
    authentication on every call. Withholds: breadth and failure.

    Two thirds of the way through each wake the outcome becomes genuinely
    unobservable — the reply is a plain acknowledgement the classifier does not
    recognise — so this family also exercises the `UNKNOWN` path at volume. §7
    says `UNKNOWN` is not failure; here is a benign source that produces a great
    deal of it, which is what makes that rule testable rather than decorative.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = []
    for wake in range(wakes):
        start = wake * sleep
        moments = timing.jittered(stream, calls, inside, .5, start)
        for index, moment in enumerate(moments):
            observable = index < max(1, (2 * calls) // 3)
            shape = 'retry_then_request' if index == 0 and stream.random() < .5 else 'session'
            contacts.append(Contact(moment, destination, port, shape,
                                    REQUESTS['http_api_bearer'],
                                    follow_ups=stream.randrange(0, 2),
                                    auth='success' if observable else ''))
    return _plan(scenario_id, group, seed, contacts,
                 {'wakes': wakes, 'calls': calls, 'sleep': sleep, 'port': port,
                  'authentication': 'success_and_unobservable', 'principals': 1},
                 label='benign_like', kind='hard_negative')


def probe_then_login(scenario_id, group, seed, *, ports=6, failures=9, probe_period=2.6,
                     login_period=3.1, destinations=2):
    """HARD POSITIVE, withheld. A small sweep, then a small number of refusals.

    Combines: the port walk of a scanner and the refused logins of a spray, in
    sequence, at a size where neither half reaches anything on its own. Six ports
    is what an administrator checking services looks like; nine failed logins
    across six accounts is smaller than one person locking themselves out twice.

    The claim under test is that co-occurrence carries information the parts do
    not. If the composition engine scores this the way it scores a six-port
    probe, the interaction term is doing nothing; if it scores it like a brute
    force, the term is doing too much and `mobile_app_sync` will show the cost.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    chosen = stream.sample(SERVICE_PORTS, k=min(ports, len(SERVICE_PORTS)))
    contacts, moment = [], 0.0
    for index, offset in enumerate(timing.jittered(stream, len(chosen), probe_period)):
        contacts.append(Contact(offset, targets[index % len(targets)], chosen[index],
                                'syn_only' if stream.random() < .6 else 'handshake'))
        moment = max(moment, offset)
    names = stream.sample(LAB_PRINCIPALS, k=min(failures, len(LAB_PRINCIPALS)))
    for index, offset in enumerate(timing.jittered(stream, failures, login_period)):
        contacts.append(Contact(moment + 4.0 + offset, targets[0], 21, 'exchange',
                                user_command(names[index % len(names)]), auth='failure'))
    return _plan(scenario_id, group, seed, contacts,
                 {'ports': len(chosen), 'failures': failures, 'destinations': len(targets),
                  'authentication': 'failure_every_attempt'},
                 label='malicious_automation_like', kind='hard_positive')


# --- P15.5 ------------------------------------------------------------------
# A new pair, withheld from everything this cycle fits: development, the eight
# calibration corpora, the formula, the composition, and the thresholds.
#
# The pairing is chosen against the two interaction terms that carry the most
# strength in `composition.INTERACTIONS`:
#
#     (NETWORK_RATE, PORT_BREADTH, 0.30)   volume and breadth together
#     (AUTH_BEHAVIOR, PORT_BREADTH, 0.35)  failing to authenticate while sweeping
#
# Every corpus so far has tested those terms with a *malicious* source on one
# side and nothing much on the other. `backup_window_sweep` is the first benign
# behaviour built to produce the first conjunction honestly, and
# `credential_drift` is the first attack built to produce the second one at a
# size where neither half is remarkable. If the interaction strengths are wrong
# in either direction, this pair is where it shows.


def backup_window_sweep(scenario_id, group, seed, *, services=11, rounds=3, period=1.6,
                        gap=55.0, destinations=3):
    """HARD NEGATIVE, withheld. A nightly backup agent doing its whole job.

    Breadth and volume and regularity and persistence, all at once, from a
    source that is entirely legitimate. A backup orchestrator snapshots every
    service it protects — database, file share, mail spool, web root, cache —
    across several addresses of the same host, on a schedule, completing every
    exchange it starts, for as long as the window lasts.

    That is the `(NETWORK_RATE, PORT_BREADTH)` interaction produced by something
    with every right to produce it, and no corpus before this one contained it.
    `hard-negative-admin` touches several services but briefly and irregularly;
    `hard-negative-backup` is sustained volume to *one* service. This family is
    the conjunction, and it is the strongest benign case for the term that says
    "volume alone is a backup client and breadth alone is an administrator,
    which is why each is weak on its own and the conjunction is not".

    It authenticates, successfully, on every service it touches — because a
    backup agent has credentials for all of them. So it also carries the
    successful-authentication surface that P15.3 blocked 21 of 22 sources for.

    Withholds: failure. Nothing here is ever refused, and nothing is malformed.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    chosen = stream.sample(SERVICE_PORTS, k=min(services, len(SERVICE_PORTS)))
    principal = stream.choice(LAB_PRINCIPALS)
    contacts = []
    for round_index in range(rounds):
        start = round_index * gap
        moments = timing.jittered(stream, len(chosen), period, .3, start)
        for index, moment in enumerate(moments):
            port = chosen[index]
            # A line protocol names its principal; everything else authenticates
            # inside a request the sensor can see the shape of but not the name.
            request = (user_command(principal) if port in (21, 110)
                       else REQUESTS['http_api_bearer'])
            contacts.append(Contact(moment, targets[index % len(targets)], port,
                                    'exchange', request, follow_ups=1,
                                    auth='success'))
    return _plan(scenario_id, group, seed, contacts,
                 {'services': len(chosen), 'rounds': rounds, 'period': period,
                  'destinations': len(targets), 'principals': 1,
                  'authentication': 'success_every_attempt'},
                 label='benign_like', kind='hard_negative')


def credential_drift(scenario_id, group, seed, *, services=7, failures=8, period=4.4,
                     settle=6.0, destinations=2):
    """HARD POSITIVE, withheld. One valid credential, walked across services.

    A stolen password works somewhere. The holder does not know where else it
    works, so they try: one success on the service that accepts it, then a walk
    across the others with the same principal, refused each time.

    Every half of this is innocuous on its own and each has a benign control
    already in the corpus. One successful login is `profile-admin-console`. One
    principal failing repeatedly is `hard-negative-api/stale-credential`, which
    P15.4 measured at 0.784 and which the failure-span gate exists to protect.
    Seven services is `hard-negative-admin` on a thorough day. The attack is the
    **order**: success first, then breadth, then failures from the principal that
    just succeeded — which is a shape no misconfigured client produces, because a
    client with a working credential has no reason to go looking for more doors.

    Deliberately single-principal. Failed-principal diversity is the strongest
    authentication evidence this sensor has, and every credential family scored
    so far supplies it; this one withholds it, so whatever the composition makes
    of this family is a measurement of the port-breadth interaction rather than
    of the signal that was already known to work.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    chosen = stream.sample(SERVICE_PORTS, k=min(services, len(SERVICE_PORTS)))
    principal = stream.choice(LAB_PRINCIPALS)
    contacts = [Contact(0.0, targets[0], 21, 'exchange', user_command(principal),
                        follow_ups=1, auth='success')]
    moment = settle
    for index, offset in enumerate(timing.jittered(stream, len(chosen), period, .35)):
        port = chosen[index]
        request = (user_command(principal) if port in (21, 110)
                   else REQUESTS['http_api_bearer'])
        contacts.append(Contact(moment + offset, targets[index % len(targets)], port,
                                'exchange', request, auth='failure'))
        moment = max(moment, settle + offset)
    for offset in timing.jittered(stream, failures, period, .35):
        contacts.append(Contact(moment + settle + offset, targets[0], 21, 'exchange',
                                user_command(principal), auth='failure'))
    return _plan(scenario_id, group, seed, contacts,
                 {'services': len(chosen), 'failures': failures,
                  'destinations': len(targets), 'principals': 1,
                  'authentication': 'one_success_then_failure_everywhere'},
                 label='malicious_automation_like', kind='hard_positive')
