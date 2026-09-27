"""Behaviour that only makes sense once authentication has an outcome. §15, §16, §43, §44.

### Why this module exists separately

Every other generator in this package can describe what a client *did*: which
ports, how fast, how patiently, with what payload shape. None of them can
describe whether the server said yes or no, because until P15.4 nothing
downstream could read the answer. The consequence was not academic. `MathRisk`
carried a weight-3.0 term for credential *presence*, and on the P15.3 locked
benchmark it blocked 21 of 22 sources of a legitimate authenticated batch API
client — a family that does nothing wrong except authenticate successfully on
every request, which is the normal case for machine-to-machine traffic.

A corpus that cannot express `530 Login incorrect` cannot distinguish those two
clients either, so it could not have found that defect and cannot demonstrate
the fix. That is what these families are for.

### The pairs

The module is organised as *pairs*, and the pairing is the whole argument. For
each site profile there is at least one benign family and one malicious family
that present the same surface evidence and differ only in outcome:

    api        authenticated batch  (every attempt SUCCESS, high rate)
               token rotation       (a few FAILURE, one principal, then SUCCESS)
               vs api spray         (many FAILURE, many principals, low rate)

    admin      login mistakes       (3 FAILURE, one principal, then SUCCESS)
               vs admin brute force (many FAILURE, many principals, fast)

    public     asset fetch          (no authentication at all, very high rate)
               vs login stuffing    (many FAILURE over HTTP, moderate rate)

    webhook    signed callback      (SIGNATURE mechanism, every attempt SUCCESS)

A system that reacts to credential presence cannot separate any of these pairs.
A system that reacts to *failure accumulated across principals* separates all of
them, and the pairs are what measure that claim rather than assert it.

### One deliberate asymmetry

`decision/auth.py` derives a principal pseudonym only from the plainly
non-secret identifier of a cleartext command (`USER <name>`), never from an
`Authorization` header, because that value is a live secret. So the HTTP
families below contribute failure *counts* and no principal diversity, and the
line-protocol families contribute both. That is a real limitation of a passive
sensor and it is represented here rather than papered over: `login_stuffing` is
the harder positive precisely because the sensor cannot see how many accounts it
is walking through.

### The usual rules

Nothing here contains a credential, secret, token, cookie or command from any
real system. Account names are meaningless words from `base.LAB_PRINCIPALS` with
a `lab-` prefix, the `Authorization` values are fixed literals that say they are
placeholders, and no password is generated anywhere. Nothing is transmitted.
"""
from ..safety import SafetyLimits
from . import timing
from .base import (Contact, LAB_PRINCIPALS, Plan, REQUESTS, SENSOR_ADDRESSES,
                   pick_destination, rng, source_address, user_command)

PROFILE_LIMITS = SafetyLimits(max_duration_seconds=600, max_connections=900,
                              max_packets=9000, max_bytes=2_097_152,
                              max_destinations=16)

#: Ports by what the traffic is, not by what the site is called. A site profile
#: is declared in the scenario matrix (§41); these are just the services the
#: behaviour plausibly touches.
WEB_PORTS = (80, 443)
API_PORTS = (8443, 8080)
ADMIN_PORTS = (443, 8443)
#: Cleartext line protocols, which is where a passive sensor can see an account
#: name at all. Not 22: SSH authenticates inside the transport, so a `USER` line
#: on port 22 would be a shape no real client produces, and a corpus that has to
#: misrepresent a protocol to make a signal appear is testing the wrong thing.
LINE_PORTS = (21, 110)


def _plan(scenario_id, group, seed, contacts, parameters, *, label, kind):
    stream = rng(seed + ':source')
    return Plan(scenario_id=scenario_id, scenario_group=group, label=label,
                label_source='controlled_scenario', label_confidence='HIGH', seed=seed,
                source=source_address(stream), contacts=contacts, parameters=parameters,
                limits=PROFILE_LIMITS, kind=kind, ingestion='pcap')


def _benign(scenario_id, group, seed, contacts, parameters, kind='hard_negative'):
    return _plan(scenario_id, group, seed, contacts, parameters,
                 label='benign_like', kind=kind)


def _malicious(scenario_id, group, seed, contacts, parameters, kind='malicious_automation'):
    return _plan(scenario_id, group, seed, contacts, parameters,
                 label='malicious_automation_like', kind=kind)


def _principals(stream, count):
    """Distinct synthetic account names, sampled without replacement."""
    if count <= len(LAB_PRINCIPALS):
        return stream.sample(LAB_PRINCIPALS, k=count)
    names = list(LAB_PRINCIPALS)
    stream.shuffle(names)
    return [f'{names[index % len(names)]}{index // len(names)}' for index in range(count)]


# --- benign: api ------------------------------------------------------------


def authenticated_batch(scenario_id, group, seed, *, bursts=6, burst_size=14,
                        inside=.18, pause=14.0, port=8443):
    """HARD NEGATIVE, api. §15's permanent regression test, in corpus form.

    A batch job holding a service token: bursts of API calls, a bearer credential
    on every single request, machine-regular timing, and the server accepting all
    of them. This is the family P15.3 blocked 21 of 22 times.

    Expected to react on NETWORK_RATE and on nothing else. AUTH_BEHAVIOR must
    stay silent, because §5 says a successful authenticated request may not
    increase credential-abuse evidence merely because authentication occurred.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, port, 'session', REQUESTS['http_api_bearer'],
                        follow_ups=1, auth='success')
                for moment in timing.bursty(stream, bursts, burst_size, inside, pause)]
    return _benign(scenario_id, group, seed, contacts,
                   {'bursts': bursts, 'burst_size': burst_size, 'port': port,
                    'authentication': 'success_every_request',
                    'credential_content_stored': False})


def high_rate_api(scenario_id, group, seed, *, calls=120, period=.55, ports=API_PORTS):
    """HARD NEGATIVE, api. Sustained authenticated volume with no burst structure.

    The rate control. `authenticated_batch` is bursty and could in principle be
    caught by a burst rule; this one is flat and fast, so a rate threshold low
    enough to catch a scanner catches this instead.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, ports[index % len(ports)], 'exchange',
                        REQUESTS['http_api_bearer'], auth='success')
                for index, moment in enumerate(timing.steady(stream, calls, period))]
    return _benign(scenario_id, group, seed, contacts,
                   {'calls': calls, 'period': period,
                    'authentication': 'success_every_request'})


def service_account(scenario_id, group, seed, *, calls=40, period=9.0, port=21,
                    rotations=2):
    """HARD NEGATIVE, api. A service account whose token expires and is renewed.

    The interesting part is that it *does* fail. Twice in the run a credential
    stops working, the client is refused, and the next attempt succeeds. So this
    family has real authentication failures — just very few of them, from one
    principal, each followed by success.

    This is the control for the obvious over-correction: having stopped counting
    credential presence, a system must not simply start counting any failure.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    name = stream.choice(LAB_PRINCIPALS)
    request = user_command(name)
    moments = timing.steady(stream, calls, period)
    failures = set(stream.sample(range(2, calls - 1), k=min(rotations, max(1, calls - 3))))
    contacts = [Contact(moment, destination, port, 'exchange', request,
                        auth='failure' if index in failures else 'success')
                for index, moment in enumerate(moments)]
    return _benign(scenario_id, group, seed, contacts,
                   {'calls': calls, 'period': period, 'port': port, 'principals': 1,
                    'authentication': 'success_with_token_rotation',
                    'failures': len(failures)})


def stale_credential_client(scenario_id, group, seed, *, attempts=21, period=26.0, port=110):
    """HARD NEGATIVE, api. A job with an old password, retrying for ten minutes.

    The most likely false positive in the whole authentication design, and the
    one a corpus of attacks would never contain. Somebody rotated a credential
    and did not update a config file, so a scheduled job now fails every time,
    at a machine interval, from one account, for as long as nobody notices.

    Every surface property of a slow brute force is present: sustained refusals,
    a long failure span, perfect regularity. One thing is absent — it is always
    the *same* account — and that one thing is the whole difference between a
    stuck client and an attack.

    It exists because the ablation could not see the span term doing anything:
    it was the sole strongest signal in 1 of 1027 windows on a corpus that had
    no family it applied to. A term that quiet is either useless or dangerous,
    and no measurement could say which until the behaviour it reacts to was in
    the corpus. It turned out to be the second.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    request = user_command(stream.choice(LAB_PRINCIPALS))
    contacts = [Contact(moment, destination, port, 'exchange', request, auth='failure')
                for moment in timing.steady(stream, attempts, period, .08)]
    return _benign(scenario_id, group, seed, contacts,
                   {'attempts': attempts, 'period': period, 'port': port, 'principals': 1,
                    'authentication': 'failure_every_attempt_one_account'})


# --- benign: admin ----------------------------------------------------------


def admin_login_mistakes(scenario_id, group, seed, *, mistakes=3, period=6.5, port=21):
    """HARD NEGATIVE, admin. §16. One person, one account, a few wrong tries, then in.

    The single most important false positive to avoid, because it is the one a
    real administrator produces on a real Monday morning, from their own office
    address, against the management interface. Consecutive failures are exactly
    what a brute force looks like; one principal and a human interval and a
    success at the end are what it does not.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    name = stream.choice(LAB_PRINCIPALS)
    request = user_command(name)
    moments = timing.human(stream, mistakes + 1, period)
    contacts = [Contact(moment, destination, port, 'exchange', request,
                        auth='failure' if index < mistakes else 'success')
                for index, moment in enumerate(moments)]
    return _benign(scenario_id, group, seed, contacts,
                   {'mistakes': mistakes, 'period': period, 'port': port, 'principals': 1,
                    'authentication': 'failures_then_success'})


def admin_console(scenario_id, group, seed, *, actions=24, period=7.0, ports=ADMIN_PORTS):
    """HARD NEGATIVE, admin. Authenticated administration over HTTP, done by hand.

    Human pacing, one credential, several management endpoints. The admin profile
    prices a false block higher than any other (`autonomy.cost`), and this is the
    traffic that price is about.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, ports[index % len(ports)], 'session',
                        REQUESTS['http_admin_basic'], follow_ups=stream.randrange(0, 2),
                        auth='success')
                for index, moment in enumerate(timing.human(stream, actions, period))]
    return _benign(scenario_id, group, seed, contacts,
                   {'actions': actions, 'period': period,
                    'authentication': 'success_every_request'})


# --- benign: public website -------------------------------------------------


def asset_fetch(scenario_id, group, seed, *, pages=4, assets=22, inside=.06, pause=11.0):
    """HARD NEGATIVE, public_website. A browser loading pages. No authentication at all.

    Included in an authentication-focused module on purpose: most traffic
    attempts no authentication, `NOT_APPLICABLE` is the common answer, and a
    corpus of nothing but login attempts would let a bug in the "no attempt"
    path go unnoticed. The instantaneous rate here is the highest in the module.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, stream.choice(WEB_PORTS), 'exchange',
                        REQUESTS[stream.choice(('http_asset', 'http_asset', 'http_get'))])
                for moment in timing.bursty(stream, pages, assets, inside, pause)]
    return _benign(scenario_id, group, seed, contacts,
                   {'pages': pages, 'assets': assets, 'authentication': 'none_attempted'})


# --- benign: payment webhook ------------------------------------------------


def signed_webhook(scenario_id, group, seed, *, callbacks=50, period=4.0, port=8443):
    """HARD NEGATIVE, payment_webhook. A signed machine callback, perfectly regular.

    Every request is signed, every request is accepted, the interval barely
    varies. Timing regularity is the classic automation tell and this is
    automation — legitimate automation, which is why TIMING is a corroborating
    family and never a carrying one.

    The payment_webhook cost profile never blocks by design; this family is here
    so that statement is measured rather than assumed.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    contacts = [Contact(moment, destination, port, 'exchange',
                        REQUESTS['http_webhook_signature'], auth='success')
                for moment in timing.steady(stream, callbacks, period, .02)]
    return _benign(scenario_id, group, seed, contacts,
                   {'callbacks': callbacks, 'period': period, 'port': port,
                    'authentication': 'signed_success'})


# --- malicious: the matching positives --------------------------------------


def api_credential_spray(scenario_id, group, seed, *, principals=18, period=3.4,
                         destinations=3, ports=LINE_PORTS):
    """POSITIVE, api. §16. Many accounts, one attempt each, all refused.

    The mirror of `authenticated_batch`: fewer requests, slower, and unmistakable
    once outcome is visible. Every attempt fails, every attempt uses a different
    principal, and the attempts are spread across addresses and services so that
    no single destination sees enough to look like a brute force.

    Should react on AUTH_BEHAVIOR (failures across principals) and PORT_BREADTH,
    and must not need NETWORK_RATE — it does not have one.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    names = _principals(stream, principals)
    contacts = [Contact(moment, targets[index % len(targets)], ports[index % len(ports)],
                        'exchange', user_command(names[index]), auth='failure')
                for index, moment in enumerate(timing.jittered(stream, principals, period))]
    return _malicious(scenario_id, group, seed, contacts,
                      {'principals': principals, 'period': period,
                       'destinations': len(targets), 'authentication': 'failure_every_attempt',
                       'credential_content_stored': False})


def admin_brute_force(scenario_id, group, seed, *, attempts=34, period=1.1, port=21,
                      principals=12):
    """POSITIVE, admin. Concentrated guessing against the management interface.

    One address, one service, fast, many principals, everything refused. The
    loudest positive in the module and the pair to `admin_login_mistakes`: same
    port, same request shape, same protocol, opposite outcome profile.
    """
    stream = rng(seed)
    destination = pick_destination(stream)[0]
    names = _principals(stream, principals)
    contacts = [Contact(moment, destination, port, 'exchange',
                        user_command(names[index % len(names)]), auth='failure')
                for index, moment in enumerate(timing.jittered(stream, attempts, period, .3))]
    return _malicious(scenario_id, group, seed, contacts,
                      {'attempts': attempts, 'period': period, 'port': port,
                       'principals': principals, 'authentication': 'failure_every_attempt'})


def login_stuffing(scenario_id, group, seed, *, attempts=40, period=2.0, ports=WEB_PORTS,
                   destinations=2):
    """POSITIVE, public_website. Credential stuffing where the sensor sees least.

    Over HTTP, so the sensor observes 401 after 401 but cannot count principals:
    the account name is inside a value `decision/auth.py` refuses to read. This
    is the hardest positive in the module by construction, and it is here to
    measure what that refusal costs rather than to make the refusal look free.

    Should react on AUTH_BEHAVIOR through failure volume and persistence alone.
    If it cannot be distinguished from `asset_fetch` without principal
    diversity, that is a finding about the limitation, not a reason to start
    hashing credentials.
    """
    stream = rng(seed)
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    contacts = [Contact(moment, targets[index % len(targets)], ports[index % len(ports)],
                        'exchange', REQUESTS['http_admin_basic'], auth='failure')
                for index, moment in enumerate(timing.jittered(stream, attempts, period))]
    return _malicious(scenario_id, group, seed, contacts,
                      {'attempts': attempts, 'period': period,
                       'destinations': len(targets), 'principal_visibility': 'none_over_http',
                       'authentication': 'failure_every_attempt'})


#: The longest a patient walk may run. Under the 600-second generation ceiling
#: with room for jitter, so a varied run can never be refused by the budget.
PATIENT_WALK_SECONDS = 540.0


def patient_account_walk(scenario_id, group, seed, *, principals=14, delay=42.0,
                         port=21, destinations=2, vary=True):
    """HARD POSITIVE, api. §68's low-and-slow case, with outcome.

    One failed attempt per account, forty seconds apart, for ten minutes. Nothing
    in a sixty-second window is remarkable: one connection, one port, one
    credential, one refusal. Only the fifteen-minute view shows fourteen accounts
    failing in a row, and only an evidence-maturity policy that tolerates a long
    thin observation can act on it.

    This is the family that justifies the LONG_DURATION maturity path, and the
    one that will expose it if that path is too eager.

    **Why `principals` and `delay` are a centre rather than a value.** Fixed, this
    generator produced sixteen sources that were one source sixteen times: at one
    contact every forty seconds, almost every window holds a single event, so the
    whole feature vector is a handful of small integers and every run walks the
    same path through them. The first build of the P15.4 development corpus
    measured it — 176 windows, 107 distinct vectors, and 74 of them appearing on
    both sides of the train boundary, the only family in the corpus below a ratio
    of 1.000. That is not a threshold problem, it is a false claim about the
    data: the corpus said sixteen independent low-and-slow sources and had one.
    Real patient attacks differ in how many accounts they try and how long they
    are willing to wait, so each run draws both from its own seeded stream and
    the declared values set the middle of the band.
    """
    stream = rng(seed)
    if vary:
        principals = stream.randrange(max(6, principals - 4), principals + 5)
        delay = delay * stream.uniform(0.8, 1.25)
        span = principals * delay * 1.15
        if span > PATIENT_WALK_SECONDS:
            delay *= PATIENT_WALK_SECONDS / span
    targets = pick_destination(stream, min(destinations, len(SENSOR_ADDRESSES)))
    names = _principals(stream, principals)
    contacts = [Contact(moment, targets[index % len(targets)], port, 'exchange',
                        user_command(names[index]), auth='failure')
                for index, moment in enumerate(timing.paced(stream, principals, delay, .12))]
    return _malicious(scenario_id, group, seed, contacts,
                      {'principals': principals, 'delay': round(delay, 3), 'port': port,
                       'varied_per_run': bool(vary),
                       'authentication': 'failure_every_attempt'}, 'hard_positive')
