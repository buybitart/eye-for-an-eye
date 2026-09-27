"""What one Eye for an Eye sensor can actually see, per behaviour family.

§4 to §6. Written **before** the P15.3 locked corpus exists, and classified from
the sensor architecture rather than from whether detection currently succeeds.
Those are different questions and answering the second one while pretending to
answer the first is how a project excuses its own failures.

### The rule

A family is classified by asking, in order:

1. Do the packets or events that constitute this behaviour reach the capture
   path of a single sensor protecting a single host?
2. Does `correlation.engine.aggregate` compute a quantity that distinguishes it?
3. Can `FeatureVector` represent that quantity?

**Yes to all three: `IN_SCOPE_OBSERVABLE`.** Detection failure is then a real
generalisation failure and must be fixed in the evidence, never reclassified
(§6).

**Yes to (1), partly to (2) or (3): `IN_SCOPE_PARTIALLY_OBSERVABLE`.** Some of
the evidence is unavailable *by construction* — a truncated capture cannot yield
a payload digest. The expected action is reduced accordingly, and that reduction
is predeclared rather than discovered after a test.

**No to (1): `OUT_OF_SCOPE`.** The behaviour happens somewhere this sensor is
not. Documenting the boundary is honest; faking support is not (§5).

`INVALID_TEST_SCENARIO` is for a family whose label cannot be justified at all —
none is currently so classified.

### The finding that shaped this cycle

Every malicious family in the corpus is observable. `scan-horizontal` looked
like an architecture limit and is not: `dataset/generators/base.SENSOR_ADDRESSES`
is eight addresses **of the monitored host**, so a horizontal scan across them
crosses this sensor's own capture path and `unique_destinations` counts it. The
failure was weighting, not visibility — see `reports/P15_3_FAILURE_MATRIX.json`.

Nothing here was written after seeing a P15.3 result. The P15.2 locked test was
used for diagnosis, which §2 permits explicitly, and for nothing else.
"""
import json
from pathlib import Path

OBSERVABILITY_SCHEMA_VERSION = 1

IN_SCOPE_OBSERVABLE = 'IN_SCOPE_OBSERVABLE'
IN_SCOPE_PARTIALLY_OBSERVABLE = 'IN_SCOPE_PARTIALLY_OBSERVABLE'
OUT_OF_SCOPE = 'OUT_OF_SCOPE'
INVALID_TEST_SCENARIO = 'INVALID_TEST_SCENARIO'
CLASSES = (IN_SCOPE_OBSERVABLE, IN_SCOPE_PARTIALLY_OBSERVABLE, OUT_OF_SCOPE,
           INVALID_TEST_SCENARIO)

#: Enforcement eligibility, predeclared per class (§53, §54). Detection and
#: block eligibility are separate questions and this names both.
TEMP_BLOCK_ELIGIBLE = 'TEMP_BLOCK_ELIGIBLE'
WATCH_ONLY = 'WATCH_OR_SOFTER'
NO_ACTION_EXPECTED = 'NO_ACTION_EXPECTED'

#: family -> (class, eligibility, what the sensor sees, what it cannot see)
FAMILIES = {
    # --- malicious ---------------------------------------------------------
    'scan-sequential': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'consecutive destination ports on one host: unique_destination_ports and '
        'sequential_port_fraction both react',
        ''),
    'scan-randomized': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'port breadth without sequence: unique_destination_ports reacts, '
        'sequential_port_fraction deliberately does not',
        ''),
    'scan-connect': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'completed connections across ports; handshake completion is counted',
        ''),
    'scan-horizontal': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'one service across several addresses OF THIS HOST. SENSOR_ADDRESSES are '
        'the monitored host-s own addresses, so unique_destinations counts them '
        'and the traffic crosses this sensor-s capture path',
        'breadth across hosts this sensor does not protect is invisible, and a '
        'real horizontal sweep of an unrelated network would be OUT_OF_SCOPE'),
    'scan-slow': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'port breadth accumulated over the 900 s window; persistence and '
        'ports_900s are the evidence, not rate',
        ''),
    'scan-burst': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'port breadth in bursts; burst fraction and interval variance both react',
        ''),
    'probe-enumeration': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'distinct service probes: unique_protocol_probes and probe_family_diversity',
        ''),
    # Reclassified in P15.5 (§16), from architecture and from a measurement
    # against its own controls rather than from a detection result.
    #
    # P15.4 called this IN_SCOPE_OBSERVABLE while writing, in this very entry,
    # that separating it from a monitoring agent needs more than repetition. The
    # P15.5 measurement is what closes the question: this family and three benign
    # controls -- `benign.monitoring_agent` at two rates and
    # `benign.health_checker` -- all produce **no evidence family above the
    # floor at all**. Not similar scores; the same empty set. A repeated probe on
    # four ports and a monitoring agent on two are, to this sensor, one
    # behaviour.
    #
    # Rule 3 is what fails: `FeatureVector` cannot represent the quantity that
    # separates them, because the quantity is whether the operator asked for the
    # probing. That is authorisation, not traffic, and no amount of looking
    # harder at the packets recovers it.
    #
    # What follows is a classification change and NOT a formula change (§17,
    # §19). Making repetition a carrying family would block every monitoring
    # agent on the network, which is the trade the carrying/corroborating split
    # exists to refuse. `tests/test_p15_5_weak_families.py` holds the control
    # comparison so this claim stays checkable.
    'probe-repeated': (
        IN_SCOPE_PARTIALLY_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'the same probe body repeated: max_probe_repetition over payload digests, '
        'plus inter-arrival regularity and incomplete connection attempts',
        'nothing that separates it from authorised monitoring. Measured in P15.5: '
        'this family and three benign controls (monitoring_agent at two rates, '
        'health_checker) each produce no evidence family above the floor, so the '
        'sensor is not scoring them similarly -- it is representing them '
        'identically. What would separate them is whether the operator authorised '
        'the probing, which is not a property of the traffic'),
    'probe-truncated': (
        IN_SCOPE_PARTIALLY_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'the same behaviour as probe-repeated seen through a truncated capture: '
        'timing, ports, addresses and connection attempts all survive',
        'the payload is cut by snaplen, so payload digests, credential shapes and '
        'protocol-family classification are unavailable BY CONSTRUCTION. Any '
        'evidence family that depends on payload content cannot contribute'),
    'protocol-mismatch': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'protocol_anomalies: a request shaped for one service sent to another',
        ''),
    'recon-multi-stage': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'breadth then focus, across the 900 s window; several families react',
        ''),
    'credential-automation': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'credential_attempts from request shape, never content',
        ''),
    'credential-low-rate': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'the same credential shapes under a rate threshold; the evidence is '
        'persistence and repetition rather than rate',
        ''),
    'deception-enumeration': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'contact with a decoy port that exists only to be contacted. The single '
        'cleanest signal available to this sensor',
        ''),

    # --- benign and hard negatives -----------------------------------------
    'benign-web': (IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
                   'ordinary browsing', ''),
    'benign-web-burst': (IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
                         'a page pulling many assets at once', ''),
    'benign-api': (IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
                   'a programmatic client on one port', ''),
    'benign-ssh': (IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
                   'an interactive session', ''),
    'benign-retry': (IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
                     'a flaky link retrying; retry_observations distinguishes a '
                     'retransmission from a fresh attempt', ''),
    'benign-noise': (IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
                     'ambient background traffic', ''),
    'benign-truncated': (IN_SCOPE_PARTIALLY_OBSERVABLE, NO_ACTION_EXPECTED,
                         'ordinary browsing through a truncated capture',
                         'payload-derived evidence unavailable, exactly as for '
                         'probe-truncated. The pair exists so a truncated capture '
                         'cannot become a proxy for guilt'),
    'hard-negative-monitoring': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a metronomic agent: the most regular timing on the network and entirely '
        'legitimate. The reason a timing term may never be sufficient alone', ''),
    'hard-negative-health-check': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'high-rate periodic checking from a load balancer', ''),
    'hard-negative-admin': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'an administrator touching several services in one sitting: real port '
        'breadth, legitimately', ''),
    'hard-negative-discovery': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'service discovery, which is breadth with a good reason', ''),
    'hard-negative-connect': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a connect probe that completes and leaves', ''),
    'hard-negative-deception': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'brushing past a decoy without enumerating it. The control that stops '
        '"touched a decoy" from becoming a signature', ''),

    # --- P15.3 compositions, classified before the benchmark was generated ---
    'composite-paced-breadth': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'slow pacing, wide port breadth and several addresses of this host at '
        'once. Every component reaches the sensor: ports, destinations and the '
        '900 s span',
        'nothing relevant. Withholding rate is the test, not a limitation'),
    'composite-credential-spray': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'credential-shaped requests spread across several addresses and '
        'services. Request shape and destination breadth are both visible',
        ''),
    'composite-decoy-recon': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'decoy contact followed by service enumeration. Both halves are ours to '
        'see: the decoy is this host-s and the ports are this host-s',
        ''),
    'hard-negative-backup': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'sustained volume to one service with every exchange completed. The '
        'control for the connections_60s term added in P15.3', ''),
    'hard-negative-crawler': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a polite crawler across several addresses of one site. The control for '
        'the destination-breadth re-normalisation added in P15.3', ''),
    'hard-negative-batch-api': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'authenticated batch jobs in bursts. The control for the credential '
        'term: a real API client authenticates constantly', ''),

    # --- P15.4: authentication with an outcome -----------------------------
    # Classified from the sensor architecture before the P15.4 corpora existed,
    # by the same rule and in the same order as everything above. The question
    # that decides each entry is new, though. Not "does the traffic reach this
    # sensor" -- all of it does -- but "can this sensor see what the server
    # ANSWERED, and can it tell one account from another". Those have different
    # answers for a cleartext line protocol and for HTTP, and the difference is
    # predeclared here rather than discovered when a number disappoints.

    # Benign. Every one of these authenticates, most of them constantly, and
    # none may be acted on for doing so (§5).
    'profile-api-batch': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a bearer credential on every request and a 2xx on every reply, so both '
        'the attempt and its success are counted. The family P15.3 blocked 21 of '
        '22 times, and the reason authentication outcome exists at all',
        'the token is never read, so this source has no principal identity -- a '
        'deliberate refusal rather than a gap'),
    'profile-api-high-rate': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'sustained authenticated volume with no burst structure. The rate '
        'control: a threshold low enough to catch a scanner catches this', ''),
    'profile-api-service-account': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a cleartext USER line, so the principal pseudonym is available, and '
        '530/230 replies, so failure and success are both counted. It genuinely '
        'fails twice per run when its token expires -- the control for the '
        'obvious over-correction of counting any failure at all', ''),
    'profile-api-stale-credential': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a scheduled job whose password was rotated and whose config file was '
        'not updated: refused every time, at a machine interval, for as long as '
        'nobody notices. Every surface property of a slow brute force -- '
        'sustained refusals, a long failure span, perfect regularity -- and one '
        'thing absent, which is that it is always the same account',
        ''),
    'profile-admin-mistakes': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'three consecutive refusals and then a success, one principal, human '
        'pacing, against the management interface. Everything needed to tell it '
        'from a brute force is visible: the principal count and the ending', ''),
    'profile-admin-console': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'authenticated administration by hand: attempts and successes counted, '
        'human intervals, several management endpoints',
        'Basic credentials are not read, so no principal identity'),
    'profile-web-assets': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a browser loading pages and assets. Attempts NOT_APPLICABLE throughout, '
        'which is the common case and the one a corpus of nothing but logins '
        'would never exercise', ''),
    'profile-webhook-signed': (
        IN_SCOPE_OBSERVABLE, NO_ACTION_EXPECTED,
        'a signed machine callback, accepted every time, at an interval that '
        'barely varies. Automation that is entirely legitimate, and the reason '
        'timing may corroborate and never carry', ''),

    # Malicious. What separates these from the seven above is not that they
    # carry credentials -- so does every benign family here -- but that the
    # server keeps refusing them.
    'positive-api-spray': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'many accounts, one attempt each, all refused, spread across addresses '
        'and services. Cleartext, so failed-principal diversity -- the strongest '
        'authentication evidence there is -- is fully visible', ''),
    'positive-admin-brute': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'concentrated guessing against the management interface: failures, '
        'principals and rate all visible at once', ''),
    'positive-web-stuffing': (
        IN_SCOPE_PARTIALLY_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'repeated 401s from one source over HTTP. Failure count, failure ratio '
        'and failure span are all visible, and are enough on their own',
        'the account name sits inside an Authorization value this system refuses '
        'to read (decision/auth.py), so principal diversity is unavailable BY '
        'CONSTRUCTION -- not because the sensor cannot see the bytes, but because '
        'deriving a stored value from a live secret is a trade this project does '
        'not make. Predeclared, so a weaker result here reads as the cost of that '
        'refusal rather than as a surprise'),
    'positive-api-patient-walk': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'one refused account every forty seconds for several minutes. Nothing in '
        'a sixty-second window is remarkable; the 900-second principal count and '
        'failure span are the whole evidence, and both are representable',
        'there is no rate evidence to find, by construction. A detector that '
        'needs one will miss this, and that is a weighting failure rather than a '
        'visibility one'),

    # --- P15.4: withheld from every fitting corpus (§49, §50) --------------
    'withheld-mobile-sync': (
        IN_SCOPE_PARTIALLY_OBSERVABLE, NO_ACTION_EXPECTED,
        'an app waking, retrying a dropped connection, and authenticating on '
        'every call. Attempts and the successes among them are counted',
        'about a third of its outcomes are genuinely unobservable: the reply is '
        'an acknowledgement the classifier does not recognise, so the result is '
        'UNKNOWN. §7 forbids reading that as failure, and this family is how the '
        'rule gets tested at volume rather than in one unit test'),
    'withheld-probe-login': (
        IN_SCOPE_OBSERVABLE, TEMP_BLOCK_ELIGIBLE,
        'a six-port sweep followed by nine refused logins from the same source. '
        'Both halves are individually unremarkable and both are individually '
        'visible; whether their co-occurrence is, is the question', ''),
}


def classify(family):
    entry = FAMILIES.get(family)
    return entry[0] if entry else None


def eligibility(family):
    entry = FAMILIES.get(family)
    return entry[1] if entry else None


def observable(family):
    return classify(family) in (IN_SCOPE_OBSERVABLE, IN_SCOPE_PARTIALLY_OBSERVABLE)


def block_eligible(family):
    return eligibility(family) == TEMP_BLOCK_ELIGIBLE


def by_class():
    out = {name: [] for name in CLASSES}
    for family, entry in sorted(FAMILIES.items()):
        out[entry[0]].append(family)
    return out


def document():
    return {
        'observability_schema_version': OBSERVABILITY_SCHEMA_VERSION,
        'classes': list(CLASSES),
        'by_class': by_class(),
        'families': {family: {'class': entry[0], 'enforcement_eligibility': entry[1],
                              'observed': entry[2], 'not_observed': entry[3]}
                     for family, entry in sorted(FAMILIES.items())},
        'note': ('classified from the sensor architecture, before the P15.3 locked '
                 'corpus existed. Detection difficulty is not a reason to reclassify'),
    }


def write(path):
    Path(path).write_text(json.dumps(document(), indent=1) + '\n', encoding='utf-8')
    return path


#: Prose that belongs to the document rather than to the table. Kept here so
#: `docs/BEHAVIOR_OBSERVABILITY.md` is regenerated in full and can never drift
#: from `FAMILIES` — a hand-edited table would defeat the point of classifying
#: in code.
_PREAMBLE = """# Behaviour observability

What one Eye for an Eye sensor can actually see, per scenario family.
Generated from `training/observability.py` - the classification lives in code so
a test can check it and a later cycle cannot quietly revise it in prose.

Classified from the sensor architecture **before** the P15.3 locked corpus
existed, and never from whether detection currently succeeds. Those are
different questions, and answering the second while claiming to answer the
first is how a project excuses its own failures.

## The rule

1. Do the packets or events constituting this behaviour reach the capture path
   of a single sensor protecting a single host?
2. Does `correlation.engine.aggregate` compute a quantity that distinguishes it?
3. Can `FeatureVector` represent that quantity?

Yes to all three is `IN_SCOPE_OBSERVABLE`, and a detection failure there is a
real generalisation failure that must be fixed in the evidence.
"""

_EPILOGUE = """
## The finding that shaped P15.3

`scan-horizontal` looked like an architecture limit and is not.
`dataset/generators/base.SENSOR_ADDRESSES` is eight addresses **of the monitored
host**, so a horizontal scan across them crosses this sensor-s own capture path
and `unique_destinations` counts every one. Its P15.2 failure was weighting and
normalisation, not visibility - see `reports/P15_3_FAILURE_MATRIX.json`.

A horizontal sweep across hosts this sensor does not protect would be a
different behaviour and genuinely out of scope. The distinction is the whole
point of classifying before measuring.

## The P15.3 compositions

Six families were added for the generalisation benchmark and classified here
before the corpus was generated, which is the only order in which a
classification means anything (§3, §50). Three are malicious compositions of
primitives the corpus already contains; three are benign compositions of the
*same* primitives, present so that each term added to MathRisk v2 has a control
that would be blocked if that term were sufficient on its own.

## The P15.4 authentication families

Thirteen more, classified before the P15.4 corpora were generated, for the same
reason and in the same order.

The question that decides them is different from every entry above it. All of
this traffic reaches the sensor, so step (1) is never in doubt; what varies is
whether the sensor can see **what the server answered**, and whether it can tell
one account from another. A cleartext line protocol gives both: `530 Login
incorrect` is the outcome, and `USER <name>` yields a principal pseudonym. HTTP
gives only the first, because the account name lives inside an `Authorization`
value that `decision/auth.py` refuses to read -- a refusal about storing values
derived from live secrets, not a limit of the capture path.

That is why `positive-web-stuffing` is `IN_SCOPE_PARTIALLY_OBSERVABLE` while
`positive-api-spray`, the same idea over FTP and POP3, is fully observable. The
cost of the refusal is predeclared here so that a weaker result on the HTTP
family reads as the price of a decision somebody made, rather than as a
discovery.

`withheld-mobile-sync` is partially observable for an unrelated reason worth
keeping distinct: about a third of its authentication outcomes are genuinely
unobservable, because the reply is an acknowledgement the classifier does not
recognise. `UNKNOWN` is the honest answer there, and the rule that it is never
read as failure needs a benign family that produces a great deal of it.

## See also

- [GENERALIZATION_POLICY.md](GENERALIZATION_POLICY.md)
- [LIMITATIONS.md](LIMITATIONS.md)
- [../reports/P15_3_OBSERVABILITY.json](../reports/P15_3_OBSERVABILITY.json)
- [../reports/P15_3_TEST_POLICY.json](../reports/P15_3_TEST_POLICY.json)
"""


def markdown():
    """The whole document, rebuilt from `FAMILIES`."""
    groups = by_class()
    lines = [_PREAMBLE, '## Summary\n']
    for name in CLASSES:
        members = groups[name]
        listed = ', '.join('`' + family + '`' for family in members) or 'none'
        lines.append(f'**{name}** ({len(members)}): {listed}\n')
    lines.append('## Per family\n')
    lines.append('| Family | Class | Enforcement | What the sensor sees | '
                 'What it cannot see |')
    lines.append('| --- | --- | --- | --- | --- |')
    for family, entry in sorted(FAMILIES.items()):
        lines.append(f'| `{family}` | {entry[0]} | {entry[1]} | {entry[2]} | '
                     f'{entry[3] or "-"} |')
    return '\n'.join(lines) + '\n' + _EPILOGUE


def write_markdown(path):
    Path(path).write_text(markdown(), encoding='utf-8')
    return path
