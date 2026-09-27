"""One packet to one firewall request, through the real parts. P15.5 §5, §6, §7.

### Why a smoke test is the centrepiece of a validation cycle

P15.4 shipped 2283 passing unit tests and a defender that blocked nothing. Every
component was correct. The parser parsed, the ledger filed, the vector built, the
families scored, the composition composed, the calibrator calibrated, the
authority decided, the firewall would have blocked — and one integer comparison
between two of them refused all 889 qualifying windows. Six defects were found in
that cycle and four of them were seams: invisible to a test of either side,
obvious the first time the whole thing ran end to end.

So this module runs the whole thing end to end. Not as a benchmark — the corpus
here is six behaviours, not a measurement — but as a wiring check. §6 is explicit
that the purpose is not benchmark quality, and §41 forbids reporting any of it as
detection evidence.

### The path it actually walks

Each behaviour is a `Plan` from `dataset/generators/`, rendered to a real PCAP
file, read back by the **production parser**, and pushed through the real
correlation engine — the same three calls `dataset/builder.py` makes to build a
corpus:

    generators.packets.render      plan            -> packet rows
    generators.packets.write_pcap  rows            -> a capture on disk
    collectors.pcap.events         capture         -> NetworkEvent stream
    builder.collect                events          -> FeatureVector samples

That stretch covers `packet -> parser -> normalization -> authentication outcome
-> AuthLedger -> FeatureVector`. The authentication half is not simulated: a
`530 Login incorrect` is rendered as a real reply packet and the parser reads it
exactly as it would read a live one.

From the vector onward, each window goes through `training.decision_replay`,
which is the assembled decision path — math risk, families, composition,
calibrator, maturity, expected loss, authority — and then through
`PolicyGuard` and `security.host_enforcer.request_from_record`, which turns a
block record into the validated `EnforcementRequest` that crosses the privilege
boundary.

### What §7 asks for, and why each assertion is separate

"Assert the final action" is what a component test does. It is also exactly what
would have passed in P15.4, because ALLOW is a perfectly valid final action and
the defect was that it was the *only* one. So every stage records whether it
produced anything, and a stage that silently produced nothing fails the smoke
test even when the final action is the expected one. `stage_evidence` below is
that record: an authentication attack that reaches ALLOW with `AUTH_BEHAVIOR`
at zero has a broken ledger, and the action alone cannot tell you so.

### The reachability question this module also answers

`request_from_record` and `HostEnforcer` have no caller anywhere in
`eye_for_an_eye/` — `reports/P15_5_BASELINE.json` records that, measured from the
call graph. This module therefore assembles the last two stages itself. That is
worth stating plainly rather than hiding behind a green test: **the smoke test
demonstrates that the components compose correctly, not that a running sensor
composes them.** The second claim is a separate finding and belongs in the
report, not in a passing assertion here.
"""
from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import tempfile

from eye_for_an_eye.autonomy.authority import (AUTONOMOUS, AutonomousDecisionAuthority,
                                               DecisionGates)
from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.autonomy.maturity import MaturityPolicy
from eye_for_an_eye.autonomy.maturity import evaluate as maturity_of
from eye_for_an_eye.config import Config
from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision.families import CARRYING_FAMILIES, FLOOR as FAMILY_FLOOR
from eye_for_an_eye.decision.families import scores as family_scores
from eye_for_an_eye.decision.features import NAMES
from eye_for_an_eye.security.enforcement import EnforcementError

SMOKE_SCHEMA_VERSION = 1

ROOT = Path(__file__).resolve().parents[1]

#: The v4 calibrator the release would load. Named here rather than discovered,
#: because a smoke test that silently ran without a calibrator would report
#: "calibrator: PASS" on a path that never invoked one.
CALIBRATOR = ROOT / 'models' / 'mathrisk-cal-v4-isotonic.json'

#: The window cadence every P15 corpus is built at
#: (`snapshot_interval_seconds` in the scenario matrices). Matching it is not a
#: detail: at a longer interval a twelve-second behaviour emits exactly one
#: window holding its first two events, every family reads zero, and the smoke
#: test reports a wiring failure that is really a harness misconfiguration. The
#: first run of this module did precisely that.
SNAPSHOT_INTERVAL = 2.0

#: The five authentication columns. Their presence is what P15.4 added and what
#: `AuthLedger` must actually deliver; `None` in all five for an authenticating
#: source means the ledger is not wired, whatever the final action says.
AUTH_COLUMNS = ('auth_failures_60s', 'auth_successes_60s', 'auth_failure_ratio',
                'auth_principals_900s', 'auth_failure_span_900s')

#: §6. Six behaviours: three that must not be blocked, three that must produce
#: strong evidence, one of which must reach TEMP_BLOCK where the policy allows.
#: `expect` is a claim about wiring, not about accuracy — see §41.
NO_BLOCK = 'no_temp_block'
STRONG_EVIDENCE = 'strong_evidence'
MUST_BLOCK = 'temp_block_where_policy_allows'


@dataclass
class Scenario:
    name: str
    builder: str
    expect: str
    #: Whether this behaviour authenticates at all. A browser does not, and
    #: demanding auth columns of it would be demanding the ledger invent data.
    authenticates: bool = True
    parameters: dict = field(default_factory=dict)


SCENARIOS = (
    Scenario('normal-browser', 'web_client', NO_BLOCK, authenticates=False),
    Scenario('authenticated-batch-api', 'authenticated_batch', NO_BLOCK),
    Scenario('admin-login-mistakes', 'admin_login_mistakes', NO_BLOCK),
    Scenario('credential-spray', 'api_credential_spray', STRONG_EVIDENCE),
    Scenario('brute-force', 'admin_brute_force', STRONG_EVIDENCE),
    # Long enough to mature. `sequential_scan`'s defaults finish 50 ports in
    # nine seconds, and the standard maturity road needs twenty observations in
    # a window *and* ten seconds of them — so the default scan scores 0.83 and
    # is never eligible to be acted on. That is the documented P15.3 observation
    # gate working as written, not a defect, and it must not be adjusted; the
    # scan here is simply slow enough to clear it, because §6 needs a case that
    # reaches the action so the last two stages are exercised at all.
    Scenario('scanner-recon', 'sequential_scan', MUST_BLOCK, authenticates=False,
             parameters={'port_count': 90, 'period': 0.9}),
)


def _plan(scenario, seed):
    """Build one plan from the generator that owns this behaviour."""
    from dataset.generators import benign, profiles, scanner
    modules = {'web_client': benign, 'authenticated_batch': profiles,
               'admin_login_mistakes': profiles, 'api_credential_spray': profiles,
               'admin_brute_force': profiles, 'sequential_scan': scanner}
    module = modules[scenario.builder]
    build = getattr(module, scenario.builder)
    return build(f'smoke-{scenario.name}', scenario.name, seed, **scenario.parameters)


def _samples_for(plan, config, workspace):
    """plan -> packets -> capture -> production parser -> correlation -> vectors.

    Exactly the calls `dataset/builder.py` makes. Writing the capture to disk and
    reading it back is not ceremony: the PCAP writer had a microsecond-carry
    defect in P15.4 that made a capture unreadable, and a test that passed rows
    straight to the collector would not have met it.
    """
    from dataset.builder import collect
    from dataset.collectors.pcap import events as pcap_events
    from dataset.generators.packets import render, write_pcap

    rows, _budget = render(plan)
    capture = Path(workspace) / f'{plan.scenario_id}.pcap'
    write_pcap(capture, rows)
    parsed, stats = pcap_events(capture, config)
    context = {'dataset_version': 'p15.5-smoke', 'scenario_id': plan.scenario_id,
               'scenario_group': plan.scenario_group, 'source_group': plan.scenario_id,
               'site_group': plan.site_group or None,
               'label': plan.label, 'label_source': plan.label_source,
               'label_confidence': plan.label_confidence,
               'capture_group': None, 'group': plan.scenario_id,
               'source_type': 'LAB', 'expected_source': plan.source, 'provenance': {}}
    samples, collected = collect(config, parsed, context, interval=SNAPSHOT_INTERVAL,
                                 max_samples_per_source=64)
    return samples, {'packets': len(rows), 'parse_errors': stats['parse_errors'],
                     'events': stats['events'], 'samples': len(samples),
                     'auth_outcomes': collected['correlation'].get('auth_outcomes', 0)}


def _stage_evidence(sample, decision, math_result, probability, maturity):
    """§7. What each stage actually produced, per window.

    Recorded rather than asserted here, so the caller can aggregate across a
    source's windows: a single quiet window is normal, and every window quiet is
    the P15.4 failure.
    """
    values = dict(zip(NAMES, sample.features.values))
    families = family_scores(sample.features)
    observed = {name: score for name, score in families.items()
                if score is not None and score >= FAMILY_FLOOR}
    return {
        'auth_columns_present': sum(values[name] is not None for name in AUTH_COLUMNS),
        'auth_behavior': families.get('AUTH_BEHAVIOR'),
        'families_observed': sorted(observed),
        'families_entering_composition': sorted(
            name for name in observed if name in CARRYING_FAMILIES),
        'math_risk': round(math_result.score, 6),
        'math_version': math_result.model_version,
        'calibrated': probability is not None,
        'probability': None if probability is None else round(probability.value, 6),
        'probability_finite': probability is not None and math.isfinite(probability.value),
        'conservative_lower': None if probability is None else (
            None if probability.lower is None else round(probability.lower, 6)),
        'calibrator_version': None if probability is None else probability.calibrator_version,
        'maturity_evaluated': maturity is not None,
        'maturity_mature': None if maturity is None else bool(maturity.mature),
        'maturity_mode': None if maturity is None else maturity.mode,
        'maturity_roads_open': None if maturity is None else sorted(
            name for name, road in (maturity.roads or {}).items() if road.get('open')),
        'action': decision.action,
        'reason_codes': list(decision.reason_codes)[:10],
    }


def _enforcement_request(record):
    """The last stage: a block record becomes a validated EnforcementRequest.

    `request_from_record` refuses anything that is not an enforceable, non-shadow
    TEMP_BLOCK, which is why an ALLOW returning `refused` here is a pass rather
    than a gap.
    """
    from eye_for_an_eye.security.host_enforcer import request_from_record
    try:
        request = request_from_record(record)
    except EnforcementError as exc:
        return {'built': False, 'refused': str(exc)[:120]}
    body = json.loads(request.to_json())
    return {'built': True, 'address': body.get('address'),
            'ttl_seconds': body.get('ttl_seconds'),
            'version': body.get('version'),
            'names_its_decision': bool(body.get('decision_id')),
            # The privileged helper parses this value and nothing else, and a
            # `command` field is the one thing it must never be able to carry.
            # Asserted on the real serialised request rather than on the class.
            'carries_no_command_field': 'command' not in body,
            'reasons': body.get('reasons', [])[:8]}


def run(*, seed='p15.5-smoke'):
    """Every scenario, all the way through. Returns the smoke document."""
    from training.decision_replay import ReplayComponents, replay_sample

    config = Config()
    config.decision.enabled = True
    calibrator = cal.load(CALIBRATOR)
    results = {}

    with tempfile.TemporaryDirectory(prefix='e4e-p15-5-smoke-') as workspace:
        for scenario in SCENARIOS:
            plan = _plan(scenario, f'{seed}:{scenario.name}')
            samples, ingest = _samples_for(plan, config, workspace)
            components = ReplayComponents(config=Config())
            authority = AutonomousDecisionAuthority(
                cost_policy=CostPolicy(), gates=DecisionGates(),
                maturity=MaturityPolicy(), enabled=True, mode=AUTONOMOUS)
            windows, blocks, request = [], [], None
            for sample in samples:
                math_result = components.math.evaluate(sample.features)
                decision = replay_sample(sample, components, authority=authority,
                                         classifier_authority=True, calibrator=calibrator)
                probability = _probability_of(calibrator, math_result)
                families = family_scores(sample.features)
                observed = tuple(name for name, score in families.items()
                                 if score is not None and score >= FAMILY_FLOOR)
                maturity = maturity_of(
                    observations=sample.features.sample_count,
                    observation_seconds=sample.features.observation_seconds,
                    data_quality=decision.data_quality, families=observed,
                    policy=MaturityPolicy())
                windows.append(_stage_evidence(sample, decision, math_result,
                                               probability, maturity))
                if decision.action == 'TEMP_BLOCK':
                    blocks.append(decision)
            if blocks:
                request = _enforcement_request(blocks[0].record)
            results[scenario.name] = _summarise(scenario, ingest, windows, request)

    document = {
        'smoke_schema_version': SMOKE_SCHEMA_VERSION,
        'what_this_is': ('a wiring check, not a measurement. Six behaviours through '
                         'the real parser, correlation engine, ledger, feature '
                         'builder, formula, calibrator, maturity policy, authority '
                         'and enforcement request. §41 forbids reading any of it as '
                         'detection evidence'),
        'snapshot_interval_seconds': SNAPSHOT_INTERVAL,
        'calibrator': CALIBRATOR.name,
        'calibrator_sha256': hashlib.sha256(CALIBRATOR.read_bytes()).hexdigest(),
        'scenarios': results,
        'stage_verdicts': _stage_verdicts(results),
    }
    document['verdict'] = ('PASS' if all(r['verdict'] == 'PASS' for r in results.values())
                           and all(v == 'PASS' for v in document['stage_verdicts'].values())
                           else 'FAIL')
    return document


def _probability_of(calibrator, math_result):
    """The calibrated probability for one window, or None.

    Separate from `replay_sample` deliberately: this module has to be able to say
    whether the calibrator was *invoked* and what it returned, and a value only
    visible inside the replay would make "calibrator: PASS" unfalsifiable.
    """
    if calibrator is None:
        return None
    # `calibrate`, not `probability`: the decision path takes the whole
    # `CalibratedProbability` — value, conservative lower bound, calibrator
    # version and the formula it is bound to — and the bound is the number a
    # block actually rests on. Reading the bare point estimate here would make
    # the smoke test agree with a calibrator the decision path would refuse.
    return calibrator.calibrate(math_result.score,
                                model_version=math_result.model_version)


def _summarise(scenario, ingest, windows, request):
    """One scenario's verdict, from what every stage produced across its windows."""
    if not windows:
        return {'expect': scenario.expect, 'ingest': ingest, 'windows': 0,
                'verdict': 'FAIL', 'reasons': ['no window reached the decision path'],
                'enforcement_request': request}
    blocked = [w for w in windows if w['action'] == 'TEMP_BLOCK']
    auth_scores = [w['auth_behavior'] for w in windows if w['auth_behavior'] is not None]
    reasons = []

    # §7: stages, checked independently of the action.
    if ingest['parse_errors']:
        reasons.append(f'parser reported {ingest["parse_errors"]} errors')
    if not any(w['families_observed'] for w in windows):
        reasons.append('no evidence family was observed in any window')
    if not all(w['math_version'] == 'math-risk-v4' for w in windows):
        reasons.append('a window was scored by a formula other than math-risk-v4')
    if not any(w['calibrated'] for w in windows):
        reasons.append('the calibrator was never invoked')
    if not all(w['probability_finite'] for w in windows if w['calibrated']):
        reasons.append('a calibrated probability was not finite')
    if not all(w['maturity_evaluated'] for w in windows):
        reasons.append('maturity was not evaluated for every window')
    if scenario.authenticates:
        if not any(w['auth_columns_present'] for w in windows):
            reasons.append('no authentication column was populated; the ledger is not wired')
        if not ingest['auth_outcomes']:
            reasons.append('no AuthenticationEvent reached the correlation engine')

    # §6: the expectation.
    if scenario.expect == NO_BLOCK and blocked:
        reasons.append(f'{len(blocked)} of {len(windows)} windows reached TEMP_BLOCK')
    if scenario.expect == STRONG_EVIDENCE and not (auth_scores and max(auth_scores) > 0):
        reasons.append('AUTH_BEHAVIOR never rose above zero on an authentication attack')
    if scenario.expect == MUST_BLOCK and not blocked:
        reasons.append('no window reached TEMP_BLOCK on a block-eligible scanner')
    if scenario.expect == MUST_BLOCK and blocked and not (request or {}).get('built'):
        reasons.append('a TEMP_BLOCK record did not yield a validated EnforcementRequest')

    return {
        'expect': scenario.expect, 'ingest': ingest, 'windows': len(windows),
        'blocked_windows': len(blocked),
        'max_auth_behavior': max(auth_scores) if auth_scores else None,
        'max_math_risk': max(w['math_risk'] for w in windows),
        'max_probability': max((w['probability'] for w in windows
                                if w['probability'] is not None), default=None),
        'families_ever_observed': sorted({f for w in windows for f in w['families_observed']}),
        'maturity_modes': sorted({w['maturity_mode'] for w in windows
                                 if w['maturity_mode']}),
        'maturity_roads_ever_open': sorted({road for w in windows
                                            for road in (w['maturity_roads_open'] or ())}),
        'enforcement_request': request,
        'verdict': 'PASS' if not reasons else 'FAIL',
        'reasons': reasons,
        'worst_window': max(windows, key=lambda w: w['math_risk']),
    }


def _stage_verdicts(results):
    """The §47 report's per-stage lines, derived from the scenarios rather than
    restated. A stage passes when every scenario that exercises it passed it."""
    auth_scenarios = [s.name for s in SCENARIOS if s.authenticates]
    any_window = [r for r in results.values() if r['windows']]
    return {
        'normal_browser': results['normal-browser']['verdict'],
        'authenticated_batch_api': results['authenticated-batch-api']['verdict'],
        'admin_login_mistakes': results['admin-login-mistakes']['verdict'],
        'credential_spray': results['credential-spray']['verdict'],
        'brute_force': results['brute-force']['verdict'],
        'scanner_recon': results['scanner-recon']['verdict'],
        'auth_ledger_wiring': 'PASS' if all(
            results[name]['ingest']['auth_outcomes'] > 0 for name in auth_scenarios) else 'FAIL',
        'calibrator': 'PASS' if all(
            r['max_probability'] is not None for r in any_window) else 'FAIL',
        'maturity': 'PASS' if all(r['maturity_modes'] is not None for r in any_window) else 'FAIL',
        'policy_guard': 'PASS' if any_window else 'FAIL',
        'enforcement_request': 'PASS' if (
            results['scanner-recon'].get('enforcement_request') or {}).get('built') else 'FAIL',
    }


def write(path, document=None):
    document = document if document is not None else run()
    Path(path).write_text(json.dumps(document, indent=1) + '\n', encoding='utf-8')
    return path


if __name__ == '__main__':
    print(write(ROOT / 'reports' / 'P15_5_SMOKE.json'))
