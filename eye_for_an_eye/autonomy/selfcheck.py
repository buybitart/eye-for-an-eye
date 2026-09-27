"""Can a decision still reach the end of the pipeline? P15.5 §40, §41.

### What this answers, and the one it must not be mistaken for

P15.4's locked benchmark took days to build and one integer comparison made its
result zero. The defect was present from the moment schema 2 landed, it was
detectable in under a second, and nothing asked.

This asks. Two synthetic vectors go through the real chain — `MathRiskEngine`,
the calibrator, `AutonomousDecisionAuthority` — and the check is that the answers
are still *different*: the quiet one must not block and the loud one must be
eligible to. A build where both come back ALLOW has something broken between two
components, whatever each component says about itself.

**It tests wiring and nothing else** (§41). It is not a detection measurement, it
is not evidence about accuracy, no number from it belongs in a report about how
well the system works, and its verdict is `WIRED` / `BROKEN` rather than anything
that could be read as a score. The fixtures are deliberately artificial: a vector
with values chosen to be obviously high is not an attack signature, and
recognising it says nothing about recognising a real one.

### Why the fixtures are versioned and synthetic

§40 says not to hardcode a real attack signature, and the reason is worth stating
plainly: a self-check built from a real attack becomes a thing the system is
tuned to pass. These two vectors are built from the feature *schema* — every
applicable feature at a fixed fraction of its range — so they cannot encode a
behaviour at all, and they survive a schema change without being rewritten.

`SELFCHECK_FIXTURE_VERSION` names them because the check's meaning depends on
them: "the loud vector was eligible to block" is only informative if a reader can
find out what the loud vector was.

### Why it cannot touch a firewall, and why its authority is nonetheless enabled

It calls `authority.decide`, which holds no enforcement privilege — that is P15
invariant 1, `AutonomousDecisionAuthority.has_enforcement_privilege` is `False`
structurally, and the record produced here is handed to nothing. There is no path
from this module to a rule.

The authority it builds is a throwaway, and it is constructed **enabled and
autonomous** on purpose. `autonomy_enabled` is the first gate in the chain, so an
authority in shadow refuses everything at the door and every gate below it —
maturity, diversity, cost, margin, the assumptions, PolicyGuard, the breakers —
goes untested. A self-check that stopped at the enablement gate would have passed
throughout P15.4, which is the precise failure it exists to catch. What it
asserts instead is that nothing was enforced: `record.enforced` is `False`,
because an authority is not a thing that can enforce.
"""
from pathlib import Path
import json
import math

from ..compatibility import FEATURE_SCHEMA
from ..decision.features import NAMES, SPEC, FeatureVector
from ..decision.math_risk import MathRiskEngine
from ..decision.onnx_model import MLResult
from ..decision.policy import DataQualityResult, POLICY_GUARD_VERSION
from . import calibrator as calibration_loader
from .authority import AUTONOMOUS, AutonomousDecisionAuthority
from .pipeline import from_config as pipeline_from_config
from .record import TEMP_BLOCK


def _config_for(config, calibrator_path):
    """The configuration this check runs against.

    A caller may hand in the deployment's own config, an explicit calibrator
    path, or neither. An explicit path wins, because the only callers that pass
    one are tests naming an artifact deliberately and a person debugging a
    specific file; in both cases being overridden silently would be worse than
    being verbose.
    """
    from ..config import Config
    settings = config
    if settings is None:
        settings = Config()
        settings.decision.enabled = True
    if calibrator_path:
        from copy import deepcopy
        settings = deepcopy(settings)
        settings.autonomy.calibrator_path = str(calibrator_path)
    return settings

#: The shape of the two fixtures below. Bumped when either changes, because a
#: verdict about "the loud vector" means nothing if the loud vector moved.
SELFCHECK_FIXTURE_VERSION = 1

WIRED = 'WIRED'
BROKEN = 'BROKEN'
SKIPPED = 'SKIPPED'

#: Every feature at this fraction of **its own declared ceiling**. Not a
#: behaviour: no real source produces a flat profile across twenty-three
#: unrelated quantities, which is the point — a fixture that looked like traffic
#: would invite being tuned for.
#:
#: The ceiling matters. A `FeatureVector` holds raw values, not normalised ones,
#: and a flat 0.95 across every column is 0.95 ports and 0.95 connections, which
#: is a very quiet source rather than a loud one. Scaling by `SPEC` is what makes
#: "near the top of its range" mean what it says.
QUIET_FRACTION = 0.02
LOUD_FRACTION = 0.95


def _vector(fraction, *, observations, seconds):
    """A vector built from the schema rather than from a captured behaviour."""
    values = tuple(round(fraction * ceiling, 6) for _, ceiling, *_ in SPEC)
    return FeatureVector(values, observation_seconds=float(seconds),
                         sample_count=int(observations))


def fixtures():
    """The two inputs, described well enough to be argued with."""
    return {
        'fixture_version': SELFCHECK_FIXTURE_VERSION,
        'feature_schema': FEATURE_SCHEMA.current,
        'features': len(NAMES),
        'quiet': {'fraction_of_ceiling': QUIET_FRACTION, 'observations': 24,
                  'observation_seconds': 60.0,
                  'means': 'every feature near the bottom of its declared range'},
        'loud': {'fraction_of_ceiling': LOUD_FRACTION, 'observations': 120,
                 'observation_seconds': 420.0,
                 'means': 'every feature near the top of its declared range'},
        'note': ('synthetic by construction and not derived from any capture. A '
                 'self-check built from a real attack becomes something the '
                 'system is tuned to pass'),
    }


def _decide(pipeline, vector, math_result):
    """One synthetic decision, through the real pipeline.

    P15.5R §23: the real construction path, not a test-only one. This goes
    through `AutonomousDecisionPipeline.decide`, which means the scope resolver,
    the configured cost policy, the configured calibrator and
    `autonomy.pipeline.decision_inputs` are all on the path — the same assembly
    `training/decision_replay.py` uses, so a self-check that passes is a
    statement about the code the benchmark measures.
    """
    return pipeline.decide(
        source='192.0.2.1', vector=vector, math_result=math_result,
        ml=MLResult(error='not_loaded'),
        quality=DataQualityResult.evaluate(vector),
        identity_confidence='HIGH', identity_origin='direct_peer',
        network_enforceable=True, enforcement_scope='NETWORK_SOURCE',
        enforcement_healthy=True, clock_sane=True)


def run(calibrator_path=None, *, config=None):
    """Push both fixtures through MathRisk, the calibrator and the authority.

    Returns a document rather than raising: a self-check that crashes tells an
    operator less than one that reports which stage stopped answering.
    """
    engine = MathRiskEngine()
    quiet = _vector(QUIET_FRACTION, observations=24, seconds=60.0)
    loud = _vector(LOUD_FRACTION, observations=120, seconds=420.0)
    stages, failures = {}, []
    config = _config_for(config, calibrator_path)

    try:
        quiet_math = engine.evaluate(quiet)
        loud_math = engine.evaluate(loud)
        stages['math_risk'] = {
            'status': WIRED, 'version': loud_math.model_version,
            'quiet': round(quiet_math.score, 6), 'loud': round(loud_math.score, 6)}
        if not (math.isfinite(loud_math.score) and math.isfinite(quiet_math.score)):
            failures.append('math_risk produced a non-score')
        elif loud_math.score <= quiet_math.score:
            failures.append('math_risk does not separate the two fixtures')
    except Exception as exc:                                    # noqa: BLE001
        stages['math_risk'] = {'status': BROKEN, 'error': f'{type(exc).__name__}: {exc}'[:160]}
        return _document(stages, failures + ['math_risk raised'])

    # P15.5R §9. Asked of the loader the runtime uses, so this stage reports the
    # state a running sensor would be in rather than whatever this module can
    # make of the same file. The three build-compatibility questions it adds —
    # source quantity, formula version, a conservative bound — are the ones that
    # separate "a well-formed artifact" from "this build's artifact".
    state = calibration_loader.load_for(config)
    probability = {'quiet': None, 'loud': None}
    if state.status == calibration_loader.NOT_CONFIGURED:
        stages['calibrator'] = {
            'status': SKIPPED,
            'reason': ('no calibrator is configured (autonomy.calibrator_path); the '
                       'decision path degrades to CALIBRATION_UNAVAILABLE, which is '
                       'a supported state and not a fault')}
    else:
        for name, result in (('quiet', quiet_math), ('loud', loud_math)):
            probability[name] = calibration_loader.calibrated_probability(
                state, math_risk=result.score)
        usable = probability['loud'] is not None
        stages['calibrator'] = {
            'status': WIRED if usable else BROKEN,
            'loader_status': state.status,
            'version': state.version,
            'bound_to': state.model_version,
            'unit': state.unit,
            'reason': state.reason,
            'quiet': None if probability['quiet'] is None else round(probability['quiet'].value, 6),
            'loud': None if probability['loud'] is None else round(probability['loud'].value, 6),
            'loud_conservative_bound': None if probability['loud'] is None
                                       else probability['loud'].lower}
        if not usable:
            # The mismatches that matter: an artifact bound to another formula,
            # mapping another quantity, or stating no bound on its own estimate.
            failures.append(f'the configured calibrator produced no probability for a '
                            f'{loud_math.model_version} score: '
                            f'{state.reason or state.status}')

    try:
        # §23, §24. Built by the real factory, so the cost policy, the gates and
        # the calibrator are this deployment's rather than this module's — and
        # then forced enabled and autonomous, deliberately, because
        # `autonomy_enabled` is the first gate and an authority in shadow refuses
        # at the door, leaving every gate below it untested. A self-check that
        # stopped at the enablement gate would have passed throughout P15.4.
        #
        # The two `attach_` flags are not decoration. On a genuinely autonomous
        # host deployment the factory would otherwise attach a real
        # `HostEnforcer`, and a self-check that hands a synthetic fixture to a
        # firewall helper is a self-check that blocks 192.0.2.1 every time
        # `doctor` runs. The journal is the same problem in the other
        # direction: these fixtures are not decisions about anybody, and an
        # entry carrying one would sit in the forensic record looking exactly
        # like a decision about a real source.
        pipeline = pipeline_from_config(config, attach_enforcer=False,
                                        attach_journal=False)
        pipeline.authority.activate(mode=AUTONOMOUS)
        stages['contracts'] = {
            'status': WIRED,
            'feature_schema_supported': FEATURE_SCHEMA.supports(quiet.schema_version),
            'feature_schema_current': FEATURE_SCHEMA.current,
            'math_version': loud_math.model_version,
            'cost_policy': pipeline.cost_policy.summary(),
            'scope_resolver': pipeline.scopes.version,
            'policy_guard_version': POLICY_GUARD_VERSION,
            'authority_version': pipeline.authority.version,
            'pipeline_version': pipeline.version}
        if not FEATURE_SCHEMA.supports(quiet.schema_version):
            failures.append('the fixture schema is not one this build serves')
        if pipeline.enforcer is not None:
            failures.append('the self-check pipeline holds an enforcer')

        quiet_outcome = _decide(pipeline, quiet, quiet_math)
        loud_outcome = _decide(pipeline, loud, loud_math)
        quiet_record, loud_record = quiet_outcome.record, loud_outcome.record
        eligible = loud_record.action == TEMP_BLOCK
        stages['authority'] = {
            'status': WIRED, 'version': pipeline.authority.version,
            'mode': pipeline.authority.mode, 'enabled': pipeline.authority.enabled,
            'quiet_action': quiet_record.action,
            'loud_action': loud_record.action,
            'loud_temp_block_eligible': eligible,
            'loud_cost_profile': loud_outcome.resolution.profile.name,
            'loud_threshold': round(loud_outcome.resolution.profile.threshold, 6),
            'loud_reasons': list(loud_record.reason_codes)[:8],
            'enforcement_withheld': loud_outcome.enforcement_withheld,
            'enforced': bool(loud_record.enforced)}
        if quiet_record.action == TEMP_BLOCK:
            failures.append('the quiet fixture was eligible to block')
        if loud_outcome.execution is not None:
            failures.append('the self-check reached an enforcer')
        if not eligible and stages['calibrator']['status'] != SKIPPED:
            failures.append(f'the loud fixture was not eligible to block: '
                            f'{list(loud_record.reason_codes)[:6]}')
        elif not eligible:
            # Without a calibrator there is no probability, `calibrated_estimate`
            # refuses, and no autonomous block is possible at any score. That is
            # the documented degraded posture rather than a broken join, so the
            # check reports the chain as connected and withholds the eligibility
            # conclusion instead of failing on a state the system chose.
            stages['authority']['eligibility_withheld'] = (
                'no calibrator was configured, so CALIBRATION_UNAVAILABLE refuses '
                'every block by design; wiring above the calibrator is confirmed '
                'and eligibility is not asserted')
        if loud_record.enforced or quiet_record.enforced:
            failures.append('a self-check decision was marked enforced')
    except Exception as exc:                                    # noqa: BLE001
        stages['authority'] = {'status': BROKEN,
                               'error': f'{type(exc).__name__}: {exc}'[:160]}
        failures.append('the authority raised')

    return _document(stages, failures)


def _document(stages, failures):
    return {
        'fixtures': fixtures(),
        'stages': stages,
        'verdict': WIRED if not failures else BROKEN,
        'failures': failures,
        'touched_enforcement': False,
        'has_enforcement_privilege': AutonomousDecisionAuthority.has_enforcement_privilege,
        'what_this_is_not': ('a detection measurement. Two synthetic vectors say '
                             'whether the pipeline is connected, and nothing at '
                             'all about whether its answers are right'),
    }


def check(config=None, *, calibrator_path=None):
    """The `doctor` entry point. Reports HEALTHY / UNAVAILABLE, never a score.

    P15.5R §23, §24: this now runs against the deployment's own configuration
    through `autonomy.pipeline.from_config` — the factory a running sensor uses.
    Until this cycle there was no configuration setting naming a calibrator, so
    the check ran on defaults, reached the authority with no probability, and
    reported honestly that eligibility had not been asserted. With
    `autonomy.calibrator_path` it exercises the join it was written for.

    A deployment that configures no calibrator still gets the withheld answer
    rather than a failure. That is the documented degraded posture, and a
    `doctor` that called it broken would be calling shadow mode broken.
    """
    document = run(calibrator_path, config=config)
    return {'status': 'HEALTHY' if document['verdict'] == WIRED else 'UNAVAILABLE',
            'verdict': document['verdict'],
            'fixture_version': SELFCHECK_FIXTURE_VERSION,
            'stages': {name: stage['status'] for name, stage in document['stages'].items()},
            'failures': document['failures'],
            'limitations': ['wiring_only_not_a_detection_measurement']}


if __name__ == '__main__':
    print(json.dumps(run('models/mathrisk-cal-v4-isotonic.json'), indent=1))
