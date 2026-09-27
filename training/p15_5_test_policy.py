"""The P15.5 acceptance standard, written before the benchmark exists. §21.

Same discipline as P15.3's and P15.4's policies, and the same reason: criteria
written after a result are not criteria, they are a description of the result
with a verdict attached. Every value here is **imported from what is actually in
force** rather than transcribed, so the committed standard and the running system
cannot disagree without the digest changing — and the digest goes into the freeze
commit, before the locked corpus is generated.

### What this cycle's policy asks that the last one could not

P15.4's policy asked whether authentication evidence had been fixed and whether
safety was spread evenly across profiles. Both were good questions and both were
answered by a benchmark that detected nothing, because the thing neither question
reached was whether the parts were *connected*.

So P15.5 adds one condition to Gate C that no previous cycle had: the
whole-system smoke test must pass. A candidate whose components are individually
correct and whose pipeline does not carry a decision from a packet to a firewall
request is not a candidate, whatever its per-family numbers say.

### Profile eligibility is a rule, not a list

§15 says to predeclare which profiles may block before the results exist, and the
honest way to do that is to declare the *rule* and let it evaluate:

    TEMP_BLOCK_ELIGIBLE  iff  the cost profile permits a network block
                         and  the calibrator's maximum conservative bound
                              reaches that profile's cutoff

Both halves are facts about the candidate rather than choices about the outcome.
The first is `CostProfile.network_block_permitted`, unchanged since P15.1. The
second is arithmetic over the artifact in force. `api` is the profile this turns
on, and §14 is explicit that a `NOT_SUPPORTED` verdict there is a policy refusing
to act on evidence it cannot bound — not a model failure and not a gate failure.

The rule is committed in this module before the P15.5 calibrator is fitted. The
document it produces is written afterwards, which is the only order in which
"the rule was not chosen to suit the answer" means anything.

### What this file deliberately still does not contain

A recall target. P15.3 had none, P15.4 had none, and inventing one now would be
the same error as inventing one after the result, merely earlier
(`docs/GENERALIZATION_POLICY.md`).

A threshold chosen from any P15.5 measurement. Nothing here moves a cost, a gate
or a cutoff; the brief forbids it in three separate places and
`tests/test_p15_4_invariants.py` fails the build if one moves.
"""
import hashlib
import json
from pathlib import Path

from eye_for_an_eye.autonomy.authority import AUTHORITY_VERSION, DecisionGates
from eye_for_an_eye.autonomy.cost import COST_POLICY_VERSION, CostPolicy
from eye_for_an_eye.autonomy.evaluation import ReleaseThresholds
from eye_for_an_eye.autonomy.maturity import MATURITY_SCHEMA_VERSION, MaturityPolicy
from eye_for_an_eye.autonomy.selfcheck import SELFCHECK_FIXTURE_VERSION
from eye_for_an_eye.compatibility import CONTRACTS
from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision import composition as composition_module
from eye_for_an_eye.decision import families as families_module
from eye_for_an_eye.decision import math_risk
from eye_for_an_eye.decision.features import MODEL_SCHEMAS, SCHEMA_VERSION
from eye_for_an_eye.decision.policy import POLICY_GUARD_VERSION
from eye_for_an_eye.security.enforcement import MAX_TTL_SECONDS

from . import observability
from .p15_5_calibration_plan import CALIBRATION_PLAN_VERSION

TEST_POLICY_VERSION = 'p15.5-test-policy-v1'

ROOT = Path(__file__).resolve().parents[1]

#: The artifact whose bound decides profile eligibility. Named, so the policy and
#: the release cannot quietly be about different files.
CALIBRATOR = 'models/mathrisk-cal-v4-isotonic.json'

#: Named before it exists, so it cannot be swapped for a friendlier one.
LOCKED_CORPUS = {
    'name': 'dataset-p15-5-locked-v1',
    'matrix': 'dataset/scenarios/matrix-p15-5-locked-v1.toml',
    'seed_salt': 'p15.5-locked',
    'scored': 'exactly once',
    'withheld_families': ['withheld-backup-sweep', 'withheld-credential-drift'],
    'what_the_rest_of_it_measures': (
        'stability under a different random draw. Every scenario except the two '
        'withheld ones is carried over from matrix-p15-4-locked-v1 unchanged, so '
        'the two benchmarks are comparable family by family and nothing about '
        'those families is evidence of generalisation'),
    'why_the_p15_4_withheld_pair_is_absent': (
        'mobile-app-sync and probe-then-login were scored once on the P15.4 '
        'benchmark. They remain barred from every fitting matrix and always '
        'will, but they are no longer unseen, and a second score is not a second '
        'independent result however carefully it is labelled'),
}

#: §27. Every one of these failing is a Gate C failure. Recall is not among them.
GATE_C_FAILS_IF = [
    'a score is used as a probability, or a probability as a score',
    'the feature schema in force is not one this build can serve',
    'the calibrator is not bound to the formula that produced the scores it maps',
    'a calibration example appears in the locked corpus',
    'a predeclared critical observable block-eligible family detects nothing',
    'the decision is degenerate: everything blocked, or nothing',
    'the whole-system smoke test fails',
]

#: §27, restated so that a reader cannot infer a criterion that is not there.
GATE_C_DOES_NOT_FAIL_BECAUSE = [
    'recall is below any particular number; no target was set, before or after',
    'a family classified IN_SCOPE_PARTIALLY_OBSERVABLE detects nothing',
    'a profile predeclared TEMP_BLOCK_NOT_SUPPORTED blocks nothing (§29)',
    'a source the maturity gate refused was in fact malicious; that gate is a '
    'floor on evidence and refusing is what it is for',
]

#: §28. False-positive safety, measured rather than asserted.
GATE_E_REQUIRES = [
    'a measured block precision, or an explicit statement that no block was taken',
    'a measured false-block rate per 1000 benign sources, with its interval',
    'new withheld hard negatives that were scored for the first time',
    'authentication hard negatives: batch API, service account, stale credential, '
    'admin login mistakes',
    'non-degenerate positive detection',
    'no catastrophic per-profile false-positive rate',
]

#: §5, §6, §7. The smoke requirements, named here so the policy and the harness
#: cannot drift apart without the digest moving.
SMOKE_REQUIREMENTS = {
    'path': ['packet', 'parser', 'normalization', 'authentication outcome',
             'AuthLedger', 'FeatureVector', 'family scores', 'EvidenceComposition',
             'MathRisk v4', 'v4 calibrator', 'EvidenceMaturity', 'ExpectedLoss',
             'AutonomousDecisionAuthority', 'PolicyGuard',
             'validated EnforcementRequest'],
    'behaviours': {
        'normal browser': 'no TEMP_BLOCK',
        'authenticated batch API': 'no TEMP_BLOCK, and the outcome was observed',
        'admin login mistakes': 'no TEMP_BLOCK',
        'credential spray': 'AUTH_BEHAVIOR above zero',
        'brute force': 'AUTH_BEHAVIOR above zero',
        'block-eligible scanner': 'TEMP_BLOCK, and a validated EnforcementRequest',
    },
    'intermediate_values_asserted': [
        'an AuthenticationEvent reached the correlation engine',
        'the schema-2 authentication columns were populated',
        'at least one evidence family was observed',
        'every window was scored by the formula in force',
        'the calibrator was invoked and returned a finite probability',
        'maturity was evaluated for every window',
    ],
    'not_evidence_of': ('detection quality. Six behaviours is a wiring check and '
                        '§41 forbids reading any number from it as a result'),
}

#: Blockers that are release blockers whatever the benchmark says.
RELEASE_BLOCKERS = [
    'a literal schema comparison on the decision path',
    'a configured component that reports NOT_CONFIGURED when it is broken',
    'an unbounded metric label',
    'a decision self-check that does not run from doctor and the readiness gate',
    'any block that is not temporary, or any TTL above the ceiling',
    'a firewall object left behind by the enforcement suite',
]


def profile_eligibility(calibrator_path=None):
    """§15. The rule, evaluated against the artifact in force.

    Returns one entry per cost profile. `TEMP_BLOCK_NOT_SUPPORTED` has two
    possible reasons and they are different claims, so they are reported
    separately: a profile that may not network-block at all is a policy decision
    taken in P15.1, and a profile whose cutoff the calibrator cannot reach is an
    arithmetic fact about how much calibration evidence exists.
    """
    policy = CostPolicy()
    path = Path(calibrator_path or ROOT / CALIBRATOR)
    bound, version, digest = None, '', ''
    if path.is_file():
        calibrator = cal.load(path)
        version = calibrator.version
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        bound = max((value for _, value in calibrator.lower_knots), default=None)
    out = {}
    for name, profile in sorted(policy.profiles.items()):
        cutoff = round(profile.threshold, 6)
        if not profile.network_block_permitted:
            out[name] = {'eligibility': 'TEMP_BLOCK_NOT_SUPPORTED', 'cutoff': cutoff,
                         'reason': 'the cost policy permits no network block on this '
                                   'profile at any probability',
                         'reason_kind': 'policy'}
            continue
        reachable = bound is not None and bound >= profile.threshold
        out[name] = {
            'eligibility': 'TEMP_BLOCK_ELIGIBLE' if reachable else 'TEMP_BLOCK_NOT_SUPPORTED',
            'cutoff': cutoff,
            'maximum_conservative_bound': None if bound is None else round(bound, 6),
            'reason': ('the calibrator can bound a probability above this cutoff'
                       if reachable else
                       'the calibrator cannot bound any probability above this '
                       'cutoff, so no evidence at any strength authorises a block'),
            'reason_kind': 'evidence' if reachable else 'calibration_width',
            'supported_actions_instead': [] if reachable
                                         else ['WATCH', 'CHALLENGE', 'RATE_LIMIT'],
        }
    return {
        'rule': ('TEMP_BLOCK_ELIGIBLE iff the cost profile permits a network block '
                 'and the calibrator maximum conservative bound reaches its cutoff'),
        'rule_committed': ('in training/p15_5_test_policy.py, before the P15.5 '
                           'calibrator was fitted'),
        'calibrator': version,
        'calibrator_sha256': digest,
        'maximum_conservative_bound': None if bound is None else round(bound, 6),
        'profiles': out,
        'api_autonomous_temp_block': out.get('api', {}).get('eligibility', 'UNKNOWN'),
        'note': ('§14: a NOT_SUPPORTED verdict here is a policy refusing to act on '
                 'evidence it cannot bound. It is not a model failure and it is '
                 'not a Gate C failure (§29)'),
    }


def _critical_families():
    """Families that must show some detection, from the observability document.

    Block-eligible and fully observable. A family classified
    IN_SCOPE_PARTIALLY_OBSERVABLE is excluded because the classification says the
    sensor cannot represent what separates it — `probe-repeated` is the P15.5
    case, reclassified before the benchmark existed and on measured evidence.
    """
    families = observability.FAMILIES
    return sorted(
        name for name, (klass, enforcement, *_) in families.items()
        if klass == observability.IN_SCOPE_OBSERVABLE
        and enforcement == observability.TEMP_BLOCK_ELIGIBLE)


def _digest(mapping):
    return hashlib.sha256(
        json.dumps(mapping, sort_keys=True, separators=(',', ':'), default=str).encode()
    ).hexdigest()


def document(calibrator_path=None):
    gates = DecisionGates()
    policy = CostPolicy()
    maturity = MaturityPolicy()
    eligibility = profile_eligibility(calibrator_path)
    body = {
        'test_policy_version': TEST_POLICY_VERSION,
        'written': 'before dataset-p15-5-locked-v1 was generated or scored',
        'objective': ('demonstrate that the complete product is connected: that a '
                      'decision travels from a packet to a validated enforcement '
                      'request, that every seam between two components is checked '
                      'by something, and that the safety properties measured in '
                      'P15.4 still hold'),
        'not_the_objective': ('a better detection number. P15.5 adds no evidence '
                              'and no intelligence; a higher recall obtained this '
                              'cycle would be a sign that something was tuned'),
        'locked_corpus': LOCKED_CORPUS,
        'schema_compatibility': {
            'feature_schema_in_force': SCHEMA_VERSION,
            'servable_feature_schemas': sorted(MODEL_SCHEMAS),
            'contracts': {name: contract.explain()
                          for name, contract in sorted(CONTRACTS.items())},
            'literal_pins_permitted_on_the_decision_path': 0,
        },
        'formula': {
            'math_risk': math_risk.VERSION,
            'family_scores': families_module.FAMILY_SCORE_VERSION,
            'composition': composition_module.COMPOSITION_VERSION,
            'authority': AUTHORITY_VERSION,
            'policy_guard': POLICY_GUARD_VERSION,
            'unchanged_this_cycle': True,
            'why': ('§19. Final validation prefers no formula change, and the four '
                    'weak families were reviewed without one: three separate '
                    'correctly from their controls and are limited by calibration '
                    'width, and the fourth cannot be separated by any traffic '
                    'feature at all'),
        },
        'calibration': {
            'plan_version': CALIBRATION_PLAN_VERSION,
            'plan': 'reports/P15_5_CALIBRATION_PLAN.json',
            'calibrator': eligibility['calibrator'],
            'calibrator_sha256': eligibility['calibrator_sha256'],
            'unit': cal.SOURCE,
            'schema_version': cal.CALIBRATION_SCHEMA_VERSION,
            'maximum_conservative_bound': eligibility['maximum_conservative_bound'],
            'fits': 1,
        },
        'policy_digests': {
            'cost_policy_version': COST_POLICY_VERSION,
            'cost_policy': policy.digest,
            'maturity_schema_version': MATURITY_SCHEMA_VERSION,
            'maturity_policy': _digest(maturity.explain()),
            'evidence_diversity_policy': _digest({
                'minimum_signal_diversity': gates.explain().get('minimum_signal_diversity'),
                'minimum_behavioural_diversity': gates.explain().get(
                    'minimum_behavioural_diversity'),
                'carrying_families': sorted(families_module.CARRYING_FAMILIES),
                'corroborating_families': sorted(families_module.CORROBORATING_ONLY),
                'interactions': sorted((a, b, round(k, 6))
                                       for a, b, k, _ in composition_module.INTERACTIONS)}),
            'decision_gates': _digest(gates.explain()),
            'release_thresholds': _digest(ReleaseThresholds().explain()),
        },
        'profile_block_eligibility': eligibility,
        'observability': {
            'schema_version': observability.OBSERVABILITY_SCHEMA_VERSION,
            'critical_families': _critical_families(),
            'classification_changes_this_cycle': {
                'probe-repeated': ('IN_SCOPE_OBSERVABLE -> '
                                   'IN_SCOPE_PARTIALLY_OBSERVABLE, from a measured '
                                   'comparison against three benign controls, '
                                   'recorded before the locked corpus existed'),
            },
            'by_class': {klass: sorted(name for name, entry in observability.FAMILIES.items()
                                       if entry[0] == klass)
                         for klass in observability.CLASSES},
        },
        'gate_c': {'fails_if': GATE_C_FAILS_IF,
                   'does_not_fail_because': GATE_C_DOES_NOT_FAIL_BECAUSE},
        'gate_e': {'requires': GATE_E_REQUIRES,
                   'thresholds': ReleaseThresholds().explain()},
        'whole_system_smoke': SMOKE_REQUIREMENTS,
        'decision_self_check': {
            'fixture_version': SELFCHECK_FIXTURE_VERSION,
            'runs_from': ['doctor', 'the autonomy readiness gate'],
            'tests': 'wiring only (§41); never reported as detection evidence',
        },
        'safety_invariants_unchanged': {
            'maximum_block_ttl_seconds': MAX_TTL_SECONDS,
            'permanent_block_possible': False,
            'decision_gates': gates.explain(),
            'baseline': 'reports/P15_4_BASELINE.json, still enforced by tests',
        },
        'release_blockers': RELEASE_BLOCKERS,
    }
    body['digest'] = _digest(body)
    return body


def write(path, calibrator_path=None):
    Path(path).write_text(json.dumps(document(calibrator_path), indent=1) + '\n',
                          encoding='utf-8')
    return path


if __name__ == '__main__':
    print(write(ROOT / 'reports' / 'P15_5_TEST_POLICY.json'))
