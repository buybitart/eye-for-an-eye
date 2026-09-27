"""The P15.4 acceptance policy, written before the locked benchmark exists. §69.

Same discipline as `training/test_policy.py` and for the same reason: acceptance
criteria written after a result are not criteria, they are a description of the
result with a verdict attached. Every number below is **imported from the values
actually in force** rather than transcribed, so the committed policy and the
running system cannot disagree without the digest changing, and the digest goes
into the freeze commit.

### What is different about this cycle's policy

P15.3's policy asked a question about generalisation to unseen *compositions*.
P15.4 asks two questions that P15.3 could not:

1. **Does the system still not act on legitimate authentication?** This is the
   defect the cycle exists to fix, and the failure mode is asymmetric — it is
   easy to fix by refusing to act on anything, and a policy that only measured
   detection would score that as a success.

2. **Is safety spread evenly across site profiles?** P15.1, P15.2 and P15.3 all
   reported that per-profile numbers could not be produced. A false-block rate
   averaged over a benchmark hides the profile where the system is worst, so the
   policy asks for the worst profile by name and not only for the mean.

### What this file deliberately does not contain

A recall target, for the same reason P15.3 had none (§10,
`docs/GENERALIZATION_POLICY.md`). Inventing one now would be the same error as
inventing one after the result, merely earlier.

A threshold chosen from any P15.4 measurement. §61 and §62 forbid moving `C_FP`,
`C_FN` or a profile cutoff to make results pass, and nothing here does: every
gate below is either an unchanged P15.3 value, a safety invariant that has never
moved, or a question with no number attached.
"""
import hashlib
import json
from pathlib import Path

from dataset import split as split_module
from eye_for_an_eye.autonomy.authority import AUTHORITY_VERSION, DecisionGates
from eye_for_an_eye.autonomy.cost import COST_POLICY_VERSION, CostPolicy
from eye_for_an_eye.autonomy.evaluation import ReleaseThresholds
from eye_for_an_eye.autonomy.maturity import MATURITY_SCHEMA_VERSION, MaturityPolicy
from eye_for_an_eye.decision import auth as auth_module
from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision import composition as composition_module
from eye_for_an_eye.decision import families as families_module
from eye_for_an_eye.decision import math_risk
from eye_for_an_eye.decision.features import SCHEMA_VERSION as FEATURE_SCHEMA_VERSION
from eye_for_an_eye.security.enforcement import MAX_TTL_SECONDS

from . import observability

TEST_POLICY_VERSION = 'p15.4-test-policy-v1'

#: Named before it exists, so it cannot be swapped for a friendlier one (§2, §66).
LOCKED_CORPUS = {
    'name': 'dataset-p15-4-locked-v1',
    'matrix': 'dataset/scenarios/matrix-p15-4-locked-v1.toml',
    'seed_salt': 'p15.4-locked',
    'scored': 'exactly once',
    'withheld_families': ['withheld-mobile-sync', 'withheld-probe-login'],
    'what_the_rest_of_it_measures': (
        'stability under a different random draw and different source addresses. '
        'Every family except the two withheld ones has been seen this cycle, so '
        'nothing about them is evidence of generalisation'),
    'prior_test_status': (
        'reports/P15_3_LOCKED_TEST.json was scored under math-risk-v3 and is not '
        'comparable row for row: the formula, the feature schema and the corpus '
        'all changed. It stays readable as the record of what P15.3 measured'),
}

#: §5, §15, §16. The question this cycle exists to answer, stated so that a
#: system which achieved it by refusing to act on anything would still fail.
AUTHENTICATION_GATE_FAILS_IF = [
    'a benign authenticated family is blocked on any source: authenticated batch, '
    'high-rate API, signed webhook, admin console, service account, stale '
    'credential client, asset fetch, or the withheld mobile app sync',
    'a source is treated as more suspicious for authenticating successfully, in '
    'any family, at any rate',
    'an UNKNOWN authentication outcome contributes to abuse evidence anywhere',
    'a single account failing repeatedly reaches TEMP_BLOCK without other '
    'evidence: an administrator mistyping a password and a job retrying an old '
    'one are both ordinary',
    'AUTH_BEHAVIOR is the only carrying family and produces a block on its own '
    'from an ambiguous observation',
    'every malicious authentication family is undetected, which would mean the '
    'benign safety was bought by switching the evidence off',
]

#: §41, §45. The per-profile question, askable for the first time.
PER_PROFILE_GATE_FAILS_IF = [
    'the report omits a per-profile table, or omits the worst profile by name',
    'any profile has a false-block rate above the aggregate limit, even when the '
    'aggregate passes',
    'the payment_webhook profile produces a network block at any probability',
    'a profile appears in the corpus with no benign sources, which would make '
    'its false-block rate undefined and its detection rate flattering',
]

#: §49, §50. The narrow claim the withheld pair supports.
GENERALIZATION_GATE_FAILS_IF = [
    'either withheld family is found in any fitting corpus',
    'the withheld benign family is blocked on any source',
    'the withheld positive is scored, found wanting, and then explained away by '
    'reclassifying it: its classification in training/observability.py was '
    'committed before the corpus existed and may not be revised after',
    'the report presents stability under a fresh random draw as evidence of '
    'generalisation',
]

#: §54, §68. TEMP_BLOCK is a strong action; low-and-slow support may not buy
#: detection with exposure.
GATE_C_FAILS_IF = [
    'a malicious IN_SCOPE_OBSERVABLE family eligible for TEMP_BLOCK is detected '
    'on zero sources; aggregate recall may not hide it',
    'an uncalibrated quantity reaches the cost arithmetic, or a calibrator is '
    'applied to a formula or model it was not fitted against, or a non-finite '
    'value produces an action',
    'the report omits the per-family table, the per-profile table or the worst '
    'family',
    'leakage is found and not excluded',
    'runtime parity fails for the production probability path',
    'the new maturity roads admit benign sources the fixed floor excluded and '
    'any of them is blocked',
]
GATE_C_DOES_NOT_FAIL_BECAUSE = [
    'supervised ML remains auxiliary rather than authoritative',
    'an OUT_OF_SCOPE family is undetected',
    'a TEMP_BLOCK-ineligible profile produced no blocks',
    'recall is low: there is no recall target',
    'a family that was detectable under math-risk-v3 only through credential '
    'presence is no longer detected. That quantity was measured to be '
    'non-evidence, and losing a detection that rested on it is the fix working',
]

#: §84 carried forward: P15.4 may not buy detection with false blocks.
GATE_E_REGRESSION_LIMITS = {
    'false_blocks_per_1000_benign': 'at most 1.0, measured on trusted ground '
    'truth over the full decision path, per source',
    'block_precision': 'at least 0.95',
    'minimum_benign_sources': 500,
    'minimum_malicious_sources': 50,
    'degenerate_decision': 'allow-all or block-all is an automatic FAIL',
    'hard_negatives': 'every hard-negative family must be present and scored, '
    'including the seven P15.4 authentication controls',
    'uncertainty': 'zero observed false blocks is reported with its Wilson upper '
    'bound and never as proven zero',
    'per_profile': 'the limit applies to the worst profile, not only the mean',
}

#: What must still hold when a block is taken (§79). None was relaxed in P15.4.
SAFETY_CONDITIONS = [
    'no hack-back, no counter-attack, no scanning back',
    'no permanent automatic block: every autonomous block carries a TTL',
    f'automatic TTL ceiling {MAX_TTL_SECONDS}s (12 hours), enforced in '
    'security/enforcement.py and unreachable by configuration',
    'owned nftables objects only; never a rule the operator wrote',
    'management networks, the allowlist and trusted proxies are protected: '
    'PolicyGuard returns OBSERVE for a protected source before any arithmetic',
    'loopback, unspecified, multicast, link-local and local addresses protected',
    'CDN and proxy addresses never network-blocked, because the address carries '
    'everybody else',
    'the payment_webhook profile never network-blocks, at any probability',
    'the mass-block circuit breaker is enabled and its trips are reported',
    'a block requires a CalibratedProbability; MathRisk, ModelScore and '
    'AnomalyScore are refused by the expected-loss engine',
    'a non-finite probability produces no action',
]

#: §3, §10, §11. The authentication data rules, restated where the acceptance
#: standard can be checked against them.
DATA_RULES = [
    'no password, Authorization header value, raw token, cookie, secret or '
    'credential body is stored anywhere: not in a feature, not in a digest, not '
    'in a decision record',
    'a principal identifier is kept only as a keyed pseudonym derived with a '
    'process-local key that is never written to disk, and only from the plainly '
    'non-secret identifier half of a cleartext command',
    f'every authentication structure is bounded: at most '
    f'{auth_module.MAX_PRINCIPALS_PER_SOURCE} principals per source, a '
    f'{auth_module.AUTH_STATE_TTL_SECONDS}s TTL, an LRU, and a byte ceiling',
    'credential presence never independently creates AUTH_ABUSE evidence',
    'UNKNOWN is never treated as FAILURE and success is never invented',
    'site_group and profile_type are evaluation metadata and can reach no model',
    'every source address is drawn from RFC 5737 documentation ranges and '
    'nothing is transmitted anywhere',
]

FORBIDDEN_FEATURES = [
    'a previous final action', 'block status', 'would_block',
    'a PolicyGuard result', 'a cost decision', 'any label-derived quantity',
    'site_group', 'profile_type', 'scenario identity', 'generator name', 'seed',
]


def _families():
    """Per-family expectation, from the classification committed before the corpus."""
    out = {}
    for family, entry in sorted(observability.FAMILIES.items()):
        holdout = split_module.HOLDOUT.get(family)
        out[family] = {
            'class': entry[0],
            'enforcement_eligibility': entry[1],
            'seen_by_fitted_components': holdout is None,
            'withheld_to': holdout[0] if holdout else None,
            'expected_action': ('TEMP_BLOCK when every safety gate is satisfied, '
                                'otherwise a softer action naming the gate that '
                                'refused'
                                if entry[1] == observability.TEMP_BLOCK_ELIGIBLE
                                else 'ALLOW'),
            'critical_for_gate_c': (entry[0] == observability.IN_SCOPE_OBSERVABLE
                                    and entry[1] == observability.TEMP_BLOCK_ELIGIBLE),
        }
    return out


def document():
    gates = DecisionGates()
    policy = CostPolicy()
    maturity = MaturityPolicy()
    families = _families()
    body = {
        'test_policy_version': TEST_POLICY_VERSION,
        'written': 'before dataset-p15-4-locked-v1 was generated or scored',
        'objective': (
            'demonstrate that authentication evidence means outcome rather than '
            'presence: that no legitimate authenticated client is acted on, that '
            'repeated refusal across accounts is, and that neither was bought '
            'with the other'),
        'not_the_objective': (
            'increasing recall. TEMP_BLOCK is a strong action and a higher '
            'detection number obtained by lowering the bar is a worse system'),
        'locked_corpus': LOCKED_CORPUS,
        'observability_schema_version': observability.OBSERVABILITY_SCHEMA_VERSION,
        'in_scope_classes': {
            name: sorted(f for f, e in observability.FAMILIES.items() if e[0] == name)
            for name in observability.CLASSES},
        'families': families,
        'critical_families': sorted(f for f, e in families.items()
                                    if e['critical_for_gate_c']),
        'unseen_families': sorted(f for f, e in families.items()
                                  if not e['seen_by_fitted_components']),
        'authentication_gate': {'fails_if_any': AUTHENTICATION_GATE_FAILS_IF},
        'per_profile_gate': {'fails_if_any': PER_PROFILE_GATE_FAILS_IF},
        'generalization_gate': {'fails_if_any': GENERALIZATION_GATE_FAILS_IF},
        'gate_c': {
            'fails_if_any': GATE_C_FAILS_IF,
            'does_not_fail_because': GATE_C_DOES_NOT_FAIL_BECAUSE,
            'recall_target': None,
        },
        'gate_e_regression_limits': GATE_E_REGRESSION_LIMITS,
        'required_safety_conditions': SAFETY_CONDITIONS,
        'data_rules': DATA_RULES,
        'forbidden_features': FORBIDDEN_FEATURES,
        'release_thresholds': ReleaseThresholds().explain(),
        'decision_gates': gates.explain(),
        'maturity_policy': {
            'schema_version': MATURITY_SCHEMA_VERSION,
            'standard_observations': maturity.minimum_observations,
            'standard_seconds': maturity.minimum_observation_seconds,
            'standard_data_quality': maturity.minimum_data_quality,
            'long_duration_seconds': maturity.long_duration_seconds,
            'long_duration_observations': maturity.long_duration_observations,
            'strong_families': maturity.strong_families,
            'strong_observations': maturity.strong_observations,
            'unchanged_standard_floor': maturity.minimum_observations == 20,
        },
        'cost_policy': {
            'version': COST_POLICY_VERSION,
            'digest': policy.digest,
            'unchanged_in_p15_4': True,
            'decision_margin': policy.decision_margin,
            'release_margin': policy.release_margin,
            'profiles': {name: {'false_block': profile.false_block,
                                'false_allow': profile.false_allow,
                                'threshold': round(profile.threshold, 6),
                                'network_block_permitted': profile.network_block_permitted}
                         for name, profile in sorted(policy.profiles.items())},
        },
        'component_versions': {
            'math_risk': math_risk.VERSION,
            'family_scores': families_module.FAMILY_SCORE_VERSION,
            'composition': composition_module.COMPOSITION_VERSION,
            'authority': AUTHORITY_VERSION,
            'cost_policy': COST_POLICY_VERSION,
            'feature_schema': FEATURE_SCHEMA_VERSION,
            'auth_schema': auth_module.AUTH_SCHEMA_VERSION,
            'maturity_schema': MATURITY_SCHEMA_VERSION,
        },
        'calibration': {
            'unit': cal.SOURCE,
            'why': ('the cost model prices a wrongly blocked source and a block is '
                    'taken on one window, so a window-fitted probability understates '
                    'the risk of the action it authorises. Measured at 8.5 to 12.1 '
                    'times on the development corpus; see '
                    'reports/P15_4_CALIBRATION_UNIT.json'),
            'direction': ('fitting on sources makes the artifact stricter, not '
                          'looser: no cost and no threshold moves'),
            'bound_to_formula': math_risk.VERSION,
            'corpora': ['dataset-p15-4-cal-v1', 'dataset-p15-4-cal2-v1',
                        'dataset-p15-4-cal3-v1', 'dataset-p15-4-cal4-v1'],
            'why_four': ('a conservative bound is a Wilson interval over the '
                         'calibration data, so fitting on sources rather than windows '
                         'divides its example count by the windows a source produces '
                         'and widens every interval. On two corpora the bound '
                         'saturated at 0.9644, below the public_website and api '
                         'cutoffs, and no block was possible on either. More examples '
                         'is the remedy §36 names; a lower cutoff is the one §61 and '
                         '§62 forbid'),
        },
        'scoring_rule': (
            'the locked benchmark is scored exactly once. If it fails, the '
            'candidate fails: no weight, threshold, gate, feature or calibrator '
            'is changed and the test rerun. The gate remains FAIL and a future '
            'cycle designs a new test (§66, §83)'),
        'what_this_does_not_claim': [
            'generalisation to real Internet traffic: every corpus is synthetic',
            'that the two withheld families represent unseen behaviour in general; '
            'they are two arrangements of primitives this corpus already contains',
            'that supervised ML is production-ready; it remains auxiliary',
            'that a passive sensor can see authentication outcome inside TLS: it '
            'cannot, and UNKNOWN is the honest and common answer',
        ],
    }
    body['digest'] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body


def write(path):
    Path(path).write_text(json.dumps(document(), indent=1) + '\n', encoding='utf-8')
    return path
