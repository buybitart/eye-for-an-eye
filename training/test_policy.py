"""The P15.3 acceptance policy, written before the locked benchmark exists.

§3 and §49. Acceptance criteria written after a result are not criteria, they
are a description of the result with a verdict attached. So this module emits
`reports/P15_3_TEST_POLICY.json` from the values that are *actually in force* —
imported from `autonomy.cost`, `autonomy.authority`, `autonomy.evaluation`,
`dataset.split` and `training.observability` rather than transcribed — and it is
committed before `dataset-generalization-test-v2` is generated.

Transcription would defeat the purpose twice over: a number copied by hand can
be copied wrong, and a number copied by hand can be quietly *changed* later
while the policy still reads as though it were predeclared. Importing them means
the committed policy and the running system cannot disagree without the digest
changing, and the digest is recorded in the freeze commit.

What this file deliberately does not contain: a recall target. There is none
(§10, and `docs/GENERALIZATION_POLICY.md`). Gate C asks whether every critical
observable family is detected at all and whether unseen behaviour survives; it
does not ask for a number, and inventing one now would be the same error as
inventing one afterwards, merely earlier.
"""
import hashlib
import json
from pathlib import Path

from dataset import split as split_module
from eye_for_an_eye.autonomy.authority import AUTHORITY_VERSION, DecisionGates
from eye_for_an_eye.autonomy.cost import COST_POLICY_VERSION, CostPolicy
from eye_for_an_eye.autonomy.evaluation import ReleaseThresholds
from eye_for_an_eye.decision import math_risk
from eye_for_an_eye.security.enforcement import MAX_TTL_SECONDS
from . import observability

TEST_POLICY_VERSION = 'p15.3-test-policy-v1'

#: The corpus this policy will be applied to, named before it exists so it
#: cannot be swapped for a friendlier one afterwards (§2, §66).
LOCKED_CORPUS = {
    'name': 'dataset-generalization-test-v2',
    'matrix': 'dataset/scenarios/matrix-generalization-v2.toml',
    'seed_salt': 'p15.3-locked',
    'scored': 'exactly once',
    'prior_test_status': (
        'reports/P15_2_LOCKED_TEST.json is diagnostic evidence from here on. It '
        'was inspected during P15.3 and may not be the final evidence for Gate C '
        'after P15.3 changes'),
}

#: §19, §40. Stated here so a reviewer can check the corpus against a claim made
#: before the corpus existed.
DATA_RULES = [
    'no raw sensitive payload is stored; credential-shaped traffic records shape '
    'and count, never content',
    'scenario identity, generator name, seed, salt and label are provenance '
    'metadata and never enter the ML feature vector or MathRisk',
    'every source address is drawn from RFC 5737 documentation ranges and nothing '
    'is transmitted anywhere',
    'source groups do not span splits; assert_no_leakage must pass on the '
    'combined fitted and locked corpora',
]

#: §20. Repeated in the policy because a leak here invalidates the benchmark
#: without producing an error anywhere.
FORBIDDEN_FEATURES = [
    'a previous final action', 'block status', 'would_block',
    'a PolicyGuard result', 'a cost decision', 'any label-derived quantity',
]

#: What must still hold when a block is taken, at the moment the locked test is
#: scored (§72, §74). None of these was relaxed in P15.3 and none may be.
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

#: §50. The interpretation is fixed now so that a zero-detection family after the
#: test cannot be reclassified into an excuse.
GATE_C_FAILS_IF = [
    'a malicious IN_SCOPE_OBSERVABLE family eligible for TEMP_BLOCK is detected '
    'on zero sources; aggregate recall may not hide it',
    'unseen-family recall is zero while seen-family recall is not',
    'an uncalibrated quantity reaches the cost arithmetic, or a calibrator is '
    'applied to a model it was not fitted against, or a non-finite value '
    'produces an action',
    'the report omits the seen/unseen split, the per-family table or the worst '
    'family',
    'leakage is found and not excluded',
    'runtime parity fails for the production probability path',
]
GATE_C_DOES_NOT_FAIL_BECAUSE = [
    'supervised ML remains auxiliary rather than authoritative',
    'an OUT_OF_SCOPE family is undetected',
    'a TEMP_BLOCK-ineligible profile produced no blocks',
    'recall is low: there is no recall target, and inventing one after the '
    'result would be the same error in the opposite direction',
]

#: §84. P15.3 may not buy Gate C with Gate E.
GATE_E_REGRESSION_LIMITS = {
    'false_blocks_per_1000_benign': 'at most 1.0, measured on trusted ground '
    'truth over the full decision path',
    'block_precision': 'at least 0.95',
    'minimum_benign_sources': 500,
    'minimum_malicious_sources': 50,
    'degenerate_decision': 'allow-all or block-all is an automatic FAIL, '
    'reported on every branch of the release gate',
    'hard_negatives': 'every hard-negative family must be present and scored; '
    'the three P15.3 compositions exist specifically as controls for the three '
    'MathRisk v2 terms',
    'uncertainty': 'zero observed false blocks is reported with its Wilson upper '
    'bound and never as proven zero',
}


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
    families = _families()
    body = {
        'test_policy_version': TEST_POLICY_VERSION,
        'written': 'before dataset-generalization-test-v2 was generated or scored',
        'objective': ('close Gate C scientifically: demonstrate that detection '
                      'survives behaviour no fitted component has seen, on a '
                      'benchmark no decision was tuned against'),
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
        'required_safety_conditions': SAFETY_CONDITIONS,
        'data_rules': DATA_RULES,
        'forbidden_features': FORBIDDEN_FEATURES,
        'gate_c': {
            'fails_if_any': GATE_C_FAILS_IF,
            'does_not_fail_because': GATE_C_DOES_NOT_FAIL_BECAUSE,
            'recall_target': None,
            'note': ('a critical, fully observable, TEMP_BLOCK-eligible family '
                     'with zero meaningful detection keeps Gate C FAIL (§52)'),
        },
        'gate_e_regression_limits': GATE_E_REGRESSION_LIMITS,
        'release_thresholds': ReleaseThresholds().explain(),
        'decision_gates': gates.explain(),
        'cost_policy': {
            'version': COST_POLICY_VERSION,
            'digest': policy.digest,
            'unchanged_in_p15_3': True,
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
            'authority': AUTHORITY_VERSION,
            'cost_policy': COST_POLICY_VERSION,
        },
        'scoring_rule': (
            'the locked benchmark is scored exactly once. If it fails, the '
            'candidate fails: no weight, threshold, gate, feature or calibrator '
            'is changed and the test rerun. Gate C remains FAIL and a future '
            'cycle designs a new test (§66, §83)'),
        'what_this_does_not_claim': [
            'generalisation to real Internet traffic: every corpus is synthetic',
            'detection of behaviour sharing no primitive with anything known',
            'that supervised ML is production-ready; it remains auxiliary',
        ],
    }
    body['digest'] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body


def write(path):
    Path(path).write_text(json.dumps(document(), indent=1) + '\n', encoding='utf-8')
    return path
