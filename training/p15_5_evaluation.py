"""The P15.5 locked measurement: one corpus, one calibrator, one run. §25, §27-§30.

Built on `training/p15_4_evaluation.py` rather than beside it. `per_profile`,
`worst_profile`, `authentication_gate`, `profile_gate` and `generalization_gate`
ask questions that did not change between the cycles, and a second copy of them
would be a second thing to keep true — which is the defect class this whole cycle
is about. What is new here is what P15.5 asks that P15.4 did not:

**The whole-system smoke test is a Gate C condition** (§27). P15.4's benchmark
detected nothing because two components disagreed, and no gate in that cycle
could have caught it, because every gate measured the *output* of a pipeline that
was not carrying anything. A candidate whose parts are individually correct and
whose pipeline does not reach a firewall request is not a candidate.

**A profile predeclared `TEMP_BLOCK_NOT_SUPPORTED` does not fail for silence**
(§29). If the calibrator cannot bound a probability above a profile's cutoff then
no evidence at any strength authorises a block there, and counting that as a
detection failure would be marking the system down for refusing to act on
evidence it cannot bound. The declaration has to exist beforehand, which is why
`profile_block_eligibility` is read from the committed policy rather than
recomputed here.

**Per-profile numbers are reported for every block-eligible profile** (§30), and
the not-supported ones are reported separately with what they *can* do, so a
reader is not left to infer why a column is empty.

### One run

`run()` writes `reports/P15_5_LOCKED_TEST.json` and that file is the result. §25
and §26 are absolute: the candidate is not modified and the corpus rescored, and
a defect discovered by this test is fixed for safety while the candidate fails.
"""
import json
from pathlib import Path

from eye_for_an_eye.autonomy.cost import PROFILES, CostPolicy
from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision import families as families_module
from eye_for_an_eye.decision import math_risk

from . import evaluation_design as design
from . import observability
from . import p15_2_evaluation as P
from . import p15_5_test_policy as policy_module
from .p15_4_evaluation import (authentication_gate, generalization_gate, per_profile,
                               profile_gate, worst_profile)

P15_5_EVALUATION_VERSION = 1

#: The frozen candidate. Changing any line is a different candidate needing a
#: different test, not another run of this one.
CANDIDATE = {
    'probability_source': 'math_risk',
    'math_risk_version': math_risk.VERSION,
    'family_scores': families_module.FAMILY_SCORE_VERSION,
    'composition': 'evidence-composition-v1, noisy-OR over carrying families '
                   'plus bounded interactions',
    'calibrator': 'models/mathrisk-cal-v4-isotonic.json',
    'calibration_method': cal.ISOTONIC,
    'calibration_unit': cal.SOURCE,
    'calibration_corpora': ['dataset-p15-4-cal-v1', 'dataset-p15-4-cal2-v1',
                            'dataset-p15-4-cal3-v1', 'dataset-p15-4-cal4-v1',
                            *(f'dataset-p15-5-cal{index}-v1' for index in range(1, 9))],
    'model_version_binding': math_risk.VERSION,
    'aggregation': 'max over a source-s windows',
    'cost_policy': 'cost-policy-v1, unchanged',
    'gates': 'DecisionGates defaults, unchanged',
    'maturity': 'three roads; the standard floor unchanged at 20 observations',
    'supervised_ml_authority': 'auxiliary; never the probability a block rests on',
    'changed_since_p15_4': ('the calibrator is refitted on twelve corpora instead '
                            'of four. No formula, gate, cutoff or policy moved'),
}

#: The new unseen pair. `withheld-mobile-sync` and `withheld-probe-login` were
#: scored on the P15.4 benchmark and are no longer unseen.
WITHHELD_FAMILIES = ('withheld-backup-sweep', 'withheld-credential-drift')

#: §31, §32. Benign families that authenticate and may never be blocked for it.
#: Written down before the corpus was scored, which is the whole point of a list
#: rather than a filter.
BENIGN_AUTHENTICATION_FAMILIES = (
    'profile-api-batch',
    'profile-api-high-rate',
    'profile-api-service-account',
    'profile-api-stale-credential',
    'profile-admin-mistakes',
    'profile-admin-console',
    'profile-webhook-signed',
    'profile-web-assets',
    'hard-negative-batch-api',
    'withheld-backup-sweep',
)

#: §33. The malicious side of the same question. If none of these is detected,
#: the benign safety above was bought by switching the evidence off.
MALICIOUS_AUTHENTICATION_FAMILIES = (
    'positive-api-spray',
    'positive-admin-brute',
    'positive-web-stuffing',
    'positive-api-patient-walk',
    'credential-automation',
    'credential-low-rate',
    'composite-credential-spray',
    'withheld-credential-drift',
)


#: Each profile name resolves to itself, so a decision on an `api` site is
#: priced at the `api` cutoff. An empty map — the default — sends every scope to
#: `public_website`, which is what every locked benchmark before P15.5 measured
#: without saying so. A deployment configures this in `[autonomy] cost_profiles`;
#: a corpus that declares profiles has to do the same or its per-profile tables
#: mean something other than they say.
SCOPE_PROFILES = {name: name for name in PROFILES}


def cost_policy():
    return CostPolicy(scope_profiles=dict(SCOPE_PROFILES))


def load_calibrator(path=None):
    return cal.load(path or CANDIDATE['calibrator'])


def critical_families(eligibility):
    """Malicious, observable, block-eligible, and on a profile that may block.

    §29 in code. A family whose only appearance is on a profile predeclared
    `TEMP_BLOCK_NOT_SUPPORTED` cannot be detected by a block, so requiring one
    would mark the system down for the calibration width it already reports.
    Families that appear on any eligible profile stay in.
    """
    eligible = {name for name, entry in eligibility['profiles'].items()
                if entry['eligibility'] == 'TEMP_BLOCK_ELIGIBLE'}
    return sorted(name for name, entry in observability.FAMILIES.items()
                  if entry[0] == observability.IN_SCOPE_OBSERVABLE
                  and entry[1] == observability.TEMP_BLOCK_ELIGIBLE), sorted(eligible)


def families_only_on_ineligible_profiles(decisions, eligibility):
    """Which families appear *only* where no block is possible.

    Computed from the corpus rather than assumed, because "this family is an API
    family" is a property of the matrix and the matrix can change.
    """
    eligible = {name for name, entry in eligibility['profiles'].items()
                if entry['eligibility'] == 'TEMP_BLOCK_ELIGIBLE'}
    profiles = {}
    for decision in decisions:
        profiles.setdefault(decision.scenario_group, set()).add(
            decision.profile_type or 'unstated')
    return sorted(name for name, seen in profiles.items()
                  if seen and not (seen & eligible))


def smoke_gate(smoke):
    """§27's new condition. Wiring, and it is allowed to fail the gate."""
    if not smoke:
        return {'verdict': 'FAIL', 'reason': 'the whole-system smoke test was not run'}
    failures = {name: result['reasons']
                for name, result in smoke.get('scenarios', {}).items()
                if result.get('verdict') != 'PASS'}
    return {'verdict': smoke.get('verdict', 'FAIL'),
            'stage_verdicts': smoke.get('stage_verdicts', {}),
            'failures': failures,
            'note': ('§41: this is a wiring result. No number from it is evidence '
                     'about detection quality')}


def verdict(measured, policy, decisions, smoke):
    """Every gate against the committed policy. Mechanical on purpose."""
    families = measured['scenario_families']
    familiarity = measured['familiarity']
    sources = measured['per_source']
    metrics = sources['decision_metrics']
    limit = 1.0
    gate_c, gate_e = [], []

    eligibility = policy['profile_block_eligibility']
    all_critical, eligible_profiles = critical_families(eligibility)
    unreachable = set(families_only_on_ineligible_profiles(decisions, eligibility))
    present = set(families)
    expected = [name for name in all_critical if name in present and name not in unreachable]
    excused = sorted(name for name in all_critical if name in present and name in unreachable)
    missing = [name for name in all_critical if name not in present]
    zero = [name for name in expected if not families[name]['blocked_sources']]
    if zero:
        gate_c.append({'condition': 'critical_family_at_zero_detection', 'families': zero})

    seen = familiarity.get('seen', {}).get('decision_metrics', {})
    unseen = familiarity.get('unseen', {}).get('decision_metrics', {})
    seen_recall, unseen_recall = seen.get('recall'), unseen.get('recall')
    if unseen_recall == 0 and seen_recall not in (None, 0):
        gate_c.append({'condition': 'unseen_recall_zero_while_seen_is_not',
                       'seen_recall': seen_recall, 'unseen_recall': unseen_recall})

    calibrator = measured['calibrator']
    if calibrator['source'] != 'math_risk':
        gate_c.append({'condition': 'calibrator_maps_the_wrong_quantity',
                       'source': calibrator['source']})
    if calibrator['model_version'] != CANDIDATE['model_version_binding']:
        gate_c.append({'condition': 'calibrator_not_bound_to_the_scored_formula',
                       'binding': calibrator['model_version'],
                       'formula': CANDIDATE['model_version_binding']})
    if not seen or not unseen:
        gate_c.append({'condition': 'generalisation_not_measured',
                       'views_present': sorted(familiarity)})
    if measured['rows_dropped'].get('duplicate_of_a_fitting_corpus') is None:
        gate_c.append({'condition': 'leakage_not_excluded'})

    smoke_result = smoke_gate(smoke)
    if smoke_result['verdict'] != 'PASS':
        gate_c.append({'condition': 'whole_system_smoke_failed',
                       'detail': smoke_result.get('failures') or smoke_result.get('reason')})

    release = sources['release_gate']
    if release['verdict'] != 'PASS':
        gate_e.append({'condition': 'release_gate_' + release['verdict'].lower(),
                       'reasons': release['reasons']})
    degenerate = sources['non_degenerate_decision_gate']
    if degenerate['verdict'] != 'NON_DEGENERATE':
        gate_e.append({'condition': 'degenerate_decision', 'verdict': degenerate['verdict']})
    blocked_benign = [name for name, entry in families.items()
                      if entry['label'] == design.BENIGN and entry['blocked_sources']]
    if blocked_benign:
        gate_e.append({'condition': 'benign_family_blocked',
                       'families': sorted(blocked_benign)})

    profiles = per_profile(decisions)
    worst = worst_profile(profiles)
    auth = authentication_gate(families, limit)
    profile = profile_gate(profiles, worst, limit)
    general = generalization_gate(families, WITHHELD_FAMILIES)
    return {
        'policy_version': policy['test_policy_version'],
        'policy_digest': policy['digest'],
        'gate_c': {'verdict': 'FAIL' if gate_c else 'PASS', 'failures': gate_c},
        'gate_e': {'verdict': 'FAIL' if gate_e else 'PASS', 'failures': gate_e},
        'whole_system_smoke': smoke_result,
        'authentication_gate': auth,
        'per_profile_gate': profile,
        'generalization_gate': general,
        'per_profile': profiles,
        'profile_block_eligibility': eligibility,
        'block_eligible_profiles': eligible_profiles,
        'critical_families_expected': expected,
        'critical_families_excused_as_unreachable': {
            'families': excused,
            'why': ('every appearance of these is on a profile predeclared '
                    'TEMP_BLOCK_NOT_SUPPORTED, so no evidence at any strength '
                    'could produce a block for them (§29). The declaration is in '
                    'the committed policy, not derived from this result')},
        'critical_families_absent_from_corpus': missing,
        'withheld_families': list(WITHHELD_FAMILIES),
        'recall': {'overall': metrics.get('recall'), 'seen': seen_recall,
                   'unseen': unseen_recall},
        'block_precision': metrics.get('block_precision'),
        'false_blocks_per_1000_benign': metrics.get('false_blocks_per_1000_benign'),
        'overall': ('PASS' if not (gate_c or gate_e)
                    and auth['verdict'] == 'PASS'
                    and profile['verdict'] == 'PASS'
                    and general['verdict'] == 'PASS' else 'FAIL'),
        'note': ('evaluated against the policy committed before the corpus was '
                 'generated. A FAIL here is final for this cycle: nothing is '
                 'retuned and rerun (§25, §26)'),
    }


def run(*, root='datasets', out=None, calibrator_path=None, resamples=2000,
        policy_path='reports/P15_5_TEST_POLICY.json',
        smoke_path='reports/P15_5_SMOKE.json'):
    """Score the locked benchmark. Once."""
    calibrator = load_calibrator(calibrator_path)
    policy = json.loads(Path(policy_path).read_text(encoding='utf-8'))
    live = policy_module.document()
    smoke = None
    if Path(smoke_path).is_file():
        smoke = json.loads(Path(smoke_path).read_text(encoding='utf-8'))

    # Every corpus the candidate was fitted on, so a row shared with any of them
    # is dropped rather than scored. Twelve calibration corpora and the
    # development corpus.
    fitting = design.load_role(design.P15_4_DEVELOPMENT, root)
    for role in (design.P15_4_CALIBRATION, design.P15_4_CALIBRATION_2,
                 design.P15_4_CALIBRATION_3, design.P15_4_CALIBRATION_4,
                 *design.P15_5_CALIBRATION_ROLE_NAMES):
        fitting = fitting + design.load_role(role, root)
    locked = design.load_role(design.P15_5_LOCKED_TEST, root)
    shared = design.duplicate_keys(fitting, locked)
    measured = P.evaluate_role(design.P15_5_LOCKED_TEST, calibrator=calibrator,
                               root=root, drop_keys=shared, resamples=resamples)
    decisions, _, _ = P.replay_role(design.P15_5_LOCKED_TEST, calibrator=calibrator,
                                    root=root, drop_keys=shared)
    body = {
        'p15_5_evaluation_version': P15_5_EVALUATION_VERSION,
        'candidate': dict(CANDIDATE),
        'cost_cutoffs': {name: round(profile.threshold, 6)
                         for name, profile in sorted(PROFILES.items())},
        'policy': {'version': policy['test_policy_version'],
                   'digest': policy['digest'],
                   # If these differ, something changed between committing the
                   # standard and applying it, and the run is not evidence.
                   'matches_current_code': policy['digest'] == live['digest']},
        'freeze': design.freeze(root=root),
        'locked_test': measured,
        'verdict': verdict(measured, policy, decisions, smoke),
    }
    if out:
        Path(out).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return body
