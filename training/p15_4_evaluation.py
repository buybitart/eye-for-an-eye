"""The P15.4 locked measurement: one corpus, one calibrator, one run. §71, §72.

`training/p15_2_evaluation.py` already runs the whole decision path over a corpus
and takes it apart per family, per familiarity and gate by gate, with a
source-group bootstrap. None of that is re-implemented. What is new is the
standard it is judged against and three questions P15.3 could not ask.

* the corpus is `dataset-p15-4-locked-v1`, generated after the freeze commit
  from a matrix committed before it, containing two behaviour families that
  appear in no fitting corpus at all;
* the calibrator is bound to `math-risk-v4` and fitted on **sources** rather
  than windows, for the reason `decision/calibration.UNITS` records;
* the standard is `reports/P15_4_TEST_POLICY.json`, committed before the corpus
  was generated, and `verdict()` evaluates it mechanically.

### The three questions P15.3 could not ask

**Authentication.** Did the system stop acting on legitimate authentication
without simply ceasing to act? The failure is asymmetric and easy to hide: a
detector that blocks nothing passes every benign check, so the gate fails both
on a blocked benign authenticated family *and* on every malicious
authentication family being undetected.

**Per profile.** Is safety spread evenly across kinds of site? Until this cycle
no corpus carried a site, so `autonomy.evaluation.worst_site` had nothing real
to group by and every per-site table in every report was a per-scenario table
wearing a different name. The gate asks for the worst profile by name, because
an aggregate false-block rate hides the profile where the system is worst.

**Generalisation, narrowly.** Two withheld families, and only those two. The
rest of this corpus is a fresh random draw of behaviour the cycle has seen,
which measures stability and nothing else — the gate fails if the report
presents the one as the other.

### The one-shot rule

§66, §72, §83. Scored once. If the verdict is FAIL, the candidate fails:
nothing is retuned and rerun, and a future cycle designs a new test.
`reports/P15_4_LOCKED_TEST.json` records the run whichever way it goes.
"""
from collections import defaultdict
import json
from pathlib import Path

from eye_for_an_eye.autonomy import evaluation as ev
from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.decision import calibration as cal
from eye_for_an_eye.decision import families as families_module
from eye_for_an_eye.decision import math_risk

from . import decision_replay as replay_module
from . import evaluation_design as design
from . import observability
from . import p15_2_evaluation as P
from . import p15_4_test_policy as policy_module

P15_4_EVALUATION_VERSION = 1

#: The frozen candidate (§70, §81). Changing any line is a different candidate
#: needing a different test, not another run of this one.
CANDIDATE = {
    'probability_source': 'math_risk',
    'math_risk_version': math_risk.VERSION,
    'family_scores': families_module.FAMILY_SCORE_VERSION,
    'composition': 'evidence-composition-v1, noisy-OR over carrying families '
                   'plus bounded interactions',
    'calibrator': 'models/mathrisk-cal-v4-isotonic.json',
    # Isotonic, on the evidence rather than by habit. §36 cautions that with
    # limited calibration data the method winning in-fold is usually the wrong
    # choice, and that isotonic always wins in-fold and often loses out of it.
    # Here it wins *out* of fold on both measures — Brier 0.0262 against 0.0282,
    # ECE 0.0157 against 0.0255 — so the caution does not apply. Neither method
    # overfits: both score better on the holdout than on the fold they were
    # fitted on. The conservative bound a block actually rests on is identical
    # for the two, at 0.981951.
    'calibration_method': cal.ISOTONIC,
    'calibration_unit': cal.SOURCE,
    'calibration_corpora': ['dataset-p15-4-cal-v1', 'dataset-p15-4-cal2-v1',
                            'dataset-p15-4-cal3-v1', 'dataset-p15-4-cal4-v1'],
    'model_version_binding': math_risk.VERSION,
    'aggregation': 'max over a source-s windows',
    'cost_policy': 'cost-policy-v1, unchanged',
    'gates': 'DecisionGates defaults, unchanged',
    'maturity': 'three roads; the standard floor unchanged at 20 observations',
    'supervised_ml_authority': 'auxiliary; never the probability a block rests on',
}

#: §15, §16. Benign families that authenticate, and may never be blocked for it.
#: Named here rather than derived, because the point of the gate is that this
#: list was written down before the corpus was scored.
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
    'withheld-mobile-sync',
)

#: The malicious side of the same question. If none of these is detected, the
#: benign safety above was bought by switching the evidence off.
MALICIOUS_AUTHENTICATION_FAMILIES = (
    'positive-api-spray',
    'positive-admin-brute',
    'positive-web-stuffing',
    'positive-api-patient-walk',
    'credential-automation',
    'credential-low-rate',
    'composite-credential-spray',
)

WITHHELD_FAMILIES = ('withheld-mobile-sync', 'withheld-probe-login')


def load_calibrator(path=None):
    return cal.load(path or CANDIDATE['calibrator'])


def critical_families():
    """Malicious, observable, block-eligible. The families that may not be zero."""
    return sorted(name for name, entry in observability.FAMILIES.items()
                  if entry[0] == observability.IN_SCOPE_OBSERVABLE
                  and entry[1] == observability.TEMP_BLOCK_ELIGIBLE)


def per_profile(decisions):
    """One report per site profile, from the profile the corpus declared.

    Separate from `autonomy.evaluation.per_site`, which groups by site: a site
    is one deployment and a profile is a *kind* of deployment, and the cost
    policy prices the second. Reporting only sites would make each row too small
    to bound and would not line up with the cutoffs the rows are judged against.
    """
    grouped = defaultdict(list)
    for decision in decisions:
        grouped[decision.profile_type or 'unstated'].append(decision)
    out = {}
    for name, rows in sorted(grouped.items()):
        outcomes, conflicts = replay_module.source_outcomes(rows)
        metrics = ev.evaluate(outcomes)
        out[name] = {
            'sources': len(outcomes),
            'label_conflicts': conflicts,
            'cost_cutoff': (round(PROFILES[name].threshold, 6) if name in PROFILES else None),
            'network_block_permitted': (PROFILES[name].network_block_permitted
                                        if name in PROFILES else None),
            'metrics': metrics.explain(),
        }
    return out


def worst_profile(profiles):
    """The profile with the highest false-block rate, named rather than averaged."""
    candidates = [(name, entry) for name, entry in profiles.items()
                  if entry['metrics'].get('false_blocks_per_1000_benign') is not None]
    if not candidates:
        return None
    name, entry = max(candidates,
                      key=lambda item: item[1]['metrics']['false_blocks_per_1000_benign'])
    return {'profile': name,
            'false_blocks_per_1000_benign': entry['metrics']['false_blocks_per_1000_benign'],
            'benign_sources': entry['metrics'].get('benign_sample'),
            'cost_cutoff': entry['cost_cutoff']}


def authentication_gate(families, limit):
    """§15, §16. Both directions, because either alone is easy to satisfy."""
    failures = []
    blocked = [name for name in BENIGN_AUTHENTICATION_FAMILIES
               if families.get(name, {}).get('blocked_sources')]
    if blocked:
        failures.append({'condition': 'benign_authenticated_family_blocked',
                         'families': sorted(blocked)})
    present = [name for name in MALICIOUS_AUTHENTICATION_FAMILIES if name in families]
    detected = [name for name in present if families[name].get('blocked_sources')]
    if present and not detected:
        failures.append({'condition': 'no_malicious_authentication_family_detected',
                         'families_present': sorted(present),
                         'note': ('benign safety with no detection means the evidence '
                                  'was switched off rather than fixed')})
    return {'verdict': 'FAIL' if failures else 'PASS', 'failures': failures,
            'benign_families_present': sorted(n for n in BENIGN_AUTHENTICATION_FAMILIES
                                              if n in families),
            'malicious_families_present': sorted(present),
            'malicious_families_detected': sorted(detected),
            'limit_applied': limit}


def profile_gate(profiles, worst, limit):
    """§41, §45. The worst profile, not the mean."""
    failures = []
    if not profiles or set(profiles) == {'unstated'}:
        failures.append({'condition': 'no_profile_metadata_in_the_corpus'})
    for name, entry in profiles.items():
        rate = entry['metrics'].get('false_blocks_per_1000_benign')
        if rate is not None and rate > limit:
            failures.append({'condition': 'profile_above_the_false_block_limit',
                             'profile': name, 'rate': rate, 'limit': limit})
        # `benign_sample`, which is what `autonomy.evaluation` calls it. The
        # first version of this gate asked for `benign_sources`, a key that does
        # not exist, so every profile reported "no benign sources" while the
        # table beside it showed hundreds. A gate that fires on a typo says
        # nothing about the system, and one reading a missing key as zero fires
        # forever.
        if entry['metrics'].get('benign_sample') in (0, None) and name != 'unstated':
            failures.append({'condition': 'profile_has_no_benign_sources',
                             'profile': name})
        if (entry['network_block_permitted'] is False
                and entry['metrics'].get('blocked_sources')):
            failures.append({'condition': 'profile_that_may_never_network_block_did',
                             'profile': name})
    return {'verdict': 'FAIL' if failures else 'PASS', 'failures': failures,
            'worst_profile': worst}


def generalization_gate(families, withheld=None):
    """§24. Whether the benchmark's withheld families were actually present.

    `withheld` is a parameter as of P15.5. It defaulted to this module's own
    `WITHHELD_FAMILIES`, so the P15.5 benchmark was checked for the presence of
    *P15.4's* pair, found neither, and failed the gate for a bookkeeping reason
    while its own withheld pair sat in the results scoring 0/18 and 14/14. Found
    by the locked benchmark; corrected without rescoring it (§25, §26).

    §49, §50: the narrow claim, judged narrowly.
    """
    names = tuple(withheld or WITHHELD_FAMILIES)
    failures = []
    present = [name for name in names if name in families]
    if len(present) != len(names):
        failures.append({'condition': 'a_withheld_family_is_absent_from_the_benchmark',
                         'expected': sorted(names), 'present': sorted(present)})
    benign = [name for name in present
              if families[name].get('label') == design.BENIGN]
    positive = [name for name in present
                if families[name].get('label') != design.BENIGN]
    for name in benign:
        if families[name].get('blocked_sources'):
            failures.append({'condition': 'the_withheld_benign_family_was_blocked',
                             'family': name,
                             'blocked': families[name]['blocked_sources']})
    return {'verdict': 'FAIL' if failures else 'PASS', 'failures': failures,
            'withheld_expected': sorted(names),
            'withheld_present': sorted(present),
            'withheld_benign': {name: {'sources': families[name]['sources'],
                                       'blocked_sources': families[name]['blocked_sources']}
                                for name in benign},
            'withheld_positive': {name: {'sources': families[name]['sources'],
                                         'blocked_sources': families[name]['blocked_sources']}
                                  for name in positive},
            'withheld_positive_blocked_sources':
                sum(families[name]['blocked_sources'] for name in positive) or None,
            'withheld_positive_sources':
                sum(families[name]['sources'] for name in positive) or None,
            'note': ('the rest of this corpus is a fresh draw of seen behaviour and '
                     'is evidence of stability, not of generalisation')}


def verdict(measured, policy, decisions):
    """Every gate against the committed policy. Mechanical on purpose."""
    families = measured['scenario_families']
    familiarity = measured['familiarity']
    sources = measured['per_source']
    metrics = sources['decision_metrics']
    limit = 1.0  # from GATE_E_REGRESSION_LIMITS, unchanged since P15.2
    gate_c, gate_e = [], []

    present = set(families)
    expected = [name for name in critical_families() if name in present]
    missing = [name for name in critical_families() if name not in present]
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
    general = generalization_gate(families)
    return {
        'policy_version': policy['test_policy_version'],
        'policy_digest': policy['digest'],
        'gate_c': {'verdict': 'FAIL' if gate_c else 'PASS', 'failures': gate_c},
        'gate_e': {'verdict': 'FAIL' if gate_e else 'PASS', 'failures': gate_e},
        'authentication_gate': auth,
        'per_profile_gate': profile,
        'generalization_gate': general,
        'per_profile': profiles,
        'critical_families_expected': expected,
        'critical_families_absent_from_corpus': missing,
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
                 'retuned and rerun (§66, §72, §83)'),
    }


def run(*, root='datasets', out=None, calibrator_path=None, resamples=2000,
        policy_path='reports/P15_4_TEST_POLICY.json'):
    """Score the locked benchmark. Once."""
    calibrator = load_calibrator(calibrator_path)
    policy = json.loads(Path(policy_path).read_text(encoding='utf-8'))
    live = policy_module.document()
    fitting = design.load_role(design.P15_4_DEVELOPMENT, root)
    for role in (design.P15_4_CALIBRATION, design.P15_4_CALIBRATION_2):
        fitting = fitting + design.load_role(role, root)
    locked = design.load_role(design.P15_4_LOCKED_TEST, root)
    shared = design.duplicate_keys(fitting, locked)
    measured = P.evaluate_role(design.P15_4_LOCKED_TEST, calibrator=calibrator,
                               root=root, drop_keys=shared, resamples=resamples)
    decisions, _, _ = P.replay_role(design.P15_4_LOCKED_TEST, calibrator=calibrator,
                                    root=root, drop_keys=shared)
    body = {
        'p15_4_evaluation_version': P15_4_EVALUATION_VERSION,
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
        'verdict': verdict(measured, policy, decisions),
    }
    if out:
        Path(out).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return body


def render(body):
    """The tables the report quotes, from the object the report was written from."""
    lines = [P.render({'locked_test': body['locked_test']}), '']
    v = body['verdict']
    lines.append(f"OVERALL: {v['overall']}")
    lines.append(f"  gate C {v['gate_c']['verdict']}   gate E {v['gate_e']['verdict']}   "
                 f"authentication {v['authentication_gate']['verdict']}   "
                 f"per-profile {v['per_profile_gate']['verdict']}   "
                 f"generalisation {v['generalization_gate']['verdict']}")
    for gate in ('gate_c', 'gate_e', 'authentication_gate', 'per_profile_gate',
                 'generalization_gate'):
        for failure in v[gate]['failures']:
            detail = (failure.get('families') or failure.get('reasons')
                      or failure.get('profile') or '')
            lines.append(f"  {gate}: {failure['condition']} {detail}")
    lines.append('')
    lines.append('per profile:')
    for name, entry in v['per_profile'].items():
        metrics = entry['metrics']
        lines.append(f"  {name:16s} sources {entry['sources']:4d}  "
                     f"false blocks/1000 benign {metrics.get('false_blocks_per_1000_benign')}  "
                     f"recall {metrics.get('recall')}  cutoff {entry['cost_cutoff']}")
    worst = v['per_profile_gate']['worst_profile']
    if worst:
        lines.append(f"  worst profile: {worst['profile']} at "
                     f"{worst['false_blocks_per_1000_benign']} per 1000 benign sources")
    lines.append('')
    lines.append(f"recall overall {v['recall']['overall']} seen {v['recall']['seen']} "
                 f"unseen {v['recall']['unseen']}")
    lines.append(f"block precision {v['block_precision']} "
                 f"false blocks/1000 benign {v['false_blocks_per_1000_benign']}")
    return '\n'.join(lines)
