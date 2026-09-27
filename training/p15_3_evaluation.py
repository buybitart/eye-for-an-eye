"""The P15.3 locked measurement: one corpus, one calibrator, one run.

`training/p15_2_evaluation.py` already knows how to run the whole decision path
over a corpus and take it apart honestly — per family, per familiarity, gate by
gate, with a source-group bootstrap. None of that is re-implemented here. What is
new is *what* is measured and *against what standard*:

* the corpus is `dataset-generalization-test-v2`, which contains six behaviour
  families no feature, weight, calibrator or gate has ever seen;
* the calibrator is `mathrisk-cal-v3-isotonic`, refitted on the calibration
  corpora against `math-risk-v3` and **bound** to that formula version, because a
  mapping fitted on one formula's scores means nothing applied to another's —
  and until P15.3 nothing in the artifact would have refused the substitution;
* the standard is `reports/P15_3_TEST_POLICY.json`, committed before the corpus
  was generated, and `verdict()` below evaluates it mechanically rather than by
  reading a table and forming an impression.

### Why the verdict is code

Because the alternative is a person looking at forty numbers and deciding
whether the cycle succeeded, which is the failure mode the whole policy exists to
prevent. `verdict()` reads the committed policy, checks each stated failure
condition against the measurement, and returns PASS or FAIL with the conditions
that fired. It cannot be argued with, and if it is wrong the fix is a better
policy in the next cycle, never a better reading of this one.

### The one-shot rule

§66 and §83. This corpus is scored once. If the verdict is FAIL, the candidate
fails: nothing is retuned and rerun, Gate C stays FAIL, and a future cycle
designs a new test. `reports/P15_3_LOCKED_TEST.json` records the run whichever
way it goes.
"""
import json
from pathlib import Path

from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.decision import calibration as cal

from . import evaluation_design as design
from . import observability
from . import p15_2_evaluation as P
from . import test_policy

P15_3_EVALUATION_VERSION = 1

#: The frozen candidate (§81). Changing any line of this is a different
#: candidate needing a different test, not another run of this one.
CANDIDATE = {
    'probability_source': 'math_risk',
    'math_risk_version': 'math-risk-v3',
    'calibrator': 'models/mathrisk-cal-v3-isotonic.json',
    'calibration_method': cal.ISOTONIC,
    'calibration_corpora': ['dataset-cal-v1', 'dataset-cal2-v1'],
    'model_version_binding': 'math-risk-v3',
    'aggregation': 'max over a source-s windows',
    'cost_policy': 'cost-policy-v1, unchanged',
    'gates': 'DecisionGates defaults, unchanged',
    'supervised_ml_authority': 'auxiliary; never the probability a block rests on',
}


def load_calibrator(path=None):
    return cal.load(path or CANDIDATE['calibrator'])


def critical_families():
    """Malicious, observable, block-eligible. The families that may not be zero."""
    return sorted(name for name, entry in observability.FAMILIES.items()
                  if entry[0] == observability.IN_SCOPE_OBSERVABLE
                  and entry[1] == observability.TEMP_BLOCK_ELIGIBLE)


def verdict(measured, policy):
    """Gate C and Gate E against the committed policy. Mechanical on purpose."""
    families = measured['scenario_families']
    familiarity = measured['familiarity']
    sources = measured['per_source']
    metrics = sources['decision_metrics']
    gate_c, gate_e = [], []

    # 1. a critical family at zero detection. Only families actually present in
    #    this corpus can be judged; one that is absent is a gap in the corpus and
    #    is reported as such rather than counted as a pass.
    present = set(families)
    expected = [name for name in critical_families() if name in present]
    missing = [name for name in critical_families() if name not in present]
    zero = [name for name in expected if not families[name]['blocked_sources']]
    if zero:
        gate_c.append({'condition': 'critical_family_at_zero_detection',
                       'families': zero})

    # 2. memorisation: unseen at zero while seen is not.
    seen = familiarity.get('seen', {}).get('decision_metrics', {})
    unseen = familiarity.get('unseen', {}).get('decision_metrics', {})
    seen_recall = seen.get('recall')
    unseen_recall = unseen.get('recall')
    if (unseen_recall == 0 and seen_recall not in (None, 0)):
        gate_c.append({'condition': 'unseen_recall_zero_while_seen_is_not',
                       'seen_recall': seen_recall, 'unseen_recall': unseen_recall})

    # 3. probability semantics.
    calibrator = measured['calibrator']
    if calibrator['source'] != 'math_risk':
        gate_c.append({'condition': 'calibrator_maps_the_wrong_quantity',
                       'source': calibrator['source']})
    if calibrator['model_version'] != CANDIDATE['model_version_binding']:
        gate_c.append({'condition': 'calibrator_not_bound_to_the_scored_formula',
                       'binding': calibrator['model_version']})

    # 4. generalisation measured at all.
    if not seen or not unseen:
        gate_c.append({'condition': 'generalisation_not_measured',
                       'views_present': sorted(familiarity)})

    # 5. leakage.
    leaked = measured['rows_dropped'].get('duplicate_of_a_fitting_corpus')
    if leaked is None:
        gate_c.append({'condition': 'leakage_not_excluded'})

    # Gate E, unchanged from P15.2 and not traded against Gate C.
    release = sources['release_gate']
    if release['verdict'] != 'PASS':
        gate_e.append({'condition': 'release_gate_' + release['verdict'].lower(),
                       'reasons': release['reasons']})
    degenerate = sources['non_degenerate_decision_gate']
    if degenerate['verdict'] != 'NON_DEGENERATE':
        gate_e.append({'condition': 'degenerate_decision',
                       'verdict': degenerate['verdict']})
    blocked_benign = [name for name, entry in families.items()
                      if entry['label'] == design.BENIGN and entry['blocked_sources']]
    if blocked_benign:
        gate_e.append({'condition': 'benign_family_blocked',
                       'families': sorted(blocked_benign)})

    return {
        'policy_version': policy['test_policy_version'],
        'policy_digest': policy['digest'],
        'gate_c': {'verdict': 'FAIL' if gate_c else 'PASS', 'failures': gate_c},
        'gate_e': {'verdict': 'FAIL' if gate_e else 'PASS', 'failures': gate_e},
        'critical_families_expected': expected,
        'critical_families_absent_from_corpus': missing,
        'recall': {'overall': metrics.get('recall'), 'seen': seen_recall,
                   'unseen': unseen_recall},
        'block_precision': metrics.get('block_precision'),
        'false_blocks_per_1000_benign': metrics.get('false_blocks_per_1000_benign'),
        'note': ('evaluated against the policy committed before the corpus was '
                 'generated. A FAIL here is final for this cycle: nothing is '
                 'retuned and rerun (§66, §83)'),
    }


def run(*, root='datasets', out=None, calibrator_path=None, resamples=2000,
        policy_path='reports/P15_3_TEST_POLICY.json'):
    """Score the locked benchmark. Once."""
    calibrator = load_calibrator(calibrator_path)
    policy = json.loads(Path(policy_path).read_text(encoding='utf-8'))
    live = test_policy.document()
    fitting = design.load_role(design.DEVELOPMENT, root)
    for role in design.CALIBRATION_ROLES:
        fitting = fitting + design.load_role(role, root)
    locked = design.load_role(design.GENERALIZATION_TEST, root)
    shared = design.duplicate_keys(fitting, locked)
    measured = P.evaluate_role(design.GENERALIZATION_TEST, calibrator=calibrator,
                               root=root, drop_keys=shared, resamples=resamples)
    body = {
        'p15_3_evaluation_version': P15_3_EVALUATION_VERSION,
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
        'verdict': verdict(measured, policy),
    }
    if out:
        Path(out).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return body


def render(body):
    """The tables the report quotes, from the same object it was written from.

    `P.render` takes the P15.2 envelope, whose measurement sits under
    `locked_test`. The P15.3 envelope has the same key, so the measurement is
    handed over in the shape that renderer expects rather than reformatted.
    """
    lines = [P.render({'locked_test': body['locked_test']}), '']
    v = body['verdict']
    lines.append(f"GATE C: {v['gate_c']['verdict']}   GATE E: {v['gate_e']['verdict']}")
    for gate in ('gate_c', 'gate_e'):
        for failure in v[gate]['failures']:
            detail = failure.get('families') or failure.get('reasons') or ''
            lines.append(f"  {gate}: {failure['condition']} {detail}")
    lines.append(f"recall overall {v['recall']['overall']} "
                 f"seen {v['recall']['seen']} unseen {v['recall']['unseen']}")
    lines.append(f"block precision {v['block_precision']} "
                 f"false blocks/1000 benign {v['false_blocks_per_1000_benign']}")
    return '\n'.join(lines)
