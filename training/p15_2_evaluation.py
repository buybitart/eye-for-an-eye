"""The frozen P15.2 evaluation. One module, every number in the report.

§109 and §110: nothing in `reports/P15_2_FINAL_REPORT.md` may come from an
ad-hoc script. This module produces the ranking table, the calibration table,
the confusion matrices, the per-family breakdown, the gate effects and the
detection-time analysis, and the report quotes it.

### The frozen candidate

    probability source   MathRisk, the deterministic engine, unchanged
    calibrator           isotonic, fitted on two independent calibration corpora
    conservative bound   Wilson lower bound over the calibration sample
    cutoff               C_FP / (C_FP + C_FN), per cost profile, unchanged
    aggregation          max over a source's windows
    gates                every P15 gate, at its P15 value

Chosen on development and calibration evidence, before the locked test was read.
The classifier scored better and could not clear Gate C: its own quality gate is
`false`, and ONNX parity cannot be run because the corpus it was trained on is
not committed. §71 and §72 are explicit that this is a reason to leave ML
auxiliary rather than a reason to promote it anyway — the product needs a
correct decision system, not a classifier with maximum authority.
"""
from collections import defaultdict
import json
from pathlib import Path
import random

from eye_for_an_eye.autonomy import evaluation as ev
from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.decision import calibration as cal

from . import candidates as C
from . import evaluation_design as design

P15_2_EVALUATION_VERSION = 1

#: The frozen candidate (§65). Changing any of these is a new candidate and a
#: new locked test, not a re-run of this one.
CANDIDATE = {
    'probability_source': 'math_risk',
    'calibrator': 'models/mathrisk-cal-v1-isotonic.json',
    'calibration_method': cal.ISOTONIC,
    'model_version': '',
    'aggregation': 'max over a source-s windows',
    'cost_policy': 'cost-policy-v1, unchanged',
    'gates': 'DecisionGates defaults, unchanged',
}


def load_calibrator(path=None):
    return cal.load(path or CANDIDATE['calibrator'])


def replay_role(role, *, calibrator, root='datasets', models=Path('models'),
                rows=None, drop_keys=None):
    """Run the whole system over one corpus. Returns (decisions, dropped, kept_rows)."""
    from eye_for_an_eye.config import Config
    from .decision_replay import ReplayComponents, replay

    data = rows if rows is not None else design.load_role(role, root)
    duplicates = 0
    if drop_keys:
        data, duplicates = design.without_duplicates(data, drop_keys)
    config = Config()
    config.decision.enabled = True
    components = ReplayComponents(config).open(
        classifier_path=models / 'risk-logreg-v1.onnx',
        classifier_manifest=models / 'risk-logreg-v1.json',
        anomaly_path=models / 'isolation-v1.onnx',
        anomaly_manifest=models / 'isolation-v1.json',
        distribution_path=models / 'risk-logreg-v1-distribution.json')
    try:
        decisions, dropped = replay(data, components, calibrator=calibrator)
    finally:
        components.close()
    dropped = dict(dropped)
    if duplicates:
        dropped['duplicate_of_a_fitting_corpus'] = duplicates
    return decisions, dropped, data


def _round(value, places=6):
    return None if value is None else round(float(value), places)


def outcomes(decisions, *, level='source'):
    from .decision_replay import source_outcomes, window_outcomes
    if level == 'window':
        return window_outcomes(decisions), []
    return source_outcomes(decisions)


def group_bootstrap(decisions, *, resamples=2000, seed=20260912, level='source'):
    """§47, §48. Resample whole sources, never correlated windows.

    Windows of one source are not independent observations — a scanner produces
    forty of them and they all say the same thing. Resampling windows would
    treat that as forty pieces of evidence and report an interval far tighter
    than the data supports. The resampling unit is the source, which is also the
    unit a block applies to.

    When zero false blocks are observed the interval does not collapse to a
    point: the upper end is whatever the resampling reaches, and the rule-of-
    three bound is reported beside it (§48). Observed zero is not proven zero.
    """
    grouped = defaultdict(list)
    for decision in decisions:
        grouped[decision.source_group or decision.sample_id].append(decision)
    groups = sorted(grouped)
    if not groups:
        return {}
    rng = random.Random(seed)
    stats = defaultdict(list)
    for _ in range(resamples):
        picked = [grouped[groups[rng.randrange(len(groups))]] for _ in groups]
        rows = []
        for windows in picked:
            labels = {w.label for w in windows}
            if len(labels) != 1:
                continue
            rows.append(ev.Outcome(blocked=any(w.blocked for w in windows),
                                   label=C.label_code(windows[0]) and ev.MALICIOUS_AUTOMATION
                                   or ev.BENIGN,
                                   score=max(w.conservative_probability for w in windows)))
        metrics = ev.evaluate(rows)
        for name in ('recall', 'false_positive_rate', 'block_precision',
                     'false_blocks_per_1000_benign'):
            value = getattr(metrics, name)
            if value is not None:
                stats[name].append(value)
    body = {'resamples': resamples, 'unit': 'source group',
            'method': 'percentile bootstrap over independent source groups'}
    for name, values in stats.items():
        values.sort()
        low = values[int(0.025 * len(values))]
        high = values[min(len(values) - 1, int(0.975 * len(values)))]
        body[name] = {'low': _round(low), 'high': _round(high)}
    benign_sources = sum(
        1 for windows in grouped.values()
        if windows and windows[0].label == design.BENIGN)
    false_blocks = sum(
        1 for windows in grouped.values()
        if windows and windows[0].label == design.BENIGN and any(w.blocked for w in windows))
    if benign_sources and false_blocks == 0:
        body['zero_false_blocks'] = {
            'benign_sources': benign_sources,
            'rule_of_three_upper_95': _round(3.0 / benign_sources),
            'per_1000_upper_95': _round(3000.0 / benign_sources, 3),
            'note': ('no false block was observed. The rule of three gives the 95% '
                     'upper bound on a rate after zero events in n trials; observed '
                     'zero is not proven zero and must never be reported as such')}
    return body


def per_family(decisions):
    """§59, §60. Every family separately, and never averaged with the others."""
    grouped = defaultdict(lambda: {'sources': set(), 'blocked': set(), 'label': '',
                                   'windows': 0, 'blocked_windows': 0,
                                   'max_probability': 0.0, 'max_bound': 0.0})
    for decision in decisions:
        entry = grouped[decision.scenario_group or 'none']
        entry['sources'].add(decision.source_group)
        entry['label'] = decision.label
        entry['windows'] += 1
        entry['blocked_windows'] += int(decision.blocked)
        entry['max_probability'] = max(entry['max_probability'],
                                       decision.calibrated_probability or 0.0)
        entry['max_bound'] = max(entry['max_bound'], decision.conservative_probability)
        if decision.blocked:
            entry['blocked'].add(decision.source_group)
    body = {}
    for name, entry in sorted(grouped.items()):
        sources = len(entry['sources'])
        body[name] = {
            'label': entry['label'],
            'familiarity': 'unseen' if name in design.WITHHELD_FAMILIES else 'seen',
            'sources': sources, 'blocked_sources': len(entry['blocked']),
            'windows': entry['windows'], 'blocked_windows': entry['blocked_windows'],
            'rate': _round(len(entry['blocked']) / sources if sources else None, 4),
            'max_calibrated_probability': _round(entry['max_probability']),
            'max_conservative_bound': _round(entry['max_bound'])}
    return body


def worst_families(families):
    """The family that fails hardest on each side. §60."""
    positives = {n: e for n, e in families.items() if e['label'] == design.MALICIOUS}
    benign = {n: e for n, e in families.items() if e['label'] == design.BENIGN}
    worst_positive = min(positives.items(), key=lambda kv: (kv[1]['rate'], kv[0]),
                         default=(None, None))
    worst_benign = max(benign.items(), key=lambda kv: (kv[1]['rate'], kv[0]),
                       default=(None, None))
    return {'worst_positive_scenario': worst_positive[0],
            'worst_positive_detail': worst_positive[1],
            'worst_benign_scenario': worst_benign[0],
            'worst_benign_detail': worst_benign[1]}


def gate_effects(decisions):
    """§51, §52. What each restraint costs in true positives and saves in false ones.

    Counted over windows whose *bound already cleared the cutoff*, because that
    is the only population a gate can be said to have stopped. A gate that never
    sees a candidate block has no effect to report, and saying so is more useful
    than a count of every window it happened to be evaluated on.
    """
    cutoff = PROFILES['public_website'].threshold
    eligible = [d for d in decisions if d.conservative_probability >= cutoff]
    body = {'cutoff': _round(cutoff),
            'windows_clearing_the_cutoff': len(eligible),
            'malicious_clearing': sum(1 for d in eligible if d.label == design.MALICIOUS),
            'benign_clearing': sum(1 for d in eligible if d.label == design.BENIGN),
            'gates': {}}
    watched = ('INSUFFICIENT_SIGNAL_DIVERSITY', 'MODEL_ONLY_EVIDENCE',
               'INSUFFICIENT_DATA_QUALITY', 'INSUFFICIENT_OBSERVATIONS',
               'INSUFFICIENT_OBSERVATION_TIME', 'HIGH_OOD', 'UNCERTAINTY_HIGH',
               'ASSUMPTION_FAILED', 'BLOCK_BUDGET_EXHAUSTED', 'MARGIN_NOT_MET',
               'IDENTITY_UNCERTAIN', 'NOT_NETWORK_ENFORCEABLE', 'SHARED_PROXY_RISK',
               'POLICY_GUARD_REFUSED', 'NETWORK_BLOCK_NOT_PERMITTED')
    for code in watched:
        suppressed_true = sum(1 for d in eligible
                              if not d.blocked and code in d.reason_codes
                              and d.label == design.MALICIOUS)
        prevented_false = sum(1 for d in eligible
                              if not d.blocked and code in d.reason_codes
                              and d.label == design.BENIGN)
        if suppressed_true or prevented_false:
            body['gates'][code] = {'true_positive_windows_suppressed': suppressed_true,
                                   'false_positive_windows_prevented': prevented_false}
    return body


def detection_time(decisions):
    """§56, §57, §58. When a positive is caught, using only evidence up to then.

    Windows arrive in corpus order within a source, which is generation order,
    which is time order. The recorded index is the first window that blocked —
    nothing later is consulted, so the number cannot be inflated by hindsight.
    """
    grouped = defaultdict(list)
    for decision in decisions:
        grouped[decision.source_group or decision.sample_id].append(decision)
    caught, missed = [], 0
    benign_late = []
    for windows in grouped.values():
        label = windows[0].label
        first = next((index for index, w in enumerate(windows) if w.blocked), None)
        if label == design.MALICIOUS:
            if first is None:
                missed += 1
            else:
                caught.append({'windows': first + 1,
                               'seconds': _round(windows[first].observation_seconds, 3)})
        elif first is not None:
            benign_late.append({'family': windows[0].scenario_group,
                                'windows': first + 1})
    windows_to = sorted(entry['windows'] for entry in caught)
    seconds_to = sorted(entry['seconds'] for entry in caught)
    return {
        'positives_detected': len(caught), 'positives_missed': missed,
        'windows_to_first_block': {
            'min': windows_to[0] if windows_to else None,
            'median': windows_to[len(windows_to) // 2] if windows_to else None,
            'max': windows_to[-1] if windows_to else None},
        'observation_seconds_at_first_block': {
            'min': seconds_to[0] if seconds_to else None,
            'median': seconds_to[len(seconds_to) // 2] if seconds_to else None,
            'max': seconds_to[-1] if seconds_to else None},
        'benign_sources_blocked_at_all': len(benign_late),
        'benign_detail': benign_late[:10],
        'note': ('§58: a benign source that simply runs for a long time must not '
                 'accumulate its way into a block. Every benign source above is a '
                 'false block, and the count should be zero')}


def evaluate_role(role, *, calibrator, root='datasets', drop_keys=None, resamples=2000):
    """Everything the report needs about one corpus, in one pass."""
    decisions, dropped, rows = replay_role(role, calibrator=calibrator, root=root,
                                           drop_keys=drop_keys)
    sources, conflicts = outcomes(decisions, level='source')
    windows, _ = outcomes(decisions, level='window')
    families = per_family(decisions)
    body = {
        'p15_2_evaluation_version': P15_2_EVALUATION_VERSION,
        'role': role,
        'corpus': design.CORPORA[role][1],
        'rows_scored': len(decisions),
        'rows_dropped': dropped,
        'label_conflicts': conflicts,
        'calibrator': {'version': calibrator.version, 'method': calibrator.method,
                       'source': calibrator.source,
                       'model_version': calibrator.model_version,
                       'samples': calibrator.samples,
                       'digest': calibrator.digest},
        'per_source': ev.report(sources, resamples=400),
        'per_window': ev.report(windows, resamples=400),
        'bootstrap_by_source_group': group_bootstrap(decisions, resamples=resamples),
        'scenario_families': families,
        'worst': worst_families(families),
        'gate_effects': gate_effects(decisions),
        'detection_time': detection_time(decisions),
        'familiarity': {},
    }
    for view in ('seen', 'unseen'):
        subset = [d for d in decisions
                  if (d.scenario_group in design.WITHHELD_FAMILIES) == (view == 'unseen')]
        if not subset:
            continue
        subset_sources, _ = outcomes(subset, level='source')
        body['familiarity'][view] = ev.report(subset_sources, resamples=200)
    return body


def run(*, root='datasets', out=None, calibrator_path=None, resamples=2000):
    calibrator = load_calibrator(calibrator_path)
    body = {'p15_2_evaluation_version': P15_2_EVALUATION_VERSION,
            'candidate': dict(CANDIDATE),
            'freeze': design.freeze(root=root)}
    fitting = design.load_role(design.DEVELOPMENT, root)
    for role in design.CALIBRATION_ROLES:
        fitting = fitting + design.load_role(role, root)
    keys = set()
    locked = design.load_role(design.LOCKED_TEST, root)
    shared = design.duplicate_keys(fitting, locked)
    keys = shared
    body['locked_test'] = evaluate_role(design.LOCKED_TEST, calibrator=calibrator,
                                        root=root, drop_keys=keys, resamples=resamples)
    if out:
        Path(out).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return body


def render(body):
    """The tables the report quotes, rendered from the same object."""
    lines = []
    test = body['locked_test']
    src = test['per_source']['decision_metrics']
    win = test['per_window']['decision_metrics']
    lines.append('LOCKED TEST - ' + test['corpus'])
    lines.append(f"rows scored {test['rows_scored']}  dropped {test['rows_dropped']}")
    lines.append(f"calibrator {test['calibrator']['version']} "
                 f"({test['calibrator']['method']}, {test['calibrator']['samples']} samples, "
                 f"digest {test['calibrator']['digest'][:12]})")
    lines.append('')
    for name, block in (('SOURCE LEVEL', src), ('WINDOW LEVEL', win)):
        lines.append(f'--- {name} ---')
        if block['status'] != 'MEASURED':
            lines.append('  ' + block['status'])
            continue
        matrix = block['confusion_matrix']['matrix']
        lines += [
            '                       ALLOW   TEMP_BLOCK',
            f'  actual benign    {matrix[0][0]:9d} {matrix[0][1]:11d}',
            f'  actual malicious {matrix[1][0]:9d} {matrix[1][1]:11d}',
            f"  benign sample        {block['benign_sample']}",
            f"  positive sample      {block['positive_sample']}",
            f"  prevalence           {block['class_prevalence']}",
            f"  precision            {block['precision']}",
            f"  recall               {block['recall']}",
            f"  specificity          {block['specificity']}",
            f"  FPR                  {block['false_positive_rate']}",
            f"  FNR                  {block['false_negative_rate']}",
            f"  block precision      {block['block_precision']}",
            f"  false blocks / 1000  {block['false_blocks_per_1000_benign']}",
            '']
    lines.append(f"non-degenerate gate  {test['per_source']['non_degenerate_decision_gate']['verdict']}")
    lines.append(f"usefulness           {test['per_source']['usefulness']}")
    lines.append(f"release gate         {test['per_source']['release_gate']['verdict']}")
    for reason in test['per_source']['release_gate'].get('reasons', ()):
        lines.append(f'  - {reason}')
    lines.append('')
    lines.append('--- by familiarity (source level) ---')
    for view, report in test['familiarity'].items():
        metrics = report['decision_metrics']
        if metrics['status'] != 'MEASURED':
            lines.append(f'  {view}: {metrics["status"]}')
            continue
        lines.append(f"  {view:<7} benign {metrics['benign_sample']:>4} "
                     f"positive {metrics['positive_sample']:>4} "
                     f"recall {metrics['recall']} "
                     f"false/1000 {metrics['false_blocks_per_1000_benign']} "
                     f"block precision {metrics['block_precision']}")
    lines.append('')
    lines.append('--- scenario families ---')
    for name, entry in test['scenario_families'].items():
        lines.append(f"  {name:<28} {entry['familiarity']:<7} {entry['label'][:9]:<9} "
                     f"src {entry['sources']:>3} blocked {entry['blocked_sources']:>3} "
                     f"rate {entry['rate']!s:<7} max p {entry['max_calibrated_probability']!s:<9} "
                     f"max bound {entry['max_conservative_bound']}")
    return '\n'.join(lines)
