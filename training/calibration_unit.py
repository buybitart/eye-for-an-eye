"""What a calibrated probability is a probability *of*. §48.

### The question, and why it is not bookkeeping

`decision/calibration.py` fits a curve from scores to probabilities over
**windows**: every two-second snapshot of every source is one fitting point, and
the label attached to it is the label of the source it came from. So the number
it produces answers:

    given a window that scores like this, what fraction of such windows
    came from a malicious source?

The cost arithmetic in `autonomy/cost.py` compares that number against
`p* = C_FP / (C_FP + C_FN)`, where `C_FP` is the cost of blocking one **source**
that should not have been blocked. Those two units are not the same, and the
difference is not a rounding error: a source under observation for ten minutes
produces dozens of windows, and a block is taken the first time any one of them
crosses. A benign source therefore gets many independent chances to be wrong
about, while the probability it is judged by was fitted as though it got one.

Every earlier cycle in this project has calibrated per window and compared per
source, and no cycle has measured the gap. This module measures it.

### What is measured

For a sweep of cutoffs on the uncalibrated score — calibration is monotone, so
the ordering, and therefore every rate below, is identical before and after —
two quantities per cutoff:

* **per-window rate** — the fraction of benign *windows* at or above it, which
  is what a window-fitted calibrator's probability refers to;
* **per-source rate** — the fraction of benign *sources* with at least one such
  window, which is what a false block actually costs.

Their ratio is the multiplier by which a window-level calibration understates
the risk of the action it authorises. It is bounded below by 1 and above by the
number of windows per source, and where it actually sits is an empirical
property of how correlated a source's windows are.

### What this module does not do

It does not change a cutoff. §61 and §62 are explicit that `C_FP`, `C_FN` and
the public-website cutoff may not be moved to make results pass, and a
measurement that ended in a lower threshold would be exactly that. What it can
honestly support is a change of **unit** — which quantity the unchanged cutoff
is compared against — and a number for the report either way.
"""
from collections import defaultdict
import json
from pathlib import Path

from dataset import store
from eye_for_an_eye.autonomy.cost import PROFILES
from eye_for_an_eye.decision import composition as composition_module
from eye_for_an_eye.decision import families as families_module

CALIBRATION_UNIT_SCHEMA_VERSION = 1

DEVELOPMENT_CORPUS = 'datasets/p15-4-dev-v1/processed/dataset-p15-4-dev-v1/samples.csv'
BENIGN = 'benign_like'
MALICIOUS = 'malicious_automation_like'

#: Where to sample the sweep. Chosen to span the range the score actually
#: occupies rather than to bracket any particular threshold, and stated as a
#: constant so nobody can quietly pick the point that tells the nicest story.
CUTOFFS = (0.30, 0.40, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90)


def scored_windows(samples=None, path=DEVELOPMENT_CORPUS):
    """(label, source_group, score) for every window, through the live engine."""
    samples = samples if samples is not None else store.read(path)
    engine = composition_module.EvidenceCompositionEngine()
    rows = []
    for sample in samples:
        if sample.label not in (BENIGN, MALICIOUS):
            continue
        score, _ = engine.evaluate(families_module.effective(
            families_module.scores(sample.features)))
        rows.append((sample.label, sample.source_group or sample.sample_id, score))
    return rows


def measure(rows=None):
    """The window-versus-source gap, across the cutoff sweep."""
    rows = rows if rows is not None else scored_windows()
    windows = defaultdict(list)
    sources = defaultdict(lambda: defaultdict(float))
    for label, group, score in rows:
        windows[label].append(score)
        sources[label][group] = max(sources[label][group], score)
    out = []
    for cutoff in CUTOFFS:
        entry = {'cutoff': cutoff}
        for label, name in ((BENIGN, 'benign'), (MALICIOUS, 'malicious')):
            window_scores = windows[label]
            source_scores = list(sources[label].values())
            window_rate = sum(1 for s in window_scores if s >= cutoff) / max(1, len(window_scores))
            source_rate = sum(1 for s in source_scores if s >= cutoff) / max(1, len(source_scores))
            entry[name] = {
                'windows': len(window_scores),
                'sources': len(source_scores),
                'window_rate': round(window_rate, 6),
                'source_rate': round(source_rate, 6),
                'multiplier': round(source_rate / window_rate, 3) if window_rate else None}
        out.append(entry)
    return out


def document(rows=None):
    rows = rows if rows is not None else scored_windows()
    sweep = measure(rows)
    windows_per_source = {}
    for label in (BENIGN, MALICIOUS):
        counts = defaultdict(int)
        for row_label, group, _ in rows:
            if row_label == label:
                counts[group] += 1
        values = sorted(counts.values()) or [0]
        windows_per_source[label] = {
            'sources': len(values), 'median': values[len(values) // 2],
            'max': values[-1]}
    multipliers = [entry['benign']['multiplier'] for entry in sweep
                   if entry['benign']['multiplier'] is not None]
    return {
        'calibration_unit_schema_version': CALIBRATION_UNIT_SCHEMA_VERSION,
        'question': 'a calibrated probability is a probability of what',
        'corpus': DEVELOPMENT_CORPUS,
        'corpus_role': 'development, not a result',
        'fitted_unit_today': 'window',
        'cost_unit': 'source; C_FP prices one wrongly blocked source',
        'windows_per_source': windows_per_source,
        'sweep': sweep,
        'benign_multiplier_range': ([min(multipliers), max(multipliers)]
                                    if multipliers else None),
        'cost_cutoffs': {name: round(profile.threshold, 6) for name, profile in PROFILES.items()},
        'note': ('the multiplier is how much a window-fitted probability understates the '
                 'chance that the SOURCE it belongs to is blocked. It is bounded below by 1 '
                 'and above by the number of windows a source produces'),
    }


def write(path, rows=None):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document(rows), indent=1) + '\n', encoding='utf-8')
    return target
