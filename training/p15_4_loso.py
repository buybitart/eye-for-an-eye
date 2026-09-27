"""Leave one out, twice over: by scenario family and by site profile. §52.

### What the two questions are

**Leave one scenario out.** Hold back one behaviour family, ask how the system
treats it, put it back, repeat for all of them. It answers: is this system
detecting *behaviour*, or has it learned the corpus? A detector that scores well
on average and collapses on whichever family is withheld has learned a list.

**Leave one profile out.** The same, grouped by site profile rather than family.
It answers something the first cannot: is the system's safety evenly spread, or
does it work on web traffic and quietly fail on APIs? P15.1, P15.2 and P15.3 all
reported that this could not be computed, because no corpus carried a site. This
is the first cycle in which it can be.

### What is and is not held out

The deterministic path — `families.py`, `composition.py`, `math_risk.py` — has
no fitted parameters, so nothing is retrained per fold and this is not
cross-validation in the usual sense. It is a **stability** analysis: the same
frozen engine scored on each subset separately, so that a family or a profile
whose behaviour it handles badly shows up as its own row instead of being
averaged away by the twenty that go well.

That distinction matters for how the numbers may be read. A weak fold here is
not evidence of overfitting — there is nothing fitted to overfit. It is evidence
that the evidence design does not cover that behaviour, which is a more useful
thing to learn and a harder one to fix.

### The number that carries the weight

Per fold, the worst benign source and the fraction of malicious sources scoring
above it. A per-fold AUC is reported too, but a fold holding one family has one
kind of positive and every kind of negative, so its AUC is easy to read wrongly;
the worst benign source is the honest summary because it is the number a cutoff
has to clear for that fold to be safe.
"""
from collections import defaultdict
import json
from pathlib import Path

from dataset import store
from eye_for_an_eye.decision import composition as composition_module
from eye_for_an_eye.decision import families as families_module

LOSO_SCHEMA_VERSION = 1

DEVELOPMENT_CORPUS = 'datasets/p15-4-dev-v1/processed/dataset-p15-4-dev-v1/samples.csv'
BENIGN = 'benign_like'
MALICIOUS = 'malicious_automation_like'


def sources(samples=None, path=DEVELOPMENT_CORPUS):
    """One row per source: label, family, profile, and its worst window score."""
    samples = samples if samples is not None else store.read(path)
    engine = composition_module.EvidenceCompositionEngine()
    rows = {}
    for sample in samples:
        if sample.label not in (BENIGN, MALICIOUS):
            continue
        score, _ = engine.evaluate(families_module.effective(
            families_module.scores(sample.features)))
        key = sample.source_group or sample.sample_id
        profile = (sample.provenance or {}).get('profile_type') or 'unstated'
        current = rows.get(key)
        if current is None:
            rows[key] = {'label': sample.label, 'family': sample.scenario_group,
                         'profile': profile, 'score': score,
                         'scenario': sample.scenario_id}
        elif score > current['score']:
            current['score'] = score
    return list(rows.values())


def fold(rows, held):
    """One fold's summary. `held` is the rows of the thing being looked at."""
    benign = [r['score'] for r in held if r['label'] == BENIGN]
    malicious = [r['score'] for r in held if r['label'] == MALICIOUS]
    # The bar is set by every benign source in the corpus, not only the ones in
    # this fold: a fold holding a malicious family has no benign members, and
    # "nothing benign here, so nothing to clear" would be a free pass.
    everyone_benign = [r['score'] for r in rows if r['label'] == BENIGN]
    bar = max(everyone_benign) if everyone_benign else 0.0
    return {
        'sources': len(held),
        'benign_sources': len(benign),
        'malicious_sources': len(malicious),
        'worst_benign_in_fold': round(max(benign), 6) if benign else None,
        'median_malicious_in_fold': (round(sorted(malicious)[len(malicious) // 2], 6)
                                     if malicious else None),
        'corpus_worst_benign': round(bar, 6),
        'malicious_above_every_benign': (round(sum(1 for s in malicious if s > bar)
                                               / len(malicious), 6) if malicious else None),
    }


def by_key(rows, key):
    groups = defaultdict(list)
    for row in rows:
        groups[row[key]].append(row)
    return {name: fold(rows, held) for name, held in sorted(groups.items())}


def document(rows=None):
    rows = rows if rows is not None else sources()
    families = by_key(rows, 'family')
    profiles = by_key(rows, 'profile')
    # Where the design is weakest, said out loud rather than left in a table of
    # forty rows for somebody to notice.
    missed = sorted(
        (name for name, entry in families.items()
         if entry['malicious_sources'] and (entry['malicious_above_every_benign'] or 0) < 0.5),
        key=lambda name: families[name]['malicious_above_every_benign'] or 0)
    exposed = sorted(
        (name for name, entry in families.items()
         if entry['benign_sources'] and (entry['worst_benign_in_fold'] or 0) >= 0.5),
        key=lambda name: -(families[name]['worst_benign_in_fold'] or 0))
    return {
        'loso_schema_version': LOSO_SCHEMA_VERSION,
        'question': ('does this detect behaviour or a corpus, and is its safety '
                     'spread evenly across site profiles'),
        'corpus': DEVELOPMENT_CORPUS,
        'corpus_role': 'development, not a result',
        'nothing_is_retrained': ('the deterministic path has no fitted parameters, so each '
                                 'fold is the same frozen engine scored on a subset. A weak '
                                 'fold means the evidence design does not cover that '
                                 'behaviour, not that something overfitted'),
        'leave_one_scenario_out': families,
        'leave_one_profile_out': profiles,
        'families_where_most_positives_do_not_clear_every_benign_source': missed,
        'families_whose_benign_sources_come_closest_to_being_blocked': exposed,
    }


def write(path, rows=None):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document(rows), indent=1) + '\n', encoding='utf-8')
    return target
