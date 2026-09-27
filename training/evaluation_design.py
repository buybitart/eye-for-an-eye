"""Which corpus may be used for what, and the freeze record that proves it.

P15 and P15.1 both measured on `dataset-eval-v1`. That makes it a development
set, whatever the filename says: every number anybody has looked at came from it,
and a threshold chosen after looking is a threshold fitted to it. §3 asks for a
final test that no decision was tuned against, so P15.2 stops using one corpus
for three jobs.

### Three corpora, one matrix, three salts

`dataset/scenarios.plans(salt=...)` mixes a salt into every scenario seed and
into the source-address shuffle, so the same 35 scenario definitions produce
independent draws. Same behaviours, different randomness, different sources.

| Role | Corpus | Used for | Touched |
| --- | --- | --- | --- |
| development | `dataset-eval-v1` | fitting candidates, every ablation, all diagnosis | freely |
| calibration | `dataset-cal-v1` | fitting calibrators, selecting between candidates | freely |
| locked test | `dataset-test-v1` | the final measurement | **once, after freeze** |

Independence is by construction rather than by promise: no scenario seed and no
run index is shared between two corpora, so no source in one is a re-observation
of a source in another. What they do share is the generators, which is the honest
limit — this measures generalisation to unseen *runs and families*, never to the
Internet.

### Seen and unseen families

`dataset/split.py` already withholds six scenario families from training
entirely, and that decision predates P15.2, so it cannot have been chosen to
flatter a result. Candidates are fitted only on rows whose family is outside that
set, which makes the withheld families genuinely unseen by every fitted component
— model and calibrator alike — in every corpus.

That gives the locked test two views, reported separately and never averaged
together (§59):

* **seen** — families the candidate trained on, drawn from sources it did not
* **unseen** — `scan-slow`, `credential-low-rate`, `hard-negative-health-check`,
  `hard-negative-admin`: behaviour no fitted component has met

The shipped classifier's own evaluation reports ROC-AUC 0.994 on the first and
0.517 on the second. Any candidate that reports one number for both is hiding
that gap rather than closing it.

### Aggregation: max over windows

A block applies to a source, so the source-level score is the maximum over its
windows. That is not a choice made for the metric — it is what the runtime does.
Windows arrive one at a time, each is decided on its own, and a source is blocked
the moment any window crosses. A mean would describe a system that waits for the
whole session and then decides on the average, which is not this system and would
flatter a scanner that is loud once and quiet afterwards.

`first_crossing` records *which* window crossed, so detection time (§56) is
measured from evidence available at the time rather than reconstructed
afterwards.
"""
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from dataset import split as split_module
from dataset.store import read

DESIGN_SCHEMA_VERSION = 1

DEVELOPMENT = 'development'
CALIBRATION = 'calibration'
CALIBRATION_2 = 'calibration_2'
LOCKED_TEST = 'locked_test'
#: P15.3. §2 permits the P15.2 locked test to be used for diagnosis, and P15.3
#: used it that way — which also spends it. A corpus that has been examined
#: cannot be the final evidence for a change made after examining it. This is
#: its replacement, generated from a different matrix: the only corpus that
#: contains the six composite families.
GENERALIZATION_TEST = 'generalization_test'
#: P15.4's own corpora, every row carrying a site and a profile (§41) and every
#: one of them containing authentication with an outcome.
#:
#: New calibration corpora were not a convenience. §59 requires the calibrator
#: to be refitted for `math-risk-v4`, and `cal-v1`/`cal2-v1` come from
#: `matrix-eval-v1`, which contains no authentication outcome at all — not one
#: refused login, not one successful one. A calibrator fitted there would map
#: the new formula's scores having never seen the evidence the new formula was
#: built to read, and would be most confident exactly where it knew least.
P15_4_DEVELOPMENT = 'p15_4_development'
P15_4_CALIBRATION = 'p15_4_calibration'
P15_4_CALIBRATION_2 = 'p15_4_calibration_2'
#: Two more, for the reason P15.2 wrote down when it added the second: a
#: conservative bound is a Wilson interval over the calibration data's own
#: examples, so its width is set by how many land in each score band, and the
#: response to an interval that is too wide is more examples rather than a lower
#: cutoff. Fitting on sources instead of windows (§48) divides the example count
#: by however many windows a source produces, so the correction that made the
#: probability honest also widened every interval — on two corpora the bound
#: saturated at 0.9644, below the public_website cutoff of 0.9756 and the api
#: cutoff of 0.9877, and no autonomous block was possible on either profile.
#: Four corpora is what buys that back without touching a single gate. The
#: locked test was not consulted before this decision and is unaffected by it.
P15_4_CALIBRATION_3 = 'p15_4_calibration_3'
P15_4_CALIBRATION_4 = 'p15_4_calibration_4'
P15_4_LOCKED_TEST = 'p15_4_locked_test'

#: P15.5's eight, and the number is not a preference. The P15.4 artifact's bound
#: is `wilson_lower(209, 209)` = 0.981951 against an `api` cutoff of 0.987654,
#: and 600 sources in the top band is what clears that cutoff while tolerating
#: two benign examples in the band. `reports/P15_5_CALIBRATION_PLAN.json` carries
#: the derivation and was committed before any of these corpora existed, which is
#: the only thing that makes eight a decision rather than a result.
P15_5_CALIBRATION_ROLE_NAMES = tuple(f'p15_5_calibration_{index}' for index in range(1, 9))
(P15_5_CALIBRATION_1, P15_5_CALIBRATION_2, P15_5_CALIBRATION_3, P15_5_CALIBRATION_4,
 P15_5_CALIBRATION_5, P15_5_CALIBRATION_6, P15_5_CALIBRATION_7,
 P15_5_CALIBRATION_8) = P15_5_CALIBRATION_ROLE_NAMES
P15_5_LOCKED_TEST = 'p15_5_locked_test'

ROLES = (DEVELOPMENT, CALIBRATION, CALIBRATION_2, LOCKED_TEST, GENERALIZATION_TEST,
         P15_4_DEVELOPMENT, P15_4_CALIBRATION, P15_4_CALIBRATION_2,
         P15_4_CALIBRATION_3, P15_4_CALIBRATION_4, P15_4_LOCKED_TEST,
         *P15_5_CALIBRATION_ROLE_NAMES, P15_5_LOCKED_TEST)

#: Every corpus used for fitting a calibrator. Two, and the reason is stated
#: because adding data after seeing a result is the shape of a mistake.
#:
#: The bound a calibrator supplies is a Wilson interval over its own examples,
#: so its width is set by how many examples land in each score band. On one
#: corpus the top band held about 380 windows and the band below it produced a
#: bound of 0.9731 against a `public_website` cutoff of 0.9756 — confident
#: detections refused by a hair of interval width rather than by evidence. The
#: response to an interval that is too wide is more examples, not a lower
#: cutoff; a second corpus halves the width without touching a single gate.
#:
#: The locked test was not consulted before this decision and is not affected
#: by it.
CALIBRATION_ROLES = (CALIBRATION, CALIBRATION_2)

#: role -> (directory under `datasets/`, dataset version, seed salt)
CORPORA = {
    DEVELOPMENT: ('eval-v1', 'dataset-eval-v1', ''),
    CALIBRATION: ('cal-v1', 'dataset-cal-v1', 'p15.2-calibration'),
    CALIBRATION_2: ('cal2-v1', 'dataset-cal2-v1', 'p15.2-calibration-2'),
    LOCKED_TEST: ('test-v1', 'dataset-test-v1', 'p15.2-locked-test'),
    GENERALIZATION_TEST: ('gen-test-v2', 'dataset-generalization-test-v2', 'p15.3-locked'),
    P15_4_DEVELOPMENT: ('p15-4-dev-v1', 'dataset-p15-4-dev-v1', 'p15.4-dev'),
    P15_4_CALIBRATION: ('p15-4-cal-v1', 'dataset-p15-4-cal-v1', 'p15.4-calibration'),
    P15_4_CALIBRATION_2: ('p15-4-cal2-v1', 'dataset-p15-4-cal2-v1', 'p15.4-calibration-2'),
    P15_4_CALIBRATION_3: ('p15-4-cal3-v1', 'dataset-p15-4-cal3-v1', 'p15.4-calibration-3'),
    P15_4_CALIBRATION_4: ('p15-4-cal4-v1', 'dataset-p15-4-cal4-v1', 'p15.4-calibration-4'),
    P15_4_LOCKED_TEST: ('p15-4-test-v1', 'dataset-p15-4-locked-v1', 'p15.4-locked'),
    **{role: (f'p15-5-cal{index}-v1', f'dataset-p15-5-cal{index}-v1',
              f'p15.5-calibration-{index}')
       for index, role in enumerate(P15_5_CALIBRATION_ROLE_NAMES, start=1)},
    P15_5_LOCKED_TEST: ('p15-5-test-v1', 'dataset-p15-5-locked-v1', 'p15.5-locked'),
}

#: Which scenario matrix built each corpus. Separate from `CORPORA` so that
#: adding a corpus from a different matrix cannot change the shape of the four
#: manifests P15.2 already wrote — those records have to stay readable exactly
#: as they are.
CORPUS_MATRIX = {
    DEVELOPMENT: 'dataset/scenarios/matrix-eval-v1.toml',
    CALIBRATION: 'dataset/scenarios/matrix-eval-v1.toml',
    CALIBRATION_2: 'dataset/scenarios/matrix-eval-v1.toml',
    LOCKED_TEST: 'dataset/scenarios/matrix-eval-v1.toml',
    GENERALIZATION_TEST: 'dataset/scenarios/matrix-generalization-v2.toml',
    P15_4_DEVELOPMENT: 'dataset/scenarios/matrix-p15-4-dev-v1.toml',
    P15_4_CALIBRATION: 'dataset/scenarios/matrix-p15-4-dev-v1.toml',
    P15_4_CALIBRATION_2: 'dataset/scenarios/matrix-p15-4-dev-v1.toml',
    P15_4_CALIBRATION_3: 'dataset/scenarios/matrix-p15-4-dev-v1.toml',
    P15_4_CALIBRATION_4: 'dataset/scenarios/matrix-p15-4-dev-v1.toml',
    P15_4_LOCKED_TEST: 'dataset/scenarios/matrix-p15-4-locked-v1.toml',
    **{role: 'dataset/scenarios/matrix-p15-5-cal-v1.toml'
       for role in P15_5_CALIBRATION_ROLE_NAMES},
    P15_5_LOCKED_TEST: 'dataset/scenarios/matrix-p15-5-locked-v1.toml',
}

#: Families withheld from training in every corpus, from the committed split
#: policy. The four in `test` are the strict unseen evaluation; the two in
#: `validation` are unseen during selection, which is what makes selection
#: itself honest about generalisation.
UNSEEN_IN_TEST = tuple(sorted(f for f, (t, _) in split_module.HOLDOUT.items() if t == 'test'))
UNSEEN_IN_SELECTION = tuple(sorted(f for f, (t, _) in split_module.HOLDOUT.items()
                                   if t == 'validation'))
WITHHELD_FAMILIES = tuple(sorted(split_module.HOLDOUT))

BENIGN = 'benign_like'
MALICIOUS = 'malicious_automation_like'


def corpus_root(role, root='datasets'):
    directory, version, _ = CORPORA[role]
    return Path(root) / directory / 'processed' / version


def load_role(role, root='datasets'):
    """Every row of one corpus, in corpus order."""
    return read(corpus_root(role, root) / 'samples.csv')


def fitting_rows(rows):
    """Rows a candidate may be fitted on: the train bucket, no withheld family.

    Both conditions, not either. The train bucket is already group-split by
    source, and excluding the withheld families by name as well means a future
    change to the bucketing cannot quietly let one in.
    """
    return [row for row in rows
            if row.split == 'train' and row.scenario_group not in split_module.HOLDOUT]


def selection_rows(rows):
    """Rows used to choose between candidates: the validation bucket.

    Includes the two families withheld into validation, so a candidate that only
    works on behaviour it has seen loses the comparison rather than winning it
    and failing later.
    """
    return [row for row in rows if row.split == 'validation']


def vector_key(sample):
    """What makes two windows the same observation.

    Values, rounded duration and sample count — the same key the replay uses to
    find vectors carrying two labels, so "duplicate" means one thing in this
    project.
    """
    vector = sample.features
    return (vector.values, round(vector.observation_seconds, 3), vector.sample_count)


def duplicate_keys(*corpora):
    """Vectors that appear in more than one of the given corpora."""
    seen = defaultdict(set)
    for index, rows in enumerate(corpora):
        for row in rows:
            seen[vector_key(row)].add(index)
    return {key for key, where in seen.items() if len(where) > 1}


def without_duplicates(rows, keys):
    """Drop rows whose vector also appears elsewhere. Returns (kept, dropped).

    §96. Two corpora from the same generators will occasionally produce the same
    bounded window — a very short benign session has only so many shapes. A test
    row that is bit-identical to a training row is not evidence about
    generalisation, and keeping it would make the test slightly easier in exactly
    the direction that flatters a memorising model. Dropping is conservative: it
    can only lower a score, never raise one.
    """
    kept = [row for row in rows if vector_key(row) not in keys]
    return kept, len(rows) - len(kept)


#: Families withheld *structurally* — their generators live in
#: `dataset/generators/withheld.py` and `tests/test_p15_4_withheld.py` refuses any
#: fitting matrix that names one. They are unseen in the strongest sense
#: available and `split_module.HOLDOUT` does not know about them, because that
#: list is about training splits and this is about corpora.
#:
#: **Found by the P15.5 locked benchmark.** `withheld-backup-sweep` and
#: `withheld-credential-drift` were scored as `seen`, so the unseen aggregate
#: excluded the only two families that had never been near a fitting corpus —
#: understating exactly the number a generalisation claim rests on. The
#: measurement was corrected afterwards and the P15.5 result was **not** rescored
#: (§25, §26); the corrected classification applies from the next cycle.
STRUCTURALLY_WITHHELD = ('withheld-backup-sweep', 'withheld-credential-drift',
                         'withheld-mobile-sync', 'withheld-probe-login')


def familiarity(row):
    """`unseen` when no fitted component has met this family, else `seen`."""
    if row.scenario_group in STRUCTURALLY_WITHHELD:
        return 'unseen'
    return 'unseen' if row.scenario_group in split_module.HOLDOUT else 'seen'


# --- the canonical source aggregation ---------------------------------------


@dataclass(frozen=True, slots=True)
class SourceOutcome:
    """One source, aggregated the way the runtime aggregates it."""

    source_group: str
    scenario_group: str
    label: str
    familiarity: str
    score: float
    windows: int
    #: Index of the first window whose score crossed the cutoff, or -1.
    first_crossing: int
    #: Observation seconds elapsed at that window, for detection time.
    first_crossing_seconds: float
    #: Cumulative windows observed before the crossing. §57: available at the
    #: time, not reconstructed from the end of the session.
    windows_to_crossing: int


def aggregate_sources(scored, *, threshold=None):
    """Group window scores into source outcomes by max, in arrival order.

    `scored` is an iterable of `(sample, score)`. Arrival order is the corpus
    order within a source group, which is generation order: the windows of one
    scenario run are emitted in time order by the feature builder.
    """
    grouped = defaultdict(list)
    for sample, score in scored:
        grouped[sample.source_group or sample.sample_id].append((sample, float(score)))
    outcomes = []
    for group, rows in sorted(grouped.items()):
        labels = {sample.label for sample, _ in rows}
        if len(labels) != 1:
            # Never silently pick a side: a source whose windows disagree about
            # ground truth is not ground truth.
            continue
        best = max(score for _, score in rows)
        crossing, crossing_seconds, windows_to = -1, 0.0, 0
        if threshold is not None:
            for index, (sample, score) in enumerate(rows):
                if score >= threshold:
                    crossing = index
                    crossing_seconds = float(sample.features.observation_seconds)
                    windows_to = index + 1
                    break
        first = rows[0][0]
        outcomes.append(SourceOutcome(
            source_group=str(group), scenario_group=str(first.scenario_group or ''),
            label=first.label, familiarity=familiarity(first), score=best,
            windows=len(rows), first_crossing=crossing,
            first_crossing_seconds=crossing_seconds, windows_to_crossing=windows_to))
    return outcomes


# --- the freeze record ------------------------------------------------------


def digest_file(path):
    target = Path(path)
    if not target.is_file():
        return ''
    sha = hashlib.sha256()
    with target.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            sha.update(chunk)
    return sha.hexdigest()


def manifest(role, rows, *, root='datasets'):
    """§2. Everything needed to say later exactly what was measured.

    Written before anything is fitted. A manifest produced afterwards records
    what survived, which is a different and much less useful document.
    """
    directory, version, salt = CORPORA[role]
    base = corpus_root(role, root)
    families = defaultdict(lambda: {'rows': 0, 'sources': set(), 'label': set()})
    sources = defaultdict(set)
    buckets = Counter()
    for row in rows:
        entry = families[row.scenario_group or 'none']
        entry['rows'] += 1
        entry['sources'].add(row.source_group)
        entry['label'].add(row.label)
        sources[row.label].add(row.source_group)
        buckets[row.split or 'none'] += 1
    seconds = sorted(row.features.observation_seconds for row in rows)
    counts = sorted(row.features.sample_count for row in rows)
    schema_versions = sorted({row.feature_schema_version for row in rows})
    return {
        'design_schema_version': DESIGN_SCHEMA_VERSION,
        'role': role,
        'dataset_version': version,
        'seed_salt': salt,
        'path': str(base / 'samples.csv'),
        'sha256': digest_file(base / 'samples.csv'),
        'manifest_sha256': digest_file(
            Path(root) / directory / 'manifests' / f'{version}.json'),
        'rows': len(rows),
        'sources': {label: len(group) for label, group in sorted(sources.items())},
        'source_total': len({row.source_group for row in rows}),
        'labels': dict(Counter(row.label for row in rows)),
        'label_sources': dict(Counter(str(row.label_source) for row in rows)),
        'source_types': dict(Counter(row.source_type for row in rows)),
        'split_buckets': dict(buckets),
        'scenario_families': {
            name: {'rows': entry['rows'], 'sources': len(entry['sources']),
                   'label': sorted(entry['label']),
                   'familiarity': 'unseen' if name in split_module.HOLDOUT else 'seen'}
            for name, entry in sorted(families.items())},
        'site_groups': dict(Counter(str(row.site_group) for row in rows)),
        'capture_groups': dict(Counter(str(row.capture_group) for row in rows)),
        'feature_schema_versions': schema_versions,
        'observation_seconds': {'min': seconds[0], 'median': seconds[len(seconds) // 2],
                                'max': seconds[-1]},
        'sample_count': {'min': counts[0], 'median': counts[len(counts) // 2],
                         'max': counts[-1]},
        'time_range': [min(row.timestamp for row in rows).isoformat(),
                       max(row.timestamp for row in rows).isoformat()],
        'withheld_families': list(WITHHELD_FAMILIES),
        'unseen_in_test': list(UNSEEN_IN_TEST),
        'unseen_in_selection': list(UNSEEN_IN_SELECTION),
    }


def freeze(root='datasets', out=None, roles=ROLES):
    """A manifest per corpus, plus the cross-corpus duplicate counts.

    A corpus that has not been generated is recorded as absent rather than
    skipped. The difference matters: this file is the answer to "what was
    measured", and a role quietly missing from it reads as a role that was never
    part of the design.
    """
    present, absent = {}, {}
    for role in roles:
        if (corpus_root(role, root) / 'samples.csv').is_file():
            present[role] = load_role(role, root)
        else:
            absent[role] = {'role': role, 'dataset_version': CORPORA[role][1],
                            'seed_salt': CORPORA[role][2],
                            'matrix': CORPUS_MATRIX.get(role, ''),
                            'status': 'NOT_GENERATED'}
    body = {'design_schema_version': DESIGN_SCHEMA_VERSION,
            'corpora': {role: manifest(role, data, root=root)
                        for role, data in present.items()}}
    body['corpora'].update(absent)
    # Lexicographic, as P15.2 wrote it: the pair keys in
    # `reports/P15_2_EVIDENCE_FREEZE.json` are compared against later runs by
    # name, so the naming stays put even though the role list has grown.
    order = sorted(present)
    overlaps = {}
    for index, first in enumerate(order):
        for second in order[index + 1:]:
            shared = duplicate_keys(present[first], present[second])
            affected = sum(1 for row in present[second] if vector_key(row) in shared)
            overlaps[f'{first}|{second}'] = {
                'identical_vectors': len(shared),
                f'{second}_rows_affected': affected,
                'note': 'independent draws of the same generators; a short benign '
                        'window has only so many shapes'}
    body['cross_corpus_duplicates'] = overlaps
    if out:
        Path(out).write_text(json.dumps(body, indent=1) + '\n', encoding='utf-8')
    return body
