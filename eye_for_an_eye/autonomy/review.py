"""The blinded view a labeller sees. P15.5R §9, §31-§39.

`docs/SHADOW_VALIDATION_PLAN.md` says a shadow deployment's release metric is
the false-block rate on that deployment's own traffic, and that the only source
of ground truth which scales to real traffic is a person reading the evidence.

That person must not be shown the answer first.

A reviewer who sees `would_action = TEMP_BLOCK`, or the reason codes, or the
evidence band, before deciding is a reviewer whose label is partly the system's
decision. The resulting number measures how well a person agrees with a system
that already told them what it thought, and it is biased in exactly the
direction the metric exists to test. §9 forbids deriving a label from a
decision; a label taken from a reviewer who was shown the decision is the same
thing with a human in the loop for decoration.

So this module projects an export row into what the reviewer gets: the
**evidence**, and nothing about the conclusion.

### Why a fixed keep-list rather than a remove-list

A remove-list is wrong by default. The moment a field is added to the export
row it appears in the reviewer's view unless somebody remembered to exclude it,
and the failure is silent — a leaked field looks exactly like a field that was
meant to be there. `KEEP` is therefore exhaustive and anything unrecognised is
dropped, so a new field is invisible to the reviewer until it is deliberately
listed.

### This is not a second data path

§8. Nothing here collects anything. It reads rows the sensor already wrote,
drops fields, and shuffles the order. No decision, no feature, no probability
is recomputed, and there is nothing in this module a sensor runs.
"""
import json
import random

REVIEW_VIEW_VERSION = 'shadow-review-view-v1'

#: Top-level fields the reviewer sees. Evidence about the source's behaviour,
#: and the identifier needed to join a label back afterwards.
KEEP = ('decision_id', 'source_pseudonym', 'site_pseudonym', 'scope',
        'profile_type', 'timestamp_bucket', 'bucket_seconds',
        'evidence_families', 'signal_diversity', 'behavioural_diversity',
        'ood_status', 'drift_status')

#: Fields inside `features` the reviewer sees. `contributions` is the only
#: feature-shaped thing an export row carries and it is what a person actually
#: reasons from: which behaviours were present and how strongly.
KEEP_FEATURES = ('schema_version', 'observations', 'observation_seconds',
                 'data_quality', 'contributions')

#: Everything the reviewer must not see, named so the test can assert on it and
#: so a reader of this file can check the keep-list against it rather than
#: inferring the intent. Every one of these is the system's conclusion or an
#: input to it.
WITHHELD = ('would_action', 'actual_action', 'shadow', 'enforcement_withheld',
            'reason_codes', 'evidence_band', 'math_risk', 'persistence',
            'calibrated', 'calibrated_probability', 'conservative_probability',
            'calibration_version', 'uncertainty', 'maturity', 'expected_loss',
            'policy_guard', 'model_health', 'ood_score', 'component_health',
            'review', 'label_policy', 'math_version')

#: What the reviewer writes. The same three labels `autonomy/evaluation.py`
#: accepts, and UNLABELED is a first-class answer rather than a failure to
#: decide: a forced label is worse evidence than no label.
LABELS = ('BENIGN', 'MALICIOUS_AUTOMATION', 'UNLABELED')


def blinded(row):
    """One export row as a reviewer sees it. Evidence in, conclusion out."""
    features = row.get('features') or {}
    view = {key: row[key] for key in KEEP if key in row}
    view['features'] = {key: features[key] for key in KEEP_FEATURES
                        if key in features}
    view['review_view_version'] = REVIEW_VIEW_VERSION
    # Written empty, by this software, every time — exactly as the export's own
    # `review` block is. The reviewer fills these in; nothing computes them.
    view['label'] = None
    view['label_confidence'] = None
    view['label_source'] = 'reviewed_evaluation'
    view['instructions'] = (
        'Decide from the behaviour described here alone. The system\'s own '
        'decision is deliberately absent. UNLABELED is a correct answer when '
        'the evidence does not settle it.')
    return view


def project(rows, *, seed=None):
    """Blind every row and shuffle, so position carries nothing.

    The order of an export file is the order decisions happened in, which is
    information: a reviewer working through a burst of consecutive rows from one
    hour will label them more alike than the evidence warrants. `seed` makes a
    review reproducible, which matters when somebody has to check it later.
    """
    out = [blinded(row) for row in rows]
    random.Random(seed).shuffle(out)
    return out


def read_export(path, *, limit=None):
    """Export rows from a JSONL file, skipping lines that do not parse.

    A truncated last line is what a full disk leaves behind (see
    `docs/BACKPRESSURE.md`); it is skipped rather than being allowed to abort a
    review of the thousands of rows that are intact.
    """
    rows, skipped = [], 0
    with open(path, encoding='utf-8') as stream:
        for line in stream:
            if not line.strip():
                continue
            if limit is not None and len(rows) >= limit:
                break
            try:
                rows.append(json.loads(line))
            except ValueError:
                skipped += 1
    return rows, skipped


def review_document(path, *, limit=None, seed=None):
    """The reviewer's pack for one export file, and what it does not contain."""
    rows, skipped = read_export(path, limit=limit)
    blinded_rows = project(rows, seed=seed)
    return {
        'review_view_version': REVIEW_VIEW_VERSION,
        'source': str(path),
        'rows': len(blinded_rows),
        'unparseable_lines_skipped': skipped,
        'shuffle_seed': seed,
        'labels': list(LABELS),
        'withheld_fields': list(WITHHELD),
        'note': ('the system\'s decision is withheld on purpose. A label taken '
                 'from a reviewer who was shown the decision is not independent '
                 'ground truth, and the false-block rate computed from it is '
                 'biased towards agreeing with the system'),
        'view': blinded_rows,
    }
