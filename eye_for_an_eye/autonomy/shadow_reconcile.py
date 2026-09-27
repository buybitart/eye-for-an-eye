"""Do the two evidence files describe the same decisions? P15S §41, §42, §43.

### Why this exists

The decision journal and the shadow export are written from the same
`PipelineOutcome`, in the same call, by the same bounded writer. Nothing should
be able to make them disagree.

That sentence is the reason to check. The whole of P15.5 was a set of components
that could not disagree either -- a forty-six column tensor into a thirty-six
column model, every unit test passing, the defect invisible from both sides. Two
files derived from one object is a weaker version of the same shape, and the
cheapest moment to discover a divergence is before three thousand sources of
evidence have been collected through it.

So this joins the two by `decision_id` and asks whether they agree about what
happened: the action, the counterfactual action, the mode, the cost profile, the
scope, the bound, the reason codes and the hour. It also answers §42's counting
question -- do the files hold the same decisions at all -- which catches the
failure that matters most to a validation window: an export that silently
dropped rows while the journal kept them.

### Two structural facts that would look like defects

**One decision can produce two journal entries.** `pipeline.decide()` journals
before the enforcement attempt so that a block always has a record that preceded
it rather than one that raced it, and journals again with the execution result
when an attempt happened. In shadow no attempt happens, so there is exactly one
entry per decision; in autonomous mode a block has two. The later entry is the
authoritative one and the earlier is deliberately kept. A reconciliation that
treated the second as a duplicate key would report every autonomous block as an
inconsistency.

**The export carries fewer reason codes.** It keeps
`EXPORT_REASON_CODE_LIMIT` of them; the journal keeps all. A shorter list in the
export is the bound doing its job, and only a *different* list is a
disagreement.

Neither of these is the rate-limited operational log, which §43 says must not be
used for counting at all. Nothing here reads it.

### What a disagreement means

Not much, on its own, and that is the point: it means the two derivations have
come apart, and the evidence should not be used until somebody knows why. This
module reports and does not repair. Choosing a winner between two files that
disagree about what the system decided would destroy the only signal that
anything is wrong.
"""
import json
from pathlib import Path

from .shadow_export import EXPORT_REASON_CODE_LIMIT, TIMESTAMP_BUCKET_SECONDS, bucket

RECONCILE_SCHEMA_VERSION = 1

#: Journal line schemas this build can read, for the reason `shadow_evidence`
#: refuses an unknown export row: a line read against the wrong field names
#: would produce a confident comparison of the wrong things.
SUPPORTED_JOURNAL_SCHEMAS = (1,)

AGREE = 'AGREE'
DISAGREE = 'DISAGREE'
EMPTY = 'EMPTY'

#: Floats are compared with a tolerance because both files carry the same value
#: through JSON, and a bound that differs in the sixteenth decimal place is the
#: same bound.
TOLERANCE = 1e-9


def read_journal(paths):
    """Journal lines, with an account of what could not be read."""
    rows, skipped = [], {'unparseable_lines': 0, 'unsupported_schema_rows': 0}
    targets = [paths] if isinstance(paths, (str, Path)) else list(paths)
    for path in targets:
        with open(path, encoding='utf-8') as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    skipped['unparseable_lines'] += 1
                    continue
                if row.get('journal_schema_version') not in SUPPORTED_JOURNAL_SCHEMAS:
                    skipped['unsupported_schema_rows'] += 1
                    continue
                rows.append(row)
    return rows, skipped


def journal_decisions(rows):
    """Decision id to its authoritative entry, plus how often it was amended.

    Later wins. The first entry is written before the enforcement attempt and
    carries no execution result; the amendment carries what happened. Both are
    kept on disk on purpose -- the first is the one that survives a crash
    between the two -- and only the last describes the finished decision.
    """
    found, amendments = {}, {}
    for row in rows:
        entry = row.get('entry') or {}
        decision = entry.get('decision') or {}
        key = decision.get('decision_id')
        if not key:
            continue
        if key in found:
            amendments[key] = amendments.get(key, 0) + 1
        found[key] = entry
    return found, amendments


def _float(value):
    return float(value) if isinstance(value, (int, float)) else None


def _same_number(left, right):
    left, right = _float(left), _float(right)
    if left is None or right is None:
        return left is right
    return abs(left - right) <= TOLERANCE


def compare_one(entry, row, *, bucket_seconds=TIMESTAMP_BUCKET_SECONDS):
    """Every field the two files both carry, and whether they say the same thing."""
    decision = entry.get('decision') or {}
    scope = entry.get('cost_scope') or {}
    cost = decision.get('cost') or {}

    journal_codes = list(decision.get('reason_codes') or ())
    export_codes = list(row.get('reason_codes') or ())
    # The export's list is a bounded prefix of the journal's, so a shorter list
    # is compared as a prefix and a longer one is a disagreement outright.
    codes_agree = (export_codes == journal_codes[:len(export_codes)]
                   and len(export_codes) == min(len(journal_codes),
                                                EXPORT_REASON_CODE_LIMIT))

    checks = {
        'would_action': (entry.get('would_action', decision.get('action')),
                         row.get('would_action')),
        'actual_action': (entry.get('actual_action'), row.get('actual_action')),
        'shadow': (bool(decision.get('shadow')), bool(row.get('shadow'))),
        'enforcement_withheld': (entry.get('enforcement_withheld', ''),
                                 row.get('enforcement_withheld', '')),
        'cost_profile': (scope.get('cost_profile'), row.get('profile_type')),
        'scope': (scope.get('scope'), row.get('scope')),
        'source_pseudonym': (decision.get('source_pseudonym'),
                             row.get('source_pseudonym')),
        'timestamp_bucket': (bucket(decision.get('timestamp'), size=bucket_seconds),
                             row.get('timestamp_bucket')),
    }
    differences = {name: {'journal': left, 'export': right}
                   for name, (left, right) in checks.items() if left != right}

    for name, left, right in (
            ('conservative_probability', cost.get('conservative_probability'),
             row.get('conservative_probability')),
            ('threshold', cost.get('threshold'),
             (row.get('expected_loss') or {}).get('threshold')),
            ('math_risk', (decision.get('math') or {}).get('risk'),
             row.get('math_risk'))):
        if not _same_number(left, right):
            differences[name] = {'journal': left, 'export': right}

    if not codes_agree:
        differences['reason_codes'] = {
            'journal': journal_codes[:EXPORT_REASON_CODE_LIMIT],
            'export': export_codes,
            'note': f'the export keeps at most {EXPORT_REASON_CODE_LIMIT}; a '
                    f'shorter list is the bound, a different one is not'}
    return differences


def reconcile(journal_paths, export_paths, *, sample=None):
    """§41, §42. The two files, joined by decision id and compared.

    `sample` compares only the first N joined decisions, for a periodic check
    during a long window. A sampled result says so, because "no disagreement in
    the first five hundred" and "no disagreement" are different claims.
    """
    from . import shadow_evidence as ev

    journal_rows, journal_skipped = read_journal(journal_paths)
    export_rows, export_skipped = ev.read_rows(export_paths)
    entries, amendments = journal_decisions(journal_rows)
    by_export = {}
    for row in export_rows:
        key = row.get('decision_id')
        if key:
            by_export[key] = row

    shared = sorted(set(entries) & set(by_export))
    examined = shared[:sample] if sample is not None else shared
    disagreements = []
    for key in examined:
        row = by_export[key]
        differences = compare_one(
            entries[key], row,
            bucket_seconds=row.get('bucket_seconds') or TIMESTAMP_BUCKET_SECONDS)
        if differences:
            disagreements.append({'decision_id': key, 'differences': differences})

    journal_only = sorted(set(entries) - set(by_export))
    export_only = sorted(set(by_export) - set(entries))

    def blocks(source, field):
        return sum(1 for value in source.values() if value.get(field) == 'TEMP_BLOCK')

    counts = {
        'journal_decisions': len(entries),
        'journal_lines': len(journal_rows),
        'journal_amendments': sum(amendments.values()),
        'export_decisions': len(by_export),
        'joined': len(shared),
        'examined': len(examined),
        'sampled': sample is not None and len(examined) < len(shared),
        'journal_only': len(journal_only),
        'export_only': len(export_only),
        'journal_would_block': sum(
            1 for entry in entries.values()
            if entry.get('would_action',
                         (entry.get('decision') or {}).get('action')) == 'TEMP_BLOCK'),
        'export_would_block': blocks(by_export, 'would_action'),
        'export_actual_block': blocks(by_export, 'actual_action'),
    }

    problems = []
    if disagreements:
        problems.append(f'{len(disagreements)} joined decisions are described '
                        f'differently by the journal and the export')
    if journal_only:
        problems.append(f'{len(journal_only)} decisions are in the journal and not '
                        f'in the export; the export dropped them, and a window '
                        f'missing decisions is incomplete by an amount that can '
                        f'at least be counted here')
    if export_only:
        problems.append(f'{len(export_only)} decisions are in the export and not '
                        f'in the journal, which should not be reachable: both are '
                        f'written from one outcome in one call')
    if counts['journal_would_block'] != counts['export_would_block']:
        problems.append(f"would-block counts differ: journal "
                        f"{counts['journal_would_block']}, export "
                        f"{counts['export_would_block']}")

    status = EMPTY if not shared and not journal_only and not export_only else (
        AGREE if not problems else DISAGREE)
    return {
        'reconcile_schema_version': RECONCILE_SCHEMA_VERSION,
        'status': status,
        'counts': counts,
        'skipped': {'journal': journal_skipped, 'export': export_skipped},
        'problems': problems,
        # Bounded: a reconciliation that printed ten thousand disagreements
        # would be read by nobody, and the first few are what gets investigated.
        'disagreements': disagreements[:20],
        'journal_only_ids': journal_only[:20],
        'export_only_ids': export_only[:20],
        'known_differences': [
            'one decision produces two journal entries when an enforcement '
            'attempt happened: the record written before it and the amendment '
            'carrying the result. The later one is compared',
            f'the export keeps at most {EXPORT_REASON_CODE_LIMIT} reason codes '
            f'and the journal keeps all of them',
            'the export coarsens its timestamp to the hour, so the journal '
            'timestamp is bucketed before comparison',
            'the rate-limited operational log is not read here and is not '
            'evidence (P15S §43)',
        ],
    }
