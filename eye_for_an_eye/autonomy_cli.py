"""P15 operator commands for the autonomous decision authority.

    eye-for-an-eye autonomy readiness     the §186 gate: can this install be autonomous?
    eye-for-an-eye autonomy status        what mode it is in, and what the brakes are doing
    eye-for-an-eye autonomy policy        the cost model and the evidence gates, in full
    eye-for-an-eye autonomy explain FILE  read one decision record and say why
    eye-for-an-eye autonomy science FILE  rare-class metrics for the final decision
    eye-for-an-eye autonomy preflight     startup evidence, before a shadow period
    eye-for-an-eye autonomy review FILE   a shadow export, blinded for labelling
    eye-for-an-eye autonomy evidence FILE what a shadow period contains, so far
    eye-for-an-eye autonomy freeze FILE   hash the period and stop collecting
    eye-for-an-eye autonomy result FILE   the release numbers, from a frozen period
    eye-for-an-eye autonomy crosscheck FILE  journal against export, decision by decision

    eye-for-an-eye autonomy enable        check, then print exactly what to turn on

Seven things this file deliberately does not do.

**`enable` does not edit the configuration.** It runs the readiness gate, refuses
outright if a critical check fails, and otherwise prints the TOML to add. An
operator turning on the setting that lets this software block people without
being asked should see the setting, in their own file, in their own editor. A
command that wrote it for them would make the most consequential change in the
project the easiest one to make by accident.

**`explain` never re-decides.** It reads a record that was produced at decision
time and renders it. Recomputing the answer now, against today's model and
today's cost policy, would answer a different question from the one the reader
asked — which is always "why did it do that *then*".

**`science` does not measure production traffic.** Outcome metrics need trusted
labels, and live traffic has none. Run without a file it prints
`GROUND_TRUTH_UNAVAILABLE`, which is the honest answer and the usual one.

**`review` does not label anything.** It projects a shadow export into the view
a person labels from, with the system's own decision removed, because a label
taken from a reviewer who was shown the decision is not independent ground
truth. It writes `label: null` and leaves it there.

**`evidence` computes no rate.** It counts what a period holds while the period
is still running, which is what it is for. A rate over a growing window invites
somebody to watch it move and stop collecting when it looks right, and that is
not a measurement of anything. Rates come from `result`, after `freeze`.

**`result` refuses to be run on live files.** It takes the freeze manifest, not
an export, and re-hashes everything the manifest names before counting. A
number computed from evidence that changed after it was frozen is not a result,
and finding that out afterwards is finding it out too late.

**`crosscheck` repairs nothing.** It joins the journal and the export by
decision id and reports where they describe the same decision differently.
Picking a winner between two files that disagree about what the system decided
would destroy the only signal that anything is wrong — and it reads neither the
operational log nor anything else rate-limited, because §43 is explicit that
counting from those is how the P15.5R closeout went wrong the first time.
"""
import argparse
import json
from pathlib import Path

from .autonomy.record import AutonomousDecisionRecord, CODE_MEANINGS
from .autonomy.runtime import AutonomousRuntime, evaluate_readiness
from .config import load_config

AUTONOMY_CLI_SCHEMA_VERSION = 1


def _resolve(path):
    if path:
        return path
    default = Path('eye-for-an-eye.toml')
    return str(default) if default.is_file() else None


def _emit(payload, as_json, renderer):
    if as_json:
        print(json.dumps(payload, ensure_ascii=True))
    else:
        print(renderer(payload), end='')
    return 0


# --- readiness --------------------------------------------------------------

def render_readiness(document):
    lines = ['AUTONOMY READINESS', '']
    for check in document['checks']:
        mark = {'PASS': 'ok  ', 'FAIL': 'FAIL', 'NOT_APPLICABLE': 'n/a '}[check['status']]
        flag = '' if check['critical'] or check['status'] != 'FAIL' else ' (not critical)'
        lines.append(f'  [{mark}] {check["check"]}{flag}')
        lines.append(f'         {check["detail"]}')
    lines += ['', f'AUTONOMOUS_READY:\n{document["autonomous_ready"]}', '']
    if document['blocking']:
        lines.append('Blocked by:')
        lines += [f'  - {name}' for name in document['blocking']]
        lines.append('')
    lines += [f'Recommended mode:\n{document["recommended_mode"]}', '',
              document['note'], '']
    return '\n'.join(lines)


# --- status -----------------------------------------------------------------

def render_status(document):
    authority = document['authority']
    breakers = authority['breakers']
    counters = authority['counters']
    lines = ['AUTONOMY STATUS', '',
             f'Mode:\n{document["mode"]}', '',
             # Two different questions, so two lines. The mode says whether
             # decisions are in force; this says whether the brakes would allow
             # a block if they were.
             #
             # The value comes from the circuit-breaker panel, whose vocabulary
             # spells "no breaker is tripped" as AUTONOMOUS_ACTIVE. Printed bare
             # under a SHADOW deployment that reads as though blocking were on,
             # which is the opposite of what it says. The word stays — other
             # tools parse it, and `autonomy status --json` is unchanged — and
             # the line now says which question it answers.
             f'Brake state:\n{authority["runtime_state"]}'
             + ('' if document['mode'] == 'AUTONOMOUS' else
                f'\n  (this is the circuit breakers, not the mode: nothing is '
                f'tripped. Mode is {document["mode"]}, so no block is carried '
                f'out.)'), '',
             f'Decision authority:\n{authority["authority_version"]} '
             f'({"enabled" if authority["enabled"] else "not enabled"})', '',
             f'Cost policy:\n{authority["cost_policy"]["cost_policy_version"]} '
             f'({authority["cost_policy"]["cost_policy_digest"]})', '']
    if document.get('degraded_reason'):
        lines += [f'Degraded because:\n{document["degraded_reason"]}', '',
                  f'Cooldown remaining:\n{document["cooldown_remaining_seconds"]}s', '']
    lines += ['Decisions:',
              f'  ALLOW       {counters["allow"]}',
              f'  TEMP_BLOCK  {counters["block"]}',
              f'  suppressed  {counters["suppressed"]} '
              '(the arithmetic preferred a block, a gate refused)', '',
              'Block budget:',
              f'  {breakers["budget"]["recent_blocks_60s"]} in the last minute of '
              f'{breakers["budget"]["limits"]["blocks_per_minute"]}',
              f'  {breakers["budget"]["active_blocks"]} active of '
              f'{breakers["budget"]["limits"]["max_active_blocks"]}', '',
              'Circuit breakers:']
    for name in ('mass_block', 'false_positive', 'technical'):
        breaker = breakers[name]['breaker']
        detail = f' - {breaker["reason"]}' if breaker['reason'] else ''
        lines.append(f'  {name}: {breaker["state"]}{detail}')
    rate = breakers['false_positive']['false_blocks_per_1000']
    lines += ['',
              'False blocks per 1000 benign sources:',
              f'  {"GROUND_TRUTH_UNAVAILABLE" if rate is None else rate}'
              f' (source: {breakers["false_positive"]["ground_truth"]})', '',
              authority['note'], '']
    return '\n'.join(lines)


# --- review -----------------------------------------------------------------

def render_review(document):
    """The pack, and a header saying what was taken out of it and why.

    Printed before the rows rather than after, because a reviewer who reads the
    rows first and the caveat second has already formed an impression under the
    assumption that they were shown everything.
    """
    lines = ['SHADOW EXPORT, BLINDED FOR REVIEW', '',
             f'Source:\n{document["source"]}', '',
             f'Rows:\n{document["rows"]}'
             + (f' ({document["unparseable_lines_skipped"]} unparseable lines '
                f'skipped)' if document['unparseable_lines_skipped'] else ''), '',
             f'Labels you may write:\n{", ".join(document["labels"])}', '',
             'Withheld on purpose:',
             f'  {", ".join(document["withheld_fields"])}', '',
             document['note'], '',
             f'Shuffle seed:\n{document["shuffle_seed"]}', '',
             'Rows follow as JSON, one per line.', '']
    lines += [json.dumps(row, ensure_ascii=True) for row in document['view']]
    return '\n'.join(lines) + '\n'


# --- preflight (P15S §3, §4, §9, §10) ---------------------------------------


def _writable(paths):
    """§9. Can the evidence be written where it was told to write it?

    A permission check on the directory, not a write. It is the same advisory
    the health surface makes, said again here because a window that discovers
    its export directory is read-only on day three has lost three days, and
    because the two writers open lazily -- attaching them proves nothing.

    Named as advisory in the output. A directory that passes this can still
    refuse a write for a reason no check can see in advance, and `retention()`
    is what catches that afterwards.
    """
    import os
    rows = []
    for role, path in paths:
        if not path:
            rows.append({'role': role, 'path': '', 'status': 'NOT_CONFIGURED'})
            continue
        directory = Path(path).expanduser().resolve().parent
        if not directory.is_dir():
            status, detail = 'FAIL', 'the directory does not exist'
        elif not os.access(directory, os.W_OK | os.X_OK):
            status, detail = 'FAIL', 'the directory is not writable'
        else:
            status, detail = 'PASS', 'the directory exists and is writable'
        rows.append({'role': role, 'path': str(path), 'status': status,
                     'detail': detail})
    return rows


def preflight_document(config):
    """The startup evidence §4 asks to be saved, from the runtime rather than
    from the configuration text.

    §4 is specific about this: *do not rely on configuration text alone.* So
    this builds the real pipeline the way `decision/engine.py` builds it and
    reads its health, rather than reporting what the TOML said. A configuration
    that says `mode = "shadow"` and a pipeline that came up in some other state
    are different facts, and the second one is the one traffic meets.

    The enforcer is deliberately **not** attached. §3 requires that
    `HostEnforcer` is not constructed for autonomous blocking in shadow, and a
    preflight that constructed one to check that none exists would be answering
    its own question wrongly. What is reported instead is whether this
    configuration *would* attach one, which is the thing an operator needs to
    know before starting.
    """
    from .autonomy.pipeline import from_config as pipeline_from_config
    from .autonomy.scope import resolved_profile_mapping

    # The journal and the export *are* attached, so the component health below
    # distinguishes "configured" from "not configured" as the running sensor
    # would. Attaching does not open the files — `BoundedJsonlWriter` opens on
    # first write — so this says nothing about whether the paths are writable,
    # and `_writable` below is what asks that. Nothing is written through them
    # either: a preflight entry in the forensic record would look exactly like a
    # decision about a real source.
    pipeline = pipeline_from_config(config, attach_enforcer=False)
    try:
        health = pipeline.health()
    finally:
        for writer in (pipeline.journal, pipeline.shadow_export):
            if writer is not None:
                writer.close()
    readiness = evaluate_readiness(config)
    mapping = resolved_profile_mapping(config)

    autonomy = config.autonomy
    shadow = bool(pipeline.shadow)
    would_attach = bool(autonomy.enabled and not shadow
                        and config.enforcement.host_enabled)
    storage = _writable((('decision_journal', autonomy.decision_journal_path),
                         ('shadow_export', autonomy.shadow_export_path)))

    warnings = []
    for row in storage:
        if row['status'] == 'FAIL':
            warnings.append(f"{row['role']}: {row['path']} — {row['detail']}")
    if not shadow:
        warnings.append('this configuration is not shadow: P15S §3 requires '
                        'SHADOW for the whole evidence period')
    if would_attach:
        warnings.append('this configuration would attach a host enforcer, so '
                        'decisions would be acted on')
    if not autonomy.shadow_export_path:
        warnings.append('no shadow export is configured, so the period would '
                        'produce no analytic evidence')
    if not autonomy.decision_journal_path:
        warnings.append('no decision journal is configured, so there is no '
                        'canonical record to reconcile the export against')
    if mapping['sites_on_the_default']:
        warnings.append(
            f"{len(mapping['sites_on_the_default'])} configured site(s) resolve "
            f"to the default cost profile: "
            f"{', '.join(mapping['sites_on_the_default'][:8])}")

    return {
        'autonomy_cli_schema_version': AUTONOMY_CLI_SCHEMA_VERSION,
        # §4, read off a constructed pipeline.
        'runtime': {
            'pipeline_version': health['pipeline_version'],
            'mode': health['mode'],
            'shadow': shadow,
            'enabled': health['enabled'],
            'owns_enforcement': health['owns_enforcement'],
            'components': health['components'],
            'calibrator': health['calibrator'],
            'cost_policy': health['cost_policy'],
        },
        # §3, stated as the invariant rather than left to be inferred.
        'enforcement': {
            'host_enforcer_attached_by_this_preflight': False,
            'this_configuration_would_attach_one': would_attach,
            'autonomous_action': 'DISABLED' if shadow or not would_attach
                                 else 'ENABLED',
            'invariant': ('in shadow a would-block is recorded and no host '
                          'enforcer is constructed for it; actual host '
                          'TEMP_BLOCK must be 0 for the whole period'),
        },
        # §9, the part of it the health surface cannot answer.
        'storage': {'paths': storage,
                    'note': ('a permission check on the directory, not a write; '
                             'the writers open lazily, so attaching them proves '
                             'nothing about whether they can write')},
        # §10.
        'profile_mapping': mapping,
        # §9, through the gate that already runs those checks rather than a
        # second implementation of them.
        'readiness': readiness.explain(),
        'warnings': warnings,
        'ready_for_shadow': (shadow and not would_attach
                             and bool(autonomy.shadow_export_path)
                             and all(row['status'] != 'FAIL' for row in storage)),
        'note': ('startup evidence. Save it with the period it belongs to: §46 '
                 'and §47 make a configuration or code change the start of a '
                 'new evidence segment, and this is what says which one'),
    }


def render_preflight(document):
    runtime = document['runtime']
    enforcement = document['enforcement']
    mapping = document['profile_mapping']
    lines = ['SHADOW PREFLIGHT', '',
             'Mode (from the constructed pipeline, not the file):',
             f'  {runtime["mode"]}  shadow={runtime["shadow"]}  '
             f'enabled={runtime["enabled"]}', '',
             'Components:']
    lines += [f'  {name}: {status}'
              for name, status in sorted(runtime['components'].items())]
    lines += ['', 'Evidence paths:']
    for row in document['storage']['paths']:
        lines.append(f'  {row["role"]}: {row["status"]}'
                     + (f' — {row["path"]}' if row['path'] else ''))
    lines.append(f'  {document["storage"]["note"]}')
    lines += ['', 'Autonomous host action:',
              f'  {enforcement["autonomous_action"]}',
              f'  would this configuration attach an enforcer: '
              f'{enforcement["this_configuration_would_attach_one"]}',
              f'  {enforcement["invariant"]}', '',
              'Cost profile per site:']
    if mapping['sites']:
        for row in mapping['sites']:
            mark = '  <- the deployment default' if row['fell_back_to_default'] else ''
            lines.append(f'  {row["site"]}: {row["cost_profile"]} '
                         f'(cutoff {row["threshold"]:.4f}){mark}')
    else:
        lines.append(f'  multi-site is off; every decision is priced at '
                     f'{mapping["default_profile"]}')
    lines += ['', f'  {mapping["note"]}', '',
              f'Readiness gate (autonomous_ready): '
              f'{document["readiness"]["autonomous_ready"]}',
              '  Note: this gate answers whether the install could run '
              'autonomously.',
              '  A shadow period does not need it to pass, and a NO here is '
              'the expected',
              '  answer before any real evidence exists.']
    for check in document['readiness']['checks']:
        if check['status'] != 'PASS':
            lines.append(f'  {check["check"]}: {check["status"]} — {check["detail"]}')
    lines.append('')
    if document['warnings']:
        lines.append('Warnings:')
        lines += [f'  - {warning}' for warning in document['warnings']]
        lines.append('')
    lines += [f'Ready to collect shadow evidence: '
              f'{"YES" if document["ready_for_shadow"] else "NO"}', '',
              document['note'], '']
    return '\n'.join(lines)


# --- shadow evidence: evidence, freeze, result ------------------------------
#
# P15S §45, §50, §51, §52. Three commands and one rule shared between them: the
# arithmetic lives in `autonomy/shadow_evidence.py` and `autonomy/shadow_result.py`
# and is exercised by the test suite. What is here is argument handling and
# rendering, so that "the numbers in the report" and "the numbers this command
# prints" cannot become two different things.


def _period(path):
    """One export set, whole. See `shadow_evidence.period_files`."""
    from .autonomy.shadow_evidence import period_files
    files = period_files(path)
    if not files:
        raise ValueError(f'{path}: no export file of that name is there')
    return files


def _labels(path):
    from .autonomy.shadow_evidence import read_labels
    if not path:
        return {}, {'rows_read': 0, 'sources_labelled': 0,
                    'conflicting_sources': [], 'unusable_labels': {},
                    'rows_without_a_label': 0, 'skipped': {'unparseable_lines': 0},
                    'note': 'no label file was given, so no source is reviewed'}
    return read_labels(path)


def evidence_document(path, *, labels_path=None, limit=None):
    """§50. What is in the period, with no rate computed from it."""
    from .autonomy.shadow_evidence import summarise
    files = _period(path)
    labels, review = _labels(labels_path)
    document = summarise(files, labels=labels, limit=limit)
    document['files'] = [str(name) for name in files]
    document['review'] = review
    return document


def render_evidence(document):
    coverage = document['time_coverage']
    states = document['label_states']
    lines = ['SHADOW EVIDENCE PERIOD', '',
             'Files read (oldest first):']
    lines += [f'  {name}' for name in document['files']]
    lines += ['', f'Rows:\n  {document["rows_read"]} read, '
                  f'{document["skipped"]["unparseable_lines"]} unparseable, '
                  f'{document["skipped"]["unsupported_schema_rows"]} from an '
                  f'unreadable schema', '',
              'Sources and windows (these are different numbers):',
              f'  {document["sources"]} sources',
              f'  {document["windows"]} decision windows',
              f'  {document["would_block_sources"]} sources would have been blocked',
              '',
              'Time covered:',
              f'  {coverage["hour_buckets"]} hour buckets, '
              f'{coverage["first_bucket"]} to {coverage["last_bucket"]}', '',
              'Collections:']
    for name, entry in sorted(document['collections'].items()):
        lines.append(f'  {name}: {entry["sources"]} sources, '
                     f'{entry["windows"]} windows, '
                     f'{entry["would_block_sources"]} would-blocked')
    lines += ['', 'Review state:']
    lines += [f'  {name}: {count}' for name, count in sorted(states.items())]
    if document['review']['conflicting_sources']:
        lines.append(f'  CONFLICT: {len(document["review"]["conflicting_sources"])} '
                     f'(reviewers disagreed; excluded from every rate)')
    if document['degraded_sources']:
        lines += ['', f'Degraded: {document["degraded_sources"]} sources have '
                      f'decisions taken while a component was DEGRADED or '
                      f'UNAVAILABLE']
    spread = document['distributions']
    lines += ['', f'Decision distribution ({spread["unit"]}):']
    for row in spread['conservative_probability']:
        if row['count']:
            lines.append(f'  conservative bound {row["from"]:.4f}–{row["to"]:.4f}: '
                         f'{row["count"]}')
    lines.append(f'  {spread["histogram_note"]}')
    if spread['evidence_families']:
        lines += ['', 'Families contributing to a would-block:']
        lines += [f'  {entry["name"]}: {entry["windows"]}'
                  for entry in spread['evidence_families'][:8]]
    if spread['reason_codes']:
        lines += ['', 'Reason codes on a would-block:']
        lines += [f'  {entry["name"]}: {entry["windows"]}'
                  for entry in spread['reason_codes'][:8]]
    suppression = spread['suppression']
    if suppression['suppressed_windows']:
        lines += ['', f'Suppressed: {suppression["suppressed_windows"]} windows '
                      f'where the bound reached the threshold and no block was '
                      f'decided']
        lines += [f'  {entry["name"]}: {entry["windows"]}'
                  for entry in suppression['failed_gates'][:8]]
        if suppression['leading_gate_share'] is not None:
            lines.append(f'  leading gate accounts for '
                         f'{suppression["leading_gate_share"]:.0%} of them')
        lines.append(f'  {suppression["note"]}')
    lines += ['', document['note'], '',
              'No rate is printed here on purpose. Freeze the period first:',
              '  eye-for-an-eye autonomy freeze <export>', '']
    return '\n'.join(lines)


def freeze_document(path, *, labels_path=None, journal=(), segment='',
                    commit='', runtime_version='', config_digest='',
                    started_at=None):
    """§51. The period, hashed, with the counts it supported at that instant."""
    from .autonomy.shadow_evidence import freeze
    files = _period(path)
    labels, _review = _labels(labels_path)
    return freeze(export_paths=files, labels=labels,
                  journal_paths=[Path(name) for name in journal],
                  segment_id=segment, git_commit=commit,
                  runtime_version=runtime_version, config_digest=config_digest,
                  started_at=started_at)


def render_freeze(document):
    summary = document['summary']
    keeping = document['retention']
    lines = ['SHADOW EVIDENCE FROZEN', '',
             f'Segment:\n  {document["segment_id"] or "(unset)"}', '',
             f'Build:\n  runtime {document["runtime_version"] or "(unset)"} '
             f'at commit {document["git_commit"] or "(unset)"}', '',
             'Files, with the hashes the result will be checked against:']
    for entry in document['files']:
        lines.append(f'  {entry["role"]:18s} {entry["bytes"]:>12d}  '
                     f'{entry["sha256"][:16]}...  {entry["path"]}')
    lines += ['', f'Contents:\n  {summary["sources"]} sources over '
                  f'{summary["windows"]} windows', '']
    if not keeping['complete']:
        lines.append('EVIDENCE IS INCOMPLETE:')
        lines += [f'  - {reason}' for reason in keeping['reasons']]
        lines += ['', f'  {keeping["note"]}', '']
    lines += [document['note'], '',
              'Next: label a blinded review pack, then',
              '  eye-for-an-eye autonomy result <this manifest> --labels <pack>', '']
    return '\n'.join(lines)


def crosscheck_document(journal_path, *, export_path, sample=None):
    """§41, §42. Do the journal and the export describe the same decisions?

    Named `crosscheck` rather than `reconcile` because the privileged firewall
    helper already has a `reconcile` verb, and that one reconciles kernel state
    against intended blocks. Two commands called reconcile that reconcile
    different things is how an operator runs the wrong one in a hurry.
    """
    from .autonomy.shadow_reconcile import reconcile
    return reconcile(_period(journal_path), _period(export_path), sample=sample)


def render_crosscheck(document):
    counts = document['counts']
    lines = [f'CROSS-SURFACE CHECK: {document["status"]}', '',
             'Decisions:',
             f'  journal {counts["journal_decisions"]} '
             f'({counts["journal_lines"]} lines, '
             f'{counts["journal_amendments"]} amendments)',
             f'  export  {counts["export_decisions"]}',
             f'  joined  {counts["joined"]}'
             + (f' ({counts["examined"]} examined, sampled)'
                if counts['sampled'] else ''), '',
             'Would-block:',
             f'  journal {counts["journal_would_block"]}',
             f'  export  {counts["export_would_block"]}',
             f'  actual host blocks: {counts["export_actual_block"]}', '']
    if document['problems']:
        lines.append('Problems:')
        lines += [f'  - {problem}' for problem in document['problems']]
        lines.append('')
    for difference in document['disagreements']:
        lines.append(f'  {difference["decision_id"]}:')
        for field, sides in difference['differences'].items():
            lines.append(f'    {field}: journal {sides.get("journal")!r} '
                         f'!= export {sides.get("export")!r}')
    if document['disagreements']:
        lines.append('')
    if document['journal_only_ids']:
        lines += ['In the journal and not the export:']
        lines += [f'  {name}' for name in document['journal_only_ids']]
        lines.append('')
    lines.append('Known differences, none of which is a defect:')
    lines += [f'  - {line}' for line in document['known_differences']]
    lines.append('')
    return '\n'.join(lines)


def result_document(path, *, labels_path=None, root=None):
    """§52. The numbers, from a freeze manifest, against the thresholds."""
    from .autonomy.shadow_result import from_manifest
    try:
        document = json.loads(Path(path).read_text(encoding='utf-8'))
    except ValueError as exc:
        # An export is JSONL, so pointing this at one fails on the second line
        # with "Extra data" -- a message about JSON, for a mistake about
        # evidence. Say which file was wanted instead.
        raise ValueError(f'{path}: not a freeze manifest ({exc}). Freeze the '
                         'period first: eye-for-an-eye autonomy freeze <export>'
                         ) from exc
    if not isinstance(document, dict) or not document.get('frozen'):
        raise ValueError(f'{path}: not a freeze manifest. A result is computed '
                         'from frozen evidence, never from files still being '
                         'written to')
    labels, review = _labels(labels_path)
    body = from_manifest(document, labels, root=root)
    body['review'] = review
    return body


def render_result(document):
    verdict = document['verdict']
    lines = [f'SHADOW RESULT: {verdict["verdict"]}', '',
             f'Frozen evidence:\n  {document["evidence"]["status"]}', '']
    if 'overall' in document:
        overall = document['overall']
        rates = overall['false_would_blocks']
        precision = overall['block_precision']
        lines += ['False would-blocks (the release metric):',
                  f'  {rates["false_would_block_sources"]} of '
                  f'{rates["benign_sources"]} reviewed benign sources',
                  f'  {rates["per_1000_benign"]} per 1000, '
                  f'95% upper bound {rates["upper_bound_95_per_1000"]} per 1000', '',
                  'Would-block precision:',
                  f'  {precision["precision"]} over '
                  f'{precision["reviewed_would_block_sources"]} reviewed blocks, '
                  f'95% lower bound {precision["lower_bound_95"]}', '',
                  'Kept apart on purpose:',
                  f'  naturally observed positives: '
                  f'{overall["natural_positive_recall"]["sources"]} sources, '
                  f'recall {overall["natural_positive_recall"]["recall"]}',
                  f'  controlled positive tests:    '
                  f'{overall["controlled_positive_recall"]["sources"]} sources, '
                  f'recall {overall["controlled_positive_recall"]["recall"]}', '']
    if verdict['verdict'] == 'INSUFFICIENT_EVIDENCE':
        lines += ['Not enough evidence to decide:']
        lines += [f'  - {reason}' for reason in verdict['sufficiency']['reasons']]
        lines.append('')
    if verdict['failing_checks']:
        lines += ['Failed:']
        lines += [f'  - {reason}' for reason in verdict['failing_checks']]
        lines.append('')
    if 'per_profile' in document:
        lines.append('By cost profile (not averaged together):')
        for entry in document['per_profile']:
            rates = entry['false_would_blocks']
            lines.append(f'  {entry["profile"]}: '
                         f'{rates["false_would_block_sources"]}/'
                         f'{rates["benign_sources"]} benign, bound '
                         f'{rates["upper_bound_95_per_1000"]} per 1000')
        lines.append('')
    if 'assumptions' in document:
        lines.append('Assumptions, each of which widens the true uncertainty:')
        lines += [f'  - {line}' for line in document['assumptions']]
        lines.append('')
    lines += [verdict['note'], '']
    return '\n'.join(lines)


# --- policy -----------------------------------------------------------------

def policy_document(config):
    from .autonomy.authority import from_config as authority_from_config
    authority = authority_from_config(config)
    return {'autonomy_cli_schema_version': AUTONOMY_CLI_SCHEMA_VERSION,
            'cost_policy': authority.cost_policy.explain(),
            'gates': authority.gates.explain(),
            'breaker_limits': authority.panel.limits.explain()}


def render_policy(document):
    costs = document['cost_policy']
    lines = ['AUTONOMY POLICY', '',
             f'Cost policy:\n{costs["cost_policy_version"]}', '',
             'Costs are relative weights, not money. C_FN = 1.0 is the reference',
             'unit: a false-block cost of 40 means blocking one real visitor is',
             'judged forty times worse than letting one automated source carry on',
             'for one block interval. None of these numbers is measured.', '',
             'Cost profiles:']
    for name, profile in costs['profiles'].items():
        mark = '' if profile['network_block_permitted'] else '  [never network-blocks]'
        lines.append(f'  {name}: C_FP={profile["false_block"]:g} '
                     f'C_FN={profile["false_allow"]:g} '
                     f'cutoff={profile["threshold"]:.4f}{mark}')
        lines.append(f'      {profile["description"]}')
    lines += ['', f'Default profile:\n{costs["default_profile"]}', '',
              f'Decision margin:\n{costs["decision_margin"]}', '',
              f'Release margin (hysteresis):\n{costs["release_margin"]}', '']
    if costs['scope_profiles']:
        lines.append('Scope mappings:')
        lines += [f'  {scope} -> {name}'
                  for scope, name in sorted(costs['scope_profiles'].items())]
        lines.append('')
    gates = document['gates']
    lines += ['Evidence gates for a block:',
              f'  observations            >= {gates["minimum_observations"]}',
              f'  observation seconds     >= {gates["minimum_observation_seconds"]}',
              f'  data quality            >= {gates["minimum_data_quality"]}',
              f'  signal families         >= {gates["minimum_signal_diversity"]}',
              f'  behavioural families    >= {gates["minimum_behavioural_diversity"]}',
              f'  decision uncertainty    <= {gates["maximum_uncertainty"]}', '',
              'Block durations (escalating, capped):',
              f'  {", ".join(str(value) + "s" for value in gates["block_ttl_ladder"])}',
              f'  hard ceiling: {gates["maximum_block_ttl_seconds"]}s. '
              'No autonomous block is ever permanent.', '']
    return '\n'.join(lines)


# --- explain ----------------------------------------------------------------

def explain_document(path):
    """Read one decision record from disk and render what it says.

    Tolerant about shape and strict about meaning: a record from a newer schema
    is refused rather than read against the wrong field names.
    """
    payload = json.loads(Path(path).read_text(encoding='utf-8'))
    version = payload.get('record_version')
    if version != AutonomousDecisionRecord.__dataclass_fields__[
            'record_version'].default:
        raise ValueError(f'decision record version {version!r} is not understood by '
                         'this build; reading it against the wrong field names would '
                         'produce a confident account of a decision nobody made')
    return payload


def render_explain(document):
    cost = document.get('cost', {})
    evidence = document.get('evidence', {})
    lines = [f'{document["action"]} — {document.get("scope", "")}', '',
             f'Decision:\n{document["decision_id"]} at {document["timestamp"]}', '',
             f'Risk evidence:\n{evidence.get("band", "unknown").lower()} '
             f'(conservative estimate {cost.get("conservative_probability", 0):.3f}, '
             f'cutoff {cost.get("threshold", 0):.3f} under cost profile '
             f'{cost.get("profile", "unset")})', '',
             f'Independent evidence families:\n{evidence.get("signal_diversity", 0)} '
             f'({evidence.get("behavioural_diversity", 0)} describing behaviour)', '',
             'Reasons:']
    for code in document.get('reason_codes', ()):
        lines.append(f'  {code}: {CODE_MEANINGS.get(code, "")}')
    lines += ['', f'Expected loss:\n  allow {cost.get("loss_allow", 0):.4f}'
                  f'\n  block {cost.get("loss_block", 0):.4f}', '']
    if document.get('block_ttl_seconds'):
        lines += [f'Block TTL:\n{document["block_ttl_seconds"]}s, then it expires '
                  'with no human action', '']
    failed = (document.get('assumptions') or {}).get('failed') or []
    if failed:
        lines += ['Assumptions that did not hold:'] + [f'  - {name}' for name in failed] + ['']
    lines += ['\n'.join(document.get('limitations', ())), '']
    return '\n'.join(lines)


# --- science ----------------------------------------------------------------

def science_document(path=None):
    """The §155 report: rare-class metrics for the final decision, or nothing.

    With no trusted evaluation file this prints `GROUND_TRUTH_UNAVAILABLE` and
    stops. That is the honest answer, and it is the answer in production:
    unlabelled traffic cannot produce accuracy, and a number computed from the
    system's own decisions would be the self-labelling loop in a report format.
    """
    from .autonomy import evaluation as ev
    if not path:
        return {'autonomy_cli_schema_version': AUTONOMY_CLI_SCHEMA_VERSION,
                'status': ev.GROUND_TRUTH_UNAVAILABLE,
                'note': ('no trusted labelled evaluation was given. Outcome metrics '
                         'need ground truth from a controlled scenario, a signed '
                         'capture sidecar, a deterministic harness or a reviewed '
                         'evaluation. Live traffic is not one of those.'),
                'accepted_label_sources': list(
                    __import__('eye_for_an_eye.autonomy.breakers', fromlist=['x'])
                    .TRUSTED_OUTCOME_SOURCES)}
    rows = []
    for entry in json.loads(Path(path).read_text(encoding='utf-8')):
        rows.append(ev.Outcome(blocked=bool(entry.get('blocked')),
                               label=str(entry.get('label', ev.UNLABELED)),
                               site_id=str(entry.get('site_id', ''))[:64],
                               score=entry.get('score'),
                               label_source=str(entry.get('label_source', ''))[:64]))
    body = ev.report(rows)
    body['autonomy_cli_schema_version'] = AUTONOMY_CLI_SCHEMA_VERSION
    body['status'] = 'MEASURED' if rows else ev.GROUND_TRUTH_UNAVAILABLE
    return body


def render_science(document):
    if document.get('status') != 'MEASURED':
        return ('SCIENTIFIC HEALTH REPORT\n\n'
                f'{document["status"]}\n\n{document.get("note", "")}\n')
    metrics = document['decision_metrics']
    lines = ['SCIENTIFIC HEALTH REPORT', '',
             f'Ground truth:\n{metrics["status"]}', '']
    if metrics['status'] != 'MEASURED':
        return '\n'.join(lines + [metrics.get('note', ''), ''])
    matrix = metrics['confusion_matrix']['matrix']
    lines += ['Final TEMP_BLOCK decision, against trusted labels:',
              '                      ALLOW    TEMP_BLOCK',
              f'  actual benign   {matrix[0][0]:9d} {matrix[0][1]:11d}',
              f'  actual malicious{matrix[1][0]:9d} {matrix[1][1]:11d}', '',
              f'Class prevalence:\n{metrics["class_prevalence"]}', '',
              f'Precision:\n{metrics["precision"]}', '',
              f'Recall:\n{metrics["recall"]}', '',
              f'Specificity:\n{metrics["specificity"]}', '',
              f'False positive rate:\n{metrics["false_positive_rate"]}', '',
              f'False negative rate:\n{metrics["false_negative_rate"]}', '',
              f'Block precision:\n{metrics["block_precision"]}', '',
              f'False blocks per 1000 benign:\n'
              f'{metrics["false_blocks_per_1000_benign"]}', '',
              f'Accuracy:\n{metrics["accuracy"]}',
              f'  {metrics["accuracy_note"]}', '',
              f'Sample:\n{metrics["benign_sample"]} benign, '
              f'{metrics["positive_sample"]} malicious automation', '',
              'Ranking (over the conservative estimate):',
              f'  ROC-AUC  {document["ranking"].get("roc_auc")}',
              f'  PR-AUC   {document["ranking"].get("pr_auc")}', '',
              'Precision at other prevalences:']
    for row in document.get('prevalence_sweep', ()):
        lines.append(f'  {row["prevalence"]:>8}  precision {row["precision"]}')
    lines.append('')
    bootstrap = document.get('bootstrap') or {}
    if bootstrap:
        lines.append('Empirical bootstrap intervals:')
        for name, interval in sorted(bootstrap.items()):
            if interval:
                lines.append(f'  {name}: {interval["statistic_low"]} .. '
                             f'{interval["statistic_high"]} '
                             f'({interval["resamples"]} resamples)')
        lines.append('')
    worst = document.get('worst_site')
    if worst:
        lines += [f'Worst site:\n{worst["site"]} — '
                  f'{worst["metrics"]["false_blocks_per_1000_benign"]} false blocks '
                  'per 1000 benign', '']
    gate = document['release_gate']
    lines += [f'Usefulness:\n{document["usefulness"]}', '',
              f'Release gate:\n{gate["verdict"]}']
    for reason in gate.get('reasons', ()):
        lines.append(f'  - {reason}')
    lines.append('')
    return '\n'.join(lines)


# --- enable -----------------------------------------------------------------

#: What an operator must type to turn autonomous decisions on.
#:
#: P15.5R §44. This omitted `calibrator_path`, which the same cycle made
#: mandatory for autonomous mode — so the command whose entire job is to say
#: what to type printed four lines that `config validate` refuses to load. The
#: gate did not catch it either: without a calibrator the readiness check is a
#: *warning* in shadow mode, deliberately, and `render_enable` printed only
#: blocking failures. So a shadow deployment with no calibrator was told
#: AUTONOMOUS_READY: YES and handed a configuration that cannot start.
#:
#: The snippet is therefore built from the configuration rather than being a
#: constant, and it says plainly when it is not complete.
SNIPPET_TAIL = """
# Optional: a cost profile per scope.
# [autonomy.cost_profiles]
# "SITE:payments" = "payment_webhook"
# "SITE:api" = "api"
"""

CALIBRATOR_REQUIRED = (
    '# REQUIRED for mode = "autonomous": the path to this build\'s calibrator.\n'
    '# Without one every block is refused with CALIBRATION_UNAVAILABLE, and the\n'
    '# configuration will not validate. Ship one, or use mode = "shadow".\n'
    'calibrator_path = ""\n')


def enable_snippet(config):
    """The TOML to add, and whether the operator still has to fill something in."""
    autonomy = getattr(config, 'autonomy', None)
    calibrator = str(getattr(autonomy, 'calibrator_path', '') or '')
    profile = str(getattr(autonomy, 'default_cost_profile', '') or 'public_website')
    lines = ['[autonomy]', 'enabled = true', 'mode = "autonomous"',
             f'default_cost_profile = "{profile}"']
    if calibrator:
        lines.append(f'calibrator_path = "{calibrator}"')
        return '\n'.join(lines) + '\n' + SNIPPET_TAIL, True
    return '\n'.join(lines) + '\n' + CALIBRATOR_REQUIRED + SNIPPET_TAIL, False


def enable_document(config):
    report = evaluate_readiness(config)
    body = report.explain()
    body['autonomy_cli_schema_version'] = AUTONOMY_CLI_SCHEMA_VERSION
    snippet, complete = enable_snippet(config)
    body['configuration_to_add'] = snippet if report.ready else ''
    body['configuration_is_complete'] = bool(report.ready and complete)
    body['already_enabled'] = bool(getattr(config.autonomy, 'enabled', False))
    return body


def render_enable(document):
    if not document['checks']:
        return 'no checks ran\n'
    if document['autonomous_ready'] != 'YES':
        lines = ['AUTONOMY NOT ENABLED', '',
                 'The readiness gate did not pass, so nothing was changed and no',
                 'configuration is suggested. Fix these first:', '']
        lines += [f'  - {name}' for name in document['blocking']]
        lines += ['', 'Then run: eye-for-an-eye autonomy readiness', '']
        return '\n'.join(lines)
    if document['already_enabled']:
        return ('AUTONOMY ALREADY ENABLED\n\n'
                'The readiness gate passes and [autonomy] enabled is already true.\n'
                'Run: eye-for-an-eye autonomy status\n')
    # Non-critical failures are printed here even though they did not block the
    # gate. One of them — no calibrator — is a warning in shadow and a refusal
    # the moment this snippet is applied, so an operator who only sees "every
    # critical check passed" is being told the opposite of what happens next.
    warnings = ''
    if document['warnings']:
        warnings = ('\nNot blocking, and worth reading first:\n'
                    + ''.join(f'  - {name}\n' for name in document['warnings']))
    incomplete = ''
    if not document.get('configuration_is_complete', True):
        incomplete = ('\nThis snippet is NOT complete: a value below is empty and\n'
                      'the configuration will not validate until you fill it in.\n')
    return ('AUTONOMY READY\n\n'
            'Every critical check passed. This command does not edit your\n'
            'configuration: add the following to your TOML file yourself, then\n'
            'restart the service.\n'
            + warnings + incomplete + '\n'
            + document['configuration_to_add']
            + '\nAfter restarting, verify with: eye-for-an-eye autonomy status\n\n'
              'What this turns on: ALLOW and TEMP_BLOCK decisions taken without\n'
              'per-event approval. Every block is temporary and expires on its own.\n'
              'It is not a claim that the decisions will be right.\n')


# --- dispatch ---------------------------------------------------------------

def autonomy_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(
        prog='eye-for-an-eye autonomy',
        description='The autonomous decision authority: readiness, policy and records.')
    parser.add_argument('action',
                        choices=('readiness', 'status', 'policy', 'explain', 'enable',
                                 'science', 'review', 'evidence', 'freeze', 'result',
                                 'crosscheck', 'preflight'))
    parser.add_argument('file', nargs='?',
                        help='decision record for explain, a trusted labelled '
                             'evaluation for science, a shadow export for review, '
                             'evidence and freeze, or a freeze manifest for result')
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--limit', type=int,
                        help='review: read at most this many export rows')
    parser.add_argument('--seed', type=int,
                        help='review: shuffle seed, so a review is reproducible')
    parser.add_argument('--labels',
                        help='evidence, freeze, result: a completed review pack')
    parser.add_argument('--journal', action='append', default=[],
                        help='freeze: also hash this decision journal')
    parser.add_argument('--segment', default='',
                        help='freeze: the evidence segment this period belongs to')
    parser.add_argument('--commit', default='',
                        help='freeze: the git commit the sensor was running')
    parser.add_argument('--runtime-version', default='',
                        help='freeze: the runtime version the sensor was running')
    parser.add_argument('--config-digest', default='',
                        help='freeze: a digest of the configuration in force')
    parser.add_argument('--started-at', type=float,
                        help='freeze: when collection began, as a unix time. '
                             'Given, it establishes whether the export rotated '
                             'away the start of its own window')
    parser.add_argument('--root',
                        help='result: re-base the manifest paths, for evidence '
                             'analysed somewhere other than where it was written')
    parser.add_argument('--export',
                        help='crosscheck: the shadow export to check the '
                             'journal against')
    parser.add_argument('--sample', type=int,
                        help='crosscheck: examine only this many joined '
                             'decisions, for a periodic check during a window')
    args = parser.parse_args(argv)
    from .operator_cli import failure
    try:
        if args.action == 'evidence':
            if not args.file:
                raise ValueError('evidence needs a shadow export file')
            return _emit(evidence_document(args.file, labels_path=args.labels,
                                           limit=args.limit),
                         args.json, render_evidence)
        if args.action == 'freeze':
            if not args.file:
                raise ValueError('freeze needs a shadow export file')
            return _emit(freeze_document(args.file, labels_path=args.labels,
                                         journal=args.journal, segment=args.segment,
                                         commit=args.commit,
                                         runtime_version=args.runtime_version,
                                         config_digest=args.config_digest,
                                         started_at=args.started_at),
                         args.json, render_freeze)
        if args.action == 'result':
            if not args.file:
                raise ValueError('result needs a freeze manifest')
            document = result_document(args.file, labels_path=args.labels,
                                       root=args.root)
            _emit(document, args.json, render_result)
            # A verdict that is not PASS leaves a non-zero status, so a script
            # cannot proceed past INSUFFICIENT_EVIDENCE by not reading the text.
            return 0 if document['verdict']['verdict'] == 'PASS' else 1
        if args.action == 'crosscheck':
            if not args.file or not args.export:
                raise ValueError('crosscheck needs a decision journal and '
                                 '--export <shadow export>')
            document = crosscheck_document(args.file, export_path=args.export,
                                           sample=args.sample)
            _emit(document, args.json, render_crosscheck)
            # Anything but AGREE leaves a non-zero status. EMPTY is not an
            # agreement: nothing agreed, because nothing was compared.
            return 0 if document['status'] == 'AGREE' else 1
        if args.action == 'review':
            if not args.file:
                raise ValueError('review needs a shadow export file')
            from .autonomy.review import review_document
            return _emit(review_document(args.file, limit=args.limit, seed=args.seed),
                         args.json, render_review)
        if args.action == 'explain':
            if not args.file:
                raise ValueError('explain needs a decision record file')
            return _emit(explain_document(args.file), args.json, render_explain)
        if args.action == 'science':
            return _emit(science_document(args.file), args.json, render_science)
        config = load_config(_resolve(args.config))
        if args.action == 'readiness':
            report = evaluate_readiness(config)
            _emit(report.explain(), args.json, render_readiness)
            return 0 if report.ready else 1
        if args.action == 'policy':
            return _emit(policy_document(config), args.json, render_policy)
        if args.action == 'preflight':
            document = preflight_document(config)
            _emit(document, args.json, render_preflight)
            return 0 if document['ready_for_shadow'] else 1
        if args.action == 'enable':
            document = enable_document(config)
            _emit(document, args.json, render_enable)
            return 0 if document['autonomous_ready'] == 'YES' else 1
        from .autonomy.authority import from_config as authority_from_config
        runtime = AutonomousRuntime(
            authority=authority_from_config(config),
            cooldown_seconds=config.autonomy.recovery_cooldown_seconds)
        runtime.start(config)
        return _emit(runtime.status(), args.json, render_status)
    except (OSError, ValueError, TypeError, RuntimeError, ImportError, KeyError) as exc:
        return failure(exc, machine=args.json, debug=debug)
