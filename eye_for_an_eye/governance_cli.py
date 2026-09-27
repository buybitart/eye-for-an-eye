"""P14 operator commands for model governance.

    eye-for-an-eye model governance status              what is switched on, and what is running
    eye-for-an-eye model governance policy              every threshold, and its digest
    eye-for-an-eye model governance assess --site <id>  assess a candidate; changes nothing
    eye-for-an-eye model governance history [--site]    what happened, and when
    eye-for-an-eye model governance audit               security-relevant events
    eye-for-an-eye model governance freeze --reason     stop all promotion and advancement
    eye-for-an-eye model governance unfreeze            resume

Two rules shape this file.

**Nothing here promotes anything.** `assess` produces a record and prints it.
Activation is deliberately not a command: automatic promotion happens because an
operator enabled it in configuration and a candidate passed every gate, and
manual promotion remains `eye-for-an-eye model promote`, which already exists and
already requires a person. Adding a one-shot "promote now, skip the gates" verb
would quietly become the thing everybody used.

**No command defaults to every site** (§96). A scope is either given or the
command is about the installation as a whole. A `--site` that defaulted to "all"
would make the most destructive version of each command the easiest one to type.
"""
import argparse
import json
from pathlib import Path

from .config import load_config
from .governance import lifecycle
from .governance.guarded import GuardedStore, ceiling_for, evaluate_advance
from .governance.journal import PromotionJournal
from .governance.policy import from_config as policy_from_config
from .governance.store import GovernanceStore, StoreError

GOVERNANCE_CLI_SCHEMA_VERSION = 1

GLOBAL_SCOPE = 'GLOBAL'


def governance_root(config):
    """Where governance state lives. Beside the registry unless configured."""
    configured = getattr(config.model_governance, 'history_path', '') or ''
    if configured:
        return Path(configured)
    registry = getattr(config.reliability, 'registry_path', '') or 'models'
    return Path(registry) / 'governance'


def _scope(args):
    """The explicit scope, or None for an installation-level command.

    Refuses to guess. A command that needs a scope and was not given one says so
    rather than choosing the global model, which is the one with the widest blast
    radius and therefore the worst possible default.
    """
    if getattr(args, 'global_scope', False) and getattr(args, 'site', ''):
        raise ValueError('give --global or --site, not both')
    if getattr(args, 'global_scope', False):
        return GLOBAL_SCOPE
    if getattr(args, 'site', ''):
        return f'SITE:{args.site}'
    return None


def _require_scope(args):
    scope = _scope(args)
    if scope is None:
        raise ValueError(
            'this command needs an explicit scope: --site <id> for one website, or '
            '--global for the shared base model. There is no default, because the '
            'safe default and the convenient default are not the same one')
    return scope


def _emit(payload, as_json, renderer):
    if as_json:
        print(json.dumps(payload))
    else:
        print(renderer(payload), end='')
    return 0


# --- status -----------------------------------------------------------------

def status(config, scope=None):
    """§99. What is on, what is running, and what would stop it."""
    policy = policy_from_config(config)
    store = GovernanceStore(governance_root(config))
    document = {'governance_cli_schema_version': GOVERNANCE_CLI_SCHEMA_VERSION,
                'auto_promotion': 'ON' if policy.auto_promote.enabled else 'OFF',
                'global_auto_promotion': 'ON' if policy.auto_promote.global_enabled else 'OFF',
                'sites_opted_in': list(policy.auto_promote.sites),
                'governance_policy': policy.summary(),
                'guarded_stages': [
                    {'stage': stage.name, 'maximum_model_driven_action': stage.action_ceiling}
                    for stage in policy.stages]}
    try:
        freeze = store.freeze_state()
        document['freeze'] = freeze.explain()
    except StoreError as exc:
        # §115: unreadable state freezes rather than resolving to "fine".
        document['freeze'] = {'frozen': True, 'reason': f'state unreadable: {exc}',
                              'automatic': True}
    if scope:
        document['scope'] = scope
        document.update(_scope_status(config, policy, scope))
    else:
        document['note'] = ('pass --site <id> or --global for the state of one '
                            'scope; nothing here defaults to every site')
    return document


def _scope_status(config, policy, scope):
    root = governance_root(config)
    body = {}
    try:
        guarded = GuardedStore(root).load(scope)
    except Exception as exc:
        return {'guarded': {'error': str(exc)}}
    if guarded is None:
        body['guarded'] = None
        body['maximum_model_driven_action'] = 'the policy default for any model'
    else:
        body['guarded'] = guarded.explain()
        body['maximum_model_driven_action'] = ceiling_for(guarded, policy)
        verdict, reasons = evaluate_advance(guarded, policy)
        body['advancement'] = {'recommendation': verdict, 'reasons': list(reasons)}
    try:
        journal = PromotionJournal(root / 'promotion-journal.json')
        entry = journal.in_flight(scope)
        body['in_flight'] = entry.explain() if entry else None
    except Exception as exc:
        body['in_flight'] = {'error': str(exc)}
    try:
        history = GovernanceStore(root).history(scope=scope, limit=5)
        body['recent'] = [entry.explain() for entry in history]
    except StoreError as exc:
        body['recent'] = [{'error': str(exc)}]
    return body


def render_status(document):
    lines = ['MODEL GOVERNANCE STATUS', '',
             f'Auto promotion:\n{document["auto_promotion"]}', '',
             f'Global auto promotion:\n{document["global_auto_promotion"]}', '',
             f'Sites opted in:\n{", ".join(document["sites_opted_in"]) or "none"}', '',
             f'Governance policy:\n{document["governance_policy"]["governance_policy_version"]} '
             f'({document["governance_policy"]["policy_digest"]})', '']
    freeze = document.get('freeze') or {}
    lines.append('Freeze:\n' + ('FROZEN - ' + (freeze.get('reason') or 'no reason given')
                                if freeze.get('frozen') else 'not frozen'))
    lines.append('')
    if freeze.get('safe_mode'):
        lines.extend(['Model safe mode:\nON - promotion and candidate authority are '
                      'off; the mathematical engine and PolicyGuard are unaffected', ''])
    lines.append('Guarded stages:')
    for stage in document['guarded_stages']:
        lines.append(f'  {stage["stage"]}: at most {stage["maximum_model_driven_action"]} '
                     'from the model alone')
    lines.append('')
    if 'scope' in document:
        lines.extend([f'Scope:\n{document["scope"]}', ''])
        guarded = document.get('guarded')
        if guarded:
            lines.extend([
                f'Guarded model:\n{guarded["version"]} (previous: {guarded["previous_version"]})', '',
                f'Stage:\n{guarded["stage"]}', '',
                f'Maximum model-driven action:\n{document["maximum_model_driven_action"]}', '',
                f'Observed sources:\n{guarded["observation"]["source_groups"]}', '',
                f'Feature vectors:\n{guarded["observation"]["feature_vectors"]}', ''])
            ratio = guarded['observation'].get('disagreement_ratio')
            lines.extend([f'Large disagreement:\n'
                          f'{"unknown" if ratio is None else format(ratio, ".1%")}', ''])
            lines.extend([f'Inference failures:\n'
                          f'{guarded["observation"]["inference_failures"]}', ''])
            advancement = document.get('advancement') or {}
            lines.append(f'Recommendation:\n{advancement.get("recommendation", "unknown")}')
            for reason in advancement.get('reasons', ()):
                lines.append(f'  - {reason}')
            lines.append('')
        else:
            lines.extend(['Guarded model:\nnone', ''])
    else:
        lines.extend([document.get('note', ''), ''])
    return '\n'.join(lines)


# --- policy -----------------------------------------------------------------

def render_policy(document):
    lines = ['MODEL GOVERNANCE POLICY', '',
             f'Version:\n{document["governance_policy_version"]}', '',
             f'Digest:\n{document.get("policy_digest", "")}', '',
             'Every number below is operator policy. None of it is measured, and',
             'none of it should be read as a recommended or validated value.', '']
    for section in ('shadow', 'regression_budgets', 'promotion_budgets',
                    'rollback_thresholds'):
        body = document.get(section) or {}
        if not body:
            continue
        lines.append(section.replace('_', ' ').capitalize() + ':')
        for key, value in body.items():
            lines.append(f'  {key}: {value}')
        lines.append('')
    return '\n'.join(lines)


# --- history and audit ------------------------------------------------------

def history(config, scope=None, limit=20):
    store = GovernanceStore(governance_root(config))
    try:
        entries = [entry.explain() for entry in store.history(scope=scope, limit=limit)]
    except StoreError as exc:
        entries = [{'error': str(exc)}]
    return {'governance_cli_schema_version': GOVERNANCE_CLI_SCHEMA_VERSION,
            'scope': scope or 'all scopes', 'entries': entries,
            'lifecycle': lifecycle.explain()['transitions']}


def render_history(document):
    lines = [f'MODEL GOVERNANCE HISTORY ({document["scope"]})', '']
    if not document['entries']:
        lines.append('nothing has been promoted, advanced or withdrawn yet.')
        return '\n'.join(lines) + '\n'
    for entry in document['entries']:
        if 'error' in entry:
            lines.append(f'  ERROR: {entry["error"]}')
            continue
        lines.append(f'{entry["at"]}  {entry["scope"]}  {entry["event"]}')
        if entry.get('version'):
            lines.append(f'    version: {entry["version"]}'
                         + (f' (from {entry["previous_version"]})'
                            if entry.get('previous_version') else ''))
        if entry.get('reason'):
            lines.append(f'    reason: {entry["reason"]}')
    return '\n'.join(lines) + '\n'


def audit(config, limit=30):
    store = GovernanceStore(governance_root(config))
    try:
        entries = store.audit_entries(limit=limit)
    except StoreError as exc:
        entries = [{'error': str(exc)}]
    return {'governance_cli_schema_version': GOVERNANCE_CLI_SCHEMA_VERSION,
            'entries': entries}


def render_audit(document):
    lines = ['MODEL GOVERNANCE AUDIT LOG', '']
    for entry in document['entries']:
        if 'error' in entry:
            lines.append(f'  ERROR: {entry["error"]}')
            continue
        lines.append(f'{entry.get("at", "")}  {entry.get("event", "")}  '
                     f'{entry.get("scope", "") or "-"}  by {entry.get("actor", "")}')
        if entry.get('detail'):
            lines.append(f'    {entry["detail"]}')
    if len(lines) == 2:
        lines.append('no governance events have been recorded.')
    return '\n'.join(lines) + '\n'


# --- freeze -----------------------------------------------------------------

def freeze(config, *, reason, by='operator'):
    store = GovernanceStore(governance_root(config))
    state = store.freeze(reason=reason, by=by)
    store.record(scope='', event='frozen', reason=reason)
    return {'governance_cli_schema_version': GOVERNANCE_CLI_SCHEMA_VERSION,
            'freeze': state.explain(),
            'effect': ['no candidate is promoted automatically',
                       'no guarded model advances to more authority',
                       'manual rollback is still available',
                       'a promotion that already happened is not undone; use '
                       '`eye-for-an-eye model rollback` for that']}


def unfreeze(config, *, reason='', by='operator'):
    store = GovernanceStore(governance_root(config))
    state = store.unfreeze(by=by, reason=reason)
    store.record(scope='', event='unfrozen', reason=reason)
    return {'governance_cli_schema_version': GOVERNANCE_CLI_SCHEMA_VERSION,
            'freeze': state.explain(),
            'note': 'the consecutive failure count was also cleared'}


def render_freeze(document):
    state = document['freeze']
    if state.get('frozen'):
        lines = ['MODEL GOVERNANCE FROZEN', '', f'Reason:\n{state.get("reason", "")}', '']
        lines.append('While frozen:')
        lines.extend(f'  - {item}' for item in document.get('effect', ()))
        return '\n'.join(lines) + '\n'
    return ('MODEL GOVERNANCE RESUMED\n\n'
            + (document.get('note', '') or '') + '\n')


# --- assessment -------------------------------------------------------------

def assess(config, scope):
    """Report what an assessment would need, and what is missing.

    A full assessment needs offline and shadow evaluation reports for both the
    candidate and the active model. Those are produced by the training and shadow
    pipelines, not by this command — so when they are absent this prints what is
    missing rather than inventing an answer, which is the same distinction
    `NEED_MORE_DATA` makes inside the engine.
    """
    policy = policy_from_config(config)
    allowed, reason = policy.auto_promote.allows(scope)
    document = {'governance_cli_schema_version': GOVERNANCE_CLI_SCHEMA_VERSION,
                'scope': scope,
                'auto_promotion_permitted': allowed,
                'reason': reason,
                'governance_policy': policy.summary(),
                'required_evidence': [
                    'an offline evaluation report for the candidate',
                    'an offline evaluation report for the active model',
                    'a completed shadow run meeting the configured minimums',
                    f'at least {policy.shadow.minimum_trusted_outcomes} trusted '
                    'reviewed outcomes',
                    'a rollback target already on disk'],
                'note': ('this command does not promote anything. A candidate is '
                         'promoted automatically only when auto-promotion is enabled '
                         'for this scope and every gate passes')}
    root = governance_root(config)
    try:
        state = GovernanceStore(root).freeze_state()
        if state.frozen:
            document['blocked_by'] = f'governance is frozen: {state.reason}'
    except StoreError as exc:
        document['blocked_by'] = f'governance state is unreadable: {exc}'
    return document


def render_assess(document):
    lines = ['AUTO-PROMOTION ASSESSMENT (dry run)', '',
             f'Scope:\n{document["scope"]}', '',
             f'Auto-promotion permitted here:\n'
             f'{"YES" if document["auto_promotion_permitted"] else "NO"} - '
             f'{document["reason"]}', '']
    if document.get('blocked_by'):
        lines.extend([f'Blocked by:\n{document["blocked_by"]}', ''])
    lines.append('A full assessment requires:')
    lines.extend(f'  - {item}' for item in document['required_evidence'])
    lines.extend(['', document['note'], ''])
    return '\n'.join(lines)


# --- entry point ------------------------------------------------------------

def governance_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye model governance')
    parser.add_argument('action', choices=('status', 'policy', 'assess', 'history',
                                           'audit', 'freeze', 'unfreeze'))
    parser.add_argument('--config', default=None)
    parser.add_argument('--site', default='')
    parser.add_argument('--global', dest='global_scope', action='store_true',
                        help='the shared base model, which reaches every site')
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--reason', default='')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        if args.action == 'status':
            return _emit(status(config, _scope(args)), args.json, render_status)
        if args.action == 'policy':
            document = policy_from_config(config).explain()
            document['policy_digest'] = policy_from_config(config).digest[:16]
            return _emit(document, args.json, render_policy)
        if args.action == 'assess':
            return _emit(assess(config, _require_scope(args)), args.json, render_assess)
        if args.action == 'history':
            return _emit(history(config, _scope(args), args.limit), args.json,
                         render_history)
        if args.action == 'audit':
            return _emit(audit(config, args.limit), args.json, render_audit)
        if args.action == 'freeze':
            if not args.reason:
                raise ValueError('--reason is required: a freeze with no reason is '
                                 'a freeze nobody can safely lift')
            return _emit(freeze(config, reason=args.reason), args.json, render_freeze)
        if args.action == 'unfreeze':
            return _emit(unfreeze(config, reason=args.reason), args.json, render_freeze)
    except (ValueError, OSError, StoreError) as exc:
        if debug:
            raise
        print(f'error: {exc}')
        return 2
    return 2
