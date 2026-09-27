"""P11 operator commands for the challenge layer.

    eye-for-an-eye challenge status    is it on, in which mode, and how is it doing
    eye-for-an-eye challenge doctor    is it set up correctly and safely
    eye-for-an-eye challenge test      mint a token locally and verify it
    eye-for-an-eye challenge stats     outcomes and budget

Nothing here opens a port, contacts anything, changes Nginx, or changes
enforcement. `challenge test` is entirely local: it signs a token and checks it,
which is exactly what the runtime does, with no request involved.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from .config import load_config

HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNAVAILABLE = 'UNAVAILABLE'
DISABLED = 'DISABLED'
NOT_CONFIGURED = 'NOT_CONFIGURED'


def _worst(statuses):
    order = (HEALTHY, NOT_CONFIGURED, DISABLED, DEGRADED, UNAVAILABLE)
    rank = {name: index for index, name in enumerate(order)}
    found = [status for status in statuses if status in rank]
    return max(found, key=lambda name: rank[name]) if found else HEALTHY


def doctor(config):
    """Every challenge check, read-only. No network request, no reload."""
    from .challenge import page as page_module
    from .challenge import token as token_module
    from .challenge.service import from_config

    settings = config.challenge
    checks = {'challenge_doctor_schema_version': 1}

    if not settings.enabled:
        checks['challenge'] = {'status': DISABLED,
                               'reason': 'challenges are not enabled in the configuration'}
        return checks

    checks['challenge'] = {'status': HEALTHY, 'mode': settings.mode,
                           'token_scheme': token_module.TOKEN_SCHEME}
    checks['secret'] = _secret_check(settings)
    checks['token'] = _token_check(settings)
    checks['cookie'] = _cookie_check(settings, page_module)
    checks['site_scope'] = _site_check(settings, token_module)
    checks['routes'] = _route_check(settings)
    checks['trusted_proxy'] = _proxy_check(config)
    checks['fail_safe'] = _fail_safe_check(config, from_config)

    # The headline is the worst individual finding, and it names which check
    # produced it. A bare "NOT_CONFIGURED" over a correctly configured challenge
    # would send an operator hunting through the wrong section: the gap is
    # usually somewhere else entirely, such as web protection being switched off.
    graded = {name: item for name, item in checks.items()
              if isinstance(item, dict) and item.get('status')}
    headline = _worst(item['status'] for item in graded.values())
    checks['challenge']['status'] = headline
    if headline != HEALTHY:
        culprit = next(name for name, item in graded.items()
                       if item['status'] == headline and name != 'challenge')
        checks['challenge']['reason'] = f'{culprit}: {graded[culprit].get("reason", "")}'
    return checks


def _secret_check(settings):
    if not settings.secret_file:
        return {'status': NOT_CONFIGURED,
                'reason': 'no challenge.secret_file is configured',
                'action': ('head -c 48 /dev/urandom | base64 > <file> '
                           '&& chmod 600 <file>')}
    target = Path(settings.secret_file)
    if not target.is_file():
        return {'status': UNAVAILABLE, 'reason': 'the secret file does not exist'}
    try:
        size = len(target.read_bytes().strip())
        mode = target.stat().st_mode & 0o077
    except OSError as exc:
        return {'status': UNAVAILABLE, 'reason': str(exc)}
    if size < 32:
        return {'status': DEGRADED, 'reason': 'the secret is shorter than 32 bytes'}
    if mode:
        return {'status': DEGRADED,
                'reason': 'the secret file is readable by other users',
                'action': f'chmod 600 {settings.secret_file}'}
    result = {'status': HEALTHY, 'bytes': size,
              'reason': 'present, long enough, and readable only by this user'}
    if settings.previous_secret_file:
        result['rotation'] = 'a previous secret is configured; tokens signed with it '\
                             'are still accepted'
    return result


def _token_check(settings):
    """Sign a token and verify it. The same code path the runtime uses."""
    from .challenge.service import load_secret
    from .challenge.token import issue, verify
    if not settings.secret_file:
        return {'status': NOT_CONFIGURED, 'reason': 'no secret to sign with'}
    try:
        secret = load_secret(settings.secret_file)
        token = issue(secret, site=settings.site_id,
                      ttl_seconds=settings.token_ttl_seconds)
        result = verify(token, secret, site=settings.site_id)
    except Exception as exc:
        return {'status': UNAVAILABLE,
                'reason': f'a token could not be signed and verified: {type(exc).__name__}'}
    if not result.valid:
        return {'status': UNAVAILABLE,
                'reason': f'a freshly signed token did not verify ({result.outcome})'}
    other_site = verify(token, secret, site=settings.site_id + '-other')
    return {'status': HEALTHY,
            'ttl_seconds': settings.token_ttl_seconds,
            'scope_isolated': not other_site.valid,
            'reason': 'a token signs and verifies, and does not verify for another site'}


def _cookie_check(settings, page_module):
    try:
        header = page_module.cookie_header('sample', secure=settings.cookie_secure,
                                           max_age=settings.token_ttl_seconds,
                                           path=settings.cookie_path,
                                           same_site=settings.cookie_same_site)
    except ValueError as exc:
        return {'status': UNAVAILABLE, 'reason': str(exc)}
    result = {'status': HEALTHY, 'secure': settings.cookie_secure,
              'http_only': True, 'same_site': settings.cookie_same_site,
              'path': settings.cookie_path,
              'reason': 'HttpOnly, and scoped to this site'}
    if not settings.cookie_secure:
        result.update(status=DEGRADED,
                      reason='the cookie is not marked Secure',
                      action=('set challenge.cookie_secure = true once the site is '
                              'served over HTTPS'))
    if settings.cookie_same_site == 'None':
        result.update(status=DEGRADED,
                      action='SameSite=None widens exposure; use Lax unless a '
                             'cross-site embed genuinely needs it')
    result['header_example'] = header.replace('sample', '<token>')
    return result


def _site_check(settings, token_module):
    normalised = token_module.normalise_site(settings.site_id)
    result = {'status': HEALTHY, 'site_id': normalised,
              'reason': 'a token is scoped to this identifier and will not verify '
                        'for another site on this server'}
    if normalised == 'default':
        result.update(status=NOT_CONFIGURED,
                      action=('set challenge.site_id when this server hosts more than '
                              'one site, so a token for one cannot be used on another'))
    return result


def _route_check(settings):
    from .challenge.policy import DEFAULT_ROUTES
    never = [rule.path_prefix for rule in DEFAULT_ROUTES if not rule.challenge]
    never += list(settings.api_path_prefixes or ())
    never += list(settings.no_challenge_path_prefixes or ())
    return {'status': HEALTHY, 'never_challenged': sorted(set(never)),
            'reason': ('API, auth, webhook and health routes are not challenged: a '
                       'browser challenge there breaks the caller and proves nothing')}


def _proxy_check(config):
    web = getattr(config, 'web', None)
    if web is None or not web.enabled:
        return {'status': NOT_CONFIGURED,
                'reason': 'web protection is not enabled, so no client identity is '
                          'resolved'}
    if not web.trusted_proxy_networks:
        return {'status': HEALTHY, 'configured': False,
                'reason': ('no trusted proxies; the peer address is the client, which '
                           'is correct for a directly exposed server')}
    return {'status': HEALTHY, 'configured': True,
            'networks': list(web.trusted_proxy_networks),
            'reason': ('challenges use the same trusted-proxy resolver as the web '
                       'layer; a forwarded header from an untrusted peer is ignored')}


def _fail_safe_check(config, from_config):
    try:
        service = from_config(config)
    except Exception as exc:
        return {'status': UNAVAILABLE,
                'reason': f'the challenge service could not be built: {type(exc).__name__}'}
    return {'status': HEALTHY if service.enabled else DEGRADED,
            'enabled': service.enabled,
            'mode': service.mode,
            'last_error': service.last_error,
            'reason': ('if the challenge subsystem fails, requests proceed normally and '
                       'the source stays watched; it can never take the site offline')}


def render(report):
    challenge = report.get('challenge', {})
    if challenge.get('status') == DISABLED:
        return 'Challenge:\nDisabled\n\n' + challenge.get('reason', '')
    headline = str(challenge.get('status'))
    if challenge.get('reason'):
        headline += ' — ' + challenge['reason']
    lines = ['CHALLENGE HEALTH', '',
             f'Challenge:\n{headline}', '',
             f'Mode:\n{challenge.get("mode", "unknown")}'
             + (' — decisions are recorded, nothing is sent'
                if challenge.get('mode') == 'shadow' else ''), '',
             f'Token version:\n{challenge.get("token_scheme", "unknown")}', '']
    for name, label in (('secret', 'Secret'), ('token', 'Token signing'),
                        ('cookie', 'Cookie security'), ('site_scope', 'Site scope'),
                        ('trusted_proxy', 'Trusted proxy'), ('fail_safe', 'Fail-safe')):
        item = report.get(name, {})
        lines += [f'{label}:\n{item.get("status")} — {item.get("reason", "")}', '']
    routes = report.get('routes', {})
    lines += ['Never challenged:'] + ['  ' + prefix
                                      for prefix in routes.get('never_challenged', [])] + ['']
    actions = [item.get('action') for item in report.values()
               if isinstance(item, dict) and item.get('action')]
    if actions:
        lines += ['What to do:'] + ['  - ' + action for action in actions] + ['']
    lines += ['Note:',
              'This check reads only. It sends no request, changes no configuration',
              'and never prints a secret or a token.']
    return '\n'.join(lines)


def challenge_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(
        prog='eye-for-an-eye challenge',
        description='Local adaptive web challenge. Shadow by default. Blocks nothing.')
    parser.add_argument('action', choices=('status', 'doctor', 'stats', 'test'))
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure

    try:
        config = load_config(args.config)
        from .challenge.service import from_config

        if args.action == 'doctor':
            report = doctor(config)
            if args.json:
                print(json.dumps(report))
            else:
                print(render(report))
            status = report.get('challenge', {}).get('status')
            return 0 if status in (HEALTHY, DISABLED, NOT_CONFIGURED) else 2

        service = from_config(config)

        if args.action == 'test':
            return _test(config, service, args)

        health = service.health()
        if args.json:
            print(json.dumps(health))
            return 0

        if args.action == 'stats':
            metrics = health.get('metrics', {})
            issued = metrics.get('challenge_issued_total', 0)
            passed = metrics.get('challenge_passed_total', 0)
            failed = metrics.get('challenge_failed_total', 0)
            print('CHALLENGE STATS\n')
            print(f'Issued:\n{issued}\n')
            print(f'Passed:\n{passed}\n')
            print(f'Failed:\n{failed}\n')
            print(f'Pass rate:\n{f"{passed / issued:.0%}" if issued else "no data yet"}\n')
            print(f'Loops prevented:\n{metrics.get("challenge_loop_prevented_total", 0)}\n')
            print(f'Budget refusals:\n{metrics.get("challenge_budget_rejected_total", 0)}\n')
            print(f'Subsystem errors:\n{metrics.get("challenge_subsystem_errors_total", 0)}\n')
            print('Note:\nA pass is not proof of a person. A failure is not proof of an '
                  'attack.\nBoth are evidence.')
            return 0

        print('CHALLENGE STATUS\n')
        print(f'Challenge:\n{"Enabled" if health["enabled"] else "Disabled"}\n')
        print(f'Mode:\n{health["mode"].title()}'
              + (' — decisions are recorded, nothing is sent'
                 if health['shadow'] and health['enabled'] else '') + '\n')
        print(f'Token version:\n{health["token_scheme"]}\n')
        print(f'Site scope:\n{health["site_id"]}\n')
        print(f'Token lifetime:\n{health["token_ttl_seconds"]} seconds\n')
        print(f'Key rotation:\n{"in progress" if health["rotation_active"] else "not active"}\n')
        if health['enabled']:
            metrics = health.get('metrics', {})
            issued = metrics.get('challenge_issued_total', 0)
            passed = metrics.get('challenge_passed_total', 0)
            print(f'Challenges issued:\n{issued}\n')
            print(f'Pass rate:\n{f"{passed / issued:.0%}" if issued else "no data yet"}\n')
            print(f'Active contexts:\n{health.get("contexts", 0)} of '
                  f'{health.get("limit", 0)}\n')
            errors = metrics.get('challenge_subsystem_errors_total', 0)
            print(f'Budget:\n{"Healthy" if not errors else "Limited"}\n')
        if health['last_error']:
            print(f'Last error:\n{health["last_error"]}\n')
        print('Note:\nNo secret and no token is ever printed here.')
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, ImportError) as exc:
        return failure(exc, machine=args.json, debug=debug)


def _test(config, service, args):
    """Sign a token locally and verify it. Contacts nothing; changes nothing."""
    from .challenge.token import issue, verify
    from .challenge.service import load_secret
    if not service.enabled:
        print('Challenges are not enabled, so there is nothing to test.', file=sys.stderr)
        print('Run "eye-for-an-eye challenge doctor" to see what is missing.',
              file=sys.stderr)
        return 2
    secret = load_secret(config.challenge.secret_file)
    site = config.challenge.site_id
    token = issue(secret, site=site, ttl_seconds=config.challenge.token_ttl_seconds)
    results = {
        'signs and verifies': verify(token, secret, site=site).valid,
        'does not verify for another site': not verify(token, secret,
                                                       site=site + '-other').valid,
        'does not verify with a different secret': not verify(
            token, os.urandom(32), site=site).valid,
        'is refused once expired': verify(
            token, secret, site=site,
            now=time.time() + config.challenge.token_ttl_seconds + 10,
        ).outcome == 'expired',
        'is refused when truncated': not verify(token[:20], secret, site=site).valid,
        'is refused when it is garbage': not verify('!!!!', secret, site=site).valid,
    }
    if args.json:
        print(json.dumps({'schema_version': 1, 'checks': results,
                          'passed': all(results.values())}))
        return 0 if all(results.values()) else 2
    print('CHALLENGE SELF-TEST\n')
    print('This is entirely local. No request was made and nothing was changed.\n')
    for name, outcome in results.items():
        print(f'  {"ok  " if outcome else "FAIL"} the token {name}')
    print(f'\nResult:\n{"all checks passed" if all(results.values()) else "a check failed"}')
    print('\nThe token itself is not printed.')
    return 0 if all(results.values()) else 2
