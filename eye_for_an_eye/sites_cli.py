"""P12 operator commands for multi-site.

    eye-for-an-eye sites list              which sites are configured, and how each is doing
    eye-for-an-eye sites show <site>       one site, in full
    eye-for-an-eye sites doctor [<site>]   is the site configuration correct and safe
    eye-for-an-eye sites baseline <site>   what this site's normal looks like
    eye-for-an-eye sites drift <site>      has this site's traffic moved
    eye-for-an-eye sites models <site>     which model answers for this site

None of these change enforcement, reload anything, or write to a site's
configuration. `doctor` reads.
"""
import argparse
import json

from .config import load_config
from .sites.baseline import ACTIVE as BASELINE_ACTIVE, MISSING
from .sites.engine import NETWORK_HOST_BLOCK, from_config
from .sites.identity import UNKNOWN_SITE
from .sites.profile import ADMIN, API, WEBSITE

HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNAVAILABLE = 'UNAVAILABLE'
NOT_CONFIGURED = 'NOT_CONFIGURED'
DISABLED = 'DISABLED'


def _worst(statuses):
    order = (HEALTHY, NOT_CONFIGURED, DISABLED, DEGRADED, UNAVAILABLE)
    rank = {name: index for index, name in enumerate(order)}
    found = [status for status in statuses if status in rank]
    return max(found, key=lambda name: rank[name]) if found else HEALTHY


def doctor(config, engine, site_id=None):
    """Every multi-site check, read-only. §92."""
    checks = {'sites_doctor_schema_version': 1}
    if engine is None:
        checks['sites'] = {'status': DISABLED,
                           'reason': 'multi-site is not enabled in the configuration'}
        return checks

    checks['sites'] = {'status': HEALTHY, 'configured': len(engine.profiles)}
    checks['domains'] = _domain_check(engine)
    checks['unknown_host'] = _unknown_check(config, engine)
    checks['proxies'] = _proxy_check(config, engine)
    checks['challenge'] = _challenge_check(config, engine)
    checks['budgets'] = _budget_check(engine)
    checks['enforcement'] = _enforcement_check(engine)
    checks['baselines'] = _baseline_check(engine, site_id)
    checks['models'] = _model_check(engine)

    graded = {name: item for name, item in checks.items()
              if isinstance(item, dict) and item.get('status')}
    headline = _worst(item['status'] for item in graded.values())
    checks['sites']['status'] = headline
    if headline != HEALTHY:
        culprit = next(name for name, item in graded.items()
                       if item['status'] == headline and name != 'sites')
        checks['sites']['reason'] = f'{culprit}: {graded[culprit].get("reason", "")}'
    return checks


def _domain_check(engine):
    domains = engine.resolver.domains
    if not domains:
        return {'status': NOT_CONFIGURED,
                'reason': 'no domains are mapped, so every request is unknown',
                'action': 'add domains to each site under [sites.profiles.<name>]'}
    per_site = {}
    for domain, site in sorted(domains.items()):
        per_site.setdefault(site, []).append(domain)
    empty = [site for site in engine.profiles if site not in per_site]
    result = {'status': HEALTHY, 'domains': len(domains), 'per_site': per_site,
              'reason': 'each domain maps to exactly one site'}
    if empty:
        result.update(status=DEGRADED,
                      reason=f'{", ".join(empty)} have no domains and can never match',
                      action='give every site at least one domain, or disable it')
    return result


def _unknown_check(config, engine):
    default = engine.resolver.default_site
    if default:
        return {'status': DEGRADED, 'default_site': default,
                'reason': (f'unmatched hosts are treated as {default}; that site\'s '
                           'policy is applied to traffic nobody configured'),
                'action': ('leave sites.default_site empty unless you are sure; the '
                           'bounded unknown bucket is the conservative choice')}
    return {'status': HEALTHY, 'bucket': UNKNOWN_SITE,
            'unknown_site_action': getattr(config.sites, 'unknown_site_action', 'OBSERVE'),
            'reason': ('unmatched hosts go to one bounded bucket; a Host header '
                       'cannot create a site')}


def _proxy_check(config, engine):
    web = getattr(config, 'web', None)
    if web is None or not web.enabled:
        return {'status': NOT_CONFIGURED,
                'reason': 'web protection is not enabled, so no client identity is resolved'}
    if not web.trusted_proxy_networks:
        return {'status': HEALTHY, 'configured': False,
                'reason': 'no trusted proxies; the peer address is the client'}
    return {'status': HEALTHY, 'configured': True,
            'networks': list(web.trusted_proxy_networks),
            'reason': ('every site uses the same trusted-proxy resolver; a forwarded '
                       'header from an untrusted peer is ignored')}


def _challenge_check(config, engine):
    settings = getattr(config, 'challenge', None)
    if settings is None or not settings.enabled:
        return {'status': NOT_CONFIGURED,
                'reason': 'challenges are not enabled; site scoping is not in use'}
    enabled = sorted(site for site, profile in engine.profiles.items()
                     if profile.settings.challenge_enabled)
    return {'status': HEALTHY, 'sites_with_challenges': enabled,
            'reason': ('each site signs its tokens with a key derived from the '
                       'master secret and that site\'s identifier, so a token for '
                       'one site does not verify for another')}


def _budget_check(engine):
    stats = engine.state.stats()
    reserved = stats['reserved_per_site'] * stats['sites']
    result = {'status': HEALTHY,
              'max_sources_global': stats['max_sources_global'],
              'reserved_per_site': stats['reserved_per_site'],
              'fair_share': stats['fair_share'],
              'reason': ('every site has a floor it can always claim; eviction is '
                         'charged to whichever site is furthest over its fair share')}
    if reserved > stats['max_sources_global'] * 0.9:
        result.update(status=DEGRADED,
                      reason=(f'reservations ({reserved}) use almost the whole global '
                              f'budget ({stats["max_sources_global"]}), leaving little '
                              'room for a busy site'),
                      action='raise sites.max_sources_global or lower the reservation')
    return result


def _enforcement_check(engine):
    host_wide = sorted(site for site, profile in engine.profiles.items()
                       if profile.settings.allow_host_network_block)
    enforcing = sorted(site for site, profile in engine.profiles.items()
                       if profile.settings.mode != 'shadow')
    result = {'status': HEALTHY, 'shadow_only': not enforcing,
              'sites_enforcing': enforcing,
              'sites_allowed_host_block': host_wide,
              'reason': 'every site is in shadow mode; nothing is enforced'}
    if host_wide:
        result.update(status=DEGRADED,
                      reason=(f'{", ".join(host_wide)} may ask for a host-wide network '
                              'block, which removes a source from EVERY site on this '
                              'server, not only the one that asked'),
                      action='confirm that is intended; see docs/CROSS_SITE_SECURITY.md')
    elif enforcing:
        result.update(reason=f'{", ".join(enforcing)} are enforcing site-local actions')
    return result


def _baseline_check(engine, site_id):
    sites = [site_id] if site_id else sorted(engine.profiles)
    states = {site: engine.baseline(site).state for site in sites
              if site in engine.baselines}
    missing = sorted(site for site, state in states.items() if state == MISSING)
    result = {'status': HEALTHY, 'states': states,
              'reason': 'every site has an active baseline'}
    if missing:
        result.update(status=NOT_CONFIGURED,
                      reason=(f'{", ".join(missing)} have no baseline; those sites '
                              'answer INSUFFICIENT_DATA rather than guessing'),
                      action='run for a while, then build and activate a baseline')
    return result


def _model_check(engine):
    if engine.models is None:
        return {'status': NOT_CONFIGURED,
                'reason': 'no model registry is configured; the mathematical engine '
                          'decides alone'}
    rows, fell_back = {}, []
    for site in sorted(engine.profiles):
        resolved = engine.models.resolve(site)
        rows[site] = {'source': resolved.source, 'version': resolved.version}
        if resolved.fell_back:
            fell_back.append(site)
    result = {'status': HEALTHY, 'per_site': rows,
              'reason': 'each site resolves to a model of the right scope'}
    if fell_back:
        result.update(status=DEGRADED,
                      reason=f'{", ".join(fell_back)} fell back to another model',
                      action='run "sites models <site>" to see why')
    return result


def render_list(engine):
    if engine is None:
        return 'Multi-site:\nDisabled\n\nOne site is protected, which needs no site configuration.'
    if not engine.profiles:
        return 'Multi-site:\nEnabled, but no sites are configured.'
    lines = ['SITES', '',
             f'{"Site":<16}{"Profile":<11}{"Mode":<9}{"Model":<18}{"Baseline":<12}Sources',
             '-' * 76]
    for site in sorted(engine.profiles):
        profile = engine.profiles[site]
        model = 'global'
        if engine.models is not None:
            resolved = engine.models.resolve(site)
            model = resolved.version or resolved.source
        lines.append(f'{site:<16}{profile.profile_type:<11}'
                     f'{profile.settings.mode:<9}{model[:17]:<18}'
                     f'{engine.baseline(site).state:<12}'
                     f'{engine.state.site_stats(site)["sources"]}')
    stats = engine.state.stats()
    lines += ['', f'Unknown host bucket:\n{UNKNOWN_SITE}, '
                  f'{engine.state.site_stats(UNKNOWN_SITE)["sources"]} sources', '',
              f'Shared budget:\n{stats["sources"]} of {stats["max_sources_global"]} '
              f'sources, {stats["reserved_per_site"]} reserved per site', '',
              'Note:',
              'Web behaviour is kept separate per site. Network behaviour is about',
              'the whole server and is shared on purpose.']
    return '\n'.join(lines)


def render_show(document):
    if not document.get('configured'):
        return f'Site:\n{document["site_id"]}\n\nNot configured.'
    profile = document['profile']
    settings = profile['settings']
    state = document['state']
    baseline = document['baseline']
    lines = ['SITE STATUS', '',
             f'Site:\n{document["site_id"]}', '',
             f'Domains:\n{", ".join(profile["domains"]) or "none"}', '',
             f'Profile:\n{profile["profile_type"]}', '',
             f'Mode:\n{settings["mode"]}'
             + (' — decisions are recorded, nothing is enforced'
                if settings['mode'] == 'shadow' else ''), '',
             f'Active sources:\n{state["sources"]} '
             f'(reserved {state["reserved"]}, fair share {state["fair_share"]})', '',
             f'Web events:\n{state["events"]}', '',
             f'Expected rate:\n{settings["expected_requests_per_minute"]:.0f} '
             'requests per minute', '',
             f'Thresholds:\nwatch {settings["thresholds"]["watch"]}, '
             f'challenge {settings["thresholds"]["challenge"]}, '
             f'rate limit {settings["thresholds"]["rate_limit"]}, '
             f'block {settings["thresholds"]["block"]}', '',
             f'Challenge:\n{"enabled" if settings["challenge_enabled"] else "disabled"}', '',
             f'Baseline:\n{baseline["state"]}'
             + (f' ({baseline["version"]}, confidence {baseline["confidence"]})'
                if baseline['state'] == BASELINE_ACTIVE else ''), '']
    if 'model' in document:
        model = document['model']
        lines += [f'Model:\n{model["model_version"] or "none"} '
                  f'({model["model_source"]}, scope {model["model_scope"] or "none"})', '']
        if model['fell_back']:
            lines += ['Model fell back because:'] + \
                     ['  - ' + reason for reason in model['reasons']] + ['']
    lines += [f'Host-wide network block:\n'
              f'{"allowed" if settings["allow_host_network_block"] else "not allowed"}'
              + ('' if settings['allow_host_network_block']
                 else ' — a block here stays site-local'), '',
              'Note:',
              'This site\'s web behaviour is counted separately from every other',
              'site. A network block would affect all of them.']
    return '\n'.join(lines)


def render_doctor(report):
    sites = report.get('sites', {})
    if sites.get('status') == DISABLED:
        return 'Multi-site:\nDisabled\n\n' + sites.get('reason', '')
    headline = str(sites.get('status'))
    if sites.get('reason'):
        headline += ' — ' + sites['reason']
    lines = ['MULTI-SITE HEALTH', '', f'Sites:\n{headline}', '',
             f'Configured:\n{sites.get("configured", 0)}', '']
    for name, label in (('domains', 'Domain mapping'), ('unknown_host', 'Unknown hosts'),
                        ('proxies', 'Trusted proxies'), ('challenge', 'Challenge scope'),
                        ('budgets', 'Resource budgets'),
                        ('enforcement', 'Enforcement'), ('baselines', 'Baselines'),
                        ('models', 'Models')):
        item = report.get(name, {})
        lines += [f'{label}:\n{item.get("status")} — {item.get("reason", "")}', '']
    actions = [item.get('action') for item in report.values()
               if isinstance(item, dict) and item.get('action')]
    if actions:
        lines += ['What to do:'] + ['  - ' + action for action in actions] + ['']
    lines += ['Note:',
              'This check reads only. It changes no configuration and enforces nothing.']
    return '\n'.join(lines)


def render_baseline(engine, site_id):
    baseline = engine.baseline(site_id)
    document = baseline.explain()
    lines = ['SITE BASELINE', '',
             f'Site:\n{site_id}', '',
             f'State:\n{document["state"]}', '',
             f'Version:\n{document["version"] or "none"}', '',
             f'Provenance:\n{document["provenance"]}', '',
             f'Confidence:\n{document["confidence"]}', '',
             f'Windows:\n{document["samples"]}', '',
             f'Distinct sources:\n{document["sources"]}', '']
    if document['distributions']:
        lines += ['What normal looks like here:']
        for name, row in sorted(document['distributions'].items()):
            lines.append(f'  {name:<24} p50 {row["p50"]:>10.2f}  '
                         f'p99 {row["p99"]:>10.2f}')
        lines.append('')
    if document['notes']:
        lines += ['Notes:'] + ['  - ' + note for note in document['notes']] + ['']
    lines += ['Note:',
              'A baseline describes this site\'s ordinary traffic. Being outside it',
              'is not evidence of an attack.']
    return '\n'.join(lines)


def render_models(engine, site_id):
    if engine.models is None:
        return ('Model:\nNo model registry is configured.\n\n'
                'The mathematical engine decides alone. That is a supported '
                'arrangement and not a deficiency: the maths engine never\n'
                'depended on a classifier.')
    resolved = engine.models.resolve(site_id)
    lines = ['SITE MODEL', '',
             f'Site:\n{site_id}', '',
             f'Model:\n{resolved.version or "none"}', '',
             f'Source:\n{resolved.source}', '',
             f'Scope:\n{resolved.scope or "none"}', '']
    if resolved.reasons:
        lines += ['Fell back because:'] + \
                 ['  - ' + reason for reason in resolved.reasons] + ['']
    lines += ['Note:',
              'A site without its own model uses the shared base model. That is the',
              'intended arrangement for most sites, not a deficiency: a classifier',
              'trained on very few examples is not better than one trained on many.']
    return '\n'.join(lines)


def sites_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(
        prog='eye-for-an-eye sites',
        description='Multi-site status. Reads only; enforces nothing.')
    parser.add_argument('action',
                        choices=('list', 'show', 'doctor', 'baseline', 'drift', 'models'))
    parser.add_argument('site', nargs='?')
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure

    try:
        config = load_config(args.config)
        engine = from_config(config)

        if args.action == 'doctor':
            report = doctor(config, engine, args.site)
            print(json.dumps(report) if args.json else render_doctor(report))
            status = report.get('sites', {}).get('status')
            return 0 if status in (HEALTHY, DISABLED, NOT_CONFIGURED) else 2

        if engine is None:
            # One message for this state, produced in one place. Two branches
            # each phrasing it their own way is how output drifts apart.
            print(json.dumps({'enabled': False}) if args.json else render_list(None))
            return 0

        if args.action == 'list':
            print(json.dumps(engine.health()) if args.json else render_list(engine))
            return 0

        if args.site is None:
            print(f'"sites {args.action}" needs a site name. '
                  'Run "sites list" to see them.')
            return 2
        if args.site not in engine.profiles:
            print(f'{args.site} is not a configured site. '
                  'Run "sites list" to see them.')
            return 2

        if args.action == 'show':
            document = engine.site_status(args.site)
            print(json.dumps(document) if args.json else render_show(document))
            return 0
        if args.action == 'baseline':
            if args.json:
                print(json.dumps(engine.baseline(args.site).explain()))
            else:
                print(render_baseline(engine, args.site))
            return 0
        if args.action == 'drift':
            return _drift(engine, args)
        if args.action == 'models':
            if args.json:
                print(json.dumps(engine.models.resolve(args.site).explain()
                                 if engine.models else {'model': None}))
            else:
                print(render_models(engine, args.site))
            return 0
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, ImportError, KeyError) as exc:
        return failure(exc, machine=args.json, debug=debug)


def _drift(engine, args):
    """§89. Site drift, reported against that site's own baseline."""
    baseline = engine.baseline(args.site)
    document = {'site_id': args.site, 'baseline': baseline.version or None,
                'baseline_state': baseline.state,
                'comparable': baseline.usable}
    if args.json:
        print(json.dumps(document))
        return 0
    lines = ['SITE DRIFT', '', f'Site:\n{args.site}', '',
             f'Baseline:\n{baseline.version or "none"} ({baseline.state})', '']
    if not baseline.usable:
        lines += ['Status:\nINSUFFICIENT_DATA', '',
                  'There is no usable baseline for this site yet, so there is nothing',
                  'to have drifted from. That is a real answer, not a failure: a new',
                  'site has no idea what its own normal looks like.', '',
                  'Recommendation:',
                  'Continue in Shadow Mode. Build a baseline when the site has been',
                  'running long enough to describe.']
    else:
        lines += ['Status:\nBASELINE ACTIVE', '',
                  f'Confidence:\n{baseline.confidence}', '',
                  'Per-window drift comparison against this baseline is reported by',
                  'the running sensor; this command shows which baseline is in use.', '',
                  'Recommendation:',
                  'Continue Shadow monitoring.']
    lines += ['', 'Note:',
              'Drift is measured against this site\'s own baseline. Another site\'s',
              'traffic changing does not make this site drifted.']
    print('\n'.join(lines))
    return 0


#: Profile names the setup flow may suggest, and the evidence that would justify
#: each. Suggestions come from local configuration only (§83) — never from
#: traffic, which an attacker writes.
SUGGESTIONS = {WEBSITE: 'the default for a site serving pages to browsers',
               API: 'the server block only proxies to an application port',
               ADMIN: 'the server block restricts access by address or basic auth'}

__all__ = ['doctor', 'sites_command', 'render_list', 'render_show', 'render_doctor',
           'render_baseline', 'render_models', 'NETWORK_HOST_BLOCK', 'SUGGESTIONS']
