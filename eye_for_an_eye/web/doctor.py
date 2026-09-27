"""What an operator needs to know about the web layer, and nothing they do not.

`doctor` answers "is this set up correctly and safely?". It reads; it never
changes an Nginx configuration, never reloads a web server, and never touches a
firewall. A check that would need to modify something reports what to do instead.

The check that matters most is the trusted-proxy one, because getting it wrong
is silent in both directions: too narrow and every client looks like the proxy,
too wide and anyone can claim to be anyone.
"""
import os
from pathlib import Path

WEB_DOCTOR_SCHEMA_VERSION = 1

HEALTHY = 'HEALTHY'
DEGRADED = 'DEGRADED'
UNAVAILABLE = 'UNAVAILABLE'
DISABLED = 'DISABLED'
NOT_CONFIGURED = 'NOT_CONFIGURED'

#: Fields the reader needs to produce useful features. A log without them still
#: works; it just says less, and the check says which.
REQUIRED_FIELDS = ('remote_addr', 'method', 'uri', 'status')
USEFUL_FIELDS = ('time', 'forwarded_for', 'args', 'bytes_sent', 'request_time',
                 'protocol', 'host', 'user_agent', 'referer')


def check(config, *, sample_lines=20):
    """Every web check, as one report. Read-only."""
    web = getattr(config, 'web', None)
    if web is None or not web.enabled:
        return {'web_doctor_schema_version': WEB_DOCTOR_SCHEMA_VERSION,
                'web': {'status': DISABLED,
                        'reason': 'web protection is not enabled in the configuration'}}

    checks = {'web_doctor_schema_version': WEB_DOCTOR_SCHEMA_VERSION}
    checks['web'] = {'status': HEALTHY, 'source_type': web.source_type,
                     'shadow_default': True}
    checks['access_log'] = _access_log(web, sample_lines)
    checks['log_format'] = _log_format(web, sample_lines)
    checks['trusted_proxy'] = _trusted_proxy(web)
    checks['privacy'] = _privacy(web)
    checks['secret'] = _secret(web)
    checks['limits'] = _limits(web)
    checks['enforcement_compatibility'] = _enforcement(config, web)

    worst = _worst(item.get('status') for item in checks.values() if isinstance(item, dict))
    checks['web']['status'] = worst
    return checks


def _worst(statuses):
    order = (HEALTHY, NOT_CONFIGURED, DISABLED, DEGRADED, UNAVAILABLE)
    rank = {name: index for index, name in enumerate(order)}
    found = [status for status in statuses if status in rank]
    return max(found, key=lambda name: rank[name]) if found else HEALTHY


def _access_log(web, sample_lines):
    path = web.access_log_path
    if not path:
        return {'status': NOT_CONFIGURED,
                'reason': 'no web.access_log_path is configured',
                'action': 'point it at the Nginx access log written in JSON format'}
    target = Path(path)
    if not target.exists():
        return {'status': UNAVAILABLE, 'path': path,
                'reason': 'the access log does not exist',
                'action': 'check the path, and that Nginx has written to it at least once'}
    if not os.access(target, os.R_OK):
        return {'status': UNAVAILABLE, 'path': path,
                'reason': 'the access log is not readable by this user',
                'action': ('add the service user to the group that owns the log, or use an '
                           'ACL. Do not run the analyser as root to read a log file')}
    try:
        info = target.stat()
    except OSError as exc:
        return {'status': UNAVAILABLE, 'path': path, 'reason': str(exc)}
    result = {'status': HEALTHY, 'path': path, 'bytes': info.st_size,
              'readable': True,
              'rotation': 'detected by inode and by truncation; the reader reopens itself'}
    if info.st_size == 0:
        result.update(status=DEGRADED, reason='the access log is empty',
                      action='make a request to the site, then run this check again')
    return result


def _sample(path, limit):
    lines = []
    try:
        with Path(path).open('rb') as handle:
            for _ in range(limit):
                raw = handle.readline()
                if not raw:
                    break
                lines.append(raw)
    except OSError:
        return []
    return lines


def _log_format(web, sample_lines):
    """Is the log actually the JSON format this reader understands?"""
    if not web.access_log_path or not Path(web.access_log_path).is_file():
        return {'status': NOT_CONFIGURED, 'reason': 'no readable access log to inspect'}
    import json
    lines = _sample(web.access_log_path, sample_lines)
    if not lines:
        return {'status': DEGRADED, 'reason': 'the access log has no lines yet'}

    parsed, fields = 0, set()
    for raw in lines:
        try:
            record = json.loads(raw.decode('utf-8', 'replace'))
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(record, dict):
            parsed += 1
            fields.update(str(key).lower() for key in record)

    if not parsed:
        return {'status': UNAVAILABLE, 'lines_sampled': len(lines),
                'reason': 'no line in the sample is JSON',
                'action': ('install the eye_for_an_eye log_format shown in docs/NGINX.md '
                           'and reload Nginx after checking it with "nginx -t"')}

    from .nginx import FORBIDDEN_FIELDS
    leaking = sorted(fields & set(FORBIDDEN_FIELDS))
    if leaking:
        return {'status': UNAVAILABLE, 'lines_sampled': len(lines),
                'sensitive_fields': leaking,
                'reason': f'the access log is recording {", ".join(leaking)}',
                'action': ('remove those fields from log_format. Lines carrying them are '
                           'dropped, so the web layer will see nothing until this is fixed')}

    missing = [name for name in REQUIRED_FIELDS if name not in fields]
    absent = [name for name in USEFUL_FIELDS if name not in fields]
    if missing:
        return {'status': DEGRADED, 'lines_sampled': len(lines),
                'missing_required_fields': missing,
                'reason': 'the log format is missing fields the analysis needs',
                'action': 'compare it with the log_format in docs/NGINX.md'}
    return {'status': HEALTHY, 'lines_sampled': len(lines), 'parsed': parsed,
            'missing_optional_fields': absent,
            'reason': 'the log format is readable and carries no credential field'}


def _trusted_proxy(web):
    """The check that decides whether client identity is right or dangerous."""
    if not web.trust_forwarded_headers:
        return {'status': HEALTHY, 'configured': False,
                'reason': 'forwarded headers are switched off; the peer address is used',
                'note': ('correct for a directly exposed server; behind a proxy every '
                         'client will look like the proxy')}
    if not web.trusted_proxy_networks:
        return {'status': NOT_CONFIGURED, 'configured': False,
                'reason': 'no trusted proxy networks are configured',
                'note': ('this is the safe default. Forwarded headers are ignored, so no '
                         'client can claim to be another address'),
                'action': ('if this site is behind Nginx, a load balancer or a CDN, list '
                           'those networks in web.trusted_proxy_networks. Until you do, '
                           'every request will look like it came from the proxy')}
    try:
        import ipaddress
        networks = [ipaddress.ip_network(entry, strict=False)
                    for entry in web.trusted_proxy_networks]
    except ValueError as exc:
        return {'status': UNAVAILABLE, 'reason': f'invalid trusted proxy network: {exc}'}

    wide = [str(network) for network in networks if network.prefixlen <= 8
            and not network.is_private]
    result = {'status': HEALTHY, 'configured': True,
              'networks': [str(network) for network in networks],
              'reason': 'forwarded addresses are believed only from these networks'}
    if wide:
        result.update(status=DEGRADED, overly_wide=wide,
                      action=('these ranges are very large. Anyone inside one can set the '
                              'client address to anything. Narrow them to the addresses '
                              'your proxy actually uses'))
    return result


def _privacy(web):
    notes = []
    status = HEALTHY
    if web.store_raw_path:
        status = DEGRADED
        notes.append('full request paths are being stored; a URL can contain a reset '
                     'token, an account id or a search term')
    if web.store_query_values:
        status = DEGRADED
        notes.append('query string values are being stored; these routinely contain '
                     'secrets')
    return {'status': status,
            'store_raw_path': web.store_raw_path,
            'store_query_values': web.store_query_values,
            'reason': ('behavioural metadata only' if status == HEALTHY
                       else 'more than behavioural metadata is being kept'),
            'notes': notes,
            'never_stored': ['Authorization', 'Cookie', 'request body', 'passwords',
                             'session tokens']}


def _secret(web):
    """The local key that lets repeated paths be counted without being kept."""
    if not web.secret_file:
        return {'status': DEGRADED, 'configured': False,
                'reason': 'no web.secret_file is configured',
                'effect': ('repeated-path counting is disabled, so path discovery '
                           'evidence will be weaker'),
                'action': 'head -c 48 /dev/urandom | base64 > <file>; chmod 600 <file>'}
    target = Path(web.secret_file)
    if not target.is_file():
        return {'status': UNAVAILABLE, 'configured': True,
                'reason': 'the configured secret file does not exist'}
    try:
        size = len(target.read_bytes().strip())
        mode = target.stat().st_mode & 0o077
    except OSError as exc:
        return {'status': UNAVAILABLE, 'reason': str(exc)}
    if size < 32:
        return {'status': DEGRADED, 'reason': 'the secret is shorter than 32 bytes'}
    if mode:
        return {'status': DEGRADED, 'reason': 'the secret file is readable by other users',
                'action': f'chmod 600 {web.secret_file}'}
    return {'status': HEALTHY, 'configured': True,
            'reason': 'a local key is present and readable only by this user'}


def _limits(web):
    return {'status': HEALTHY,
            'max_sources': web.max_sources,
            'max_distinct_paths': web.max_distinct_paths,
            'source_ttl_seconds': web.source_ttl_seconds,
            'max_lines_per_poll': web.max_lines_per_poll,
            'reason': ('every structure is bounded; a source requesting a million unique '
                       'URLs costs the same as one requesting sixty-four')}


def _enforcement(config, web):
    """Is enforcement configured in a way that could hurt the site?"""
    enforcement = getattr(config, 'enforcement', None)
    if enforcement is None or not enforcement.enabled:
        return {'status': HEALTHY, 'enabled': False,
                'reason': 'automatic blocking is off; web decisions are recorded only'}
    result = {'status': HEALTHY, 'enabled': True,
              'reason': ('a client behind a trusted proxy can never be blocked at the '
                         'network layer; the strongest action available there is a rate '
                         'limit')}
    if not enforcement.management_networks:
        result.update(status=DEGRADED,
                      action=('no management network is protected. Add your own address '
                              'to enforcement.management_networks before enabling '
                              'blocking, so you cannot lock yourself out'))
    return result


def render(report):
    """The report as text, in the shape §78 asks for."""
    web = report.get('web', {})
    if web.get('status') == DISABLED:
        return 'Web integration:\nDisabled\n\n' + web.get('reason', '')
    lines = ['WEB HEALTH', '',
             f'Web integration:\n{web.get("status", "UNKNOWN")}', '',
             f'Web server:\n{web.get("source_type", "unknown")}', '']
    log = report.get('access_log', {})
    lines += [f'Access log:\n{log.get("status")} — {log.get("path", "not configured")}', '']
    fmt = report.get('log_format', {})
    lines += [f'Log format:\n{fmt.get("status")} ({fmt.get("parsed", 0)} of '
              f'{fmt.get("lines_sampled", 0)} sampled lines parsed)', '']
    proxy = report.get('trusted_proxy', {})
    lines += [f'Trusted proxy:\n{"Configured" if proxy.get("configured") else "Not configured"}',
              '']
    privacy = report.get('privacy', {})
    lines += [f'Privacy:\n{privacy.get("reason")}', '']
    enforcement = report.get('enforcement_compatibility', {})
    lines += [f'Enforcement:\n{"on" if enforcement.get("enabled") else "off"} — '
              f'{enforcement.get("reason")}', '']
    actions = [item.get('action') for item in report.values()
               if isinstance(item, dict) and item.get('action')]
    if actions:
        lines += ['What to do:'] + ['  - ' + action for action in actions] + ['']
    lines += ['Note:',
              'This check reads only. It does not change Nginx and does not change a',
              'firewall.']
    return '\n'.join(lines)
