"""P10 operator commands for the web layer.

    eye-for-an-eye web doctor      is this set up correctly and safely?
    eye-for-an-eye web status      what has the web sensor seen?
    eye-for-an-eye web sources     which sources are being watched
    eye-for-an-eye web incident    one source, in full
    eye-for-an-eye web log-format  the Nginx log_format to install

None of these change Nginx, reload a web server, or touch a firewall. `web
log-format` prints text for a person to install after checking it with
`nginx -t` themselves.
"""
import argparse
import json
import sys
from pathlib import Path

from .config import load_config


def _secret(config):
    path = getattr(config.web, 'secret_file', '')
    if not path:
        return None
    try:
        data = Path(path).read_bytes().strip()
    except OSError:
        return None
    return data if len(data) >= 32 else None


def _sensor(config, *, from_end=True):
    """Build a sensor over the configured log. Never starts a background thread."""
    from .web.identity import ClientResolver
    from .web.nginx import NginxSource
    from .web.risk import WebMathRisk
    from .web.sensor import WebSensor
    from .web.state import WebSourceTable

    web = config.web
    if not web.enabled:
        raise ValueError('web protection is not enabled in the configuration')
    if web.source_type != 'nginx':
        raise ValueError(f'no reader is implemented for source type {web.source_type!r}')
    resolver = ClientResolver(web.trusted_proxy_networks,
                              trust_forwarded=web.trust_forwarded_headers)
    source = NginxSource(web.access_log_path, resolver, secret=_secret(config),
                         store_path=web.store_raw_path,
                         max_lines_per_poll=web.max_lines_per_poll)
    source.start(from_end=from_end)
    table = WebSourceTable(max_sources=web.max_sources,
                           ttl_seconds=web.source_ttl_seconds,
                           max_distinct_paths=web.max_distinct_paths)
    return WebSensor(source, risk=WebMathRisk(), table=table,
                     shadow=(config.decision.mode != 'enforce'),
                     expected_methods=tuple(web.expected_methods),
                     evaluation_interval=web.evaluation_interval_seconds,
                     minimum_quality=web.minimum_quality)


def web_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(
        prog='eye-for-an-eye web',
        description='Local web protection. Reads request metadata. Changes nothing.')
    parser.add_argument('action', choices=('doctor', 'status', 'sources', 'incident',
                                           'log-format'))
    parser.add_argument('source', nargs='?', default='', help='a client address')
    parser.add_argument('--replay', default='',
                        help='read a log file from the start instead of following it')
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure

    try:
        if args.action == 'log-format':
            from .web.nginx import LOG_FORMAT
            print(LOG_FORMAT)
            print('\nInstall this in the http block, then add:')
            print('    access_log /var/log/nginx/eye-for-an-eye.log eye_for_an_eye;')
            print('\nCheck it with "nginx -t" before reloading. This command changed '
                  'nothing.')
            return 0

        config = load_config(args.config)

        if args.action == 'doctor':
            from .web.doctor import check, render
            report = check(config)
            if args.json:
                print(json.dumps(report))
            else:
                print(render(report))
            status = report.get('web', {}).get('status')
            return 0 if status in ('HEALTHY', 'DISABLED', 'NOT_CONFIGURED') else 2

        sensor = _sensor(config, from_end=not args.replay)
        if args.replay:
            from .web.nginx import NginxSource
            from .web.identity import ClientResolver
            resolver = ClientResolver(config.web.trusted_proxy_networks,
                                      trust_forwarded=config.web.trust_forwarded_headers)
            sensor.source = NginxSource(args.replay, resolver, secret=_secret(config))
            sensor.source.start(from_end=False)
        decisions = sensor.poll()

        if args.action == 'status':
            health = sensor.health()
            if args.json:
                print(json.dumps({'health': health,
                                  'decisions': [d.explain() for d in decisions]}))
                return 0
            source = health.get('source', {})
            print('WEB STATUS\n')
            print(f'Web integration:\n{"Receiving" if source.get("open") else "Not reading"}\n')
            print(f'Web server:\n{config.web.source_type}\n')
            print(f'Lines read:\n{source.get("lines_read", 0)}\n')
            print(f'Events:\n{source.get("events", 0)}\n')
            print(f'Parse errors:\n{source.get("parse_errors", 0)}\n')
            print(f'Log rotations:\n{source.get("rotations", 0)}\n')
            print(f'Trusted proxy:\n'
                  f'{"Configured" if source.get("trusted_proxies_configured") else "Not configured"}\n')
            print(f'Sources watched:\n{health.get("sources", 0)} of '
                  f'{health.get("max_sources", 0)}\n')
            print(f'Mode:\n{"Shadow — nothing is enforced" if sensor.shadow else "Enforcing"}')
            return 0

        if args.action == 'sources':
            rows = sorted(decisions, key=lambda item: -item.risk)[:args.limit]
            if args.json:
                print(json.dumps({'rows': len(rows),
                                  'sources': [row.explain() for row in rows]}))
                return 0
            print('WEB SOURCES\n')
            if not rows:
                print('No source has been evaluated yet.')
                print('The sensor reads new log lines from the moment it starts.')
                return 0
            print(f'{"Source":40} {"Risk":6} {"Action":11} Requests')
            for row in rows:
                print(f'  {row.source:38} {row.risk:<6.2f} {row.action:11} {row.observations}')
            return 0

        if args.action == 'incident':
            if not args.source:
                print('Which source? Use "web sources" to see them.', file=sys.stderr)
                return 2
            from .web.sensor import incident
            decision = sensor.evaluate(args.source, force=True)
            if decision is None:
                print(f'No web activity recorded for {args.source}.', file=sys.stderr)
                return 2
            if args.json:
                print(json.dumps(decision.explain()))
                return 0
            print(incident(decision))
            return 0
        raise ValueError('unknown web action')
    except (OSError, ValueError, TypeError, RuntimeError, ImportError) as exc:
        return failure(exc, machine=args.json, debug=debug)
