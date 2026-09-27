"""P6 operator entrypoints. Diagnostics never repair, download or change the firewall."""
import argparse
from dataclasses import asdict, fields
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import sys
import tomllib
from .config import DEPLOYMENT_PROFILES, load_config, redacted_config
from .configuration import PROFILE_TEMPLATES, initialize, migrate
from .security.redaction import safe_string

# Legacy unavailable remains 1; distinct actionable errors are now stable.
SUCCESS, UNAVAILABLE, CONFIG, DEPENDENCY, PERMISSION, STORAGE, BIND, DEGRADED = range(8)


def output(result, machine=False):
    if machine:
        print(json.dumps(result, ensure_ascii=True))
    else:
        for key, value in result.items():
            if key == 'schema_version':
                continue
            print(f'{key.replace("_", " ").capitalize()}: ' +
                  (json.dumps(value, ensure_ascii=True) if isinstance(value, (dict, list)) else str(value)))


def failure(exc, code=CONFIG, machine=False, debug=False):
    if isinstance(exc, PermissionError):
        code = PERMISSION
    elif isinstance(exc, ImportError):
        code = DEPENDENCY
    elif isinstance(exc, sqlite3.Error):
        code = STORAGE
    result = {'schema_version': 1, 'error': type(exc).__name__, 'exit_code': code,
              'message': safe_string(str(exc), 512)}
    if machine:
        print(json.dumps(result), file=sys.stderr)
    else:
        print(f"Error [{code}]: {result['message']}", file=sys.stderr)
    if debug:
        import traceback
        traceback.print_exc()
    return code


def config_sources(config, path, environ, args):
    """Provenance of effective settings; returns source names, never environment values."""
    raw = tomllib.loads(Path(path).read_text(encoding='utf-8')) if path else {}
    result = {}
    for section in fields(config):
        current = getattr(config, section.name)
        for key in ([f.name for f in fields(current)] if hasattr(current, '__dataclass_fields__') else [None]):
            dotted = section.name + ('.' + key if key else '')
            present = key in raw.get(section.name, {}) if key else section.name in raw
            env = 'E4E__' + dotted.replace('.', '__').upper()
            result[dotted] = 'env' if env in environ else 'config' if present else 'default'
    mapping = {'bind': 'network.bind_address', 'port': 'network.port', 'protocol': 'network.protocol',
        'storage_path': 'storage.path', 'status_file': 'runtime.status_file', 'sensor_id': 'runtime.sensor_id',
        'profile': 'deployment.profile', 'secret_file': 'deception.secret_file', 'secret_env': 'deception.secret_env',
        'mode': 'deception.mode', 'enrichment': 'enrichment.enabled', 'rdap': 'enrichment.rdap_enabled',
        'storage': 'storage.enabled', 'mmdb': 'enrichment.mmdb_path', 'pcap': 'capture.pcap_path',
        'p0f_db': 'capture.p0f_db', 'ipc_socket': 'capture.ipc_socket', 'bpf': 'capture.bpf',
        'probes': 'probes_path', 'log_file': 'logging.file', 'active_path_probe': 'active_probes.enabled',
        'allow_cidr': 'active_probes.allowed_cidrs', 'lab': 'lab.enabled',
        'lab_max_bytes': 'lab.max_bytes', 'lab_max_duration': 'lab.max_duration', 'lab_max_connections': 'lab.max_connections'}
    for field in fields(config.limits):
        mapping[field.name] = 'limits.' + field.name
    for flag, dotted_field in mapping.items():
        if getattr(args, flag, None) is not None:
            result[dotted_field] = 'cli'
    if getattr(args, 'storage_path', None) and getattr(args, 'storage', None) is None:
        result['storage.enabled'] = 'cli'
    if getattr(args, 'rdap', None):
        result['enrichment.enabled'] = 'cli'
    return result


def startup_plan(config):
    profile = config.deployment.profile
    if config.firewall.enabled:
        raise ValueError('run does not apply firewall rules; use explicit isolated firewall commands separately')
    if config.network.udp_responses:
        raise ValueError('run requires network.udp_responses=false')
    if profile == 'sensor':
        if not (config.capture.pcap_path or config.capture.ipc_socket):
            raise ValueError('sensor requires capture.pcap_path or capture.ipc_socket; use demo for a rootless local example')
        if importlib.util.find_spec('scapy') is None:
            raise ModuleNotFoundError('capture dependency unavailable; install the locked capture extra')
        command = 'ip_id'
    else:
        if config.network.protocol != 'tcp':
            raise ValueError('honeypot/lab run supports bounded TCP only')
        if not config.deception.enabled:
            raise ValueError('honeypot/lab requires deception.enabled=true')
        if profile == 'lab' and not ipaddress.ip_address(config.network.bind_address).is_loopback:
            raise ValueError('lab requires loopback bind; DO NOT USE ON PUBLIC INTERNET')
        from .security.secrets import load_secret
        load_secret(config)
        command = 'services'
    if config.storage.enabled:
        from .storage.lifecycle import migration_plan
        plan = migration_plan(config)
        if plan['current_version'] not in (None, plan['target_version']):
            raise sqlite3.DatabaseError('storage migration required; run storage migrate to review, then --apply --backup <new-path>')
    for name, value in (('storage.path', config.storage.path if config.storage.enabled else ''),
                         ('runtime.status_file', config.runtime.status_file), ('logging.file', config.logging.file)):
        if value and (not Path(value).parent.is_dir() or not os.access(Path(value).parent, os.W_OK)):
            raise PermissionError(f'{name}: parent directory must exist and be writable by the service user')
    from .security.privileges import ensure_analysis_user
    ensure_analysis_user(config.runtime.enforce_unprivileged)
    return command, {'schema_version': 1, 'mode': profile.upper(), 'active_probes': config.active_probes.enabled,
        'egress': config.deployment.egress, 'udp_deception': False, 'firewall_management': config.enforcement.enabled,
        'decision_mode': config.decision.mode, 'ml_required': config.ml.required,
        'api': f'{config.api.bind_address}:{config.api.port}' if config.api.enabled else 'disabled',
        'metrics': f'{config.metrics.bind_address}:{config.metrics.port}' if config.metrics.enabled else 'disabled',
        'listener': f'{config.network.bind_address}:{config.network.port}' if profile != 'sensor' else 'passive capture/IPC'}


def main(command, argv, *, debug=False):
    machine = '--json' in argv
    try:
        if command == 'config':
            actions = argparse.ArgumentParser(prog='eye-for-an-eye config')
            actions.add_argument('action', choices=('init', 'validate', 'show', 'migrate'))
            if not argv or argv[0] in ('--help', '-h'):
                actions.print_help()
                return 0
            action = actions.parse_args(argv[:1]).action
            if action in ('init', 'migrate'):
                parser = argparse.ArgumentParser(prog='eye-for-an-eye config '+action)
                parser.add_argument('--output', default='eye-for-an-eye.toml')
                # Two different vocabularies, and they are not interchangeable.
                # `init` selects a *setup* profile — a starter file, which is
                # what `PROFILE_TEMPLATES` registers — while `migrate` writes
                # `deployment.profile` straight into the configuration, where
                # only the three the loader accepts are valid. The choices are
                # derived from the registry rather than repeated here, because
                # this list had already drifted: it offered neither `website`
                # nor the two production postures, both of which the registry
                # had. `tests/test_p16_production_profiles.py` pins the
                # derivation so it cannot drift again.
                parser.add_argument('--profile', default='sensor',
                                    choices=(sorted(PROFILE_TEMPLATES) if action == 'init'
                                             else DEPLOYMENT_PROFILES))
                parser.add_argument('--config', required=action == 'migrate')
                parser.add_argument('--json', action='store_true')
                args = parser.parse_args(argv[1:])
                output(initialize(args.output, args.profile) if action == 'init' else migrate(args.config, args.output, args.profile), machine)
                return 0
            from .cli import _parser, _settings
            parser = _parser('proto')
            parser.prog = 'eye-for-an-eye config '+action
            parser.add_argument('--json', action='store_true')
            parser.add_argument('--effective', action='store_true')
            parser.add_argument('--source', action='store_true')
            parser.add_argument('--profile', choices=DEPLOYMENT_PROFILES)
            args = parser.parse_args(argv[1:])
            config = _settings(args, require_version=True)
            result = {'schema_version': 1, 'status': 'valid', 'config_version': config.config_version}
            if action == 'show':
                result['configuration'] = redacted_config(config)
                if args.source:
                    result['sources'] = config_sources(config, args.config, os.environ, args)
            output(result, machine)
            return 0
        if command == 'profiles':
            from .deception.profiles import PROFILES
            parser = argparse.ArgumentParser(prog='eye-for-an-eye profiles')
            parser.add_argument('action', choices=('list', 'show'))
            parser.add_argument('name', nargs='?')
            parser.add_argument('--json', action='store_true')
            args = parser.parse_args(argv)
            rows = [asdict(p) for p in PROFILES]
            if args.action == 'show':
                rows = [row for row in rows if row['profile_id'] == args.name]
                if not rows:
                    raise ValueError('unknown profile; use profiles list')
            output({'schema_version': 1, 'catalogue_version': 2, 'profiles': rows}, machine)
            return 0
        if command == 'upgrade':
            parser = argparse.ArgumentParser(prog='eye-for-an-eye upgrade')
            parser.add_argument('action', choices=('check',))
            parser.add_argument('--config')
            parser.add_argument('--json', action='store_true')
            args = parser.parse_args(argv)
            from .storage.lifecycle import migration_plan
            config = load_config(args.config)
            source_version = tomllib.loads(Path(args.config).read_text(encoding='utf-8')).get('config_version', 0) if args.config else config.config_version
            output({'schema_version': 1, 'database': migration_plan(config), 'network_update_check': False,
                    'config_version': source_version, 'config_target_version': config.config_version,
                    'config_migration_required': source_version != config.config_version, 'restart_required': True}, machine)
            return 0
        if command == 'demo':
            parser = argparse.ArgumentParser(prog='eye-for-an-eye demo')
            parser.add_argument('--json', action='store_true')
            parser.parse_args(argv)
            from .demo import run
            output(run(), machine)
            return 0
        if command == 'run':
            from .cli import _parser, _settings, main as runtime_main
            parser = _parser('proto')
            parser.prog = 'eye-for-an-eye run'
            parser.add_argument('--profile', choices=DEPLOYMENT_PROFILES)
            args = parser.parse_args(argv)
            if not args.config:
                if not Path('eye-for-an-eye.toml').is_file():
                    raise ValueError('No configuration found. Run: eye-for-an-eye config init; or eye-for-an-eye demo')
                args.config = 'eye-for-an-eye.toml'
            config = _settings(args, require_version=True)
            runtime_command, plan = startup_plan(config)
            if args.check_config:
                output(plan)
                return 0
            print('Startup: '+json.dumps(plan), file=sys.stderr)
            if config.deployment.profile == 'lab':
                print('WARNING: LAB ONLY / DO NOT USE ON PUBLIC INTERNET', file=sys.stderr)
            if runtime_command == 'services' and not ipaddress.ip_address(config.network.bind_address).is_loopback:
                print('WARNING: listener uses a non-loopback address; review decoy ports and source allowlist', file=sys.stderr)
            if any(section.enabled and not ipaddress.ip_address(section.bind_address).is_loopback
                   for section in (config.api, config.metrics)):
                print('WARNING: non-loopback operational endpoint; protect it with authentication/TLS and access controls', file=sys.stderr)
            return runtime_main([], command=runtime_command, config_override=config, debug=debug)
        raise ValueError('unknown operator command')
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, TypeError, RuntimeError, ImportError, sqlite3.Error) as exc:
        return failure(exc, machine=machine, debug=debug)
