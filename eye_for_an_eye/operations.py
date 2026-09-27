"""Finite local diagnostics and sanitized exports; no network requests or repairs."""
import argparse
from dataclasses import asdict
import csv
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
import sys
import time
from .api.models import EventResponse
from .config import load_config
from .observability.version import version_info
from .security.privileges import ensure_analysis_user
from .storage.operations import backup, storage_info
from .storage.reader import Query, Reader


def _never_started(config, problem):
    """True when `status` failed only because nothing has ever run here. P18 §47.

    Deliberately narrow. A service that *is* running and whose snapshot is stale,
    oversized or malformed must still be a failure — that is a real fault and
    hiding it would be the sort of friendliness that costs an operator a morning.
    The one case treated as an answer rather than an error is the absent file.
    """
    if not isinstance(problem, OSError):
        return False
    path = config.runtime.status_file
    return bool(path) and not Path(path).exists()


def status(config):
    path = Path(config.runtime.status_file)
    if not config.runtime.status_file or path.stat().st_size > 65536 or time.time() - path.stat().st_mtime > 5:
        raise ValueError('missing, stale or oversized status')
    with path.open(encoding='utf-8') as stream:
        encoded = stream.read(65537)
    if len(encoded) > 65536:
        raise ValueError('oversized status')
    state = json.loads(encoded)
    if not isinstance(state, dict) or state.get('schema_version', 1) != 1:
        raise ValueError('invalid or unsupported status snapshot')
    if any(key in state and not isinstance(state[key], dict) for key in ('health', 'operational', 'metrics', 'queue')):
        raise ValueError('invalid status component structure')
    return state


def _autonomy_checks(config):
    """P15.5R §50. What `doctor` must be able to refuse.

    Six conditions, each named and each answered separately, because an operator
    reading "autonomy: DEGRADED" needs to know which of them it was. The one that
    matters most is the calibrator: a deployment can be perfectly configured,
    pass every other check, and be unable to place a single block because its
    calibrator belongs to another formula. That is not a hypothetical — it is the
    shape of P15.4, and the reason this section exists at all.

    Read-only. Nothing here loads a model into an interpreter, opens a socket or
    goes near a firewall.
    """
    from .autonomy import calibrator as calibration_loader
    from .autonomy.cost import CostError, from_config as cost_from_config
    from .compatibility import FEATURE_SCHEMA
    from .decision.math_risk import VERSION as MATH_RISK_VERSION

    autonomy = getattr(config, 'autonomy', None)
    if autonomy is None or not autonomy.enabled:
        return {'status': 'DISABLED',
                'reason': ('autonomy is off; the P0-P14 fused path decides and the '
                           'P15 authority is not constructed'),
                'mode': getattr(autonomy, 'mode', 'shadow')}

    autonomous = autonomy.mode == 'autonomous'
    report = {'status': 'HEALTHY', 'mode': autonomy.mode, 'checks': {}}

    def record(name, status, detail):
        report['checks'][name] = {'status': status, 'detail': detail}
        order = ('HEALTHY', 'DEGRADED', 'UNAVAILABLE')
        if order.index(status) > order.index(report['status']):
            report['status'] = status

    state = calibration_loader.load_for(config)
    record('calibrator',
           {'HEALTHY': 'HEALTHY', 'NOT_CONFIGURED': 'UNAVAILABLE' if autonomous else 'DEGRADED',
            'DEGRADED': 'DEGRADED', 'UNAVAILABLE': 'UNAVAILABLE'}[state.status],
           state.reason or f'{state.version} on {state.model_version}')

    record('feature_schema',
           'HEALTHY' if FEATURE_SCHEMA.supports(FEATURE_SCHEMA.current) else 'UNAVAILABLE',
           f'current {FEATURE_SCHEMA.current}, servable {list(FEATURE_SCHEMA.servable)}')

    record('formula', 'HEALTHY', MATH_RISK_VERSION)

    try:
        policy = cost_from_config(config)
        unmapped = sorted(scope for scope, name in policy.scope_profiles.items()
                          if name not in policy.profiles)
        record('cost_policy', 'UNAVAILABLE' if unmapped else 'HEALTHY',
               f'{len(policy.profiles)} profiles, {len(policy.scope_profiles)} scope '
               f'mappings, default {policy.default_profile}'
               + (f'; unknown profile for {unmapped}' if unmapped else ''))
    except CostError as exc:
        record('cost_policy', 'UNAVAILABLE', str(exc)[:160])

    enforcement = config.enforcement
    if not autonomous:
        record('enforcement', 'HEALTHY',
               'shadow mode: decisions are recorded and nothing is enforced')
    elif not enforcement.host_enabled:
        record('enforcement', 'DEGRADED',
               'autonomous mode without enforcement.host_enabled: decisions are '
               'taken and no block is placed')
    elif not config.runtime.config_path:
        record('enforcement', 'UNAVAILABLE',
               'the privileged helper is invoked with --config <path> and this '
               'configuration was not loaded from a file')
    else:
        record('enforcement', 'HEALTHY',
               f'host enforcement via the privileged helper, '
               f'{len(enforcement.management_networks)} management networks protected')

    # P15.5R §24, §25. The two optional evidence files, checked before they are
    # needed rather than when the first decision fails to land.
    #
    # An operator who turns the journal on and points it at a directory that
    # does not exist finds out at the first decision, in a counter, on a machine
    # they are not watching. `doctor` is where that belongs — and the check is
    # advisory in exactly the way `storage_writable` below is: `os.access` asks
    # a permission question rather than writing, and it cannot know whether the
    # filesystem will be full in an hour. What it catches is the configuration
    # mistake, which is the common one.
    files = []
    for label, path in (('journal', autonomy.decision_journal_path),
                        ('shadow export', autonomy.shadow_export_path)):
        if not path:
            continue
        parent = Path(path).parent
        files.append((label, parent.is_dir() and os.access(parent, os.W_OK)))
    unwritable = [label for label, writable in files if not writable]
    if not files:
        record('evidence_files', 'HEALTHY',
               'no decision journal or shadow export is configured; decisions are '
               'reported and not persisted, which is the default')
    elif unwritable:
        record('evidence_files', 'DEGRADED',
               f'{", ".join(unwritable)}: the directory does not exist or is not '
               f'writable, so records will be counted as failures and dropped')
    else:
        record('evidence_files', 'HEALTHY',
               f'{len(files)} configured, directories writable (advisory: a '
               f'permission check, not a write)')
    return report


def doctor(config):
    checks = {'configuration': {'status': 'HEALTHY'}, 'versions': version_info(config)}
    # The web layer reports itself. It is read-only: no Nginx configuration and no
    # firewall rule is touched by any check in it.
    try:
        from .web.doctor import check as web_check
        checks['web'] = web_check(config).get('web', {'status': 'DISABLED'})
        checks['web_detail'] = web_check(config)
    except (ImportError, AttributeError, OSError, ValueError):
        checks['web'] = {'status': 'UNAVAILABLE', 'reason': 'web checks failed to run'}
    configured = bool(config.ml.model_path and config.ml.manifest_path)
    # No model file is a documented, safe state: the mathematical engine works alone.
    # Not the literal 1. This reported the feature schema as 1 from P15.4 onward,
    # when the schema in force was 2 — an operator-facing health field stating
    # something false about the build it describes (P15.5 §2).
    from .compatibility import FEATURE_SCHEMA
    checks['ml'] = {'status': 'DISABLED' if not config.ml.enabled else 'NOT_CONFIGURED' if not configured else 'DEGRADED',
        'required': config.ml.required,
        'feature_schema_version': FEATURE_SCHEMA.current,
        'servable_feature_schemas': list(FEATURE_SCHEMA.servable), 'loaded': False,
        'reason': 'no local model file is configured; the mathematical engine works alone' if not configured
                  else 'use runtime health for loaded session status'}
    if config.ml.enabled and config.ml.model_path and config.ml.manifest_path:
        from .decision.onnx_model import read_artifacts
        try:
            manifest, _ = read_artifacts(config.ml)
            checks['ml'].update(status='HEALTHY', model_version=manifest['model_version'],
                reason='artifact hash/manifest checked; CPU warmup occurs at startup')
        except (ValueError, OSError):
            checks['ml'].update(status='UNAVAILABLE', reason='model artifact validation failed')
    # §40. Two synthetic vectors through MathRisk, the calibrator and the
    # authority. Wiring only (§41) — nothing here is evidence about detection,
    # and the check reports WIRED/BROKEN rather than anything resembling a score.
    try:
        from .autonomy.selfcheck import check as decision_selfcheck
        checks['decision_pipeline'] = decision_selfcheck(config)
    except (ImportError, AttributeError, OSError, ValueError) as exc:
        checks['decision_pipeline'] = {
            'status': 'UNAVAILABLE',
            'reason': f'the decision self-check could not run: {type(exc).__name__}'}
    parent = Path(config.storage.path).resolve().parent
    checks['autonomy'] = _autonomy_checks(config)
    checks['storage_writable'] = {'status': 'HEALTHY' if parent.is_dir() and os.access(parent, os.W_OK) else 'UNAVAILABLE',
        'limitations': ['advisory_access_check_not_a_write_guarantee']}
    try:
        disk = shutil.disk_usage(parent)
        checks['disk'] = {'status': 'HEALTHY' if disk.free > config.storage.max_bytes else 'DEGRADED', 'free_bytes': disk.free}
    except OSError:
        checks['disk'] = {'status': 'UNAVAILABLE', 'error': 'dependency_unavailable'}
    if not Path(config.storage.path).exists():
        checks['database'] = {'status': 'DEGRADED' if config.storage.enabled else 'DISABLED', 'reason': 'not_created'}
    else:
        try:
            checks['database'] = {'status': 'HEALTHY', **storage_info(Reader(config.storage.path, config.api))}
        except (OSError, sqlite3.Error):
            checks['database'] = {'status': 'UNAVAILABLE', 'error': 'storage_failure'}
    for name, path in (('geoip', config.enrichment.mmdb_path), ('p0f', config.capture.p0f_db)):
        present = bool(path and Path(path).is_file())
        checks[name] = {'status': 'HEALTHY' if present else 'DEGRADED' if path else 'DISABLED',
                        'reason': 'local_database_present' if present else 'optional_data_not_configured' if not path else 'dependency_unavailable'}
        if present:
            age = max(0, (time.time()-Path(path).stat().st_mtime)/86400)
            checks[name].update(file_age_days=round(age, 1), age_source='filesystem_mtime_not_database_release_date')
            if age > 30:
                checks[name]['status'] = 'DEGRADED'
                checks[name]['action'] = 'review the data provider version and update policy'
    try:
        ensure_analysis_user(config.runtime.enforce_unprivileged)
        checks['capabilities'] = {'status': 'HEALTHY' if sys.platform.startswith('linux') else 'DEGRADED',
            'limitations': ['capture_helper_separately_requires_only_CAP_NET_RAW',
                           'Linux checks NOT VERIFIED IN CURRENT ENVIRONMENT' if not sys.platform.startswith('linux') else 'analysis_role_checked']}
    except (OSError, RuntimeError):
        checks['capabilities'] = {'status': 'UNAVAILABLE', 'error': 'permission_failure'}
    ports = [('listener', config.network.bind_address, config.network.port, config.network.protocol)] if config.deployment.profile != 'sensor' else []
    ports += [(name, section.bind_address, section.port, 'tcp') for name, section in
              (('api', config.api), ('metrics', config.metrics)) if section.enabled]
    checks['ports'] = []
    for name, address, port, protocol in ports:
        try:
            with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,
                               socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM) as probe:
                probe.bind((address, port))
            outcome = 'bind_available_at_check_time'
        except OSError:
            outcome = 'network_bind_failure_or_port_in_use'
        checks['ports'].append({'component': name, 'bind_address': address, 'port': port, 'result': outcome})
    checks['port_availability'] = {'status': 'DEGRADED' if any(p['result'].startswith('network_') for p in checks['ports']) else 'HEALTHY',
        'action': 'compare with the running service; never terminate an unknown port owner'}
    checks['security_policy'] = {'status': 'HEALTHY', 'egress': config.deployment.egress,
        'active_probes': config.active_probes.enabled, 'udp_responses': config.network.udp_responses,
        'firewall_apply_automatic': config.enforcement.enabled, 'decision_mode': config.decision.mode}
    checks['secrets'] = {'status': 'DISABLED'}
    if config.deployment.profile in ('honeypot', 'lab'):
        from .security.secrets import load_secret
        try:
            load_secret(config)
            checks['secrets'] = {'status': 'HEALTHY', 'values': 'redacted'}
        except (OSError, ValueError):
            checks['secrets'] = {'status': 'UNAVAILABLE', 'action': 'configure a readable persistent 32..4096-byte secret file'}
    checks['limitations'] = ['diagnostic_only_no_repairs', 'bind_probe_sends_no_packets_and_does_not_listen',
                            'run_same_config_and_user_as_service', 'optional_databases_do_not_disable_sensor']
    return checks


def export_events(reader, query, destination, *, format, max_bytes, redact_ip=False):
    rows, cursor = reader.events(query)
    output = io.StringIO(newline='')
    if format == 'csv':
        columns = ('event_id', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'transport',
                   'event_type', 'classification', 'confidence')
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
    for _, event in rows:
        item = EventResponse.from_event(event, redact_ip)
        if format == 'jsonl':
            output.write(json.dumps(item, ensure_ascii=True, separators=(',', ':')) + '\n')
        else:
            # Spreadsheet formula injection also applies to operator-chosen event identifiers.
            row = {key: item[key] for key in columns}
            for key, value in row.items():
                if isinstance(value, str) and value.startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
                    row[key] = "'" + value
            writer.writerow(row)
        if output.tell() > max_bytes:
            raise ValueError('export exceeds byte budget')
    data = output.getvalue().encode('utf-8')
    if len(data) > max_bytes:
        raise ValueError('export exceeds byte budget')
    target = Path(destination).resolve()
    if target in (reader.path, Path(str(reader.path) + '-wal'), Path(str(reader.path) + '-shm'), Path(str(reader.path) + '.lock')):
        raise ValueError('export cannot target storage')
    with target.open('xb') as stream:
        target.chmod(0o600)
        stream.write(data)
    return {'status': 'complete', 'records': len(rows), 'bytes': len(data), 'next_cursor': cursor}


def main(command, argv, *, debug=False):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye ' + command)
    if command in ('events', 'storage'):
        parser.add_argument('action', choices=('tail', 'export') if command == 'events' else ('info', 'backup', 'migrate', 'restore', 'prune'))
        parser.add_argument('destination', nargs='?')
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--health-only', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--backup')
    parser.add_argument('--format', choices=('jsonl', 'csv'), default='jsonl')
    parser.add_argument('--max-bytes', type=int, default=1_048_576)
    for key in ('from', 'to', 'limit', 'cursor', 'event-type', 'transport', 'classification', 'confidence', 'source', 'destination-port'):
        parser.add_argument('--' + key)
    args = parser.parse_args(argv)
    stage = 'configuration_error'
    try:
        # P18 §27, §120. Without --config these commands loaded built-in
        # defaults, so on a freshly installed machine `doctor` reported a
        # confident health verdict about a configuration that is not the one
        # installed — Web DISABLED, Autonomy DISABLED — while the installed file
        # had the shadow analysis path switched on. A wrong answer in the shape of
        # a health report is worse than an error, and `doctor` is the command the
        # installer, the README and the beginner messages all point at.
        #
        # Only the absent-flag case changes, the discovered file is announced, and
        # if nothing is discoverable the old behaviour stands.
        if not args.config:
            from .beginner import default_config_path
            discovered = default_config_path()
            if discovered.is_file():
                args.config = str(discovered)
                sys.stderr.write('Reading the settings file for this computer:\n  '
                                 + args.config + '\n\n')
            elif command in ('doctor', 'status'):
                # Nothing to report on. Reporting on built-in defaults instead is
                # what this branch exists to stop: `doctor` did exactly that and
                # produced a confident health verdict — Web DISABLED, Autonomy
                # DISABLED — about a configuration that is not on the machine.
                sys.stdout.write(
                    'Eye for an Eye is not set up on this computer yet.\n'
                    '\n'
                    'It looked for a settings file and found none. There is nothing\n'
                    'to report on, so it will not guess.\n'
                    '\n'
                    'To set it up:\n'
                    '  eye-for-an-eye setup\n'
                    '\n'
                    'To report on a particular file:\n'
                    '  eye-for-an-eye ' + command + ' --config <path>\n')
                return 1
        config = load_config(args.config)
        if not 1 <= args.max_bytes <= 4_194_304:
            raise ValueError('max export bytes must be 1..4194304')
        reader = Reader(config.storage.path, config.api,
                        allowed_versions=(1, 2) if command == 'storage' and args.action == 'backup' else (2,))
        if command == 'doctor':
            result = doctor(config)
            if args.config and os.name == 'posix':
                mode = stat.S_IMODE(Path(args.config).stat().st_mode)
                result['config_permissions'] = {'status': 'DEGRADED' if mode & 0o022 else 'HEALTHY',
                    'mode': oct(mode), 'action': 'review ownership and writable config groups; no permissions changed'}
        elif command == 'version':
            result = version_info(config)
        elif command == 'status':
            stage = 'dependency_unavailable'
            # P18 §47. `status` reads the snapshot a running service writes, so
            # there is nothing to read when nothing is running — the state of
            # every computer that has just been installed. It used to answer that
            # with `Error [1]: [Errno 2] No such file or directory:
            # '.../status.json'`, and this is the command the installer and the
            # README both tell a new user to run next.
            try:
                result = status(config)
            except OSError as unavailable:
                if not _never_started(config, unavailable):
                    raise
                # There is no runtime snapshot. Before answering "not running",
                # ask whether the beginner watcher is running, because it writes a
                # marker and not a snapshot.
                #
                # The first version of this branch did not ask, and reported
                # `Protection: NOT RUNNING` while `eye-for-an-eye start` was
                # running in another terminal and `easy status` was correctly
                # reporting WATCHING. That is worse than the error it replaced: an
                # errno is confusing, a confident wrong answer is misleading, and
                # an operator deciding whether traffic is being watched is exactly
                # who must not be misled.
                from .beginner import running_marker
                watching = running_marker().is_file()
                result = {'schema_version': 1, 'running': watching,
                          'state': 'WATCHING' if watching else 'NOT RUNNING',
                          'detail': ('Safe Monitoring is running. It writes no runtime '
                                     'snapshot, so this command has no metrics to show.'
                                     if watching else
                                     'Eye for an Eye is not running on this computer.'),
                          'status_file': config.runtime.status_file,
                          'next': ['eye-for-an-eye easy status'] if watching
                                  else ['eye-for-an-eye start']}
                if args.json:
                    sys.stdout.write(json.dumps(result) + '\n')
                elif watching:
                    sys.stdout.write(
                        'Eye for an Eye\n'
                        '\n'
                        '  Protection: WATCHING (Safe Monitoring)\n'
                        '\n'
                        'It is running, and nothing is blocked.\n'
                        '\n'
                        'This command reports the snapshot the sensor service writes,\n'
                        'and Safe Monitoring does not write one. For what it is seeing:\n'
                        '  eye-for-an-eye easy status\n')
                else:
                    sys.stdout.write(
                        'Eye for an Eye\n'
                        '\n'
                        '  Protection: NOT RUNNING\n'
                        '\n'
                        'Nothing is running, so there is nothing to report.\n'
                        'Nothing is blocked.\n'
                        '\n'
                        'To start Safe Monitoring:\n'
                        '  eye-for-an-eye start\n'
                        '\n'
                        'To check the installation instead:\n'
                        '  eye-for-an-eye check-install\n')
                return 0 if watching else 1
        else:
            stage = 'storage_failure'
            if not config.storage.enabled:
                raise ValueError('storage disabled')
            if command == 'storage':
                if args.action in ('migrate', 'restore', 'prune'):
                    from .storage.lifecycle import migration_plan, migrate_database, restore_new, prune
                    if args.action == 'migrate':
                        result = migrate_database(config, args.backup) if args.apply else {'schema_version': 1, 'plan': migration_plan(config)}
                    elif args.action == 'restore':
                        if not args.destination:
                            raise ValueError('restore source backup required; destination is storage.path in --config')
                        result = restore_new(config, args.destination, confirmed=args.yes)
                    else:
                        result = prune(config, confirmed=args.apply)
                elif args.action == 'backup':
                    if not args.destination:
                        raise ValueError('backup destination required')
                    result = backup(reader, args.destination, max_bytes=config.storage.max_bytes)
                else:
                    result = storage_info(reader)
            else:
                params = {key: getattr(args, key) for key in ('from', 'to', 'limit', 'cursor', 'event_type', 'transport',
                          'classification', 'confidence', 'source', 'destination_port') if getattr(args, key) is not None}
                query = Query.parse(params, config.api)
                if command == 'stats':
                    result = {'activity': reader.stats(query), 'storage': storage_info(reader)}
                    try:
                        current = status(config)
                        result['queue_drops'] = current['queue']['dropped']
                    except (OSError, ValueError, KeyError, TypeError):
                        result['queue_drops'] = None
                        result['limitations'] = ['live_status_unavailable']
                elif args.action == 'export':
                    if not args.destination:
                        raise ValueError('export destination required')
                    result = export_events(reader, query, args.destination, format=args.format,
                                           max_bytes=args.max_bytes, redact_ip=config.api.redact_ip)
                else:
                    rows, cursor = reader.events(query)
                    result = {'items': [EventResponse.from_event(event, config.api.redact_ip) for _, event in rows],
                              'next_cursor': cursor, 'window': asdict(query)}
        from .operator_cli import output
        result.setdefault('schema_version', 1)
        if command == 'status' and args.health_only:
            operational = result.get('operational', {})
            ready = operational.get('ready', result.get('running') and result.get('health', {}).get('status') != 'unavailable')
            result = {'schema_version': 1, 'ready': bool(ready), 'status': operational.get('status', 'UNAVAILABLE')}
            output(result, args.json)
            return 0 if ready else 1
        encoded = json.dumps(result, ensure_ascii=True)
        if len(encoded) > 4_194_304:
            raise ValueError('output byte budget exceeded')
        displayed = result
        if command == 'status' and not args.json:
            metrics = result.get('metrics', {})
            uptime = result.get('uptime_seconds', 0)
            displayed = {key: result.get(key, 'unknown') for key in ('application_version', 'deployment_profile', 'mode', 'uptime_seconds')}
            displayed.update(health=result.get('operational', result.get('health', {})),
                active_connections=metrics.get('connections_active', 0), queue=result.get('queue', {}),
                events_per_second_average=round(metrics.get('events_created_total', 0) / max(1, uptime), 2),
                events_per_minute_average=round(60 * metrics.get('events_created_total', 0) / max(1, uptime), 2),
                storage_bytes=metrics.get('storage_bytes', 0), stored_events=metrics.get('storage_retained_events', 0),
                drops=metrics.get('events_dropped_total', 0), storage_pressure=result.get('storage_pressure', 'unknown'),
                deception=result.get('deception', {}))
            if result.get('storage_pressure') in ('WARNING', 'CRITICAL'):
                displayed['action'] = 'storage pressure can drop events; review disk/retention and backup before changes'
            elif metrics.get('events_dropped_total', 0):
                displayed['action'] = 'event loss observed; inspect queue and ingestion load before changing limits'
        output(displayed, args.json or command in ('events', 'stats', 'version'))
        if command == 'status':
            return 0 if result.get('operational', {}).get('ready', result.get('running') and result['health']['status'] != 'unavailable') else 1
        if command == 'doctor':
            if any(isinstance(value, dict) and value.get('status') == 'UNAVAILABLE' for value in result.values()):
                return 1
            return 7 if any(isinstance(value, dict) and value.get('status') == 'DEGRADED' for value in result.values()) else 0
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, sqlite3.Error) as exc:
        from .operator_cli import failure
        code = 5 if stage == 'storage_failure' else 1 if stage == 'dependency_unavailable' else 2
        return failure(exc, code, machine=args.json, debug=debug)
