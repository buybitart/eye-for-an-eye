"""Explicit entrypoints with validation before listeners, capture or workers."""
from .event_types import EventType
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import signal
import sys
import threading
import time
from .config import load_config, redacted_config
from .security.secrets import load_secret

COMMANDS = ('proto', 'services', 'ip_id', 'nat', 'uptime', 'garbage', 'config', 'capture-helper', 'firewall', 'health', 'metrics', 'analyze-pcap',
            'doctor', 'status', 'stats', 'events', 'storage', 'version', 'run', 'profiles', 'demo', 'upgrade', 'simulate', 'decision',
            'setup', 'model', 'drift', 'review', 'learning', 'web', 'challenge', 'sites', 'autonomy',
            # P17. The beginner layer, added beside the expert commands rather than
            # in front of them: `status` and `doctor` still mean exactly what they
            # meant before, and `easy status` is the short answer.
            'start', 'stop', 'easy', 'check-install')


def _parser(command):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye ' + command,
        description='LAB ONLY / NOT FOR PUBLIC DEPLOYMENT' if command == 'garbage' else 'Bounded defensive observation')
    parser.add_argument('--config', help='strict TOML configuration')
    if command in ('proto', 'services', 'garbage'):
        parser.add_argument('port', nargs='?', type=int)
        parser.add_argument('protocol', nargs='?', type=str.lower, choices=('tcp', 'udp'))
    else:
        parser.add_argument('interface', nargs='?')
        parser.add_argument('filter', nargs='?')
    parser.add_argument('--bind')
    parser.add_argument('--probes')
    parser.add_argument('--pcap')
    parser.add_argument('--p0f-db')
    parser.add_argument('--bpf')
    parser.add_argument('--secret-file')
    parser.add_argument('--secret-env')
    parser.add_argument('--mode', choices=('sensor', 'lab'), help='bounded deception mode')
    parser.add_argument('--log-file')
    parser.add_argument('--enrichment', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--rdap', action=argparse.BooleanOptionalAction, default=None, help='explicitly enable external RDAP enrichment')
    parser.add_argument('--mmdb')
    parser.add_argument('--active-path-probe', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--allow-cidr', action='append')
    parser.add_argument('--lab', action=argparse.BooleanOptionalAction, default=None, help='enable finite loopback-only deprecated experiment')
    parser.add_argument('--storage', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--storage-path')
    parser.add_argument('--status-file')
    parser.add_argument('--sensor-id')
    parser.add_argument('--ipc-socket')
    parser.add_argument('--lab-max-bytes', type=int)
    parser.add_argument('--lab-max-duration', type=float)
    parser.add_argument('--lab-max-connections', type=int)
    for flag in ('max-connections', 'max-connections-per-ip', 'max-request-bytes', 'max-response-bytes'):
        parser.add_argument('--' + flag, type=int)
    for flag in ('first-byte-timeout', 'idle-timeout', 'total-timeout'):
        parser.add_argument('--' + flag, type=float)
    parser.add_argument('--check-config', action='store_true', help='validate inputs and exit without opening sockets')
    return parser


def _settings(args, *, require_version=False):
    config = load_config(args.config, validate=False, require_version=require_version)
    if getattr(args, 'profile', None):
        config.deployment.profile = args.profile
    for key in ('port', 'protocol'):
        if getattr(args, key, None) is not None:
            setattr(config.network, key, getattr(args, key))
    for key in ('max_connections', 'max_connections_per_ip', 'max_request_bytes', 'max_response_bytes',
                'first_byte_timeout', 'idle_timeout', 'total_timeout'):
        if getattr(args, key) is not None:
            setattr(config.limits, key, getattr(args, key))
    for obj, key, value in [(config.network, 'bind_address', args.bind), (config, 'probes_path', args.probes),
        (config.capture, 'interface', getattr(args, 'interface', None)),
        (config.capture, 'bpf', args.bpf if args.bpf is not None else getattr(args, 'filter', None)),
        (config.capture, 'pcap_path', args.pcap), (config.capture, 'p0f_db', args.p0f_db),
        (config.deception, 'secret_file', args.secret_file), (config.deception, 'secret_env', args.secret_env),
        (config.deception, 'mode', args.mode),
        (config.logging, 'file', args.log_file), (config.enrichment, 'mmdb_path', args.mmdb),
        (config.lab, 'max_bytes', args.lab_max_bytes), (config.lab, 'max_duration', args.lab_max_duration),
        (config.lab, 'max_connections', args.lab_max_connections),
        (config.storage, 'path', args.storage_path), (config.runtime, 'status_file', args.status_file),
        (config.runtime, 'sensor_id', args.sensor_id), (config.capture, 'ipc_socket', args.ipc_socket)]:
        if value is not None:
            setattr(obj, key, value)
    for obj, key, value in ((config.enrichment, 'enabled', args.enrichment),
                           (config.enrichment, 'rdap_enabled', args.rdap),
                           (config.active_probes, 'enabled', args.active_path_probe),
                           (config.lab, 'enabled', args.lab), (config.storage, 'enabled', args.storage)):
        if value is not None:
            setattr(obj, key, value)
    if args.rdap:
        config.enrichment.enabled = True
    if args.storage_path and args.storage is None:
        config.storage.enabled = True
    if args.allow_cidr:
        config.active_probes.allowed_cidrs = args.allow_cidr
    return config.validate()


def _secret(config):
    return load_secret(config)


def main(argv=None, *, command=None, config_override=None, debug=False) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if '--debug' in argv:
        argv.remove('--debug')
        debug = True
    if command is None:
        root = argparse.ArgumentParser(prog='eye-for-an-eye')
        from . import __version__
        root.add_argument('--version', action='version', version=__version__)
        root.add_argument('command', choices=COMMANDS)
        if not argv:
            root.print_help()
            return 0
        parsed = root.parse_args(argv[:1])
        argv = argv[1:]
        command = parsed.command
    if command == 'drift':
        from .reliability_cli import drift as drift_command
        return drift_command(argv, debug=debug)
    if command == 'review':
        from .review_cli import review_command
        return review_command(argv, debug=debug)
    if command == 'learning':
        from .learning_cli import learning_command
        return learning_command(argv, debug=debug)
    if command == 'web':
        from .web_cli import web_command
        return web_command(argv, debug=debug)
    if command == 'challenge':
        from .challenge_cli import challenge_command
        return challenge_command(argv, debug=debug)
    if command == 'sites':
        from .sites_cli import sites_command
        return sites_command(argv, debug=debug)
    if command == 'autonomy':
        from .autonomy_cli import autonomy_command
        return autonomy_command(argv, debug=debug)
    if command in ('start', 'stop', 'easy', 'check-install'):
        from .beginner import (easy_command, start_command, stop_command,
                               check_command)
        return {'start': start_command, 'stop': stop_command, 'easy': easy_command,
                'check-install': check_command}[command](argv, debug=debug)
    if command in ('setup', 'model'):
        if command == 'model' and argv[:1] == ['health']:
            from .reliability_cli import model_health_command
            return model_health_command(argv[1:], debug=debug)
        if command == 'model' and argv[:1] == ['governance']:
            from .governance_cli import governance_command
            return governance_command(argv[1:], debug=debug)
        if command == 'model' and argv[:1] and argv[0] in ('list', 'promote', 'rollback', 'candidate'):
            from .reliability_cli import registry_command
            return registry_command(argv[0], argv[1:], debug=debug)
        from .setup_cli import setup, model
        return setup(argv, debug=debug) if command == 'setup' else model(argv, debug=debug)
    if command in ('config', 'run', 'profiles', 'demo', 'upgrade'):
        from .operator_cli import main as operator_main
        return operator_main(command, argv, debug=debug)
    if command in ('doctor', 'status', 'stats', 'events', 'storage', 'version'):
        from .operations import main as operational_main
        return operational_main(command, argv, debug=debug)
    if command in ('simulate', 'decision'):
        from .decision.cli import simulate, explain
        return simulate(argv) if command == 'simulate' else explain(argv)
    if command == 'analyze-pcap':
        from .offline import cli
        return cli(argv)
    if command in ('health', 'metrics'):
        parser = _parser('proto')
        try:
            config = _settings(parser.parse_args(argv))
            path = Path(config.runtime.status_file)
            if not config.runtime.status_file or path.stat().st_size > 16384 or time.time() - path.stat().st_mtime > 5:
                raise ValueError('status file missing, stale or oversized')
            state = json.loads(path.read_text(encoding='utf-8'))
            sys.stdout.write(json.dumps(state['health' if command == 'health' else 'metrics']) + '\n')
            return 0 if state.get('running') and state['health']['status'] in ('healthy', 'degraded') else 1
        except (OSError, ValueError, KeyError, TypeError) as exc:
            sys.stderr.write(f'status unavailable: {type(exc).__name__}\n')
            return 1
    if command in ('config', 'firewall'):
        actions = argparse.ArgumentParser(prog='eye-for-an-eye config')
        actions.add_argument('action', choices=('validate', 'show') if command == 'config' else ('dry-run', 'apply', 'verify', 'rollback'))
        action = actions.parse_args(argv[:1]).action
        parser = _parser('proto')
        try:
            config = _settings(parser.parse_args(argv[1:]))
            if command == 'firewall':
                from .security.firewall import FirewallManager
                manager = FirewallManager(config)
                result = getattr(manager, action.replace('-', '_'))()
                sys.stdout.write(json.dumps(result, indent=2) + '\n')
                return 0 if result.get('status', 'healthy') == 'healthy' else 1
            if action == 'show':
                sys.stdout.write(json.dumps(redacted_config(config), indent=2) + '\n')
            return 0
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            parser.error(str(exc))
    parser = _parser(command)
    args = parser.parse_args(argv)
    try:
        config = _settings(args) if config_override is None else config_override.validate()
        if command == 'capture-helper':
            if not config.capture.interface or not config.capture.ipc_socket:
                raise ValueError('capture-helper requires interface and IPC socket')
            if config.enrichment.enabled or config.storage.enabled or config.active_probes.enabled:
                raise ValueError('capture helper cannot enable analysis/storage/enrichment')
            if args.check_config:
                return 0
            from .network.capture_helper import run_helper
            try:
                return run_helper(config)
            except (OSError, RuntimeError, ImportError) as exc:
                from .operator_cli import failure
                return failure(exc, code=1, debug=debug)
        if command in ('proto', 'services', 'garbage') and config.capture.pcap_path:
            raise ValueError('--pcap is only supported by ip_id, nat and uptime; no listener is started')
        if command == 'garbage' and (not config.lab.enabled or config.network.protocol != 'tcp'):
            raise ValueError('LAB ONLY experiment is OFF; requires --lab and TCP on loopback')
        if command == 'services' and config.firewall.enabled and not config.deception.redirected:
            raise ValueError('firewall-backed services require deception.redirected=true')
        if command == 'services' and config.network.port in config.firewall.real_service_ports + config.firewall.management_ports:
            raise ValueError('deception listener cannot bind a protected service port')
        if config.lab.enabled and command != 'garbage':
            raise ValueError('--lab is only for the deprecated garbage entrypoint')
        if config.active_probes.enabled and command != 'nat':
            raise ValueError('active path probes are only supported by nat')
        if command in ('ip_id', 'nat', 'uptime') and not (config.capture.ipc_socket or config.capture.pcap_path):
            raise ValueError('analysis capture requires --ipc-socket with a separate helper, or --pcap')
        if config.active_probes.enabled and config.runtime.enforce_unprivileged:
            raise ValueError('raw active probes are unavailable in the unprivileged analysis runtime')
        if config.capture.pcap_path and (config.active_probes.enabled or config.enrichment.rdap_enabled):
            raise ValueError('PCAP replay forbids active probes and external RDAP')
        from .fingerprint.probes import load_probes
        probes = load_probes(config.probes_path) if config.probes_path else {}
        secret = _secret(config) if command == 'services' and config.network.protocol == 'tcp' else None
        if args.check_config:
            return 0
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))

    from .events import EventPipeline, NetworkEvent
    from .runtime import EventRuntime
    from .security.policy import allow_response
    from .security.privileges import ensure_analysis_user
    from .enrichment.worker import EnrichmentService
    from .network.listeners import SelectorServer
    from .fingerprint.probes import match_probe
    from .correlation.features import PayloadFeatures
    from .deception.engine import DeceptionEngine
    from .fingerprint.path import path_provider
    sink = EventRuntime(config, mode=command)
    pipeline = EventPipeline(sink)
    enrichment = EnrichmentService(enabled=config.enrichment.enabled, on_result=pipeline.enriched,
        workers=config.enrichment.workers, queue_size=config.enrichment.queue_size, timeout=config.enrichment.timeout,
        cache_entries=config.limits.state_entries, cache_ttl=config.limits.state_ttl,
        negative_ttl=config.enrichment.negative_ttl, provider_options=asdict(config.enrichment))
    pipeline.enrichment = enrichment
    path_service = EnrichmentService(enabled=config.active_probes.enabled, provider=path_provider,
        on_result=lambda event_id, ip, result: sink.emit(NetworkEvent(ip, event_type=EventType.PATH_MEASUREMENT,
            observations={'parent_event_id': event_id, 'path_characteristics': result})),
        workers=1, queue_size=16, timeout=config.active_probes.timeout + 1, negative_ttl=60,
        cache_ttl=60, provider_options={'allowed_cidrs': config.active_probes.allowed_cidrs,
                                      'timeout': config.active_probes.timeout})
    sink.attach(enrichment=enrichment, path=path_service)
    cancel = threading.Event()
    handlers = {}
    server = None
    def stop(signum, frame):
        cancel.set()
        if server:
            server.stop()
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, stop)
    remaining = [config.lab.max_bytes]
    payload_features = PayloadFeatures(probes, config.fingerprint.min_probe_evidence)
    def connected(peer, destination):
        pipeline.record(NetworkEvent(peer[0], peer[1], destination[0], destination[1], 'tcp', EventType.CONNECTION_ACCEPTED,
            observations={'completed_handshake': True, 'attempt_visibility': 'accepted_connections_only'}))
        if command == 'garbage' and allow_response(config, command, peer[0], 'tcp'):
            size = min(remaining[0], config.limits.max_response_bytes)
            remaining[0] -= size
            return b'\x0e' * size
        return b''
    def received(peer, destination, data):
        event = NetworkEvent(peer[0], peer[1], destination[0], destination[1], config.network.protocol,
            EventType.SERVICE_PROBE, observations={**payload_features.observe(data, config.network.protocol),
                'scope': 'tcp_stream_prefix' if config.network.protocol == 'tcp' else 'udp_datagram',
                'original_destination': 'unverified_for_udp' if config.network.protocol == 'udp' else 'socket'})
        pipeline.record(event)
        match = match_probe(data, config.network.protocol, probes, config.fingerprint.min_probe_evidence)
        if match.probe_name:
            sink.emit(NetworkEvent(peer[0], peer[1], destination[0], destination[1], config.network.protocol,
                EventType.PROBE_MATCH, observations={'parent_event_id': event.event_id}, hypotheses={'probe': asdict(match)}))
        return b''
    exit_code = 0
    try:
        ensure_analysis_user(config.runtime.enforce_unprivileged)
        sink.start()
        enrichment.start()
        path_service.start()
        if command in ('proto', 'services', 'garbage'):
            decoy = None
            if command == 'services' and config.network.protocol == 'tcp':
                def load():
                    state = sink.deception_load()
                    if server:
                        state['pressure'] = max(state['pressure'], server.active_connections / config.limits.max_connections)
                    return state
                decoy = DeceptionEngine(config, secret, sink, load=load, probes=probes)
            server = SelectorServer(config, on_data=received, on_connect=connected,
                session_factory=decoy.open if decoy else None,
                max_duration=config.lab.max_duration if command == 'garbage' or config.deployment.profile == 'lab' else None,
                max_accepts=config.lab.max_connections if command == 'garbage' else None,
                lab_only=command == 'garbage')
            sink.attach(listener=server)
            server.serve_forever()
            if server.error:
                raise server.error
        else:
            from .network.capture import run_capture
            run_capture(config, pipeline, command, cancel, path_service)
    except KeyboardInterrupt:
        cancel.set()
    except (OSError, ValueError, RuntimeError, ImportError) as exc:
        from .operator_cli import failure, BIND, DEPENDENCY, PERMISSION, UNAVAILABLE
        code = PERMISSION if isinstance(exc, PermissionError) else DEPENDENCY if isinstance(exc, ImportError) else BIND if server and server.error else UNAVAILABLE
        if code == BIND:
            exc = OSError(f'listener {config.network.bind_address}:{config.network.port}: {exc}; check configuration or the existing service; no process was stopped')
        exit_code = failure(exc, code, debug=debug)
    finally:
        deadline = time.monotonic() + config.runtime.shutdown_timeout
        cancel.set()
        if server:
            server.stop()
        for service in (enrichment, path_service):
            try:
                service.close(timeout=min(3, max(.1, deadline - time.monotonic())))
            except RuntimeError as exc:
                sys.stderr.write(f'{exc}\n')
                exit_code = 1
        sink.emit(NetworkEvent('runtime', event_type=EventType.SHUTDOWN_METRICS, observations={
            'logging': dict(sink.metrics), 'enrichment': dict(enrichment.metrics),
            'listener': dict(server.metrics) if server else {}}))
        if not sink.close(timeout=max(0, deadline - time.monotonic())):
            exit_code = 1
        for sig, previous in handlers.items():
            signal.signal(sig, previous)
    return exit_code
