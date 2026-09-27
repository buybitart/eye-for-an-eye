"""P8 operator commands: drift status, drift report and model health.

Read-only. These commands never train, download, promote or change a firewall.
"""
import argparse
import json
import sys

from .config import load_config
from .decision.distribution import DistributionError, RollingDistribution, load_reference
from .decision.drift import DriftEngine, model_health

BAR = {'STABLE': '.', 'WARNING': '~', 'DRIFTED': '!', 'INSUFFICIENT_DATA': '?'}
PLAIN = {'STABLE': 'Stable', 'WARNING': 'Medium', 'DRIFTED': 'High',
         'INSUFFICIENT_DATA': 'Not enough data'}


def _reference(config):
    """Load the reference distribution bound to the configured model, or explain why not."""
    path = config.reliability.distribution_path
    if not config.reliability.ood_enabled and not config.reliability.drift_enabled:
        return None, 'drift and OOD are disabled in the configuration'
    if not path:
        return None, 'no reliability.distribution_path is configured'
    expected = None
    if config.ml.manifest_path:
        try:
            from .decision.onnx_model import read_artifacts
            manifest, _ = read_artifacts(config.ml)
            expected = manifest['model_version']
        except (OSError, ValueError):
            expected = None
    try:
        return load_reference(path, expected_model_version=expected), ''
    except (DistributionError, OSError, ValueError) as exc:
        return None, f'distribution unavailable: {exc}'


def _state(config, window):
    """Drift state read from stored production statistics, if any exist yet."""
    reference, problem = _reference(config)
    if reference is None:
        return None, None, problem
    engine = DriftEngine(reference, warning_threshold=config.reliability.drift_warning_threshold,
                         drifted_threshold=config.reliability.drift_drifted_threshold,
                         minimum_samples=config.reliability.drift_minimum_samples)
    rolling = RollingDistribution(reference)
    return reference, engine.evaluate(rolling.snapshot(window)), ''


def drift(argv, *, debug=False):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye drift',
        description='Compare recent traffic with the model training distribution. Read only.')
    parser.add_argument('action', choices=('status', 'report'))
    parser.add_argument('--config')
    parser.add_argument('--window', default='24h', choices=('1h', '24h', '7d'))
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure
    try:
        config = load_config(args.config)
        reference, result, problem = _state(config, args.window)
        if reference is None:
            payload = {'schema_version': 1, 'status': 'INSUFFICIENT_DATA', 'reason': problem}
            if args.json:
                print(json.dumps(payload))
            else:
                print('DATA DRIFT\n\nStatus:\nNot enough data\n\nReason:\n' + problem)
            return 0
        if args.json:
            print(json.dumps({'schema_version': 1, **result.explain(limit=64)}))
            return 0
        print('DATA DRIFT\n')
        print(f'Reference:\n{result.reference_dataset}\n{result.reference_version}\n')
        print(f'Window:\n{args.window}\n')
        print(f'Status:\n{PLAIN.get(result.status, result.status)}\n')
        if args.action == 'report':
            print(f'{"Feature":26} {"Drift":18} PSI')
            for feature in sorted(result.per_feature, key=lambda f: -(f.psi or 0))[:20]:
                value = '-' if feature.psi is None else f'{feature.psi:.3f}'
                print(f'  {feature.feature:24} {PLAIN.get(feature.status, feature.status):18} {value}')
            print()
        print(f'Samples:\n{result.sample_count}\n')
        print('Recommendation:')
        if result.status == 'DRIFTED':
            print('Traffic is not like the training data. Keep enforcement limited.')
            print('Review new traffic samples before you trust the model.')
        elif result.status == 'WARNING':
            print('Some features are moving. Keep watching.')
        elif result.status == 'INSUFFICIENT_DATA':
            print('Collect more traffic before reading this report.')
        else:
            print('No action needed.')
        return 0
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return failure(exc, machine=args.json, debug=debug)


def model_health_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye model health',
        description='Report whether the local model can still be trusted. Read only.')
    parser.add_argument('--config')
    parser.add_argument('--window', default='24h', choices=('1h', '24h', '7d'))
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure
    try:
        config = load_config(args.config)
        loaded, version = False, 'none'
        if config.ml.enabled and config.ml.model_path and config.ml.manifest_path:
            try:
                from .decision.onnx_model import read_artifacts
                manifest, _ = read_artifacts(config.ml)
                loaded, version = True, manifest['model_version']
            except (OSError, ValueError):
                loaded = False
        _, result, _ = _state(config, args.window)
        health = model_health(loaded=loaded, model_version=version, drift=result,
                              ood_warning=config.reliability.drift_ood_rate_warning,
                              ood_unreliable=config.reliability.drift_ood_rate_unreliable)
        if args.json:
            print(json.dumps({'schema_version': 1, **health.explain()}))
            return 0
        print('MODEL HEALTH\n')
        print(f'Classifier:\n{version}\n{health.state}\n')
        print('Anomaly model:\nnot installed\n')
        print('Feature schema:\n1\n')
        print(f'Data drift:\n{PLAIN.get(health.drift_status, health.drift_status)}\n')
        print('Reasons:')
        for reason in health.reasons:
            print('  ' + reason)
        print('\nNote:\nThe mathematical engine stays active in every state.')
        print('\nRecommendation:')
        print('Continue Shadow monitoring.' if health.state != 'HEALTHY'
              else 'No action needed. Keep watching before you enable blocking.')
        return 0
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return failure(exc, machine=args.json, debug=debug)


# --- P9 model lifecycle ---------------------------------------------------

def _registry(config):
    from pathlib import Path
    from .decision.registry import ModelRegistry
    root = getattr(config.reliability, 'registry_path', '') or 'models'
    return ModelRegistry(Path(root))


def registry_command(action, argv, *, debug=False):
    """`model list`, `model promote`, `model rollback`, `model candidate`.

    Promotion and rollback change which model the sensor loads, so both require
    an explicit confirmation flag. Nothing here is ever called automatically.
    """
    parser = argparse.ArgumentParser(prog=f'eye-for-an-eye model {action}',
        description='Local model registry. Offline. Promotion is always explicit.')
    if action == 'promote':
        parser.add_argument('version')
        parser.add_argument('--yes', action='store_true',
                            help='confirm that this changes the model the sensor loads')
        parser.add_argument('--reason', default='')
    if action == 'rollback':
        parser.add_argument('--yes', action='store_true',
                            help='confirm that this restores the previous active model')
        parser.add_argument('--reason', default='')
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure
    from .decision.registry import CANDIDATE, RegistryError
    try:
        config = load_config(args.config)
        registry = _registry(config)
        state = registry.state

        if action == 'list':
            versions = registry.list_versions()
            if args.json:
                print(json.dumps({'schema_version': 1, **state.explain(),
                                  'versions': [v.explain() for v in versions]}))
                return 0
            print('MODEL REGISTRY\n')
            if not versions:
                print('No model versions are registered.')
                print('The sensor is using the model paths in your configuration.')
                return 0
            print(f'{"Version":28} {"Role":10} {"Dataset":16} Created')
            for item in versions:
                print(f'  {item.version:26} {item.role:10} {item.dataset_version:16} {item.created_at}')
            print()
            print(f'Active:\n{state.active or "none"}\n')
            print(f'Candidate:\n{state.candidate or "none"}\n')
            print(f'Rollback target:\n{state.previous_active or "none"}')
            return 0

        if action == 'candidate':
            if not state.candidate:
                message = 'There is no candidate model.'
                print(json.dumps({'schema_version': 1, 'candidate': None}) if args.json else message)
                return 0
            described = registry.describe_version(state.candidate, CANDIDATE)
            payload = {'schema_version': 1, 'candidate': described.explain(),
                       'active': state.active,
                       'note': 'a candidate runs in shadow only and cannot change the firewall'}
            if args.json:
                print(json.dumps(payload))
                return 0
            print('CANDIDATE MODEL\n')
            print(f'Candidate:\n{described.version}\n')
            print(f'Active:\n{state.active or "none"}\n')
            print(f'Dataset:\n{described.dataset_version}\n')
            print(f'Parent model:\n{described.parent_model or "none"}\n')
            print(f'Feature schema:\n{described.feature_schema_version}\n')
            print('Authority:\nShadow only. A candidate cannot change the firewall.\n')
            print('Next:\nRead the evaluation report, then promote explicitly if you agree.')
            return 0

        if action == 'promote':
            if not args.yes:
                print('Refusing to promote without --yes.', file=sys.stderr)
                print(f'This would make {args.version} the model the sensor loads.', file=sys.stderr)
                return 2
            new_state = registry.promote(args.version, gate_passed=True, reason=args.reason)
            payload = {'schema_version': 1, 'promoted': args.version,
                       'previous_active': new_state.previous_active,
                       'rollback': 'eye-for-an-eye model rollback --yes'}
            if args.json:
                print(json.dumps(payload))
            else:
                print(f'Promoted:\n{args.version}\n')
                print(f'Previous active:\n{new_state.previous_active or "none"}\n')
                print('To undo this:\neye-for-an-eye model rollback --yes\n')
                print('Restart the service for the change to take effect.')
            return 0

        if action == 'rollback':
            if not args.yes:
                print('Refusing to roll back without --yes.', file=sys.stderr)
                print(f'This would restore {state.previous_active or "(nothing)"}.', file=sys.stderr)
                return 2
            new_state = registry.rollback(reason=args.reason)
            payload = {'schema_version': 1, 'active': new_state.active,
                       'replaced': new_state.previous_active}
            if args.json:
                print(json.dumps(payload))
            else:
                print(f'Active model:\n{new_state.active}\n')
                print(f'Replaced:\n{new_state.previous_active or "none"}\n')
                print('Restart the service for the change to take effect.')
            return 0
        raise ValueError('unknown registry action')
    except RegistryError as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return failure(exc, machine=getattr(args, 'json', False), debug=debug)
