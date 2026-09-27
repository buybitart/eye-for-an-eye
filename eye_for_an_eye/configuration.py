"""Explicit starter/migration files. Only new operator-selected files are created."""
from dataclasses import asdict
from importlib.resources import files
import json
import os
from pathlib import Path
import secrets
from .config import CONFIG_VERSION, load_config


def encode_toml(config):
    """The schema contains only scalar/list/inline-table values; no arbitrary serializer."""
    def value(item):
        if type(item) is bool:
            return 'true' if item else 'false'
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=True)
        if isinstance(item, (int, float)):
            return str(item)
        if isinstance(item, list):
            return '[' + ', '.join(value(child) for child in item) + ']'
        if isinstance(item, dict):
            return '{' + ', '.join(json.dumps(key) + ' = ' + value(child) for key, child in item.items()) + '}'
        raise ValueError('unsupported configuration value')
    sections = asdict(config)
    lines = [f'config_version = {CONFIG_VERSION}', 'probes_path = ' + value(sections.pop('probes_path')), '']
    sections.pop('config_version')
    for section, settings in sections.items():
        lines += ['[' + section + ']'] + [key + ' = ' + value(item) for key, item in settings.items()] + ['']
    return '\n'.join(lines)


def write_new(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


# Setup profile -> template file. "website" is a friendly name for the passive sensor
# deployment profile with settings a web server owner wants; it is not a new deployment mode.
#
# `production-shadow` and `production-autonomous` are the two production postures.
# Both are sensor deployments running the same runtime, and the difference between
# them is one thing: whether a decision the authority takes is carried out. Shadow
# is where a deployment starts, and the only one a quick start should reach for.
PROFILE_TEMPLATES = {'website': 'website', 'sensor': 'sensor', 'honeypot': 'honeypot',
                     'lab': 'lab', 'production-shadow': 'production-shadow',
                     'production-autonomous': 'production-autonomous'}

#: Setup profiles that are a sensor deployment under another name. The runtime
#: reads `deployment.profile`; these are the names an operator selects.
SENSOR_PROFILES = ('website', 'production-shadow', 'production-autonomous')


def initialize(destination, profile):
    target = Path(destination).absolute()
    if profile not in PROFILE_TEMPLATES:
        raise ValueError('profile: expected one of ' + ', '.join(sorted(PROFILE_TEMPLATES)))
    if target.exists() or target.is_symlink():
        raise FileExistsError('configuration destination already exists; choose a new path')
    deployment = 'sensor' if profile in SENSOR_PROFILES else profile
    text = files('eye_for_an_eye').joinpath('templates', PROFILE_TEMPLATES[profile] + '.toml').read_text(encoding='utf-8')
    secret = target.with_name(target.stem + '.secret')
    created_secret = False
    try:
        # Only deception profiles need a persistent secret; a passive sensor never serves decoys.
        if deployment != 'sensor':
            write_new(secret, secrets.token_bytes(32))
            created_secret = True
            text = text.replace('secret_file = ""', 'secret_file = ' + json.dumps(secret.name))
        write_new(target, text.encode('utf-8'))
    except BaseException:
        if created_secret:
            secret.unlink(missing_ok=True)
        raise
    return {'schema_version': 1, 'status': 'created', 'config': str(target), 'profile': profile,
            'deployment_profile': deployment,
            'persistent_secret_created': created_secret, 'next': 'config validate; doctor; run --config <file>',
            'limitations': ['Windows ACLs must be reviewed by the operator'] if os.name == 'nt' else []}


def migrate(source, destination, profile):
    config = load_config(source, validate=False, environ={})
    if config.config_version not in (0, CONFIG_VERSION):
        raise ValueError('cannot migrate an unknown future config version')
    config.config_version = CONFIG_VERSION
    config.deployment.profile = profile
    if config.enrichment.rdap_enabled or config.active_probes.enabled:
        config.deployment.egress = 'restricted'
    config.validate()
    write_new(Path(destination).absolute(), encode_toml(config).encode('utf-8'))
    return {'schema_version': 1, 'status': 'migrated_to_new_file', 'target_version': CONFIG_VERSION,
            'source_unchanged': True, 'restart_required': True, 'profile': profile}
