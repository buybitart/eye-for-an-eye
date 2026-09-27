"""Fail if a configuration is not passive. Used by the install smoke test and by operators.

Usage: python scripts/check_safe_defaults.py <config.toml>
Exit code 0 means the configuration observes only and changes no firewall.
"""
import json
import subprocess
import sys

EXPECTED = {
    ('decision', 'mode'): 'shadow',
    ('enforcement', 'enabled'): False,
    ('active_probes', 'enabled'): False,
    ('enrichment', 'rdap_enabled'): False,
    ('firewall', 'enabled'): False,
    ('network', 'udp_responses'): False,
    ('deployment', 'egress'): 'disabled',
    ('api', 'bind_address'): '127.0.0.1',
    ('metrics', 'bind_address'): '127.0.0.1',
}


def main(argv):
    if len(argv) != 2:
        print('usage: check_safe_defaults.py <config.toml>', file=sys.stderr)
        return 2
    commands = ([sys.executable, '-m', 'eye_for_an_eye'], ['eye-for-an-eye'])
    payload = ''
    for command in commands:
        try:
            result = subprocess.run([*command, 'config', 'show', '--config', argv[1], '--json'],
                                    capture_output=True, text=True)
        except OSError:
            continue
        if result.returncode == 0 and result.stdout.strip():
            payload = result.stdout
            break
    if not payload:
        print('cannot read the configuration with either entry point', file=sys.stderr)
        return 1
    config = json.loads(payload)['configuration']
    problems = [f'{section}.{key} is {config[section][key]!r}, expected {value!r}'
                for (section, key), value in EXPECTED.items() if config[section][key] != value]
    for line in problems:
        print('UNSAFE: ' + line, file=sys.stderr)
    if problems:
        return 1
    print('safe defaults confirmed: observe only, no firewall change, local only')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
