"""Fresh wheel installation outside the checkout; no runtime dependencies or network."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import venv


def check(wheel):
    with tempfile.TemporaryDirectory(prefix='e4e-wheel-') as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True).create(root/'venv')
        binary = root/'venv'/('Scripts' if os.name == 'nt' else 'bin')
        python = binary/('python.exe' if os.name == 'nt' else 'python')
        cli = binary/('eye-for-an-eye.exe' if os.name == 'nt' else 'eye-for-an-eye')
        environment = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHONPATH', 'E4E__', 'EYE_FOR_AN_EYE_SECRET'))}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        def run(args, expected=(0,)):
            result = subprocess.run([str(x) for x in args], cwd=root, env=environment,
                capture_output=True, text=True, timeout=45)
            if result.returncode not in expected:
                raise RuntimeError(f'{args[0]} exited {result.returncode}: {result.stderr[-2000:]}')
            return result.stdout
        run([python, '-m', 'pip', 'install', '--no-index', '--no-deps', wheel])
        location = run([python, '-I', '-c', 'import eye_for_an_eye; print(eye_for_an_eye.__file__)']).strip()
        if not Path(location).is_relative_to(root/'venv'):
            raise RuntimeError('smoke imported the checkout instead of the installed wheel')
        version = run([cli, '--version']).strip()
        run([cli, 'config', 'init', '--json'])
        run([cli, 'config', 'validate', '--config', 'eye-for-an-eye.toml', '--json'])
        run([cli, 'doctor', '--config', 'eye-for-an-eye.toml', '--json'], (0, 7))
        demonstration = json.loads(run([cli, 'demo', '--json']))
        (root/'legacy.toml').write_text('[network]\nport=4321\n', encoding='utf-8')
        compatibility = json.loads(run([cli, 'upgrade', 'check', '--config', 'legacy.toml', '--json']))
        if not compatibility['config_migration_required']:
            raise RuntimeError('legacy configuration migration was not identified')
        run([cli, 'config', 'migrate', '--config', 'legacy.toml', '--output', 'upgraded.toml', '--json'])
        run([cli, 'config', 'validate', '--config', 'upgraded.toml', '--json'])
        return {'schema_version': 1, 'version': version, 'fresh_wheel': True, 'offline_install': True,
                'demo': demonstration['status'], 'config_upgrade': 'complete'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('wheel', type=lambda value: Path(value).resolve())
    print(json.dumps(check(parser.parse_args().wheel)))
