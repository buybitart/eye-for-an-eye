"""Verify real directives against systemd; staging only, no host installation/start."""
from pathlib import Path
import shutil
import subprocess
import tempfile


def verify():
    source = Path(__file__).resolve().parents[1]/'deploy/systemd'
    with tempfile.TemporaryDirectory(prefix='e4e-units-') as directory:
        root = Path(directory)
        units = root/'etc/systemd/system'
        units.mkdir(parents=True)
        # A dummy executable satisfies verifier existence checks; it is never run.
        executable = root/'opt/eye-for-an-eye/.venv/bin/eye-for-an-eye'
        executable.parent.mkdir(parents=True)
        executable.write_text('#!/bin/sh\nexit 0\n')
        executable.chmod(0o755)
        for name in ('local-fs.target', 'sysinit.target', 'basic.target', 'shutdown.target', 'multi-user.target'):
            (units/name).write_text('[Unit]\nDescription=Verification dependency stub\nDefaultDependencies=no\n')
        files = []
        for file in source.glob('*.service'):
            shutil.copy2(file, units/file.name)
            (units/file.name).chmod(0o644)
            files.append('/etc/systemd/system/'+file.name)
        result = subprocess.run(['systemd-analyze', 'verify', '--generators=no', '--man=no', '--root='+str(root), *files],
            capture_output=True, text=True, timeout=20)
        print(result.stdout+result.stderr)
        return result.returncode


if __name__ == '__main__':
    raise SystemExit(verify())
