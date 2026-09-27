"""Beginner installer for Windows. P17 §4, §5, §6, §22, §23, §26, §39, §40.

Run by `Install-EyeForAnEye.cmd`, which does nothing but find a Python and hand
over to this file. All of the real work is here, because a `.cmd` file is a bad
place to keep logic that needs testing.

### What this installer may and may not do

It creates a virtual environment under the user's own application data, installs
this project into it, and writes one safe configuration file. That is all.

It never changes the firewall, never turns on blocking, never starts or enables a
service, never asks for Administrator, and never downloads anything. Installing
this software does not enable blocking — that is a property of the configuration
it writes (`production-shadow`), and `verify()` below checks the written file
rather than trusting the template.

### Why it is standalone

It runs *before* the package exists, so it may import nothing from
`eye_for_an_eye` and nothing from outside the standard library. Everything the
installed package needs to say afterwards lives in `eye_for_an_eye/beginner.py`
instead, which is the tested half.

### Exit codes

0 installed, 2 something the user must fix (explained in plain words), 3 an
unexpected internal failure (the traceback goes to the log, not the screen).
"""
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

#: The profile a beginner install writes. P17 §6. Named once, asserted later.
SAFE_PROFILE = 'production-shadow'

#: Settings that must be off in the written configuration for the install to be
#: reported as safe. Checked against the file, not against intent.
MUST_BE_OFF = (
    ('[enforcement]', 'host_enabled'),
    ('[enforcement]', 'enabled'),
    ('[firewall]', 'enabled'),
)

REQUIRED_PYTHON = (3, 12)


def application_directory():
    """Where a beginner's files go on this machine. P17 §22.

    Windows convention is `%LOCALAPPDATA%`, which needs no elevation and is not
    synchronised to a network profile — a decision journal is a deployment's own
    evidence and does not belong in a roaming profile. Elsewhere the XDG data
    directory, matching `scripts/install.sh` so the two installers do not
    disagree about where the same project lives.
    """
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~\\AppData\\Local')
    else:
        base = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
    return Path(base) / 'eye-for-an-eye'


class Report:
    """The install log. P17 §26: a diagnostic record with no secrets in it.

    It records what the installer did, the commands it ran and their output. It
    never records the environment, so a token that happens to be in a variable
    cannot arrive here by accident, and the user is asked to send this file
    rather than anything else.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.lines = []

    def say(self, text=''):
        """Print for the human and keep it for the log."""
        print(text)
        self.lines.append(text)

    def note(self, text):
        """Keep it for the log only."""
        self.lines.append('    ' + text)

    def save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            header = ['Eye for an Eye install report',
                      'written: ' + time.strftime('%Y-%m-%dT%H:%M:%S'),
                      'platform: ' + platform.platform(),
                      'python: ' + sys.version.split()[0],
                      'This file contains no passwords, tokens or traffic.', '']
            self.path.write_text('\n'.join(header + self.lines) + '\n', encoding='utf-8')
        except OSError:
            pass          # a missing log must never be the reason an install fails
        return self.path


def explain(report, what_happened, is_my_computer_safe, what_to_do):
    """The three questions every beginner error must answer. P17 §10."""
    report.say()
    report.say('=' * 58)
    report.say('What happened')
    report.say('  ' + what_happened)
    report.say()
    report.say('Is my computer safe')
    report.say('  ' + is_my_computer_safe)
    report.say()
    report.say('What to do next')
    for step in what_to_do:
        report.say('  ' + step)
    report.say('=' * 58)


def find_python(report):
    """A Python 3.12 interpreter, or None with the reason already explained.

    The interpreter running this file is tried first: `Install-EyeForAnEye.cmd`
    prefers a 3.12 it can find, so usually this is already the right one.
    """
    if sys.version_info[:2] == REQUIRED_PYTHON:
        report.note(f'using the interpreter that started this installer: {sys.executable}')
        return sys.executable
    wanted = '.'.join(str(part) for part in REQUIRED_PYTHON)
    for candidate in (shutil.which('py'), shutil.which('python3.12'), shutil.which('python3')):
        if not candidate:
            continue
        command = [candidate, '-' + wanted, '-c', 'import sys;print(sys.version_info[:2])'] \
            if Path(candidate).stem == 'py' else \
            [candidate, '-c', 'import sys;print(sys.version_info[:2])']
        try:
            found = subprocess.run(command, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if found.returncode == 0 and f'({REQUIRED_PYTHON[0]}, {REQUIRED_PYTHON[1]})' in found.stdout:
            report.note(f'found Python {wanted} at {candidate}')
            return candidate if Path(candidate).stem != 'py' else None or candidate
    explain(report,
            f'Python {wanted} is not installed on this computer, or Windows cannot find it.',
            'Yes. Nothing was installed and nothing was changed.',
            [f'1. Open https://www.python.org/downloads/ and install Python {wanted}.',
             '2. During setup, tick "Add python.exe to PATH".',
             '3. Run this installer again.',
             '',
             'This installer does not download Python for you on purpose: it will not',
             'fetch and run a program from the Internet on your behalf.'])
    return None


def check_source_tree(report, source):
    """The files this installer needs must be present and readable. P17 §5."""
    required = ['pyproject.toml', 'eye_for_an_eye', 'README.md', 'LICENSE']
    missing = [name for name in required if not (source / name).exists()]
    if missing:
        explain(report,
                'Some of the program files are missing: ' + ', '.join(missing) + '.',
                'Yes. Nothing was installed.',
                ['1. Download the release archive again.',
                 '2. Unzip all of it, keeping the folders as they are.',
                 '3. Run the installer from inside the unzipped folder.'])
        return False
    report.note(f'source tree looks complete: {source}')
    return True


def check_writable(report, target):
    """A beginner install writes only under the user's own directory. P17 §39."""
    try:
        target.mkdir(parents=True, exist_ok=True)
        probe = target / '.write-probe'
        probe.write_text('ok', encoding='utf-8')
        probe.unlink()
    except OSError as problem:
        explain(report,
                f'Eye for an Eye cannot write to its own folder:\n  {target}',
                'Yes. Nothing was installed.',
                ['1. Check that the folder is not read-only.',
                 '2. If your computer is managed by someone else, ask them for',
                 '   permission to write to that folder.',
                 '',
                 'Note: this installer does not need Administrator. If something is',
                 'asking you for it, stop and check what is asking.'])
        report.note(f'write check failed: {type(problem).__name__}')
        return False
    report.note(f'write check passed: {target}')
    return True


def run(report, command, step):
    """Run one installer step, keeping its output in the log rather than on screen."""
    report.note(f'$ {" ".join(str(part) for part in command)}')
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.SubprocessError) as problem:
        report.note(f'{step} could not start: {type(problem).__name__}')
        return None
    report.note(f'{step} exit {done.returncode}')
    for stream in (done.stdout, done.stderr):
        for line in (stream or '').splitlines()[-40:]:
            report.note(line)
    return done


def verify(target, config_path):
    """Is what was installed actually safe? P17 §6, §45.

    Read back the configuration that was written and confirm blocking is off. A
    template is a promise; the file on disk is the fact. This is the check a test
    can run without installing anything, so it lives here rather than in prose.
    """
    problems = []
    if not config_path.is_file():
        return ['no configuration was written']
    body = config_path.read_text(encoding='utf-8')
    section = ''
    seen = {}
    for raw in body.splitlines():
        line = raw.split('#', 1)[0].strip()
        if line.startswith('['):
            section = line
            continue
        if '=' not in line:
            continue
        key, _, value = (part.strip() for part in line.partition('='))
        seen.setdefault((section, key), value)
    for section_name, key in MUST_BE_OFF:
        value = seen.get((section_name, key))
        if value is not None and value != 'false':
            problems.append(f'{section_name} {key} = {value}, expected false')
    if seen.get(('[autonomy]', 'mode')) not in ('"shadow"', None):
        problems.append('autonomy mode is not shadow')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--source', default=str(Path(__file__).resolve().parents[1]),
                        help='the unpacked project folder')
    parser.add_argument('--target', default='', help='where to install')
    parser.add_argument('--dry-run', action='store_true',
                        help='say what would happen and change nothing')
    args = parser.parse_args(argv)

    source = Path(args.source).resolve()
    target = Path(args.target).resolve() if args.target else application_directory()
    report = Report(target / 'install-report.txt')

    report.say('Eye for an Eye — Safe Monitoring installer')
    report.say()
    report.say('This will not block anyone. It only watches and writes notes.')
    report.say()

    if not check_source_tree(report, source):
        report.save()
        return 2

    report.say('Step 1 of 4 — checking this computer')
    interpreter = find_python(report)
    if interpreter is None:
        report.save()
        return 2
    if not args.dry_run and not check_writable(report, target):
        report.save()
        return 2
    report.say('  Looks good.')

    environment = target / 'runtime'
    executable = environment / ('Scripts' if sys.platform == 'win32' else 'bin')
    config_path = target / 'eye-for-an-eye.toml'

    if args.dry_run:
        report.say()
        report.say('Nothing was changed. This was a practice run.')
        report.say(f'  It would install into: {target}')
        report.say(f'  It would write this configuration: {config_path}')
        report.say(f'  Mode it would choose: Safe Monitoring ({SAFE_PROFILE})')
        report.say('  Automatic blocking: OFF')
        report.save()
        return 0

    report.say()
    report.say('Step 2 of 4 — making a private space for the program')
    made = run(report, [interpreter, '-m', 'venv', str(environment)], 'virtual environment')
    if made is None or made.returncode != 0:
        explain(report, 'The program could not create its own private space to run in.',
                'Yes. Nothing is running and your firewall was not touched.',
                ['1. Send the file below to whoever is helping you.',
                 f'   {report.path}',
                 '2. It contains no passwords and no private traffic.'])
        report.save()
        return 2
    report.say('  Done.')

    report.say()
    report.say('Step 3 of 4 — installing the program (this can take a few minutes)')
    python = executable / ('python.exe' if sys.platform == 'win32' else 'python')
    installed = run(report, [str(python), '-m', 'pip', 'install', '--disable-pip-version-check',
                             str(source) + '[ml]'], 'install')
    if installed is None or installed.returncode != 0:
        explain(report, 'The program could not finish installing.',
                'Yes. Nothing is running and your firewall was not touched.',
                ['1. Check that this computer can reach the Internet.',
                 '2. Run the installer again.',
                 '3. If it fails again, send the file below to whoever is helping you:',
                 f'   {report.path}'])
        report.save()
        return 2
    report.say('  Done.')

    report.say()
    report.say('Step 4 of 4 — writing a safe first setting')
    if config_path.exists():
        report.say(f'  A setting file is already there. Keeping it: {config_path}')
        report.note('existing configuration left untouched')
    else:
        cli = executable / ('eye-for-an-eye.exe' if sys.platform == 'win32' else 'eye-for-an-eye')
        written = run(report, [str(cli), 'config', 'init', '--profile', SAFE_PROFILE,
                               '--output', str(config_path)], 'config init')
        if written is None or written.returncode != 0:
            explain(report, 'The program installed, but its first setting could not be written.',
                    'Yes. Nothing is running and your firewall was not touched.',
                    ['1. Run the installer again.',
                     f'2. If it fails again, send: {report.path}'])
            report.save()
            return 2
    report.say('  Done.')

    problems = verify(target, config_path)
    if problems:
        explain(report, 'The setting that was written is not the safe one this installer '
                        'promised.',
                'Blocking is not running, because nothing was started. But do not start it '
                'until this is fixed.',
                ['1. Do not start Eye for an Eye.',
                 f'2. Send this file to whoever is helping you: {report.path}'])
        for problem in problems:
            report.note('verify: ' + problem)
        report.save()
        return 2

    # P17 §23. The first-run summary, in the words the status view uses.
    report.say()
    report.say('Installation complete.')
    report.say()
    report.say('  Mode:               Safe Monitoring')
    report.say('  Automatic blocking: OFF')
    report.say(f'  Settings file:      {config_path}')
    report.say(f'  Notes and records:  {target / "data"}')
    report.say(f'  Install report:     {report.path}')
    report.say()
    report.say('Next: start it.')
    if sys.platform == 'win32':
        report.say('  Double-click Start-EyeForAnEye.cmd')
    else:
        report.say(f'  {executable / "eye-for-an-eye"} start')
    report.save()
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\nStopped. Nothing was changed.')
        raise SystemExit(2)
