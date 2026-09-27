"""First-run setup and model status.

Safe by design: setup writes only files the operator asked for. It never changes
the firewall, never enables active probes and never opens a public port.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys

from .config import load_config
from .configuration import initialize
from .decision.features import SCHEMA_VERSION

#: The profiles `setup` offers. P18 §34, §36, §107.
#:
#: `production-shadow` is here because it is what the safe first install means:
#: the full analysis path running, deciding, writing evidence, and enforcing
#: nothing. The `website` profile leaves `[autonomy]` out entirely, so a machine
#: set up with it decides nothing at all — which P18 found was the difference
#: between what a Linux beginner got from `scripts/install.sh` and what a Windows
#: beginner got from `scripts/install_windows.py`.
#:
#: `production-autonomous` is deliberately absent. It stays behind
#: `eye-for-an-eye config init`, which is the expert door, because §36 keeps
#: autonomous enforcement out of the first flow.
PROFILES = ('production-shadow', 'website', 'sensor', 'honeypot', 'lab')
PRIVILEGES = (
    'The service itself runs as a normal user.',
    'Live packet capture needs a separate helper with CAP_NET_RAW (Linux) or root.',
    'Firewall commands need root. They are separate and always manual.',
)


def interfaces():
    """Names only. Setup never enables capture and never opens a socket."""
    try:
        return sorted(name for _, name in socket.if_nameindex())
    except (OSError, AttributeError):
        return []


def prepare_directories(config):
    """Create the directories the operator's own configuration points at."""
    rows = []
    for name, value in (('storage', config.storage.path if config.storage.enabled else ''),
                        ('status_file', config.runtime.status_file),
                        ('log_file', config.logging.file)):
        if not value:
            continue
        parent = Path(value).resolve().parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        rows.append({'name': name, 'directory': str(parent),
                     'exists': parent.is_dir(), 'writable': parent.is_dir() and os.access(parent, os.W_OK)})
    return rows


def create_storage(config):
    """Create the empty local database once, so the first doctor run is clean."""
    if not config.storage.enabled:
        return {'created': False, 'reason': 'storage is disabled in the configuration'}
    path = Path(config.storage.path)
    if path.exists():
        return {'created': False, 'reason': 'database already exists'}
    from .storage.sqlite import SQLiteStore
    store = SQLiteStore(config.storage)
    store.open()
    store.close()
    return {'created': True, 'reason': 'empty local database created'}


def capabilities():
    return {'platform': sys.platform,
            'running_as_root': bool(hasattr(os, 'geteuid') and os.geteuid() == 0),
            'capture_library': importlib.util.find_spec('scapy') is not None,
            'onnx_runtime': importlib.util.find_spec('onnxruntime') is not None}


def model_state(config):
    """Report the local model without loading a session."""
    state = {'schema_version': 1, 'model': 'none', 'format': 'ONNX',
             'feature_schema': SCHEMA_VERSION, 'status': 'Not configured',
             'mode': config.decision.mode.capitalize() if config.decision.enabled else 'Off',
             'required': config.ml.required}
    if not config.ml.enabled:
        state['status'] = 'Disabled'
        state['reason'] = 'ml.enabled is false; the maths engine works alone'
        return state
    if not (config.ml.model_path and config.ml.manifest_path):
        state['reason'] = 'no model file in the configuration; the maths engine works alone'
        return state
    from .decision.onnx_model import read_artifacts
    try:
        manifest, _ = read_artifacts(config.ml)
    except (OSError, ValueError) as exc:
        state['status'] = 'Unavailable'
        state['reason'] = 'model file check failed: ' + type(exc).__name__
        return state
    # The schema this artifact was fitted on, which is what an operator needs in
    # order to know which columns it actually sees. Leaving the build's own
    # schema here would say "2" about a model trained on eighteen columns.
    state.update(model=manifest['model_version'], status='Healthy',
                 feature_schema=manifest.get('feature_schema_version', SCHEMA_VERSION),
                 dataset_version=manifest.get('training_dataset_version', 'unknown'),
                 reason='file hash and manifest match; the session starts with the service')
    return state


def summary(config, config_path, *, created, secret_created, profile):
    """The values in this summary are read back from the written file, not assumed."""
    database = create_storage(config)
    api = 'Disabled'
    if config.api.enabled:
        api = 'Local only' if config.api.bind_address in ('127.0.0.1', '::1') else 'OPEN: ' + config.api.bind_address
    storage = 'Off'
    if config.storage.enabled:
        parent = Path(config.storage.path).resolve().parent
        storage = 'OK' if parent.is_dir() and os.access(parent, os.W_OK) else 'Not writable'
    model = model_state(config)
    ai = {'Healthy': 'ONNX local', 'Not configured': 'Maths only (no model file yet)',
          'Disabled': 'Off', 'Unavailable': 'Model file problem'}[model['status']]
    return {'schema_version': 1, 'status': 'created' if created else 'existing',
            'config': str(config_path), 'profile': profile, 'database': database,
            'deployment_profile': config.deployment.profile,
            'persistent_secret_created': secret_created,
            'mode': config.decision.mode.upper() if config.decision.enabled else 'OFF',
            'ai': ai, 'model_status': model['status'],
            'automatic_block': 'ON' if config.enforcement.enabled else 'OFF',
            'api': api, 'storage': storage,
            'active_probes': 'ON' if config.active_probes.enabled else 'OFF',
            'firewall_changed': False,
            'directories': prepare_directories(config),
            'capabilities': capabilities(), 'interfaces': interfaces(),
            'privileges': list(PRIVILEGES),
            'next': ['eye-for-an-eye status']}


def print_summary(result):
    print('Eye for an Eye is installed.' if result['status'] == 'created'
          else 'Eye for an Eye is already set up.')
    print()
    print('Mode: ' + result['mode'])
    print('AI: ' + result['ai'])
    print('Automatic block: ' + result['automatic_block'])
    print('API: ' + result['api'])
    print('Storage: ' + result['storage'])
    print()
    print('Config file: ' + result['config'])
    for row in result['directories']:
        if not row['writable']:
            print('Warning: cannot write in ' + row['directory'] + ' (' + row['name'] + ')')
    if result['api'].startswith('OPEN'):
        print('Warning: the API is not local only. Protect it before you start the service.')
    print()
    print('Privileges:')
    for line in result['privileges']:
        print('  ' + line)
    print()
    print('Next:')
    print()
    print('eye-for-an-eye status')


def _resolve(path, *, required):
    if path:
        return path
    default = Path('eye-for-an-eye.toml')
    if default.is_file():
        return str(default)
    if required:
        raise ValueError('No configuration found. Run: eye-for-an-eye setup')
    return None


# ---------------------------------------------------------------------------
# Choosing what to watch. P18 §28-§31.
#
# Until P18 the beginner path for this step was "open the settings file in a
# text editor and put the path between the quotes", which §28 forbids outright
# and which asks a person who was promised they need not know TOML to edit TOML
# correctly on their first attempt.
# ---------------------------------------------------------------------------

#: The three sources a beginner can be offered, in the words the question uses.
WATCH_CHOICES = ('website-log', 'network', 'demo')

#: Where a web server's access log commonly is. Suggestions only — §30 forbids
#: choosing one silently, and only paths that exist on this machine are shown.
#:
#: `eye-for-an-eye.log` is first deliberately. The reader in
#: `eye_for_an_eye/web/nginx.py` parses **JSON** lines, so a default nginx
#: `access.log` in `combined` format yields nothing at all: every line is counted
#: as a parse error and dropped. The file that works is the one the `log_format`
#: from `eye-for-an-eye web log-format` writes.
LOG_SUGGESTIONS = ('/var/log/nginx/eye-for-an-eye.log',
                   '/var/log/nginx/access.log',
                   '/var/log/apache2/access.log',
                   '/var/log/httpd/access_log')


def log_suggestions():
    """The suggestions that actually exist here, in order."""
    return tuple(path for path in LOG_SUGGESTIONS if Path(path).is_file())


def access_log_problem(path):
    """Why this file cannot be used as an access log, in plain words, or ''.

    Reads at most one line. An empty file is accepted: a log created a minute ago
    by following `eye-for-an-eye web log-format` is empty and correct, and
    refusing it would send the operator back to fix something that is right.
    """
    target = Path(path)
    if not target.exists():
        return ('There is no file at that path.\n'
                'Check the spelling, or ask your web server where it writes its\n'
                'visitor file.')
    if target.is_dir():
        return 'That is a folder, not a file. Eye for an Eye needs the file itself.'
    try:
        with target.open('rb') as stream:
            first = b''
            for _ in range(20):
                line = stream.readline()
                if not line:
                    break
                if line.strip():
                    first = line.strip()
                    break
    except OSError:
        return ('Eye for an Eye is not allowed to read that file.\n'
                'The account that runs Eye for an Eye needs permission to read it.\n'
                'On many systems that means adding that account to the group that\n'
                'owns the log directory.')
    if not first:
        return ''                     # empty, and that is fine
    try:
        record = json.loads(first.decode('utf-8', 'replace'))
    except ValueError:
        return ('That file is not in the format Eye for an Eye reads.\n'
                'It reads one JSON line per visit. Your web server is writing\n'
                'something else, so every line would be thrown away.\n'
                '\n'
                'To fix it, run this and follow what it prints:\n'
                '  eye-for-an-eye web log-format\n'
                '\n'
                'Then point Eye for an Eye at the new file that creates.')
    if not isinstance(record, dict) or 'remote_addr' not in record:
        return ('That file has JSON lines, but not the ones Eye for an Eye needs.\n'
                'The line it read has no "remote_addr" field.\n'
                '\n'
                'Run this and compare it with your web server settings:\n'
                '  eye-for-an-eye web log-format')
    return ''


def set_access_log(config_path, log_path):
    """Write `web.access_log_path` into an existing configuration, and prove it.

    The written file is loaded back and validated before this returns, and the
    original is restored if the value did not arrive. An edit nobody reads back
    is an edit that might not have happened — the lesson `verify()` in
    `scripts/build_prod.py` was taught in P16, applied to a configuration.
    """
    target = Path(config_path)
    original = target.read_text(encoding='utf-8')
    marker = 'access_log_path = '
    lines = original.splitlines(keepends=True)
    hits = [index for index, line in enumerate(lines) if line.lstrip().startswith(marker)]
    if len(hits) != 1:
        raise ValueError(f'expected exactly one access_log_path setting in {target}, '
                         f'found {len(hits)}; edit the file by hand and see '
                         f'docs/WEB_PROTECTION.md')
    index = hits[0]
    indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
    ending = '\n' if lines[index].endswith('\n') else ''
    lines[index] = indent + marker + json.dumps(str(log_path), ensure_ascii=True) + ending

    mode = target.stat().st_mode & 0o7777
    scratch = target.with_name(target.name + '.p18-setup')
    try:
        scratch.write_text(''.join(lines), encoding='utf-8')
        os.chmod(scratch, mode)
        os.replace(scratch, target)
        written = load_config(str(target), require_version=True)
        written.validate()
        if written.web.access_log_path != str(log_path):
            raise ValueError('the configuration did not keep the path that was written')
        if not written.web.enabled:
            raise ValueError('web analysis is switched off in this configuration; '
                             'see docs/WEB_PROTECTION.md')
    except BaseException:
        target.write_text(original, encoding='utf-8')
        os.chmod(target, mode)
        scratch.unlink(missing_ok=True)
        raise
    return {'access_log_path': str(log_path), 'config': str(target)}


def capture_readiness():
    """Whether the network-sensor answer can honestly be offered here. §31.

    Live capture refuses on any non-Linux platform, and on Linux it needs a
    separate helper holding CAP_NET_RAW that this command does not install and
    must not pretend to.
    """
    if sys.platform != 'linux':
        return (False, 'Watching network packets works only on Linux. '
                       'Use a website log instead.')
    return (True, 'Watching network packets also needs a separate helper program '
                  'with permission to read from the network card. '
                  'See docs/PRIVILEGES.md.')


def _ask(prompt, stream_in, stream_out):
    print(prompt, file=stream_out)
    stream_out.flush()
    answer = stream_in.readline()
    if not answer:
        raise EOFError('no answer')
    return answer.strip()


def choose_watch(stream_in=None, stream_out=None):
    """§29's first question, asked with only the answers this build supports."""
    stream_in = stream_in or sys.stdin
    stream_out = stream_out or sys.stdout
    capture_ok, capture_note = capture_readiness()
    while True:
        print('', file=stream_out)
        print('What do you want Eye for an Eye to watch?', file=stream_out)
        print('', file=stream_out)
        print('  1. A website log   — the file your web server writes about visitors',
              file=stream_out)
        print('  2. Network traffic — ' +
              ('Linux only, needs an extra helper program' if capture_ok
               else 'not available on this computer'), file=stream_out)
        print('  3. Nothing yet     — just try the demo first', file=stream_out)
        print('', file=stream_out)
        answer = _ask('Type 1, 2 or 3 and press Enter:', stream_in, stream_out)
        if answer == '1':
            return 'website-log'
        if answer == '2':
            if not capture_ok:
                print('', file=stream_out)
                print(capture_note, file=stream_out)
                continue
            return 'network'
        if answer == '3':
            return 'demo'
        print('', file=stream_out)
        print('Please type 1, 2 or 3.', file=stream_out)


def choose_access_log(stream_in=None, stream_out=None):
    """Ask for the access log, offering what exists as suggestions. §30."""
    stream_in = stream_in or sys.stdin
    stream_out = stream_out or sys.stdout
    found = log_suggestions()
    while True:
        print('', file=stream_out)
        print('Where does your web server write its visitor file?', file=stream_out)
        if found:
            print('', file=stream_out)
            print('These exist on this computer:', file=stream_out)
            for path in found:
                print('  ' + path, file=stream_out)
            print('', file=stream_out)
            print('Eye for an Eye will not pick one for you.', file=stream_out)
        print('', file=stream_out)
        answer = _ask('Type the full path and press Enter (or type q to skip):',
                      stream_in, stream_out)
        if answer.lower() in ('q', 'quit', ''):
            return ''
        problem = access_log_problem(answer)
        if not problem:
            return answer
        print('', file=stream_out)
        print('That will not work yet.', file=stream_out)
        print('', file=stream_out)
        for line in problem.splitlines():
            print('  ' + line, file=stream_out)


def choose_interface(stream_in=None, stream_out=None):
    """Ask which network connection to watch. §31. Nothing is probed or sent."""
    stream_in = stream_in or sys.stdin
    stream_out = stream_out or sys.stdout
    available = interfaces()
    print('', file=stream_out)
    print('This is the network connection Eye for an Eye will watch.', file=stream_out)
    if not available:
        print('', file=stream_out)
        print('No network connections could be listed on this computer.', file=stream_out)
        return ''
    print('', file=stream_out)
    for name in available:
        print('  ' + name, file=stream_out)
    while True:
        print('', file=stream_out)
        answer = _ask('Type one name and press Enter (or type q to skip):',
                      stream_in, stream_out)
        if answer.lower() in ('q', 'quit', ''):
            return ''
        if answer in available:
            return answer
        print('', file=stream_out)
        print('That is not one of the names above.', file=stream_out)


def default_setup_config():
    """Where `setup` writes when nothing said otherwise. P18.

    Four rules, in order:

    1. `--config` — handled by the caller.
    2. A configuration already in the current directory. An operator editing a
       deployment in place gets the file that is in front of them.
    3. The configuration an install receipt names, which is where
       `scripts/install.sh` put it.
    4. Running as root on Linux: `/etc/eye-for-an-eye/eye-for-an-eye.toml`, the
       conventional place for a system-wide configuration, and what the Debian
       package's own `README.Debian` tells an administrator to use.
    5. Otherwise the per-user location the beginner commands read.

    The last rule is the one that matters, and it is what the current directory
    used to be. A configuration written somewhere `status`, `check-install` and
    `doctor` never look is the exact defect P18 exists to fix, and typing
    `eye-for-an-eye setup` in a home directory after installing the Debian
    package — which writes no receipt, because it owns no configuration — landed
    squarely in it.

    The chosen path is printed either way, so nothing here is silent.
    """
    here = Path('eye-for-an-eye.toml')
    if here.is_file():
        return str(here)
    from .beginner import receipt, application_directory
    recorded = receipt().get('config')
    if recorded:
        return recorded
    if sys.platform.startswith('linux') and hasattr(os, 'geteuid') and os.geteuid() == 0:
        return '/etc/eye-for-an-eye/eye-for-an-eye.toml'
    return str(application_directory() / 'data' / 'eye-for-an-eye.toml')


def setup(argv, *, debug=False):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye setup',
        description='Prepare a safe first configuration. Nothing is blocked and no firewall rule is changed.')
    # P18 §34. The default was `website`, which has no [autonomy] section, so a
    # machine set up with it decides nothing. `scripts/install.sh` passes the
    # profile explicitly and was therefore unaffected; the Debian package does not,
    # and running `setup` after installing it produced the weaker configuration.
    parser.add_argument('--profile', choices=PROFILES, default='production-shadow',
                        help='production-shadow: watch, decide, record, block nothing '
                             '(default)')
    parser.add_argument('--config', help='configuration file to create or reuse')
    parser.add_argument('--json', action='store_true')
    # P18 §28-§31. `--watch` is the non-interactive form of the first question,
    # so the guided path and the scripted path go through one implementation.
    parser.add_argument('--watch', choices=WATCH_CHOICES,
                        help='what to watch: website-log, network, or demo (nothing yet)')
    parser.add_argument('--access-log', help='the access log to read, with --watch website-log')
    parser.add_argument('--interface', help='the network connection to watch, with --watch network')
    parser.add_argument('--no-questions', action='store_true',
                        help='never ask anything; write the configuration and stop')
    parser.add_argument('--advanced', action='store_true',
                        help='print the full technical summary even when asked questions')
    args = parser.parse_args(argv)
    from .operator_cli import failure
    try:
        target = Path(args.config or default_setup_config()).absolute()
        target.parent.mkdir(parents=True, exist_ok=True)
        created, secret_created = False, False
        if not target.exists():
            record = initialize(str(target), args.profile)
            created, secret_created = True, record['persistent_secret_created']
        config = load_config(str(target), require_version=True)

        # Ask only when there is somebody to answer. A pipe, a service unit and
        # `--json` all take the quiet path, which is exactly what setup did
        # before P18 — the questions are an addition, never a new requirement.
        guided = (not args.no_questions and not args.json and args.watch is None
                  and sys.stdin.isatty() and sys.stdout.isatty())
        watch, chosen = args.watch, {}
        if guided:
            watch = choose_watch()
        if watch == 'website-log':
            log_path = args.access_log
            if log_path:
                problem = access_log_problem(log_path)
                if problem:
                    raise ValueError('cannot use that access log: ' + problem)
            elif guided:
                log_path = choose_access_log()
            if log_path:
                chosen = set_access_log(target, log_path)
                config = load_config(str(target), require_version=True)
        elif watch == 'network':
            ready, note = capture_readiness()
            if not ready:
                raise ValueError(note)
            name = args.interface or (choose_interface() if guided else '')
            # Setup records the operator's answer and stops there. Turning on
            # capture means a helper this command does not install and a socket
            # it must not invent, so it says what remains instead of writing a
            # configuration that would refuse to start.
            chosen = {'interface': name, 'capture': 'NEEDS THE CAPTURE HELPER'}

        result = summary(config, target, created=created, secret_created=secret_created,
                         profile=args.profile)
        result['watch'] = watch or ''
        result['chosen'] = chosen
        if args.json:
            print(json.dumps(result, ensure_ascii=True))
        elif guided and not args.advanced:
            # Somebody answered questions at a terminal, so the answer to those
            # questions comes first and alone. The expert summary — API binding,
            # storage state, the privilege notes — is the right output for
            # `scripts/install.sh` and the wrong end to an interview.
            print_beginner_summary(result)
            _print_watch_outcome(watch, chosen, target)
        else:
            print_summary(result)
            _print_watch_outcome(watch, chosen, target)
        return 0
    except EOFError:
        print('No answer was given, so nothing was changed.', file=sys.stderr)
        print('Run it again, or use: eye-for-an-eye setup --watch website-log '
              '--access-log <path>', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('', file=sys.stderr)
        print('Stopped. Nothing was changed.', file=sys.stderr)
        return 130
    except (OSError, ValueError, TypeError, RuntimeError, ImportError) as exc:
        return failure(exc, machine=args.json, debug=debug)


def print_beginner_summary(result):
    """Four lines and the file. What a person who answered questions needs."""
    print()
    print('Eye for an Eye is set up.' if result['status'] == 'created'
          else 'Eye for an Eye was already set up.')
    print()
    print('  Mode:               ' +
          ('Safe Monitoring' if result['automatic_block'] == 'OFF' else 'BLOCKING ENABLED'))
    print('  Automatic blocking: ' + result['automatic_block'])
    print('  Settings file:      ' + result['config'])
    for row in result['directories']:
        if not row['writable']:
            print('  Warning: cannot write in ' + row['directory'])
    if result['api'].startswith('OPEN'):
        print('  Warning: the API is not local only. Protect it before you start.')
    print()
    print('For the technical detail, run: eye-for-an-eye doctor')


def _print_watch_outcome(watch, chosen, target):
    """What the traffic-source answer actually achieved, in short words."""
    if not watch:
        return
    print()
    if watch == 'website-log' and chosen.get('access_log_path'):
        print('Eye for an Eye will watch:')
        print('  ' + chosen['access_log_path'])
        print()
        print('Start it when you are ready:')
        print('  eye-for-an-eye start')
        return
    if watch == 'website-log':
        print('No website log was chosen, so Eye for an Eye still has nothing to')
        print('watch. Run this again when you know the path:')
        print('  eye-for-an-eye setup --watch website-log --access-log <path>')
        return
    if watch == 'network':
        print('Watching network packets needs one more thing this command does not')
        print('install: a helper program allowed to read from the network card.')
        if chosen.get('interface'):
            print()
            print('The connection you chose: ' + chosen['interface'])
        print()
        print('Read docs/PRIVILEGES.md, then docs/INSTALL.md. Nothing was started.')
        return
    print('Nothing is being watched yet. Try the demo — it needs no website:')
    print('  eye-for-an-eye easy demo')


def model(argv, *, debug=False):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye model',
        description='Report the local risk model. Never downloads and never trains.')
    parser.add_argument('action', choices=('status',))
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure
    try:
        config = load_config(_resolve(args.config, required=False))
        state = model_state(config)
        if args.json:
            print(json.dumps(state, ensure_ascii=True))
        else:
            print('Model: ' + state['model'])
            print('Format: ' + state['format'])
            print('Feature schema: ' + str(state['feature_schema']))
            print('Status: ' + state['status'])
            print('Mode: ' + state['mode'])
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, ImportError) as exc:
        return failure(exc, machine=args.json, debug=debug)
