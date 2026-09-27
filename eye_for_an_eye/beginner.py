"""The beginner layer: start, stop, status, check, uninstall. P17 §7-§11, §24-§28.

A layer above the expert commands, not beside them. Every decision this module
reports is taken by code that already existed: `load_config().validate()` decides
whether a configuration is valid, `operations.doctor` decides what is healthy,
`autonomy.runtime` decides whether enforcement may start. This file chooses which
of those to call and how to say the answer in short words. It decides nothing
itself, which is the only way a friendly layer can be trusted: there is no second
opinion for it to hold.

### What it may not do

It may not lower a gate to make a message nicer. When the autonomous profile
refuses to validate because no management network is set, the beginner layer
prints a sentence a person can act on and returns the same refusal. P17 §21.

### What "watching" means, honestly

Two traffic sources exist and they are not equally available:

* **A web server's access log.** Pure file reading, no platform guard anywhere in
  `eye_for_an_eye/web/`, so it works on Windows and Linux alike. This is the
  beginner path.
* **Packet capture.** `eye_for_an_eye/network/capture.py` refuses on any
  non-Linux platform — *live analysis requires the Linux capture-helper IPC* —
  and needs a separate helper holding `CAP_NET_RAW`. Not a beginner path, and
  this module says so rather than implying parity.

Automatic blocking is Linux-only for the same kind of reason: the enforcement
backends refuse on other platforms. A Windows beginner cannot turn on blocking by
accident because the platform cannot carry it out, and that is stated rather than
relied upon.
"""
from pathlib import Path
import json
import os
import sys
import time

#: The profile the beginner path uses. The same constant the installer uses; if
#: these two ever disagree, `tests/test_p17_beginner.py` fails.
SAFE_PROFILE = 'production-shadow'

#: How long between reads of the access log while watching. Not a detection
#: parameter: the sensor's own windows and limits are untouched by it.
WATCH_SECONDS = 5.0

OK, NEEDS_SETUP, NOT_RUNNING, ERROR = 'OK', 'NEEDS SETUP', 'NOT RUNNING', 'ERROR'


def application_directory():
    """Where a beginner's files live. Must match `scripts/install_windows.py`."""
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~\\AppData\\Local')
    else:
        base = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
    return Path(base) / 'eye-for-an-eye'


#: The file `scripts/install.sh` writes to record what it installed and where.
#: P18 §53. It is a pointer, not payload: nothing depends on it existing, and a
#: damaged one degrades to the candidate search below.
RECEIPT_NAME = 'install-receipt.json'


def receipt_candidates():
    """Where an install receipt may be, most specific first.

    A `--prefix` install is deliberately not guessed. Its receipt sits inside
    that prefix, the installer prints the path, and `--config` names the file.
    Guessing at arbitrary prefixes would be a search that sometimes finds
    somebody else's installation.
    """
    override = os.environ.get('EYE_FOR_AN_EYE_RECEIPT')
    if override:
        return (Path(override),)
    found = [application_directory() / RECEIPT_NAME]
    if sys.platform != 'win32':
        found.append(Path('/opt/eye-for-an-eye') / RECEIPT_NAME)
    return tuple(found)


def receipt():
    """What the installer recorded, or an empty dict.

    Never raises. A beginner command must not fail because a receipt is absent,
    truncated or from a future version — it must fall back to looking.
    """
    for path in receipt_candidates():
        try:
            body = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if isinstance(body, dict) and body.get('schema_version') == 1:
            body['receipt_path'] = str(path)
            return body
    return {}


def config_candidates():
    """Every place one of this project's own installers puts a configuration.

    This list exists because P18 ran the documented Linux flow and found the two
    halves disagreeing. `scripts/install.sh` writes
    `<prefix>/data/eye-for-an-eye.toml`; this module looked only at
    `<prefix>/eye-for-an-eye.toml`, which is where `scripts/install_windows.py`
    writes it. So a **successful** Linux install was followed by
    `check-install` reporting *a settings file exists — NO*, `easy status`
    reporting NEEDS SETUP with the wrong reason, and `start` telling a Linux
    user to double-click a Windows `.cmd` file.

    The receipt is the fix. This list is what keeps an install that predates the
    receipt — or a plain `pip install` followed by `setup` — working anyway.
    """
    found = []
    recorded = receipt().get('config')
    if recorded:
        found.append(Path(recorded))
    base = application_directory()
    # The platform's own installer location first, so that a message about a
    # file that does not exist yet still names the place it would go.
    if sys.platform == 'win32':
        found += [base / 'eye-for-an-eye.toml', base / 'data' / 'eye-for-an-eye.toml']
    else:
        found += [base / 'data' / 'eye-for-an-eye.toml', base / 'eye-for-an-eye.toml',
                  Path('/etc/eye-for-an-eye/eye-for-an-eye.toml'),
                  Path('/var/lib/eye-for-an-eye/eye-for-an-eye.toml')]
    seen, unique = set(), []
    for path in found:
        if str(path) not in seen:
            seen.add(str(path))
            unique.append(path)
    return tuple(unique)


def default_config_path():
    """The configuration this computer actually has, or where one would go.

    The first candidate that exists, and otherwise the first candidate — so an
    error message names a plausible location instead of nothing.
    """
    candidates = config_candidates()
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def installed_program():
    """The directory holding the installed program, if one can be established.

    Returns (path, source) where source says how it was established, or
    (None, '') when it cannot be. Guessing is not allowed here: `uninstall`
    deletes what this returns.
    """
    recorded = receipt().get('program')
    if recorded and Path(recorded).is_dir():
        return Path(recorded), 'the install receipt'
    base = application_directory()
    for name, installer in (('runtime', 'scripts/install_windows.py'),
                            ('venv', 'scripts/install.sh')):
        if (base / name).is_dir():
            return base / name, installer
    return None, ''


def running_marker():
    return application_directory() / 'watching.json'


def stop_request():
    """The file `stop` writes and the watching loop looks for. P17W §12.

    Stopping is **cooperative**: `stop` asks, and the watching process notices and
    leaves. No signal is sent and no process id is ever acted on.

    That is a deliberate choice against the obvious design. Reading a pid from a
    file and signalling it is one PID reuse away from terminating something that
    has nothing to do with this project — and on Windows there is no cheap,
    dependency-free way to prove a pid is still the process you started. A
    verified kill would need either a new dependency or a `tasklist` parse that
    establishes only "some python", which is not the same as "mine". Nothing is
    worth a beginner button that can stop the wrong program, so only our own
    process ever acts on this file, and the worst case is that the request is
    ignored because nothing is listening.

    The cost is honest and stated in the message: stopping takes up to one poll
    interval.
    """
    return application_directory() / 'stop-requested'


# ---------------------------------------------------------------------------
# Saying what went wrong, in the three parts a beginner needs. P17 §10, §11.
# ---------------------------------------------------------------------------

#: Known failures, matched on a distinctive fragment of the real message. The
#: fragments are quoted from the code that raises them, so a reworded error stops
#: matching and falls through to the honest generic answer rather than to a
#: confident wrong one.
KNOWN_PROBLEMS = (
    ('sensor requires capture.pcap_path or capture.ipc_socket', {
        'what': 'Eye for an Eye does not know where to watch yet.',
        'safe': 'Yes. Nothing is running and nothing was blocked.',
        'do': ['Pick one of these two:',
               '  1. A website log  — if you run a web server, point Eye for an Eye',
               '     at the file it writes about visitors.',
               '  2. A network sensor — Linux only, and needs an extra helper program.',
               '',
               'The website log is the easy one. See docs/BEGINNER_GUIDE.md, Step 3.']}),
    ('requires at least one protected network', {
        'what': 'Automatic blocking will not start, on purpose.',
        'safe': 'Yes. Blocking did not start, so nothing can be blocked.',
        'do': ['Eye for an Eye does not know which addresses it must never block.',
               'Without that, it could lock you out of your own computer.',
               '',
               'See what is still missing:',
               '  eye-for-an-eye autonomy readiness',
               '',
               'Then read docs/AUTONOMOUS_MODE.md, which shows the exact settings',
               'to add. Automatic blocking is Linux only.',
               '',
               'This is a safety rule. It cannot be skipped.']}),
    ('live analysis requires the Linux capture-helper IPC', {
        'what': 'Watching network packets does not work on this kind of computer.',
        'safe': 'Yes. Nothing is running.',
        'do': ['Packet watching needs Linux and an extra helper program.',
               '',
               'On Windows, use a website log instead. It works the same way for you',
               'and needs no extra program. See docs/BEGINNER_GUIDE.md, Step 3.']}),
    ('configuration destination already exists', {
        'what': 'There is already a settings file, so a new one was not written.',
        'safe': 'Yes. Your old settings were not touched.',
        'do': ['This is usually fine — it means Eye for an Eye is already set up.',
               'Run the check to see how it is doing:',
               '  eye-for-an-eye check-install']}),
    ('artifact ownership/write permissions rejected', {
        'what': 'A learning file could be changed by another account on this computer, '
                'so Eye for an Eye refused to use it.',
        'safe': 'Yes. It refused rather than trusting the file.',
        'do': ['This is a safety rule and it is working.',
               'Fix the file permissions so only your account can change it,',
               'then run the check again:',
               '  eye-for-an-eye check-install']}),
    ('No such file or directory', {
        'what': 'A file Eye for an Eye expected is not there.',
        'safe': 'Yes. Nothing is running.',
        'do': ['Run the check and read what it says is missing:',
               '  eye-for-an-eye check-install']}),
    ('Permission denied', {
        'what': 'Eye for an Eye is not allowed to read or write something it needs.',
        'safe': 'Yes. Nothing is running.',
        'do': ['Check that the file or folder it named belongs to your account.',
               '',
               'Do not run everything as Administrator to get past this. Only the',
               'one operation that truly needs it should ever ask.']}),
)


def plain(problem):
    """A three-part answer for a raised exception. P17 §10.

    Returns (what happened, is my computer safe, what to do next). Anything not
    recognised gets an answer that admits it is not recognised — a wrong
    confident explanation is worse than a traceback, because a traceback at least
    does not mislead.
    """
    message = str(problem)
    for fragment, answer in KNOWN_PROBLEMS:
        if fragment in message:
            return answer['what'], answer['safe'], list(answer['do'])
    return ('Eye for an Eye stopped because of something it did not expect.',
            'Nothing was blocked. Blocking is off unless you turned it on yourself.',
            ['The exact message was:',
             '  ' + message[:400],
             '',
             'For the technical detail, run the same command again with --debug.'])


def report_problem(problem, stream=None):
    """Print the three-part answer. No traceback unless --debug asked for one."""
    stream = stream or sys.stderr
    what, safe, steps = plain(problem)
    print('', file=stream)
    print('What happened', file=stream)
    print('  ' + what, file=stream)
    print('', file=stream)
    print('Is my computer safe', file=stream)
    print('  ' + safe, file=stream)
    print('', file=stream)
    print('What to do next', file=stream)
    for step in steps:
        print('  ' + step, file=stream)


# ---------------------------------------------------------------------------
# Reading the real state. Every fact below comes from existing code.
# ---------------------------------------------------------------------------

def traffic_source(config):
    """Which source is configured, in the vocabulary the beginner view uses."""
    if getattr(config.web, 'access_log_path', ''):
        return 'website log'
    if getattr(config.capture, 'ipc_socket', '') or getattr(config.capture, 'pcap_path', ''):
        return 'network sensor'
    return ''


def blocking_is_off(config):
    """True when nothing can be blocked. Read from the configuration, not assumed."""
    return not (config.enforcement.host_enabled or config.enforcement.enabled
                or config.firewall.enabled)


def summarise(config_path=None):
    """The beginner status, built from `operations.doctor` and the configuration.

    `doctor` is the expert view and stays exactly as it is; this function reads
    its answer and translates. The translation is deliberately lossy in one
    direction only: it never reports healthier than `doctor` did.
    """
    from .config import load_config
    from . import operations

    path = Path(config_path or default_config_path())
    if not path.is_file():
        return {'state': NEEDS_SETUP, 'reason': 'no settings file yet',
                'config_path': str(path), 'blocking': 'OFF', 'source': '',
                'watching': False, 'detail': {}}

    config = load_config(str(path))
    config.validate()
    detail = operations.doctor(config)
    marker = running_marker()
    watching = marker.is_file()

    # A beginner is told NEEDS SETUP for anything they can act on, and ERROR only
    # for something they cannot. `doctor` reporting DEGRADED because no access log
    # and no calibrator are configured is a to-do list, not a fault: the README
    # says so and so does this.
    unhealthy = [name for name, value in detail.items()
                 if isinstance(value, dict) and value.get('status') == 'ERROR']
    if unhealthy:
        state = ERROR
    elif not traffic_source(config):
        state = NEEDS_SETUP
    elif not watching:
        state = NOT_RUNNING
    else:
        state = OK
    return {'state': state, 'reason': '', 'config_path': str(path),
            'blocking': 'OFF' if blocking_is_off(config) else 'ON',
            'source': traffic_source(config), 'watching': watching,
            'mode': getattr(config.autonomy, 'mode', ''), 'detail': detail}


def render(summary):
    """The beginner status screen. P17 §8, §9."""
    lines = ['Eye for an Eye', '']
    lines.append('  Protection:         ' +
                 ('WATCHING' if summary['watching'] else 'NOT RUNNING'))
    lines.append('  Mode:               ' +
                 ('SAFE MONITORING' if summary['blocking'] == 'OFF' else 'BLOCKING ENABLED'))
    lines.append('  Traffic source:     ' + (summary['source'].upper() or 'NOT CHOSEN YET'))
    lines.append('  Automatic blocking: ' + summary['blocking'])
    lines.append('')
    if summary['state'] == OK:
        lines.append('Everything looks OK.')
    elif summary['state'] == NEEDS_SETUP:
        lines.append('NEEDS SETUP.')
        lines.append('')
        # The reason comes first. P18 found this branch ordered the other way
        # round, so a computer with no settings file at all was told "does not
        # know where to watch yet" and sent to choose a traffic source — a
        # confident wrong explanation, which is the one thing a friendly message
        # must never be.
        if summary['reason'] == 'no settings file yet':
            lines.append('Eye for an Eye is installed but not set up yet.')
            lines.append('It looked for its settings file here and found none:')
            lines.append('  ' + summary['config_path'])
            lines.append('')
            lines.append('Set it up now:')
            lines.append('  eye-for-an-eye setup')
        elif not summary['source']:
            lines.append('Eye for an Eye does not know where to watch yet.')
            lines.append('')
            lines.append('Choose what to watch:')
            lines.append('  eye-for-an-eye setup --watch website-log')
            lines.append('')
            lines.append('See docs/BEGINNER_GUIDE.md, Step 3 — Choose what to watch.')
        elif summary['reason']:
            lines.append(summary['reason'].capitalize() + '.')
            lines.append('Run the installer again, or see docs/BEGINNER_GUIDE.md.')
    elif summary['state'] == NOT_RUNNING:
        lines.append('NOT RUNNING.')
        lines.append('')
        lines.append('It is set up but not watching. Start it when you are ready.')
    else:
        lines.append('ERROR.')
        lines.append('')
        lines.append('Something needs attention. For the technical detail, run:')
        lines.append('  eye-for-an-eye doctor')
    lines.append('')
    lines.append('For the full technical view, run: eye-for-an-eye doctor')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# The five beginner actions.
# ---------------------------------------------------------------------------

def status_command(argv, *, debug=False):
    """`eye-for-an-eye easy status`, and `--advanced` for the expert view. P17 §8."""
    import argparse
    parser = argparse.ArgumentParser(prog='eye-for-an-eye easy status')
    parser.add_argument('--config')
    parser.add_argument('--advanced', action='store_true',
                        help='print the full technical report instead')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        summary = summarise(args.config)
    except Exception as problem:                     # noqa: BLE001 - translated below
        if debug:
            raise
        report_problem(problem)
        return 2
    if args.json:
        print(json.dumps(summary, ensure_ascii=True, default=str))
    elif args.advanced:
        from .operator_cli import output
        output(summary['detail'])
    else:
        print(render(summary))
    return 0 if summary['state'] == OK else 1


def check_command(argv, *, debug=False):
    """`eye-for-an-eye check-install`. P17 §27."""
    import argparse
    parser = argparse.ArgumentParser(prog='eye-for-an-eye check-install')
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    checks = []

    def record(name, ok, detail=''):
        checks.append({'check': name, 'ok': bool(ok), 'detail': detail})

    try:
        from . import __version__
        record('the program is installed', True, 'version ' + __version__)
    except Exception as problem:                     # noqa: BLE001
        record('the program is installed', False, type(problem).__name__)

    path = Path(args.config or default_config_path())
    record('a settings file exists', path.is_file(), str(path))

    config = None
    if path.is_file():
        try:
            from .config import load_config
            config = load_config(str(path))
            config.validate()
            record('the settings are valid', True)
        except Exception as problem:                 # noqa: BLE001
            record('the settings are valid', False, str(problem)[:200])

    if config is not None:
        record('automatic blocking is off', blocking_is_off(config))
        record('a traffic source is chosen', bool(traffic_source(config)),
               traffic_source(config) or 'not chosen yet')

    try:
        import onnxruntime                            # noqa: F401
        record('the learning part is available', True)
    except Exception:                                 # noqa: BLE001
        record('the learning part is available', False,
               'optional; Eye for an Eye works without it')

    if args.json:
        print(json.dumps({'checks': checks}, ensure_ascii=True))
        return 0 if all(item['ok'] for item in checks) else 1

    print('Eye for an Eye — install check')
    print()
    for item in checks:
        mark = 'yes' if item['ok'] else 'NO '
        print(f'  [{mark}] {item["check"]}' + (f'   ({item["detail"]})' if item['detail'] else ''))
    print()
    required = [item for item in checks
                if not item['ok'] and 'learning part' not in item['check']]
    if not required:
        print('Everything needed is there.')
        return 0
    print('Something needs attention:')
    for item in required:
        print('  - ' + item['check'] + ' — no')
    print()
    print('See docs/BEGINNER_GUIDE.md, or run: eye-for-an-eye doctor')
    return 1


def start_command(argv, *, debug=False):
    """`eye-for-an-eye start` — begin Safe Monitoring. P17 §7, §20.

    The order is the one the README already prescribes and the one §20 requires:
    validate the configuration, look at it with `doctor`, and only then do
    anything. Nothing here can enable blocking: the configuration decides that,
    and a configuration with blocking on is refused by this command with an
    explanation, because `start` is the beginner door and the beginner door does
    not open onto enforcement.
    """
    import argparse
    parser = argparse.ArgumentParser(prog='eye-for-an-eye start')
    parser.add_argument('--config')
    parser.add_argument('--once', action='store_true',
                        help='read the traffic source once and stop')
    parser.add_argument('--seconds', type=float, default=0.0,
                        help='stop by itself after this many seconds')
    args = parser.parse_args(argv)

    try:
        from .config import load_config
        path = Path(args.config or default_config_path())
        if not path.is_file():
            # P18: this used to say "On Windows, double-click
            # Install-EyeForAnEye.cmd" on every platform, which a Linux beginner
            # met immediately after a successful `sh scripts/install.sh`.
            print('Eye for an Eye is not set up on this computer yet.', file=sys.stderr)
            print('', file=sys.stderr)
            print('It looked for its settings file here and found none:', file=sys.stderr)
            print('  ' + str(path), file=sys.stderr)
            print('', file=sys.stderr)
            if sys.platform == 'win32':
                print('Install it first: double-click Install-EyeForAnEye.cmd.',
                      file=sys.stderr)
            else:
                print('If it is installed, set it up now:', file=sys.stderr)
                print('  eye-for-an-eye setup', file=sys.stderr)
                print('', file=sys.stderr)
                print('If it is not installed yet, run this in the folder you', file=sys.stderr)
                print('unpacked:', file=sys.stderr)
                print('  sh install.sh', file=sys.stderr)
            return 2
        config = load_config(str(path))
        config.validate()

        if not blocking_is_off(config):
            print('This settings file has automatic blocking switched on.', file=sys.stderr)
            print('', file=sys.stderr)
            print('"start" only runs Safe Monitoring, which never blocks anyone.',
                  file=sys.stderr)
            print('To run with blocking, use the expert command and read', file=sys.stderr)
            print('docs/AUTONOMOUS_MODE.md first:', file=sys.stderr)
            print('  eye-for-an-eye run --config ' + str(path), file=sys.stderr)
            return 2

        source = traffic_source(config)
        if not source:
            raise ValueError('sensor requires capture.pcap_path or capture.ipc_socket')
        if source == 'network sensor':
            print('Starting the network sensor. This is the expert path; the messages')
            print('below come from it directly.')
            print()
            from .operator_cli import main as operator_main
            return operator_main('run', ['--config', str(path)], debug=debug)

        return _watch_website_log(config, path, args, debug=debug)
    except Exception as problem:                     # noqa: BLE001 - translated
        if debug:
            raise
        report_problem(problem)
        return 2


def _watch_website_log(config, path, args, *, debug=False):
    """Read the web access log on an interval, using the existing web sensor.

    A loop around `WebSensor.poll()`, which is what `eye-for-an-eye web status`
    already calls once. No detection logic is added, changed or bypassed here:
    the sensor decides, this function only asks it again in a little while and
    counts what came back.
    """
    from .web_cli import _sensor

    sensor = _sensor(config, from_end=True)
    marker = running_marker()
    started = time.monotonic()
    decisions = 0

    print('Eye for an Eye is watching.')
    print()
    print('  Mode:               SAFE MONITORING')
    print('  Automatic blocking: OFF')
    print('  Watching:           ' + str(getattr(config.web, 'access_log_path', '')))
    print()
    print('Nothing is blocked. Press Ctrl+C to stop.')
    print(flush=True)
    request = stop_request()
    try:
        request.unlink()          # a request left by a previous run is not ours
    except OSError:
        pass
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({'pid': os.getpid(), 'started': time.time(),
                                      'config': str(path), 'blocking': 'OFF'}),
                          encoding='utf-8')
    except OSError:
        pass                      # the marker is a convenience, never a requirement
    asked_to_stop = False
    try:
        while True:
            found = sensor.poll()
            if found:
                decisions += len(found)
                health = sensor.health()
                # flush: a progress line that is block-buffered when redirected
                # to a file or a journal shows nothing at all until the process
                # ends, which is the one time it is not useful.
                print(f'  {time.strftime("%H:%M:%S")}  '
                      f'visitors seen: {health.get("sources", 0)}   '
                      f'notes written: {decisions}   blocked: 0', flush=True)
            if request.is_file():
                asked_to_stop = True
                break
            if args.once:
                break
            if args.seconds and time.monotonic() - started >= args.seconds:
                break
            time.sleep(WATCH_SECONDS)
        if asked_to_stop:
            print()
            print('Stopped, because you asked it to stop. Nothing was blocked.')
    except KeyboardInterrupt:
        print()
        print('Stopped. Nothing was blocked.')
    finally:
        for leftover in (marker, request):
            try:
                leftover.unlink()
            except OSError:
                pass
    return 0


def stop_command(argv, *, debug=False):
    """`eye-for-an-eye stop` — ask the watching process to stop, and confirm it did.

    P17W §12. The first version of this command printed instructions for pressing
    Ctrl+C and returned 0. That is a button called Stop that does not stop, which
    §12 forbids outright, and it was right to forbid it: a beginner who clicks
    Stop and is told to go and do it themselves has been given a label instead of
    a feature.

    It now writes the stop request, waits for the watching process to clear its
    own marker, and reports whether that happened. What it never does is signal a
    process id — see `stop_request()` for why the safer design was chosen over the
    obvious one.
    """
    import argparse
    parser = argparse.ArgumentParser(prog='eye-for-an-eye stop')
    parser.add_argument('--wait', type=float, default=WATCH_SECONDS * 3 + 2,
                        help='how long to wait for it to stop, in seconds')
    args = parser.parse_args(argv)

    marker = running_marker()
    request = stop_request()

    if not marker.is_file():
        print('Eye for an Eye is not watching right now.')
        print()
        print('Nothing to stop. Nothing is blocked.')
        return 0

    try:
        request.parent.mkdir(parents=True, exist_ok=True)
        request.write_text(json.dumps({'asked': time.time()}), encoding='utf-8')
    except OSError as problem:
        if debug:
            raise
        report_problem(problem)
        return 2

    print('Asking Eye for an Eye to stop.')
    print()
    deadline = time.monotonic() + max(args.wait, 1.0)
    while time.monotonic() < deadline:
        if not marker.is_file():
            print('Stopped. Nothing is blocked.')
            try:
                request.unlink()
            except OSError:
                pass
            return 0
        time.sleep(0.5)

    # It did not stop in time. Say so plainly, leave the request in place so it
    # stops at its next look, and do not escalate to killing anything.
    print('It has not stopped yet.')
    print()
    print('It checks for the stop request every few seconds, so it should stop')
    print('on its own in a moment. Run Status again to see.')
    print()
    print('If it never stops, close the window that says "watching".')
    print('Nothing is blocked either way.')
    return 1


def uninstall_command(argv, *, debug=False):
    """`eye-for-an-eye easy uninstall` — say what would go, then do only that.

    P17 §28, P18 §54-§56. It never removes evidence or settings without being
    told to: those are the user's, and a decision journal is a deployment's own
    record.

    P18 rewrote the path discovery. The first version hard-coded the Windows
    layout — `<app>/runtime` — so on Linux it announced a directory that does not
    exist, removed nothing, and printed `Removed:` with an empty list followed by
    `Done.`, while the real 21 MB install and a working `eye-for-an-eye` command
    stayed on disk. A button that reports success for work it did not do is worse
    than no button.

    It now resolves what is actually installed (`installed_program()`), refuses
    to claim a removal it did not make, and when it cannot establish what to
    remove it says so and names the script that can.
    """
    import argparse
    import shutil
    parser = argparse.ArgumentParser(prog='eye-for-an-eye easy uninstall')
    parser.add_argument('--yes', action='store_true', help='actually remove it')
    parser.add_argument('--also-remove-my-records', action='store_true',
                        help='also delete settings, notes and records')
    args = parser.parse_args(argv)

    record = receipt()
    program, source = installed_program()
    base = application_directory()
    command = Path(record['command']) if record.get('command') else None

    # Only paths that exist are offered for removal, and only ones this project's
    # own installers create. Nothing else is touched.
    mine = []
    if program is not None:
        mine.append((program, 'the program itself'))
    if command is not None and (command.is_symlink() or command.is_file()):
        mine.append((command, 'the eye-for-an-eye command'))

    data_dir = Path(record['data_dir']) if record.get('data_dir') else base / 'data'
    keep = [path for path in (Path(record['config']) if record.get('config')
                              else base / 'eye-for-an-eye.toml',
                              data_dir, base / 'install-report.txt',
                              base / RECEIPT_NAME)
            if path.exists()]

    print('Uninstall Eye for an Eye')
    print()
    if not mine:
        print('Nothing to remove was found.')
        print()
        print('Eye for an Eye could not work out what was installed on this')
        print('computer, so it will not delete anything by guessing.')
        print()
        if sys.platform == 'win32':
            print('Use Uninstall-EyeForAnEye.cmd in the folder you unpacked.')
        else:
            print('Use the uninstaller that came with it, in the folder you')
            print('unpacked:')
            print('  sh scripts/uninstall.sh')
            print('')
            print('Add --purge to that command to delete your settings and')
            print('records as well.')
        return 1

    print('This will remove:')
    for path, what in mine:
        print(f'  {path}   ({what})')
    print(f'  (found by: {source or "the install receipt"})')
    print()
    if args.also_remove_my_records:
        print('You asked to remove your own files as well:')
        for item in keep or ['(none found)']:
            print(f'  {item}')
    elif keep:
        print('This will be kept, because it is yours:')
        for item in keep:
            print(f'  {item}')
        print()
        print('To remove those too, add --also-remove-my-records.')
    else:
        print('No settings or records of yours were found to keep.')
    print()
    print('Your firewall is not changed by uninstalling. Eye for an Eye never')
    print('changed it unless you switched blocking on yourself.')
    if not args.yes:
        print()
        print('Nothing was removed. To go ahead, run the same command with --yes.')
        return 0

    removed, failed = [], []
    targets = [path for path, _ in mine] + (keep if args.also_remove_my_records else [])
    for item in targets:
        try:
            if item.is_symlink() or item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
            else:
                continue
            removed.append(str(item))
        except OSError as problem:
            failed.append((str(item), type(problem).__name__))
    print()
    if removed:
        print('Removed:')
        for item in removed:
            print('  ' + item)
    for item, why in failed:
        print(f'Could not remove {item}: {why}', file=sys.stderr)
    print()
    if failed:
        print('Some things could not be removed. Eye for an Eye is not fully gone.')
        return 1
    if not removed:
        # Reached only if everything vanished between the listing and the
        # removal. Saying "Done." here is the bug this rewrite exists to fix.
        print('Nothing was removed — the files listed above were already gone.')
        return 1
    print('Done. Eye for an Eye is removed.')
    return 0


def demo_command(argv, *, debug=False):
    """`eye-for-an-eye easy demo` — prove the install works. P17 §24.

    The expert `demo` command already does exactly the right thing: one synthetic
    visitor on loopback, one decision, no firewall change, nothing contacted
    outside the machine. What it does not do is say so briefly — it prints the
    whole decision record as JSON, which is the correct output for the command it
    is and the wrong first experience for a beginner.

    Found by following `START_HERE.md` as a beginner rather than by reading it:
    the demo *worked* and still failed the point of the step. So this runs the
    same demo, keeps its output for `--advanced`, and says the short version.
    """
    import argparse
    import contextlib
    import io as _io
    parser = argparse.ArgumentParser(prog='eye-for-an-eye easy demo')
    parser.add_argument('--config')
    parser.add_argument('--advanced', action='store_true',
                        help='print everything the expert demo prints')
    args = parser.parse_args(argv)

    from .operator_cli import main as operator_main

    forwarded = ['--config', args.config] if args.config else []
    captured = _io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            code = operator_main('demo', forwarded, debug=debug)
    except Exception as problem:                     # noqa: BLE001 - translated
        if debug:
            raise
        report_problem(problem)
        return 2

    if args.advanced:
        print(captured.getvalue(), end='')
        return code

    body = captured.getvalue()
    events = body.count('"event_id"')
    if code != 0:
        print('The demo did not finish.', file=sys.stderr)
        print('', file=sys.stderr)
        print('Nothing was blocked and your firewall was not changed.', file=sys.stderr)
        print('For the detail, run: eye-for-an-eye easy demo --advanced', file=sys.stderr)
        return code
    print('Demo complete.')
    print()
    print(f'  {events or 1} test event processed.')
    print('  No network block was created.')
    print('  Nothing outside this computer was contacted.')
    print()
    print('Eye for an Eye works on this computer.')
    return 0


def easy_command(argv, *, debug=False):
    """`eye-for-an-eye easy <action>` — the beginner group."""
    actions = {'status': status_command, 'check': check_command,
               'start': start_command, 'stop': stop_command,
               'demo': demo_command, 'uninstall': uninstall_command}
    if not argv or argv[0] not in actions:
        print('eye-for-an-eye easy <' + '|'.join(sorted(actions)) + '>')
        print()
        print('  start      begin Safe Monitoring (never blocks anyone)')
        print('  status     a short answer about how it is doing')
        print('  check      check the installation')
        print('  demo       prove it works, without a website')
        print('  stop       how to stop it')
        print('  uninstall  remove the program')
        return 0 if argv[:1] in ([], ['--help'], ['-h']) else 2
    return actions[argv[0]](argv[1:], debug=debug)
