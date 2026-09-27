"""The Linux beginner path, checked by running it. P18 §20, §27-§47, §111-§113.

Every test here exists because P18 executed the documented Linux flow and found
something wrong with it. That is the point of the file: P17 built the beginner
layer and shipped a Windows acceptance run, and the Linux half of the same
documentation had never been followed end to end by anybody. It looked right.

What running it actually produced, on a clean Ubuntu 24.04 machine, immediately
after a **successful** `sh scripts/install.sh`:

* `eye-for-an-eye check-install` -> *a settings file exists — NO*
* `eye-for-an-eye easy status`   -> NEEDS SETUP, blaming the traffic source
* `eye-for-an-eye start`         -> *"Install it first. On Windows,
                                    double-click Install-EyeForAnEye.cmd."*
* `eye-for-an-eye status`        -> `Error [1]: [Errno 2] ... status.json`
* `eye-for-an-eye easy uninstall --yes` -> `Removed:` (nothing) then `Done.`,
                                    with 21 MB and a working command still there

The cause of the first three was one disagreement: the installer wrote the
configuration to `<prefix>/data/eye-for-an-eye.toml` and the beginner layer looked
only at `<prefix>/eye-for-an-eye.toml`, which is where the *Windows* installer
puts it. Two halves of one product, each correct on its own.

So these tests are mostly about agreement between parts, which is the kind of
defect a unit test on either part cannot see.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

from eye_for_an_eye import beginner, setup_cli
from eye_for_an_eye.cli import COMMANDS
from eye_for_an_eye.configuration import initialize

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'scripts' / 'install.sh'
UNINSTALLER = ROOT / 'scripts' / 'uninstall.sh'


def shadow_config(directory, *, access_log=''):
    """A real production-shadow configuration on disk, written by the real writer."""
    target = Path(directory) / 'eye-for-an-eye.toml'
    initialize(str(target), 'production-shadow')
    if access_log:
        setup_cli.set_access_log(target, access_log)
    return target


def json_log(directory, name='visitors.log'):
    """One access-log line in the format the reader actually parses."""
    path = Path(directory) / name
    path.write_text(json.dumps({
        'time': '2026-09-26T19:00:00+00:00', 'remote_addr': '203.0.113.9',
        'method': 'GET', 'uri': '/', 'status': 200, 'bytes_sent': 512,
        'request_length': 80, 'request_time': '0.001', 'protocol': 'HTTP/1.1',
        'host': 'example.test', 'user_agent': 'curl/8.5.0', 'referer': '-'}) + '\n',
        encoding='utf-8')
    return path


class TestTheInstallerAndTheBeginnerLayerAgreeOnWhereThingsAre(unittest.TestCase):
    """The regression that made three commands wrong at once."""

    def test_the_directory_the_installer_writes_the_config_to_is_one_the_layer_looks_in(self):
        # Read the installer's own default rather than restating it here. A test
        # that hard-codes the answer agrees with itself, not with the installer.
        body = INSTALLER.read_text(encoding='utf-8')
        self.assertIn('DATA_DIR="$PREFIX/data"', body,
                      'the installer no longer puts data in <prefix>/data; this test '
                      'and eye_for_an_eye/beginner.config_candidates() must both be '
                      'updated to match it')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'eye-for-an-eye'
            (base / 'data').mkdir(parents=True)
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=base):
                candidates = [str(path) for path in beginner.config_candidates()]
        self.assertIn(str(base / 'data' / 'eye-for-an-eye.toml'), candidates)

    def test_the_windows_installer_location_is_also_looked_in(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'eye-for-an-eye'
            base.mkdir(parents=True)
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=base):
                candidates = [str(path) for path in beginner.config_candidates()]
        self.assertIn(str(base / 'eye-for-an-eye.toml'), candidates)

    def test_a_receipt_decides_and_an_unusual_prefix_is_therefore_found(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'app'
            base.mkdir()
            odd = Path(directory) / 'somewhere-else'
            odd.mkdir()
            config = shadow_config(odd)
            (base / beginner.RECEIPT_NAME).write_text(json.dumps({
                'schema_version': 1, 'config': str(config),
                'program': str(odd), 'data_dir': str(odd)}), encoding='utf-8')
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=base):
                self.assertEqual(beginner.default_config_path(), config)

    def test_a_damaged_receipt_is_ignored_rather_than_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'app'
            base.mkdir()
            (base / beginner.RECEIPT_NAME).write_text('{not json', encoding='utf-8')
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=base):
                self.assertEqual(beginner.receipt(), {})
                self.assertTrue(beginner.config_candidates())

    def test_a_receipt_from_a_future_schema_is_ignored_rather_than_trusted(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'app'
            base.mkdir()
            (base / beginner.RECEIPT_NAME).write_text(
                json.dumps({'schema_version': 99, 'config': '/nowhere'}), encoding='utf-8')
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=base):
                self.assertEqual(beginner.receipt(), {})

    def test_the_installer_writes_both_the_receipt_and_the_report_the_docs_promise(self):
        body = INSTALLER.read_text(encoding='utf-8')
        self.assertIn('install-receipt.json', body)
        # START_HERE.md and docs/BEGINNER_GUIDE.md both tell people to send this
        # file. Before P18 only the Windows installer wrote one.
        self.assertIn('install-report.txt', body)
        self.assertIn('install-report.txt', (ROOT / 'START_HERE.md').read_text(encoding='utf-8'))


class TestNoBeginnerMessageSendsALinuxUserToAWindowsFile(unittest.TestCase):
    def test_start_does_not_mention_a_cmd_file_on_a_non_windows_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'nothing.toml'
            import io
            import contextlib
            captured = io.StringIO()
            with unittest.mock.patch.object(sys, 'platform', 'linux'), \
                    contextlib.redirect_stderr(captured):
                code = beginner.start_command(['--config', str(missing)])
        self.assertEqual(code, 2)
        message = captured.getvalue()
        self.assertNotIn('.cmd', message)
        self.assertNotIn('double-click', message)
        self.assertIn('eye-for-an-eye setup', message)
        # It must also say where it looked. "Not set up" without a path is a
        # message that cannot be acted on.
        self.assertIn(str(missing), message)

    def test_start_still_says_the_right_thing_on_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'nothing.toml'
            import io
            import contextlib
            captured = io.StringIO()
            with unittest.mock.patch.object(sys, 'platform', 'win32'), \
                    contextlib.redirect_stderr(captured):
                beginner.start_command(['--config', str(missing)])
        self.assertIn('Install-EyeForAnEye.cmd', captured.getvalue())


class TestEveryCommandABeginnerMessageNamesExists(unittest.TestCase):
    """The generalised form of the `eye-for-an-eye setup protect` defect.

    A beginner message that names a command which does not exist is worse than a
    traceback: it sends somebody to type something that will be rejected, and they
    have no way to know the message was wrong rather than their typing.

    `eye-for-an-eye setup protect` was in `KNOWN_PROBLEMS` as the answer for the
    management-network refusal. It has never existed.
    """

    #: Subcommands of a real command. Named here because argparse subparsers are
    #: not reachable from `COMMANDS`, and a wrong one is exactly the bug.
    SUBCOMMANDS = {
        'easy': ('status', 'check', 'start', 'stop', 'demo', 'uninstall'),
        'model': ('status',),
        'config': ('validate', 'show', 'init'),
        'setup': (),
        'web': ('log-format', 'doctor', 'status'),
        'autonomy': ('readiness', 'status', 'policy', 'explain', 'enable',
                     'preflight', 'evidence', 'freeze', 'crosscheck', 'result',
                     'science'),
        'storage': ('info', 'backup', 'migrate', 'restore', 'prune'),
        'events': ('tail', 'export'),
    }

    def named_commands(self, path):
        """Commands the file tells somebody to run.

        Two things are deliberately not counted, because neither is an
        instruction and both appear in this project:

        * Output quoted back to the reader. `docs/TROUBLESHOOTING.md` shows
          apt's own refusal, `eye-for-an-eye depends on python3.12`, which is
          apt talking. Only ```sh blocks and inline code spans count; a bare
          fence is what you will see, not what you should type.
        * English prose in a message. `beginner.py` prints
          `(the eye-for-an-eye command)`. So a string literal counts only when
          the command is how it begins, which is this project's convention for
          showing a command — two spaces and then the command.
        """
        body = path.read_text(encoding='utf-8')
        if path.suffix == '.py':
            # String literals, then only those that begin with the command.
            regions = re.findall(r"'([^'\n]*)'", body) + re.findall(r'"([^"\n]*)"', body)
        else:
            regions = re.findall(r'```sh\n(.*?)```', body, re.DOTALL)
            regions += re.findall(r'`([^`\n]+)`', body)
        found = set()
        for region in regions:
            for line in region.splitlines():
                match = re.match(r'\s*(?:sudo )?eye-for-an-eye ([a-z][a-z0-9-]*)'
                                 r'(?: ([a-z][a-z0-9-]*))?', line)
                if not match:
                    continue
                command, sub = match.group(1), match.group(2) or ''
                if command in ('--help', '-h'):
                    continue
                found.add((command, sub))
        return found

    def test_the_scanner_finds_something_so_this_check_is_not_vacuous(self):
        """A test that looks at nothing passes. Guard against that directly."""
        for name in ('eye_for_an_eye/beginner.py', 'eye_for_an_eye/setup_cli.py',
                     'START_HERE.md', 'docs/BEGINNER_GUIDE.md',
                     'docs/INSTALL_LINUX.md', 'docs/TROUBLESHOOTING.md'):
            with self.subTest(file=name):
                self.assertGreaterEqual(len(self.named_commands(ROOT / name)), 5,
                                        'the scanner found almost nothing, so the '
                                        'checks below are not really checking')
        # And it must reject a command that does not exist.
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'fake.md'
            fake.write_text('```sh\neye-for-an-eye setup protect\n```\n', encoding='utf-8')
            self.assertIn(('setup', 'protect'), self.named_commands(fake))
            self.assertNotIn('protect', self.SUBCOMMANDS['setup'])

    def test_the_beginner_layer_names_only_real_commands(self):
        for path in (ROOT / 'eye_for_an_eye' / 'beginner.py',
                     ROOT / 'eye_for_an_eye' / 'setup_cli.py'):
            for command, sub in sorted(self.named_commands(path)):
                with self.subTest(file=path.name, command=command, sub=sub):
                    self.assertIn(command, COMMANDS,
                                  f'{path.name} tells the user to run '
                                  f'"eye-for-an-eye {command}", which is not a command')
                    if sub and command in self.SUBCOMMANDS:
                        self.assertIn(sub, self.SUBCOMMANDS[command],
                                      f'{path.name} tells the user to run '
                                      f'"eye-for-an-eye {command} {sub}", and '
                                      f'{command} has no {sub}')

    def test_the_beginner_documentation_names_only_real_commands(self):
        for name in ('START_HERE.md', 'docs/BEGINNER_GUIDE.md',
                     'docs/INSTALL_LINUX.md', 'docs/TROUBLESHOOTING.md'):
            path = ROOT / name
            for command, sub in sorted(self.named_commands(path)):
                with self.subTest(file=name, command=command, sub=sub):
                    self.assertIn(command, COMMANDS,
                                  f'{name} tells the reader to run '
                                  f'"eye-for-an-eye {command}", which is not a command')
                    if sub and command in self.SUBCOMMANDS:
                        self.assertIn(sub, self.SUBCOMMANDS[command],
                                      f'{name} tells the reader to run '
                                      f'"eye-for-an-eye {command} {sub}", and '
                                      f'{command} has no {sub}')

    def test_the_management_network_answer_no_longer_names_a_command_that_never_existed(self):
        fragments = [fragment for fragment, _ in beginner.KNOWN_PROBLEMS]
        index = fragments.index('requires at least one protected network')
        answer = beginner.KNOWN_PROBLEMS[index][1]
        self.assertNotIn('setup protect', '\n'.join(answer['do']))


class TestTheStatusSaysWhichProblemItActuallyFound(unittest.TestCase):
    def test_no_settings_file_is_not_reported_as_no_traffic_source(self):
        rendered = beginner.render({'state': beginner.NEEDS_SETUP,
                                    'reason': 'no settings file yet',
                                    'config_path': '/somewhere/eye-for-an-eye.toml',
                                    'blocking': 'OFF', 'source': '',
                                    'watching': False, 'detail': {}})
        self.assertIn('not set up yet', rendered)
        self.assertIn('/somewhere/eye-for-an-eye.toml', rendered)
        self.assertNotIn('does not know where to watch', rendered)

    def test_no_traffic_source_is_still_reported_as_no_traffic_source(self):
        rendered = beginner.render({'state': beginner.NEEDS_SETUP, 'reason': '',
                                    'config_path': '/somewhere/eye-for-an-eye.toml',
                                    'blocking': 'OFF', 'source': '',
                                    'watching': False, 'detail': {}})
        self.assertIn('does not know where to watch', rendered)
        self.assertNotIn('not set up yet', rendered)


class TestUninstallNeverClaimsWorkItDidNotDo(unittest.TestCase):
    """`Removed:` with an empty list, then `Done.`, was the shipped behaviour."""

    def run_uninstall(self, base, argv):
        import io
        import contextlib
        captured = io.StringIO()
        with unittest.mock.patch.object(beginner, 'application_directory',
                                        return_value=base), \
                unittest.mock.patch.dict(os.environ,
                                         {'EYE_FOR_AN_EYE_RECEIPT':
                                          str(base / beginner.RECEIPT_NAME)}), \
                contextlib.redirect_stdout(captured), \
                contextlib.redirect_stderr(captured):
            code = beginner.uninstall_command(argv)
        return code, captured.getvalue()

    def test_with_nothing_installed_it_refuses_rather_than_reporting_done(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'eye-for-an-eye'
            base.mkdir()
            code, output = self.run_uninstall(base, ['--yes'])
        self.assertEqual(code, 1, 'an uninstall that removed nothing must not succeed')
        self.assertNotIn('Done.', output)
        self.assertIn('Nothing to remove was found', output)
        # And it must point at the thing that can do it.
        self.assertIn('uninstall.sh' if sys.platform != 'win32'
                      else 'Uninstall-EyeForAnEye.cmd', output)

    def test_it_removes_what_the_receipt_records_and_keeps_what_is_the_users(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'eye-for-an-eye'
            program = base / 'venv'
            (program / 'bin').mkdir(parents=True)
            (program / 'bin' / 'eye-for-an-eye').write_text('#!/bin/sh\n', encoding='utf-8')
            data = base / 'data'
            data.mkdir()
            config = data / 'eye-for-an-eye.toml'
            config.write_text('config_version = 1\n', encoding='utf-8')
            journal = data / 'decisions.jsonl'
            journal.write_text('{}\n', encoding='utf-8')
            command = Path(directory) / 'bin' / 'eye-for-an-eye'
            command.parent.mkdir()
            command.symlink_to(program / 'bin' / 'eye-for-an-eye')
            (base / beginner.RECEIPT_NAME).write_text(json.dumps({
                'schema_version': 1, 'program': str(program), 'data_dir': str(data),
                'config': str(config), 'command': str(command)}), encoding='utf-8')

            code, output = self.run_uninstall(base, ['--yes'])

            self.assertEqual(code, 0, output)
            self.assertIn('Done. Eye for an Eye is removed.', output)
            self.assertFalse(program.exists(), 'the program is still installed')
            self.assertFalse(command.is_symlink(), 'the command still resolves')
            self.assertTrue(config.is_file(), 'it deleted the operator configuration')
            self.assertTrue(journal.is_file(), 'it deleted a decision record')

    def test_the_users_records_go_only_when_asked(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'eye-for-an-eye'
            program = base / 'venv'
            program.mkdir(parents=True)
            data = base / 'data'
            data.mkdir()
            journal = data / 'decisions.jsonl'
            journal.write_text('{}\n', encoding='utf-8')
            (base / beginner.RECEIPT_NAME).write_text(json.dumps({
                'schema_version': 1, 'program': str(program),
                'data_dir': str(data)}), encoding='utf-8')
            code, output = self.run_uninstall(base, ['--yes', '--also-remove-my-records'])
        self.assertEqual(code, 0, output)
        self.assertFalse(journal.exists())

    def test_without_yes_it_removes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'eye-for-an-eye'
            program = base / 'venv'
            program.mkdir(parents=True)
            (base / beginner.RECEIPT_NAME).write_text(json.dumps({
                'schema_version': 1, 'program': str(program)}), encoding='utf-8')
            code, output = self.run_uninstall(base, [])
            self.assertEqual(code, 0)
            self.assertIn('Nothing was removed', output)
            self.assertTrue(program.is_dir(),
                            'it removed the program without being asked')


class TestStatusAfterStopAndBeforeAnyStart(unittest.TestCase):
    """§47. `Error [1]: [Errno 2] ... status.json` was the answer on a fresh install."""

    def test_a_status_file_that_was_never_written_is_an_answer_not_an_error(self):
        from eye_for_an_eye import operations
        with tempfile.TemporaryDirectory() as directory:
            config = shadow_config(directory)
            result = subprocess.run(
                [sys.executable, '-m', 'eye_for_an_eye', 'status', '--config', str(config)],
                capture_output=True, text=True, cwd=ROOT, timeout=120)
        self.assertNotIn('Errno', result.stdout + result.stderr)
        self.assertIn('NOT RUNNING', result.stdout)
        self.assertEqual(result.returncode, 1, 'not running is still not success')
        self.assertTrue(hasattr(operations, '_never_started'))

    def test_the_machine_readable_answer_says_running_false(self):
        with tempfile.TemporaryDirectory() as directory:
            config = shadow_config(directory)
            result = subprocess.run(
                [sys.executable, '-m', 'eye_for_an_eye', 'status', '--json',
                 '--config', str(config)],
                capture_output=True, text=True, cwd=ROOT, timeout=120)
        payload = json.loads(result.stdout)
        self.assertIs(payload['running'], False)
        self.assertEqual(payload['state'], 'NOT RUNNING')

    def test_it_does_not_say_not_running_while_safe_monitoring_is_running(self):
        """The defect the §47 fix introduced, and the reason to run things.

        `start` writes a beginner marker; only the sensor service writes the
        runtime snapshot `status` reads. So the first version of the §47 fix
        answered `Protection: NOT RUNNING` while `eye-for-an-eye start` was
        running in another terminal and `easy status` was correctly reporting
        WATCHING. Replacing a confusing errno with a confident wrong answer is
        not an improvement — an operator asking whether traffic is being watched
        is exactly who must not be misled.
        """
        with tempfile.TemporaryDirectory() as directory:
            config = shadow_config(directory)
            base = Path(directory) / 'app'
            base.mkdir()
            (base / 'watching.json').write_text('{"pid": 1}', encoding='utf-8')
            environment = dict(os.environ, XDG_DATA_HOME=str(directory),
                               HOME=str(directory))
            # `application_directory()` resolves to <XDG_DATA_HOME>/eye-for-an-eye.
            marker_home = Path(directory) / 'eye-for-an-eye'
            marker_home.mkdir(exist_ok=True)
            (marker_home / 'watching.json').write_text('{"pid": 1}', encoding='utf-8')
            result = subprocess.run(
                [sys.executable, '-m', 'eye_for_an_eye', 'status', '--json',
                 '--config', str(config)],
                capture_output=True, text=True, cwd=ROOT, env=environment, timeout=120)
            payload = json.loads(result.stdout)
        self.assertIs(payload['running'], True, result.stdout + result.stderr)
        self.assertEqual(payload['state'], 'WATCHING')
        self.assertEqual(result.returncode, 0)

    def test_the_watch_display_is_flushed_so_a_redirect_shows_it(self):
        body = (ROOT / 'eye_for_an_eye' / 'beginner.py').read_text(encoding='utf-8')
        self.assertIn('flush=True', body,
                      'the progress display is block-buffered when redirected, so a '
                      'service log or a captured run shows nothing until it ends')

    def test_a_snapshot_that_exists_but_is_broken_is_still_a_failure(self):
        """The narrowness matters. Only the absent file became an answer."""
        with tempfile.TemporaryDirectory() as directory:
            config = shadow_config(directory)
            (Path(directory) / 'status.json').write_text('not json', encoding='utf-8')
            result = subprocess.run(
                [sys.executable, '-m', 'eye_for_an_eye', 'status', '--config', str(config)],
                capture_output=True, text=True, cwd=ROOT, timeout=120)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('NOT RUNNING', result.stdout)
        self.assertIn('Error', result.stdout + result.stderr)


class TestTheExpertCommandsReadTheConfigurationThisComputerHas(unittest.TestCase):
    """§27, §120. `doctor` with no --config reported on built-in defaults."""

    def test_doctor_without_a_config_flag_uses_the_discovered_file(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'eye-for-an-eye'
            (base / 'data').mkdir(parents=True)
            config = shadow_config(base / 'data')
            environment = dict(os.environ,
                               XDG_DATA_HOME=str(directory),
                               HOME=str(directory))
            result = subprocess.run([sys.executable, '-m', 'eye_for_an_eye', 'doctor'],
                                    capture_output=True, text=True, cwd=ROOT,
                                    env=environment, timeout=180)
        self.assertIn(str(config), result.stderr,
                      'doctor did not say which settings file it read')

    def test_it_says_which_file_it_read_rather_than_reading_one_silently(self):
        body = (ROOT / 'eye_for_an_eye' / 'operations.py').read_text(encoding='utf-8')
        self.assertIn('Reading the settings file for this computer', body)


class TestChoosingAWebsiteLogWithoutEditingToml(unittest.TestCase):
    """§28. The beginner guide used to say: open the file in a text editor."""

    def test_the_guide_no_longer_asks_anyone_to_edit_the_settings_file(self):
        body = (ROOT / 'docs' / 'BEGINNER_GUIDE.md').read_text(encoding='utf-8')
        self.assertIn('never have to edit a settings file by hand', body)
        self.assertNotIn('Put the path between the quotes', body)

    def test_a_json_access_log_is_accepted_and_read_back(self):
        with tempfile.TemporaryDirectory() as directory:
            log = json_log(directory)
            config = shadow_config(directory)
            before = stat.S_IMODE(config.stat().st_mode)
            setup_cli.set_access_log(config, log)
            from eye_for_an_eye.config import load_config
            written = load_config(str(config), require_version=True)
            self.assertEqual(written.web.access_log_path, str(log))
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), before,
                             'writing the path changed the file permissions')

    def test_a_default_nginx_combined_log_is_refused_with_the_real_fix(self):
        with tempfile.TemporaryDirectory() as directory:
            combined = Path(directory) / 'access.log'
            combined.write_text(
                '203.0.113.9 - - [26/Sep/2026:19:00:00 +0000] "GET / HTTP/1.1" '
                '200 512 "-" "curl/8.5.0"\n', encoding='utf-8')
            problem = setup_cli.access_log_problem(str(combined))
        self.assertTrue(problem, 'a combined-format log was accepted; every line of it '
                                 'would be thrown away and the sensor would see nothing')
        self.assertIn('web log-format', problem)

    def test_an_empty_log_is_accepted_because_a_new_one_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / 'new.log'
            empty.touch()
            self.assertEqual(setup_cli.access_log_problem(str(empty)), '')

    def test_a_missing_file_and_a_directory_are_both_refused_plainly(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIn('no file at that path',
                          setup_cli.access_log_problem(str(Path(directory) / 'nope')))
            self.assertIn('folder', setup_cli.access_log_problem(directory))

    def test_a_failed_write_leaves_the_configuration_exactly_as_it_was(self):
        with tempfile.TemporaryDirectory() as directory:
            config = shadow_config(directory)
            original = config.read_text(encoding='utf-8')
            # A path the configuration will reject, so the read-back fails.
            with self.assertRaises(Exception):
                setup_cli.set_access_log(config, '\x00not a path')
            self.assertEqual(config.read_text(encoding='utf-8'), original)

    def test_suggestions_are_only_files_that_exist(self):
        for path in setup_cli.log_suggestions():
            self.assertTrue(Path(path).is_file())

    def test_the_first_suggestion_is_the_one_that_can_actually_be_read(self):
        # A default access.log cannot be parsed, so it must not be offered first.
        self.assertEqual(setup_cli.LOG_SUGGESTIONS[0],
                         '/var/log/nginx/eye-for-an-eye.log')


class TestTheFirstQuestion(unittest.TestCase):
    """§29. Asked with only the answers this build supports."""

    def ask(self, answers, platform='linux'):
        import io
        stream_in = io.StringIO(answers)
        stream_out = io.StringIO()
        with unittest.mock.patch.object(sys, 'platform', platform):
            choice = setup_cli.choose_watch(stream_in, stream_out)
        return choice, stream_out.getvalue()

    def test_it_offers_exactly_the_three_supported_answers(self):
        choice, shown = self.ask('1\n')
        self.assertEqual(choice, 'website-log')
        self.assertIn('What do you want Eye for an Eye to watch?', shown)
        self.assertIn('1. A website log', shown)
        self.assertIn('2. Network traffic', shown)
        self.assertIn('3. Nothing yet', shown)

    def test_network_traffic_is_offered_on_linux(self):
        choice, _ = self.ask('2\n')
        self.assertEqual(choice, 'network')

    def test_network_traffic_is_refused_rather_than_offered_on_windows(self):
        choice, shown = self.ask('2\n1\n', platform='win32')
        self.assertEqual(choice, 'website-log')
        self.assertIn('not available on this computer', shown)

    def test_a_nonsense_answer_asks_again_instead_of_guessing(self):
        choice, shown = self.ask('banana\n3\n')
        self.assertEqual(choice, 'demo')
        self.assertIn('Please type 1, 2 or 3', shown)

    def test_no_answer_at_all_is_an_error_and_not_a_silent_default(self):
        import io
        with self.assertRaises(EOFError):
            setup_cli.choose_watch(io.StringIO(''), io.StringIO())

    def test_setup_asks_nothing_when_nobody_is_there_to_answer(self):
        """A pipe, a service unit and --json all take the quiet path."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'eye-for-an-eye.toml'
            result = subprocess.run(
                [sys.executable, '-m', 'eye_for_an_eye', 'setup',
                 '--profile', 'production-shadow', '--config', str(target)],
                capture_output=True, text=True, cwd=ROOT, timeout=180,
                stdin=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('What do you want', result.stdout)
            self.assertTrue(target.is_file())


class TestTheSafeProfileIsTheSameOnBothPlatforms(unittest.TestCase):
    """§34, §35. The two installers were writing two different products."""

    def test_the_linux_installer_defaults_to_the_same_profile_as_the_windows_one(self):
        body = INSTALLER.read_text(encoding='utf-8')
        self.assertIn(f'PROFILE="{beginner.SAFE_PROFILE}"', body,
                      'the Linux installer no longer defaults to the profile the '
                      'beginner layer calls safe')

    def test_the_safe_profile_runs_the_shadow_analysis_path(self):
        """The old default, `website`, has no [autonomy] section at all."""
        with tempfile.TemporaryDirectory() as directory:
            config = shadow_config(directory)
            from eye_for_an_eye.config import load_config
            loaded = load_config(str(config), require_version=True)
            loaded.validate()
        self.assertTrue(loaded.autonomy.enabled)
        self.assertEqual(loaded.autonomy.mode, 'shadow')

    def test_the_safe_profile_blocks_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            config = shadow_config(directory)
            from eye_for_an_eye.config import load_config
            loaded = load_config(str(config), require_version=True)
        self.assertFalse(loaded.enforcement.enabled)
        self.assertFalse(loaded.enforcement.host_enabled)
        self.assertFalse(loaded.firewall.enabled)
        self.assertTrue(beginner.blocking_is_off(loaded))

    def test_setup_offers_the_shadow_profile_but_not_the_autonomous_one(self):
        self.assertIn('production-shadow', setup_cli.PROFILES)
        self.assertNotIn('production-autonomous', setup_cli.PROFILES,
                         'autonomous enforcement must not be reachable from the '
                         'first setup flow')


class TestTheLinuxInstallerDoesNothingItMustNotDo(unittest.TestCase):
    """§20. The list of things an installer must never do, checked on the script."""

    FORBIDDEN = (
        ('iptables -F', 'flushes firewall rules'),
        ('nft flush', 'flushes firewall rules'),
        ('ufw disable', 'disables an existing firewall'),
        ('setenforce', 'changes SELinux'),
        ('aa-disable', 'disables AppArmor'),
        ('aa-complain', 'weakens AppArmor'),
        ('systemctl enable', 'enables a service'),
        ('systemctl start', 'starts a service'),
        ('curl', 'downloads something'),
        ('wget', 'downloads something'),
        ('usermod', 'modifies an account'),
        ('userdel', 'modifies an account'),
        ('visudo', 'modifies sudo'),
        ('chown -R /', 'changes ownership outside its own tree'),
    )

    def test_neither_installer_script_does_any_of_them(self):
        for script in (INSTALLER, UNINSTALLER, ROOT / 'install.sh', ROOT / 'uninstall.sh'):
            body = script.read_text(encoding='utf-8')
            for fragment, why in self.FORBIDDEN:
                with self.subTest(script=script.name, fragment=fragment):
                    self.assertNotIn(fragment, body,
                                     f'{script.name} {why}')

    def test_the_uninstaller_removes_only_its_own_paths(self):
        body = UNINSTALLER.read_text(encoding='utf-8')
        for removal in re.finditer(r'rm -rf "([^"]+)"', body):
            target = removal.group(1)
            with self.subTest(target=target):
                self.assertTrue(target.startswith(('$PREFIX', '$DATA_DIR')),
                                f'the uninstaller removes {target}, which is not '
                                f'one of its own directories')

    def test_the_installer_reports_the_platform_and_architecture(self):
        body = INSTALLER.read_text(encoding='utf-8')
        self.assertIn('uname -s', body)
        self.assertIn('uname -m', body)

    def test_the_installer_checks_it_can_write_before_it_writes(self):
        body = INSTALLER.read_text(encoding='utf-8')
        self.assertIn('cannot write in', body)

    def test_a_dry_run_changes_nothing_and_says_every_step(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ['sh', str(INSTALLER), '--dry-run', '--prefix',
                 str(Path(directory) / 'program'), '--data-dir',
                 str(Path(directory) / 'data')],
                capture_output=True, text=True, cwd=ROOT, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('[dry-run]', result.stdout)
            self.assertFalse((Path(directory) / 'program').exists(),
                             'a dry run created something')

    def test_an_unknown_profile_is_refused_by_name(self):
        result = subprocess.run(['sh', str(INSTALLER), '--profile', 'wide-open',
                                 '--dry-run'],
                                capture_output=True, text=True, cwd=ROOT, timeout=120)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('profile must be', result.stderr)


class TestTheRootLevelDoorsAreDoorsAndNotSecondImplementations(unittest.TestCase):
    """§19, §23. One installer, one uninstaller, reached from the top of the tree."""

    def test_both_exist_and_are_executable(self):
        for name in ('install.sh', 'uninstall.sh'):
            path = ROOT / name
            self.assertTrue(path.is_file(), f'{name} is missing from the tree root')
            self.assertTrue(path.stat().st_mode & stat.S_IXUSR,
                            f'{name} is not executable')

    def test_they_hand_over_rather_than_reimplement(self):
        for name, target in (('install.sh', 'scripts/install.sh'),
                             ('uninstall.sh', 'scripts/uninstall.sh')):
            body = (ROOT / name).read_text(encoding='utf-8')
            self.assertIn(target, body)
            self.assertIn('exec sh', body)
            # A door has no installation logic of its own.
            for absent in ('venv', 'pip install', 'PROFILE', 'mkdir -p'):
                with self.subTest(name=name, absent=absent):
                    self.assertNotIn(absent, body,
                                     f'{name} looks like a second implementation')

    def test_the_release_root_will_contain_them(self):
        body = (ROOT / 'scripts' / 'build_prod.py').read_text(encoding='utf-8')
        self.assertIn("'install.sh', 'uninstall.sh',", body)


class TestTheDocumentedLinuxQuickStartRuns(unittest.TestCase):
    """§112, §113. Every command in the Quick start, in order, for real.

    `setup` and `start` are documented without flags because that is what a person
    types. A test cannot answer an interactive question or wait for a blocking
    loop, so those two get the smallest possible addition — `--watch`/`--access-log`
    and `--once` — and this docstring says so rather than a comment claiming the
    documented command passed.
    """

    def test_the_readme_quick_start_is_the_beginner_path_and_needs_no_root(self):
        body = (ROOT / 'README.md').read_text(encoding='utf-8')
        block = body.split('## Quick start', 1)[1].split('```sh', 1)[1].split('```', 1)[0]
        commands = [line.strip() for line in block.splitlines() if line.strip()]
        self.assertIn('sh install.sh', commands)
        self.assertIn('eye-for-an-eye setup', commands)
        self.assertIn('eye-for-an-eye start', commands)
        for command in commands:
            self.assertNotIn('sudo', command)
            self.assertNotIn('git clone', command)
            self.assertNotIn('pip install', command)
            self.assertNotIn('python -m venv', command)
            self.assertNotIn('PYTHONPATH', command)

    def test_the_quick_start_names_no_firewall_or_enforcement_command(self):
        """Checked on the commands, not the prose. The prose is allowed — and
        ought — to say that it changes no firewall rule."""
        body = (ROOT / 'README.md').read_text(encoding='utf-8')
        section = body.split('## Quick start', 1)[1].split('\n## ', 1)[0]
        commands = '\n'.join(re.findall(r'```sh\n(.*?)```', section, re.DOTALL))
        self.assertTrue(commands, 'the Quick start has no shell block')
        for forbidden in ('firewall', 'host_enabled', 'production-autonomous',
                          'autonomy enable', 'nft ', 'iptables'):
            self.assertNotIn(forbidden, commands)

    def test_setup_then_start_then_status_leaves_blocking_off(self):
        with tempfile.TemporaryDirectory() as directory:
            log = json_log(directory)
            target = Path(directory) / 'eye-for-an-eye.toml'
            for argv in (['setup', '--profile', 'production-shadow',
                          '--config', str(target), '--no-questions'],
                         ['setup', '--config', str(target), '--watch', 'website-log',
                          '--access-log', str(log)],
                         ['start', '--config', str(target), '--once'],
                         ['easy', 'status', '--config', str(target)]):
                result = subprocess.run([sys.executable, '-m', 'eye_for_an_eye'] + argv,
                                        capture_output=True, text=True, cwd=ROOT,
                                        timeout=300, stdin=subprocess.DEVNULL)
                with self.subTest(argv=argv):
                    self.assertIn(result.returncode, (0, 1),
                                  result.stdout + result.stderr)
            from eye_for_an_eye.config import load_config
            after = load_config(str(target), require_version=True)
        self.assertTrue(beginner.blocking_is_off(after),
                        'following the Quick start turned blocking on')
        self.assertEqual(after.web.access_log_path, str(log))


class TestThePlatformTableClaimsOnlyWhatIsImplemented(unittest.TestCase):
    """§12. Only real supported behaviour."""

    def table(self):
        body = (ROOT / 'README.md').read_text(encoding='utf-8')
        section = body.split('## Which platform', 1)[1].split('\n## ', 1)[0]
        rows = {}
        for line in section.splitlines():
            cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
            if len(cells) == 3 and cells[0] not in ('Feature', '---'):
                rows[cells[0]] = (cells[1], cells[2])
        return rows

    def test_the_table_exists_and_covers_the_features_that_differ(self):
        rows = self.table()
        for feature in ('Packet capture', 'nftables enforcement',
                        'Autonomous host blocking', 'systemd service',
                        'Web access-log monitoring', 'Local demo'):
            self.assertIn(feature, rows)

    def test_it_says_no_to_windows_for_everything_the_code_guards(self):
        rows = self.table()
        for feature in ('Packet capture', 'nftables enforcement', 'systemd service'):
            self.assertTrue(rows[feature][1].startswith('No'),
                            f'{feature} is claimed on Windows')

    def test_the_code_really_does_guard_those(self):
        capture = (ROOT / 'eye_for_an_eye' / 'network' / 'capture.py').read_text(encoding='utf-8')
        self.assertIn('live analysis requires the Linux capture-helper IPC', capture)
        host = (ROOT / 'eye_for_an_eye' / 'security' / 'host_firewall.py').read_text(encoding='utf-8')
        self.assertIn('linux', host.lower())

    def test_the_web_path_really_does_work_on_both(self):
        """The one row that says Yes twice, checked rather than assumed."""
        web = ROOT / 'eye_for_an_eye' / 'web'
        for path in sorted(web.glob('*.py')):
            body = path.read_text(encoding='utf-8')
            for guard in ("sys.platform != 'linux'", 'sys.platform != "linux"'):
                self.assertNotIn(guard, body,
                                 f'{path.name} has a platform guard, so the table '
                                 f'claim that web monitoring works on Windows is wrong')


class TestEveryRelativeLinkInTheBeginnerDocumentationResolves(unittest.TestCase):
    """§111. The existing check walked docs/ only, so a broken link in
    START_HERE.md — `docs/DEVELOPMENT.md`, which has never existed — survived P17
    and the P16 clean-clone run."""

    def test_root_markdown_links_resolve(self):
        broken = []
        for name in ('README.md', 'START_HERE.md', 'SECURITY.md', 'CONTRIBUTING.md',
                     'CHANGELOG.md', 'ROADMAP.md', 'THIRD_PARTY_NOTICES.md'):
            path = ROOT / name
            if not path.is_file():
                continue
            for match in re.finditer(r'\[[^\]]*\]\(([^)#\s]+)(?:#[^)\s]*)?\)',
                                     path.read_text(encoding='utf-8')):
                link = match.group(1)
                if link.startswith(('http://', 'https://', 'mailto:')):
                    continue
                if not (path.parent / link).exists():
                    broken.append(f'{name} -> {link}')
        self.assertEqual(broken, [], 'broken relative links in the repository root')


class TestTheReleaseArtifactBuilders(unittest.TestCase):
    """§22-§24, §115. Built from the release root, verified against it."""

    def test_the_tarball_builder_verifies_against_the_release_root(self):
        body = (ROOT / 'scripts' / 'build_linux_tarball.py').read_text(encoding='utf-8')
        self.assertIn('def verify(', body)
        self.assertIn('content differs from the release root', body)
        self.assertIn('install.sh is not executable inside the archive', body)

    def test_the_tarball_builder_refuses_a_release_root_with_a_symlink(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        try:
            import build_linux_tarball
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'root'
            (fake / 'eye_for_an_eye').mkdir(parents=True)
            (fake / 'eye_for_an_eye' / '__init__.py').write_text(
                '__version__ = "0.0.0"\n', encoding='utf-8')
            for name in build_linux_tarball.AT_THE_TOP:
                (fake / name).write_text('x\n', encoding='utf-8')
            (fake / 'link').symlink_to(fake / 'README.md')
            with self.assertRaises(SystemExit):
                build_linux_tarball.build(fake, Path(directory) / 'out.tar.gz',
                                          'eye-for-an-eye-0.0.0')

    def test_the_deb_builder_keeps_no_configuration_and_enables_no_service(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        try:
            import build_deb
        finally:
            sys.path.pop(0)
        for body in (build_deb.POSTINST, build_deb.POSTRM):
            for forbidden in ('systemctl enable', 'systemctl start', 'rm -rf',
                              'curl', 'wget', 'nft ', 'userdel'):
                self.assertNotIn(forbidden, body)
        # The interpreter is named exactly, not left to an alternatives symlink.
        # The first version of this package used `#!/usr/bin/python3` and a
        # dependency on the `python3` metapackage; it installed onto a machine
        # whose python3 alternative pointed at 3.11 and every command ran under
        # the wrong interpreter.
        self.assertIn('#!/usr/bin/python3.12', build_deb.LAUNCHER)
        self.assertNotIn('#!/usr/bin/python3\n', build_deb.LAUNCHER)
        self.assertIn('Python 3.12', build_deb.LAUNCHER)
        self.assertIn('from eye_for_an_eye.cli import main', build_deb.LAUNCHER)

    def test_the_deb_units_are_derived_from_the_ones_in_deploy(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        try:
            import build_deb
        finally:
            sys.path.pop(0)
        for name in build_deb.UNITS:
            source = (ROOT / 'deploy' / 'systemd' / name).read_text(encoding='utf-8')
            packaged = build_deb.packaged_unit(source)
            self.assertNotIn('/opt/eye-for-an-eye/.venv', packaged)
            self.assertIn('/usr/bin/eye-for-an-eye', packaged)
            self.assertEqual(len(source.splitlines()), len(packaged.splitlines()))

    def test_the_deb_version_sorts_before_the_final_release(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        try:
            import build_deb
        finally:
            sys.path.pop(0)
        self.assertEqual(build_deb.debian_version('0.8.0rc1'), '0.8.0~rc1')
        self.assertEqual(build_deb.debian_version('0.8.0'), '0.8.0')

    def test_the_sbom_no_longer_says_the_licence_is_unapproved(self):
        body = (ROOT / 'scripts' / 'build_release.py').read_text(encoding='utf-8')
        self.assertNotIn("'value': 'not approved; release blocked'", body)
        self.assertIn("metadata['license']", body)


class TestTheSystemdUnitsStayHardened(unittest.TestCase):
    """§50. Reviewed, not added blindly — every directive here was already there."""

    REQUIRED = ('NoNewPrivileges=true', 'ProtectSystem=strict', 'ProtectHome=true',
                'PrivateTmp=true', 'RestrictSUIDSGID=true', 'LockPersonality=true',
                'MemoryDenyWriteExecute=true', 'ProtectKernelTunables=true',
                'ProtectKernelModules=true', 'ProtectControlGroups=true',
                'UMask=0077', 'TasksMax=', 'MemoryMax=', 'RestrictAddressFamilies=')

    def test_every_unit_keeps_every_directive(self):
        for path in sorted((ROOT / 'deploy' / 'systemd').glob('*.service')):
            body = path.read_text(encoding='utf-8')
            for directive in self.REQUIRED:
                with self.subTest(unit=path.name, directive=directive):
                    self.assertIn(directive, body)

    def test_only_the_capture_helper_has_a_capability(self):
        for path in sorted((ROOT / 'deploy' / 'systemd').glob('*.service')):
            body = path.read_text(encoding='utf-8')
            if path.name == 'eye-for-an-eye-capture.service':
                self.assertIn('AmbientCapabilities=CAP_NET_RAW', body)
                self.assertIn('CapabilityBoundingSet=CAP_NET_RAW', body)
            else:
                self.assertIn('AmbientCapabilities=\n', body + '\n')
                self.assertIn('CapabilityBoundingSet=\n', body + '\n')

    def test_no_unit_runs_as_root(self):
        for path in sorted((ROOT / 'deploy' / 'systemd').glob('*.service')):
            body = path.read_text(encoding='utf-8')
            self.assertNotIn('User=root', body)
            self.assertRegex(body, r'User=eye-for-an-eye')

    def test_no_unit_is_enabled_by_any_installation_path(self):
        for script in (INSTALLER, ROOT / 'install.sh',
                       ROOT / 'scripts' / 'install_windows.py'):
            self.assertNotIn('systemctl enable',
                             script.read_text(encoding='utf-8'))


def install_smoke_job():
    """The `install-smoke` job's text, read out of the workflow file.

    Read textually rather than with a YAML parser, because PyYAML is not a
    declared dependency of this project and a test that needed it would fail in a
    clean clone -- the environment these tests exist to speak for.
    """
    body = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
    lines = body.splitlines()
    start = next(i for i, line in enumerate(lines) if line == '  install-smoke:')
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r'^  \S', lines[i])), len(lines))
    return '\n'.join(lines[start:end])


def install_smoke_step(fragment):
    """One step of that job, chosen by a fragment of the command it runs.

    Scoped to a single step on purpose. The job legitimately contains
    `sudo nft list ruleset ... || true`, because a runner without nftables must
    not fail the firewall check, and a test that scanned the whole job for `||
    true` would read that as an evasion.
    """
    chunks = install_smoke_job().split('      - name: ')
    matching = [chunk for chunk in chunks if fragment in chunk]
    if len(matching) != 1:
        raise AssertionError(f'{len(matching)} install-smoke steps mention '
                             f'{fragment!r}; expected exactly one')
    return matching[0]


def commands_of(step):
    """A step with its YAML comments removed, so prose is not read as script.

    The doctor step's comment explains what a `|| true` would have hidden. A
    check for that string has to look at what the runner executes, not at the
    paragraph saying why it is absent.
    """
    return '\n'.join(line for line in step.splitlines()
                     if not line.lstrip().startswith('#'))


class TestContinuousIntegrationExpectsTheSafeProfilesRealAnswer(unittest.TestCase):
    """Why the first public CI run failed, and what stops it happening again.

    `doctor` exits 7 when any component is DEGRADED. The `install-smoke` job ran
    `eye-for-an-eye doctor` as a bare command under `set -e`, which asserts exit
    0, and that held only while the profile the installer writes was `website`:
    that profile has no `[autonomy]` section, so there was nothing to be degraded
    about. P18 changed the installed default to `production-shadow`, which runs
    the decision authority and therefore reports a missing calibrator on a fresh
    machine. From that moment the job asserted the opposite of the correct
    answer, and the first public push proved it.

    Two facts had to be read together to see it: which profile the installer
    writes, and what the CI step expects of it. Nothing connected them, so
    nothing failed until GitHub ran the job. These tests are that connection, in
    one place, so the next person to change either half hears it from a test run
    instead of from a public red build.
    """

    def test_the_installer_writes_a_profile_whose_fresh_doctor_is_degraded(self):
        self.assertIn('PROFILE="production-shadow"',
                      INSTALLER.read_text(encoding='utf-8'),
                      'the installed profile changed; the CI expectation below '
                      'has to be rechecked against it')
        template = (ROOT / 'eye_for_an_eye' / 'templates'
                    / 'production-shadow.toml').read_text(encoding='utf-8')
        self.assertIn('[autonomy]', template,
                      'the safe profile no longer constructs the authority, so a '
                      'fresh doctor may no longer be degraded')
        self.assertRegex(template, r'(?m)^\s*calibrator_path\s*=\s*""\s*$',
                         'the profile no longer ships an empty calibrator path, so '
                         'a fresh doctor may no longer report it as degraded')

    def test_the_install_smoke_job_expects_exit_seven_and_does_not_swallow_it(self):
        commands = commands_of(install_smoke_step('eye-for-an-eye doctor'))
        self.assertIn('-eq 7', commands,
                      'install-smoke does not assert the exit code a fresh '
                      'install of the safe profile actually produces')
        for evasion in ('|| true', '|| :', 'continue-on-error'):
            with self.subTest(evasion=evasion):
                self.assertNotIn(evasion, commands,
                                 'the doctor step tolerates a failure instead of '
                                 'asserting the outcome')

    def test_the_job_still_asserts_the_things_that_must_not_degrade(self):
        """Accepting exit 7 must not become accepting anything.

        A degraded database, configuration, security policy or config permission
        on a fresh install would be a real defect, so the step names each one it
        requires to be HEALTHY and exit 7 cannot become a blanket pass.
        """
        step = install_smoke_step('eye-for-an-eye doctor')
        for component in ('configuration', 'database', 'security_policy',
                          'config_permissions', 'decision_pipeline'):
            with self.subTest(component=component):
                self.assertIn(f"'{component}'", step)
        self.assertIn('HEALTHY', step)


class TestContinuousIntegrationRunsPytestSoTheRepositoryIsImportable(unittest.TestCase):
    """Why every CI pytest invocation must be `python -m pytest`.

    Python prepends the *script's* own directory to `sys.path` when it runs a
    script, and the *working* directory when it runs `-m`. A console-script entry
    point such as `<venv>/bin/pytest` is a script living in the environment, so
    under it the repository root is not on `sys.path`.

    This suite imports repository-local top-level modules that exist nowhere else:
    `dataset`, `training`, `benchmarks`, and `tests.<module>` for fixtures shared
    between test files. None of them is packaged - `pyproject.toml` installs
    `eye_for_an_eye*` and nothing more - so under the console script they are
    unimportable and collection fails wholesale. `eye_for_an_eye` itself is
    installed, which is why such a failure names those modules and not the
    package, and why it looks like many separate failures rather than one.

    The first public rc2 commit failed this way, with 32 collection errors. The
    fix is one word in the invocation; this test is what keeps the word there.
    """

    def workflows(self):
        found = sorted((ROOT / '.github' / 'workflows').glob('*.yml'))
        self.assertTrue(found, 'no workflow files were found to check')
        return found

    def test_no_workflow_runs_the_pytest_console_script(self):
        for path in self.workflows():
            for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if 'pytest' not in line or line.lstrip().startswith('#'):
                    continue
                with self.subTest(file=path.name, line=number):
                    self.assertIn('-m pytest', line,
                                  f'{path.name}:{number} runs pytest without `-m`, so '
                                  f'the repository root would not be on sys.path and '
                                  f'`dataset`, `training`, `benchmarks` and '
                                  f'`tests.<module>` would not import')

    def test_the_suite_really_does_import_those_repository_local_modules(self):
        """The reason the rule exists, asserted rather than assumed.

        If this stopped being true the rule above would be cargo cult, so it is
        checked: at least one test module imports each of these by name.
        """
        bodies = {path: path.read_text(encoding='utf-8')
                  for path in sorted((ROOT / 'tests').glob('test_*.py'))}
        for module in ('dataset', 'training', 'benchmarks', 'tests.'):
            with self.subTest(module=module):
                importers = [path.name for path, body in bodies.items()
                             if re.search(rf'(?m)^\s*(from|import)\s+{re.escape(module)}', body)]
                self.assertTrue(importers,
                                f'nothing imports {module!r} any more; the sys.path '
                                f'rule above may no longer be needed')


if __name__ == '__main__':
    unittest.main()
