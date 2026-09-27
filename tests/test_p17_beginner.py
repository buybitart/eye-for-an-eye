"""The beginner layer must be easy and must not be a way round anything. P17 §45.

The point of this file is the second half. A friendly wrapper is the obvious
place for a safety control to quietly stop applying: it has its own code path, it
is written to make things pleasant, and the tests people write for it tend to
check that the words are nice. So most of what is below asserts that the wrapper
did *not* acquire an opinion of its own.
"""
from pathlib import Path
import io
import json
import sys
import tempfile
import time
import unittest
import unittest.mock

from eye_for_an_eye import beginner
from eye_for_an_eye.configuration import initialize
from eye_for_an_eye.config import load_config

ROOT = Path(__file__).resolve().parents[1]


def _shadow_config(directory, profile=beginner.SAFE_PROFILE):
    path = Path(directory) / 'beginner.toml'
    initialize(str(path), profile)
    return path


class TestTheInstallerCannotTurnOnBlocking(unittest.TestCase):
    """§6, §45. The installed default is checked against the written file."""

    def setUp(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(lambda: sys.path.remove(str(ROOT / 'scripts')))
        import install_windows
        self.installer = install_windows

    def test_the_installer_and_the_runtime_agree_on_the_safe_profile(self):
        """Two constants naming one thing is how they drift apart."""
        self.assertEqual(self.installer.SAFE_PROFILE, beginner.SAFE_PROFILE)

    def test_the_profile_the_installer_writes_blocks_nothing(self):
        with tempfile.TemporaryDirectory() as workspace:
            path = _shadow_config(workspace, self.installer.SAFE_PROFILE)
            problems = self.installer.verify(Path(workspace), path)
            self.assertEqual(problems, [], f'the safe profile is not safe: {problems}')

    def test_the_installer_refuses_a_configuration_that_would_block(self):
        """The check must fail on the enforcing profile, or it checks nothing."""
        with tempfile.TemporaryDirectory() as workspace:
            path = _shadow_config(workspace, 'production-autonomous')
            problems = self.installer.verify(Path(workspace), path)
            self.assertTrue(problems,
                            'verify() passed a profile that enables host enforcement')

    def test_a_missing_configuration_is_a_problem_and_not_a_pass(self):
        with tempfile.TemporaryDirectory() as workspace:
            problems = self.installer.verify(Path(workspace),
                                             Path(workspace) / 'absent.toml')
            self.assertTrue(problems)

    def test_the_installer_never_mentions_elevation_as_a_requirement(self):
        """§39, §40. It must not ask for Administrator, and must not advise it."""
        body = (ROOT / 'scripts' / 'install_windows.py').read_text(encoding='utf-8')
        lowered = body.lower()
        for forbidden in ('runas', 'shellexecute', 'requireadministrator',
                          'run as administrator'):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, lowered)

    def test_the_installer_downloads_nothing(self):
        """§5. It may name python.org in a message; it may not fetch anything."""
        body = (ROOT / 'scripts' / 'install_windows.py').read_text(encoding='utf-8')
        for forbidden in ('urllib.request', 'urlopen', 'requests.get', 'curl ',
                          'Invoke-WebRequest', 'certutil'):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, body)


class TestSafeStartIsActuallySafe(unittest.TestCase):
    """§7, §21. `start` is the beginner door and it does not open onto blocking."""

    def test_the_shadow_profile_reports_blocking_off(self):
        with tempfile.TemporaryDirectory() as workspace:
            config = load_config(str(_shadow_config(workspace)))
            self.assertTrue(beginner.blocking_is_off(config))

    def test_the_enforcing_profile_reports_blocking_on(self):
        """If this ever says off, the beginner status is lying."""
        with tempfile.TemporaryDirectory() as workspace:
            path = _shadow_config(workspace, 'production-autonomous')
            config = load_config(str(path), validate=False)
            self.assertFalse(beginner.blocking_is_off(config))

    def test_start_refuses_a_configuration_with_blocking_switched_on(self):
        """It refuses — and the refusal comes from the existing gate, not from here.

        Written expecting `start`'s own "this has blocking on" message, this test
        found something better: `config.validate()` raises first, because the
        shipped autonomous profile has no management network and the configuration
        layer refuses it outright. The beginner layer never gets as far as its own
        opinion, which is the correct order. Its job is then only to say the
        existing refusal in words a beginner can act on.
        """
        with tempfile.TemporaryDirectory() as workspace:
            path = _shadow_config(workspace, 'production-autonomous')
            captured = io.StringIO()
            with unittest.mock.patch.object(sys, 'stderr', captured):
                code = beginner.start_command(['--config', str(path)])
            text = captured.getvalue()
            self.assertNotEqual(code, 0, 'start accepted an enforcing configuration')
            self.assertNotIn('Traceback', text)
            self.assertIn('will not start', text)
            self.assertIn('lock you out', text)

    def test_start_refuses_an_enforcing_configuration_that_does_validate(self):
        """The branch above never reaches: this is the one that tests it.

        A configuration with host enforcement on, a management network set *and*
        the calibrator present validates. `start` must still refuse it, because
        `start` is the beginner door and the beginner door does not open onto
        enforcement.

        Getting this configuration to validate at all took three steps — the
        management network, then the calibrator file, each refused in turn. That is
        the shape of the gate, and it is worth seeing from the outside.
        """
        import shutil

        with tempfile.TemporaryDirectory() as workspace:
            path = _shadow_config(workspace, 'production-autonomous')
            body = path.read_text(encoding='utf-8').replace(
                'management_networks = []', 'management_networks = ["192.0.2.0/24"]')
            path.write_text(body, encoding='utf-8')
            shutil.copy2(ROOT / 'models' / 'mathrisk-cal-v4-isotonic.json',
                         Path(workspace) / 'mathrisk-cal-v4-isotonic.json')
            load_config(str(path)).validate()          # it really does validate now
            captured = io.StringIO()
            with unittest.mock.patch.object(sys, 'stderr', captured):
                code = beginner.start_command(['--config', str(path)])
            self.assertNotEqual(code, 0, 'start accepted an enforcing configuration')
            self.assertIn('Safe Monitoring', captured.getvalue())

    def test_start_without_a_traffic_source_explains_rather_than_starting(self):
        with tempfile.TemporaryDirectory() as workspace:
            path = _shadow_config(workspace)
            captured = io.StringIO()
            with unittest.mock.patch.object(sys, 'stderr', captured):
                code = beginner.start_command(['--config', str(path)])
            text = captured.getvalue()
            self.assertNotEqual(code, 0)
            self.assertIn('does not know where to watch', text)
            self.assertNotIn('Traceback', text)


class TestExpectedErrorsDoNotDumpATraceback(unittest.TestCase):
    """§11. A beginner sees three sentences; --debug still raises."""

    def test_every_known_problem_answers_all_three_questions(self):
        for fragment, _answer in beginner.KNOWN_PROBLEMS:
            with self.subTest(fragment=fragment[:40]):
                what, safe, steps = beginner.plain(RuntimeError(fragment))
                self.assertTrue(what and safe and steps)
                self.assertNotIn('Traceback', what)

    def test_an_unknown_problem_admits_that_it_is_unknown(self):
        """Inventing an explanation is worse than a traceback, not better."""
        what, safe, steps = beginner.plain(RuntimeError('quantum flux capacitor'))
        self.assertIn('did not expect', what)
        self.assertIn('quantum flux capacitor', ' '.join(steps))

    def test_the_management_network_refusal_is_explained_and_not_worked_around(self):
        """§18, §21. The refusal keeps its meaning in beginner words."""
        what, safe, steps = beginner.plain(
            ValueError('enforcement.host_enabled requires at least one protected '
                       'network: set enforcement.management_networks'))
        joined = ' '.join([what, safe] + steps).lower()
        self.assertIn('will not start', joined)
        self.assertIn('lock you out', joined)
        self.assertIn('cannot be skipped', joined)

    def test_debug_re_raises_instead_of_translating(self):
        """§11. The friendly message is the default, not the only option."""
        with tempfile.TemporaryDirectory() as workspace:
            path = _shadow_config(workspace)
            path.write_text('this is not valid TOML at all [[[', encoding='utf-8')
            with self.assertRaises(Exception):
                beginner.status_command(['--config', str(path)], debug=True)
            captured = io.StringIO()
            with unittest.mock.patch.object(sys, 'stderr', captured):
                code = beginner.status_command(['--config', str(path)])
            self.assertEqual(code, 2)
            self.assertNotIn('Traceback', captured.getvalue())
            self.assertIn('What happened', captured.getvalue())


class TestTheBeginnerStatusTellsTheTruth(unittest.TestCase):
    """§8, §9. It may be shorter than `doctor`; it may not be sunnier."""

    def test_it_reports_needs_setup_when_no_source_is_chosen(self):
        with tempfile.TemporaryDirectory() as workspace:
            summary = beginner.summarise(str(_shadow_config(workspace)))
            self.assertEqual(summary['state'], beginner.NEEDS_SETUP)
            self.assertEqual(summary['blocking'], 'OFF')

    def test_it_says_blocking_is_off_in_the_rendered_view(self):
        with tempfile.TemporaryDirectory() as workspace:
            screen = beginner.render(beginner.summarise(str(_shadow_config(workspace))))
            self.assertIn('Automatic blocking: OFF', screen)

    def test_it_uses_only_the_four_beginner_health_words(self):
        """§9. `DEGRADED` and `OOD` belong in the expert view, not this one."""
        with tempfile.TemporaryDirectory() as workspace:
            screen = beginner.render(beginner.summarise(str(_shadow_config(workspace))))
            for jargon in ('DEGRADED', 'OOD', 'calibrator', 'schema', 'FeatureVector',
                           'nftables', 'ONNX'):
                with self.subTest(term=jargon):
                    self.assertNotIn(jargon, screen)

    def test_a_missing_configuration_is_needs_setup_and_not_a_crash(self):
        with tempfile.TemporaryDirectory() as workspace:
            summary = beginner.summarise(str(Path(workspace) / 'absent.toml'))
            self.assertEqual(summary['state'], beginner.NEEDS_SETUP)

    def test_it_points_at_the_expert_view_rather_than_replacing_it(self):
        with tempfile.TemporaryDirectory() as workspace:
            screen = beginner.render(beginner.summarise(str(_shadow_config(workspace))))
            self.assertIn('eye-for-an-eye doctor', screen)


class TestStopActuallyStops(unittest.TestCase):
    """P17W §12. A button called Stop that does not stop is forbidden.

    The first version printed "press Ctrl+C" and returned 0, which is a label
    rather than a feature. These tests hold the fix in place, and hold the shape
    of the fix: cooperative, never a signal to a process id.
    """

    def test_stopping_is_cooperative_and_signals_no_process(self):
        """The safety property, checked on the import graph and the source.

        A pid read from a file is one PID reuse away from terminating an
        unrelated program, and on Windows there is no cheap way to prove a pid is
        still yours. So `beginner.py` must not reach for process termination at
        all — not `os.kill`, not `taskkill`, not `psutil`, not `SIGTERM`.
        """
        body = (ROOT / 'eye_for_an_eye' / 'beginner.py').read_text(encoding='utf-8')
        for forbidden in ('os.kill', 'taskkill', 'SIGTERM', 'SIGKILL', 'psutil',
                          '.terminate()', '.kill()', 'pkill'):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, body,
                                 'stop must never act on a process id')

    def test_stop_reports_nothing_to_stop_when_nothing_runs(self):
        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace) / 'eye-for-an-eye'
            target.mkdir(parents=True)
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=target):
                captured = io.StringIO()
                with unittest.mock.patch.object(sys, 'stdout', captured):
                    code = beginner.stop_command([])
            self.assertEqual(code, 0)
            self.assertIn('not watching', captured.getvalue())

    def test_stop_writes_the_request_and_confirms_when_the_marker_clears(self):
        """The success path: it waits for the watcher to clear its own marker."""
        import threading

        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace) / 'eye-for-an-eye'
            target.mkdir(parents=True)
            marker = target / 'watching.json'
            marker.write_text('{"pid": 1}', encoding='utf-8')

            def pretend_to_be_the_watcher():
                for _ in range(100):
                    if (target / 'stop-requested').is_file():
                        marker.unlink()
                        return
                    time.sleep(0.05)

            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=target):
                watcher = threading.Thread(target=pretend_to_be_the_watcher)
                watcher.start()
                captured = io.StringIO()
                with unittest.mock.patch.object(sys, 'stdout', captured):
                    code = beginner.stop_command(['--wait', '10'])
                watcher.join(timeout=10)
            self.assertEqual(code, 0, 'stop did not confirm the stop')
            self.assertIn('Stopped', captured.getvalue())
            self.assertFalse(marker.exists())

    def test_stop_says_so_and_does_not_escalate_when_nothing_answers(self):
        """The failure path must not become a kill. It reports and leaves."""
        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace) / 'eye-for-an-eye'
            target.mkdir(parents=True)
            (target / 'watching.json').write_text('{"pid": 999999}', encoding='utf-8')
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=target):
                captured = io.StringIO()
                with unittest.mock.patch.object(sys, 'stdout', captured):
                    code = beginner.stop_command(['--wait', '1'])
            text = captured.getvalue()
            self.assertEqual(code, 1, 'an unstopped watcher must not report success')
            self.assertIn('has not stopped yet', text)
            self.assertIn('Nothing is blocked', text)
            self.assertTrue((target / 'stop-requested').is_file(),
                            'the request should stay so it stops at its next look')

    def test_the_watching_loop_looks_for_the_request(self):
        """Both halves must exist, or the request is written and never read."""
        body = (ROOT / 'eye_for_an_eye' / 'beginner.py').read_text(encoding='utf-8')
        self.assertIn('if request.is_file():', body)
        self.assertIn('asked_to_stop', body)


class TestUninstallIsConservative(unittest.TestCase):
    """§28. It removes the program. It does not remove the user's records."""

    def test_it_changes_nothing_without_an_explicit_yes(self):
        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace) / 'eye-for-an-eye'
            (target / 'runtime').mkdir(parents=True)
            (target / 'data').mkdir()
            (target / 'eye-for-an-eye.toml').write_text('x', encoding='utf-8')
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=target):
                with unittest.mock.patch.object(sys, 'stdout', io.StringIO()):
                    beginner.uninstall_command([])
            self.assertTrue((target / 'runtime').is_dir(), 'a dry run removed something')
            self.assertTrue((target / 'data').is_dir())

    def test_it_keeps_records_and_settings_by_default(self):
        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace) / 'eye-for-an-eye'
            (target / 'runtime').mkdir(parents=True)
            (target / 'data').mkdir()
            settings = target / 'eye-for-an-eye.toml'
            settings.write_text('x', encoding='utf-8')
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=target):
                with unittest.mock.patch.object(sys, 'stdout', io.StringIO()):
                    beginner.uninstall_command(['--yes'])
            self.assertFalse((target / 'runtime').exists(), 'the program was not removed')
            self.assertTrue((target / 'data').is_dir(), 'records were removed silently')
            self.assertTrue(settings.is_file(), 'settings were removed silently')

    def test_it_touches_nothing_outside_its_own_directory(self):
        with tempfile.TemporaryDirectory() as workspace:
            target = Path(workspace) / 'eye-for-an-eye'
            (target / 'runtime').mkdir(parents=True)
            unrelated = Path(workspace) / 'my-important-folder'
            unrelated.mkdir()
            (unrelated / 'keep.txt').write_text('keep', encoding='utf-8')
            with unittest.mock.patch.object(beginner, 'application_directory',
                                            return_value=target):
                with unittest.mock.patch.object(sys, 'stdout', io.StringIO()):
                    beginner.uninstall_command(['--yes', '--also-remove-my-records'])
            self.assertTrue((unrelated / 'keep.txt').is_file())


class TestTheExpertInterfacesAreUntouched(unittest.TestCase):
    """§46. P17 adds a layer; it removes nothing."""

    def test_every_previous_command_is_still_registered(self):
        from eye_for_an_eye.cli import COMMANDS
        for command in ('doctor', 'status', 'run', 'demo', 'config', 'autonomy',
                        'web', 'setup', 'model', 'sites', 'challenge', 'simulate',
                        'analyze-pcap', 'firewall', 'capture-helper'):
            with self.subTest(command=command):
                self.assertIn(command, COMMANDS)

    def test_the_beginner_commands_were_added(self):
        from eye_for_an_eye.cli import COMMANDS
        for command in ('start', 'stop', 'easy', 'check-install'):
            with self.subTest(command=command):
                self.assertIn(command, COMMANDS)

    def test_the_beginner_layer_holds_no_security_logic_of_its_own(self):
        """§17, §21. It must not compute a verdict the real code already computes.

        Checked on the module's *imports* rather than on its text. The first
        version of this test matched substrings anywhere in the file and failed on
        the word "calibrator" inside a docstring — a check that forbids naming a
        thing in prose makes the code harder to explain without making it safer.
        What matters is what the module can reach, and that is its import graph.
        """
        import ast

        source = (ROOT / 'eye_for_an_eye' / 'beginner.py').read_text(encoding='utf-8')
        reached = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                reached.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                reached.add(('.' * node.level) + (node.module or ''))
                reached.update(('.' * node.level) + (node.module or '') + '.' + alias.name
                               for alias in node.names)
        forbidden = ('.security.firewall', '.security.host_firewall',
                     '.autonomy.authority', '.autonomy.breakers', '.decision.math_risk',
                     '.autonomy.calibrator', '.decision.composition')
        for name in forbidden:
            with self.subTest(module=name):
                self.assertFalse(any(name in entry for entry in reached),
                                 f'the beginner layer reaches {name} directly')

    def test_it_reaches_the_expert_code_for_every_verdict_it_reports(self):
        """The other half: it must not be deciding on its own either."""
        source = (ROOT / 'eye_for_an_eye' / 'beginner.py').read_text(encoding='utf-8')
        for required in ('from .config import load_config', 'from . import operations',
                         'config.validate()'):
            with self.subTest(call=required):
                self.assertIn(required, source)


class TestTheBeginnerDocumentsExistAndStayShort(unittest.TestCase):
    """§12, §13, §14, §44. Checked as properties, because prose drifts."""

    START = ROOT / 'START_HERE.md'
    GUIDE = ROOT / 'docs' / 'BEGINNER_GUIDE.md'

    def test_both_documents_are_published(self):
        self.assertTrue(self.START.is_file())
        self.assertTrue(self.GUIDE.is_file())

    def test_start_here_is_about_one_screen_before_the_detail(self):
        """§12. Everything before the first '---' must fit on a screen."""
        first = self.START.read_text(encoding='utf-8').split('\n---\n', 1)[0]
        self.assertLess(len(first.splitlines()), 26,
                        'the opening of START_HERE.md no longer fits one screen')

    def test_start_here_uses_numbered_steps(self):
        """Numbered, in order, and enough of them to be the whole path.

        P18 rewrote the page Linux-first and changed the notation from
        `## Step 1 — Install` to `### 1. Check the download`. The property the
        original test was defending is that a beginner is walked through numbered
        steps, so that is what this checks — the numbers and their order, not one
        particular way of writing them. It asks for more steps than the original
        did, because the Linux path has more.
        """
        import re
        body = self.START.read_text(encoding='utf-8')
        numbers = [int(match.group(1)) for match in
                   re.finditer(r'^#{2,3} (?:Step )?(\d+)[.\s]', body, re.MULTILINE)]
        self.assertGreaterEqual(len(numbers), 5,
                                'START_HERE.md no longer walks through numbered steps')
        self.assertEqual(numbers, sorted(numbers), 'the steps are out of order')
        self.assertEqual(numbers[0], 1, 'the steps do not start at 1')

    def test_neither_document_requires_python_or_git_knowledge(self):
        """§2, §32, §36. The words a beginner must not have to meet."""
        for page in (self.START, self.GUIDE):
            body = page.read_text(encoding='utf-8')
            for jargon in ('python -m venv', 'python3 -m venv', 'virtualenv',
                           '/activate', 'pip install', 'PYTHONPATH', 'git clone',
                           'nftables', 'FeatureVector', 'MathRisk', 'ONNX', 'OOD'):
                with self.subTest(page=page.name, term=jargon):
                    self.assertNotIn(jargon, body)

    def test_a_beginner_is_never_asked_to_understand_a_virtual_environment(self):
        """The rule behind the word, rather than the word.

        P18 needed two mentions of "venv" in the guide and neither asks the
        reader to know anything:

        * `sudo apt install python3.12 python3.12-venv` — a package name. Leave it
          out and `python3 -m venv` fails on Ubuntu, so the beginner gets a broken
          install to protect a word.
        * `~/.local/share/eye-for-an-eye/venv` — where the program is. A path.

        Anything else is the concept leaking in, which is what §2 forbids.
        """
        import re
        allowed = ('python3.12-venv', '/venv`', '/venv |', '/venv\n')
        for page in (self.START, self.GUIDE):
            body = page.read_text(encoding='utf-8')
            for match in re.finditer(r'\S*venv\S*', body):
                word = match.group(0)
                with self.subTest(page=page.name, word=word):
                    self.assertTrue(
                        any(form.strip() in word or word.endswith('/venv')
                            for form in allowed),
                        f'{page.name} uses "{word}", which asks the reader to know '
                        f'what a virtual environment is')

    def test_the_sentences_are_short(self):
        """§44. Long sentences are where one action per step goes wrong."""
        import re
        for page in (self.START, self.GUIDE):
            body = page.read_text(encoding='utf-8')
            prose = [line for line in body.splitlines()
                     if line and not line.startswith(('#', '|', '```', '    ', '*', '>'))]
            long_ones = [line for line in prose
                         for sentence in re.split(r'(?<=[.!?])\s+', line)
                         if len(sentence.split()) > 34]
            self.assertEqual(long_ones, [],
                             f'{page.name} has sentences too long for a beginner: '
                             f'{long_ones[:2]}')

    def test_they_say_blocking_is_off_and_say_it_early(self):
        """§6. The most important fact must not be buried.

        Emphasis markers are stripped first: the sentence reads "does **not**
        block anyone", and a check that cannot see through bold would force the
        prose to be written around the test.
        """
        opening = self.START.read_text(encoding='utf-8')[:500]
        plain_text = opening.replace('*', '').replace('_', '').lower()
        self.assertIn('not block', plain_text)
        self.assertIn('blocking is off', plain_text)

    def test_the_autonomous_warning_is_not_made_childish(self):
        """§44. Simple steps, precise warnings. These are different jobs.

        Emphasis is stripped before matching, for the same reason as above: the
        guide writes "has **not** been tested", and prose should not have to be
        bent around a check that cannot see through bold.
        """
        body = (self.GUIDE.read_text(encoding='utf-8')
                .replace('*', '').replace('_', ' ').lower())
        for precise in ('lock you out', 'temporary', 'never', 'not been tested',
                        'no way for them to appeal'):
            with self.subTest(term=precise):
                self.assertIn(precise, body)

    def test_the_readme_offers_both_paths_near_the_top(self):
        """§34, §35."""
        body = (ROOT / 'README.md').read_text(encoding='utf-8')
        top = body[:2600]
        self.assertIn('START_HERE.md', top)
        self.assertIn('BEGINNER_GUIDE.md', top)
        self.assertIn('I want to develop it', top)


class TestTheLaunchersOnlyBootstrap(unittest.TestCase):
    """§4, §15. A .cmd file holds no logic that could disagree with the CLI."""

    LAUNCHERS = ('Install-EyeForAnEye.cmd', 'Start-EyeForAnEye.cmd',
                 'Status-EyeForAnEye.cmd', 'Demo-EyeForAnEye.cmd',
                 'Stop-EyeForAnEye.cmd', 'Uninstall-EyeForAnEye.cmd')

    def test_they_all_exist(self):
        for name in self.LAUNCHERS:
            with self.subTest(name=name):
                self.assertTrue((ROOT / name).is_file())

    def test_they_are_short_enough_to_hold_no_logic(self):
        """Statements, not output lines.

        The first version counted every non-comment line, and failed the moment
        the Install launcher gained a friendly several-line error message. A
        message is not logic: counting it pushes a launcher towards terse
        unhelpful output to satisfy a test, which is the opposite of what this
        whole phase is for. `echo` and `pause` are excluded.
        """
        for name in self.LAUNCHERS:
            with self.subTest(name=name):
                lines = (ROOT / name).read_text(encoding='utf-8').splitlines()
                statements = [
                    line for line in lines
                    if line.strip()
                    and not line.strip().lower().startswith(('rem', '@', 'echo', 'pause', ')'))
                ]
                self.assertLess(len(statements), 25,
                                f'{name} is growing logic of its own')

    def test_no_launcher_configures_anything(self):
        """A launcher that edits configuration is a second installer."""
        for name in self.LAUNCHERS:
            body = (ROOT / name).read_text(encoding='utf-8')
            for forbidden in ('host_enabled', 'management_networks', 'config init',
                              'autonomy', 'firewall', 'netsh', 'reg add'):
                with self.subTest(name=name, term=forbidden):
                    self.assertNotIn(forbidden, body)

    def test_the_action_launchers_call_the_installed_cli(self):
        for name in self.LAUNCHERS[1:]:
            with self.subTest(name=name):
                body = (ROOT / name).read_text(encoding='utf-8')
                self.assertIn('eye-for-an-eye.exe', body)

    def test_the_install_launcher_hands_over_to_the_python_installer(self):
        body = (ROOT / 'Install-EyeForAnEye.cmd').read_text(encoding='utf-8')
        self.assertIn('scripts\\install_windows.py', body)

    def test_the_install_launcher_works_in_the_archive_layout_too(self):
        """P17W §15, §16. The bug this test exists for.

        The beginner archive puts the launchers at the top and the project under
        `app/`, so a launcher that only looks for `scripts\\install_windows.py`
        finds nothing when a person unzips the download and double-clicks. That is
        what happened: the archive was built, unpacked, and the very first click
        of the beginner flow would have failed. Static review had passed it twice.
        """
        body = (ROOT / 'Install-EyeForAnEye.cmd').read_text(encoding='utf-8')
        self.assertIn('app\\scripts\\install_windows.py', body,
                      'the launcher cannot find the installer in the release archive')
        self.assertIn('EFAE_INSTALLER', body)

    def test_the_release_root_would_carry_them(self):
        """§47. Assembled by the one assembler, not hand-copied."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            '_build_prod_p17', ROOT / 'scripts' / 'build_prod.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ('START_HERE.md',) + self.LAUNCHERS:
            with self.subTest(name=name):
                self.assertIn(name, module.INCLUDE)


if __name__ == '__main__':
    unittest.main()
