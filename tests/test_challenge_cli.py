"""P11 operator commands: what a person sees, and what they must never see.

Two properties are load-bearing here and are asserted on real output rather than
on the code that produces it:

* No secret and no token ever reaches a terminal, a log, or a JSON document.
  `challenge test` signs a token and checks six things about it without ever
  printing it — an operator who pastes the output into a bug report has not
  handed anyone a valid bypass.
* `doctor` never fails the way an operator most fears. It reads; it makes no
  request, reloads nothing and changes nothing, and it exits 0 when challenges
  are simply switched off, because "off" is a supported state, not a fault.
"""
import json
import os
import stat
import unittest
from pathlib import Path
import tempfile

from eye_for_an_eye import challenge_cli
from eye_for_an_eye.challenge_cli import (DEGRADED, DISABLED, HEALTHY, NOT_CONFIGURED,
                                          UNAVAILABLE, challenge_command, doctor, render)
from eye_for_an_eye.cli import COMMANDS
from eye_for_an_eye.config import load_config


def write_config(directory, *, enabled=True, mode='shadow', secret=True,
                 site_id='blog.example', web=True, extra=''):
    """A real configuration file, loaded through the real loader."""
    root = Path(directory)
    lines = ['[challenge]', f'enabled = {"true" if enabled else "false"}',
             f'mode = "{mode}"', f'site_id = "{site_id}"']
    if secret:
        secret_file = root / 'challenge.secret'
        secret_file.write_bytes(os.urandom(48).hex().encode())
        secret_file.chmod(0o600)
        lines.append(f'secret_file = "{secret_file}"')
    if extra:
        lines.append(extra)
    if web:
        access_log = root / 'access.log'
        access_log.touch()
        lines += ['', '[web]', 'enabled = true',
                  f'access_log_path = "{access_log}"']
    path = root / 'eye-for-an-eye.toml'
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return path


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def config(self, **kwargs):
        return load_config(str(write_config(self.root, **kwargs)))

    def invoke(self, argv, path):
        """Run a subcommand against an existing config, capturing both streams.

        Deliberately separate from writing the configuration: a helper that
        rewrote the files on every call would quietly defeat the read-only tests
        below, which compare the directory before and after.
        """
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = challenge_command([*argv, '--config', str(path)])
        return code, out.getvalue(), err.getvalue()

    def run_command(self, *argv, **kwargs):
        """Write a configuration and run a subcommand against it."""
        return self.invoke(argv, write_config(self.root, **kwargs))


class TestRouting(Base):
    def test_challenge_is_a_routed_command(self):
        self.assertIn('challenge', COMMANDS)

    def test_the_router_reaches_the_challenge_module(self):
        from eye_for_an_eye.cli import main
        with self.assertRaises(SystemExit) as raised:
            main(['challenge', '--help'])
        self.assertEqual(raised.exception.code, 0)

    def test_an_unknown_action_is_refused_rather_than_guessed(self):
        with self.assertRaises(SystemExit):
            challenge_command(['unblock-everything'])


class TestDoctor(Base):
    def test_a_healthy_configuration_reports_healthy(self):
        report = doctor(self.config())
        self.assertEqual(report['challenge']['status'], HEALTHY)
        self.assertEqual(report['secret']['status'], HEALTHY)
        self.assertEqual(report['token']['status'], HEALTHY)
        self.assertTrue(report['token']['scope_isolated'])

    def test_the_headline_names_the_check_that_produced_it(self):
        """Otherwise an operator hunts through the wrong section of the report."""
        report = doctor(self.config(web=False))
        self.assertEqual(report['challenge']['status'], NOT_CONFIGURED)
        self.assertIn('trusted_proxy', report['challenge']['reason'])
        self.assertIn('trusted_proxy', render(report).split('Secret:')[0])

    def test_challenges_switched_off_is_a_state_not_a_fault(self):
        report = doctor(self.config(enabled=False))
        self.assertEqual(report['challenge']['status'], DISABLED)
        code, printed, _ = self.run_command('doctor', enabled=False)
        self.assertEqual(code, 0)
        self.assertIn('Disabled', printed)

    def test_a_missing_secret_is_named_with_the_command_that_creates_one(self):
        report = doctor(self.config(secret=False))
        self.assertEqual(report['secret']['status'], NOT_CONFIGURED)
        self.assertIn('chmod 600', report['secret']['action'])

    def test_a_world_readable_secret_is_reported_and_not_used_silently(self):
        path = write_config(self.root)
        secret_file = self.root / 'challenge.secret'
        secret_file.chmod(0o644)
        report = doctor(load_config(str(path)))
        self.assertEqual(report['secret']['status'], DEGRADED)
        self.assertIn('chmod 600', report['secret']['action'])
        self.assertNotEqual(report['challenge']['status'], HEALTHY)

    def test_a_secret_file_that_is_not_there_is_unavailable_not_a_crash(self):
        path = write_config(self.root)
        (self.root / 'challenge.secret').unlink()
        report = doctor(load_config(str(path)))
        self.assertEqual(report['secret']['status'], UNAVAILABLE)

    def test_a_short_secret_is_degraded(self):
        path = write_config(self.root)
        (self.root / 'challenge.secret').write_bytes(b'short')
        report = doctor(load_config(str(path)))
        self.assertEqual(report['secret']['status'], DEGRADED)

    def test_the_default_site_identifier_is_flagged_on_a_shared_server(self):
        report = doctor(self.config(site_id='default'))
        self.assertEqual(report['site_scope']['status'], NOT_CONFIGURED)
        self.assertIn('more than', report['site_scope']['action'])

    def test_a_cookie_without_secure_is_degraded_with_the_reason(self):
        report = doctor(self.config(extra='cookie_secure = false'))
        self.assertEqual(report['cookie']['status'], DEGRADED)
        self.assertIn('HTTPS', report['cookie']['action'])

    def test_the_routes_never_challenged_are_listed_for_a_person_to_check(self):
        never = doctor(self.config())['routes']['never_challenged']
        for route in ('/api/', '/health', '/webhook'):
            self.assertIn(route, never)

    def test_the_report_says_the_subsystem_cannot_take_the_site_down(self):
        reason = doctor(self.config())['fail_safe']['reason']
        self.assertIn('offline', reason)

    def test_a_doctor_report_is_json_serialisable(self):
        json.dumps(doctor(self.config()))

    def test_the_exit_code_is_two_only_when_something_is_actually_broken(self):
        healthy, _, _ = self.run_command('doctor')
        self.assertEqual(healthy, 0)
        write_config(self.root)
        (self.root / 'challenge.secret').unlink()
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            broken = challenge_command(['doctor', '--config',
                                        str(self.root / 'eye-for-an-eye.toml')])
        self.assertEqual(broken, 2)


class TestNothingSecretIsEverPrinted(Base):
    """The property that makes this output safe to paste into a bug report."""

    def secret_text(self):
        return (self.root / 'challenge.secret').read_bytes().decode()

    def test_the_secret_never_appears_in_any_subcommand(self):
        write_config(self.root)
        secret = self.secret_text()
        for action in ('doctor', 'status', 'stats', 'test'):
            _, printed, errors = self.run_command(action)
            self.assertNotIn(secret, printed, action)
            self.assertNotIn(secret, errors, action)
            self.assertNotIn(secret[:16], printed, action)

    def test_the_secret_never_appears_in_json_output(self):
        write_config(self.root)
        secret = self.secret_text()
        for action in ('doctor', 'status', 'stats', 'test'):
            _, printed, _ = self.run_command(action, '--json')
            self.assertNotIn(secret, printed, action)
            self.assertNotIn(secret[:16], printed, action)

    def test_the_secret_file_path_is_not_echoed_by_status(self):
        _, printed, _ = self.run_command('status')
        self.assertNotIn('challenge.secret', printed)

    def test_the_self_test_signs_a_token_and_still_does_not_print_it(self):
        from eye_for_an_eye.challenge.service import load_secret
        from eye_for_an_eye.challenge.token import issue
        config = self.config()
        secret = load_secret(config.challenge.secret_file)
        token = issue(secret, site=config.challenge.site_id)
        _, printed, _ = self.run_command('test')
        self.assertIn('all checks passed', printed)
        self.assertIn('not printed', printed)
        # The exact token differs per run (random nonce), so assert on the two
        # parts that would be stable and damaging: the signature alphabet in
        # bulk, and any long base64url run at all.
        self.assertNotIn(token, printed)
        for chunk in printed.split():
            self.assertLess(len(chunk.strip('.,')), 40,
                            f'a long opaque string reached the terminal: {chunk[:20]}...')

    def test_a_rendered_doctor_report_carries_no_long_opaque_strings(self):
        text = render(doctor(self.config()))
        for chunk in text.split():
            self.assertLess(len(chunk), 60, chunk[:20])


class TestSelfTest(Base):
    def test_all_six_local_checks_pass_on_a_healthy_configuration(self):
        code, printed, _ = self.run_command('test', '--json')
        document = json.loads(printed)
        self.assertTrue(document['passed'])
        self.assertEqual(len(document['checks']), 6)
        self.assertTrue(all(document['checks'].values()))
        self.assertEqual(code, 0)

    def test_the_checks_cover_expiry_scope_and_tampering(self):
        _, printed, _ = self.run_command('test', '--json')
        names = ' '.join(json.loads(printed)['checks'])
        for expected in ('another site', 'different secret', 'expired',
                         'truncated', 'garbage'):
            self.assertIn(expected, names)

    def test_a_disabled_subsystem_says_so_rather_than_pretending_to_test(self):
        code, printed, errors = self.run_command('test', enabled=False)
        self.assertEqual(code, 2)
        self.assertIn('not enabled', errors)
        self.assertIn('doctor', errors)
        self.assertEqual(printed, '')


class TestStatusAndStats(Base):
    def test_status_names_the_mode_and_says_shadow_sends_nothing(self):
        _, printed, _ = self.run_command('status', mode='shadow')
        self.assertIn('Shadow', printed)
        self.assertIn('nothing is sent', printed)

    def test_status_on_a_fresh_service_reports_no_data_rather_than_a_rate(self):
        _, printed, _ = self.run_command('status')
        self.assertIn('no data yet', printed)
        self.assertNotIn('100%', printed)

    def test_stats_refuses_to_call_a_pass_proof_of_anything(self):
        _, printed, _ = self.run_command('stats')
        self.assertIn('not proof of a person', printed)
        self.assertIn('not proof of an attack', printed)

    def test_status_json_is_the_service_health_document(self):
        _, printed, _ = self.run_command('status', '--json')
        document = json.loads(printed)
        self.assertEqual(document['token_scheme'], 'challenge-v1')
        self.assertTrue(document['shadow'])
        self.assertNotIn('secret', json.dumps(document))

    def test_a_disabled_subsystem_still_reports_status_without_failing(self):
        code, printed, _ = self.run_command('status', enabled=False)
        self.assertEqual(code, 0)
        self.assertIn('Disabled', printed)


class TestReadOnly(Base):
    """`doctor` is the command an operator runs when something is wrong."""

    def snapshot(self):
        return {path: (path.stat().st_mtime_ns, path.stat().st_size)
                for path in sorted(self.root.rglob('*')) if path.is_file()}

    def test_doctor_changes_no_file_on_disk(self):
        path = write_config(self.root)
        before = self.snapshot()
        self.invoke(['doctor'], path)
        self.assertEqual(before, self.snapshot())

    def test_every_subcommand_changes_no_file_on_disk(self):
        path = write_config(self.root)
        before = self.snapshot()
        for action in ('doctor', 'status', 'stats', 'test'):
            self.invoke([action], path)
            self.assertEqual(before, self.snapshot(), action)

    def test_doctor_does_not_loosen_the_secret_permissions_it_reads(self):
        self.invoke(['doctor'], write_config(self.root))
        mode = stat.S_IMODE((self.root / 'challenge.secret').stat().st_mode)
        self.assertEqual(mode, 0o600)

    def imported(self):
        """The modules this file actually imports, by parsing it.

        A substring search would match the word "requests" in an ordinary
        English sentence, which is how a test like this ends up asserting on
        prose instead of on behaviour.
        """
        import ast
        tree = ast.parse(Path(challenge_cli.__file__).read_text(encoding='utf-8'))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module)
                names.update(f'{node.module}.{alias.name}' for alias in node.names)
        return names

    def test_the_module_imports_nothing_that_reaches_the_network(self):
        names = self.imported()
        for forbidden in ('socket', 'urllib', 'urllib.request', 'http',
                          'http.client', 'requests', 'ftplib', 'asyncio',
                          'subprocess', 'xmlrpc'):
            self.assertNotIn(forbidden, names)

    def test_the_module_never_reloads_or_restarts_anything(self):
        source = Path(challenge_cli.__file__).read_text(encoding='utf-8')
        for forbidden in ('nginx -s', 'nginx -t', 'systemctl', 'nft ', 'iptables'):
            self.assertNotIn(forbidden, source, forbidden)

    def called(self):
        """Every call in the module, as `receiver.name` where there is one."""
        import ast
        tree = ast.parse(Path(challenge_cli.__file__).read_text(encoding='utf-8'))
        names = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute):
                names.add(target.attr)
                if isinstance(target.value, ast.Name):
                    names.add(f'{target.value.id}.{target.attr}')
        return names

    def test_the_module_calls_nothing_that_writes_a_file(self):
        """`str.replace` is fine and `os.replace` is not, so the receiver matters."""
        names = self.called()
        for forbidden in ('write_text', 'write_bytes', 'open', 'unlink', 'mkdir',
                          'rmtree', 'touch', 'os.replace', 'os.remove', 'os.rename',
                          'os.chmod', 'shutil.copy', 'shutil.move'):
            self.assertNotIn(forbidden, names, forbidden)


if __name__ == '__main__':
    unittest.main()
