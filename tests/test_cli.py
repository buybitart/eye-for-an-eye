import contextlib
import io
import unittest
from unittest.mock import patch
from eye_for_an_eye.cli import main


class CliTests(unittest.TestCase):
    def test_validation_happens_before_socket(self):
        cases = [('proto', ['0', 'tcp']), ('proto', ['1234', 'bogus']),
                 ('proto', ['--total-timeout', 'nan']), ('proto', ['--bind', 'bad']),
                 ('nat', ['--active-path-probe']), ('services', ['--check-config']),
                 ('garbage', ['1234', 'tcp']), ('proto', ['--probes', 'missing-file']),
                 ('proto', ['--pcap', __file__])]
        for command, args in cases:
            with self.subTest(command=command, args=args), patch('socket.socket', side_effect=AssertionError('network opened')), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main(args, command=command)
                self.assertEqual(error.exception.code, 2)

    def test_help_and_check_config_open_no_network(self):
        with patch('socket.socket', side_effect=AssertionError('network opened')):
            self.assertEqual(main(['--check-config'], command='proto'), 0)
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
                main(['--help'], command='proto')
            self.assertEqual(result.exception.code, 0)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
                main(['proto', '--help'])
            self.assertIn('--first-byte-timeout', output.getvalue())
