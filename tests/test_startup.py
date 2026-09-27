"""Regression tests: importing entrypoints must not initialize the runtime."""
import importlib.util
import subprocess
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class StartupTests(unittest.TestCase):
    def test_all_package_modules_import_without_runtime_or_optional_dependencies(self):
        program = '''
import importlib, pkgutil, socket, threading, sys
from unittest.mock import patch
import eye_for_an_eye
def forbidden(*args, **kwargs):
    raise AssertionError('runtime action during import')
with patch.object(socket, 'socket', forbidden), patch.object(threading.Thread, 'start', forbidden):
    for module in pkgutil.walk_packages(eye_for_an_eye.__path__, eye_for_an_eye.__name__ + '.'):
        importlib.import_module(module.name)
assert not any(name in sys.modules for name in ('scapy', 'maxminddb', 'ipwhois'))
'''
        result = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_entrypoints_are_import_safe(self):
        for path in ROOT.glob('+*.py'):
            with self.subTest(module=path.name):
                spec = importlib.util.spec_from_file_location('entry_' + path.stem[1:], path)
                module = importlib.util.module_from_spec(spec)
                with patch.object(sys, 'argv', [str(path)]), \
                     patch.object(socket, 'socket', side_effect=AssertionError('socket on import')), \
                     patch.object(threading.Thread, 'start', side_effect=AssertionError('thread on import')):
                    spec.loader.exec_module(module)
                self.assertTrue(callable(module.main))


if __name__ == '__main__':
    unittest.main()
