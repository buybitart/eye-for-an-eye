import configparser
from pathlib import Path
import unittest
from eye_for_an_eye.security.privileges import unit_settings


class DeploymentTests(unittest.TestCase):
    def test_unit_files_match_validated_privilege_profiles(self):
        root = Path(__file__).resolve().parents[1] / 'deploy' / 'systemd'
        for name, role in [('eye-for-an-eye.service', 'analysis'), ('eye-for-an-eye-listener.service', 'analysis'),
                           ('eye-for-an-eye-capture.service', 'capture')]:
            parsed = configparser.ConfigParser(interpolation=None)
            parsed.optionxform = str
            parsed.read(root / name)
            for key, value in unit_settings(role).items():
                with self.subTest(unit=name, directive=key):
                    self.assertEqual(parsed['Service'][key], value)
            self.assertNotEqual(parsed['Service']['User'], 'root')
            self.assertEqual(parsed['Service']['KillMode'], 'control-group')
