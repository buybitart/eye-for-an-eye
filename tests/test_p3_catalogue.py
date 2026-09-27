import dataclasses
import hashlib
import hmac
import struct
import unittest
from eye_for_an_eye.deception.profiles import CATALOGUE_VERSION, PROFILES
from eye_for_an_eye.deception.selector import profile_seed, select_profile


class CatalogueTests(unittest.TestCase):
    def test_explicit_binary_domain_and_catalogue(self):
        secret = bytes(range(32))
        message = b'EFAE-DECEPTION-V1\0' + struct.pack('!I', 2) + b'\x04\x7f\x00\x00\x01' + struct.pack('!HB', 1234, 6)
        self.assertEqual(profile_seed(secret, '127.0.0.1', 1234, 'tcp'), hmac.digest(secret, message, hashlib.sha256))
        with self.assertRaises(ValueError):
            profile_seed(secret, '127.0.0.1', 1234, 'tcp', 1)

    def test_catalogue_is_reviewed_consistent_and_slots(self):
        self.assertEqual(CATALOGUE_VERSION, 2)
        for profile in PROFILES:
            with self.subTest(profile=profile.profile_id):
                self.assertFalse(hasattr(profile, '__dict__'))
                self.assertEqual(profile.handler, profile.service_family)
                self.assertIsInstance(profile.capabilities, frozenset)
                selected = select_profile(bytes(range(32)), '::1', 1234, 'tcp', 2, profile.service_family)
                self.assertEqual(selected, profile)
                with self.assertRaises(ValueError):
                    dataclasses.replace(profile, total_timeout=11)
                with self.assertRaises(ValueError):
                    dataclasses.replace(profile, handler='shell')
