"""Deterministic profiles and bounded protocol response regressions."""

import dataclasses
import os
import subprocess
import sys
import unittest
from pathlib import Path

from eye_for_an_eye.deception.profiles import PROFILES, response_for
from eye_for_an_eye.deception.selector import profile_seed, select_profile


SECRET = bytes(range(32))  # Public test fixture, never a runtime default.


class ProfileTests(unittest.TestCase):
    def test_catalog_is_immutable_and_bounded(self):
        self.assertIsInstance(PROFILES, tuple)
        self.assertEqual(len({profile.id for profile in PROFILES}), len(PROFILES))
        for profile in PROFILES:
            self.assertIsInstance(profile.banner, bytes)
            self.assertLessEqual(len(profile.banner), profile.max_response)
            self.assertLessEqual(profile.max_response, 1024)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                profile.profile_id = "changed"

    def test_invalid_profile_cannot_exceed_response_budget(self):
        with self.assertRaises(ValueError):
            dataclasses.replace(PROFILES[0], banner=b"12345", max_response_bytes=4)

    def test_missing_or_short_secret_is_rejected(self):
        for secret in (None, b"", b"a" * 31, "a" * 32):
            with self.subTest(secret=type(secret).__name__), self.assertRaises((TypeError, ValueError)):
                select_profile(secret, "127.0.0.1", 2222, "tcp")

    def test_canonical_ip_and_binary_fields(self):
        self.assertEqual(profile_seed(SECRET, "::1", 22, "tcp"), profile_seed(SECRET, "0:0:0:0:0:0:0:1", 22, "TCP"))
        self.assertNotEqual(profile_seed(SECRET, "127.0.0.1", 22, "tcp"), profile_seed(SECRET, "127.0.0.1", 22, "udp"))
        self.assertNotEqual(profile_seed(SECRET, "127.0.0.1", 22, "tcp"), profile_seed(SECRET, "127.0.0.1", 23, "tcp"))
        self.assertNotEqual(profile_seed(SECRET, "127.0.0.1", 22, "tcp"), profile_seed(SECRET, "127.0.0.2", 22, "tcp"))

    def test_selection_survives_fresh_process(self):
        expected = select_profile(SECRET, "127.0.0.1", 2222, "tcp").id
        code = "from eye_for_an_eye.deception.selector import select_profile; print(select_profile(bytes(range(32)), '127.0.0.1', 2222, 'tcp').id)"
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run([sys.executable, "-B", "-c", code], cwd=Path(__file__).resolve().parents[1], env=environment, capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), expected)

    def test_unsupported_transport_and_invalid_destination_rejected(self):
        for destination, port, transport in (("localhost", 22, "tcp"), ("127.0.0.1", 0, "tcp"), ("127.0.0.1", 65536, "tcp"), ("127.0.0.1", 22, "icmp"), ("127.0.0.1", 22, "udp")):
            with self.subTest(destination=destination, port=port, transport=transport), self.assertRaises(ValueError):
                select_profile(SECRET, destination, port, transport)

    def test_http_waits_for_valid_request(self):
        profile = next(profile for profile in PROFILES if profile.service == "http")
        for request in (b"", b"garbage", b"GET / HTTP/1.1\r\n", b"GET / HTTP/1.1\r\nBroken header\r\n\r\n", b"GET / HTTP/1.1\r\nHost: x\x1b\r\n\r\n"):
            with self.subTest(request=request):
                self.assertEqual(response_for(profile, request), b"")
        response = response_for(profile, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.0 200 OK\r\n"))
        headers, body = response.split(b"\r\n\r\n", 1)
        self.assertIn(f"Content-Length: {len(body)}".encode("ascii"), headers)

    def test_http_head_has_no_body(self):
        profile = next(profile for profile in PROFILES if profile.service == "http")
        response = response_for(profile, b"HEAD / HTTP/1.0\r\n\r\n")
        self.assertTrue(response.endswith(b"\r\n\r\n"))
        self.assertIn(b"Content-Length: 3", response)

    def test_greetings_and_all_responses_enforce_request_limit(self):
        for profile in PROFILES:
            self.assertEqual(response_for(profile, b"x" * (profile.max_request + 1)), b"")
            if profile.service in {"ssh", "ftp"}:
                self.assertEqual(response_for(profile, b""), profile.banner)


if __name__ == "__main__":
    unittest.main()
