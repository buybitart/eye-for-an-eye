import dataclasses
import random
import unittest
from eye_for_an_eye.config import Config
from eye_for_an_eye.deception.privacy import Privacy
from eye_for_an_eye.deception.profiles import PROFILES
from eye_for_an_eye.deception.protocols import ProtocolSession


def session(family, **kwargs):
    config = Config()
    profile = next(profile for profile in PROFILES if profile.service_family == family)
    return ProtocolSession(profile, config.limits, Privacy(bytes(range(32)), **kwargs))


class ProtocolTests(unittest.TestCase):
    def test_http_framing_methods_and_no_fetch(self):
        for method in (b'GET', b'HEAD', b'OPTIONS'):
            with self.subTest(method=method):
                value = session('http')
                self.assertEqual(value.start(), [])
                self.assertEqual(value.feed(method + b' /../../etc/passwd?token=private HTTP/1.1\r\n'), [])
                step = value.feed(b'Host: localhost\r\nCookie: secret\r\n\r\n')[0]
                self.assertTrue(step.close)
                self.assertTrue(step.credential)
                self.assertNotIn(b'private', step.response)
                if method == b'HEAD':
                    self.assertTrue(step.response.endswith(b'\r\n\r\n'))
                elif method == b'OPTIONS':
                    self.assertIn(b'204 No Content', step.response)
                else:
                    self.assertTrue(step.response.endswith(b'OK\n'))
                self.assertEqual(value.feed(b'GET / HTTP/1.0\r\n\r\n'), [])
        for request in (b'GET http://example.test/ HTTP/1.1\r\nHost: a\r\n\r\n',
                        b'GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\n',
                        b'GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n',
                        b'GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n'):
            value = session('http')
            value.start()
            self.assertIn(b'400 Bad Request', value.feed(request)[0].response)

    def test_ftp_dialog_rejects_login_and_data_commands(self):
        value = session('ftp', usernames='hash', preview=True)
        self.assertTrue(value.start()[0].response.startswith(b'220 '))
        steps = value.feed(b'USER alice\r\nPASS super-secret\r\nSYST\r\nFEAT\r\nPWD\r\nPORT 1,2,3,4,5,6\r\nQUIT\r\n')
        self.assertEqual([step.response[:3] for step in steps], [b'331', b'530', b'215', b'211', b'530', b'502', b'221'])
        self.assertTrue(steps[-1].close)
        self.assertEqual(len(steps[0].username), 64)
        self.assertEqual(steps[0].username, steps[1].username)
        self.assertNotIn('alice', repr(steps))
        self.assertNotIn('super-secret', repr(steps))
        self.assertFalse(value.buffer)

    def test_ssh_identification_only(self):
        value = session('ssh')
        greeting = value.start()[0]
        self.assertTrue(greeting.response.startswith(b'SSH-2.0-'))
        self.assertFalse(greeting.close)
        step = value.feed(b'SSH-2.0-TestClient_1.0\r\n')[0]
        self.assertTrue(step.close)
        self.assertFalse(step.anomaly)
        self.assertEqual(step.response, b'')
        self.assertEqual(value.feed(b'execute command'), [])

    def test_session_budgets_and_malformed(self):
        value = session('ftp')
        value.start()
        steps = value.feed(b'FEAT\r\n' * 100)
        self.assertLessEqual(len(steps), 12)
        self.assertLessEqual(value.response_bytes, 1024)
        self.assertTrue(value.closed)
        value = session('ftp')
        value.start()
        self.assertTrue(value.feed(b'\xff\x00\r\n')[0].anomaly)
        value = session('http')
        value.start()
        self.assertTrue(value.feed(b'x' * 4096)[0].close)
        config = Config()
        config.limits.max_response_bytes = 4
        value = ProtocolSession(PROFILES[0], config.limits, Privacy(bytes(range(32))))
        self.assertEqual(value.start()[0].response, b'')
        self.assertTrue(value.closed)

    def test_finite_local_parser_fuzz(self):
        rng = random.Random(3107)
        for family in ('http', 'ftp', 'ssh'):
            for _ in range(160):
                value = session(family, preview=True)
                value.start()
                blob = rng.randbytes(rng.randrange(0, 5000))
                for offset in range(0, len(blob), 137):
                    steps = value.feed(blob[offset:offset + 137])
                    self.assertTrue(all(isinstance(dataclasses.asdict(step), dict) for step in steps))
                self.assertLessEqual(value.request_bytes, value.max_request)
                self.assertLessEqual(value.response_bytes, value.max_response)
                self.assertLessEqual(value.transitions, value.max_transitions)
                value.close()
                self.assertFalse(value.buffer)
