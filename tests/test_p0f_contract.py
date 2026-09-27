"""Contract against installed Scapy 2.7 with our synthetic, non-attributing DB."""
import tempfile
import unittest
from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.modules import p0f
from eye_for_an_eye.fingerprint.p0f_adapter import P0fAdapter


class P0fContractTests(unittest.TestCase):
    def test_real_parser_match_and_adapter_database_isolation(self):
        packet = IP(src='192.0.2.1', dst='127.0.0.1', ttl=61, id=1) / TCP(
            sport=12345, dport=80, seq=1, flags='S', window=8192)
        original_database = p0f.p0fdb
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / 'first.fp', Path(directory) / 'second.fp'
            template = '[tcp:request]\nlabel = s:unix:{name}:synthetic\nsig = 4:64:0:0:8192,0::bad:0\n'
            first.write_text(template.format(name='FixtureA'), encoding='ascii')
            second.write_text(template.format(name='FixtureB'), encoding='ascii')
            a, b = P0fAdapter(first), P0fAdapter(second)
            for adapter, name in ((a, 'FixtureA'), (b, 'FixtureB'), (a, 'FixtureA')):
                with self.subTest(name=name):
                    result = adapter.fingerprint(packet)
                    self.assertEqual(result.status, 'matched')
                    self.assertEqual(result.os_family, name)
                    self.assertEqual(result.distance, 3)
                    self.assertFalse(result.fuzzy)
                    self.assertEqual(result.confidence, 'MEDIUM')
        self.assertIs(p0f.p0fdb, original_database)

    def test_malformed_and_empty_database_are_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.fp'
            for content in ('', '[tcp:request]\nlabel = invalid\nsig = bad\n'):
                path.write_text(content, encoding='ascii')
                self.assertEqual(P0fAdapter(path).fingerprint(None).confidence, 'UNKNOWN')
