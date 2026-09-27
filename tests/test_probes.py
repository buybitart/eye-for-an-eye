"""Regression cases for the byte-oriented, bounded Nmap probe parser."""

import tempfile
import unittest
from pathlib import Path

from eye_for_an_eye.fingerprint.probes import (
    ProbeKey,
    ProbeLimits,
    ProbeParseError,
    load_probes,
    match_probe,
    parse_probes,
)


class ProbeParserTests(unittest.TestCase):
    def test_empty_payload_is_safe(self):
        probes = parse_probes(["Probe TCP NULL q||"])
        self.assertEqual(probes[ProbeKey("tcp", "NULL")], b"")
        result = match_probe(b"", "tcp", probes)
        self.assertIsNone(result.probe_name)
        self.assertEqual(result.confidence, "UNKNOWN")
        self.assertEqual(result.score, 0)

    def test_binary_payload_is_byte_exact(self):
        probes = parse_probes([r"Probe TCP Binary q|\x80\xff\0\r\n|"])
        self.assertEqual(probes[ProbeKey("tcp", "Binary")], b"\x80\xff\x00\r\n")

    def test_all_documented_escapes(self):
        probes = parse_probes([r"Probe TCP Escapes q|\\\0\a\b\f\n\r\t\v\x41|"])
        self.assertEqual(probes[ProbeKey("tcp", "Escapes")], b"\\\0\a\b\f\n\r\t\vA")

    def test_alternative_delimiters_and_no_payload(self):
        probes = parse_probes([r"Probe UDP Example q@a|b\x80@ no-payload"])
        self.assertEqual(probes[ProbeKey("udp", "Example")], b"a|b\x80")
        self.assertEqual(parse_probes(["Probe TCP Eq q=hello="])[ProbeKey("tcp", "Eq")], b"hello")

    def test_transport_collision_is_impossible(self):
        probes = parse_probes(["Probe TCP Same q|tcp bytes|", "Probe UDP Same q|udp bytes|"])
        self.assertEqual(len(probes), 2)
        self.assertEqual(probes[ProbeKey("tcp", "Same")], b"tcp bytes")
        self.assertEqual(probes[ProbeKey("udp", "Same")], b"udp bytes")

    def test_other_directives_and_comments_are_ignored(self):
        probes = parse_probes(["# comment", "", "Exclude 9100", "Probe TCP P q|bytes|", "ports 80", "match http m|hello|"])
        self.assertEqual(len(probes), 1)

    def test_malformed_probe_has_line_number(self):
        invalid = ["Probe", "Probe TCP P q|missing", "Probe TCP P q|x| garbage", r"Probe TCP P q|\xGG|", r"Probe TCP P q|\z|", "Probe ICMP P q|x|"]
        for line in invalid:
            with self.subTest(line=line), self.assertRaisesRegex(ProbeParseError, "line 2"):
                parse_probes(["# ignored", line])

    def test_duplicate_identity_rejected(self):
        with self.assertRaisesRegex(ProbeParseError, "duplicate"):
            parse_probes(["Probe TCP P q|a|", "Probe TCP P q|b|"])

    def test_entry_payload_and_input_limits(self):
        with self.assertRaisesRegex(ProbeParseError, "entries"):
            parse_probes(["Probe TCP A q|a|", "Probe TCP B q|b|"], limits=ProbeLimits(max_entries=1))
        with self.assertRaisesRegex(ProbeParseError, "payload"):
            parse_probes(["Probe TCP A q|12345|"], limits=ProbeLimits(max_probe_bytes=4))
        with self.assertRaisesRegex(ProbeParseError, "input"):
            parse_probes(["# " + "x" * 64], limits=ProbeLimits(max_input_bytes=32))
        with self.assertRaisesRegex(ProbeParseError, "aggregate"):
            parse_probes(["Probe TCP A q|123|", "Probe TCP B q|456|"], limits=ProbeLimits(max_payload_bytes=5))

    def test_file_load_preserves_raw_non_ascii_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probes"
            path.write_bytes(b"Probe TCP Raw q|\x80\x85\xff|\n")
            self.assertEqual(load_probes(path)[ProbeKey("tcp", "Raw")], b"\x80\x85\xff")

    def test_oversized_file_line_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probes"
            path.write_bytes(b"# " + b"x" * 128)
            with self.assertRaisesRegex(ProbeParseError, "input"):
                load_probes(path, limits=ProbeLimits(max_input_bytes=64))


class ProbeMatchingTests(unittest.TestCase):
    def test_one_byte_cannot_be_high_confidence(self):
        result = match_probe(b"A", "tcp", {ProbeKey("tcp", "P"): b"ABC"})
        self.assertEqual(result.confidence, "UNKNOWN")
        self.assertEqual(result.score, 0)

    def test_exact_evidence_is_low_confidence_heuristic(self):
        result = match_probe(b"ABCDEFGH", "tcp", {ProbeKey("tcp", "P"): b"ABCDEFGH"})
        self.assertEqual(result.probe_name, "P")
        self.assertEqual(result.score, 1)
        self.assertEqual(result.evidence_bytes, 8)
        self.assertEqual(result.confidence, "LOW")

    def test_prefix_score_uses_longer_payload_length(self):
        result = match_probe(b"ABCDEFGH", "tcp", {ProbeKey("tcp", "P"): b"ABCDEFGHIJKLMNOP"})
        self.assertEqual(result.score, 0.5)
        self.assertEqual(result.evidence_bytes, 8)

    def test_transport_and_unrelated_bytes_do_not_match(self):
        probes = {ProbeKey("udp", "WrongTransport"): b"ABCDEFGH", ProbeKey("tcp", "WrongPrefix"): b"xABCDEFGH"}
        self.assertIsNone(match_probe(b"ABCDEFGH", "tcp", probes).probe_name)

    def test_matcher_rejects_unbounded_caller_data(self):
        with self.assertRaises(ValueError):
            match_probe(b"x" * 65537, "tcp", {})
        with self.assertRaises(ValueError):
            match_probe(b"abcdefgh", "tcp", {}, min_evidence=0)


if __name__ == "__main__":
    unittest.main()
