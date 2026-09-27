import unittest
from unittest.mock import patch
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6DestUnreach
from eye_for_an_eye.config import Config
from eye_for_an_eye.events import EventPipeline
from eye_for_an_eye.network.capture import PacketObserver


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        class Sink:
            def emit(inner, event):
                self.events.append(event)
                return True
        self.observer = PacketObserver(Config(), EventPipeline(Sink()))

    def test_base_event_survives_failed_fingerprint(self):
        packet = IP(src='192.0.2.1', dst='127.0.0.1') / TCP(sport=1234, dport=80)
        with patch.object(self.observer.p0f, 'fingerprint', side_effect=ValueError('malformed')):
            self.observer.observe(packet)
        self.assertEqual(self.events[0].src_ip, '192.0.2.1')
        self.assertEqual(self.events[0].event_type, 'network_observation')
        self.assertEqual(self.events[-1].event_type, 'parse_error')

    def test_quoted_tcp_is_not_source_connection(self):
        self.observer.observe(IP(src='192.0.2.1') / ICMP(type=3) / IP() / TCP(dport=22))
        self.assertEqual(self.events[0].transport, 'icmp')
        self.assertIsNone(self.events[0].dst_port)

    def test_ipv6_fragment_does_not_fingerprint_timestamp(self):
        self.observer.observe(IPv6(src='2001:db8::1') / IPv6ExtHdrFragment(m=1) / TCP(options=[('Timestamp', (1234, 0))]))
        self.assertTrue(self.events[0].observations['fragmented'])
        self.assertNotIn('tcp_timestamp', self.events[1].observations)

    def test_outer_ipv6_is_not_replaced_by_quoted_ipv4(self):
        packet = IPv6(src='2001:db8::1', dst='::1') / ICMPv6DestUnreach() / IP(src='192.0.2.1') / TCP()
        self.observer.observe(packet)
        self.assertEqual(self.events[0].src_ip, '2001:db8::1')
        self.assertEqual(self.events[0].transport, 'icmpv6')
        self.assertEqual(self.events[0].observations['ip_version'], 6)

    def test_fragment_and_quoted_tcp_are_not_sent_to_p0f(self):
        with patch.object(self.observer.p0f, 'fingerprint') as fingerprint:
            self.observer.observe(IP(src='192.0.2.1', flags='MF') / TCP())
            self.observer.observe(IP(src='192.0.2.1') / ICMP(type=3) / IP() / TCP())
            fingerprint.assert_not_called()
