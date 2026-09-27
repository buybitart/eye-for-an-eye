"""P10 client identity resolution.

This is the security-critical test group of the whole web layer. Two questions
are asked repeatedly in different shapes:

  1. Can a client on the Internet make the system believe it is somebody else?
  2. Can a suspicious client behind a CDN get the CDN's address blocked, taking
     the site off the air for everyone else?

The answer to both must be no, structurally, not by configuration.
"""
import unittest

from eye_for_an_eye.web.identity import (DIRECT_PEER, HIGH, IdentityError, LOW, MEDIUM,
                                         PARTIAL_PROXY_CHAIN, TRUSTED_PROXY_CHAIN,
                                         UNTRUSTED_FORWARDED, ClientResolver, parse_chain,
                                         source_scope)

PROXY_V4 = '10.0.0.0/8'
PROXY_V6 = '2001:db8:proxy::/48'.replace('proxy', 'aaaa')
CDN = '203.0.113.0/24'


class TestDirectClient(unittest.TestCase):
    def resolver(self):
        return ClientResolver([PROXY_V4])

    def test_a_direct_client_is_the_peer(self):
        identity = self.resolver().resolve('198.51.100.7')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertEqual(identity.origin, DIRECT_PEER)
        self.assertEqual(identity.confidence, HIGH)
        self.assertTrue(identity.network_enforceable)

    def test_a_direct_ipv6_client_is_the_peer(self):
        identity = self.resolver().resolve('2001:db8::1')
        self.assertEqual(identity.address, '2001:db8::1')
        self.assertTrue(identity.network_enforceable)

    def test_a_peer_with_a_port_is_still_parsed(self):
        self.assertEqual(self.resolver().resolve('198.51.100.7:54321').address, '198.51.100.7')

    def test_a_bracketed_ipv6_peer_with_a_port_is_parsed(self):
        self.assertEqual(self.resolver().resolve('[2001:db8::1]:443').address, '2001:db8::1')


class TestSpoofing(unittest.TestCase):
    """An untrusted peer's forwarded header is worth nothing."""

    def resolver(self):
        return ClientResolver([PROXY_V4])

    def test_a_spoofed_header_from_an_untrusted_peer_is_ignored(self):
        identity = self.resolver().resolve('198.51.100.7',
                                           forwarded='192.0.2.99, 203.0.113.5')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertEqual(identity.origin, DIRECT_PEER)
        self.assertTrue(identity.forwarded_ignored)
        self.assertIn('not a configured trusted proxy', identity.reason)

    def test_an_attacker_cannot_frame_another_address(self):
        """The whole point: a header must not move blame to a third party."""
        victim = '192.0.2.50'
        identity = self.resolver().resolve('198.51.100.7', forwarded=victim)
        self.assertNotEqual(identity.address, victim)
        self.assertEqual(identity.address, '198.51.100.7')

    def test_an_attacker_cannot_hide_behind_a_trusted_address(self):
        """Claiming to be a proxy does not make you one."""
        identity = self.resolver().resolve('198.51.100.7', forwarded='10.0.0.5')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertTrue(identity.network_enforceable, 'the real peer stays enforceable')

    def test_a_spoofed_real_ip_header_from_an_untrusted_peer_is_ignored(self):
        identity = self.resolver().resolve('198.51.100.7', real_ip='192.0.2.50')
        self.assertEqual(identity.address, '198.51.100.7')

    def test_a_client_prepended_chain_behind_a_trusted_proxy_is_marked_partial(self):
        """The classic attack: the client writes the left of the chain itself."""
        identity = self.resolver().resolve('10.0.0.1', forwarded='192.0.2.99, 198.51.100.7')
        # 198.51.100.7 is what our proxy actually saw; 192.0.2.99 is the client's claim.
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertEqual(identity.origin, PARTIAL_PROXY_CHAIN)
        self.assertEqual(identity.confidence, MEDIUM)
        self.assertFalse(identity.network_enforceable)

    def test_the_leftmost_address_is_never_taken_blindly(self):
        identity = self.resolver().resolve('10.0.0.1',
                                           forwarded='1.2.3.4, 5.6.7.8, 198.51.100.7')
        self.assertNotEqual(identity.address, '1.2.3.4')
        self.assertEqual(identity.address, '198.51.100.7')


class TestTrustedProxy(unittest.TestCase):
    def resolver(self):
        return ClientResolver([PROXY_V4, CDN])

    def test_one_trusted_proxy_reveals_the_client(self):
        identity = self.resolver().resolve('10.0.0.1', forwarded='198.51.100.7')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertEqual(identity.origin, TRUSTED_PROXY_CHAIN)
        self.assertEqual(identity.confidence, HIGH)

    def test_several_trusted_proxies_are_walked_through(self):
        identity = self.resolver().resolve('10.0.0.1',
                                           forwarded='198.51.100.7, 203.0.113.9, 10.0.0.2')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertEqual(identity.origin, TRUSTED_PROXY_CHAIN)
        self.assertEqual(identity.confidence, HIGH)

    def test_an_ipv6_proxy_chain_works(self):
        resolver = ClientResolver([PROXY_V6])
        identity = resolver.resolve('2001:db8:aaaa::1', forwarded='2001:db8:ffff::9')
        self.assertEqual(identity.address, '2001:db8:ffff::9')
        self.assertEqual(identity.confidence, HIGH)

    def test_a_trusted_proxy_with_no_header_leaves_the_client_unknown(self):
        identity = self.resolver().resolve('10.0.0.1')
        self.assertEqual(identity.confidence, LOW)
        self.assertFalse(identity.network_enforceable)
        self.assertIn('real client is unknown', identity.reason)

    def test_a_chain_of_only_our_own_proxies_learns_nothing(self):
        identity = self.resolver().resolve('10.0.0.1', forwarded='10.0.0.2, 10.0.0.3')
        self.assertEqual(identity.confidence, LOW)
        self.assertFalse(identity.network_enforceable)
        self.assertIn('no client address was learned', identity.reason)

    def test_rfc_7239_forwarded_syntax_is_understood(self):
        identity = self.resolver().resolve('10.0.0.1', forwarded='for=198.51.100.7;proto=https')
        self.assertEqual(identity.address, '198.51.100.7')

    def test_a_real_ip_header_is_used_when_there_is_no_chain(self):
        identity = self.resolver().resolve('10.0.0.1', real_ip='198.51.100.7')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertEqual(identity.confidence, HIGH)


class TestProxyIsNeverBlocked(unittest.TestCase):
    """§66 and §141. The test that keeps a website online."""

    def resolver(self):
        return ClientResolver([CDN])

    def test_a_client_behind_a_cdn_never_makes_the_cdn_enforceable(self):
        identity = self.resolver().resolve('203.0.113.10', forwarded='198.51.100.7')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertFalse(identity.network_enforceable,
                         'blocking here would hit the CDN, not the client')
        self.assertIn('never blocked', identity.reason)

    def test_a_hundred_clients_behind_one_proxy_stay_separate(self):
        """§140. One proxy must not collapse into one attacker identity."""
        resolver = self.resolver()
        addresses = {resolver.resolve('203.0.113.10', forwarded=f'198.51.100.{n}').address
                     for n in range(1, 101)}
        self.assertEqual(len(addresses), 100)

    def test_no_resolution_behind_a_proxy_is_ever_network_enforceable(self):
        resolver = self.resolver()
        for forwarded in ('198.51.100.7', '1.2.3.4, 198.51.100.7', 'for=198.51.100.7',
                          None, '203.0.113.11'):
            with self.subTest(forwarded=forwarded):
                identity = resolver.resolve('203.0.113.10', forwarded=forwarded)
                self.assertFalse(identity.network_enforceable)

    def test_the_scope_says_what_may_be_acted_on(self):
        resolver = self.resolver()
        direct = resolver.resolve('198.51.100.7')
        behind = resolver.resolve('203.0.113.10', forwarded='198.51.100.7')
        self.assertEqual(source_scope(direct), 'NETWORK_SOURCE')
        self.assertEqual(source_scope(behind), 'WEB_CLIENT')


class TestMalformedInput(unittest.TestCase):
    """A header is attacker-controlled text. None of this may raise."""

    def resolver(self):
        return ClientResolver([PROXY_V4])

    def test_a_malformed_peer_produces_an_unusable_identity(self):
        for peer in ('', None, 'not-an-address', '999.999.999.999', 'x' * 500):
            with self.subTest(peer=peer):
                identity = self.resolver().resolve(peer)
                self.assertFalse(identity.network_enforceable)
                self.assertEqual(identity.confidence, LOW)
                self.assertEqual(identity.origin, UNTRUSTED_FORWARDED)

    def test_a_malformed_chain_does_not_raise(self):
        for header in ('', 'unknown', '_hidden', 'garbage, more garbage', ',,,,',
                       'a' * 10_000, '\x00\x01\x02', '192.0.2.1\n192.0.2.2'):
            with self.subTest(header=header):
                identity = self.resolver().resolve('10.0.0.1', forwarded=header)
                self.assertIsNotNone(identity.address)

    def test_obfuscated_rfc_7239_identifiers_are_not_addresses(self):
        self.assertEqual(parse_chain('for=_hidden'), ())
        self.assertEqual(parse_chain('for=unknown'), ())

    def test_a_very_long_chain_is_bounded(self):
        header = ', '.join(f'192.0.2.{n % 250 + 1}' for n in range(1000))
        self.assertLessEqual(len(parse_chain(header)), 16)

    def test_a_newline_in_a_header_cannot_split_the_chain(self):
        chain = parse_chain('192.0.2.1\r\nX-Injected: 1')
        self.assertLessEqual(len(chain), 1)

    def test_an_invalid_trusted_network_is_refused_at_construction(self):
        for entry in ('not-a-network', '10.0.0.0/99', ''):
            with self.subTest(entry=entry):
                with self.assertRaises(IdentityError):
                    ClientResolver([entry])

    def test_a_resolver_with_no_proxies_configured_trusts_nothing(self):
        resolver = ClientResolver([])
        self.assertFalse(resolver.configured)
        identity = resolver.resolve('198.51.100.7', forwarded='192.0.2.1')
        self.assertEqual(identity.address, '198.51.100.7')
        self.assertTrue(identity.forwarded_ignored)


class TestTrustSwitch(unittest.TestCase):
    def test_forwarded_headers_can_be_switched_off_entirely(self):
        resolver = ClientResolver([PROXY_V4], trust_forwarded=False)
        identity = resolver.resolve('10.0.0.1', forwarded='198.51.100.7')
        self.assertEqual(identity.address, '10.0.0.1')
        self.assertEqual(identity.confidence, LOW,
                         'a proxy peer with no usable client is still uncertain')


class TestExplanation(unittest.TestCase):
    def test_every_identity_explains_itself(self):
        resolver = ClientResolver([PROXY_V4])
        for peer, forwarded in (('198.51.100.7', None), ('10.0.0.1', '198.51.100.7'),
                                ('10.0.0.1', None), ('bad', None)):
            with self.subTest(peer=peer):
                document = resolver.resolve(peer, forwarded=forwarded).explain()
                self.assertIn(document['confidence'], ('HIGH', 'MEDIUM', 'LOW'))
                self.assertTrue(document['reason'])
                self.assertIsInstance(document['network_enforceable'], bool)


if __name__ == '__main__':
    unittest.main()
