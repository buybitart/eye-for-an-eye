"""P12 Phase 1 (§2-§9, §109, §145): which site does a request belong to?

The two failures this guards against are opposite and both bad. Mapping a
request to the wrong site contaminates a baseline and — worse — could let a
challenge token cross a site boundary. Letting a request *create* a site hands
an attacker with a `Host:` loop an unbounded memory allocator.

So the tests come in two halves: a host must never resolve to a site the
operator did not map it to, and no amount of hostile input may add a site.
"""
import unittest

from eye_for_an_eye.challenge.token import normalise_site
from eye_for_an_eye.sites.identity import (CONFIGURED, DEFAULT_SITE, MALFORMED,
                                           MAX_SITE_CHARS, RESERVED_SITE_IDS,
                                           SiteResolver, SiteResolverError,
                                           UNKNOWN, UNKNOWN_SITE, normalise_host,
                                           normalise_site_id)

# Documentation domains (RFC 2606). Never a real one, in code or in defaults.
MAIN = 'example.org'
API = 'api.example.org'
ADMIN = 'admin.example.net'


def resolver(**kwargs):
    return SiteResolver({'main': [MAIN, 'www.example.org'],
                         'api': [API],
                         'admin': [ADMIN]}, **kwargs)


class TestHostNormalisation(unittest.TestCase):
    """§6. Case, ports, trailing dots, literals, and internationalised names."""

    def test_case_is_folded(self):
        for raw in ('example.org', 'EXAMPLE.ORG', 'Example.Org', 'eXaMpLe.oRg'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), 'example.org')

    def test_a_port_is_removed(self):
        for raw in ('example.org:443', 'example.org:80', 'example.org:8443'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), 'example.org')

    def test_a_trailing_dot_is_the_same_name(self):
        self.assertEqual(normalise_host('example.org.'), 'example.org')
        self.assertEqual(normalise_host('EXAMPLE.ORG.:443'), 'example.org')

    def test_an_ipv4_literal_survives(self):
        self.assertEqual(normalise_host('192.0.2.1'), '192.0.2.1')
        self.assertEqual(normalise_host('192.0.2.1:8080'), '192.0.2.1')

    def test_a_bracketed_ipv6_literal_is_canonicalised(self):
        """One address with several spellings must reduce to one string."""
        for raw in ('[2001:db8::1]', '[2001:DB8::1]', '[2001:db8:0:0:0:0:0:1]',
                    '[2001:db8::1]:443'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '[2001:db8::1]')

    def test_an_unbracketed_ipv6_address_is_refused(self):
        """It is not valid in a Host header, and guessing splits the address."""
        for raw in ('2001:db8::1', '2001:db8::1:443', '::1'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')

    def test_an_internationalised_name_becomes_punycode(self):
        encoded = normalise_host('bücher.example')
        self.assertTrue(encoded.startswith('xn--'), encoded)
        self.assertEqual(encoded, normalise_host('BÜCHER.EXAMPLE'))

    def test_an_unencodable_name_is_refused_rather_than_guessed(self):
        for raw in ('​.example', '..', '﻿'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')


class TestMalformedHostsAreRefused(unittest.TestCase):
    """§7. Everything doubtful becomes `''`, which becomes UNKNOWN_SITE."""

    def test_empty_and_blank(self):
        for raw in ('', None, ' ', '\t', '.', '..', '...'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')

    def test_several_values_in_one_field(self):
        """Two Host headers, or a forwarded list. Which was meant is unknowable."""
        for raw in ('example.org, api.example.org', 'example.org;api.example.org',
                    'example.org api.example.org', 'example.org\r\napi.example.org'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')

    def test_control_characters(self):
        for raw in ('exam\x00ple.org', 'example.org\n', 'example\x7f.org',
                    'example.org\r'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')

    def test_bad_ports(self):
        for raw in ('example.org:', 'example.org:abc', 'example.org:80:80',
                    'example.org:-1'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')

    def test_bad_brackets(self):
        for raw in ('[2001:db8::1', '[not-an-address]', '[]', '[2001:db8::1]x'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')

    def test_bad_labels(self):
        for raw in ('-example.org', 'example-.org', 'exa mple.org', 'a' * 64 + '.org',
                    'example..org', 'exa/mple.org', 'exa:mple', '@example.org',
                    'example.org/../admin'):
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(raw), '')

    def test_a_name_longer_than_dns_allows(self):
        self.assertEqual(normalise_host('.'.join(['abc'] * 100)), '')

    def test_normalisation_is_idempotent(self):
        for raw in ('EXAMPLE.ORG:443', '[2001:DB8::1]:80', '192.0.2.1:8080',
                    'example.org.'):
            once = normalise_host(raw)
            with self.subTest(host=raw):
                self.assertEqual(normalise_host(once), once)


class TestResolution(unittest.TestCase):
    def test_a_configured_domain_resolves_to_its_site(self):
        found = resolver().resolve(MAIN)
        self.assertEqual(found.site_id, 'main')
        self.assertEqual(found.origin, CONFIGURED)
        self.assertTrue(found.known)

    def test_every_spelling_of_a_configured_domain_resolves_the_same(self):
        built = resolver()
        for raw in (MAIN, MAIN.upper(), f'{MAIN}:443', f'{MAIN}.', f'  {MAIN}  '):
            with self.subTest(host=raw):
                self.assertEqual(built.resolve(raw).site_id, 'main')

    def test_sites_do_not_bleed_into_each_other(self):
        built = resolver()
        self.assertEqual(built.resolve(API).site_id, 'api')
        self.assertEqual(built.resolve(ADMIN).site_id, 'admin')
        self.assertEqual(built.resolve('www.example.org').site_id, 'main')

    def test_a_subdomain_is_not_the_parent_site(self):
        """§7. Matching is exact; a subdomain is a different name."""
        built = resolver()
        for raw in ('sub.example.org', 'a.b.example.org', 'notexample.org',
                    'example.org.evil.test', 'evil-example.org'):
            with self.subTest(host=raw):
                self.assertEqual(built.resolve(raw).site_id, UNKNOWN_SITE)

    def test_a_domain_that_merely_contains_a_configured_one_does_not_match(self):
        built = resolver()
        self.assertEqual(built.resolve('xexample.orgx').site_id, UNKNOWN_SITE)


class TestUnknownHost(unittest.TestCase):
    """§9. Unknown is a bucket with a name, not the primary site."""

    def test_an_unknown_host_does_not_become_the_first_site(self):
        found = resolver().resolve('nothing-configured.test')
        self.assertEqual(found.site_id, UNKNOWN_SITE)
        self.assertEqual(found.origin, UNKNOWN)
        self.assertFalse(found.known)

    def test_a_malformed_host_is_reported_as_malformed_not_merely_unknown(self):
        found = resolver().resolve('exam ple.org')
        self.assertEqual(found.site_id, UNKNOWN_SITE)
        self.assertEqual(found.origin, MALFORMED)

    def test_an_explicit_default_site_is_honoured_when_configured(self):
        found = resolver(default_site='main').resolve('nothing-configured.test')
        self.assertEqual(found.site_id, 'main')
        self.assertEqual(found.origin, DEFAULT_SITE)

    def test_a_default_site_must_be_one_of_the_configured_sites(self):
        with self.assertRaises(SiteResolverError):
            resolver(default_site='does-not-exist')

    def test_a_malformed_host_ignores_the_default_site(self):
        """A host that could not be read is not evidence about which site it is."""
        found = resolver(default_site='main').resolve('exam ple.org')
        self.assertEqual(found.site_id, UNKNOWN_SITE)

    def test_with_no_sites_configured_nothing_is_invented(self):
        found = SiteResolver().resolve(MAIN)
        self.assertEqual(found.site_id, UNKNOWN_SITE)
        self.assertIn('no sites', found.reason)

    def test_every_match_explains_itself(self):
        built = resolver()
        for host in (MAIN, 'nothing-configured.test', 'exam ple.org'):
            with self.subTest(host=host):
                self.assertTrue(built.resolve(host).reason)


class TestHostCannotCreateASite(unittest.TestCase):
    """§109, §110, §135, §146. The cardinality attack."""

    def test_the_resolver_has_no_method_that_adds_a_site(self):
        built = resolver()
        for name in dir(built):
            if name.startswith('_'):
                continue
            self.assertNotIn(name, ('add', 'add_site', 'register', 'create',
                                    'update', 'setdefault', 'insert'))

    def test_a_hundred_thousand_invented_hosts_add_no_sites(self):
        built = resolver()
        before = len(built)
        for index in range(100_000):
            found = built.resolve(f'{index}.attacker.test')
            self.assertEqual(found.site_id, UNKNOWN_SITE)
        self.assertEqual(len(built), before)
        self.assertEqual(len(built.domains), 4)

    def test_invented_hosts_all_share_one_bucket(self):
        """The whole point: one bucket, not one bucket per host."""
        built = resolver()
        found = {built.resolve(f'{index}.attacker.test').site_id
                 for index in range(10_000)}
        self.assertEqual(found, {UNKNOWN_SITE})

    def test_hostile_hosts_never_raise(self):
        built = resolver()
        for raw in ('', ' ', '\x00', 'a' * 5000, '[' * 100, ':' * 100,
                    '../../etc/passwd', '<script>', "' OR '1'='1",
                    '‮example.org', 'example.org\x00.evil.test',
                    '%2e%2e%2f', 'example.org%00', 'x' * 300 + ':443'):
            with self.subTest(host=raw[:30]):
                self.assertEqual(built.resolve(raw).site_id, UNKNOWN_SITE)

    def test_a_null_byte_cannot_smuggle_a_configured_domain(self):
        built = resolver()
        for raw in (f'{MAIN}\x00', f'\x00{MAIN}', f'evil.test\x00{MAIN}',
                    f'{MAIN}\n{API}'):
            with self.subTest(host=repr(raw)):
                self.assertEqual(built.resolve(raw).site_id, UNKNOWN_SITE)


class TestConfigurationIsRefusedRatherThanResolved(unittest.TestCase):
    """§145. An ambiguous mapping is a question only the operator can answer."""

    def test_one_domain_on_two_sites_is_rejected(self):
        with self.assertRaises(SiteResolverError) as raised:
            SiteResolver({'main': [MAIN], 'other': [MAIN]})
        self.assertIn('both', str(raised.exception))

    def test_a_duplicate_that_only_differs_in_spelling_is_still_rejected(self):
        for second in (MAIN.upper(), f'{MAIN}:443', f'{MAIN}.'):
            with self.subTest(spelling=second):
                with self.assertRaises(SiteResolverError):
                    SiteResolver({'main': [MAIN], 'other': [second]})

    def test_the_same_domain_twice_on_one_site_is_fine(self):
        built = SiteResolver({'main': [MAIN, MAIN.upper(), f'{MAIN}:443']})
        self.assertEqual(built.resolve(MAIN).site_id, 'main')

    def test_an_unusable_domain_is_rejected_at_startup(self):
        for bad in ('', 'exa mple.org', '-example.org', None):
            with self.subTest(domain=bad):
                with self.assertRaises(SiteResolverError):
                    SiteResolver({'main': [bad]})

    def test_an_unusable_site_name_is_rejected(self):
        for bad in ('', '   ', '!!!', '///'):
            with self.subTest(site=bad):
                with self.assertRaises(SiteResolverError):
                    SiteResolver({bad: [MAIN]})

    def test_reserved_site_names_are_rejected(self):
        for reserved in RESERVED_SITE_IDS:
            if not reserved:
                continue
            with self.subTest(site=reserved):
                with self.assertRaises(SiteResolverError):
                    SiteResolver({reserved: [MAIN]})

    def test_too_many_sites_is_rejected(self):
        many = {f'site{index}': [f'{index}.example.test'] for index in range(30)}
        SiteResolver(many, max_sites=64)
        with self.assertRaises(SiteResolverError):
            SiteResolver(many, max_sites=10)

    def test_site_names_that_normalise_to_the_same_thing_are_rejected(self):
        with self.assertRaises(SiteResolverError):
            SiteResolver({'Main': [MAIN], 'main': [API]})


class TestSiteIdRules(unittest.TestCase):
    def test_a_site_id_is_folded_and_bounded(self):
        self.assertEqual(normalise_site_id('  MAIN  '), 'main')
        self.assertEqual(len(normalise_site_id('x' * 500)), MAX_SITE_CHARS)

    def test_awkward_characters_are_removed(self):
        for raw, expected in (('site/../other', 'site..other'),
                              ('site name', 'sitename'),
                              ('site\x00id', 'siteid'),
                              ('site:id', 'siteid')):
            with self.subTest(raw=raw):
                self.assertEqual(normalise_site_id(raw), expected)

    def test_a_site_id_can_never_contain_a_path_separator(self):
        """It becomes a directory name in the model registry."""
        for raw in ('a/b', 'a\\b', '../../etc', 'a\x00b'):
            with self.subTest(raw=raw):
                cleaned = normalise_site_id(raw)
                for forbidden in ('/', '\\', '\x00'):
                    self.assertNotIn(forbidden, cleaned)

    def test_the_challenge_layer_uses_the_same_definition(self):
        """Two answers to "what is this site called" would eventually disagree."""
        for raw in ('MAIN', 'site-a', 'Site_B', 'a.b.c', 'x' * 200):
            with self.subTest(raw=raw):
                self.assertEqual(normalise_site(raw), normalise_site_id(raw)[:64])

    def test_the_challenge_layer_still_has_its_own_fallback(self):
        """An unnamed site still needs a key to sign with."""
        self.assertEqual(normalise_site(''), 'default')
        self.assertEqual(normalise_site(None), 'default')
        self.assertEqual(normalise_site_id(''), '')


if __name__ == '__main__':
    unittest.main()
