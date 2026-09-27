"""Can a source choose which cutoff it is judged at? P15.5R §18, §19.

### The property being defended

`ScopeResolver.resolve` prices a window at the most protective profile among the
scopes that apply to it. That rule is only sound if the *candidate set* is
honest. Every mechanism between "the ports this window touched" and "the scopes
that competed" is therefore a place where a source could, by choosing what else
to touch, arrange to be judged at a cheaper cutoff than the one its target
deserves.

There was such a place. The candidate list was capped at sixteen scopes and the
cap was applied to the raw list of destination ports in arrival order, so a
source that touched seventeen other ports first pushed the priced one off the
end. `tests/test_p15_5r_runtime_end_to_end.py` found it by accident: a port-22
scanner was priced at `public_website` because port 22 was the twenty-first
distinct port in that window.

### Why the fix is ordering rather than a bigger limit

A larger cap postpones the same defect and leaves the security property
depending on a number. Filtering to the operator's map bounds the list by
configuration instead of by traffic, and sorting by protection before truncating
makes the truncation harmless by construction: everything dropped is something
that could not have won. After both, the answer does not depend on arrival order
at all — which is what these tests check, by shuffling.
"""
import random
import unittest

from eye_for_an_eye.autonomy.cost import CostPolicy
from eye_for_an_eye.autonomy.scope import (GLOBAL, MAX_SERVICE_SCOPES, ScopeResolver,
                                           service_scope)


class Sample:
    """The two fields `services_for` reads off a correlation sample."""

    def __init__(self, port, transport='tcp'):
        self.port = port
        self.transport = transport


def resolver(mapping, *, default='public_website'):
    return ScopeResolver(CostPolicy(scope_profiles=dict(mapping),
                                    default_profile=default))


class TestPortChurnCannotEvictTheProtectedService(unittest.TestCase):
    """§19, the headline case."""

    def test_a_priced_service_survives_a_flood_of_unpriced_ports(self):
        scopes = resolver({'SERVICE:22/tcp': 'api'})
        window = [Sample(40000 + n) for n in range(2000)] + [Sample(22)]
        self.assertEqual(scopes.services_for(window), ('SERVICE:22/tcp',))
        self.assertEqual(scopes.resolve(services=scopes.services_for(window)).profile.name,
                         'api')

    def test_a_priced_service_survives_a_flood_of_cheaper_priced_ports(self):
        """The case filtering alone does not fix: every distractor is mapped."""
        mapping = {f'SERVICE:{9000 + n}/tcp': 'honeypot'
                   for n in range(MAX_SERVICE_SCOPES * 4)}
        mapping['SERVICE:22/tcp'] = 'api'
        scopes = resolver(mapping)
        window = [Sample(9000 + n) for n in range(MAX_SERVICE_SCOPES * 4)]
        window.append(Sample(22))
        services = scopes.services_for(window)
        self.assertIn('SERVICE:22/tcp', services)
        self.assertEqual(scopes.resolve(services=services).profile.name, 'api')

    def test_the_protected_service_is_first_whatever_the_arrival_order(self):
        mapping = {f'SERVICE:{9000 + n}/tcp': 'honeypot' for n in range(40)}
        mapping['SERVICE:443/tcp'] = 'payment_webhook'
        scopes = resolver(mapping)
        ports = [9000 + n for n in range(40)] + [443]
        rng = random.Random(20260919)
        for attempt in range(12):
            rng.shuffle(ports)
            with self.subTest(attempt=attempt):
                services = scopes.services_for([Sample(p) for p in ports])
                self.assertEqual(services[0], 'SERVICE:443/tcp')

    def test_the_decision_is_identical_under_every_arrival_order(self):
        """The property, stated directly: no dependence on insertion order."""
        mapping = {'SERVICE:80/tcp': 'public_website', 'SERVICE:443/tcp': 'api',
                   'SERVICE:22/tcp': 'admin', 'SERVICE:2222/tcp': 'honeypot'}
        scopes = resolver(mapping)
        ports = [80, 443, 22, 2222] * 6
        rng = random.Random(7)
        answers = set()
        for _ in range(24):
            rng.shuffle(ports)
            services = scopes.services_for([Sample(p) for p in ports])
            answers.add((services, scopes.resolve(services=services).profile.name))
        self.assertEqual(len(answers), 1, answers)


class TestCardinalityPressure(unittest.TestCase):
    """§19. Bounded means bounded, even under a map an operator over-filled."""

    def test_the_candidate_list_stays_capped(self):
        mapping = {f'SERVICE:{1000 + n}/tcp': 'api' for n in range(200)}
        scopes = resolver(mapping)
        window = [Sample(1000 + n) for n in range(200)]
        self.assertEqual(len(scopes.services_for(window)), MAX_SERVICE_SCOPES)

    def test_an_enormous_window_of_unpriced_ports_costs_nothing(self):
        scopes = resolver({})
        window = [Sample(n) for n in range(1, 60000)]
        self.assertEqual(scopes.services_for(window), ())
        self.assertEqual(scopes.resolve(services=()).scope, GLOBAL)

    def test_malformed_ports_are_ignored_rather_than_named(self):
        scopes = resolver({'SERVICE:443/tcp': 'api'})
        window = [Sample(None), Sample(-1), Sample(70000), Sample('nonsense'),
                  Sample(443)]
        self.assertEqual(scopes.services_for(window), ('SERVICE:443/tcp',))


class TestAddressFamilyDoesNotChangeTheService(unittest.TestCase):
    """§19. A service is the thing listening, not the family reaching it.

    `service_scope` is built from the destination port and transport, both of
    which a correlation sample carries regardless of whether the packet was IPv4
    or IPv6. That is deliberate: if the scope differed by family, a source could
    dodge a priced service by connecting over the other one.
    """

    def test_the_same_port_resolves_to_the_same_scope_either_way(self):
        # `Sample` carries no address family, exactly as the real one does not
        # for this purpose; the destination address lives in `destination`.
        self.assertEqual(service_scope(443, 'tcp'), 'SERVICE:443/tcp')
        scopes = resolver({'SERVICE:443/tcp': 'api'})
        for label in ('ipv4', 'ipv6'):
            with self.subTest(family=label):
                services = scopes.services_for([Sample(443)])
                self.assertEqual(services, ('SERVICE:443/tcp',))

    def test_transport_does_distinguish_a_service(self):
        """UDP 443 and TCP 443 are different things listening."""
        self.assertNotEqual(service_scope(443, 'tcp'), service_scope(443, 'udp'))
        scopes = resolver({'SERVICE:443/tcp': 'api'})
        self.assertEqual(scopes.services_for([Sample(443, 'udp')]), ())

    def test_an_unknown_transport_does_not_become_a_wildcard(self):
        self.assertEqual(service_scope(443, ''), 'SERVICE:443/unknown')
        self.assertEqual(service_scope(443, 'tcp; drop table'), 'SERVICE:443/unknown')


class TestMultipleLegitimateServices(unittest.TestCase):
    """§19. A machine hosting several priced services still prices correctly."""

    MAPPING = {'SERVICE:80/tcp': 'public_website',
               'SERVICE:443/tcp': 'api',
               'SERVICE:8443/tcp': 'admin',
               'SERVICE:9999/tcp': 'payment_webhook'}

    def test_each_service_alone_prices_at_its_own_profile(self):
        scopes = resolver(self.MAPPING)
        for port, expected in ((80, 'public_website'), (443, 'api'),
                               (8443, 'admin'), (9999, 'payment_webhook')):
            with self.subTest(port=port):
                services = scopes.services_for([Sample(port)])
                self.assertEqual(scopes.resolve(services=services).profile.name,
                                 expected)

    def test_a_window_spanning_two_takes_the_more_protective(self):
        scopes = resolver(self.MAPPING)
        services = scopes.services_for([Sample(8443), Sample(443)])
        resolution = scopes.resolve(services=services)
        self.assertEqual(resolution.profile.name, 'api')
        self.assertTrue(resolution.ambiguous)

    def test_a_window_touching_the_no_block_service_refuses_outright(self):
        """§14, §21. Not a higher cutoff — a profile that forbids the action."""
        scopes = resolver(self.MAPPING)
        services = scopes.services_for([Sample(80), Sample(443), Sample(9999)])
        resolution = scopes.resolve(services=services)
        self.assertEqual(resolution.profile.name, 'payment_webhook')
        self.assertFalse(resolution.profile.network_block_permitted)

    def test_a_mapped_service_takes_precedence_over_the_deployment_default(self):
        """`GLOBAL` is the fallback, not a competitor.

        The operator who wrote `SERVICE:2222/tcp = "honeypot"` on an API
        deployment said something more specific than "this machine is an API",
        and a rule that let the default win whenever it was more protective
        would make every profile cheaper than the default unreachable — which
        is configuration that appears to work and does not.
        """
        scopes = resolver({'SERVICE:2222/tcp': 'honeypot'}, default='api')
        services = scopes.services_for([Sample(2222)])
        self.assertEqual(scopes.resolve(services=services).profile.name, 'honeypot')

    def test_the_default_applies_when_no_specific_scope_does(self):
        scopes = resolver({'SERVICE:2222/tcp': 'honeypot'}, default='api')
        self.assertEqual(scopes.resolve(services=()).profile.name, 'api')
        self.assertEqual(scopes.resolve(services=()).scope, GLOBAL)

    def test_adding_a_service_can_only_move_the_answer_towards_protection(self):
        """The adversarial property, after the precedence rule.

        A source on the cheap service cannot make itself cheaper by touching
        the expensive one as well — it can only make itself more expensive.
        """
        scopes = resolver({'SERVICE:2222/tcp': 'honeypot',
                           'SERVICE:443/tcp': 'api'}, default='public_website')
        cheap = scopes.resolve(services=scopes.services_for([Sample(2222)]))
        both = scopes.resolve(
            services=scopes.services_for([Sample(2222), Sample(443)]))
        self.assertEqual(cheap.profile.name, 'honeypot')
        self.assertEqual(both.profile.name, 'api')
        self.assertGreater(both.profile.threshold, cheap.profile.threshold)


class TestTheOrderingItself(unittest.TestCase):
    """The sort key, checked directly, because everything above rests on it."""

    def test_a_no_block_profile_sorts_ahead_of_every_cutoff(self):
        scopes = resolver({'SERVICE:1/tcp': 'payment_webhook',
                           'SERVICE:2/tcp': 'api'})
        self.assertEqual(scopes.services_for([Sample(2), Sample(1)])[0],
                         'SERVICE:1/tcp')

    def test_higher_cutoffs_sort_ahead_of_lower_ones(self):
        scopes = resolver({'SERVICE:1/tcp': 'honeypot', 'SERVICE:2/tcp': 'admin',
                           'SERVICE:3/tcp': 'public_website', 'SERVICE:4/tcp': 'api'})
        order = scopes.services_for([Sample(n) for n in (1, 2, 3, 4)])
        self.assertEqual(order, ('SERVICE:4/tcp', 'SERVICE:3/tcp',
                                 'SERVICE:2/tcp', 'SERVICE:1/tcp'))

    def test_two_scopes_on_one_profile_order_by_name(self):
        scopes = resolver({'SERVICE:8/tcp': 'api', 'SERVICE:9/tcp': 'api'})
        self.assertEqual(scopes.services_for([Sample(9), Sample(8)]),
                         ('SERVICE:8/tcp', 'SERVICE:9/tcp'))


if __name__ == '__main__':
    unittest.main()
