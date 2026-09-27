from copy import deepcopy
import sys
import unittest
from unittest.mock import patch
from eye_for_an_eye.config import Config
from eye_for_an_eye.security.firewall import FirewallManager, NamespaceBackend, OWNER, TABLE, fingerprint, render


def lab_config():
    config = Config()
    config.firewall.enabled = True
    config.firewall.lab_namespace = 'e4e-lab-sensor'
    config.firewall.destination_addresses = ['10.203.0.1']
    config.firewall.decoy_ports = [2222, 8080]
    return config.validate()


def nft_fixture(config):
    def match(protocol, field, value):
        return {'match': {'op': '==', 'left': {'payload': {'protocol': protocol, 'field': field}}, 'right': value}}
    return {'nftables': [
        {'table': {'family': 'ip', 'name': TABLE, 'comment': OWNER + fingerprint(config)}},
        {'chain': {'family': 'ip', 'table': TABLE, 'name': 'prerouting', 'type': 'nat', 'hook': 'prerouting', 'prio': -100, 'policy': 'accept'}},
        {'set': {'family': 'ip', 'table': TABLE, 'name': 'leased_ports', 'type': 'inet_service', 'flags': ['timeout'], 'timeout': 30,
                 'elem': [{'elem': {'val': port, 'expires': 29}} for port in config.firewall.decoy_ports]}},
        {'rule': {'chain': 'prerouting', 'expr': [match('tcp', 'dport', {'set': [22, 3389, 1234]}), {'return': None}]}},
        {'rule': {'chain': 'prerouting', 'expr': [match('ip', 'daddr', '10.203.0.1'), match('tcp', 'dport', '@leased_ports'), {'redirect': {'port': 1234}}]}}
    ]}


class FakeBackend:
    def __init__(self, config):
        self.config, self.state = config, None
        self.is_ready = True
        self.calls = []
        self.foreign_rules = {'real_service': 'unchanged'}

    def read(self):
        return deepcopy(self.state)

    def ready(self):
        return self.is_ready

    def transaction(self, script):
        self.calls.append(script)
        self.state = None if script == f'delete table ip {TABLE}\n' else nft_fixture(self.config)


class FirewallTests(unittest.TestCase):
    def test_dry_run_never_calls_backend_or_shell(self):
        with patch('subprocess.run', side_effect=AssertionError('shell')), patch('socket.socket', side_effect=AssertionError('network')):
            result = FirewallManager(lab_config()).dry_run()
        self.assertIn('flags timeout', result['script'])
        self.assertNotIn('flush', result['script'])
        self.assertEqual(result['ipv6'], 'unsupported')

    def test_apply_verify_idempotent_rollback_and_foreign_rules(self):
        config = lab_config()
        backend = FakeBackend(config)
        manager = FirewallManager(config, backend=backend)
        manager.apply()
        expected = backend.read()
        manager.apply()
        self.assertEqual(expected, backend.read())
        self.assertEqual(manager.verify()['status'], 'healthy')
        self.assertTrue(backend.calls[1].startswith('delete table ip eye_for_an_eye'))
        manager.rollback()
        self.assertEqual(manager.rollback()['reason'], 'already_absent')
        self.assertEqual(backend.foreign_rules, {'real_service': 'unchanged'})

    def test_readiness_and_collision_fail_closed(self):
        config = lab_config()
        backend = FakeBackend(config)
        manager = FirewallManager(config, backend=backend)
        backend.is_ready = False
        with self.assertRaises(RuntimeError):
            manager.apply()
        self.assertEqual(backend.calls, [])
        backend.state = nft_fixture(config)
        self.assertEqual(manager.verify()['reason'], 'listener_unavailable')
        backend.state['nftables'][0]['table']['comment'] = 'someone else'
        for operation in (manager.apply, manager.rollback):
            with self.assertRaises(PermissionError):
                operation()

    def test_tampering_and_expired_lease_are_not_verified(self):
        config = lab_config()
        backend = FakeBackend(config)
        manager = FirewallManager(config, backend=backend)
        manager.apply()
        backend.state['nftables'][-1]['rule']['expr'][-1]['redirect']['port'] = 22
        self.assertEqual(manager.verify()['status'], 'degraded')
        backend.state = nft_fixture(config)
        backend.state['nftables'][2]['set']['elem'] = []
        self.assertEqual(manager.verify()['status'], 'degraded')
        backend.state = nft_fixture(config)
        backend.state['nftables'][2]['set']['timeout'] = 30000
        self.assertEqual(manager.verify()['status'], 'degraded')

    def test_protected_ports_ipv6_and_namespace_rejected(self):
        for key, value in (('decoy_ports', [22]), ('destination_addresses', ['::1']), ('lab_namespace', 'default; bad')):
            config = lab_config()
            setattr(config.firewall, key, value)
            with self.subTest(key=key), self.assertRaises(ValueError):
                render(config)

    def test_no_host_execution_on_non_linux(self):
        with patch.object(sys, 'platform', 'win32'), patch('subprocess.run', side_effect=AssertionError('host command')):
            with self.assertRaises(RuntimeError):
                NamespaceBackend(lab_config())._run(['nft', 'list', 'tables'])
