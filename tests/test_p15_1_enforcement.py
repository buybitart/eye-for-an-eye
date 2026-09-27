"""P15.1: host enforcement, against a real kernel where one is available.

Two halves, deliberately.

The **structural** half runs everywhere and needs no privilege: the request
vocabulary, the privilege separation, the refusals. These are the properties
that must hold on a developer laptop, in CI, and on a machine with no `nft` at
all, because they are properties of the code rather than of the environment.

The **kernel** half needs Linux, `nft` and root, and skips loudly otherwise. It
is the part P15 could not write. Every test in it creates a real table, writes a
real element with a real timeout, reads it back from the kernel and deletes it —
and two of them assert the thing that matters most: that a ruleset belonging to
somebody else is still there afterwards, untouched.

**Where this runs.** A disposable container that this session owns and can lose.
Not a laptop, not a production host, and not the machine anybody is reading this
on — §28. The teardown deletes one table by name and nothing else, so a failed
run leaves at most one expired-by-kernel table behind.
"""
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from eye_for_an_eye.autonomy.record import AutonomousDecisionRecord, TEMP_BLOCK
from eye_for_an_eye.config import Config
from eye_for_an_eye.security.enforcement import (EnforcementError, EnforcementRequest,
                                                 HOST_NETWORK, MAX_TTL_SECONDS,
                                                 ProtectedNetworks)
from eye_for_an_eye.security.host_enforcer import HostEnforcer, request_from_record
from eye_for_an_eye.security import host_firewall
from eye_for_an_eye.security.host_firewall import HostBackend, FAMILY

ROOT = Path(__file__).resolve().parents[1]

DECISION = 'dec-' + 'ab' * 9
REASONS = ('HIGH_PORT_BREADTH', 'AUTH_FAILURE_AUTOMATION', 'COST_BLOCK_PREFERRED')


def kernel_available():
    return (sys.platform.startswith('linux') and shutil.which('nft') is not None
            and os.geteuid() == 0)


requires_kernel = unittest.skipUnless(
    kernel_available() and os.environ.get('E4E_RUN_HOST_FIREWALL', '1') != '0',
    'host firewall tests need Linux, nft and root on a machine you can lose; '
    'set E4E_RUN_HOST_FIREWALL=0 to skip deliberately')

#: The reachability tests additionally need `ip` to build a veth pair. It is
#: separate from `requires_kernel` so the skip says which thing is missing —
#: "no iproute2" and "not root" call for completely different responses.
requires_veth = unittest.skipUnless(
    shutil.which('ip') is not None,
    'the reachability tests need iproute2 to build a throw-away veth pair')


def request(address='198.51.100.7', ttl=300, **changes):
    body = {'address': address, 'ttl_seconds': ttl, 'decision_id': DECISION,
            'reasons': REASONS, 'scope': HOST_NETWORK}
    body.update(changes)
    return EnforcementRequest(**body)


def blocking_record(**changes):
    body = {'action': TEMP_BLOCK, 'decision_id': DECISION, 'source': '198.51.100.7',
            'block_ttl_seconds': 300, 'reason_codes': REASONS,
            'network_enforceable': True, 'enforcement_scope': 'NETWORK_SOURCE',
            'shadow': False}
    body.update(changes)
    return AutonomousDecisionRecord(**body)


# --- structural: no privilege, no kernel ------------------------------------

class TestTheRequestVocabulary(unittest.TestCase):
    """§16, §18. What may cross the privilege boundary, and what may not."""

    def test_a_request_carries_no_command_field(self):
        """The property that keeps a privileged helper from being a shell."""
        fields = set(EnforcementRequest.__dataclass_fields__)
        self.assertEqual(fields, {'address', 'ttl_seconds', 'decision_id', 'reasons',
                                  'scope', 'version'})
        for forbidden in ('command', 'script', 'table', 'chain', 'rule', 'args',
                          'path', 'executable', 'nft'):
            with self.subTest(field=forbidden):
                self.assertNotIn(forbidden, fields)

    def test_every_block_names_source_family_scope_ttl_decision_and_reason(self):
        """§18's complete list, on one object."""
        body = request().explain()
        for key in ('address', 'family', 'scope', 'ttl_seconds', 'decision_id', 'reasons'):
            with self.subTest(key=key):
                self.assertTrue(body[key] not in (None, '', [], 0), key)

    def test_a_permanent_block_cannot_be_expressed(self):
        """§19. Not a policy: there is no value of the field that means forever."""
        for ttl in (0, -1, MAX_TTL_SECONDS + 1, 10 ** 9):
            with self.subTest(ttl=ttl):
                with self.assertRaises(EnforcementError):
                    request(ttl=ttl)

    def test_the_twelve_hour_ceiling_is_unchanged(self):
        self.assertEqual(MAX_TTL_SECONDS, 43_200)
        self.assertEqual(request(ttl=MAX_TTL_SECONDS).ttl_seconds, 43_200)

    def test_loopback_and_reserved_addresses_are_refused_at_construction(self):
        for address in ('127.0.0.1', '::1', '0.0.0.0', '224.0.0.1', '169.254.1.1', '::'):
            with self.subTest(address=address):
                with self.assertRaises(EnforcementError):
                    request(address=address)

    def test_a_block_must_name_the_decision_that_produced_it(self):
        for value in ('', 'nope', 'dec-zzzz', 'dec-' + 'ab' * 8):
            with self.subTest(decision_id=value):
                with self.assertRaises(EnforcementError):
                    request(decision_id=value)

    def test_a_block_must_name_at_least_one_reason(self):
        with self.assertRaises(EnforcementError):
            request(reasons=())
        with self.assertRaises(EnforcementError):
            request(reasons=('lowercase',))

    def test_only_the_host_network_scope_exists(self):
        """§32. There is no site-specific packet filter, so there is no such scope."""
        with self.assertRaises(EnforcementError):
            request(scope='SITE_WEB')

    def test_an_unknown_field_is_refused_rather_than_ignored(self):
        payload = json.dumps({'version': 1, 'scope': HOST_NETWORK,
                              'address': '198.51.100.7', 'ttl_seconds': 300,
                              'decision_id': DECISION, 'reasons': list(REASONS),
                              'command': 'flush ruleset'})
        with self.assertRaises(EnforcementError):
            EnforcementRequest.from_json(payload)

    def test_an_oversized_request_is_refused_before_parsing(self):
        with self.assertRaises(EnforcementError):
            EnforcementRequest.from_json('{"a":"' + 'x' * 8192 + '"}')

    def test_a_request_survives_a_round_trip(self):
        original = request()
        restored = EnforcementRequest.from_json(original.to_json())
        self.assertEqual(restored, original)

    def test_an_ipv4_mapped_address_normalises_to_the_same_machine(self):
        self.assertEqual(str(request(address='::ffff:198.51.100.7').parsed),
                         '198.51.100.7')


class TestProtectedNetworks(unittest.TestCase):
    """§23. The refusal an operator's access depends on."""

    def protection(self):
        config = Config()
        config.enforcement.management_networks = ['192.0.2.0/24']
        config.enforcement.allowlist = ['203.0.113.0/24']
        config.enforcement.trusted_proxies = ['10.0.0.0/8']
        return ProtectedNetworks.from_config(config).with_local(['198.51.100.200'])

    def test_loopback_is_always_protected(self):
        self.assertTrue(self.protection().protects(ipaddress.ip_address('127.0.0.1')))

    def test_a_management_network_is_protected_and_says_so(self):
        reason = self.protection().protects(ipaddress.ip_address('192.0.2.44'))
        self.assertIn('192.0.2.0/24', reason)

    def test_an_allowlisted_source_is_protected(self):
        self.assertTrue(self.protection().protects(ipaddress.ip_address('203.0.113.9')))

    def test_a_trusted_proxy_is_protected(self):
        """§22. Blocking the proxy takes the site off the air for everyone behind it."""
        self.assertTrue(self.protection().protects(ipaddress.ip_address('10.1.2.3')))

    def test_an_address_of_this_host_is_protected(self):
        self.assertIn('this host',
                      self.protection().protects(ipaddress.ip_address('198.51.100.200')))

    def test_an_ordinary_source_is_not_protected(self):
        self.assertEqual(self.protection().protects(ipaddress.ip_address('198.51.100.7')), '')

    def test_an_ipv4_mapped_protected_address_is_still_protected(self):
        mapped = ipaddress.ip_address('::ffff:192.0.2.44')
        self.assertTrue(self.protection().protects(mapped))


class TestPrivilegeSeparation(unittest.TestCase):
    """§16. A fact about the process table, not a claim about a call graph."""

    def test_the_decision_authority_imports_nothing_that_can_enforce(self):
        import ast
        source = (ROOT / 'eye_for_an_eye' / 'autonomy' / 'authority.py').read_text(encoding='utf-8')
        for node in ast.walk(ast.parse(source)):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or '')] + [a.name for a in node.names]
            for name in names:
                with self.subTest(imported=name):
                    for forbidden in ('host_firewall', 'host_enforcer', 'firewall',
                                      'subprocess', 'security'):
                        self.assertNotIn(forbidden, name)

    def test_the_unprivileged_enforcer_never_calls_nft_itself(self):
        import ast
        source = (ROOT / 'eye_for_an_eye' / 'security' / 'host_enforcer.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or '')
        self.assertNotIn('eye_for_an_eye.security.host_firewall', imported)
        self.assertNotIn('.host_firewall', imported)
        self.assertFalse(HostEnforcer.has_firewall_privilege)

    def test_the_helper_is_reached_as_a_module_of_this_interpreter(self):
        """No configurable executable: a settable helper path is a settable
        privileged program, and nothing needs one."""
        from eye_for_an_eye.security.host_enforcer import HELPER_MODULE
        self.assertEqual(HELPER_MODULE, 'eye_for_an_eye.security.firewall_helper')
        enforcer = HostEnforcer('/nonexistent.toml')
        self.assertEqual(enforcer.python, sys.executable)

    def test_no_module_in_the_project_flushes_a_ruleset(self):
        """§17. The one command that would be unrecoverable.

        Docstrings are stripped before scanning. `host_firewall.py` explains at
        length that it contains no `delete ruleset`, and a test that failed on
        the sentence saying so would be fixed by deleting the explanation —
        which is the trap `tests/denial.py` exists for, in a different costume.
        """
        import ast
        for path in sorted((ROOT / 'eye_for_an_eye').rglob('*.py')):
            if '__pycache__' in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'))
            literals = [node.value.lower() for node in ast.walk(tree)
                        if isinstance(node, ast.Constant) and isinstance(node.value, str)]
            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef)):
                    text = ast.get_docstring(node, clean=False)
                    if text:
                        docstrings.add(text.lower())
            for value in literals:
                if value in docstrings:
                    continue
                for forbidden in ('flush ruleset', 'delete ruleset', 'flush table',
                                  '--flush'):
                    with self.subTest(module=path.name, command=forbidden):
                        self.assertNotIn(forbidden, value)


class TestTheRecordAuthorisesTheRequest(unittest.TestCase):
    """The address and the TTL come from the decision, not from the caller."""

    def test_only_a_block_record_authorises_enforcement(self):
        from eye_for_an_eye.autonomy.record import ALLOW, COST_ALLOW_PREFERRED
        allowed = AutonomousDecisionRecord(action=ALLOW,
                                           reason_codes=(COST_ALLOW_PREFERRED,))
        with self.assertRaises(EnforcementError):
            request_from_record(allowed)

    def test_a_shadow_decision_is_a_record_not_an_instruction(self):
        with self.assertRaises(EnforcementError):
            request_from_record(blocking_record(shadow=True))

    def test_a_client_behind_a_proxy_is_never_network_enforced(self):
        """§22, and the invariant the whole web layer rests on."""
        with self.assertRaises(EnforcementError):
            request_from_record(blocking_record(network_enforceable=False))
        with self.assertRaises(EnforcementError):
            request_from_record(blocking_record(enforcement_scope='WEB_CLIENT'))

    def test_the_request_carries_the_records_own_address_and_ttl(self):
        record = blocking_record(source='203.0.113.5', block_ttl_seconds=1800)
        built = request_from_record(record)
        self.assertEqual(str(built.parsed), '203.0.113.5')
        self.assertEqual(built.ttl_seconds, 1800)
        self.assertEqual(built.decision_id, record.decision_id)


# --- kernel: a real table, real elements, real timeouts ---------------------

@requires_kernel
class TestAgainstTheRealKernel(unittest.TestCase):
    """The half P15 could not write. Creates and deletes one table, by name."""

    INSTALLATION = 'p15-1-test'

    def setUp(self):
        self.backend = HostBackend(self.INSTALLATION, max_entries=64)
        self.backend.cleanup()

    def tearDown(self):
        self.backend.cleanup()

    def test_the_owned_table_is_created_with_timeout_sets(self):
        result = self.backend.apply(request())
        self.assertTrue(result.applied, result.detail)
        self.assertTrue(result.verified, result.detail)
        self.assertTrue(result.succeeded)
        owned, detail = self.backend.owns_table()
        self.assertTrue(owned, detail)

    def test_apply_is_only_a_block_once_the_kernel_confirms_it(self):
        """§24. A failed apply is not a successful block."""
        result = self.backend.apply(request(ttl=120))
        entries = self.backend.entries()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry['address'], '198.51.100.7')
        self.assertEqual(entry['family'], 'ipv4')
        self.assertLessEqual(entry['timeout'], 120)
        self.assertGreater(entry['expires'], 0)
        self.assertLessEqual(entry['expires'], entry['timeout'])
        self.assertEqual(result.expires_in, entry['expires'])

    def test_every_element_carries_a_kernel_timeout(self):
        """§25. The property that makes a crash survivable."""
        for address, ttl in (('198.51.100.7', 60), ('203.0.113.9', 300),
                             ('2001:db8::1', 900)):
            self.backend.apply(request(address=address, ttl=ttl))
        for entry in self.backend.entries():
            with self.subTest(address=entry['address']):
                self.assertIsInstance(entry['timeout'], int)
                self.assertGreater(entry['timeout'], 0)
                self.assertLessEqual(entry['timeout'], MAX_TTL_SECONDS)

    def test_ipv6_goes_to_its_own_set(self):
        self.backend.apply(request(address='2001:db8::dead'))
        families = {entry['family'] for entry in self.backend.entries()}
        self.assertEqual(families, {'ipv6'})

    def test_a_block_expires_without_anybody_helping(self):
        """§24, §49. Watched, not asserted: the kernel counts it down."""
        self.backend.apply(request(ttl=2))
        self.assertEqual(len(self.backend.entries()), 1)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and self.backend.entries():
            time.sleep(0.5)
        self.assertEqual(self.backend.entries(), [],
                         'a two-second block outlived its timeout')

    def test_an_early_release_removes_exactly_one_element(self):
        self.backend.apply(request(address='198.51.100.7'))
        self.backend.apply(request(address='203.0.113.9'))
        self.assertTrue(self.backend.release(request(address='198.51.100.7')))
        remaining = [entry['address'] for entry in self.backend.entries()]
        self.assertEqual(remaining, ['203.0.113.9'])

    def test_repeating_a_block_does_not_duplicate_the_element(self):
        """§95. A set holds an address once."""
        self.backend.apply(request(ttl=300))
        self.backend.apply(request(ttl=300))
        self.assertEqual(len(self.backend.entries()), 1)

    def test_the_entry_ceiling_is_enforced_by_the_backend(self):
        small = HostBackend(self.INSTALLATION, max_entries=3)
        try:
            for octet in range(1, 6):
                small.apply(request(address=f'198.51.100.{octet}'))
            self.assertLessEqual(len(small.entries()), 3)
        finally:
            small.cleanup()

    def test_a_dry_run_validates_against_the_live_ruleset_and_writes_nothing(self):
        """§27."""
        self.backend.apply(request(address='203.0.113.1'))
        before = self.backend.entries()
        preview = self.backend.dry_run(request(address='198.51.100.7'))
        self.assertTrue(preview['validated'], preview['detail'])
        self.assertIn('add element', preview['script'])
        self.assertEqual(self.backend.entries(), before)

    def test_status_reports_what_exists(self):
        self.backend.apply(request())
        body = self.backend.status()
        self.assertTrue(body['available'])
        self.assertTrue(body['owned_table_present'])
        self.assertEqual(body['active_blocks'], 1)

    def test_reconcile_adopts_our_own_table_after_a_restart(self):
        """§25. A new backend object, the same installation, the same table."""
        self.backend.apply(request(ttl=600))
        restarted = HostBackend(self.INSTALLATION, max_entries=64)
        body = restarted.reconcile()
        self.assertTrue(body['adopted'], body['detail'])
        self.assertEqual(len(body['entries']), 1)
        self.assertEqual(body['unbounded'], [])

    def test_cleanup_deletes_our_table_and_reports_it(self):
        self.backend.apply(request())
        body = self.backend.cleanup()
        self.assertTrue(body['deleted'], body['detail'])
        owned, _ = self.backend.owns_table()
        self.assertFalse(owned)


@requires_kernel
class TestOwnershipIsolation(unittest.TestCase):
    """§17, §26. The tests that say what happens to somebody else's rules."""

    NEIGHBOUR = 'e4e_p15_1_neighbour'

    def setUp(self):
        self.backend = HostBackend('p15-1-isolation', max_entries=16)
        self.backend.cleanup()
        self._nft(['add', 'table', 'inet', self.NEIGHBOUR])
        self._nft(['add', 'chain', 'inet', self.NEIGHBOUR, 'forward',
                   '{ type filter hook forward priority 0; policy accept; }'])

    def tearDown(self):
        self.backend.cleanup()
        self._nft(['delete', 'table', 'inet', self.NEIGHBOUR])

    def _nft(self, args):
        return subprocess.run([shutil.which('nft'), *args], capture_output=True,
                              text=True, timeout=5, check=False)

    def _tables(self):
        result = self._nft(['-j', 'list', 'tables'])
        return {item['table']['name'] for item in json.loads(result.stdout)['nftables']
                if 'table' in item}

    def test_applying_a_block_leaves_an_unrelated_table_alone(self):
        before = self._tables()
        self.assertIn(self.NEIGHBOUR, before)
        self.backend.apply(request())
        after = self._tables()
        self.assertIn(self.NEIGHBOUR, after, 'an unrelated table disappeared')
        self.assertEqual(before - {self.backend.table}, after - {self.backend.table})

    def test_cleanup_leaves_an_unrelated_table_alone(self):
        self.backend.apply(request())
        self.backend.cleanup()
        self.assertIn(self.NEIGHBOUR, self._tables())

    def test_a_table_with_our_name_and_another_owner_is_refused_not_adopted(self):
        """The reason ownership is a comment and not just a name."""
        self.backend.cleanup()
        name = self.backend.table
        self._nft(['add', 'table', FAMILY, name, '{ comment "somebody-else"; }'])
        try:
            owned, detail = self.backend.owns_table()
            self.assertFalse(owned)
            self.assertIn('not ours', detail)
            with self.assertRaises(host_firewall.HostFirewallError):
                self.backend.apply(request())
            body = self.backend.cleanup()
            self.assertFalse(body['deleted'])
            self.assertIn(name, self._tables(), 'a foreign table was deleted')
        finally:
            self._nft(['delete', 'table', FAMILY, name])

    def test_two_installations_own_separate_tables(self):
        """One host, two sensors, no silent refusal and no takeover."""
        self.backend.apply(request())
        other = HostBackend('a-different-installation', max_entries=16)
        self.assertNotEqual(other.table, self.backend.table)
        owned, detail = other.owns_table()
        self.assertFalse(owned)
        self.assertEqual(detail, 'no table')
        try:
            self.assertTrue(other.apply(request(address='203.0.113.44')).succeeded)
            self.assertEqual(len(self.backend.entries()), 1)
            self.assertEqual(len(other.entries()), 1)
        finally:
            other.cleanup()


@requires_kernel
class TestTheHelperRefusesWhatItMust(unittest.TestCase):
    """§20, §23, §29. The lockout tests, through the real privilege boundary."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.directory = tempfile.mkdtemp(prefix='e4e-p15-1-')
        cls.config_path = Path(cls.directory) / 'host.toml'

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory, ignore_errors=True)

    def write_config(self, *, host_enabled=True, management=('192.0.2.0/24',)):
        body = ['config_version = 1', '', '[decision]', 'enabled = true', '',
                '[enforcement]', f'host_enabled = {str(host_enabled).lower()}',
                'management_networks = [' + ', '.join(f'"{n}"' for n in management) + ']',
                'trusted_proxies = ["10.0.0.0/8"]']
        self.config_path.write_text('\n'.join(body) + '\n', encoding='utf-8')
        return str(self.config_path)

    def run_helper(self, verb, payload=None, **config):
        path = self.write_config(**config)
        completed = subprocess.run(
            [sys.executable, '-m', 'eye_for_an_eye.security.firewall_helper',
             '--config', path, verb],
            input=payload, text=True, capture_output=True, timeout=20, check=False,
            cwd=str(ROOT))
        try:
            document = json.loads(completed.stdout or '{}')
        except ValueError:
            document = {'unparseable': completed.stdout[:200], 'stderr': completed.stderr[:200]}
        return completed.returncode, document

    def setUp(self):
        self.cleanup_backend().cleanup()

    def tearDown(self):
        self.cleanup_backend().cleanup()

    def cleanup_backend(self):
        """The backend the helper itself would build, so teardown reaches the
        same table. The installation name comes from `runtime.sensor_id`, which
        defaults to `local` -- guessing it here once cost a confusing failure."""
        from eye_for_an_eye.security.firewall_helper import _installation
        from eye_for_an_eye.config import load_config
        return HostBackend(_installation(load_config(self.write_config())),
                           max_entries=16)

    def test_host_enforcement_is_refused_while_the_switch_is_off(self):
        """§20. Code existing is not permission."""
        code, body = self.run_helper('apply', request().to_json(), host_enabled=False)
        self.assertNotEqual(code, 0)
        self.assertTrue(body.get('refused'))
        self.assertIn('host_enabled', body.get('reason', ''))

    def test_a_management_address_is_refused_at_the_helper(self):
        """§23, §29. The refusal an operator's access depends on."""
        payload = request(address='192.0.2.44').to_json()
        code, body = self.run_helper('apply', payload)
        self.assertNotEqual(code, 0)
        self.assertIn('protected', body.get('reason', ''))

    def test_a_trusted_proxy_is_refused_at_the_helper(self):
        """§22, §29."""
        code, body = self.run_helper('apply', request(address='10.4.5.6').to_json())
        self.assertNotEqual(code, 0)
        self.assertIn('protected', body.get('reason', ''))

    def test_loopback_is_refused_before_it_reaches_the_backend(self):
        payload = json.dumps({'version': 1, 'scope': HOST_NETWORK,
                              'address': '127.0.0.1', 'ttl_seconds': 300,
                              'decision_id': DECISION, 'reasons': list(REASONS)})
        code, body = self.run_helper('apply', payload)
        self.assertNotEqual(code, 0)
        self.assertTrue(body.get('refused'))

    def test_an_installation_with_no_protected_network_is_refused(self):
        code, body = self.run_helper('apply', request().to_json(), management=())
        self.assertNotEqual(code, 0)
        self.assertTrue(body.get('refused'))
        # Configuration validation refuses it before the helper's own check ever
        # runs, which is the better of the two places for it to fail.
        self.assertIn('refused', body.get('reason', '').lower())

    def test_a_request_with_a_command_field_is_refused(self):
        payload = json.dumps({'version': 1, 'scope': HOST_NETWORK,
                              'address': '198.51.100.7', 'ttl_seconds': 300,
                              'decision_id': DECISION, 'reasons': list(REASONS),
                              'command': 'flush ruleset'})
        code, body = self.run_helper('apply', payload)
        self.assertNotEqual(code, 0)
        self.assertTrue(body.get('refused'))

    def test_an_ordinary_source_is_applied_and_verified(self):
        code, body = self.run_helper('apply', request(address='198.51.100.77').to_json())
        self.assertEqual(code, 0, body)
        self.assertTrue(body.get('ok'), body)
        self.assertTrue(body['result']['verified'])
        self.assertGreater(body['result']['expires_in_seconds'], 0)

    def test_a_dry_run_writes_nothing(self):
        code, body = self.run_helper('dry-run', request(address='198.51.100.88').to_json())
        self.assertEqual(code, 0, body)
        code, status = self.run_helper('status')
        self.assertEqual(status.get('active_blocks', 0), 0)


@requires_kernel
class TestEnforcementFailureInjection(unittest.TestCase):
    """§31. Break one thing; assert the host firewall is still intact."""

    def setUp(self):
        self.backend = HostBackend('p15-1-failure', max_entries=8)
        self.backend.cleanup()

    def tearDown(self):
        self.backend.cleanup()

    def _tables(self):
        result = subprocess.run([shutil.which('nft'), '-j', 'list', 'tables'],
                                capture_output=True, text=True, timeout=5, check=False)
        return {item['table']['name'] for item in json.loads(result.stdout)['nftables']
                if 'table' in item}

    def test_a_missing_nft_is_reported_and_changes_nothing(self):
        missing = HostBackend('p15-1-failure', nft_path='/nonexistent/nft')
        usable, reason = missing.available()
        self.assertFalse(usable)
        self.assertIn('nft', reason)

    def test_an_invalid_rule_is_refused_by_the_check_pass(self):
        """`nft -c` runs before `nft -f`, so a bad script never commits."""
        broken = HostBackend('p15-1-failure')
        broken.owner = 'e4e:p15.1:"; flush ruleset; #'
        before = self._tables()
        with self.assertRaises(host_firewall.HostFirewallError):
            broken.apply(request())
        self.assertEqual(self._tables() - {broken.table}, before - {broken.table},
                         'a malformed owner comment reached the ruleset')

    def test_a_failed_verification_is_not_a_successful_block(self):
        """The kernel disagreeing with the write is a failure, not a warning."""
        self.backend.apply(request(ttl=300))
        self.backend.release(request())
        verified, expires, detail = self.backend._verify_element(request())
        self.assertFalse(verified)
        self.assertIn('not in the owned set', detail)

    def test_the_backend_survives_the_table_being_removed_underneath_it(self):
        self.backend.apply(request())
        subprocess.run([shutil.which('nft'), 'delete', 'table', FAMILY,
                        self.backend.table], capture_output=True, timeout=5, check=False)
        self.assertEqual(self.backend.entries(), [])
        result = self.backend.apply(request())
        self.assertTrue(result.succeeded, result.detail)

    def test_no_failure_path_deletes_an_unrelated_table(self):
        neighbour = 'e4e_p15_1_bystander'
        subprocess.run([shutil.which('nft'), 'add', 'table', 'inet', neighbour],
                       capture_output=True, timeout=5, check=False)
        try:
            for attempt in (request(address='198.51.100.7'),):
                self.backend.apply(attempt)
            self.backend.cleanup()
            self.assertIn(neighbour, self._tables())
        finally:
            subprocess.run([shutil.which('nft'), 'delete', 'table', 'inet', neighbour],
                           capture_output=True, timeout=5, check=False)


@requires_kernel
class TestTheMassBlockBreakerKeepsTheHostReachable(unittest.TestCase):
    """§30. A classifier that says malicious to everything, against a real firewall."""

    def setUp(self):
        self.backend = HostBackend('p15-1-breaker', max_entries=1024)
        self.backend.cleanup()

    def tearDown(self):
        self.backend.cleanup()

    def test_the_block_budget_bounds_what_reaches_the_kernel(self):
        from eye_for_an_eye.autonomy.breakers import BreakerPanel, BudgetLimits
        panel = BreakerPanel(BudgetLimits(blocks_per_minute=5, max_active_blocks=1000))
        applied = 0
        for octet in range(1, 60):
            allowed, code, _ = panel.permits_block()
            if not allowed:
                continue
            result = self.backend.apply(request(address=f'198.51.100.{octet}'))
            if result.succeeded:
                panel.record_block()
                applied += 1
        self.assertEqual(applied, 5, 'the budget did not bound what reached the kernel')
        self.assertEqual(len(self.backend.entries()), 5)

    def test_the_management_network_survives_a_model_that_flags_everything(self):
        """The whole point: the operator can still reach the machine."""
        config = Config()
        config.enforcement.management_networks = ['192.0.2.0/24']
        protection = ProtectedNetworks.from_config(config)
        refused = applied = 0
        for octet in range(1, 40):
            for prefix in ('192.0.2.', '198.51.100.'):
                address = ipaddress.ip_address(prefix + str(octet))
                if protection.protects(address):
                    refused += 1
                    continue
                if self.backend.apply(request(address=str(address))).succeeded:
                    applied += 1
        self.assertEqual(refused, 39, 'a management address was not refused')
        blocked = {entry['address'] for entry in self.backend.entries()}
        self.assertFalse(any(a.startswith('192.0.2.') for a in blocked))
        self.assertGreater(applied, 0)


@requires_kernel
@requires_veth
class TestTheBlockActuallyStopsTraffic(unittest.TestCase):
    """The one question every other test in this file assumes the answer to.

    Everything above verifies that an element is in a set the kernel agrees
    exists, with a timeout the kernel is counting down. None of it verifies that
    a packet from that address fails to arrive. Those are different claims, and a
    project that shipped the first while believing it had shown the second would
    have a firewall that is correct in every respect except the only one that
    matters.

    So: a veth pair into a throw-away namespace, a listener on this side, and a
    real TCP connection from the other. Reachable, blocked, reachable again.

    The namespace exists only to give the traffic a source address that is not
    this host's. A protected address could not be blocked — that is the point of
    the protection, and it would make this test vacuous. Everything created here
    is named and deleted in `tearDownClass`.
    """

    NS = 'e4e_reach_test'
    HOST_SIDE = 'e4ereach0'
    PEER_SIDE = 'e4ereach1'
    HOST_ADDRESS = '198.51.100.1'
    PEER_ADDRESS = '198.51.100.2'
    PORT = 59187

    @classmethod
    def _ip(cls, *arguments, check=True):
        return subprocess.run([shutil.which('ip'), *arguments], check=check,
                              capture_output=True, text=True, timeout=20)

    @classmethod
    def setUpClass(cls):
        cls.listener = None
        cls.serving = False
        cls._ip('netns', 'add', cls.NS)
        try:
            cls._ip('link', 'add', cls.HOST_SIDE, 'type', 'veth',
                    'peer', 'name', cls.PEER_SIDE)
            cls._ip('link', 'set', cls.PEER_SIDE, 'netns', cls.NS)
            cls._ip('addr', 'add', f'{cls.HOST_ADDRESS}/24', 'dev', cls.HOST_SIDE)
            cls._ip('link', 'set', cls.HOST_SIDE, 'up')
            cls._ip('netns', 'exec', cls.NS, 'ip', 'addr', 'add',
                    f'{cls.PEER_ADDRESS}/24', 'dev', cls.PEER_SIDE)
            cls._ip('netns', 'exec', cls.NS, 'ip', 'link', 'set', cls.PEER_SIDE, 'up')
            cls.listener = socket.socket()
            cls.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            cls.listener.bind((cls.HOST_ADDRESS, cls.PORT))
            cls.listener.listen(16)
            cls.serving = True
            threading.Thread(target=cls._serve, daemon=True).start()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def _serve(cls):
        while cls.serving:
            try:
                connection, _ = cls.listener.accept()
            except OSError:
                return
            try:
                connection.sendall(b'ok')
            finally:
                connection.close()

    @classmethod
    def tearDownClass(cls):
        cls.serving = False
        if cls.listener is not None:
            cls.listener.close()
        cls._ip('link', 'del', cls.HOST_SIDE, check=False)
        cls._ip('netns', 'del', cls.NS, check=False)

    def setUp(self):
        self.backend = HostBackend(installation='reachability')
        self.addCleanup(self.backend.cleanup)

    def reachable(self):
        """Does a TCP connection from the peer address complete?

        Run inside the namespace, with a short timeout. A DROP produces no
        refusal, so an unreachable host is a timeout rather than a connection
        error — and distinguishing those two is exactly what tells a firewall
        drop apart from a listener that died.
        """
        probe = ('import socket, sys\n'
                 's = socket.socket()\n'
                 's.settimeout(3)\n'
                 'try:\n'
                 f'    s.connect(({self.HOST_ADDRESS!r}, {self.PORT}))\n'
                 '    sys.stdout.write(s.recv(2).decode())\n'
                 'except OSError:\n'
                 "    sys.stdout.write('unreachable')\n")
        result = subprocess.run(
            [shutil.which('ip'), 'netns', 'exec', self.NS, sys.executable, '-c', probe],
            capture_output=True, text=True, timeout=30)
        self.assertIn(result.stdout.strip(), ('ok', 'unreachable'), result.stderr)
        return result.stdout.strip() == 'ok'

    def test_a_block_stops_real_packets_and_a_release_lets_them_through_again(self):
        self.assertTrue(self.reachable(),
                        'the probe could not reach the listener before any block; '
                        'this test proves nothing until it can')

        applied = self.backend.apply(request(address=self.PEER_ADDRESS, ttl=300))
        self.assertTrue(applied.applied and applied.verified, applied.detail)
        self.assertFalse(self.reachable(),
                         'the element is in the kernel set and the packet still '
                         'arrived: the set is not attached to a drop rule')

        self.assertTrue(self.backend.release(request(address=self.PEER_ADDRESS)))
        self.assertTrue(self.reachable(),
                        'the block was released and the source is still cut off')

    def test_an_expiring_block_restores_traffic_without_anybody_acting(self):
        """Crash safety, end to end.

        Nothing calls release here. The kernel timeout runs out on its own and
        the source is reachable again, which is what protects a stranger from a
        permanent block when this software dies in the middle of an incident.

        Eight seconds, not two: a probe against a dropped address costs the
        socket timeout, so a shorter block expires *during* the measurement and
        the test would fail for a reason that is not about the system.
        """
        applied = self.backend.apply(request(address=self.PEER_ADDRESS, ttl=8))
        self.assertTrue(applied.applied and applied.verified, applied.detail)
        self.assertFalse(self.reachable())
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.reachable():
                break
            time.sleep(0.5)
        else:
            self.fail('an eight-second block was still dropping traffic a minute later')
        self.assertEqual(self.backend.entries(), [],
                         'traffic returned while the element was still in the set')

    def test_blocking_one_address_does_not_cut_off_another(self):
        """A block is about one source, not about the link it arrived on."""
        self.backend.apply(request(address='198.51.100.9', ttl=300))
        self.assertTrue(self.reachable(),
                        'blocking one address cut off a different one')


if __name__ == '__main__':
    unittest.main()
