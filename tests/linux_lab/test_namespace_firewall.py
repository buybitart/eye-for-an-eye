"""Opt-in, disposable three-namespace lab. Never executes nft in the host namespace."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import pytest
from eye_for_an_eye.config import Config
from eye_for_an_eye.security.firewall import FirewallManager

pytestmark = pytest.mark.linux_lab
ENABLED = sys.platform.startswith('linux') and os.environ.get('E4E_RUN_NAMESPACE_LAB') == '1'


def command(args, *, data=None, check=True):
    result = subprocess.run(args, input=data, capture_output=True, text=True, check=False, timeout=5)
    if check and result.returncode:
        raise RuntimeError(f'isolated lab command failed: {result.stderr[:2048]}')
    return result


def in_namespace(namespace, args, **kwargs):
    assert namespace.startswith('e4e-lab-')
    return command(['ip', 'netns', 'exec', namespace, *args], **kwargs)


@contextmanager
def isolated_lab():
    if not ENABLED:
        pytest.skip('NOT VERIFIED IN CURRENT ENVIRONMENT: requires explicit E4E_RUN_NAMESPACE_LAB=1 on isolated Linux')
    if os.geteuid() != 0 or any(shutil.which(name) is None for name in ('ip', 'nft', 'setpriv', 'sysctl')):
        pytest.skip('Linux lab requires namespace setup privileges, iproute2, nft and setpriv')
    suffix = uuid.uuid4().hex[:8]
    names = {role: f'e4e-lab-{role}-{suffix}' for role in ('client', 'sensor', 'service')}
    created, processes = [], []
    try:
        for name in names.values():
            command(['ip', 'netns', 'add', name])
            created.append(name)
            command(['ip', '-n', name, 'link', 'set', 'lo', 'up'])
        command(['ip', '-n', names['client'], 'link', 'add', 'cli0', 'type', 'veth', 'peer', 'name', 'sns0', 'netns', names['sensor']])
        command(['ip', '-n', names['sensor'], 'link', 'add', 'sns1', 'type', 'veth', 'peer', 'name', 'svc0', 'netns', names['service']])
        for role, interface, address in [('client', 'cli0', '10.203.0.2/24'), ('sensor', 'sns0', '10.203.0.1/24'),
                                         ('sensor', 'sns1', '10.203.1.1/24'), ('service', 'svc0', '10.203.1.2/24')]:
            command(['ip', '-n', names[role], 'address', 'add', address, 'dev', interface])
            command(['ip', '-n', names[role], 'link', 'set', interface, 'up'])
        command(['ip', '-n', names['client'], 'route', 'add', '10.203.1.0/24', 'via', '10.203.0.1'])
        command(['ip', '-n', names['service'], 'route', 'add', '10.203.0.0/24', 'via', '10.203.1.1'])
        in_namespace(names['sensor'], ['sysctl', '-q', '-w', 'net.ipv4.ip_forward=1'])
        # These namespaces have no default route or connection to a host interface.
        yield names, processes
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(2)
        for name in reversed(created):
            command(['ip', 'netns', 'delete', name], check=False)


def request(namespace, port):
    code = "import socket,sys; s=socket.create_connection(('10.203.1.2',int(sys.argv[1])),1); s.settimeout(.1)\ntry:\n data=s.recv(1024)\nexcept TimeoutError:\n s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); s.settimeout(1); data=s.recv(1024)\nprint(data.hex()); s.close(); sys.exit(0 if data else 1)"
    return in_namespace(namespace, [sys.executable, '-B', '-c', code, str(port)], check=False)


def test_three_namespace_redirect_lease_and_rollback(monkeypatch):
    with isolated_lab() as (names, processes), tempfile.TemporaryDirectory(prefix='e4e-lab-') as directory:
        path = Path(directory)
        path.chmod(0o755)
        secret = path / 'fixture.secret'
        secret.write_bytes(bytes(range(32)))  # Public lab fixture; never production.
        os.chown(secret, 65534, 65534)
        secret.chmod(0o600)
        drop = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--bounding-set=-all']
        listener = subprocess.Popen(['ip', 'netns', 'exec', names['sensor'], *drop, sys.executable,
            '-B', '-m', 'eye_for_an_eye', 'services', '1234', 'tcp', '--bind', '0.0.0.0', '--secret-file', str(secret)],
            env={**os.environ, 'E4E__DECEPTION__SOURCE_ALLOWLIST': '["10.203.0.0/24"]'},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(listener)
        service_code = "import socket,time; s=socket.socket(); s.bind(('10.203.1.2',2220)); s.listen(8); s.settimeout(.5); end=time.monotonic()+30\nwhile time.monotonic()<end:\n try: c,a=s.accept()\n except TimeoutError: continue\n with c:\n  c.settimeout(1); c.recv(1024); c.sendall(b'SSH-2.0-LabService\\r\\n')\ns.close()"
        service = subprocess.Popen(['ip', 'netns', 'exec', names['service'], *drop, sys.executable, '-B', '-c', service_code],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(service)
        config = Config()
        config.firewall.enabled = True
        config.firewall.lab_namespace = names['sensor']
        config.firewall.destination_addresses = ['10.203.1.2']
        config.firewall.decoy_ports = [8080]
        config.firewall.real_service_ports = [2220]
        config.firewall.listener_address = '10.203.0.1'
        config.firewall.lease_seconds = 5
        manager = FirewallManager(config)
        original_verify = manager.verify
        def diagnostic_verify():
            result = original_verify()
            if result['status'] != 'healthy':
                print('Owned lab table diagnostic:', json.dumps(manager.backend.read()))
            return result
        monkeypatch.setattr(manager, 'verify', diagnostic_verify)
        deadline = time.monotonic() + 5
        while not manager.backend.ready() and time.monotonic() < deadline:
            time.sleep(.1)
        assert listener.poll() is None
        assert bytes.fromhex(request(names['client'], 2220).stdout.strip()).startswith(b'SSH-2.0-LabService')
        in_namespace(names['sensor'], ['nft', '-f', '-'], data='table ip foreign_fixture {\n chain untouched { type filter hook forward priority 0; policy accept; }\n}\n')
        before = json.loads(in_namespace(names['sensor'], ['nft', '-j', 'list', 'table', 'ip', 'foreign_fixture']).stdout)
        manager.apply()
        manager.apply()
        assert manager.verify()['status'] == 'healthy'
        assert request(names['client'], 8080).returncode == 0
        assert bytes.fromhex(request(names['client'], 2220).stdout.strip()).startswith(b'SSH-2.0-LabService')
        listener.terminate()
        listener.wait(2)
        assert manager.verify()['status'] == 'degraded'
        time.sleep(5.2)
        assert manager.verify()['status'] == 'degraded'  # kernel lease expired
        assert request(names['client'], 8080).returncode != 0
        manager.rollback()
        manager.rollback()
        after = json.loads(in_namespace(names['sensor'], ['nft', '-j', 'list', 'table', 'ip', 'foreign_fixture']).stdout)
        assert before == after
        assert request(names['client'], 2220).returncode == 0


def test_minimal_capture_capability_in_isolated_namespace():
    with isolated_lab() as (names, _):
        base = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups']
        code = 'from eye_for_an_eye.security.privileges import ensure_capture_user; import socket; ensure_capture_user(); s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.close()'
        denied = in_namespace(names['sensor'], [*base, '--bounding-set=-all', sys.executable, '-c', code], check=False)
        assert denied.returncode != 0
        allowed = in_namespace(names['sensor'], [*base, '--bounding-set=-all,+net_raw', '--inh-caps=+net_raw', '--ambient-caps=+net_raw', sys.executable, '-c', code], check=False)
        assert allowed.returncode == 0, allowed.stderr
