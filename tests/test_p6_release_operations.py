"""Operator contracts: no implicit runtime, explicit migrations, bounded local demo."""
from contextlib import closing, redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import time
from unittest.mock import patch
import pytest
from eye_for_an_eye.cli import main
from eye_for_an_eye.config import Config, load_config
from eye_for_an_eye.configuration import initialize, migrate
from eye_for_an_eye.demo import run as demo
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.operator_cli import failure, startup_plan
from eye_for_an_eye.security.secrets import load_secret
from eye_for_an_eye.storage.lifecycle import migration_plan, migrate_database, restore_new, prune
from eye_for_an_eye.storage.locking import WriterLease
from eye_for_an_eye.storage.operations import backup, storage_info
from eye_for_an_eye.storage.reader import Reader
from eye_for_an_eye.storage.sqlite import APPLICATION_ID, SQLiteStore


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for key in list(os.environ):
        if key.startswith('E4E__') or key == 'EYE_FOR_AN_EYE_SECRET':
            monkeypatch.delenv(key)


def invoke(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize('profile', ['sensor', 'honeypot', 'lab'])
def test_starter_safe_and_never_overwrites(tmp_path, profile):
    target = tmp_path/'settings.toml'
    result = initialize(target, profile)
    before = target.read_bytes()
    config = load_config(target, require_version=True)
    assert config.deployment.egress == 'disabled'
    assert config.deployment.profile == profile
    assert not config.active_probes.enabled and not config.enrichment.rdap_enabled
    assert not config.network.udp_responses and not config.firewall.enabled
    assert config.api.bind_address == config.metrics.bind_address == '127.0.0.1'
    if profile != 'sensor':
        secret = load_secret(config)
        assert len(secret) == 32 and secret.hex() not in json.dumps(result)
        if os.name == 'posix':
            assert Path(config.deception.secret_file).stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        initialize(target, profile)
    assert before == target.read_bytes()


def test_repository_starter_and_reference_configs_are_valid():
    root = Path(__file__).resolve().parents[1]
    for path in root.glob('config.*.toml'):
        config = load_config(path, require_version=True)
        assert config.config_version == 1
        assert not config.active_probes.enabled and not config.network.udp_responses


def test_missing_config_and_help_never_open_runtime(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch('socket.socket', side_effect=AssertionError('network')), \
         patch('sqlite3.connect', side_effect=AssertionError('storage')), \
         patch('threading.Thread.start', side_effect=AssertionError('thread')):
        assert invoke([])[0] == 0
        from eye_for_an_eye import __version__
        assert invoke(['--version'])[1].strip() == __version__
        code, out, err = invoke(['run'])
        assert code == 2 and 'config init' in err and not out
        assert 'Traceback' not in err
        assert invoke(['config', 'validate', '--json'])[0] == 0


def test_effective_provenance_and_redaction(tmp_path, monkeypatch):
    target = tmp_path/'settings.toml'
    initialize(target, 'sensor')
    monkeypatch.setenv('E4E__NETWORK__PORT', '4321')
    monkeypatch.setenv('EYE_FOR_AN_EYE_SECRET', 'ab'*32)
    code, out, err = invoke(['config', 'show', '--config', str(target), '4322', '--source', '--effective', '--json'])
    record = json.loads(out)
    assert code == 0 and not err
    assert record['configuration']['network']['port'] == 4322
    assert record['sources']['network.port'] == 'cli'
    assert record['sources']['network.bind_address'] == 'config'
    assert record['sources']['capture.interface'] == 'default'
    assert 'ab'*32 not in out
    record = json.loads(invoke(['config', 'show', '--config', str(target), '--source', '--json'])[1])
    assert record['sources']['network.port'] == 'env'


def test_legacy_migration_requires_explicit_new_file(tmp_path):
    source, dest = tmp_path/'legacy.toml', tmp_path/'new.toml'
    source.write_text('[network]\nport=4321\n', encoding='utf-8')
    original = source.read_bytes()
    assert invoke(['config', 'validate', '--config', str(source), '--json'])[0] == 2
    migrate(source, dest, 'sensor')
    assert load_config(dest, require_version=True).network.port == 4321
    assert source.read_bytes() == original
    with pytest.raises(FileExistsError):
        migrate(source, dest, 'sensor')
    code, out, _ = invoke(['upgrade', 'check', '--config', str(source), '--json'])
    assert code == 0 and json.loads(out)['config_migration_required']


@pytest.mark.parametrize('change', [
    lambda c: setattr(c, 'config_version', 99),
    lambda c: setattr(c.limits, 'max_connections', 0),
    lambda c: setattr(c.enrichment, 'rdap_enabled', True),
    lambda c: setattr(c.deployment, 'egress', 'unbounded'),
])
def test_invalid_settings_rejected(change):
    config = Config()
    change(config)
    with pytest.raises(ValueError):
        config.validate()


def test_future_schema_cannot_be_hidden_by_environment(tmp_path, monkeypatch):
    path = tmp_path/'future.toml'
    path.write_text('config_version=99\n', encoding='utf-8')
    monkeypatch.setenv('E4E__CONFIG_VERSION', '1')
    assert invoke(['config', 'validate', '--config', str(path)])[0] == 2
    with pytest.raises(ValueError):
        migrate(path, tmp_path/'new.toml', 'sensor')


def test_malformed_environment_table_has_actionable_error(monkeypatch):
    monkeypatch.setenv('E4E__DEPLOYMENT', '{}')
    code, _, err = invoke(['config', 'validate', '--json'])
    assert code == 2 and 'E4E__SECTION__FIELD' in json.loads(err)['message']
    assert 'Traceback' not in err


@pytest.mark.parametrize('exc,expected', [(ValueError('constraint'), 2), (ImportError('capture extra required'), 3),
    (PermissionError('service directory'), 4), (sqlite3.DatabaseError('schema'), 5)])
def test_stable_machine_errors_and_debug(exc, expected):
    out = io.StringIO()
    with redirect_stderr(out):
        assert failure(exc, machine=True) == expected
    record = json.loads(out.getvalue())
    assert record['schema_version'] == 1 and record['exit_code'] == expected
    assert 'Traceback' not in out.getvalue()
    with redirect_stderr(io.StringIO()) as err:
        try:
            raise exc
        except Exception as raised:
            failure(raised, debug=True)
    assert 'Traceback' in err.getvalue()


def legacy_database(path):
    event = json.loads(NetworkEvent('192.0.2.1').to_json())
    event['schema_version'] = 2
    for key in ('classification', 'confidence', 'deception'):
        event.pop(key)
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(f'''CREATE TABLE events(seq INTEGER PRIMARY KEY,event_id TEXT UNIQUE,ingested_at REAL,
            sensor_id TEXT,event_type TEXT,event_json TEXT);
            CREATE INDEX event_age ON events(ingested_at);
            CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at REAL);
            INSERT INTO schema_migrations VALUES(1,0);
            PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=1;''')
        connection.execute('INSERT INTO events VALUES(1,?,?,?,?,?)',
            (event['event_id'], time.time(), 'local', event['event_type'], json.dumps(event)))
        connection.commit()
    return event['event_id']


def storage_config(path):
    config = Config()
    config.storage.enabled = True
    config.storage.path = str(path)
    return config


def test_migration_backup_checksum_and_writer_lease(tmp_path):
    config = storage_config(tmp_path/'old.db')
    event_id = legacy_database(config.storage.path)
    with closing(sqlite3.connect(config.storage.path)) as old:
        # Migration must preserve even expired rows; retention is a separate operation.
        old.execute('UPDATE events SET ingested_at=0')
        old.commit()
    original = Path(config.storage.path).read_bytes()
    assert migration_plan(config)['current_version'] == 1
    assert original == Path(config.storage.path).read_bytes()
    with pytest.raises(ValueError):
        migrate_database(config, None)
    lease = WriterLease(config.storage.path+'.lock')
    lease.acquire()
    try:
        with pytest.raises((RuntimeError, OSError)):
            migrate_database(config, tmp_path/'blocked.db')
        assert not (tmp_path/'blocked.db').exists()
    finally:
        lease.close()
    result = migrate_database(config, tmp_path/'before.db')
    assert result['backup']['sha256'] == hashlib.sha256((tmp_path/'before.db').read_bytes()).hexdigest()
    with closing(sqlite3.connect(tmp_path/'before.db')) as old:
        assert old.execute('PRAGMA user_version').fetchone()[0] == 1
        assert old.execute('SELECT event_id FROM events').fetchone()[0] == event_id
    assert migration_plan(config)['current_version'] == 2
    assert Reader(config.storage.path, config.api).event(event_id).event_id == event_id
    assert migrate_database(config, None)['status'] == 'no_migration_required'
    restored = storage_config(tmp_path/'restored-v1.db')
    assert restore_new(restored, tmp_path/'before.db', confirmed=True)['backup']['database_schema_version'] == 1
    assert migration_plan(restored)['current_version'] == 1


def test_restore_new_only_and_prune_default_dry_run(tmp_path):
    config = storage_config(tmp_path/'live.db')
    store = SQLiteStore(config.storage)
    store.open()
    try:
        store.write(NetworkEvent('192.0.2.1'))
        copy = tmp_path/'copy.db'
        backup(Reader(config.storage.path, config.api), copy, max_bytes=config.storage.max_bytes)
        before = copy.read_bytes()
        assert prune(config)['status'] == 'dry_run'
        with pytest.raises((RuntimeError, OSError)):
            prune(config, confirmed=True)
    finally:
        store.close()
    with pytest.raises(ValueError):
        restore_new(config, copy)
    with pytest.raises(FileExistsError):
        restore_new(config, copy, confirmed=True)
    config.storage.path = str(tmp_path/'restored.db')
    assert restore_new(config, copy, confirmed=True)['status'] == 'restored_to_new_database'
    assert storage_info(Reader(config.storage.path, config.api))['events'] == 1
    assert copy.read_bytes() == before


def test_run_bind_error_rolls_back_and_identifies_port(tmp_path):
    target = tmp_path/'settings.toml'
    initialize(target, 'honeypot')
    config = load_config(target)
    config.api.enabled = config.metrics.enabled = False
    config.correlation.enabled = False
    config.decision.enabled = False
    with socket.socket() as occupied:
        occupied.bind(('127.0.0.1', 0))
        occupied.listen(1)
        config.network.port = occupied.getsockname()[1]
        config.deception.decoy_ports = [config.network.port]
        from eye_for_an_eye.cli import main as runtime_main
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = runtime_main([], command='services', config_override=config)
        assert code == 6 and str(config.network.port) in err.getvalue()
        assert 'Traceback' not in err.getvalue()
    state = json.loads(Path(config.runtime.status_file).read_text())
    assert not state['running']
    reopened = SQLiteStore(config.storage)
    reopened.open()
    reopened.close()


def test_sensor_startup_requires_capture_extra(tmp_path):
    config = Config()
    config.capture.pcap_path = str(tmp_path/'fixture.pcap')
    with patch('importlib.util.find_spec', return_value=None), pytest.raises(ImportError):
        startup_plan(config)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX permission semantics; Windows uses ACLs')
def test_world_readable_secret_rejected(tmp_path):
    config = Config()
    secret = tmp_path/'fixture.secret'
    secret.write_bytes(bytes(range(32)))
    secret.chmod(0o644)
    config.deception.secret_file = str(secret)
    with pytest.raises(PermissionError):
        load_secret(config)
    secret.chmod(0o600)
    assert len(load_secret(config)) == 32
    config = storage_config(tmp_path/'private.db')
    store = SQLiteStore(config.storage)
    store.open()
    store.close()
    assert Path(config.storage.path).stat().st_mode & 0o077 == 0


def test_optional_missing_database_is_diagnosed_without_repairs(tmp_path):
    config = Config()
    config.capture.p0f_db = str(tmp_path/'absent.p0f')
    config.enrichment.mmdb_path = str(tmp_path/'absent.mmdb')
    config.validate()
    from eye_for_an_eye.operations import doctor
    from eye_for_an_eye.fingerprint.p0f_adapter import P0fAdapter
    with patch('socket.create_connection', side_effect=AssertionError('egress')):
        result = doctor(config)
        assert result['p0f']['status'] == result['geoip']['status'] == 'DEGRADED'
        assert P0fAdapter(config.capture.p0f_db).reason == 'database_missing'
    assert not list(tmp_path.iterdir())


def test_finite_demo_event_api_storage_and_shutdown():
    result = demo()
    assert result['stored_events'] >= 1 and result['api_status'] == 200
    assert result['response_bytes'] <= Config().limits.max_response_bytes
    assert result['external_requests'] == 0 and result['temporary_state_removed']
    assert result['shutdown_seconds'] < 5


@pytest.mark.parametrize('state', [[], {'schema_version': 99}, {'operational': []}])
def test_corrupt_status_has_machine_error_without_traceback(tmp_path, state):
    path = tmp_path/'settings.toml'
    initialize(path, 'sensor')
    (tmp_path/'status.json').write_text(json.dumps(state), encoding='utf-8')
    code, out, err = invoke(['status', '--config', str(path), '--json'])
    assert code == 1 and not out
    assert json.loads(err)['schema_version'] == 1
    assert 'Traceback' not in err
