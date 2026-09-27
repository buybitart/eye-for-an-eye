"""First-run UX: setup and model status stay safe, honest and repeatable."""
import json
from pathlib import Path
import pytest
from eye_for_an_eye import setup_cli
from eye_for_an_eye.cli import COMMANDS, main
from eye_for_an_eye.config import load_config
from eye_for_an_eye.configuration import PROFILE_TEMPLATES, initialize

MODELS = Path(__file__).resolve().parents[1] / 'models'


def run(argv, workdir, monkeypatch):
    """Run a command in `workdir`, with this machine's own layout out of the way.

    P18 changed where `setup` writes when nothing names a file: the current
    directory put it somewhere `status`, `check-install` and `doctor` never look,
    which was the defect that phase existed to fix. Pointing XDG_DATA_HOME at the
    temporary directory keeps these tests hermetic either way — they neither read
    nor write the developer's real configuration — and `--config` below says
    explicitly which file each one means.
    """
    monkeypatch.chdir(workdir)
    monkeypatch.setenv('XDG_DATA_HOME', str(workdir))
    monkeypatch.delenv('EYE_FOR_AN_EYE_RECEIPT', raising=False)
    return main(list(argv))


def test_setup_and_model_are_routed_commands():
    assert 'setup' in COMMANDS and 'model' in COMMANDS


#: `production-autonomous` is shipped deliberately unvalidatable: it turns host
#: blocking on and leaves `management_networks` empty, so it cannot start until
#: an operator names the addresses that must never be blocked. That refusal is
#: the profile's whole safety property, and it is asserted in
#: `tests/test_p15_invariants.py` and `tests/test_p16_production_profiles.py`.
#: Here it means only that the template is parsed rather than validated.
REFUSES_UNTIL_CONFIGURED = ('production-autonomous',)


@pytest.mark.parametrize('profile', sorted(PROFILE_TEMPLATES))
def test_every_profile_template_is_packaged_and_valid(profile, tmp_path):
    target = tmp_path / (profile + '.toml')
    record = initialize(str(target), profile)
    assert record['profile'] == profile and target.is_file()
    config = load_config(str(target), require_version=True,
                         validate=profile not in REFUSES_UNTIL_CONFIGURED)
    assert config.deployment.profile == record['deployment_profile']


def test_website_profile_is_shadow_only_and_never_enables_enforcement(tmp_path):
    initialize(str(tmp_path / 'e.toml'), 'website')
    config = load_config(str(tmp_path / 'e.toml'), require_version=True)
    assert config.decision.mode == 'shadow'
    assert not config.enforcement.enabled
    assert not config.active_probes.enabled
    assert not config.firewall.enabled
    assert not config.enrichment.enabled and not config.enrichment.rdap_enabled
    assert config.api.bind_address == '127.0.0.1' and config.metrics.bind_address == '127.0.0.1'
    assert config.deployment.egress == 'disabled'


def test_passive_profiles_do_not_create_a_deception_secret(tmp_path):
    for profile, expected in (('website', False), ('sensor', False), ('honeypot', True), ('lab', True)):
        record = initialize(str(tmp_path / (profile + '.toml')), profile)
        assert record['persistent_secret_created'] is expected
        assert (tmp_path / (profile + '.secret')).exists() is expected


def test_setup_creates_a_safe_configuration_and_reports_it(tmp_path, monkeypatch, capsys):
    assert run(['setup', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 0
    printed = capsys.readouterr().out
    assert 'Eye for an Eye is installed.' in printed
    assert 'Mode: SHADOW' in printed
    assert 'Automatic block: OFF' in printed
    assert 'API: Local only' in printed
    assert 'eye-for-an-eye status' in printed
    assert (tmp_path / 'eye-for-an-eye.toml').is_file()
    # And the file it reports is the file it made.
    reported = [line.split(': ', 1)[1] for line in printed.splitlines()
                if line.startswith('Config file: ')]
    assert reported and Path(reported[0]) == tmp_path / 'eye-for-an-eye.toml'


def test_setup_without_a_named_file_writes_where_the_other_commands_look(tmp_path,
                                                                        monkeypatch,
                                                                        capsys):
    """P18. The Debian package writes no receipt, so `eye-for-an-eye setup` typed
    in a home directory used to leave `./eye-for-an-eye.toml` — a configuration
    the next command could not find."""
    from eye_for_an_eye import beginner
    assert run(['setup'], tmp_path, monkeypatch) == 0
    printed = capsys.readouterr().out
    written = [line.split(': ', 1)[1] for line in printed.splitlines()
               if line.startswith('Config file: ')]
    assert written, printed
    assert Path(written[0]).is_file()
    assert Path(written[0]) in beginner.config_candidates(), (
        'setup wrote a configuration the beginner commands do not look for')


def test_setup_is_idempotent_and_never_overwrites_an_existing_file(tmp_path, monkeypatch, capsys):
    assert run(['setup', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 0
    capsys.readouterr()
    written = (tmp_path / 'eye-for-an-eye.toml').read_bytes()
    assert run(['setup', '--json', '--config', 'eye-for-an-eye.toml'],
               tmp_path, monkeypatch) == 0
    record = json.loads(capsys.readouterr().out)
    assert record['status'] == 'existing'
    assert record['firewall_changed'] is False
    assert (tmp_path / 'eye-for-an-eye.toml').read_bytes() == written


def test_setup_reports_only_what_the_written_file_says(tmp_path, monkeypatch, capsys):
    assert run(['setup', '--json', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 0
    record = json.loads(capsys.readouterr().out)
    config = load_config(str(tmp_path / 'eye-for-an-eye.toml'), require_version=True)
    assert record['mode'] == config.decision.mode.upper()
    assert record['automatic_block'] == ('ON' if config.enforcement.enabled else 'OFF')
    assert record['active_probes'] == 'OFF'
    assert record['ai'] == 'Maths only (no model file yet)'
    assert record['privileges'] and all(isinstance(line, str) for line in record['privileges'])


def test_setup_refuses_an_unknown_profile(tmp_path, monkeypatch):
    with pytest.raises(SystemExit):
        run(['setup', '--profile', 'firewall'], tmp_path, monkeypatch)


def test_model_status_without_a_model_is_honest(tmp_path, monkeypatch, capsys):
    assert run(['setup'], tmp_path, monkeypatch) == 0
    capsys.readouterr()
    assert run(['model', 'status'], tmp_path, monkeypatch) == 0
    printed = capsys.readouterr().out
    assert 'Model: none' in printed and 'Status: Not configured' in printed
    # No model is configured, so there is no artifact to describe and the
    # build's own schema is the honest thing to print.
    from eye_for_an_eye.decision.features import SCHEMA_VERSION
    assert f'Feature schema: {SCHEMA_VERSION}' in printed and 'Mode: Shadow' in printed


@pytest.mark.skipif(not (MODELS / 'risk-logreg-v1.onnx').is_file(), reason='model artifact not distributed')
def test_model_status_reports_a_healthy_local_artifact(tmp_path, monkeypatch, capsys):
    assert run(['setup', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 0
    capsys.readouterr()
    local = tmp_path / 'models'
    local.mkdir()
    for name in ('risk-logreg-v1.onnx', 'risk-logreg-v1.json'):
        local.joinpath(name).write_bytes((MODELS / name).read_bytes())
        local.joinpath(name).chmod(0o644)
    path = tmp_path / 'eye-for-an-eye.toml'
    path.write_text(path.read_text(encoding='utf-8')
                    .replace('model_path = ""', 'model_path = "models/risk-logreg-v1.onnx"')
                    .replace('manifest_path = ""', 'manifest_path = "models/risk-logreg-v1.json"'), encoding='utf-8')
    assert run(['model', 'status', '--json'], tmp_path, monkeypatch) == 0
    state = json.loads(capsys.readouterr().out)
    # `feature_schema` is the artifact's, not the build's: an operator reading
    # this needs to know which columns the shipped model actually sees.
    assert state == {'schema_version': 1, 'model': 'risk-logreg-v1', 'format': 'ONNX',
                     'feature_schema': 1, 'status': 'Healthy', 'mode': 'Shadow', 'required': False,
                     'dataset_version': state['dataset_version'], 'reason': state['reason']}
    from eye_for_an_eye.decision.features import CLASSIFIER_SCHEMA_VERSION
    assert state['feature_schema'] == CLASSIFIER_SCHEMA_VERSION


def test_model_status_reports_a_broken_artifact_without_crashing(tmp_path, monkeypatch, capsys):
    assert run(['setup', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 0
    capsys.readouterr()
    (tmp_path / 'broken.onnx').write_bytes(b'not-a-model')
    (tmp_path / 'broken.json').write_text('{"manifest_version": 1}', encoding='utf-8')
    path = tmp_path / 'eye-for-an-eye.toml'
    path.write_text(path.read_text(encoding='utf-8')
                    .replace('model_path = ""', 'model_path = "broken.onnx"')
                    .replace('manifest_path = ""', 'manifest_path = "broken.json"'), encoding='utf-8')
    assert run(['model', 'status'], tmp_path, monkeypatch) == 0
    assert 'Status: Unavailable' in capsys.readouterr().out


def test_setup_never_touches_the_firewall(tmp_path, monkeypatch):
    import eye_for_an_eye.security.firewall as firewall

    def fail(*args, **kwargs):
        raise AssertionError('setup must never change firewall rules')

    for name in ('dry_run', 'apply', 'verify', 'rollback'):
        monkeypatch.setattr(firewall.FirewallManager, name, fail, raising=False)
    assert run(['setup'], tmp_path, monkeypatch) == 0


def test_interface_detection_only_reads_names(monkeypatch):
    monkeypatch.setattr(setup_cli.socket, 'if_nameindex', lambda: [(1, 'lo'), (2, 'eth0')])
    assert setup_cli.interfaces() == ['eth0', 'lo']
    monkeypatch.setattr(setup_cli.socket, 'if_nameindex', lambda: (_ for _ in ()).throw(OSError()))
    assert setup_cli.interfaces() == []


def test_setup_creates_the_empty_database_so_the_first_doctor_run_is_clean(tmp_path, monkeypatch, capsys):
    assert run(['setup', '--json', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 0
    record = json.loads(capsys.readouterr().out)
    assert record['database'] == {'created': True, 'reason': 'empty local database created'}
    assert (tmp_path / 'events.sqlite3').is_file()
    # P18: 7 is "doctor found something degraded", and on a fresh install of the
    # safe profile that is the required answer, not a fault. §35 — where a
    # deployment-specific artifact is missing, say so rather than pretending
    # HEALTHY — and on a fresh install the calibrator and the access log are both
    # missing. This exited 0 while the default profile was `website`, which has no
    # [autonomy] section and therefore nothing to be degraded about.
    assert run(['doctor', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 7
    printed = capsys.readouterr().out
    assert 'NOT_CONFIGURED' in printed
    assert 'calibrator' in printed.lower(), 'doctor did not name what is missing'
    assert run(['setup', '--json', '--config', 'eye-for-an-eye.toml'], tmp_path, monkeypatch) == 0
    assert json.loads(capsys.readouterr().out)['database']['created'] is False
