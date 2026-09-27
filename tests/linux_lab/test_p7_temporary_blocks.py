"""Only disposable namespace enforcement. No unscoped nft command exists here."""
import json
import time
import pytest
from eye_for_an_eye.analysis import EventAnalysis
from eye_for_an_eye.config import Config
from eye_for_an_eye.decision.features import FeatureVector, NAMES
from eye_for_an_eye.decision.onnx_model import MLResult
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.security.temporary_blocks import TemporaryBlocks
from .test_namespace_firewall import isolated_lab, in_namespace

pytestmark = pytest.mark.linux_lab


def test_shadow_owned_expiry_protection_and_foreign_preservation():
    with isolated_lab() as (names, _):
        ns = names['sensor']
        in_namespace(ns, ['nft', '-f', '-'], data='table inet p7_foreign {\n chain keep {\n }\n}\n')
        before = json.loads(in_namespace(ns, ['nft', '-j', 'list', 'ruleset']).stdout)
        cfg = Config()
        cfg.deployment.profile = 'lab'
        cfg.firewall.lab_namespace = ns
        cfg.enforcement.management_networks = ['10.204.0.0/24']
        values = dict.fromkeys(NAMES, 0.0)
        values.update(ports_60s=64, ports_900s=128, credentials_60s=20, anomaly_60s=1, continuation_60s=1, persistence_900s=300)
        vector = FeatureVector(tuple(values.values()), 300, 100, loss_fraction=0.0)
        engine = EventAnalysis(cfg).decisions
        record = engine._record(NetworkEvent('10.203.0.2'), vector, MLResult())
        assert record.observations['would_enforce'] and not record.observations['enforced']
        assert json.loads(in_namespace(ns, ['nft', '-j', 'list', 'ruleset']).stdout) == before
        cfg.enforcement.enabled, cfg.decision.mode = True, 'enforce'
        cfg.enforcement.block_seconds = [2, 4]
        manager = TemporaryBlocks(cfg)
        try:
            assert not manager.block('127.0.0.1', 2)
            assert not manager.block('10.203.0.1', 2)  # actual namespace interface address
            assert not manager.block('10.204.0.1', 2)
            engine.enforcer = manager
            record = engine._record(NetworkEvent('10.203.0.2'), vector, MLResult())
            assert record.observations['enforced']
            assert manager.block('2001:db8::123', 2)
            state = manager._verify()
            assert any(v.get('set', {}).get('elem') for v in state['nftables'])
            time.sleep(2.2)
            state = manager._verify()
            assert all(not v.get('set', {}).get('elem') for v in state['nftables'])
        finally:
            manager.close()
        assert json.loads(in_namespace(ns, ['nft', '-j', 'list', 'ruleset']).stdout) == before
