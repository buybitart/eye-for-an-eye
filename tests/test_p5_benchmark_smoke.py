"""CI smoke checks envelopes and fixtures, never host-speed thresholds."""
from benchmarks.common import config, percentiles, source_hash
from benchmarks.workloads import event, payloads, PROFILES
from eye_for_an_eye.events import NetworkEvent


def test_reproducible_bounded_workload_and_percentiles():
    assert event(42).to_json() == event(42).to_json()
    assert payloads() == payloads()
    assert max(map(len, payloads())) == 256
    assert len(PROFILES) == 7
    assert PROFILES['idle']['connections_limit'] == 128
    assert NetworkEvent.from_json(event(99999, 50000).to_json()).src_ip == '10.0.195.79'
    assert percentiles([1, 2, 3, 4])['p50_ms'] == 2
    assert len(source_hash()) == 64
    config().validate()
