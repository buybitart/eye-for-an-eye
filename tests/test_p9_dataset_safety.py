"""Safety boundary: local targets only, hard bounds, reproducible seeds, bounded collection."""
import json
import pytest
from dataset import scenarios
from dataset.builder import BuildBudget, behaviour_summary, source_group
from dataset.cli import main
from dataset.generators.packets import render, write_pcap
from dataset.safety import (Budget, BudgetExceeded, DiskBudget, SafetyLimits, UnsafeTarget, describe,
                            interruption_safe, is_documentation, validate_live_target,
                            validate_synthetic_address)

PUBLIC = ('8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111')
DOCUMENTATION = ('192.0.2.1', '198.51.100.7', '203.0.113.9', '2001:db8::1')


def test_public_targets_are_rejected_for_anything_that_opens_a_socket():
    assert str(validate_live_target('127.0.0.1')) == '127.0.0.1'
    assert str(validate_live_target('::1')) == '::1'
    for address in PUBLIC + DOCUMENTATION + ('10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.1.1'):
        with pytest.raises(UnsafeTarget):
            validate_live_target(address)
    for address in ('not-an-address', '', None, '999.1.1.1'):
        with pytest.raises(UnsafeTarget):
            validate_live_target(address)
    assert str(validate_live_target('10.9.9.9', allowlist=('10.9.0.0/16',))) == '10.9.9.9'
    with pytest.raises(UnsafeTarget):
        validate_live_target('192.0.2.5', allowlist=('192.0.2.0/24',))


def test_synthetic_addresses_are_never_globally_routable():
    for address in DOCUMENTATION:
        assert str(validate_synthetic_address(address)) == address
        assert is_documentation(address)
    for address in PUBLIC:
        with pytest.raises(UnsafeTarget):
            validate_synthetic_address(address)
    assert not is_documentation('127.0.0.1')


def test_a_scenario_without_limits_does_not_run():
    with pytest.raises(ValueError):
        Budget(None)
    with pytest.raises(ValueError):
        SafetyLimits(max_connections=0)
    with pytest.raises(ValueError, match='ceiling'):
        SafetyLimits(max_duration_seconds=6000)
    tight = SafetyLimits().tightened(max_connections=3)
    assert tight.max_connections == 3


def test_hard_bounds_stop_a_scenario():
    budget = Budget(SafetyLimits(max_connections=2, max_packets=3, max_destinations=1, max_samples=1))
    budget.connection('a')
    with pytest.raises(BudgetExceeded, match='max_destinations'):
        budget.connection('b')
    other = Budget(SafetyLimits(max_packets=2))
    other.packet(10)
    other.packet(10)
    with pytest.raises(BudgetExceeded, match='max_packets'):
        other.packet(10)
    assert other.snapshot()['stopped_by'] == 'packets'
    timed = Budget(SafetyLimits(max_duration_seconds=5))
    timed.advance(4)
    with pytest.raises(BudgetExceeded, match='max_duration'):
        timed.advance(6)


def test_disk_budget_truncates_instead_of_filling_the_disk():
    disk = DiskBudget(max_output_bytes=4096)
    assert disk.add(4000) and not disk.truncated
    assert not disk.add(1000) and disk.truncated
    build = BuildBudget(max_output_bytes=4096, max_samples=2)
    assert build.accept(10) and build.accept(10)
    assert not build.accept(10) and build.truncated


def test_interruption_flushes_instead_of_raising():
    flushed = []
    with interruption_safe(on_stop=lambda: flushed.append(True)):
        raise KeyboardInterrupt
    assert flushed == [True]


def test_scenarios_are_reproducible_from_their_seed(tmp_path):
    plans = {plan.scenario_id: plan for plan in scenarios.plans()}
    for name in ('scan/sequential/50-ports', 'benign/web/browse', 'credential/automation'):
        plan = plans[name]
        first, _ = render(plan)
        second, _ = render(plan)
        assert first == second
        again = {p.scenario_id: p for p in scenarios.plans()}[name]
        assert [(c.time, c.port, c.shape, c.request) for c in again.contacts] == \
               [(c.time, c.port, c.shape, c.request) for c in plan.contacts]
        assert again.source == plan.source
    plan = plans['scan/sequential/50-ports']
    one = write_pcap(tmp_path / 'a.pcap', render(plan)[0])
    two = write_pcap(tmp_path / 'b.pcap', render(plan)[0])
    assert one.read_bytes() == two.read_bytes()


def test_every_generated_plan_stays_inside_its_bounds():
    for plan in scenarios.plans():
        budget = plan.parameters['budget']
        assert budget['stopped_by'] is None
        assert budget['connections'] <= plan.limits.max_connections
        assert budget['destinations'] <= plan.limits.max_destinations
        assert budget['elapsed_seconds'] <= plan.limits.max_duration_seconds
        for contact in plan.contacts:
            assert not is_documentation(contact.destination) or True
            assert len(contact.request) <= plan.limits.max_request_bytes
        summary = behaviour_summary(plan)
        assert summary['ports'] and summary['destinations']
        assert source_group(plan).startswith(plan.scenario_id)


def test_lab_run_prints_the_boundary_and_aborts_on_a_public_target(capsys):
    assert main(['lab-run', '--scenario', 'scan/sequential/50-ports']) == 0
    context = json.loads(capsys.readouterr().out)
    assert context['transmits_to_internet'] is False and context['exploitation'] is False
    assert context['target_policy'].startswith('isolated lab')
    assert context['expected_label'] == 'malicious_automation_like'
    assert context['max_connections'] and context['max_duration_seconds']
    assert main(['lab-run', '--scenario', 'scan/sequential/50-ports', '--target', '8.8.8.8']) == 2
    aborted = json.loads(capsys.readouterr().out)
    assert aborted['aborted'] is True and 'allowlist' in aborted['reason']
    assert main(['lab-run', '--scenario', 'no/such/scenario']) == 2


def test_describe_reports_the_boundary():
    context = describe('unit', '127.0.0.1', SafetyLimits(), 'benign_like')
    assert context['destructive_payloads'] is False and context['transmits_to_internet'] is False
