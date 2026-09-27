"""Group split discipline: leakage is a failing test, not a warning."""
from pathlib import Path
import pytest
from training import corpus as corpus_module
from training.dataset import DATASET_VERSION, load
from training.split import (LeakageError, assert_disjoint, assert_group_separation, assign,
                            chronological_order, partition)
from training.validation import group_leakage

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / 'datasets' / DATASET_VERSION

pytestmark = pytest.mark.skipif(not (DATASET / 'dataset_manifest.json').is_file(),
                                reason='research dataset is not distributed in the source archive')


@pytest.fixture(scope='module')
def rows():
    return load(DATASET)[1]


def test_no_source_group_crosses_a_split(rows):
    assert assert_group_separation(rows, keys=('source_group',))
    parts = partition(rows)
    assert sum(len(subset) for subset in parts.values()) == len(rows)
    assert assert_disjoint(parts['train'], parts['test'])
    assert assert_disjoint(parts['train'], parts['validation'])
    assert assert_disjoint(parts['validation'], parts['test'])
    leakage = group_leakage(rows)
    assert leakage['source_groups_in_multiple_splits'] == []
    assert leakage['source_group_count'] == len({row['source_group'] for row in rows})


def test_held_out_families_are_test_only(rows):
    leakage = group_leakage(rows)
    assert set(corpus_module.HELD_OUT) <= set(leakage['test_only_scenario_groups'])
    for name in corpus_module.HELD_OUT:
        assert {row['split'] for row in rows if row['scenario_group'] == name} == {'test'}


def test_leakage_raises(rows):
    leaked = [rows[0], dict(rows[0], split='test' if rows[0]['split'] != 'test' else 'train')]
    with pytest.raises(LeakageError, match='source_group'):
        assert_group_separation(leaked, keys=('source_group',))
    with pytest.raises(LeakageError):
        assert_disjoint([rows[0]], [dict(rows[0])])
    with pytest.raises(ValueError):
        partition([dict(rows[0], split='holdout')])


def test_hash_assignment_is_deterministic_and_order_independent():
    groups = [f'source-{index}' for index in range(400)]
    first = assign(groups, salt='p8')
    assert first == assign(list(reversed(groups)), salt='p8')
    assert first == assign(groups + groups, salt='p8')
    assert first != assign(groups, salt='other')
    assert set(first.values()) == {'train', 'validation', 'test'}
    assert 0 < sum(v == 'test' for v in first.values()) < len(groups)
    with pytest.raises(ValueError):
        assign(groups, salt='p8', validation=.6, test=.6)


def test_chronological_report_is_descriptive(rows):
    report = chronological_order(rows)
    assert set(report['spans']) == {'train', 'validation', 'test'}
    assert all(span['rows'] > 0 for span in report['spans'].values())
    assert 'single real temporal stream' in report['applies']


def test_corpus_covers_all_four_scenario_kinds():
    kinds = {corpus_module.spec(name)['kind'] for name in corpus_module.SCENARIOS}
    assert kinds == {corpus_module.BENIGN, corpus_module.HARD_NEGATIVE,
                     corpus_module.MALICIOUS, corpus_module.HARD_POSITIVE}
    for name in ('owner_vulnerability_scanner', 'service_discovery', 'monitoring_agent', 'load_balancer'):
        assert corpus_module.label_of(name) == 0
    for name in ('slow_sequential_scan', 'few_port_scan', 'low_rate_credentials', 'multi_burst_recon'):
        assert corpus_module.label_of(name) == 1
    first = [s.time for s in corpus_module.scenario_samples('slow_sequential_scan', 0)]
    assert first == [s.time for s in corpus_module.scenario_samples('slow_sequential_scan', 0)]
    assert first != [s.time for s in corpus_module.scenario_samples('slow_sequential_scan', 1)]


def test_dataset_build_is_reproducible_and_matches_the_shipped_files(rows):
    from training.dataset import build_rows
    rebuilt = build_rows()
    assert build_rows() == rebuilt
    assert len(rebuilt) == len(rows)
    assert sorted(r['sample_id'] for r in rebuilt) == sorted(r['sample_id'] for r in rows)
    assert {r['sample_id']: r['split'] for r in rebuilt} == {r['sample_id']: r['split'] for r in rows}


def test_rebuilt_dataset_hashes_match_the_committed_manifest(tmp_path):
    import json
    from training.dataset import write
    committed = json.loads((DATASET / 'dataset_manifest.json').read_text(encoding='utf-8'))
    fresh = write(tmp_path / 'rebuild')
    assert fresh['sha256'] == committed['sha256']
    assert {name: info['sha256'] for name, info in fresh['files'].items()} == \
        {name: info['sha256'] for name, info in committed['files'].items()}
    assert fresh['record_count'] == committed['record_count']
