"""Offline dataset commands.

These are development commands, not runtime ones: the production wheel ships
`eye_for_an_eye` only, so dataset tooling stays out of the deployed surface. Every command
runs offline and none of them writes runtime configuration or activates a model.

    python -m dataset generate  --output datasets
    python -m dataset validate  --dataset datasets/processed/dataset-v1.0
    python -m dataset stats     --dataset datasets/processed/dataset-v1.0
    python -m dataset split     --dataset datasets/processed/dataset-v1.0
    python -m dataset manifest  --dataset datasets/processed/dataset-v1.0
    python -m dataset leakage   --dataset datasets/processed/dataset-v1.0
    python -m dataset lab-run   --scenario scan/sequential/50-ports
    python -m dataset export-shadow --events events.jsonl --output datasets/unlabeled
    python -m dataset review     --pool datasets/unlabeled/shadow_unlabeled.csv --output review.json
    python -m dataset diff      --left ... --right ...
"""
import argparse
import json
from pathlib import Path
import random
from . import (leakage as leakage_module, manifest as manifest_module, review as review_module,
               scenarios, schema, split as split_module)
from .builder import build_features, generate_raw
from .collectors.pcap import offline_config
from .statistics import distribution_shift, out_of_distribution, source_report, training_statistics
from .store import read, write, write_splits
from .validator import validate


def dataset_hash_placeholder():
    return 'see the dataset manifest; this file describes distributions, not contents'

DEFAULT_ROOT = Path('datasets')


def _paths(root, version):
    root = Path(root)
    return {'raw': root / 'raw' / version, 'raw_root': root / 'raw',
            'intermediate': root / 'intermediate' / version,
            'processed': root / 'processed' / version, 'manifests': root / 'manifests',
            'unlabeled': root / 'unlabeled'}


def _load(directory):
    directory = Path(directory)
    samples = read(directory / 'samples.csv')
    return samples


def command_generate(args):
    matrix = scenarios.load(args.matrix)
    version = args.dataset_version or matrix['dataset_version']
    salt = getattr(args, 'seed_salt', '') or ''
    paths = _paths(args.output, version)
    raw_index = generate_raw(scenarios.plans(matrix, salt=salt), paths['raw'],
                             dataset_version=version,
                             matrix_version=matrix['matrix_version'], overwrite=args.overwrite_raw)
    samples, build_report = build_features(
        raw_index, paths['raw'], offline_config(), dataset_version=version,
        interval=matrix['snapshot_interval_seconds'],
        max_samples_per_source=matrix['max_samples_per_source'],
        max_samples_per_scenario=matrix['max_samples_per_scenario'])
    # Deterministic shuffle. Build order groups rows by scenario family, which makes row
    # position weakly predictive of the label; position is metadata, never a feature, and this
    # removes the temptation entirely.
    random.Random(f'{version}:row-order').shuffle(samples)
    assignment = split_module.assign(samples)
    split_module.apply(samples, assignment)
    split_module.assert_no_leakage(samples)
    parts = split_module.partition(samples)
    paths['processed'].mkdir(parents=True, exist_ok=True)
    files = {'samples': write(paths['processed'] / 'samples.csv', samples)}
    files.update(write_splits(paths['processed'], parts))
    statistics = training_statistics(samples)
    stats_path = Path(args.output) / 'stats_v1.json'
    stats_path.write_text(json.dumps(statistics, indent=2) + '\n', encoding='utf-8')
    (Path(args.output) / 'model_features_v1.json').write_text(
        json.dumps(schema.model_feature_document(), indent=2) + '\n', encoding='utf-8')
    reproduce = (f'python -m dataset generate --matrix {args.matrix} --output {args.output} '
                 f'--dataset-version {version}'
                 + (f' --seed-salt {salt}' if salt else ''))
    manifest = manifest_module.build(
        version, samples, files=files, reproduce=reproduce, scenarios=scenarios.coverage(matrix),
        seeds=sorted({sample.provenance.get('seed') for sample in samples
                      if sample.provenance.get('seed')}),
        sources={'controlled_lab': len(samples), 'pcap': 0, 'shadow': 0},
        truncated=build_report['truncated'], stats_file=str(stats_path),
        notes=['every row came from a synthetic capture parsed by the production packet parser',
               'labels come from controlled scenario intent, never from a decision this system made'])
    manifest['build'] = {'runs': len(build_report['runs']), 'samples_per_scenario':
                         build_report['samples_per_scenario']}
    manifest_module.write(paths['manifests'] / f'{version}.json', manifest)
    split_files = {name: files[name] for name in split_module.SPLITS}
    split_record = manifest_module.split_manifest(
        version, parts, policy=split_module.describe(samples, assignment)['policy'],
        holdout={family: {'split': target, 'reason': reason}
                 for family, (target, reason) in split_module.HOLDOUT.items()},
        files=split_files, seed=split_module.DEFAULT_SALT)
    manifest_module.write(paths['manifests'] / f'{version}-split.json', split_record)
    report = validate(samples, manifest=manifest, directory=paths['processed'])
    print(json.dumps({'dataset_version': version, 'samples': len(samples),
                      'labels': manifest['labels'], 'splits': {k: len(v) for k, v in parts.items()},
                      'readiness': report['readiness'], 'critical': report['critical'],
                      'truncated': manifest['truncated'], 'sha256': manifest['sha256']}, indent=2))
    return 1 if report['critical'] else 0


DATASET_V1 = 'dataset-v1'


def command_build(args):
    """LAB + PCAP + SHADOW -> one dataset. Each source keeps its own label authority."""
    from .collectors import pcap as pcap_collector, shadow as shadow_collector
    from .deduplicate import cross_source
    from .statistics import training_quantiles
    version = args.dataset_version
    root = Path(args.output)
    paths = _paths(root, version)
    config = offline_config()
    matrix = scenarios.load(args.matrix)
    report = {'sources': {}}
    samples = []

    if args.lab:
        raw_index = generate_raw(scenarios.plans(matrix), paths['raw_root'] / 'lab' / version, dataset_version=version,
                                 matrix_version=matrix['matrix_version'], overwrite=args.overwrite_raw)
        lab_samples, lab_report = build_features(
            raw_index, paths['raw_root'] / 'lab' / version, config, dataset_version=version,
            interval=matrix['snapshot_interval_seconds'],
            max_samples_per_source=matrix['max_samples_per_source'],
            max_samples_per_scenario=matrix['max_samples_per_scenario'])
        samples.extend(lab_samples)
        report['sources'][schema.LAB] = {'runs': raw_index['runs'], 'samples': len(lab_samples),
                                         'truncated': lab_report['truncated'],
                                         'packets': raw_index['packets']}
        if args.live_runs:
            live_samples, live_report = _live(config, version, paths['raw_root'] / 'lab-live' / version,
                                              runs=args.live_runs, overwrite=args.overwrite_raw)
            samples.extend(live_samples)
            report['sources']['LAB_LIVE'] = live_report

    if args.pcap:
        corpus = pcap_collector.build_corpus(paths['raw_root'] / 'pcap' / version, overwrite=args.overwrite_raw)
        _, entries = pcap_collector.load_corpus(paths['raw_root'] / 'pcap' / version / 'captures.json')
        pcap_samples, captures = [], []
        for entry, capture in entries:
            produced, stats = pcap_collector.ingest(
                entry, capture, config, dataset_version=version,
                interval=matrix['snapshot_interval_seconds'],
                max_samples_per_source=matrix['max_samples_per_source'],
                max_samples_per_capture=matrix['max_samples_per_scenario'])
            pcap_samples.extend(produced)
            captures.append({k: stats[k] for k in ('capture_id', 'capture_group', 'samples', 'packets')})
        samples.extend(pcap_samples)
        report['sources'][schema.PCAP] = {
            'captures': len(entries), 'samples': len(pcap_samples),
            'labelled_captures': sum(1 for entry, _ in entries
                                     if entry['label'] in schema.SUPERVISED_LABELS),
            'unlabelled_captures': sum(1 for entry, _ in entries if entry['label'] == schema.UNLABELED),
            'corpus_version': corpus['capture_corpus_version'], 'per_capture': captures}

    if args.shadow:
        shadow_samples, shadow_manifest = shadow_collector.generate_pool(
            paths['raw_root'] / 'shadow' / version, paths['unlabeled'] / 'shadow', config, dataset_version=version,
            interval=matrix['snapshot_interval_seconds'],
            max_samples_per_source=matrix['max_samples_per_source'], overwrite=args.overwrite_raw)
        samples.extend(shadow_samples)
        report['sources'][schema.SHADOW_UNLABELED] = {
            'samples': len(shadow_samples), 'groups': shadow_manifest['groups'],
            'reviewed': 0, 'collection': shadow_manifest['collection']}

    if not samples:
        raise ValueError('no source selected; pass --lab, --pcap and/or --shadow')

    # Deterministic shuffle. Build order groups rows by scenario family, which makes row
    # position weakly predictive of the label; position is metadata, never a feature, and this
    # removes the temptation entirely.
    random.Random(f'{version}:row-order').shuffle(samples)
    assignment = split_module.assign(samples)
    split_module.apply(samples, assignment)
    split_module.assert_no_leakage(samples)
    parts = split_module.partition(samples)
    unlabelled = [sample for sample in samples if not sample.supervised]

    paths['processed'].mkdir(parents=True, exist_ok=True)
    files = {'samples': write(paths['processed'] / 'samples.csv', samples)}
    files.update(write_splits(paths['processed'], parts))
    files['unlabeled'] = write(paths['processed'] / 'unlabeled.csv', unlabelled)

    statistics = training_statistics(samples)
    quantiles = training_quantiles(samples)
    statistics['training_quantiles'] = quantiles
    statistics['by_source'] = {name: {'rows': info['rows'], 'role': info['role'],
                                      'labels': info['labels'],
                                      'supervised_eligible': info['supervised_eligible']}
                               for name, info in source_report(samples).items()}
    (root / 'stats_v1.json').write_text(json.dumps(statistics, indent=2) + '\n', encoding='utf-8')
    shift = distribution_shift(samples, reference=schema.LAB)
    ood = out_of_distribution([s for s in samples if not s.supervised], quantiles)
    manifest_module.write(paths['manifests'] / f'{version}-distribution.json', {
        'manifest_schema_version': manifest_module.MANIFEST_SCHEMA_VERSION,
        'dataset_version': version, 'created_at': manifest_module.now(),
        'sources': {name: info['rows'] for name, info in source_report(samples).items()},
        'shift': shift,
        'out_of_distribution': {'rows_outside_training_quantiles': len(ood),
                                'pool_rows': sum(1 for s in samples if not s.supervised),
                                'examples': dict(list(ood.items())[:10]),
                                'use': 'review candidates and dataset-v2 scenario ideas; never a label'},
        'sha256': dataset_hash_placeholder()})
    review_list = review_module.queue([s for s in samples if not s.supervised], quantiles=quantiles)
    paths['unlabeled'].mkdir(parents=True, exist_ok=True)
    (paths['unlabeled'] / 'review_queue.json').write_text(
        json.dumps({'review_queue_version': 1, 'created_at': manifest_module.now(),
                    'prioritisation': ('behavioural only: model and mathematical baseline '
                                       'disagreeing, high risk the policy did not act on, and '
                                       'features outside the training distribution. Never identity.'),
                    'rows': len(review_list), 'queue': review_list[:100]}, indent=2) + '\n',
        encoding='utf-8')
    (root / 'model_features_v1.json').write_text(
        json.dumps(schema.model_feature_document(), indent=2) + '\n', encoding='utf-8')

    reproduce = (f'python -m dataset build --lab --pcap --shadow --matrix {args.matrix} '
                 f'--output {args.output} --dataset-version {version}')
    dataset_manifest = manifest_module.build(
        version, samples, files=files, reproduce=reproduce, scenarios=scenarios.coverage(matrix),
        seeds=sorted({sample.provenance.get('seed') for sample in samples
                      if sample.provenance.get('seed')}),
        sources={name: info.get('samples', 0) for name, info in report['sources'].items()},
        stats_file=str(root / 'stats_v1.json'),
        notes=['LAB gives ground truth, PCAP gives packet realism, SHADOW gives observation '
               'without ground truth; they are not interchangeable',
               'unreviewed shadow telemetry is never part of a supervised split'])
    dataset_manifest['source_report'] = report['sources']
    dataset_manifest['cross_source_duplicates'] = cross_source(samples)
    manifest_module.write(paths['manifests'] / f'{version}.json', dataset_manifest)
    split_record = manifest_module.split_manifest(
        version, parts, policy=split_module.describe(samples, assignment)['policy'],
        holdout={**{f: {'split': t, 'reason': r} for f, (t, r) in split_module.HOLDOUT.items()},
                 **{c: {'split': t, 'reason': r} for c, (t, r) in split_module.CAPTURE_HOLDOUT.items()}},
        files={name: files[name] for name in split_module.SPLITS}, seed=split_module.DEFAULT_SALT)
    split_record['dataset_sha256'] = dataset_manifest['sha256']
    split_record['grouping_rules'] = dict(schema.GROUP_KEY)
    split_record['frozen'] = args.freeze
    manifest_module.write(paths['manifests'] / f'{version}-split.json', split_record)

    validation = validate(samples, manifest=dataset_manifest, directory=paths['processed'],
                          leakage_report=False)
    print(json.dumps({'dataset_version': version, 'samples': len(samples),
                      'sources': dataset_manifest['sources'],
                      'supervised_eligible': validation['supervised_eligible'],
                      'unlabelled_pool': validation['unlabelled_pool'],
                      'splits': {k: len(v) for k, v in parts.items()},
                      'readiness_without_leakage_report': validation['readiness'],
                      'critical': validation['critical'], 'sha256': dataset_manifest['sha256']},
                     indent=2))
    return 1 if validation['critical'] else 0


def _live(config, version, raw_dir, *, runs=1, overwrite=False):
    """Short live loopback runs recorded once; real timing cannot be regenerated."""
    from .collectors import live as live_collector
    from . import provenance as provenance_module
    from .builder import collect
    from .manifest import file_digest, now
    root = Path(raw_dir)
    index_path = root / 'live_index.json'
    produced, entries = [], []
    if index_path.exists() and not overwrite:
        index = json.loads(index_path.read_text(encoding='utf-8'))
    else:
        root.mkdir(parents=True, exist_ok=True)
        recorded = []
        for scenario_id in live_collector.LIVE_SCENARIOS:
            for run_index in range(runs):
                events, stats = live_collector.run(scenario_id, run_index)
                name = f"{scenario_id.replace('/', '_')}-{run_index:02d}.events.json"
                (root / name).write_text('\n'.join(event.to_json() for event in events) + '\n',
                                         encoding='utf-8')
                recorded.append({**stats, 'trace': name, 'sha256': file_digest(root / name)})
        index = {'live_index_schema_version': 1, 'created_at': now(), 'runs': recorded,
                 'immutability': 'live timing cannot be regenerated; these traces are inputs',
                 'safety': 'loopback only, enforced by production config validation'}
        index_path.write_text(json.dumps(index, indent=2) + '\n', encoding='utf-8')
    from eye_for_an_eye.events import NetworkEvent
    for entry in index['runs']:
        path = root / entry['trace']
        if file_digest(path) != entry['sha256']:
            raise ValueError('recorded live trace changed since ingestion')
        events = [NetworkEvent.from_json(line) for line in
                  path.read_text(encoding='utf-8').splitlines() if line.strip()]
        events.sort(key=lambda event: (event.timestamp, event.event_id))
        group = f"{entry['scenario_id']}#{entry['run']:02d}"
        context = {'dataset_version': version, 'source_type': schema.LAB,
                   'scenario_id': entry['scenario_id'], 'scenario_group': entry['family'],
                   'source_group': group, 'capture_group': None, 'group': group,
                   'label': entry['label'], 'label_source': 'controlled_scenario',
                   'label_confidence': 'HIGH',
                   'provenance': provenance_module.lab(
                       scenario_family=entry['family'], scenario_variant=entry['scenario_id'],
                       run_id=group, seed=f"{entry['scenario_id']}:{entry['run']}",
                       generator_version=manifest_module.GENERATOR_VERSION,
                       ingestion='live_loopback', duration_seconds=entry['wall_seconds'],
                       scenario_kind=entry['kind'])}
        rows, _ = collect(config, events, context, interval=2.0, max_samples_per_source=20)
        produced.extend(rows)
        entries.append({'scenario_id': entry['scenario_id'], 'run': entry['run'],
                        'samples': len(rows), 'events': entry['events'],
                        'wall_seconds': entry['wall_seconds']})
    return produced, {'runs': len(entries), 'samples': len(produced), 'per_run': entries,
                      'ingestion': 'live_loopback'}


def command_validate(args):
    samples = _load(args.dataset)
    version = samples[0].dataset_version
    manifest_path = Path(args.manifests or Path(args.dataset).parents[1] / 'manifests') / f'{version}.json'
    manifest = manifest_module.read(manifest_path) if manifest_path.is_file() else None
    leakage_path = Path(args.manifests or Path(args.dataset).parents[1] / 'manifests') / f'{version}-leakage.json'
    report = validate(samples, manifest=manifest, directory=args.dataset,
                      leakage_report=leakage_path.is_file())
    report['leakage_report'] = str(leakage_path) if leakage_path.is_file() else None
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'rows': report['rows'], 'sources': report['sources'],
                      'supervised_eligible': report['supervised_eligible'],
                      'unlabelled_pool': report['unlabelled_pool'], 'splits': report['splits'],
                      'critical': report['critical'], 'warnings': report['warnings'],
                      'readiness': report['readiness'], 'readiness_reasons': report['readiness_reasons'],
                      'automatic_enforcement_ready': report['automatic_enforcement_ready']}, indent=2))
    return 1 if report['critical'] else 0


def command_stats(args):
    samples = _load(args.dataset)
    report = validate(samples)
    payload = {'balance': report['balance'], 'labels': report['labels'], 'scenarios': report['scenarios'],
               'features': report['features'], 'duplicates': report['duplicates']}
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'balance': payload['balance'], 'labels': payload['labels']}, indent=2))
    return 0


def command_split(args):
    samples = _load(args.dataset)
    random.Random(f'{samples[0].dataset_version}:row-order').shuffle(samples)
    assignment = split_module.assign(samples)
    split_module.apply(samples, assignment)
    split_module.assert_no_leakage(samples)
    print(json.dumps(split_module.describe(samples, assignment), indent=2))
    return 0


def command_manifest(args):
    version = _load(args.dataset)[0].dataset_version
    path = Path(args.manifests or Path(args.dataset).parents[1] / 'manifests') / f'{version}.json'
    manifest = manifest_module.read(path)
    problems = manifest_module.verify_files(manifest, args.dataset)
    print(json.dumps({'dataset_version': manifest['dataset_version'], 'sha256': manifest['sha256'],
                      'record_count': manifest['record_count'], 'labels': manifest['labels'],
                      'generator_version': manifest['generator_version'],
                      'git_commit': manifest['git_commit'], 'reproduce': manifest['reproduce'],
                      'file_problems': problems}, indent=2))
    return 1 if problems else 0


def _runs_for_leakage(root, version):
    """Environment metadata per run: LAB scenario runs and PCAP captures, side by side."""
    runs = []
    lab_index = Path(root) / 'raw' / 'lab' / version / 'raw_index.json'
    if lab_index.is_file():
        for entry in json.loads(lab_index.read_text(encoding='utf-8'))['captures']:
            runs.append({**entry, 'source_type': schema.LAB})
    captures = Path(root) / 'raw' / 'pcap' / version / 'captures.json'
    if captures.is_file():
        for entry in json.loads(captures.read_text(encoding='utf-8'))['captures']:
            runs.append({**entry, 'source_type': schema.PCAP,
                         'source_group': entry['capture_id'],
                         'label': entry['label']})
    return runs


def command_leakage(args):
    samples = _load(args.dataset)
    if args.raw_index:
        runs = json.loads(Path(args.raw_index).read_text(encoding='utf-8'))['captures']
    else:
        runs = _runs_for_leakage(args.root, samples[0].dataset_version)
    report = leakage_module.report(samples, runs)
    report['runs_analysed'] = len(runs)
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'findings': report['findings'],
                      'suspicious_features': [row['feature'] for row in
                                              report['feature_separation']['suspicious']],
                      'port_leakage': {k: report['port_leakage'][k] for k in
                                       ('exclusive_to_one_label', 'best_single_port_rule_accuracy',
                                        'shared_port_fraction')}}, indent=2))
    return 0


def command_lab_run(args):
    from .safety import describe as describe_safety, validate_live_target
    matrix = scenarios.load(args.matrix)
    plans = [plan for plan in scenarios.plans(matrix) if plan.scenario_id == args.scenario]
    if not plans:
        print(json.dumps({'error': 'unknown scenario', 'scenario': args.scenario}))
        return 2
    plan = plans[0]
    try:
        target = validate_live_target(args.target)
    except ValueError as error:
        print(json.dumps({'aborted': True, 'reason': str(error), 'scenario': args.scenario}))
        return 2
    context = describe_safety(plan.scenario_id, target, plan.limits, plan.label)
    context.update(contacts=len(plan.contacts), seed=plan.seed,
                   duration_seconds=round(plan.duration, 2), dry_run=not args.execute)
    print(json.dumps(context, indent=2))
    if args.execute:
        print(json.dumps({'error': 'loopback execution is not enabled in this build; '
                                   'raw captures are generated offline by "python -m dataset generate"'}))
        return 2
    return 0


def command_export_shadow(args):
    from .collectors.shadow import export
    result = export(args.events, args.output, secret_path=args.secret, max_samples=args.max_samples)
    print(json.dumps(result, indent=2))
    return 0


def command_review(args):
    from .review import export as review_export
    samples = read(Path(args.pool))
    print(json.dumps(review_export(samples, args.output), indent=2))
    return 0


def command_review_queue(args):
    samples = _load(args.dataset)
    quantiles = None
    if args.stats:
        quantiles = json.loads(Path(args.stats).read_text(encoding='utf-8')).get('training_quantiles')
    pool = [sample for sample in samples if not sample.supervised]
    entries = review_module.queue(pool, quantiles=quantiles)
    payload = {'review_queue_version': 1, 'pool_rows': len(pool), 'rows': len(entries),
               'queue': entries[:100]}
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'pool_rows': len(pool), 'queued': len(entries),
                      'top': [{'sample_id': e['sample_id'], 'priority': e['priority'],
                               'reasons': e['reasons']} for e in entries[:5]]}, indent=2))
    return 0


def command_diff(args):
    left, right = _load(args.left), _load(args.right)
    from .statistics import balance_report, feature_report
    left_features, right_features = feature_report(left), feature_report(right)
    shifts = []
    for name in schema.MODEL_FEATURES:
        a, b = left_features[name]['overall'], right_features[name]['overall']
        shifts.append({'feature': name, 'mean_delta': b['mean'] - a['mean'],
                       'p95_delta': (b['p95'] or 0) - (a['p95'] or 0),
                       'missing_delta': b['missing_percent'] - a['missing_percent']})
    shifts.sort(key=lambda item: abs(item['mean_delta']), reverse=True)
    print(json.dumps({'left': balance_report(left), 'right': balance_report(right),
                      'largest_shifts': shifts[:10]}, indent=2))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog='python -m dataset', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)

    build = sub.add_parser('build', help='LAB + PCAP + SHADOW into one dataset')
    build.add_argument('--lab', action='store_true')
    build.add_argument('--pcap', action='store_true')
    build.add_argument('--shadow', action='store_true')
    build.add_argument('--live-runs', type=int, default=1,
                       help='short live loopback runs per live scenario; 0 disables them')
    build.add_argument('--matrix', default=str(scenarios.MATRIX_V1))
    build.add_argument('--output', default=str(DEFAULT_ROOT))
    build.add_argument('--dataset-version', default=DATASET_V1)
    build.add_argument('--overwrite-raw', action='store_true')
    build.add_argument('--freeze', action='store_true', help='mark the test split frozen')
    build.set_defaults(handler=command_build)

    generate = sub.add_parser('generate', help='build raw captures, features, splits and manifests')
    generate.add_argument('--matrix', default=str(scenarios.MATRIX_V1))
    generate.add_argument('--output', default=str(DEFAULT_ROOT))
    generate.add_argument('--dataset-version')
    generate.add_argument('--overwrite-raw', action='store_true',
                          help='regenerate immutable raw captures in place; normally write a new version')
    generate.add_argument('--seed-salt', default='',
                          help='independent corpus from the same matrix: the salt enters every '
                               'scenario seed and the source-address shuffle. Empty reproduces '
                               'every corpus built before P15.2 exactly.')
    generate.set_defaults(handler=command_generate)

    for name, handler, extra in (('validate', command_validate, True), ('stats', command_stats, True),
                                 ('split', command_split, False), ('manifest', command_manifest, False)):
        item = sub.add_parser(name)
        item.add_argument('--dataset', required=True)
        item.add_argument('--manifests')
        if extra:
            item.add_argument('--output')
        item.set_defaults(handler=handler)

    leak = sub.add_parser('leakage', help='port, timing, generator and single-feature leakage checks')
    leak.add_argument('--dataset', required=True)
    leak.add_argument('--raw-index')
    leak.add_argument('--root', default=str(DEFAULT_ROOT))
    leak.add_argument('--output')
    leak.set_defaults(handler=command_leakage)

    lab = sub.add_parser('lab-run', help='print the safety context of a scenario before running it')
    lab.add_argument('--scenario', required=True)
    lab.add_argument('--target', default='127.0.0.1')
    lab.add_argument('--matrix', default=str(scenarios.MATRIX_V1))
    lab.add_argument('--execute', action='store_true')
    lab.set_defaults(handler=command_lab_run)

    shadow = sub.add_parser('export-shadow', help='sanitised shadow features into the unlabelled pool')
    shadow.add_argument('--events', required=True)
    shadow.add_argument('--output', required=True)
    shadow.add_argument('--secret')
    shadow.add_argument('--max-samples', type=int, default=20000)
    shadow.set_defaults(handler=command_export_shadow)

    review = sub.add_parser('review', help='review-friendly export of the unlabelled pool')
    review.add_argument('--pool', required=True)
    review.add_argument('--output', required=True)
    review.set_defaults(handler=command_review)

    queue = sub.add_parser('review-queue', help='prioritised review candidates from the unlabelled pool')
    queue.add_argument('--dataset', required=True)
    queue.add_argument('--stats')
    queue.add_argument('--output')
    queue.set_defaults(handler=command_review_queue)

    diff = sub.add_parser('diff', help='compare two processed datasets')
    diff.add_argument('--left', required=True)
    diff.add_argument('--right', required=True)
    diff.set_defaults(handler=command_diff)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == '__main__':
    raise SystemExit(main())
