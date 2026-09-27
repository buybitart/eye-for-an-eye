"""Fixed seeded synthetic sequences, with labels from scenario intent, not decisions.

The frozen P7 generator for `synthetic-behavior-v2`, kept so that corpus stays
byte-reproducible. Its `label_source` value is listed in
`training.schema.LEGACY_LABEL_SOURCES` and is deliberately absent from
`ALLOWED_LABEL_SOURCES`: rows from here must not be fed to the current
`training/validation.py`, which validates the v3 corpus conventions. Changing the
string to satisfy the current vocabulary would change this file's output and so
defeat the only reason it still exists.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
from eye_for_an_eye.correlation.engine import Sample
from eye_for_an_eye.decision.features import from_samples

DATASET_VERSION = 'synthetic-behavior-v2'
BENIGN = ('browser', 'monitoring', 'reverse_proxy', 'backup', 'health_checker', 'software_updater', 'administrator', 'load_balancer')
ATTACK = ('sequential_scan', 'credential_burst', 'protocol_abuse', 'slow_scan', 'random_ports', 'low_rate_credentials', 'burst_pause', 'distributed_sources')


def scenario_samples(name, trial):
    rng = random.Random(f'p7-v2:{name}:{trial}')
    rate = {'browser': .4, 'monitoring': 4, 'reverse_proxy': .08, 'backup': 1, 'health_checker': 5,
        'software_updater': .7, 'administrator': 2, 'load_balancer': .1, 'sequential_scan': .12,
        'credential_burst': .3, 'protocol_abuse': .25, 'slow_scan': 8, 'random_ports': .2,
        'low_rate_credentials': 12, 'burst_pause': .1, 'distributed_sources': 5}[name]
    count = 12 if name == 'distributed_sources' else 96
    time = 0.0
    samples = []
    for index in range(count):
        time += rate * rng.uniform(.5, 1.5)
        if name == 'burst_pause' and index == 48:
            time += 400
        scan = name in ('sequential_scan', 'slow_scan', 'random_ports', 'burst_pause', 'distributed_sources')
        port = 2000 + index if scan else rng.choice([80, 443] if name != 'administrator' else [22, 443, 8080])
        if name == 'random_ports':
            port = rng.randrange(1024, 65536)
        credential = name in ('credential_burst', 'low_rate_credentials') or (name == 'administrator' and index % 25 == 0)
        anomaly = name == 'protocol_abuse' or (scan and rng.random() < .65)
        family = rng.choice(['http', 'ssh', 'ftp']) if scan else 'http'
        # Some benign automation repeats probes; rate/repetition alone must not imply hostility.
        digest = '' if credential else ('repeat' if name in ('monitoring', 'health_checker', 'protocol_abuse') else str(rng.randrange(8)))
        samples.append(Sample(time, f'{index:04}', '192.0.2.200', port, 'tcp', True, not scan,
            digest, '', family, credential, anomaly,
            rng.random() < (.6 if name in ('browser', 'reverse_proxy', 'backup', 'administrator', 'load_balancer',
                                         'credential_burst', 'protocol_abuse') else .2),
            False, True, trial % 3 != 0))
    return samples


def build(trials=18):
    rows = []
    for name in BENIGN + ATTACK:
        for trial in range(trials):
            # Entire source sequences stay together; test also contains unseen scenario families.
            held_out = name in ('slow_scan', 'low_rate_credentials', 'distributed_sources')
            split = 'test' if held_out or trial % 6 == 5 else 'validation' if trial % 6 == 4 else 'train'
            samples = scenario_samples(name, trial)
            for count in range(4, len(samples)+1, 4):
                active = samples[:count]
                vector = from_samples(active, now=active[-1].time, loss_fraction=0.0)
                rows.append({'dataset_version': DATASET_VERSION, 'scenario_id': name,
                    'source_group': f'{name}-{trial}', 'timestamp': active[-1].time, 'split': split,
                    'label': int(name in ATTACK), 'label_source': 'synthetic_scenario_intent_not_observed_verdict',
                    'features': asdict(vector)})
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    rows = build()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        for row in rows:
            stream.write(json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n')
    print(json.dumps({'rows': len(rows), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'dataset_version': DATASET_VERSION}))


if __name__ == '__main__':
    main()
