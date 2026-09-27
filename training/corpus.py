"""Deterministic synthetic scenario corpus v3.

ENGINEERING VALIDATION CORPUS ONLY - NOT SUFFICIENT FOR PRODUCTION MODEL QUALITY.
Every sequence is generated locally from a fixed seed. No capture, no live traffic,
no Internet and no decision made by this system is used. Labels describe generator
intent; they are never derived from a risk score, an action or a firewall state.
"""
import random
from eye_for_an_eye.correlation.engine import Sample

CORPUS_VERSION = 'synthetic-behavior-v3'
SEED_PREFIX = 'p8-v3'
TRIALS = 12
HELD_OUT_TRIALS = 6

BENIGN, HARD_NEGATIVE = 'benign', 'hard_negative'
MALICIOUS, HARD_POSITIVE = 'malicious_automation', 'hard_positive'
POSITIVE_KINDS = (MALICIOUS, HARD_POSITIVE)

DEFAULTS = dict(kind=BENIGN, count=72, rate=1.0, jitter=(.5, 1.5), ports=('fixed', (443, 80)), destinations=1,
                handshake=.97, credential=.0, anomaly=.02, continuation=.55, retry=.05, payload=.85,
                deception=.0, digest='varied', families=('http',), pauses=())

# Scenario families. Benign and hard-negative families carry label 0; the two positive
# kinds carry label 1. Hard negatives are legitimate behaviour that looks hostile;
# hard positives are hostile behaviour that looks quiet.
SCENARIOS = {
    # --- ordinary benign -------------------------------------------------------
    'web_browser': dict(rate=.8, ports=('fixed', (80, 443)), handshake=.98, continuation=.6, payload=.9, count=60),
    'mobile_app_client': dict(rate=3.0, ports=('fixed', (443,)), handshake=.95, continuation=.5, payload=.35),
    'software_updater': dict(rate=25.0, ports=('fixed', (443,)), handshake=.99, continuation=.3, digest='repeat',
                             payload=.8, count=44),
    'interactive_ssh': dict(rate=4.0, ports=('fixed', (22,)), handshake=1.0, continuation=.8, credential=.04,
                            payload=.2, families=('ssh',), count=60),
    'backup_client': dict(rate=6.0, ports=('fixed', (873, 22)), handshake=.99, continuation=.7, digest='repeat',
                          payload=.85, families=('ssh',)),
    'flaky_client': dict(rate=1.5, ports=('fixed', (443, 80)), handshake=.55, retry=.35, anomaly=.05, payload=.5),
    'human_manual_access': dict(rate=12.0, jitter=(.2, 2.5), ports=('fixed', (22, 443, 8080)), handshake=.95,
                                credential=.03, payload=.3, families=('http', 'ssh'), count=48),
    'cdn_origin_fetch': dict(rate=.35, ports=('fixed', (443,)), handshake=.99, continuation=.45, payload=.9, count=96),
    # --- hard negatives: legitimate, deliberately suspicious-looking -----------
    'monitoring_agent': dict(kind=HARD_NEGATIVE, rate=5.0, jitter=(.98, 1.02), ports=('fixed', (9100, 443)),
                             digest='repeat', handshake=.99, continuation=.2, payload=.9),
    'health_checker': dict(kind=HARD_NEGATIVE, rate=1.0, jitter=(.97, 1.03), ports=('fixed', (8080,)),
                           digest='repeat', handshake=.98, anomaly=.10, continuation=.15, payload=.25, count=96),
    'load_balancer': dict(kind=HARD_NEGATIVE, rate=.12, jitter=(.9, 1.1), ports=('fixed', (8080, 8443)),
                          digest='repeat', handshake=.99, continuation=.25, payload=.85, count=96),
    'reverse_proxy': dict(kind=HARD_NEGATIVE, rate=.08, ports=('fixed', (8080,)), handshake=.99, continuation=.5,
                          payload=.3, count=96),
    'service_discovery': dict(kind=HARD_NEGATIVE, rate=.5, ports=('cycle', (80, 443, 8080, 9090, 5432, 6379)),
                              handshake=.8, anomaly=.15, digest='repeat', continuation=.2, payload=.8,
                              families=('http',), count=72),
    'deployment_probe': dict(kind=HARD_NEGATIVE, rate=.3, ports=('cycle', (80, 443, 8080, 9090)), handshake=.85,
                             anomaly=.2, continuation=.1, digest='repeat', payload=.4, count=72,
                             pauses=((24, 120.0), (48, 120.0))),
    'admin_diagnostic': dict(kind=HARD_NEGATIVE, rate=1.2, ports=('cycle', (22, 80, 443, 3306, 5432)),
                             credential=.25, anomaly=.1, handshake=.7, digest='varied', payload=.9,
                             families=('http', 'ssh', 'ftp'), count=60),
    'owner_vulnerability_scanner': dict(kind=HARD_NEGATIVE, rate=.2, ports=('sequential', 1000), handshake=.3,
                                        anomaly=.5, digest='unique', continuation=.1, payload=.3,
                                        families=('http', 'ssh', 'ftp'), count=96),
    # --- malicious automation --------------------------------------------------
    'sequential_port_scan': dict(kind=MALICIOUS, rate=.15, ports=('sequential', 20), handshake=.25, anomaly=.55,
                                 digest='unique', continuation=.05, payload=.3, families=('http', 'ssh', 'ftp'),
                                 count=96),
    'horizontal_scan': dict(kind=MALICIOUS, rate=.2, ports=('fixed', (445,)), destinations=12, handshake=.2,
                            anomaly=.5, digest='repeat', continuation=.05, payload=.85, count=96),
    'randomized_port_scan': dict(kind=MALICIOUS, rate=.18, ports=('random', 1024, 65535), handshake=.2, anomaly=.5,
                                 digest='unique', continuation=.05, payload=.25, families=('http', 'ssh', 'ftp'),
                                 count=96),
    'repeated_probe_bot': dict(kind=MALICIOUS, rate=.4, ports=('fixed', (80, 443, 8080)), digest='repeat',
                               anomaly=.35, handshake=.5, continuation=.3, payload=1.0, count=96),
    'protocol_mismatch_probe': dict(kind=MALICIOUS, rate=.3, ports=('fixed', (443, 22, 25)), anomaly=.9,
                                    handshake=.6, digest='varied', continuation=.2, payload=.9,
                                    families=('http', 'ssh'), count=96),
    'credential_automation': dict(kind=MALICIOUS, rate=.35, ports=('fixed', (22,)), credential=1.0, handshake=.8,
                                  digest='none', continuation=.4, payload=.95, families=('ssh',), count=96),
    'service_enumeration': dict(kind=MALICIOUS, rate=.6,
                                ports=('cycle', (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080)),
                                handshake=.4, anomaly=.4, digest='unique', continuation=.1, payload=.4,
                                families=('http', 'ssh', 'ftp'), count=84),
    'deception_prober': dict(kind=MALICIOUS, rate=.5, ports=('fixed', (23, 2323)), deception=1.0, digest='repeat',
                             anomaly=.3, handshake=.7, continuation=.6, payload=.85, count=84),
    'bursty_recon': dict(kind=MALICIOUS, rate=.05, ports=('sequential', 3000), handshake=.3, anomaly=.45,
                         digest='unique', continuation=.05, payload=.3, families=('http', 'ssh'), count=96,
                         pauses=((24, 90.0), (48, 90.0), (72, 90.0))),
    # --- hard positives: hostile but quiet -------------------------------------
    'slow_sequential_scan': dict(kind=HARD_POSITIVE, rate=11.0, ports=('sequential', 4000), handshake=.35,
                                 anomaly=.4, digest='unique', continuation=.05, payload=.35,
                                 families=('http', 'ssh'), count=96),
    'few_port_scan': dict(kind=HARD_POSITIVE, rate=8.0, ports=('cycle', (22, 445, 3389, 5900)), handshake=.3,
                          anomaly=.35, digest='unique', continuation=.05, payload=.85,
                          families=('ssh', 'ftp'), count=60),
    'paced_random_scan': dict(kind=HARD_POSITIVE, rate=9.0, jitter=(.6, 1.6), ports=('random', 1024, 65535),
                              handshake=.3, anomaly=.35, digest='unique', continuation=.05, payload=.3,
                              families=('http', 'ssh'), count=72),
    'low_rate_credentials': dict(kind=HARD_POSITIVE, rate=14.0, ports=('fixed', (22,)), credential=1.0,
                                 handshake=.85, digest='none', continuation=.35, payload=.9,
                                 families=('ssh',), count=60),
    'multi_burst_recon': dict(kind=HARD_POSITIVE, rate=.6, ports=('sequential', 5000), handshake=.35, anomaly=.4,
                              digest='unique', continuation=.05, payload=.4, families=('http', 'ssh'), count=72,
                              pauses=((18, 300.0), (36, 300.0), (54, 300.0))),
}

# Whole families reserved for test only, to measure behaviour never seen while fitting.
HELD_OUT = {
    'few_port_scan': 'unseen hard-positive shape: very small port set, long gaps',
    'multi_burst_recon': 'unseen hard-positive shape: separated bursts',
    'service_discovery': 'unseen hard-negative shape: legitimate repeated multi-port probing',
    'owner_vulnerability_scanner': 'unseen hard-negative shape: authorised scanning is behaviourally hostile',
}


def spec(name):
    if name not in SCENARIOS:
        raise KeyError('unknown scenario family')
    return {**DEFAULTS, **SCENARIOS[name]}


def label_of(name):
    return int(spec(name)['kind'] in POSITIVE_KINDS)


def _port(strategy, rng, index):
    kind = strategy[0]
    if kind == 'fixed':
        return rng.choice(strategy[1])
    if kind == 'cycle':
        return strategy[1][index % len(strategy[1])]
    if kind == 'sequential':
        return strategy[1] + index
    if kind == 'random':
        return rng.randrange(strategy[1], strategy[2])
    raise ValueError('unknown port strategy')


def _digest(strategy, rng, index, credential):
    if credential or strategy == 'none':
        return ''
    if strategy == 'repeat':
        return 'repeat'
    if strategy == 'unique':
        return f'u{index}'
    return str(rng.randrange(8))


def scenario_samples(name, trial):
    """Fixed seed per (family, trial). Same inputs always produce the same sequence."""
    if type(trial) is not int or not 0 <= trial < 1000:
        raise ValueError('bounded trial index required')
    config = spec(name)
    rng = random.Random(f'{SEED_PREFIX}:{name}:{trial}')
    pauses = dict(config['pauses'])
    low, high = config['jitter']
    time = 0.0
    samples = []
    for index in range(config['count']):
        time += config['rate'] * rng.uniform(low, high) + pauses.get(index, 0.0)
        credential = rng.random() < config['credential']
        destination = f'198.51.100.{1 + index % config["destinations"]}'
        samples.append(Sample(
            time, f'{index:04}', destination, _port(config['ports'], rng, index), 'tcp',
            True, rng.random() < config['handshake'], _digest(config['digest'], rng, index, credential), '',
            rng.choice(config['families']), credential, rng.random() < config['anomaly'],
            rng.random() < config['continuation'], rng.random() < config['retry'],
            rng.random() < config['payload'], rng.random() < config['deception']))
    return samples


def split_of(name, trial):
    """Whole source sequences and whole held-out families stay on one side of the split."""
    if name in HELD_OUT:
        return 'test'
    return 'train' if trial % 6 < 4 else 'validation' if trial % 6 == 4 else 'test'


def sequences():
    """(family, trial, split) for the whole corpus, deterministic order."""
    for name in SCENARIOS:
        for trial in range(HELD_OUT_TRIALS if name in HELD_OUT else TRIALS):
            yield name, trial, split_of(name, trial)
