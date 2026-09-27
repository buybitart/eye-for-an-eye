"""Scenario matrix: which behaviours exist, in which variants, with which seeds."""
from pathlib import Path
import random
import tomllib
from ..generators import benign, composite, deception, profiles, protocol, scanner, withheld
from ..safety import validate_synthetic_address

MATRIX_V1 = Path(__file__).parent / 'matrix-v1.toml'

#: §41. The site profiles a scenario may declare. These are the names
#: `autonomy.cost.PROFILES` already uses, because a per-profile evaluation is
#: only meaningful if it groups traffic the same way the cost policy prices it.
#: An unnamed profile is allowed and means "no site was stated" — silence rather
#: than a default, since guessing one would put traffic in a bucket nobody
#: chose and then report a number about it.
PROFILE_TYPES = ('public_website', 'api', 'admin', 'payment_webhook', 'honeypot')
REGISTRY = {
    'benign.web_client': benign.web_client,
    'benign.web_burst': benign.web_burst,
    'benign.ssh_session': benign.ssh_session,
    'benign.retry_then_success': benign.retry_then_success,
    'benign.ambient_noise': benign.ambient_noise,
    'benign.monitoring_agent': benign.monitoring_agent,
    'benign.health_checker': benign.health_checker,
    'benign.admin_diagnostic': benign.admin_diagnostic,
    'benign.service_discovery': benign.service_discovery,
    'benign.connect_probe': benign.connect_probe,
    'scanner.sequential_scan': scanner.sequential_scan,
    'scanner.randomized_scan': scanner.randomized_scan,
    'scanner.horizontal_scan': scanner.horizontal_scan,
    'scanner.slow_scan': scanner.slow_scan,
    'scanner.burst_scan': scanner.burst_scan,
    'scanner.service_enumeration': scanner.service_enumeration,
    'scanner.multi_stage_recon': scanner.multi_stage_recon,
    'scanner.connect_scan': scanner.connect_scan,
    'protocol.protocol_mismatch': protocol.protocol_mismatch,
    'protocol.repeated_probes': protocol.repeated_probes,
    'protocol.credential_automation': protocol.credential_automation,
    'protocol.low_rate_credentials': protocol.low_rate_credentials,
    'deception.decoy_enumeration': deception.decoy_enumeration,
    'deception.decoy_brush_past': deception.decoy_brush_past,
    # P15.3: new compositions of existing primitives, for measuring
    # generalisation to behaviour no fitted component has seen.
    'composite.paced_breadth_sweep': composite.paced_breadth_sweep,
    'composite.credential_spray': composite.credential_spray,
    'composite.decoy_then_enumerate': composite.decoy_then_enumerate,
    'composite.backup_client': composite.backup_client,
    'composite.content_crawler': composite.content_crawler,
    'composite.batch_api_client': composite.batch_api_client,
    # P15.4: authentication with an *outcome*. Paired benign and malicious
    # families per site profile, so the difference under test is what the server
    # answered rather than whether a credential was carried (§15, §16, §43, §44).
    'profiles.authenticated_batch': profiles.authenticated_batch,
    'profiles.high_rate_api': profiles.high_rate_api,
    'profiles.service_account': profiles.service_account,
    'profiles.stale_credential_client': profiles.stale_credential_client,
    'profiles.admin_login_mistakes': profiles.admin_login_mistakes,
    'profiles.admin_console': profiles.admin_console,
    'profiles.asset_fetch': profiles.asset_fetch,
    'profiles.signed_webhook': profiles.signed_webhook,
    'profiles.api_credential_spray': profiles.api_credential_spray,
    'profiles.admin_brute_force': profiles.admin_brute_force,
    'profiles.login_stuffing': profiles.login_stuffing,
    'profiles.patient_account_walk': profiles.patient_account_walk,
    # §49, §50. Withheld from every fitting corpus and scored once at the end.
    # The prefix is load-bearing: `tests/test_p15_4_withheld.py` refuses any
    # development or calibration matrix that contains one.
    'withheld.mobile_app_sync': withheld.mobile_app_sync,
    'withheld.probe_then_login': withheld.probe_then_login,
    # P15.5's pair. The P15.4 pair above has been scored once and is no longer
    # unseen; it stays withheld from fitting all the same, because "scored once"
    # and "safe to fit to" are different states.
    'withheld.backup_window_sweep': withheld.backup_window_sweep,
    'withheld.credential_drift': withheld.credential_drift,
}
#: Raised from 32 in P15.1. The false-block rate is measured per *source*, and
#: at 32 runs per scenario the whole matrix could not produce the 500 distinct
#: benign sources the release gate asks for — so the gate could never be
#: evaluated, which is a worse failure than a low number. Still a hard cap: a
#: matrix is a deliberate representative set, and a combinatorial sweep of one
#: generator is not more evidence, it is the same evidence repeated.
MAX_RUNS_PER_SCENARIO = 64


def load(path=MATRIX_V1):
    matrix = tomllib.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(matrix.get('scenario'), list) or not matrix['scenario']:
        raise ValueError('scenario matrix is empty')
    if 'seed_salt' in matrix and not isinstance(matrix['seed_salt'], str):
        raise ValueError('seed_salt must be a string')
    seen = set()
    for entry in matrix['scenario']:
        if set(entry) - {'id', 'group', 'generator', 'runs', 'params', 'snaplen',
                         'site_group', 'profile_type'}:
            raise ValueError('unknown scenario matrix field')
        # §41. Declared per scenario, because a site is a property of the traffic
        # rather than of the generator: the same crawler behaviour belongs to a
        # public website in one row and to an API in another.
        if entry.get('profile_type') and entry['profile_type'] not in PROFILE_TYPES:
            raise ValueError('unknown profile_type: ' + str(entry['profile_type']))
        if entry['generator'] not in REGISTRY:
            raise ValueError('unknown generator: ' + entry['generator'])
        if entry['id'] in seen:
            raise ValueError('duplicate scenario id: ' + entry['id'])
        if not 1 <= entry['runs'] <= MAX_RUNS_PER_SCENARIO:
            raise ValueError('scenario run count out of bounds')
        seen.add(entry['id'])
    return matrix


def source_pool(seed='dataset-v1:sources'):
    """One distinct documentation address per run, shuffled so no range maps to a label.

    All three RFC 5737 documentation ranges, 762 addresses. The third was added
    in P15.1 for the same reason the run cap moved: measuring a false-block rate
    per source needs more distinct sources than two /24s can supply once both
    classes have to come out of the same pool.

    Shuffling is the load-bearing part and predates that change. If one range
    held the benign runs and another the malicious ones, the address itself
    would carry the label, and a model could learn the corpus instead of the
    behaviour.
    """
    pool = ([f'192.0.2.{octet}' for octet in range(1, 255)]
            + [f'198.51.100.{octet}' for octet in range(1, 255)]
            + [f'203.0.113.{octet}' for octet in range(1, 255)])
    random.Random(seed).shuffle(pool)
    return pool


def plans(matrix=None, *, salt=''):
    """Deterministic (scenario, run) -> Plan. The seed is stored with every sample.

    `salt` (P15.2) makes the same matrix produce an **independent** corpus: it
    enters every scenario seed and the address shuffle, so two salts give
    different random draws of the same behaviours over different sources.

    This exists because one corpus cannot be both a development set and a locked
    test set. P15 and P15.1 both measured on `dataset-eval-v1`, so it has been
    inspected and is a development set now, whatever it is called. A final test
    has to be data no decision was tuned against, and generating it from a fresh
    salt is cheaper and cleaner than carving a smaller holdout out of a corpus
    that has already been looked at.

    The empty default reproduces every dataset built before P15.2 byte for byte.
    An empty salt must therefore never change the seeds, which is why it is
    concatenated rather than always mixed in.
    """
    matrix = matrix or load()
    salt = str(salt or matrix.get('seed_salt') or '')
    suffix = f':{salt}' if salt else ''
    pool = source_pool(f'dataset-v1:sources{suffix}')
    index = 0
    for entry in matrix['scenario']:
        builder = REGISTRY[entry['generator']]
        for run in range(entry['runs']):
            seed = f"{entry['id']}:{run}{suffix}"
            plan = builder(entry['id'], entry['group'], seed, **entry.get('params', {}))
            if index >= len(pool):
                raise ValueError('scenario matrix exceeds the documentation address pool')
            plan.source = str(validate_synthetic_address(pool[index]))
            index += 1
            # §41. Stamped from the matrix rather than invented by the
            # generator, so one behaviour can belong to different sites in
            # different rows and the site is always something a person wrote
            # down. Never a feature — see `dataset.schema.NEVER_MODEL_INPUT`.
            plan.site_group = str(entry.get('site_group') or '')
            plan.profile_type = str(entry.get('profile_type') or '')
            plan.parameters = dict(plan.parameters, generator=entry['generator'], run=run,
                                   matrix_version=matrix['matrix_version'],
                                   snaplen=entry.get('snaplen'),
                                   site_group=plan.site_group or None,
                                   profile_type=plan.profile_type or None)
            # Recorded only when it is doing something. An unconditional
            # `seed_salt: ''` would change the provenance of every row ever
            # written and break the byte-reproducibility `research-v2` depends on.
            if salt:
                plan.parameters['seed_salt'] = salt
            yield plan


def coverage(matrix=None):
    matrix = matrix or load()
    return [{'scenario': entry['id'], 'group': entry['group'], 'generator': entry['generator'],
             'runs': entry['runs'], 'params': entry.get('params', {})} for entry in matrix['scenario']]
