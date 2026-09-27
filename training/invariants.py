"""The safety numbers P15.4 may not move, recorded from the code in force. §1.

Every cycle so far has been asked not to weaken a gate to obtain a pass, and
every cycle has kept that promise by intention. Intention does not survive a
refactor. This module reads the constants that are actually loaded, hashes them,
and writes `reports/P15_4_BASELINE.json` — so "nothing was weakened" becomes a
digest comparison rather than a claim, and `tests/test_p15_4_invariants.py`
fails the build the moment one of them moves.

What is recorded, and why each one is here:

* **cost profiles** — a false block is priced at 40× a false allow on a public
  website, and the cutoff follows from that. Lowering either number lowers the
  cutoff without appearing to touch a threshold (§61, §62).
* **decision gates** — observations, observation time, data quality, signal and
  behavioural diversity, uncertainty. §68 and the brief's opening list forbid
  reducing any of them, and the diversity requirement is called out twice.
* **block TTL ladder and ceiling** — 12 hours maximum, temporary only (§79).
* **mass-block breaker limits** — the circuit breaker that stops a bad decision
  becoming a bad outage (§79).
* **PolicyGuard protections** — management networks, proxies, CDN, and the
  profiles that may never network-block at all.

A value may still change during P15.4 if the owner decides it should. What it
may not do is change *quietly*, or as a side effect of making a result look
better. The digest is what makes the difference visible.
"""
import hashlib
import json
from pathlib import Path

from eye_for_an_eye.autonomy.authority import (AUTHORITY_VERSION, DecisionGates,
                                               MAX_BLOCK_TTL_SECONDS)
from eye_for_an_eye.autonomy.breakers import BudgetLimits
from eye_for_an_eye.autonomy.cost import COST_POLICY_VERSION, CostPolicy
from eye_for_an_eye.autonomy.evaluation import ReleaseThresholds
from eye_for_an_eye.config import Config
from eye_for_an_eye.security.enforcement import MAX_TTL_SECONDS

BASELINE_SCHEMA_VERSION = 1


def document():
    gates = DecisionGates()
    policy = CostPolicy()
    limits = BudgetLimits()
    enforcement = Config().enforcement
    body = {
        'baseline_schema_version': BASELINE_SCHEMA_VERSION,
        'purpose': ('the values P15.4 may not move. Recorded from the constants '
                    'in force, not transcribed, so the record and the running '
                    'system cannot disagree without the digest changing'),
        'cost_policy': {
            'version': COST_POLICY_VERSION,
            'digest': policy.digest,
            'decision_margin': policy.decision_margin,
            'release_margin': policy.release_margin,
            'profiles': {name: {'false_block': profile.false_block,
                                'false_allow': profile.false_allow,
                                'challenge': profile.challenge,
                                'rate_limit': profile.rate_limit,
                                'threshold': round(profile.threshold, 6),
                                'network_block_permitted': profile.network_block_permitted}
                         for name, profile in sorted(policy.profiles.items())},
        },
        'decision_gates': gates.explain(),
        'authority_version': AUTHORITY_VERSION,
        'block_ttl': {
            'ladder_seconds': list(gates.block_ttl_ladder),
            'maximum_block_ttl_seconds': MAX_BLOCK_TTL_SECONDS,
            'enforcement_ceiling_seconds': MAX_TTL_SECONDS,
            'permanent_block_possible': False,
        },
        'block_budget_and_mass_block_breaker': limits.explain(),
        'policy_guard': {
            'management_networks': list(enforcement.management_networks),
            'allowlist': list(enforcement.allowlist),
            'trusted_proxies': list(enforcement.trusted_proxies),
            'protected_unconditionally': ['loopback', 'unspecified', 'multicast',
                                          'link_local', 'local_addresses'],
            'profiles_never_network_blocked': sorted(
                name for name, profile in policy.profiles.items()
                if not profile.network_block_permitted),
        },
        'release_thresholds': ReleaseThresholds().explain(),
    }
    body['digest'] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body


def write(path):
    Path(path).write_text(json.dumps(document(), indent=1) + '\n', encoding='utf-8')
    return path
