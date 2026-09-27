"""Every version the release rests on, read from the code in force. P15.5 §1.

P15.4's locked benchmark failed on one integer comparison between two components
that were each individually correct. The lesson the P15.5 brief draws from it is
that component correctness is not system correctness, and the lesson this module
draws is narrower and more mechanical: **a version that nothing records is a
version nobody can check.**

So this is the second baseline of the P15 series and it does a different job from
the first. `training/invariants.py` records the *values a cycle may not move* —
cost profiles, decision gates, the TTL ceiling, the breaker limits — and fails
the build when one of them shifts. This module records the *identities of the
parts*: which formula, which schema, which calibrator artifact, which policy. One
answers "has anything been weakened"; the other answers "what exactly is being
frozen", which is the question a release has to answer and P15.4 could not.

Everything here is imported from the running code or hashed from the artifact on
disk. Nothing is transcribed, because a transcribed version number is a comment
that happens to look like evidence.

### Why the calibrator artifacts are hashed rather than named

`mathrisk-cal-v4-isotonic.json` names itself in its own `version` field, and that
field is written by the fitter. A digest over the file's bytes is the only record
that survives somebody refitting the artifact without renaming it — which is not
a hypothetical, because refitting on more calibration data is exactly what §11
through §14 of this cycle ask for. The digest recorded before the refit and the
digest recorded after it are what make that change visible in the freeze commit.

### What the `runtime_integration` section is for

§5 asks for a whole-system smoke test through the real production path, and §10
asks which configured components can be silently absent. Both questions need an
answer to a prior one: which modules does the shipped runtime actually assemble?
That is a fact about the code, so it is measured here by walking the import and
call graph rather than asserted in prose — and it is recorded in the baseline
because if it changes during the cycle, the freeze commit has to show it.
"""
import ast
import hashlib
import json
from pathlib import Path

from eye_for_an_eye.autonomy.authority import (AUTHORITY_VERSION, DecisionGates,
                                               MAX_BLOCK_TTL_SECONDS)
from eye_for_an_eye.autonomy.cost import COST_POLICY_VERSION, CostPolicy
from eye_for_an_eye.autonomy.maturity import MATURITY_SCHEMA_VERSION, MaturityPolicy
from eye_for_an_eye.correlation.auth_state import AUTH_STATE_SCHEMA_VERSION
from eye_for_an_eye.decision.auth import AUTH_SCHEMA_VERSION
from eye_for_an_eye.decision.calibration import CALIBRATION_SCHEMA_VERSION, UNITS
from eye_for_an_eye.decision.composition import COMPOSITION_VERSION, INTERACTIONS
from eye_for_an_eye.decision.families import (CARRYING_FAMILIES, CORROBORATING_ONLY,
                                              FAMILY_SCORE_VERSION)
from eye_for_an_eye.decision.features import (CLASSIFIER_SCHEMA_VERSION, MODEL_SCHEMAS,
                                              NAMES, SCHEMA_VERSION)
from eye_for_an_eye.decision.math_risk import VERSION as MATH_RISK_VERSION
from eye_for_an_eye.decision.policy import POLICY_GUARD_VERSION
from eye_for_an_eye.decision.scores import SCORE_CONTRACT_VERSION
from eye_for_an_eye.events import SCHEMA_VERSION as EVENT_SCHEMA_VERSION
# `security.enforcement` is the request *value* and imports nothing that can
# write a rule. `security.host_firewall` does, and P15 invariant 1 forbids any
# module under `training/` from importing it — so the host firewall's schema
# version is deliberately absent from this record rather than reached for
# through an indirection that would satisfy the letter of the invariant and
# not its point. `tests/test_p15_invariants.py` is what enforces that.
from eye_for_an_eye.security.enforcement import ENFORCEMENT_REQUEST_VERSION, MAX_TTL_SECONDS
from eye_for_an_eye.sites.profile import SITE_PROFILE_SCHEMA_VERSION

P15_5_BASELINE_SCHEMA_VERSION = 1

ROOT = Path(__file__).resolve().parents[1]

#: The calibrator artifacts a release could be asked to load. Hashed, not named:
#: a refit that keeps the filename is exactly the change a digest catches.
CALIBRATOR_ARTIFACTS = (
    'models/mathrisk-cal-v4-isotonic.json',
    'models/mathrisk-cal-v4-sigmoid.json',
    'models/classifier-cal-v1-isotonic.json',
    'models/classifier-cal-v1-sigmoid.json',
)

#: The model artifacts whose bytes decide what the auxiliary classifier computes.
MODEL_ARTIFACTS = (
    'models/risk-logreg-v1.onnx',
    'models/risk-logreg-v1.json',
    'models/isolation-v1.onnx',
    'models/isolation-v1.json',
    'models/risk-logreg-v1-distribution.json',
)

#: The components the P15 autonomous decision is composed of, and the module that
#: would have to construct each one for a running sensor to use it. `reachable`
#: below answers whether anything in the shipped package does.
AUTONOMOUS_STACK = {
    'AutonomousDecisionAuthority': 'eye_for_an_eye/autonomy/authority.py',
    'DecisionInputs': 'eye_for_an_eye/autonomy/authority.py',
    'MaturityPolicy': 'eye_for_an_eye/autonomy/maturity.py',
    'CostPolicy': 'eye_for_an_eye/autonomy/cost.py',
    'HostEnforcer': 'eye_for_an_eye/security/host_enforcer.py',
    'EnforcementRequest': 'eye_for_an_eye/security/enforcement.py',
}


def _digest_file(relative):
    path = ROOT / relative
    if not path.is_file():
        return {'path': relative, 'present': False}
    body = path.read_bytes()
    return {'path': relative, 'present': True, 'bytes': len(body),
            'sha256': hashlib.sha256(body).hexdigest()}


def _constructed_in(package):
    """Every name constructed or called anywhere under `package`, with the file.

    A call graph built from the AST rather than from imports, because an import
    proves a module was read and a call proves it was used. The P15.4 defect and
    the question §5 asks are both about the second.
    """
    found = {}
    for path in sorted((ROOT / package).rglob('*.py')):
        if '__pycache__' in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except SyntaxError:
            continue
        relative = path.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else None)
            if name:
                found.setdefault(name, set()).add(relative)
    return {name: sorted(paths) for name, paths in found.items()}


def runtime_integration():
    """Which parts of the autonomous stack the shipped package assembles.

    `defining_module_only` is the finding this exists to record: a component
    whose only constructor in `eye_for_an_eye/` is the module that defines it is
    a component the running sensor never builds, however well it is unit tested.
    """
    calls = _constructed_in('eye_for_an_eye')
    report = {}
    for name, home in AUTONOMOUS_STACK.items():
        sites = [p for p in calls.get(name, ()) if p != home]
        report[name] = {
            'constructed_in_package': sorted(calls.get(name, ())),
            'constructed_outside_defining_module': sites,
            'defining_module_only': not sites,
        }
    return {
        'question': ('which components of the P15 autonomous decision does the '
                     'shipped package assemble, as opposed to define and test'),
        'method': ('AST call graph over eye_for_an_eye/. A construction site '
                   'outside the defining module is what makes a component '
                   'reachable from a running sensor'),
        'components': report,
        'decision_engine_imports_autonomy': 'autonomy' in (
            ROOT / 'eye_for_an_eye' / 'decision' / 'engine.py').read_text(encoding='utf-8'),
    }


def _digest_mapping(mapping):
    return hashlib.sha256(
        json.dumps(mapping, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def _diversity_policy(gates):
    """The evidence-diversity requirement, isolated from the rest of the gates.

    §21 asks for a hash of this policy specifically, and it is worth separating:
    the P15.4 brief forbade reducing the diversity requirement twice over, so the
    number a reviewer wants to check has its own digest rather than being one
    field inside a larger one that moves for unrelated reasons.
    """
    explained = gates.explain()
    return {'minimum_signal_diversity': explained.get('minimum_signal_diversity'),
            'minimum_behavioural_diversity': explained.get('minimum_behavioural_diversity'),
            'carrying_families': sorted(CARRYING_FAMILIES),
            'corroborating_families': sorted(CORROBORATING_ONLY),
            # Name and strength only. The justification string beside each
            # interaction is documentation, and a reworded sentence must not read
            # as a changed policy.
            'interactions': sorted((a, b, round(k, 6)) for a, b, k, _ in INTERACTIONS)}


def document():
    policy = CostPolicy()
    maturity = MaturityPolicy()
    gates = DecisionGates()
    body = {
        'p15_5_baseline_schema_version': P15_5_BASELINE_SCHEMA_VERSION,
        'purpose': ('the identity of every part the P15.5 release candidate is '
                    'composed of, read from the code and hashed from the '
                    'artifacts rather than transcribed'),
        'relationship_to_p15_4_baseline': (
            'reports/P15_4_BASELINE.json records the values that may not move '
            'and is still enforced by tests/test_p15_4_invariants.py. This file '
            'records which parts are being frozen, which is a different question'),
        'formula_versions': {
            'math_risk': MATH_RISK_VERSION,
            'family_scores': FAMILY_SCORE_VERSION,
            'evidence_composition': COMPOSITION_VERSION,
            'authority': AUTHORITY_VERSION,
            'policy_guard': POLICY_GUARD_VERSION,
            'cost_policy': COST_POLICY_VERSION,
        },
        'schema_versions': {
            'feature_schema': SCHEMA_VERSION,
            'feature_schemas_servable': sorted(MODEL_SCHEMAS),
            'classifier_schema': CLASSIFIER_SCHEMA_VERSION,
            'feature_count': len(NAMES),
            'tensor_columns': 2 * len(NAMES),
            'auth_event_schema': AUTH_SCHEMA_VERSION,
            'auth_state_schema': AUTH_STATE_SCHEMA_VERSION,
            'maturity_schema': MATURITY_SCHEMA_VERSION,
            'calibration_schema': CALIBRATION_SCHEMA_VERSION,
            'calibration_units': list(UNITS),
            'score_contract': SCORE_CONTRACT_VERSION,
            'event_schema': EVENT_SCHEMA_VERSION,
            'site_profile_schema': SITE_PROFILE_SCHEMA_VERSION,
            'enforcement_request': ENFORCEMENT_REQUEST_VERSION,
            'host_firewall_schema': 'not recorded here; see invariant 1 above',
        },
        'policy_digests': {
            'cost_policy': policy.digest,
            # `MaturityPolicy` and `DecisionGates` are frozen dataclasses with no
            # digest of their own, so the hash is taken over the same `explain()`
            # a record carries. That is deliberate: it hashes what an operator can
            # actually read back, not a private field they cannot.
            'maturity_policy': _digest_mapping(maturity.explain()),
            'evidence_diversity_policy': _digest_mapping(_diversity_policy(gates)),
            'decision_gates': _digest_mapping(gates.explain()),
        },
        'ttl_ceilings': {
            'maximum_block_ttl_seconds': MAX_BLOCK_TTL_SECONDS,
            'enforcement_ceiling_seconds': MAX_TTL_SECONDS,
        },
        'artifacts': {
            'calibrators': [_digest_file(p) for p in CALIBRATOR_ARTIFACTS],
            'models': [_digest_file(p) for p in MODEL_ARTIFACTS],
        },
        'runtime_integration': runtime_integration(),
    }
    body['digest'] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body


def write(path):
    Path(path).write_text(json.dumps(document(), indent=1) + '\n', encoding='utf-8')
    return path


if __name__ == '__main__':
    print(write(ROOT / 'reports' / 'P15_5_BASELINE.json'))
