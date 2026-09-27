"""Human-owned release gates. Missing evidence is failure, never fabricated success."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib
from build_release import runtime_source_hash

ROOT = Path(__file__).resolve().parents[1]


def check(artifacts):
    failures = []
    metadata = tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))['project']
    version = metadata['version']
    initializer = (ROOT/'eye_for_an_eye/__init__.py').read_text(encoding='utf-8')
    if repr(version) not in initializer and '"'+version+'"' not in initializer:
        failures.append('application/package version mismatch')
    if version not in (ROOT/'CHANGELOG.md').read_text(encoding='utf-8'):
        failures.append('current version absent from CHANGELOG')
    locked = tomllib.loads((ROOT/'uv.lock').read_text(encoding='utf-8'))
    if not any(p['name'] == metadata['name'] and p['version'] == version for p in locked['package']):
        failures.append('lockfile version mismatch')
    if not (ROOT/'.git').exists():
        failures.append('RELEASE BLOCKER: Git revision and clean working tree cannot be verified in this source snapshot')
    else:
        state = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True, timeout=10)
        if state.returncode or state.stdout.strip():
            failures.append('RELEASE BLOCKER: working tree is not clean or cannot be checked')
    if not (ROOT/'LICENSE').is_file() or not metadata.get('license'):
        failures.append('RELEASE BLOCKER: maintainer-approved LICENSE and SPDX metadata missing')
    # Both markers, because P15.1 changed the wording. SECURITY.md now documents a
    # real workflow -- GitHub Private Vulnerability Reporting -- that cannot be
    # used until the repository exists, and says so with OWNER_ACTION_REQUIRED. A
    # check looking only for the old phrase would have started passing the moment
    # the wording improved, while the channel was still unavailable.
    security = (ROOT/'SECURITY.md').read_text(encoding='utf-8')
    if 'RELEASE BLOCKER' in security or 'OWNER_ACTION_REQUIRED' in security:
        failures.append('RELEASE BLOCKER: private security reporting channel unconfirmed')
    # The validation record is a local, human-owned file: it is written by
    # whoever ran the gates, on the machine they ran them on, and it is not
    # published (see docs/RELEASE_CONTENTS.md). So the public release root does
    # not contain one, and an unguarded read here raised FileNotFoundError
    # rather than reporting a failure -- in a module whose first line is
    # "Missing evidence is failure, never fabricated success". Every other
    # missing thing in this function appends to `failures`; this one threw.
    # Absent evidence is now the blocker it always should have been, which is
    # also the correct answer for a reader who has just cloned the repository
    # and has run no gates at all.
    record = ROOT/'release/validation.json'
    try:
        evidence = json.loads(record.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        failures.append('RELEASE BLOCKER: no readable release validation record at '
                        'release/validation.json; run the gates and write one')
        evidence = None
    if evidence is not None:
        if evidence.get('version') != version:
            failures.append('release evidence version mismatch')
        for name, state in evidence.get('required_gates', {}).items():
            if state != 'passed':
                failures.append('RELEASE BLOCKER: '+name+' = '+state)
    required_artifacts = {'sbom.cdx.json', 'build-evidence.json',
                          'eye_for_an_eye-'+version+'-py3-none-any.whl', 'eye_for_an_eye-'+version+'.tar.gz'}
    for name in required_artifacts | {'SHA256SUMS'}:
        if not (artifacts/name).is_file():
            failures.append('artifact missing: '+name)
    if (artifacts/'SHA256SUMS').is_file():
        covered = set()
        for line in (artifacts/'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            covered.add(name)
            if Path(name).name != name or not (artifacts/name).is_file():
                failures.append('unsafe or missing checksum entry')
                continue
            with (artifacts/name).open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                    failures.append('checksum mismatch: '+name)
        if not required_artifacts <= covered:
            failures.append('checksum manifest is incomplete')
    if (artifacts/'build-evidence.json').is_file():
        build = json.loads((artifacts/'build-evidence.json').read_text())
        if not build.get('two_builds_identical') or build.get('runtime_source_sha256') != runtime_source_hash():
            failures.append('build reproducibility/source evidence missing or stale')
    return {'schema_version': 1, 'release_ready': not failures, 'failures': failures, 'published': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    result = check(parser.parse_args().artifacts)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['release_ready'] else 1)
