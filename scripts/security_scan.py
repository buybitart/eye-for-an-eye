"""Review-aware Bandit gate and bounded source secret-pattern scanning. No network."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def bandit_gate():
    with tempfile.TemporaryDirectory(prefix='e4e-bandit-') as directory:
        report = Path(directory)/'report.json'
        result = subprocess.run([sys.executable, '-m', 'bandit', '-r', 'eye_for_an_eye', '-ll', '-f', 'json', '-o', str(report)],
            cwd=ROOT, capture_output=True, text=True, timeout=60)
        if result.returncode not in (0, 1) or not report.is_file():
            raise RuntimeError(result.stderr)
        findings = json.loads(report.read_text())['results']
    reviewed = json.loads((ROOT/'security/bandit-reviewed.json').read_text())
    # Match on identity alone so that an entry can also carry the review itself.
    # Previously the whole record had to compare equal, which left no room for a
    # `reason` field -- a register of accepted security findings that cannot say
    # why any of them was accepted. An entry without a reason does not count as
    # reviewed, so a finding cannot be silenced by adding a hash and nothing else.
    accepted = {(entry['test_id'], entry['file'], entry['code_sha256'])
                for entry in reviewed if str(entry.get('reason', '')).strip()}
    unknown = []
    for item in findings:
        identity = (item['test_id'], item['filename'].replace('\\', '/'),
                    hashlib.sha256(item['code'].encode()).hexdigest())
        if identity not in accepted:
            unknown.append({'file': identity[1], 'line': item['line_number'], 'test_id': item['test_id']})
    return unknown, len(findings)


def secrets_gate():
    # Narrow high-confidence patterns; no claim of comprehensive entropy/history scanning.
    patterns = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
                r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}\b', r'\bAKIA[0-9A-Z]{16}\b',
                r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b',
                r'(?im)^\s*(?:password|api_key|access_token|secret)\s*=\s*["\'][^"\']{16,}["\']']
    roots = ('eye_for_an_eye', 'dataset', 'deploy', 'docs', 'scripts', 'security', 'training',
             'tests', 'benchmarks', '.github', 'requirements')
    files = [p for name in roots for p in (ROOT/name).rglob('*') if p.is_file() and p.suffix in ('.py', '.toml', '.md', '.yml', '.txt')]
    files += list(ROOT.glob('*.toml')) + list(ROOT.glob('*.md'))
    findings = []
    for path in files:
        text = path.read_text(encoding='utf-8')
        if any(re.search(pattern, text) for pattern in patterns):
            findings.append(str(path.relative_to(ROOT)))
    # Secrets do not belong in the source tree even if their contents are random.
    for name in ('eye_for_an_eye', 'dataset', 'deploy', 'tests', 'training', 'datasets'):
        directory = ROOT/name
        if directory.is_dir():
            for pattern in ('*.secret', '*.dataset-secret', '*.pem', '*.key', 'id_rsa', 'id_ed25519', '.env'):
                findings += [str(p.relative_to(ROOT)) for p in directory.rglob(pattern)]
    for pattern in ('*.secret', '*.dataset-secret', '*.pem', '*.key', '.env'):
        findings += [str(p.relative_to(ROOT)) for p in ROOT.glob(pattern)]
    return sorted(set(findings))


#: The same patterns `secrets_gate()` applies, hoisted so the history scan cannot
#: drift from the working-tree scan. Two lists of one thing is how a scan comes to
#: pass on the tree and miss the history.
SECRET_PATTERNS = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
                   r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}\b', r'\bAKIA[0-9A-Z]{16}\b',
                   r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b',
                   r'(?im)^\s*(?:password|api_key|access_token|secret)\s*=\s*["\'][^"\']{16,}["\']']

#: A blob larger than this is not read. A key is small; a model is not.
MAX_BLOB_BYTES = 1_048_576


def history_gate(root=None):
    """Scan every blob in every commit of the repository, if there is one. P18 §135.

    This exists because the `scope` field below used to be the fixed string *"no
    Git history available or scanned"*. That was honest about what it did not do,
    and it was also a hard-coded sentence in place of a measurement: a run against
    a repository with history printed exactly the same words as a run against a
    bare directory. §135 asks for the history that will actually be published to
    be scanned, and for a fresh public history built from the release root that is
    a cheap thing to do properly.

    Returns (scope, findings). `scope` says what was really examined.
    """
    root = Path(root or ROOT)
    if not (root/'.git').exists():
        return 'working source only; this directory is not a Git repository', []

    def git(*arguments, binary=False):
        return subprocess.run(['git', '-C', str(root), *arguments], check=True,
                              capture_output=True, timeout=900,
                              **({} if binary else {'text': True}))
    try:
        commits = git('rev-list', '--all').stdout.split()
        listing = git('cat-file', '--batch-all-objects', '--batch-check').stdout.splitlines()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as problem:
        return f'working source only; Git history unreadable ({type(problem).__name__})', []
    blobs = []
    for line in listing:
        fields = line.split()
        if len(fields) == 3 and fields[1] == 'blob' and int(fields[2]) <= MAX_BLOB_BYTES:
            blobs.append(fields[0])
    findings = []
    for digest in blobs:
        try:
            body = git('cat-file', 'blob', digest, binary=True).stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
        try:
            text = body.decode('utf-8')
        except UnicodeDecodeError:
            continue
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, text):
                findings.append({'blob': digest, 'pattern': pattern[:40]})
                break
    return (f'working source and the full Git history of this repository: '
            f'{len(commits)} commit(s), {len(blobs)} blob(s) of at most '
            f'{MAX_BLOB_BYTES} bytes read'), findings


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--skip-history', action='store_true',
                        help='scan the working source only, and say so')
    arguments = parser.parse_args()
    unknown, reviewed_count = bandit_gate()
    secrets = secrets_gate()
    if arguments.skip_history:
        scope, history = 'working source only; --skip-history was given', []
    else:
        scope, history = history_gate()
    print(json.dumps({'unreviewed_bandit': unknown, 'reviewed_bandit_count': reviewed_count,
                      'secret_pattern_files': secrets, 'history_secret_blobs': history,
                      'scope': scope}))
    raise SystemExit(bool(unknown or secrets or history))
