"""Equivalent file-by-file diff against the pre-P5 snapshot when Git is absent."""
import difflib
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    baseline = json.loads(Path('.p5-check/baseline.json').read_text(encoding='utf-8'))
    exclusions = ['.git/**', '.venv/**', '.p1-check-venv/**', '.uv-cache/**', '.p3-check/**',
        '.p4-check/**', '.p5-check/**', '.ruff_cache/**', '.pytest_cache/**', '**/__pycache__/**',
        '*.egg-info/**', 'build/**', 'dist/**', 'docs/P5_DIFF_STAT.md', 'benchmarks/results/p5/change-manifest.json']
    argv = ['rg', '--files', '--hidden']
    for pattern in exclusions:
        argv += ['-g', '!'+pattern]
    current = {Path(name).as_posix() for name in subprocess.check_output(argv, text=True).splitlines()}
    rows = []
    for name in sorted(current | set(baseline)):
        path = Path(name)
        previous = baseline.get(name)
        raw = path.read_bytes() if path.exists() else b''
        digest = hashlib.sha256(raw).hexdigest() if path.exists() else None
        if previous and digest == previous['sha256']:
            continue
        before = (previous.get('text') or '').splitlines() if previous else []
        after = raw.decode('utf-8', errors='replace').splitlines()
        additions = deletions = 0
        for operation, i, j, a, b in difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes():
            if operation in ('replace', 'insert'):
                additions += b-a
            if operation in ('replace', 'delete'):
                deletions += j-i
        rows.append({'path': name, 'status': 'modified' if previous and path.exists() else 'added' if path.exists() else 'deleted',
            'insertions': additions, 'deletions': deletions, 'sha256_before': previous['sha256'] if previous else None,
            'sha256_after': digest})
    summary = {'changed_files': len(rows), 'insertions': sum(r['insertions'] for r in rows),
               'deletions': sum(r['deletions'] for r in rows)}
    lines = ['# P5 file-by-file diff', '',
        'git diff --stat was executed and returned: warning: Not a git repository.',
        'Equivalent text comparison against the saved pre-P5 snapshot follows; this is not Git output.',
        'Caches/venvs/local scratch/build output and this generated inventory pair are excluded.',
        'Reproduce with python -m benchmarks.inventory while .p5-check/baseline.json is available.',
        '', f"{summary['changed_files']} files changed, {summary['insertions']} insertions(+), {summary['deletions']} deletions(-).",
        '', '| File | Status | + | - |', '|---|---|---:|---:|']
    for row in rows:
        lines.append(f"| [{row['path']}](../{row['path']}) | {row['status']} | {row['insertions']} | {row['deletions']} |")
    Path('docs/P5_DIFF_STAT.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    Path('benchmarks/results/p5/change-manifest.json').write_text(json.dumps({'summary': summary, 'files': rows}, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(summary))
    print(json.dumps([r['path'] for r in rows if r['status'] == 'modified']))


if __name__ == '__main__':
    main()
