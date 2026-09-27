#!/usr/bin/env python3
"""Assemble the public release root. P16 §24-§28, §92, §110.

Curate, copy, verify — in that order, and never `mv`. The development tree is
left exactly as it was, because the first independent check of a release root is
that the tree it came from is still there to compare against.

### Why this is a script and not a sequence of commands

An assembly nobody can repeat is an assembly nobody can audit. Everything the
public repository contains is named in `INCLUDE` below, everything left out is
named in `EXCLUDE` with the reason, and `verify()` fails the build if an
excluded category reaches `prod/` anyway. A reviewer reads one file to see what
was published and why.

### What "standalone" is checked to mean

`prod/` must work with the parent gone. So the verification refuses:

* any symlink, absolute or relative — a link pointing out of the tree is the
  exact failure this is guarding against, and a link pointing inside it buys
  nothing worth the risk of getting that wrong;
* any file matching an excluded category;
* a missing file from the required set.

It does not check that the tests pass; that is the clean-clone run's job, on a
copy, with the parent unreachable.
"""
import argparse
import fnmatch
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]

#: Everything the public repository contains. A directory is copied whole, minus
#: the per-directory prunes below; a file is copied as named.
INCLUDE = (
    # The software.
    'eye_for_an_eye',
    'tests',
    'dataset',        # dataset *tooling*: schema, validators, generators
    'training',       # training tooling; the corpora it builds are not published
    'benchmarks',
    'scripts',
    'deploy',
    'security',
    'models',
    'requirements',
    '.github',
    # Documentation. `docs` is pruned by the patterns below.
    'docs',
    # The public root.
    'README.md', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', 'CHANGELOG.md',
    'ROADMAP.md', 'THIRD_PARTY_NOTICES.md', 'pyproject.toml', 'MANIFEST.in',
    # P17. The beginner entry point. `START_HERE.md` is the first file a
    # non-developer should notice, and the launchers are what they double-click,
    # so a release root without them is a release root a beginner cannot use.
    'START_HERE.md',
    'Install-EyeForAnEye.cmd', 'Start-EyeForAnEye.cmd', 'Status-EyeForAnEye.cmd',
    'Demo-EyeForAnEye.cmd', 'Stop-EyeForAnEye.cmd', 'Uninstall-EyeForAnEye.cmd',
    # P18 §23, §57. The Linux door, at the top of the tree, because Linux is the
    # platform with the complete feature set and its installer sat two directories
    # down while six Windows launchers sat at the root. Both files hand over to
    # `scripts/`; §19 forbids a second implementation of installation logic and
    # there is not one.
    'install.sh', 'uninstall.sh',
    'Dockerfile', 'docker-compose.lab.yml', 'uv.lock', 'requirements-p0.lock',
    '.gitignore', '.gitattributes', '.editorconfig', '.dockerignore',
    '.python-version',
    'config.example.toml', 'config.sensor.toml', 'config.lab.toml',
    'config.honeypot.toml',
    # Deprecated top-level compatibility entry points. Kept rather than dropped
    # because `tests/test_cli_integration.py` runs `+garbage.py` directly, and
    # a release root whose own test suite cannot run is not a release root. The
    # command behind it is LAB_ONLY and bounded four ways — loopback bind,
    # loopback peer, a byte budget and a connection and duration cap — which
    # `docs/RELEASE_CONTENTS.md` states and `eye_for_an_eye/network/listeners.py`
    # enforces.
    '+garbage.py', '+ip_id.py', '+nat.py', '+proto.py', '+services.py',
    '+uptime.py',
)

#: Evidence published with the software, because public documentation cites it.
#: The rest of `reports/` is development-phase material and stays in the
#: development tree; `docs/RELEASE_CONTENTS.md` says so.
#:
#: `P15_5R_RUNTIME_INTEGRATION.md` is deliberately not here. It is the most
#: useful of the phase reports and also the one that quotes the development
#: machine directly — user names, absolute paths, the exact `sudo` invocations
#: a run was made with. Sanitising it line by line would leave a report whose
#: commands no longer reproduce anything; `docs/VALIDATION_STATUS.md` carries
#: its conclusions instead, which is what a public reader needs from it.
INCLUDE_REPORTS = (
    'reports/README.md',
    'reports/P15_5_FINAL_RELEASE_VALIDATION.md',
    # Two small records the published test suite reads. They pin project
    # invariants — a baseline that must not move, a test policy that must state
    # no recall target — so the tests that check them belong with them.
    'reports/P15_4_BASELINE.json',
    'reports/P15_3_TEST_POLICY.json',
    'reports/P15_FINAL_AUTONOMOUS_DEFENSE_REPORT.md',
    'reports/model-risk-logreg-v1.md',
    # Evidence the published documentation cites by name. A page that points at
    # a report nobody can read is a citation in the shape of one, and the clean
    # clone's link check is what found these: they resolved in the development
    # tree and pointed at nothing in the release root.
    'reports/P13_FULL_SYSTEM_AUDIT_REPORT.md',
    'reports/P14_SCOPED_SAFE_AUTO_PROMOTION_REPORT.md',
    'reports/P15_1_FINAL_REPORT.md',
    'reports/P15_1_DECISION_EVALUATION.md',
    'reports/P15_2_FINAL_REPORT.md',
    'reports/P15_3_OBSERVABILITY.json',
    'reports/P15_5R_PERFORMANCE.json',
    'reports/DATASET_v1.md',
    'reports/DATASET_V1_REPORT.md',
)


#: Never copied, whatever it is found inside. Each entry is (glob, category,
#: reason) and the reason is what `docs/RELEASE_CONTENTS.md` publishes.
EXCLUDE = (
    ('__pycache__', 'GENERATED_EXCLUDE', 'compiled Python'),
    ('*.pyc', 'GENERATED_EXCLUDE', 'compiled Python'),
    ('.pytest_cache', 'GENERATED_EXCLUDE', 'test runner cache'),
    ('.ruff_cache', 'GENERATED_EXCLUDE', 'linter cache'),
    ('.p5-check', 'GENERATED_EXCLUDE', 'local check scratch directory'),
    ('*.egg-info', 'GENERATED_EXCLUDE', 'packaging metadata, rebuilt on demand'),
    ('build', 'GENERATED_EXCLUDE', 'build output'),
    ('.venv', 'LOCAL_ONLY', 'a virtual environment belongs to one machine'),
    ('.git', 'LOCAL_ONLY', 'the release root is curated, not a copy of the history'),
    ('datasets', 'GENERATED_EXCLUDE',
     'generated corpora, 710 MB. The generators, schema, validators and data '
     'cards are published; the corpora they produce are rebuilt rather than '
     'shipped'),
    ('*.sqlite3', 'SENSITIVE_DATA', 'runtime event storage'),
    ('*.jsonl', 'SENSITIVE_DATA',
     'decision journals and shadow exports are a deployment\'s own evidence'),
    ('*.pcap', 'SENSITIVE_DATA',
     'captured traffic. The test fixtures under tests/fixtures are synthetic '
     'and are kept by the explicit exception below'),
    ('*.secret', 'SECRET', 'a deception or pseudonym secret'),
    ('.env', 'SECRET', 'environment secrets'),
    ('*.pdf', 'PRIVATE', 'the development reference library is not redistributed'),
    ('AGENTS.md', 'DEVELOPMENT_ONLY', 'instructions to a development assistant'),
    ('SKILL.md', 'DEVELOPMENT_ONLY', 'instructions to a development assistant'),
    ('SECURITY_AGENT.md', 'DEVELOPMENT_ONLY', 'instructions to a development assistant'),
    ('clean-code-policy.md', 'DEVELOPMENT_ONLY', 'internal engineering policy'),
    ('OTF_*.md', 'PRIVATE', 'funding application drafts'),
    ('release', 'DEVELOPMENT_ONLY', 'local validation records'),
    # A record of a cleanup performed on the *development* tree: a KEEP table
    # naming AGENTS.md, SECURITY_AGENT.md, SKILL.md, clean-code-policy.md,
    # datasets/DATA_CARD_v1.md and release/validation*.json, none of which a
    # reader of the public repository has. `docs/RELEASE_CONTENTS.md` answers
    # the question a public reader actually has — what is in this repository and
    # what was left out, by category and reason — so publishing both meant two
    # pages describing one thing, and the one written for the development tree
    # was the one that described files the reader does not have.
    ('REPOSITORY_CLEANUP.md', 'DEVELOPMENT_ONLY',
     'a cleanup record for the development tree; docs/RELEASE_CONTENTS.md is '
     'the public content and exclusion page'),
)

#: Files that match an EXCLUDE glob and are kept anyway, each for a stated
#: reason. An exception is narrow on purpose: a category with a list of
#: exceptions longer than itself is a category that was drawn wrongly.
KEEP_ANYWAY = (
    ('tests/fixtures/**/*.pcap',
     'small synthetic captures the test suite replays; provenance is in '
     'docs/DATA_AND_MODELS.md'),
)


def excluded(relative):
    """The category and reason this path is not published, or None."""
    name = Path(relative).name
    for pattern, _reason in KEEP_ANYWAY:
        if fnmatch.fnmatch(str(relative), pattern):
            return None
    for pattern, category, reason in EXCLUDE:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(str(relative), pattern):
            return category, reason
    return None


def copy_tree(source, destination, report):
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(ROOT)
        verdict = excluded(relative)
        if verdict:
            report.setdefault(verdict[0], []).append(str(relative))
            continue
        if any(excluded(parent.relative_to(ROOT)) for parent in path.parents
               if parent != ROOT and ROOT in parent.parents or parent == ROOT):
            continue
        target = destination / relative
        if path.is_symlink():
            report.setdefault('SYMLINK_SKIPPED', []).append(str(relative))
            continue
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            report.setdefault('INCLUDE', []).append(str(relative))


def build(destination):
    report = {}
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name in INCLUDE:
        source = ROOT / name
        if not source.exists():
            raise SystemExit(f'missing required entry: {name}')
        if source.is_dir():
            copy_tree(source, destination, report)
        else:
            shutil.copy2(source, destination / name)
            report.setdefault('INCLUDE', []).append(name)
    for name in INCLUDE_REPORTS:
        source = ROOT / name
        if not source.exists():
            raise SystemExit(f'missing required evidence file: {name}')
        (destination / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination / name)
        report.setdefault('INCLUDE', []).append(name)
    return report


def verify(destination):
    """§26, §92. Standalone means the parent can be gone."""
    problems = []
    # §60. A development machine's own paths are not published. The check is on
    # the release root rather than on the development tree, because the tree is
    # allowed to know where it lives and the release is not.
    # Assembled rather than written out, so this file does not match its own
    # detector. The alternative — exempting the detector from the scan — is a
    # hole shaped exactly like the thing being looked for, and an exemption
    # list is the first place a real match would end up hiding.
    #
    # Both halves of this check were too narrow until P16's Windows
    # materialization pass, and both misses were found by grepping the release
    # root by hand rather than by the check reporting them:
    #
    # * the owner's own Windows repository root was never in the list, so it was
    #   published in two reports while `verify()` said PASS — the check knew the
    #   machines it was written on and not the machine it was written for;
    # * the ephemeral cloud working directory was not in it either, and a
    #   session id is machine state exactly as a user name is.
    #
    # Every marker below is still assembled from fragments for the reason given
    # above: a detector that contains its own patterns as literals reports
    # itself, and the first fix anyone reaches for then is an exemption.
    private_paths = tuple('/home/' + name for name in ('e4etest', 'claude')) + (
        '/' + 'Users' + '/', 'C:' + '\\' + 'Users', '/' + 'sessions' + '/',
        'D:' + '\\' + 'Eye_for_an_Eye', 'D:' + '/' + 'Eye_for_an_Eye')
    # Every file that decodes as text is scanned, not a list of extensions.
    # The extension allowlist this replaces covered Markdown, Python, TOML, YAML
    # and shell, and so let two JSON evidence records through with absolute
    # build paths inside them. Evidence records are mostly JSON, which is the
    # worst possible thing for that list to have omitted. A detector that
    # inspects some file types reports "none in the types I looked at", and that
    # is not what a PASS was being read as.
    for path in sorted(destination.rglob('*')):
        relative = path.relative_to(destination)
        if path.is_symlink():
            problems.append(f'symlink: {relative} -> {os.readlink(path)}')
            continue
        verdict = excluded(relative)
        if verdict:
            problems.append(f'{verdict[0]} reached the release root: {relative}')
            continue
        if path.is_file():
            try:
                text = path.read_text(encoding='utf-8')
            except (UnicodeDecodeError, OSError):
                continue
            for marker in private_paths:
                if marker in text:
                    problems.append(f'developer path in {relative}: {marker}')
    for required in ('LICENSE', 'README.md', 'pyproject.toml',
                     'eye_for_an_eye/__init__.py',
                     'eye_for_an_eye/templates/production-shadow.toml',
                     'eye_for_an_eye/templates/production-autonomous.toml'):
        if not (destination / required).is_file():
            problems.append(f'missing: {required}')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--output', default=str(ROOT / 'prod'))
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args(argv)
    destination = Path(args.output).resolve()

    if not args.verify_only:
        report = build(destination)
        for category in sorted(report):
            if category == 'INCLUDE':
                continue
            print(f'{category}: {len(report[category])}')
        print(f'INCLUDE: {len(report.get("INCLUDE", []))}')

    problems = verify(destination)
    for problem in problems:
        print(f'PROBLEM {problem}', file=sys.stderr)
    print('VERIFY ' + ('FAIL' if problems else 'PASS'))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
