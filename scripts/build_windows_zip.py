"""Package the release root as a beginner Windows archive. P17W §15, §16.

One rule shapes this file: **the archive derives from `prod/`, and nothing is
maintained by hand.** A second copy of the tree, curated separately, is two lists
of one thing — which in this project has already gone wrong twice.

So this script reads a release root that `scripts/build_prod.py` produced and
rearranges it, without adding, editing or omitting any file content. What a
beginner sees at the top of the archive is:

    START_HERE.md
    Install-EyeForAnEye.cmd
    Start-EyeForAnEye.cmd
    Status-EyeForAnEye.cmd
    Demo-EyeForAnEye.cmd
    Stop-EyeForAnEye.cmd
    Uninstall-EyeForAnEye.cmd
    README.md
    app/            <- everything else, untouched

The launchers `cd /d "%~dp0"` to their own directory, and the installer resolves
its source from its own location's parent, so they have to sit beside the tree
they install. That is why `app/` holds the project and the launchers are copied,
not moved: the copy at the top is what a beginner clicks, and `app/` holds the
one the installer actually reads. Both are byte-identical to `prod/`, which
`verify()` below checks rather than assumes.

Nothing here signs anything. There is no MSI, no installer package and no
certificate, because this project has none, and claiming otherwise would be worse
than a plain ZIP.
"""
import argparse
import hashlib
from pathlib import Path
import sys
import zipfile

#: What a beginner must see without opening a folder. Read from the release root;
#: a name missing there is an error, not something to be invented here.
AT_THE_TOP = ('START_HERE.md', 'README.md',
              'Install-EyeForAnEye.cmd', 'Start-EyeForAnEye.cmd',
              'Status-EyeForAnEye.cmd', 'Demo-EyeForAnEye.cmd',
              'Stop-EyeForAnEye.cmd', 'Uninstall-EyeForAnEye.cmd')


def version(root):
    """The real version, read from the package rather than chosen."""
    initializer = (root / 'eye_for_an_eye' / '__init__.py').read_text(encoding='utf-8')
    for line in initializer.splitlines():
        if line.startswith('__version__'):
            return line.split('=', 1)[1].strip().strip('\'"')
    raise SystemExit('cannot read the version from eye_for_an_eye/__init__.py')


def build(root, destination):
    """Write the archive. Returns (entries, bytes, sha256 of the archive)."""
    missing = [name for name in AT_THE_TOP if not (root / name).is_file()]
    if missing:
        raise SystemExit('the release root is missing: ' + ', '.join(missing))

    files = sorted(path for path in root.rglob('*') if path.is_file())
    if any(path.is_symlink() for path in root.rglob('*')):
        raise SystemExit('the release root contains a symlink; refusing to archive it')

    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, 'app/' + str(path.relative_to(root)).replace('\\', '/'))
        for name in AT_THE_TOP:
            archive.write(root / name, name)
    return (len(files) + len(AT_THE_TOP), destination.stat().st_size,
            hashlib.sha256(destination.read_bytes()).hexdigest())


def verify(root, destination):
    """Every archived file must be byte-identical to the release root."""
    problems = []
    with zipfile.ZipFile(destination) as archive:
        names = set(archive.namelist())
        for name in AT_THE_TOP:
            if name not in names:
                problems.append(f'not at the top of the archive: {name}')
        for path in sorted(root.rglob('*')):
            if not path.is_file():
                continue
            entry = 'app/' + str(path.relative_to(root)).replace('\\', '/')
            if entry not in names:
                problems.append(f'missing from the archive: {entry}')
                continue
            if archive.read(entry) != path.read_bytes():
                problems.append(f'content differs from the release root: {entry}')
        for name in AT_THE_TOP:
            if name in names and archive.read(name) != (root / name).read_bytes():
                problems.append(f'top-level copy differs from the release root: {name}')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--prod', default=str(Path(__file__).resolve().parents[1] / 'prod'),
                        help='the release root that build_prod.py produced')
    parser.add_argument('--output-dir', default='')
    args = parser.parse_args(argv)

    root = Path(args.prod).resolve()
    if not (root / 'eye_for_an_eye' / '__init__.py').is_file():
        raise SystemExit(f'not a release root: {root}')
    release = version(root)
    out = Path(args.output_dir).resolve() if args.output_dir else root.parent
    destination = out / f'Eye-for-an-Eye-{release}-Windows.zip'

    entries, size, digest = build(root, destination)
    problems = verify(root, destination)
    for problem in problems:
        print('PROBLEM ' + problem, file=sys.stderr)
    print(f'archive : {destination}')
    print(f'entries : {entries}')
    print(f'bytes   : {size}')
    print(f'sha256  : {digest}')
    print('signed  : NO — this project has no signing key, and a plain ZIP that '
          'says so beats a package that claims what it cannot prove')
    print('VERIFY ' + ('FAIL' if problems else 'PASS'))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
