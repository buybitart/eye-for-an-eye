"""Package the release root as a Linux release archive. P18 §22, §23, §24.

One rule, the same one `scripts/build_windows_zip.py` follows: **the archive
derives from `prod/`, and nothing in it is maintained by hand.** A second copy of
the tree, curated separately, is two lists of one thing, and this project has
already been bitten twice by exactly that.

So this script reads a release root that `scripts/build_prod.py` produced and
writes it into a tarball under one top-level directory, adding, editing and
omitting nothing. What a beginner sees after `tar xzf` is:

    eye-for-an-eye-<version>/
        START_HERE.md
        install.sh
        uninstall.sh
        README.md
        LICENSE
        SECURITY.md
        ... the rest of the tree, untouched

`install.sh` at the top is the door to `scripts/install.sh`; §23 asks that the
first visible action not be "open pyproject.toml", and a beginner who has just
unpacked an archive looks at the top of it and nowhere else.

### Why one top-level directory

A tarball that unpacks into the current directory scatters seventy entries over
whatever the person happened to be standing in. Every entry here is prefixed with
`eye-for-an-eye-<version>/`, which `verify()` checks rather than assumes.

### Reproducibility

Every member gets a fixed mtime, uid/gid 0, no owner names, and a mode derived
from the source file's executable bit alone. Members are added in sorted order.
Two runs over the same release root produce byte-identical archives, which
`--check-reproducible` demonstrates rather than claims.

Nothing here signs anything. This project has no signing key; a plain archive
with a published SHA-256 is what it can honestly offer.
"""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile

#: Fixed member timestamp. A release input, not a wall clock — the same constant
#: `scripts/build_release.py` uses, for the same reason.
EPOCH = 1788825600  # 2026-09-08 00:00 UTC

#: What a beginner must see at the top of the unpacked archive. Read from the
#: release root; a name missing there is an error, never something invented here.
AT_THE_TOP = ('START_HERE.md', 'install.sh', 'uninstall.sh', 'README.md',
              'LICENSE', 'SECURITY.md')


def version(root):
    """The real version, read from the package rather than chosen."""
    initializer = (root / 'eye_for_an_eye' / '__init__.py').read_text(encoding='utf-8')
    for line in initializer.splitlines():
        if line.startswith('__version__'):
            return line.split('=', 1)[1].strip().strip('\'"')
    raise SystemExit('cannot read the version from eye_for_an_eye/__init__.py')


def build(root, destination, prefix):
    """Write the archive. Returns (members, bytes, sha256 of the archive)."""
    missing = [name for name in AT_THE_TOP if not (root / name).is_file()]
    if missing:
        raise SystemExit('the release root is missing: ' + ', '.join(missing))
    if any(path.is_symlink() for path in root.rglob('*')):
        raise SystemExit('the release root contains a symlink; refusing to archive it')

    files = sorted(path for path in root.rglob('*') if path.is_file())
    encoded = io.BytesIO()
    with tarfile.open(fileobj=encoded, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for path in files:
            relative = path.relative_to(root).as_posix()
            member = archive.gettarinfo(str(path), prefix + '/' + relative)
            member.uid = member.gid = 0
            member.uname = member.gname = ''
            member.mtime = EPOCH
            # The executable bit is the only thing carried over from disk. A
            # release archive that grants some other permission by accident is a
            # release archive nobody can reason about.
            member.mode = 0o755 if path.stat().st_mode & 0o100 else 0o644
            member.pax_headers = {}
            with path.open('rb') as stream:
                archive.addfile(member, stream)

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('wb') as stream, gzip.GzipFile(
            filename='', mode='wb', fileobj=stream, mtime=EPOCH) as compressed:
        compressed.write(encoded.getvalue())
    return (len(files), destination.stat().st_size,
            hashlib.sha256(destination.read_bytes()).hexdigest())


def verify(root, destination, prefix):
    """Every archived file must be byte-identical to the release root."""
    problems = []
    with tarfile.open(destination, 'r:gz') as archive:
        members = {member.name: member for member in archive.getmembers()}
        for name, member in members.items():
            if not name.startswith(prefix + '/'):
                problems.append(f'not under the single top-level directory: {name}')
            if not member.isfile():
                problems.append(f'unexpected member type: {name}')
            if member.uid or member.gid or member.uname or member.gname:
                problems.append(f'carries an owner: {name}')
            if member.mode not in (0o644, 0o755):
                problems.append(f'unexpected mode {oct(member.mode)}: {name}')
        for name in AT_THE_TOP:
            if prefix + '/' + name not in members:
                problems.append(f'not at the top of the archive: {name}')
        for path in sorted(root.rglob('*')):
            if not path.is_file():
                continue
            entry = prefix + '/' + path.relative_to(root).as_posix()
            if entry not in members:
                problems.append(f'missing from the archive: {entry}')
                continue
            extracted = archive.extractfile(entry)
            if extracted is None or extracted.read() != path.read_bytes():
                problems.append(f'content differs from the release root: {entry}')
        # install.sh has to be runnable straight out of the archive. A beginner
        # told to run `sh install.sh` survives a missing bit; one who types
        # `./install.sh` does not, and the instruction should work either way.
        launcher = members.get(prefix + '/install.sh')
        if launcher is not None and not launcher.mode & 0o100:
            problems.append('install.sh is not executable inside the archive')
    return problems


def checksums(paths, destination):
    """A SHA256SUMS file in the format `sha256sum -c` reads. P18 §24."""
    rows = []
    for path in sorted(paths):
        with path.open('rb') as stream:
            rows.append(hashlib.file_digest(stream, 'sha256').hexdigest() + '  ' + path.name)
    destination.write_text('\n'.join(rows) + '\n', encoding='utf-8')
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--prod', default=str(Path(__file__).resolve().parents[1] / 'prod'),
                        help='the release root that build_prod.py produced')
    parser.add_argument('--output-dir', default='')
    parser.add_argument('--check-reproducible', action='store_true',
                        help='build twice and compare, instead of claiming it')
    parser.add_argument('--sha256sums', action='store_true',
                        help='also write SHA256SUMS beside the archive')
    args = parser.parse_args(argv)

    root = Path(args.prod).resolve()
    if not (root / 'eye_for_an_eye' / '__init__.py').is_file():
        raise SystemExit(f'not a release root: {root}')
    release = version(root)
    prefix = f'eye-for-an-eye-{release}'
    out = Path(args.output_dir).resolve() if args.output_dir else root.parent
    destination = out / f'{prefix}-linux-x86_64.tar.gz'

    members, size, digest = build(root, destination, prefix)
    problems = verify(root, destination, prefix)

    if args.check_reproducible:
        again = out / (destination.name + '.again')
        build(root, again, prefix)
        same = again.read_bytes() == destination.read_bytes()
        again.unlink()
        if not same:
            problems.append('two builds over the same release root are not identical')
        print('reproducible : ' + ('YES (two builds byte-identical)' if same else 'NO'))

    if args.sha256sums:
        rows = checksums([destination], out / 'SHA256SUMS')
        print('sha256sums   : ' + str(out / 'SHA256SUMS'))
        for row in rows:
            print('  ' + row)

    for problem in problems:
        print('PROBLEM ' + problem, file=sys.stderr)
    print(f'archive : {destination}')
    print(f'prefix  : {prefix}/')
    print(f'files   : {members}')
    print(f'bytes   : {size}')
    print(f'sha256  : {digest}')
    print('signed  : NO — this project has no signing key. Check the published '
          'SHA-256 instead: sha256sum -c SHA256SUMS')
    print('VERIFY ' + ('FAIL' if problems else 'PASS'))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
