"""Build a real Debian package from the release root. P18 §15-§18, §115, §116.

### Why a .deb is appropriate here, and where it is not

`pyproject.toml` declares `dependencies = []`. Every third-party library this
project can use — scapy, onnxruntime, numpy, maxminddb — is an optional extra,
and the core runs on the standard library alone. That is what makes a
policy-clean Debian package possible at all: one `Depends` line naming the
interpreter, and nothing else to resolve.

The narrow part is the interpreter. `requires-python = ">=3.12,<3.13"`, so the
package declares `python3 (>= 3.12), python3 (<< 3.13)` and installs only where
the system Python is 3.12. In practice that is **Ubuntu 24.04 LTS** and its
derivatives. Debian 12 ships Python 3.11 and Debian 13 ships 3.13, so on both the
package correctly refuses to install rather than installing something that cannot
run. `scripts/install.sh` remains the path for those systems, because it can ask
`uv` for a 3.12 interpreter that the distribution does not provide.

That limitation is declared, not hidden, and it is the reason the release archive
is the primary Linux path while this package is the convenient one.

### What it installs, and why each path

    /usr/bin/eye-for-an-eye                          the command
    /usr/lib/python3/dist-packages/eye_for_an_eye/   the Python package
    /usr/lib/systemd/system/*.service                units, installed, never enabled
    /usr/lib/sysusers.d/eye-for-an-eye.conf          the service accounts
    /usr/share/doc/eye-for-an-eye/                   copyright, changelog, guides
    /usr/share/eye-for-an-eye/deploy/                example deployment configs
    /usr/share/man/man1/eye-for-an-eye.1.gz          the man page

`/opt` is deliberately not used. §18 asks for a reason before `/opt`, and the
reason that justifies it for `scripts/install.sh` — a self-contained tree with its
own interpreter environment — does not apply to a package whose files are
ordinary distribution files under `/usr`.

No configuration is shipped under `/etc`. That is a decision, not an omission: a
packaged configuration becomes a conffile, and a conffile is the mechanism by
which an upgrade asks an operator to merge a policy file they did not write.
`eye-for-an-eye setup --config /etc/eye-for-an-eye/eye-for-an-eye.toml` writes the
operator's own file, the package never touches it, and §116's "configuration
should not be silently overwritten" is satisfied by there being nothing to
overwrite.

### What the package scripts may do

§115 says keep them minimal, and they are: `postinst` asks systemd to create the
service accounts and to re-read its unit files, and that is all. No service is
enabled or started, no firewall rule is touched, nothing is downloaded, and
nothing outside this package is deleted — on install or on removal. §55 in
particular: `apt purge` does not delete an operator's configuration, database or
decision journal, because the package does not own those paths.

### Units are derived, not duplicated

The unit files come from `deploy/systemd/` with two paths substituted, because a
packaged copy maintained by hand is a second list of one thing. `verify()` diffs
the packaged unit against its source line by line and fails if anything other
than the two mapped lines differs.
"""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

#: Debian revision. Bumped when the packaging changes without the upstream
#: version changing.
REVISION = '1'

#: How the venv paths in `deploy/systemd/` become package paths. Every entry is
#: checked by `verify()`; a unit that differs anywhere else fails the build.
UNIT_SUBSTITUTIONS = (
    ('/opt/eye-for-an-eye/.venv/bin/eye-for-an-eye', '/usr/bin/eye-for-an-eye'),
    ('WorkingDirectory=/opt/eye-for-an-eye', 'WorkingDirectory=/var/lib/eye-for-an-eye'),
)

UNITS = ('eye-for-an-eye.service', 'eye-for-an-eye-capture.service',
         'eye-for-an-eye-listener.service')

#: The service accounts, with the fixed uids removed. `deploy/systemd/eye-for-an-eye.conf`
#: pins 10000-10002 and says in its own first line to review them for conflicts
#: before installing — correct advice for a hand-built deployment and wrong for a
#: package, which must let the system allocate. Same accounts, same shells, same
#: home directories, ids chosen by systemd-sysusers.
SYSUSERS = """\
# Service accounts for Eye for an Eye. Created by systemd-sysusers on install.
#
# No interactive login: both accounts use /usr/sbin/nologin. P18 §51.
#
# Ids are allocated by the system. The hand-deployment template in
# deploy/systemd/eye-for-an-eye.conf pins 10000-10002 and tells the operator to
# check them for conflicts first; a package cannot ask that, so it does not pin.
g eye-for-an-eye-ipc -
u eye-for-an-eye -:eye-for-an-eye-ipc "Eye for an Eye analysis" /var/lib/eye-for-an-eye /usr/sbin/nologin
u eye-for-an-eye-capture -:eye-for-an-eye-ipc "Eye for an Eye capture" /nonexistent /usr/sbin/nologin
"""

#: The command.
#:
#: `#!/usr/bin/python3.12`, not `#!/usr/bin/python3`, and the package depends on
#: `python3.12` rather than on the `python3` metapackage. That is not pedantry: it
#: was found by installing the first version of this package and running it.
#:
#: On the test machine the `python3` *package* was 3.12.3, so
#: `Depends: python3 (>= 3.12), python3 (<< 3.13)` was satisfied and apt installed
#: happily — while `/usr/bin/python3` was an alternatives symlink to Python
#: 3.11.15, so every command ran under the wrong interpreter. A dependency on a
#: metapackage says nothing about where a symlink points, and an administrator is
#: allowed to point it wherever they like.
#:
#: The version check below stays anyway, as the answer for a file copied by hand
#: onto a machine that has no 3.12 at all. P18 §42.
LAUNCHER = '''\
#!/usr/bin/python3.12
"""Eye for an Eye command line. Installed by the Debian package."""
import sys

if sys.version_info[:2] != (3, 12):
    sys.stderr.write(
        'Eye for an Eye needs Python 3.12.\\n'
        'This computer is using Python %d.%d.\\n'
        '\\n'
        'Install Python 3.12, or install Eye for an Eye with its own installer,\\n'
        'which can provide 3.12 itself:\\n'
        '  sh install.sh\\n' % sys.version_info[:2])
    raise SystemExit(2)

from eye_for_an_eye.cli import main

raise SystemExit(main())
'''

POSTINST = """\
#!/bin/sh
# Minimal by policy. P18 §115.
#
# It creates the service accounts the unit files name and asks systemd to re-read
# its units. It does not enable or start anything: §34 and §119 require that
# installing this package cannot put the machine into enforcement, and the safest
# way to guarantee that is for the installer to have no code that could.
set -e

case "$1" in
  configure)
    if command -v systemd-sysusers >/dev/null 2>&1; then
      # A failure here must not fail the install. The accounts matter only when an
      # operator deliberately starts a service, and systemd reports a missing
      # User= loudly at that point rather than quietly doing the wrong thing.
      systemd-sysusers /usr/lib/sysusers.d/eye-for-an-eye.conf >/dev/null 2>&1 || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    ;;
esac

exit 0
"""

POSTRM = """\
#!/bin/sh
# Minimal by policy. P18 §115, §55.
#
# It removes nothing of the operator's. The configuration, the database, the
# decision journal and any exported evidence live in paths this package does not
# own, so `apt purge` leaves them exactly where they are. Deleting them is a
# separate, deliberate act; /usr/share/doc/eye-for-an-eye/README.Debian says how.
#
# The service accounts are also left alone: an account that still owns files is
# not safe to remove, and files it owns are the operator's evidence.
set -e

case "$1" in
  remove|purge)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    ;;
esac

exit 0
"""

README_DEBIAN = """\
Eye for an Eye on Debian and Ubuntu
===================================

What this package installed
---------------------------

  /usr/bin/eye-for-an-eye                          the command
  /usr/lib/python3/dist-packages/eye_for_an_eye/   the program
  /usr/lib/systemd/system/                         service units, NOT enabled
  /usr/lib/sysusers.d/eye-for-an-eye.conf          the service accounts
  /usr/share/eye-for-an-eye/deploy/                example deployment configs
  /usr/share/man/man1/eye-for-an-eye.1.gz          the man page

Automatic blocking is off. No firewall rule was changed. No service was
started or enabled.

First steps
-----------

  eye-for-an-eye setup      choose what to watch
  eye-for-an-eye start      begin Safe Monitoring
  eye-for-an-eye status     see how it is doing

Where your files go
-------------------

Nothing under /etc is shipped by this package, on purpose: a packaged
configuration file is one an upgrade can ask you to merge. Your configuration
is yours, written by `eye-for-an-eye setup`.

For a system-wide deployment:

  sudo mkdir -p /etc/eye-for-an-eye
  sudo eye-for-an-eye setup --config /etc/eye-for-an-eye/eye-for-an-eye.toml

Runtime state lives under /var/lib/eye-for-an-eye, which the systemd units
create themselves through StateDirectory=.

Removing it
-----------

  sudo apt remove eye-for-an-eye     removes the program
  sudo apt purge eye-for-an-eye      the same; it does NOT delete your data

Neither one deletes your configuration, your database or your decision
journal. This package does not own those paths, so it will not remove them.
To delete them as well, do it deliberately:

  sudo rm -rf /etc/eye-for-an-eye /var/lib/eye-for-an-eye

Optional extras
---------------

These are not dependencies and none of them is required:

  nftables            needed only for automatic host blocking (Linux)
  onnxruntime, numpy  the optional local model; the maths engine works alone
  scapy               reading saved packet capture files

The versions this project supports are pinned in pyproject.toml, and the
versions in the distribution archive do not always match them. Install them
into a virtual environment rather than over the distribution's packages.

systemd
-------

The units are installed and left disabled. Read
/usr/share/doc/eye-for-an-eye/SYSTEMD.md before enabling one, and note that
the analysis service needs a configuration and a traffic source first.
"""

MANPAGE = """\
.TH EYE-FOR-AN-EYE 1 "2026-09-26" "eye-for-an-eye {version}" "Eye for an Eye"
.SH NAME
eye\\-for\\-an\\-eye \\- bounded defensive network and web traffic observation
.SH SYNOPSIS
.B eye\\-for\\-an\\-eye
.I command
.RI [ options ]
.SH DESCRIPTION
Eye for an Eye watches the traffic arriving at a server, scores how each source
behaves over time, and records what it saw. By default it blocks nothing.
.PP
Automatic host blocking is a separate, Linux-only feature that must be
configured deliberately. It refuses to start until the operator has named the
networks it must never block.
.SH BEGINNER COMMANDS
.TP
.B setup
Choose what to watch. Asks questions when run in a terminal.
.TP
.B start
Begin Safe Monitoring. Blocks nothing.
.TP
.B status
Say how it is doing, in short words.
.TP
.B stop
Ask a running instance to stop.
.TP
.B demo
Process one synthetic local event. Contacts nothing and changes no firewall.
.TP
.B check\\-install
Check that the installation is complete.
.SH ADMINISTRATOR COMMANDS
.TP
.B doctor
The full technical health report.
.TP
.B config validate
Check a configuration without using it.
.TP
.B run
Run the sensor directly, with the expert output.
.TP
.B autonomy readiness
Report what automatic blocking still needs.
.TP
.B web log\\-format
Print the access log format this program reads.
.SH FILES
.TP
.I /usr/share/eye-for-an-eye/deploy/
Example deployment configurations.
.TP
.I /usr/lib/systemd/system/eye-for-an-eye.service
The analysis service. Installed disabled.
.SH SECURITY
Report vulnerabilities privately. See
.I /usr/share/doc/eye-for-an-eye/SECURITY.md
and do not open a public issue.
.SH AUTHOR
Aliaksandr Zasinets.
.SH COPYRIGHT
Copyright (c) 2026 Aliaksandr Zasinets. MIT License.
"""


def version(root):
    """The upstream version, read from the package rather than chosen. §89."""
    initializer = (root / 'eye_for_an_eye' / '__init__.py').read_text(encoding='utf-8')
    for line in initializer.splitlines():
        if line.startswith('__version__'):
            return line.split('=', 1)[1].strip().strip('\'"')
    raise SystemExit('cannot read the version from eye_for_an_eye/__init__.py')


def debian_version(upstream):
    """`0.8.0rc1` -> `0.8.0~rc1`, so that it sorts before `0.8.0`.

    Derived from the upstream string, never a second version to maintain. The
    tilde is the only thing Debian understands as "earlier than the release".
    """
    for marker in ('rc', 'a', 'b', 'dev'):
        index = upstream.find(marker)
        if index > 0 and upstream[index - 1].isdigit():
            return upstream[:index] + '~' + upstream[index:]
    return upstream


def packaged_unit(source_text):
    """A unit file with the venv paths replaced by the package's paths."""
    text = source_text
    for original, replacement in UNIT_SUBSTITUTIONS:
        text = text.replace(original, replacement)
    return text


def stage(root, staging, upstream, maintainer):
    """Lay out the package tree. Returns the list of installed paths."""
    package = 'eye-for-an-eye'
    dist = staging / 'usr/lib/python3/dist-packages'
    docs = staging / 'usr/share/doc' / package
    shared = staging / 'usr/share' / package
    for directory in (staging / 'usr/bin', dist, docs, shared,
                      staging / 'usr/lib/systemd/system',
                      staging / 'usr/lib/sysusers.d',
                      staging / 'usr/share/man/man1', staging / 'DEBIAN'):
        directory.mkdir(parents=True, exist_ok=True)

    # The Python package, copied whole. Compiled files are never copied: a .deb
    # that ships .pyc is a .deb whose bytecode can disagree with its source.
    shutil.copytree(root / 'eye_for_an_eye', dist / 'eye_for_an_eye',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))

    launcher = staging / 'usr/bin' / package
    launcher.write_text(LAUNCHER, encoding='utf-8')
    launcher.chmod(0o755)

    for name in UNITS:
        source = (root / 'deploy/systemd' / name).read_text(encoding='utf-8')
        (staging / 'usr/lib/systemd/system' / name).write_text(
            packaged_unit(source), encoding='utf-8')
    (staging / 'usr/lib/sysusers.d' / (package + '.conf')).write_text(
        SYSUSERS, encoding='utf-8')

    # Documentation. `copyright` is the project's own LICENSE, unaltered.
    licence = (root / 'LICENSE').read_text(encoding='utf-8')
    (docs / 'copyright').write_text(
        'Upstream-Name: Eye for an Eye\n'
        'Source: the release archive this package was built from\n'
        'Files: *\n'
        'Copyright: 2026 Aliaksandr Zasinets\n'
        'License: MIT\n'
        '\n' + '\n'.join(' ' + line if line else ' .' for line in licence.splitlines())
        + '\n', encoding='utf-8')
    (docs / 'README.Debian').write_text(README_DEBIAN, encoding='utf-8')
    for name in ('README.md', 'START_HERE.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md'):
        if (root / name).is_file():
            shutil.copy2(root / name, docs / name)
    for name in ('BEGINNER_GUIDE.md', 'SYSTEMD.md', 'PRIVILEGES.md', 'INSTALL_LINUX.md',
                 'AUTONOMOUS_MODE.md', 'VALIDATION_STATUS.md', 'TROUBLESHOOTING.md'):
        if (root / 'docs' / name).is_file():
            shutil.copy2(root / 'docs' / name, docs / name)

    changelog = (f'{package} ({debian_version(upstream)}-{REVISION}) unstable; '
                 f'urgency=medium\n'
                 f'\n'
                 f'  * Packaged from the Eye for an Eye {upstream} release root.\n'
                 f'    The project changelog is in CHANGELOG.md in this directory.\n'
                 f'\n'
                 f' -- {maintainer}  Sat, 26 Sep 2026 00:00:00 +0000\n')
    with gzip.GzipFile(filename='', mode='wb', mtime=0,
                       fileobj=(docs / 'changelog.Debian.gz').open('wb')) as stream:
        stream.write(changelog.encode('utf-8'))
    if (root / 'CHANGELOG.md').is_file():
        shutil.copy2(root / 'CHANGELOG.md', docs / 'CHANGELOG.md')

    # Example deployment configurations, as examples and nothing more: none of
    # them is installed into /etc and none is read unless an operator names it.
    (shared / 'deploy').mkdir(parents=True, exist_ok=True)
    for path in sorted((root / 'deploy').glob('*.toml')):
        shutil.copy2(path, shared / 'deploy' / path.name)

    with gzip.GzipFile(filename='', mode='wb', mtime=0,
                       fileobj=(staging / 'usr/share/man/man1'
                                / (package + '.1.gz')).open('wb')) as stream:
        stream.write(MANPAGE.format(version=upstream).encode('utf-8'))

    for name, body in (('postinst', POSTINST), ('postrm', POSTRM)):
        script = staging / 'DEBIAN' / name
        script.write_text(body, encoding='utf-8')
        script.chmod(0o755)

    installed = sorted(path for path in staging.rglob('*')
                       if path.is_file() and 'DEBIAN' not in path.relative_to(staging).parts)
    size_kb = max(1, sum(path.stat().st_size for path in installed) // 1024)
    (staging / 'DEBIAN/control').write_text(
        f'Package: {package}\n'
        f'Version: {debian_version(upstream)}-{REVISION}\n'
        f'Architecture: all\n'
        f'Maintainer: {maintainer}\n'
        f'Installed-Size: {size_kb}\n'
        # The interpreter, and nothing else. `dependencies = []` upstream is what
        # makes this one line possible; see this file's own docstring for why the
        # version matters and which distributions it excludes.
        #
        # `python3.12`, not `python3 (>= 3.12), python3 (<< 3.13)`. The metapackage
        # form was tried first and it installed onto a machine whose
        # /usr/bin/python3 alternative pointed at 3.11 — satisfied dependency,
        # wrong interpreter. This form depends on the binary that is actually run.
        f'Depends: python3.12\n'
        f'Suggests: nftables\n'
        f'Section: net\n'
        f'Priority: optional\n'
        # No Homepage field. It is optional, the repository URL is not known while
        # the project is unpublished, and `https://github.com/` is not a homepage —
        # it is a field filled in to look complete. The owner adds the real URL.
        f'Description: bounded defensive network and web traffic observation\n'
        f' Eye for an Eye watches the traffic arriving at a server, scores how each\n'
        f' source behaves over time, and records what it saw. It runs entirely on the\n'
        f' machine it protects: no cloud service and no account.\n'
        f' .\n'
        f' By default it blocks nothing. Automatic host blocking is a separate,\n'
        f' Linux-only feature that must be configured deliberately, and it refuses to\n'
        f' start until the operator has named the networks it must never block.\n'
        f' .\n'
        f' Installing this package enables no blocking, changes no firewall rule and\n'
        f' starts no service. The systemd units are installed disabled.\n'
        f' .\n'
        f' Real-world validation of autonomous blocking is pending; see\n'
        f' /usr/share/doc/{package}/VALIDATION_STATUS.md.\n',
        encoding='utf-8')
    return installed


def verify(root, staging, built):
    """What the package must be true about itself before it is offered."""
    problems = []

    for name in UNITS:
        source = (root / 'deploy/systemd' / name).read_text(encoding='utf-8').splitlines()
        packaged = (staging / 'usr/lib/systemd/system' / name).read_text(
            encoding='utf-8').splitlines()
        if len(source) != len(packaged):
            problems.append(f'{name}: the packaged unit has a different number of lines')
            continue
        for index, (before, after) in enumerate(zip(source, packaged), start=1):
            if before == after:
                continue
            mapped = any(original in before and replacement in after
                         for original, replacement in UNIT_SUBSTITUTIONS)
            if not mapped:
                problems.append(f'{name}:{index}: changed by something other than the '
                                f'declared substitutions: {before!r} -> {after!r}')
        for forbidden in ('ExecStart=/opt/', 'ExecStartPre=/opt/'):
            if any(line.startswith(forbidden) for line in packaged):
                problems.append(f'{name}: still runs from /opt')
        if any(line.strip() in ('[Install]',) for line in packaged):
            # An [Install] section is fine; what must not happen is the package
            # enabling it. That is checked on the scripts, below.
            pass

    for script, body in (('postinst', POSTINST), ('postrm', POSTRM)):
        for forbidden in ('systemctl enable', 'systemctl start', 'nft ', 'iptables',
                          'rm -rf', 'curl', 'wget', 'setenforce', 'aa-disable',
                          'userdel', 'groupdel'):
            if forbidden in body:
                problems.append(f'{script}: contains a forbidden operation: {forbidden}')

    staged_names = {path.relative_to(staging).as_posix() for path in staging.rglob('*')
                    if path.is_file()}
    for forbidden in sorted(name for name in staged_names
                            if name.startswith('etc/')
                            or name.endswith(('.pyc', '.secret', '.sqlite3', '.mmdb'))
                            or '__pycache__' in name):
        problems.append('must not be in the package: ' + forbidden)
    for required in ('usr/bin/eye-for-an-eye',
                     'usr/lib/python3/dist-packages/eye_for_an_eye/__init__.py',
                     'usr/lib/python3/dist-packages/eye_for_an_eye/templates/'
                     'production-shadow.toml',
                     'usr/share/doc/eye-for-an-eye/copyright',
                     'usr/share/doc/eye-for-an-eye/changelog.Debian.gz',
                     'usr/share/doc/eye-for-an-eye/README.Debian',
                     'usr/lib/sysusers.d/eye-for-an-eye.conf',
                     'usr/share/man/man1/eye-for-an-eye.1.gz'):
        if required not in staged_names:
            problems.append('missing from the package: ' + required)

    # The built archive, read back. A package is what dpkg-deb wrote, not what
    # the staging directory looked like.
    listing = subprocess.run(['dpkg-deb', '--contents', str(built)],
                             capture_output=True, text=True, check=True).stdout
    for line in listing.splitlines():
        fields = line.split()
        if not fields:
            continue
        mode, name = fields[0], fields[-1]
        if name.startswith('./etc/'):
            problems.append('the built package ships a configuration file: ' + name)
        if mode.startswith('l'):
            problems.append('the built package contains a symlink: ' + name)
        if 'setuid' in mode or mode[3] == 's' or mode[6] == 's':
            problems.append('the built package contains a setuid/setgid file: ' + name)
    if './usr/bin/eye-for-an-eye' not in listing:
        problems.append('the built package has no /usr/bin/eye-for-an-eye')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--prod', default=str(Path(__file__).resolve().parents[1] / 'prod'),
                        help='the release root that build_prod.py produced')
    parser.add_argument('--output-dir', default='')
    # RFC 2606 reserves `.invalid` precisely so that a machine-readable field can
    # hold a name without claiming a mailbox. The owner supplies the real address
    # at release time; inventing one would send a bug report nowhere while looking
    # as though it went somewhere.
    parser.add_argument('--maintainer',
                        default='Aliaksandr Zasinets <aliaksandr.zasinets@invalid>',
                        help='Debian Maintainer field; the owner supplies the real address')
    args = parser.parse_args(argv)

    if not shutil.which('dpkg-deb'):
        print('dpkg-deb is not installed; a Debian package cannot be built here.',
              file=sys.stderr)
        return 2
    root = Path(args.prod).resolve()
    if not (root / 'eye_for_an_eye' / '__init__.py').is_file():
        raise SystemExit(f'not a release root: {root}')
    upstream = version(root)
    out = Path(args.output_dir).resolve() if args.output_dir else root.parent
    out.mkdir(parents=True, exist_ok=True)
    name = f'eye-for-an-eye_{debian_version(upstream)}-{REVISION}_all.deb'
    built = out / name

    with tempfile.TemporaryDirectory(prefix='e4e-deb-') as directory:
        staging = Path(directory) / 'root'
        staging.mkdir()
        installed = stage(root, staging, upstream, args.maintainer)
        # Deterministic metadata for every staged file, so two builds of the same
        # release root produce the same package.
        for path in sorted(staging.rglob('*')):
            os.utime(path, (0, 0))
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build',
                        str(staging), str(built)],
                       check=True, capture_output=True, text=True)
        problems = verify(root, staging, built)
        files = len(installed)

    digest = hashlib.sha256(built.read_bytes()).hexdigest()
    for problem in problems:
        print('PROBLEM ' + problem, file=sys.stderr)
    print(f'package  : {built}')
    print(f'version  : {debian_version(upstream)}-{REVISION}  (upstream {upstream})')
    print(f'files    : {files}')
    print(f'bytes    : {built.stat().st_size}')
    print(f'sha256   : {digest}')
    print('depends  : python3.12')
    print('installs : nothing under /etc; no service enabled; no firewall change')
    print('signed   : NO — this project has no signing key')
    print('VERIFY ' + ('FAIL' if problems else 'PASS'))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
