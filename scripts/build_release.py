"""Build twice, compare reproducibility, emit hashes and a dependency inventory. Never publish."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EPOCH = 1788825600  # 2026-09-08 00:00 UTC: release input, not wall clock.


def normalize_sdist(path):
    # Setuptools sdist includes filesystem mtimes. Normalize only the generated archive.
    encoded = io.BytesIO()
    with tarfile.open(path, 'r:gz') as source, tarfile.open(fileobj=encoded, mode='w', format=tarfile.PAX_FORMAT) as target:
        for member in sorted(source.getmembers(), key=lambda item: item.name):
            if not (member.isfile() or member.isdir()):
                raise ValueError('unexpected sdist member type')
            if member.name.startswith('/') or '..' in Path(member.name).parts:
                raise ValueError('unsafe sdist path')
            member.uid = member.gid = 0
            member.uname = member.gname = ''
            member.mtime = EPOCH
            member.mode = 0o755 if member.isdir() else 0o644
            member.pax_headers = {}
            target.addfile(member, source.extractfile(member) if member.isfile() else None)
    with path.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=EPOCH) as compressed:
        compressed.write(encoded.getvalue())


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def runtime_source_hash():
    digest = hashlib.sha256()
    for path in sorted((ROOT/'eye_for_an_eye').rglob('*')):
        if path.is_file() and path.suffix in ('.py', '.toml'):
            digest.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return digest.hexdigest()


def build(output, uv):
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError('artifact output must be empty; choose a new directory')
    with tempfile.TemporaryDirectory(prefix='e4e-build-') as directory:
        passes = []
        for index in range(2):
            target = Path(directory)/str(index)
            subprocess.run([uv, 'build', '--build-constraints', str(ROOT/'requirements/build.txt'), '--require-hashes',
                '--cache-dir', str(ROOT/'.uv-cache'), '--out-dir', str(target)], cwd=ROOT,
                env={**os.environ, 'SOURCE_DATE_EPOCH': str(EPOCH)}, check=True, timeout=180)
            normalize_sdist(next(target.glob('*.tar.gz')))
            passes.append({path.name: sha(path) for path in target.iterdir() if path.name.endswith(('.whl', '.tar.gz'))})
        if passes[0] != passes[1]:
            raise RuntimeError('independent build passes are not reproducible')
        for name in passes[0]:
            (output/name).write_bytes((Path(directory)/'0'/name).read_bytes())
    inspect_wheel(next(output.glob('*.whl')))
    write_sbom(output)
    (output/'build-evidence.json').write_text(json.dumps({'schema_version': 1, 'two_builds_identical': True,
        'runtime_source_sha256': runtime_source_hash(),
        'source_date_epoch': EPOCH, 'artifacts': passes[0], 'signing': 'not_configured',
        'container': 'not_built_by_this_script'}, indent=2)+'\n', encoding='utf-8')
    write_checksums(output)
    return {'artifacts': str(output), 'reproducible': True}


def inspect_wheel(wheel):
    """What must be true of the built wheel before anything else happens.

    P18 replaced a hard-coded count here. The check read `if len(templates) != 3`,
    written when the package had three configuration templates. It has had six
    since the two production profiles were added, so this script could not
    complete on its own source tree: every wheel it built failed its own check
    with *packaged deployment templates missing*, which is the opposite of what
    had happened.

    A count goes stale silently. The set does not: every template in the source
    must be in the wheel, and the error names the ones that are not.
    """
    expected = {path.name for path in (ROOT/'eye_for_an_eye'/'templates').glob('*.toml')}
    if not expected:
        raise RuntimeError('no configuration templates found in the source tree')
    with zipfile.ZipFile(wheel) as archive:
        packaged = {Path(name).name for name in archive.namelist() if '/templates/' in name}
        missing = sorted(expected - packaged)
        if missing:
            raise RuntimeError('deployment templates missing from the wheel: '
                               + ', '.join(missing))
        if any(p.endswith(('.secret', '.mmdb', '.db', '.sqlite3')) for p in archive.namelist()):
            raise RuntimeError('private runtime artifact in wheel')


def write_checksums(output):
    rows = [f'{sha(path)}  {path.name}' for path in sorted(output.iterdir())
            if path.is_file() and path.name != 'SHA256SUMS']
    (output/'SHA256SUMS').write_text('\n'.join(rows)+'\n', encoding='utf-8')
    return rows


def write_sbom(output):
    """The CycloneDX inventory, schema-validated before it is written.

    P18 split this out of `build()` so that it can be produced without the
    two-pass reproducible build. `.python-version` pins an exact patch release,
    and on a machine where that interpreter cannot be obtained `uv build` refuses —
    correctly, because the reproducibility claim depends on it. An SBOM does not
    depend on it, and refusing to describe the dependencies because the
    interpreter is a patch behind would be a strange place to stop.
    """
    metadata = tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))['project']
    # Runtime extras, not CI/build dependencies. All pins come from the frozen export.
    import re
    pinned = re.findall(r'^([a-zA-Z0-9_-]+)==([^\s]+)', (ROOT/'requirements/runtime.txt').read_text(), re.MULTILINE)
    components = [{'type': 'library', 'name': name, 'version': version, 'bom-ref': 'pkg:pypi/'+name+'@'+version,
                   'purl': 'pkg:pypi/'+name+'@'+version} for name, version in pinned]
    license_metadata = {'scapy': 'GPL-2.0-only', 'maxminddb': 'Apache-2.0', 'ipwhois': 'BSD',
                        'dnspython': 'ISC', 'defusedxml': 'PSFL', 'flatbuffers': 'Apache-2.0',
                        'ml-dtypes': 'Apache-2.0', 'numpy': 'BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0', 'onnx': 'Apache-2.0',
                        'onnxruntime': 'MIT', 'packaging': 'Apache-2.0 OR BSD-2-Clause',
                        'protobuf': 'BSD-3-Clause', 'typing-extensions': 'PSF-2.0'}
    for component in components:
        component['licenses'] = [{'license': {'name': license_metadata[component['name']]}}]
    base = next(line.split()[1] for line in (ROOT/'Dockerfile').read_text().splitlines() if line.startswith('FROM python:'))
    # P18: the project licence is read from pyproject, not restated here. This
    # property used to read "not approved; release blocked", which stayed true in
    # the code long after P16 settled the licence — so every generated SBOM carried
    # a wrong machine-readable claim about an MIT project. Provenance is the one
    # thing an SBOM exists to get right.
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'metadata': {'component': {'type': 'application', 'name': metadata['name'], 'version': metadata['version'],
                                   'licenses': [{'license': {'id': metadata['license']}}]},
                     'properties': [{'name': 'e4e:scope', 'value': 'Python wheel plus optional capture/enrichment/ML dependencies; no training or container OS inventory'},
                                    {'name': 'e4e:container-base-reference', 'value': base},
                                    {'name': 'e4e:container-state', 'value': 'template only; image not built by this script'},
                                    {'name': 'e4e:project-license', 'value': metadata['license']}]},
        'components': components}
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    encoded_sbom = json.dumps(sbom, indent=2)+'\n'
    if JsonStrictValidator(SchemaVersion.V1_6).validate_str(encoded_sbom):
        raise RuntimeError('generated SBOM failed CycloneDX 1.6 schema validation')
    (output/'sbom.cdx.json').write_text(encoded_sbom, encoding='utf-8')
    return output/'sbom.cdx.json'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--uv', default='uv')
    parser.add_argument('--sbom-only', action='store_true',
                        help='write the SBOM and checksums over an existing output '
                             'directory; do not build, and claim no reproducibility')
    parser.add_argument('--checksums-only', action='store_true',
                        help='write SHA256SUMS over an existing output directory')
    args = parser.parse_args()
    target = args.output.resolve()
    if args.sbom_only or args.checksums_only:
        if args.sbom_only:
            wheel = next(target.glob('*.whl'), None)
            if wheel is not None:
                inspect_wheel(wheel)
            write_sbom(target)
        rows = write_checksums(target)
        print(json.dumps({'artifacts': str(target), 'reproducible': None,
                          'sbom': bool(args.sbom_only), 'checksums': len(rows)}))
    else:
        print(json.dumps(build(target, args.uv)))
