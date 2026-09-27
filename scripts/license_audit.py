"""Read licence metadata from installed distributions. Reports; never concludes.

`THIRD_PARTY_NOTICES.md` is kept from this output rather than by hand, so a new
dependency turns into a visible diff instead of a quiet omission.

What this does not do is decide anything. Package metadata is often imprecise —
one dependency here declares only "BSD", another puts a copyright header where an
SPDX expression belongs — so the output is an inventory to check against the
licence file inside each wheel, not a compatibility verdict.
"""
import argparse
import importlib.metadata as metadata
import json
import sys

#: Which extra pulls each package in. Transitive entries name their parent, so a
#: reader can see why something is present without resolving the graph again.
PACKAGES = {
    'scapy': 'capture',
    'maxminddb': 'enrichment',
    'ipwhois': 'enrichment',
    'dnspython': 'transitive (ipwhois)',
    'defusedxml': 'transitive (ipwhois)',
    'onnxruntime': 'ml',
    'onnx': 'ml',
    'numpy': 'ml',
    'protobuf': 'transitive (onnx)',
    'flatbuffers': 'transitive (onnxruntime)',
    'ml_dtypes': 'transitive (onnxruntime)',
    'scikit-learn': 'ml-training',
    'scipy': 'transitive (scikit-learn)',
    'joblib': 'transitive (scikit-learn)',
    'threadpoolctl': 'transitive (scikit-learn)',
    'skl2onnx': 'ml-training',
    'pytest': 'test',
    'ruff': 'lint',
}

#: Licences that oblige a redistributor to more than keeping a notice. Listed by
#: name rather than detected by pattern: a short list somebody maintains
#: deliberately beats a clever rule that quietly stops matching.
COPYLEFT = ('GPL', 'AGPL', 'LGPL', 'MPL', 'EPL', 'CDDL')


def declared_licence(dist):
    """The clearest licence string the metadata offers, in order of precision."""
    expression = dist.get('License-Expression')
    if expression:
        return expression.strip(), 'License-Expression'
    raw = (dist.get('License') or '').strip()
    if raw:
        first = raw.splitlines()[0].strip()
        return first, 'License'
    classifiers = [c for c in (dist.get_all('Classifier') or [])
                   if c.startswith('License ::')]
    if classifiers:
        return classifiers[0].split(' :: ')[-1], 'Classifier'
    return '', 'none'


def audit(packages=PACKAGES):
    rows = []
    for name, extra in sorted(packages.items()):
        try:
            dist = metadata.metadata(name)
        except metadata.PackageNotFoundError:
            rows.append({'package': name, 'extra': extra, 'version': None,
                         'licence': None, 'source': 'not installed',
                         'copyleft': None})
            continue
        licence, source = declared_licence(dist)
        rows.append({'package': name, 'extra': extra,
                     'version': dist.get('Version'),
                     'licence': licence or '(metadata declares none)',
                     'source': source,
                     'copyleft': any(token in licence.upper() for token in COPYLEFT)})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='license_audit',
        description='Inventory installed dependency licences. Not a legal conclusion.')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    rows = audit()
    if args.json:
        print(json.dumps({'rows': rows,
                          'note': 'metadata inventory; read the wheel LICENSE before '
                                  'redistributing anything'}, indent=2))
        return 0
    print(f'{"package":16} {"version":12} {"extra":24} licence')
    for row in rows:
        mark = ' *' if row['copyleft'] else ''
        print(f'{row["package"]:16} {str(row["version"] or "-"):12} '
              f'{row["extra"]:24} {row["licence"] or "-"}{mark}')
    copyleft = [row['package'] for row in rows if row['copyleft']]
    missing = [row['package'] for row in rows if row['source'] == 'not installed']
    print()
    if copyleft:
        print('* copyleft, and bundling it into a combined distribution carries '
              'obligations this project\'s MIT licence does not: ' + ', '.join(copyleft))
    if missing:
        print('not installed in this environment, so not audited here: '
              + ', '.join(missing))
    print('Metadata is often imprecise. For anything you redistribute, read the '
          'licence file inside the wheel.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
