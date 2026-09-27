"""Reading and writing dataset files.

CSV plus a JSON manifest rather than Parquet: this corpus is thousands of rows, `pyarrow` is
not in the project's locked extras, and the project keeps its dependency surface small. The
column order and the feature schema are versioned either way, so the format can change under
a new dataset version without ambiguity.
"""
import csv
import json
from pathlib import Path
from . import schema
from .manifest import file_digest

MAX_FIELD_CHARS = 4096
MAX_ROWS = 500_000


def write(path, samples):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=schema.COLUMNS, lineterminator='\n')
        writer.writeheader()
        for sample in samples:
            row = sample.to_row()
            row['provenance'] = json.dumps(row['provenance'], sort_keys=True, separators=(',', ':'))
            if len(row['provenance']) > MAX_FIELD_CHARS:
                raise ValueError('sample provenance exceeds the field budget')
            writer.writerow(row)
    return {'file': target.name, 'rows': len(samples), 'bytes': target.stat().st_size,
            'sha256': file_digest(target)}


def read(path):
    target = Path(path)
    samples = []
    with target.open(encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream)
        # Either the current layout or the version 1 one. A corpus written
        # before sites existed is not malformed; it simply predates the column.
        if schema.accepted_columns(reader.fieldnames) is None:
            raise ValueError('dataset column contract mismatch')
        for row in reader:
            if len(samples) >= MAX_ROWS:
                raise ValueError('dataset row budget exceeded')
            if any(value is None or len(value) > MAX_FIELD_CHARS for value in row.values()):
                raise ValueError('malformed dataset field')
            samples.append(schema.sample_from_row(row, json.loads(row['provenance'])))
    return samples


def write_splits(directory, parts, *, verify=True):
    root = Path(directory)
    files = {}
    for name, rows in parts.items():
        files[name] = write(root / f'{name}.csv', rows)
    if verify:
        for name, info in files.items():
            restored = read(root / info['file'])
            if len(restored) != info['rows']:
                raise ValueError(f'round trip lost rows in {name}')
    return files
