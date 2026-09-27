"""Bridge between the two dataset formats this repository carries.

There are two column contracts here, and they came from different stages:

* `training.dataset` — 32 columns, numeric labels, float timestamps. The format
  the P7 baseline trainer reads.
* `dataset.schema` — 37 columns, string labels, ISO timestamps, plus provenance,
  source type, capture group and label confidence. The richer format the P8
  dataset package writes, and the one a P9 candidate dataset uses.

Neither is wrong. The newer format carries things the trainer never needed, and
the trainer's format predates them. But a P9 candidate dataset is written in the
newer format, so without a bridge the newer datasets cannot be trained on at all.

This module is that bridge and nothing more. It converts rows; it does not train,
does not relabel, and does not decide anything. Two rules it will not bend:

* Only supervised rows cross. Uncertain and unlabelled rows are dropped, because
  the trainer has no way to represent "we do not know" and would otherwise be
  handed a guess.
* A label is converted, never derived. `benign_like` becomes 0 and
  `malicious_automation_like` becomes 1; anything else is refused.
"""
from pathlib import Path

from dataset import schema as dataset_schema
from dataset import store as dataset_store

#: Columns the trainer does not have and does not need. Named here so the
#: conversion is a documented projection rather than a silent drop.
DROPPED_COLUMNS = ('dataset_schema_version', 'source_type', 'capture_group',
                   'label_confidence', 'provenance')


class BridgeError(ValueError):
    """A dataset could not be converted. Refusing is the safe outcome."""


def training_row(sample):
    """One `DatasetSample` as a training-pipeline row.

    `scenario_group` is filled from whichever grouping key this sample's source
    type actually uses, so a group-aware split keeps correlated rows together
    even for shadow and capture rows, which have no scenario of their own.
    """
    if sample.label not in dataset_schema.BINARY_CODE:
        raise BridgeError(f'{sample.label!r} is not a supervised label')
    if sample.label_source in dataset_schema.FORBIDDEN_LABEL_SOURCES:
        raise BridgeError('a decision made by this system is not ground truth')
    group = (sample.scenario_group or sample.source_group or sample.capture_group
             or sample.sample_id)
    vector = sample.features
    row = {'sample_id': sample.sample_id,
           'dataset_version': sample.dataset_version,
           'feature_schema_version': sample.feature_schema_version,
           'timestamp': sample.timestamp.timestamp(),
           'scenario_id': sample.scenario_id or '',
           'scenario_group': group,
           'source_group': sample.source_group or group,
           'split': sample.split or '',
           'label': dataset_schema.BINARY_CODE[sample.label],
           'label_source': sample.label_source,
           'sample_count': vector.sample_count,
           'observation_seconds': round(vector.observation_seconds, 6),
           'capped': int(vector.capped),
           'loss_fraction': '' if vector.loss_fraction is None else vector.loss_fraction,
           'vector': vector}
    from .dataset import RAW_COLUMNS
    for column, value in zip(RAW_COLUMNS, vector.values, strict=True):
        row[column] = '' if value is None else round(float(value), 9)
    return row


def convert(samples):
    """Supervised rows only. Returns `(rows, dropped)`.

    `dropped` counts what did not cross and why, so a caller can say out loud
    that a dataset of 2000 rows produced 1400 training rows rather than quietly
    training on fewer than expected.
    """
    rows, dropped = [], {}
    for sample in samples:
        if sample.label not in dataset_schema.SUPERVISED_LABELS:
            key = f'not_supervised_{sample.label}'
            dropped[key] = dropped.get(key, 0) + 1
            continue
        try:
            rows.append(training_row(sample))
        except BridgeError:
            dropped['refused'] = dropped.get('refused', 0) + 1
    return rows, dropped


def read_samples(path):
    """Read a dataset-package CSV, or one directory of split CSVs."""
    target = Path(path)
    if target.is_dir():
        samples = []
        for name in ('train', 'validation', 'test'):
            split = target / f'{name}.csv'
            if split.is_file():
                for sample in dataset_store.read(split):
                    if sample.split is None:
                        sample.split = name
                    samples.append(sample)
        if not samples:
            raise BridgeError(f'no train/validation/test CSV found in {target}')
        return samples
    return dataset_store.read(target)


def load(path):
    """Read a dataset-package dataset and return training-pipeline rows."""
    rows, dropped = convert(read_samples(path))
    if not rows:
        raise BridgeError('the dataset contains no supervised rows')
    return rows, dropped


def materialise(samples, directory, *, dataset_version, parent_dataset='', lineage=None):
    """Write a training-format dataset directory from dataset-package samples.

    The trainer's own writer fills in a manifest describing the synthetic corpus
    it was built for. That would be a false statement about a candidate dataset
    containing reviewed rows, so the manifest is corrected afterwards: the real
    dataset version, the real label sources, the real parent, and a note that
    this directory is a converted view rather than an original dataset.
    """
    import json
    from collections import Counter
    from . import dataset as training_dataset

    rows, dropped = convert(samples)
    if not rows:
        raise BridgeError('the dataset contains no supervised rows')
    for row in rows:
        if row['split'] not in training_dataset.SPLITS:
            raise BridgeError(f'row {row["sample_id"]} has no usable split')
    target = Path(directory)
    manifest = training_dataset.write(target, [
        {key: value for key, value in row.items() if key != 'vector'} for row in rows])

    label_sources = Counter(row['label_source'] for row in rows)
    manifest['dataset_version'] = dataset_version
    manifest['parent_dataset'] = parent_dataset
    manifest['generator'] = 'training.bridge (converted from the dataset package format)'
    manifest['source'] = ('converted view of a dataset-package dataset; the original rows '
                          'and their provenance stay in that dataset, unchanged')
    sources = sorted(label_sources)
    # One source stays a plain string, which is what every existing reader
    # expects. Several are listed, because naming only one would be untrue.
    manifest['label_source'] = sources[0] if len(sources) == 1 else sources
    manifest['label_sources'] = sources
    manifest['label_source_counts'] = dict(label_sources)
    manifest['converted_rows'] = len(rows)
    manifest['dropped_rows'] = dict(dropped)
    manifest['dropped_columns'] = list(DROPPED_COLUMNS)
    manifest['conversion_note'] = ('uncertain and unlabelled rows never cross; a label is '
                                   'converted, never derived')
    if lineage:
        manifest['lineage'] = dict(lineage)
    (target / 'dataset_manifest.json').write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + '\n', encoding='utf-8')
    return manifest
