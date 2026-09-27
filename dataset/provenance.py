"""Provenance: where a row came from and what authority its label has.

Provenance travels with every sample and reaches no model. `dataset.schema.NEVER_MODEL_INPUT`
names each of these keys with the reason it is excluded, and the validator refuses a manifest
that lists one as a model feature.

The three sources are not equivalent and this module keeps that visible:

* LAB gives high label confidence and lower realism.
* PCAP gives packet-level realism; its label is only as good as its sidecar.
* SHADOW gives deployment realism and, by default, no ground truth at all.
"""
from . import schema

PROVENANCE_KEYS = ('source_type', 'source_role', 'ingestion', 'label_authority', 'scenario_family',
                   'scenario_variant', 'run_id', 'seed', 'generator_version', 'capture_id',
                   'capture_origin', 'sensor_placement', 'collected_at', 'duration_seconds',
                   'window_horizon_seconds', 'snapshot_index', 'scenario_kind', 'analysis_only',
                   'sensor_observations', 'review')
FORBIDDEN_PROVENANCE_KEYS = ('src_ip', 'dst_ip', 'source_ip', 'ip', 'username', 'password', 'payload',
                             'cookie', 'token', 'authorization', 'body', 'command_text')


def _base(source_type, ingestion, label_authority, **extra):
    if source_type not in schema.SOURCE_TYPES:
        raise ValueError('unknown source type')
    if ingestion not in schema.INGESTION_MODES:
        raise ValueError('unknown ingestion mode')
    record = {'source_type': source_type, 'source_role': schema.SOURCE_ROLES[source_type],
              'ingestion': ingestion, 'label_authority': label_authority}
    record.update({key: value for key, value in extra.items() if value is not None})
    forbidden = set(record) & set(FORBIDDEN_PROVENANCE_KEYS)
    if forbidden:
        raise ValueError('provenance must not carry identity or content: ' + ', '.join(sorted(forbidden)))
    return record


def lab(*, scenario_family, scenario_variant, run_id, seed, generator_version, ingestion,
        duration_seconds=None, scenario_kind=None, profile_type=None):
    """Controlled behaviour. The generator decided the label before it produced the behaviour.

    `profile_type` (§41) travels here rather than in a column of its own, because
    it is evaluation metadata and provenance is where evaluation metadata lives.
    It has to travel somewhere: without it no per-profile result can be computed,
    which is the gap every cycle since P15.1 has reported and none has closed.
    Never a feature — `dataset.schema.NEVER_MODEL_INPUT` names it and
    `tests/test_p15_4_profiles.py` checks from four directions that it cannot
    reach a model.
    """
    return _base(schema.LAB, ingestion, 'controlled scenario intent, decided before generation',
                 scenario_family=scenario_family, scenario_variant=scenario_variant, run_id=run_id,
                 seed=seed, generator_version=generator_version, duration_seconds=duration_seconds,
                 scenario_kind=scenario_kind, profile_type=profile_type)


def pcap(*, capture_id, capture_origin, scenario_family=None, label_authority=None,
         generator_version=None, scenario_kind=None):
    """A capture artifact. Its sidecar carries the label; the filename never does."""
    return _base(schema.PCAP, 'capture_fixture',
                 label_authority or 'explicit capture sidecar, not the file name',
                 capture_id=capture_id, capture_origin=capture_origin, scenario_family=scenario_family,
                 generator_version=generator_version, scenario_kind=scenario_kind)


def shadow(*, sensor_placement, collected_at, reviewed=False, analysis_only=None,
           sensor_observations=None, review=None):
    """Observed telemetry. Unlabelled unless a person reviewed it."""
    source_type = schema.SHADOW_REVIEWED if reviewed else schema.SHADOW_UNLABELED
    authority = ('manual review of a sanitised behaviour summary' if reviewed
                 else 'none: observation without ground truth')
    return _base(source_type, 'shadow_export', authority, sensor_placement=sensor_placement,
                 collected_at=collected_at, analysis_only=analysis_only,
                 sensor_observations=sensor_observations, review=review, scenario_kind='observed')


def group_key(sample):
    """Which grouping key must keep this sample's correlated rows together."""
    return schema.GROUP_KEY[sample.source_type]


def group_value(sample):
    return getattr(sample, group_key(sample))
