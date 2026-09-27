"""Versioned dataset schema and the canonical ML feature contract.

There is exactly one FeatureVector implementation in this project. This module reuses
`eye_for_an_eye.decision.features` and never restates a formula, so a dataset row and a
runtime tensor cannot drift apart. It also names, once, which columns may reach a model
and why every excluded column is excluded.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from eye_for_an_eye.decision.features import (INPUT_ORDER, MODEL_SCHEMAS, NAMES, SCHEMA_1_NAMES,
                                              SCHEMA_VERSION, SPEC, FeatureVector, upgrade)

#: 2 adds `site_group`, which P12 uses to filter and evaluate per site.
#: Version 1 files are still readable: the column is optional on read and
#: absent means "written before sites existed", not "no site".
DATASET_SCHEMA_VERSION = 2
FEATURE_SCHEMA_VERSION = SCHEMA_VERSION
MODEL_FEATURE_LIST_VERSION = 1

# --- labels ------------------------------------------------------------------
BENIGN, MALICIOUS = 'benign_like', 'malicious_automation_like'
UNCERTAIN, UNLABELED = 'uncertain', 'unlabeled'
SUPERVISED_LABELS = (BENIGN, MALICIOUS)
ALL_LABELS = (BENIGN, MALICIOUS, UNCERTAIN, UNLABELED)
BINARY_CODE = {BENIGN: 0, MALICIOUS: 1}
LABEL_MEANING = ('a label describes observed behaviour in one window, not a person, an actor, an '
                 'intent or a confirmed attack')

LABEL_SOURCES = ('controlled_scenario', 'manual_review', 'trusted_fixture', 'synthetic_generator')
# Shadow observations carry no ground truth at all. They are admitted only into the unlabelled
# pool, and only under a source that says exactly what they are.
UNLABELED_SOURCES = ('shadow_observation', 'unlabelled_capture')
ALL_LABEL_SOURCES = LABEL_SOURCES + UNLABELED_SOURCES
# A decision this system made is never ground truth for training this system.
FORBIDDEN_LABEL_SOURCES = ('shadow_decision', 'model_score', 'math_score', 'risk_threshold', 'blocked',
                           'automatically_blocked', 'firewall', 'previous_model', 'self_labelled')
CONFIDENCES = ('HIGH', 'MEDIUM', 'LOW')
# Only deterministic controlled ground truth is HIGH.
# Where a row came from and what authority its label has. Never a model feature.
LAB, PCAP = 'LAB', 'PCAP'
SHADOW_REVIEWED, SHADOW_UNLABELED = 'SHADOW_REVIEWED', 'SHADOW_UNLABELED'
SOURCE_TYPES = (LAB, PCAP, SHADOW_REVIEWED, SHADOW_UNLABELED)
SHADOW_TYPES = (SHADOW_REVIEWED, SHADOW_UNLABELED)
SOURCE_ROLES = {
    LAB: 'high label confidence, lower realism: controlled behaviour with known ground truth',
    PCAP: 'higher realism at packet level; label quality depends entirely on capture provenance',
    SHADOW_REVIEWED: 'deployment realism with a human label; the only shadow rows eligible for training',
    SHADOW_UNLABELED: 'deployment realism with no ground truth; never enters a supervised split',
}
# Which grouping key keeps correlated rows together, per source.
GROUP_KEY = {LAB: 'source_group', PCAP: 'capture_group',
             SHADOW_REVIEWED: 'source_group', SHADOW_UNLABELED: 'source_group'}
SOURCE_KINDS = ('controlled_lab', 'pcap', 'shadow')
INGESTION_MODES = ('synthetic_capture', 'synthetic_event', 'live_loopback', 'capture_fixture',
                   'shadow_export')

# --- feature contract --------------------------------------------------------
CEILINGS = {name: ceiling for name, ceiling, *_ in SPEC}
TRANSFORMS = {name: transform for name, _, transform, *_ in SPEC}
UNITS = {name: units for name, _, _, units, _ in SPEC}
WINDOWS = {name: window for name, *_, window in SPEC}
FEATURE_RANGE = (0.0, 1.0)
FEATURE_DTYPE = 'float32'
MISSING_POLICY = ('every value carries an explicit availability mask; an unobserved value is stored as '
                  'missing and never silently imputed as an observed zero')

EXCLUDED_FROM_MODEL = {
    'previous_risk': 'feedback loop: this is the decayed output of this system, not an observation',
    'available_previous_risk': 'availability mask of an excluded feedback column',
}
MODEL_FEATURES = tuple(name for name in INPUT_ORDER if name not in EXCLUDED_FROM_MODEL)
MODEL_INDEX = tuple(INPUT_ORDER.index(name) for name in MODEL_FEATURES)
EXCLUDED_INDEX = tuple(INPUT_ORDER.index(name) for name in EXCLUDED_FROM_MODEL)


def model_features_for(feature_schema_version):
    """The model input names a dataset of that schema version declares.

    A manifest describes the dataset it was written for, so it must be read
    against the schema *it* names rather than against whichever one this build
    has. Without this, appending a column would make every historical manifest
    look wrong — and "the manifest disagrees with the code" is exactly the alarm
    that must stay meaningful, so it may not be allowed to fire for the one
    reason that is not a defect.
    """
    order = MODEL_SCHEMAS.get(feature_schema_version)
    if order is None:
        raise ValueError(f'unknown feature schema {feature_schema_version}')
    return tuple(name for name in order if name not in EXCLUDED_FROM_MODEL)


def feature_names_for(feature_schema_version):
    """Every feature name of that schema, availability flags excluded.

    This is the raw column list a manifest records, so it includes columns the
    model may not see — `previous_risk` among them. `model_features_for` is the
    narrower question.
    """
    order = MODEL_SCHEMAS.get(feature_schema_version)
    if order is None:
        raise ValueError(f'unknown feature schema {feature_schema_version}')
    return tuple(name for name in order if not name.startswith('available_'))

# Columns that exist in the dataset file or the wider system and may never become model input.
# The reason is recorded so the exclusion survives a future contributor asking "why not?".
NEVER_MODEL_INPUT = {
    'src_ip': 'identity leakage: the model must learn behaviour, not which address it came from',
    'src_ip_numeric': 'identity leakage in numeric disguise',
    'dst_ip': 'sensor identity, not source behaviour',
    'source_group': 'pseudonymous source identity; a model could memorise the source',
    'source_group_hash': 'the pseudonym is metadata only, never a feature',
    # P12. A site identifier is the sharpest leakage available: a model given it
    # learns "traffic to the admin site is malicious", which is a fact about one
    # deployment's shape and not about behaviour at all. It would score well on
    # the data it was trained on and fail on the first site it had not seen.
    'site_group': 'site identity; a model would learn which site rather than what happened',
    'site_id': 'site identity, in its configured spelling',
    'domain': 'site identity by another name; a domain is not behaviour',
    'host': 'the Host header is client-controlled and identifies a site, not behaviour',
    'profile_type': 'website, api or admin is a configuration choice, never a label',
    'scenario_id': 'label leakage: the scenario name determines the label',
    'scenario_group': 'label leakage and split metadata',
    'scenario_family': 'label leakage',
    'label': 'the target',
    'label_source': 'label leakage',
    'label_confidence': 'label leakage',
    'provenance': 'label and environment leakage',
    'sample_id': 'identity of the row itself',
    'timestamp': 'harness identity: generation time separates classes only in the lab',
    'split': 'split metadata',
    'source_type': 'environment identity: LAB, PCAP or SHADOW is where a row came from, not behaviour',
    'capture_group': 'capture identity; a model could memorise which capture a window came from',
    'capture_id': 'capture identity',
    'sensor_id': 'sensor identity',
    'container_id': 'lab environment identity',
    'pcap_filename': 'capture identity, and a filename is not evidence',
    'generator_version': 'harness identity: metadata only, never an input',
    'seed': 'harness identity',
    'run_id': 'harness identity',
    'would_block': 'decision feedback loop',
    'final_score': 'decision feedback loop',
    'asn': 'identity and weak causal signal; also a bias source',
    'as_name': 'identity and weak causal signal',
    'provider': 'identity and weak causal signal',
    'country': 'bias and weak causal signal; geography is not behaviour',
    'city': 'bias and weak causal signal',
    'username': 'credential content must never enter the dataset',
    'hostname': 'identity',
    'previous_action': 'decision feedback loop',
    'action': 'decision feedback loop',
    'blocked': 'label leakage from enforcement state',
    'block_status': 'label leakage from enforcement state',
    'rate_limited': 'decision feedback loop',
    'firewall_status': 'label leakage from enforcement state',
    'would_enforce': 'decision feedback loop',
    'final_risk': 'decision feedback loop',
    'risk': 'decision feedback loop',
    'math_score': 'this system\'s own mathematical baseline output',
    'ml_score': 'a previous model\'s output',
    'previous_risk': EXCLUDED_FROM_MODEL['previous_risk'],
    'available_previous_risk': EXCLUDED_FROM_MODEL['available_previous_risk'],
}
BEHAVIOUR_FEATURES = tuple(name for name in MODEL_FEATURES if not name.startswith('available_'))
AVAILABILITY_FEATURES = tuple(name for name in MODEL_FEATURES if name.startswith('available_'))
# Schema 1 carries no TTL / IP-ID / TCP-timestamp / p0f column, so no fingerprint-derived
# feature can dominate a model built on it. Kept explicit so a future schema cannot drift.
FINGERPRINT_DERIVED = ()

if set(MODEL_FEATURES) & set(NEVER_MODEL_INPUT):
    raise RuntimeError('model feature contract contradicts its own exclusion list')


@dataclass(slots=True)
class DatasetSample:
    """One source, one observation window, one row.

    `features` is the production FeatureVector. Everything else is metadata: it exists for
    grouping, splitting, provenance and review, and none of it is model input.
    """
    dataset_version: str
    feature_schema_version: int
    sample_id: str
    timestamp: datetime
    source_type: str
    scenario_group: str | None
    source_group: str | None
    capture_group: str | None
    label: str
    label_source: str | None
    label_confidence: str
    features: FeatureVector
    provenance: dict = field(default_factory=dict)
    scenario_id: str | None = None
    split: str | None = None
    dataset_schema_version: int = DATASET_SCHEMA_VERSION
    #: P12: which site this window came from, as a pseudonymous group. Metadata
    #: for filtering, splitting and per-site evaluation — never model input, and
    #: listed in NEVER_MODEL_INPUT above so it cannot become one by accident.
    #: Optional, so every row written before P12 still loads.
    site_group: str | None = None

    def __post_init__(self):
        if not isinstance(self.features, FeatureVector):
            raise ValueError('DatasetSample requires a production FeatureVector')
        # The vector always carries the schema this build constructs. The row's
        # own `feature_schema_version` records what the file was written as, and
        # may legitimately be older: a corpus predating an appended column is
        # read with that column explicitly unknown rather than refused. What is
        # never allowed is a vector claiming a schema this build cannot build.
        if self.features.schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError('feature schema mismatch')
        if self.feature_schema_version > FEATURE_SCHEMA_VERSION:
            raise ValueError('sample declares a feature schema newer than this build')
        if self.source_type not in SOURCE_TYPES:
            raise ValueError('unknown source type')
        if self.label not in ALL_LABELS:
            raise ValueError('unknown label')
        if self.label_source in FORBIDDEN_LABEL_SOURCES:
            raise ValueError('a decision made by this system is not ground truth')
        if self.label_source not in ALL_LABEL_SOURCES:
            raise ValueError('unknown label source')
        if self.label_source in UNLABELED_SOURCES and self.label != UNLABELED:
            raise ValueError('an observation without ground truth may only enter the unlabelled pool')
        if self.label in SUPERVISED_LABELS and self.label_source in UNLABELED_SOURCES:
            raise ValueError('an observation without independent ground truth cannot carry a label')
        if self.source_type == SHADOW_UNLABELED and self.label != UNLABELED:
            raise ValueError('unreviewed shadow telemetry is unlabelled by definition')
        if self.source_type == SHADOW_REVIEWED and self.label_source != 'manual_review':
            raise ValueError('reviewed shadow telemetry needs a manual review as its label source')
        if self.label_confidence not in CONFIDENCES:
            raise ValueError('unknown label confidence')
        if self.label in (UNCERTAIN, UNLABELED) and self.label_confidence == 'HIGH':
            raise ValueError('an unlabelled or uncertain sample cannot carry HIGH confidence')
        if getattr(self, GROUP_KEY[self.source_type]) is None:
            raise ValueError(f'{self.source_type} rows need a {GROUP_KEY[self.source_type]}')
        for name in ('sample_id', 'scenario_group', 'source_group', 'capture_group', 'scenario_id', 'site_group'):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 200):
                raise ValueError(f'invalid {name}')
            # A control character in an identifier is the shape of CSV and log
            # injection. The CSV writer would quote it and the round trip would
            # survive, which is precisely why it is worth refusing here instead:
            # these are pseudonymous identifiers the system generates, so a
            # newline in one means something upstream is wrong, not that a real
            # identifier happens to contain it.
            if value is not None and any(ord(character) < 0x20 or ord(character) == 0x7f
                                         for character in value):
                raise ValueError(f'{name} contains a control character')
        if self.split is not None and self.split not in ('train', 'validation', 'test'):
            raise ValueError('invalid split')
        if self.timestamp.tzinfo is None:
            raise ValueError('sample timestamp requires timezone')
        if not isinstance(self.provenance, dict):
            raise ValueError('provenance must be a mapping')
        forbidden = set(self.provenance) & {'src_ip', 'dst_ip', 'username', 'password', 'payload', 'cookie'}
        if forbidden:
            raise ValueError('provenance must not carry identity or payload: ' + ', '.join(sorted(forbidden)))

    @property
    def supervised(self):
        """Eligible for supervised training: a real label from an independent source."""
        return self.label in SUPERVISED_LABELS and self.source_type != SHADOW_UNLABELED

    @property
    def group(self):
        return getattr(self, GROUP_KEY[self.source_type])

    def to_row(self):
        row = {'dataset_version': self.dataset_version, 'dataset_schema_version': self.dataset_schema_version,
               'feature_schema_version': self.feature_schema_version, 'sample_id': self.sample_id,
               'timestamp': self.timestamp.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'),
               'source_type': self.source_type,
               'scenario_id': self.scenario_id or '', 'scenario_group': self.scenario_group or '',
               'source_group': self.source_group or '', 'capture_group': self.capture_group or '',
               'site_group': self.site_group or '',
               'split': self.split or '',
               'label': self.label, 'label_source': self.label_source,
               'label_confidence': self.label_confidence,
               'sample_count': self.features.sample_count,
               'observation_seconds': round(self.features.observation_seconds, 6),
               'capped': int(self.features.capped),
               'loss_fraction': '' if self.features.loss_fraction is None else self.features.loss_fraction}
        for name, value in zip(NAMES, self.features.values, strict=True):
            row['raw_' + name] = '' if value is None else round(float(value), 9)
        row['provenance'] = self.provenance
        return row


EVIDENCE_COLUMNS = ('sample_count', 'observation_seconds', 'capped', 'loss_fraction')
RAW_COLUMNS = tuple('raw_' + name for name in NAMES)
METADATA_COLUMNS = ('dataset_version', 'dataset_schema_version', 'feature_schema_version', 'sample_id',
                    'timestamp', 'source_type', 'scenario_id', 'scenario_group', 'source_group',
                    'capture_group', 'site_group', 'split', 'label', 'label_source', 'label_confidence')
# Ordered CSV columns. `provenance` is a JSON object in the final column so it stays with the
# row without inventing a column per generator knob.
COLUMNS = METADATA_COLUMNS + EVIDENCE_COLUMNS + RAW_COLUMNS + ('provenance',)

#: The version 1 layout, kept so that datasets written before P12 still load.
#: Dropping compatibility here would strand every existing corpus — including
#: the research dataset the model was trained on — for the sake of one metadata
#: column, which is not a trade worth making.
COLUMNS_V1 = tuple(name for name in COLUMNS if name != 'site_group')

#: Layouts written before feature schema 2. The same argument as above and a
#: stronger one: every result P15.1 through P15.3 reported was measured on
#: corpora that predate the authentication columns, and a result stays
#: reproducible only while the data behind it still loads. Such a row is read
#: with its authentication features explicitly unknown — `features.upgrade` is
#: careful that "unknown" never becomes "zero failures".
RAW_COLUMNS_FEATURE_SCHEMA_1 = tuple('raw_' + name for name in SCHEMA_1_NAMES)
COLUMNS_FEATURE_SCHEMA_1 = (METADATA_COLUMNS + EVIDENCE_COLUMNS
                            + RAW_COLUMNS_FEATURE_SCHEMA_1 + ('provenance',))
COLUMNS_FEATURE_SCHEMA_1_V1 = tuple(name for name in COLUMNS_FEATURE_SCHEMA_1
                                    if name != 'site_group')
ACCEPTED_COLUMN_SETS = (COLUMNS, COLUMNS_V1,
                        COLUMNS_FEATURE_SCHEMA_1, COLUMNS_FEATURE_SCHEMA_1_V1)

#: Dataset schema versions this build can read. A row from an older corpus is
#: not a defect: the columns it lacks are ones that did not exist when it was
#: written, and refusing it would strand the data the model was trained on.
READABLE_SCHEMA_VERSIONS = (1, 2)

#: Feature schemas a stored row may declare. An older one is read with its
#: newer columns explicitly unknown (`features.upgrade`); a newer one is
#: refused, because this build cannot know what those columns mean.
READABLE_FEATURE_SCHEMA_VERSIONS = (1, 2)


def accepted_columns(fieldnames):
    """Which known layout these columns are, or None if they are neither."""
    found = tuple(fieldnames or ())
    for known in ACCEPTED_COLUMN_SETS:
        if found == known:
            return known
    return None


#: How to read the `privacy` field below. Three classes, because there are three
#: kinds of thing here and conflating them is how a column nobody examined ends
#: up in a model.
PRIVACY_CLASSES = {
    'behavioural_aggregate': ('a bounded count, rate or fraction describing one source '
                              'in one time window; no address, no payload, no content, '
                              'no account and no header text'),
    'availability_mask': 'one bit saying whether the paired value was observed at all',
    'identity_or_decision': ('identity, provenance, or something this system itself '
                             'decided; never a model input under any configuration'),
}


def _feature_family(name):
    """Which evidence family a column belongs to, for the runtime decision record.

    A mask inherits the family of the value it masks: it describes the same
    phenomenon, one step removed. A column no family claims is reported as
    UNASSIGNED rather than guessed at — an unmapped feature contributes to no
    family at runtime, and saying so here keeps the two views consistent.
    """
    from eye_for_an_eye.autonomy.evidence import FEATURE_FAMILIES
    base = name[len('available_'):] if name.startswith('available_') else name
    return FEATURE_FAMILIES.get(base, 'UNASSIGNED')


def model_feature_document():
    """Content of datasets/model_features_v1.json: the ordered list plus every reason.

    This is the machine-readable data dictionary. For every column it carries the
    name, type, unit, meaning, range, missing-value semantics, source, evidence
    family, whether a model may see it, and a privacy classification.
    """
    return {
        'model_feature_list_version': MODEL_FEATURE_LIST_VERSION,
        'feature_schema_version': FEATURE_SCHEMA_VERSION,
        'tensor_contract': {'input_name': 'features', 'dtype': FEATURE_DTYPE,
                            'shape': [1, len(INPUT_ORDER)], 'order': list(INPUT_ORDER),
                            'range': list(FEATURE_RANGE)},
        'privacy_classes': dict(PRIVACY_CLASSES),
        'model_features': [
            {'index': position, 'name': name, 'tensor_index': INPUT_ORDER.index(name),
             'kind': 'availability_mask' if name.startswith('available_') else 'behaviour',
             'units': UNITS.get(name, 'availability mask 0 or 1'),
             'window_seconds': WINDOWS.get(name, WINDOWS.get(name[len('available_'):], 0)),
             'raw_ceiling': CEILINGS.get(name), 'transform': TRANSFORMS.get(name, 'mask'),
             'feature_family': _feature_family(name),
             'privacy': ('availability_mask' if name.startswith('available_')
                         else 'behavioural_aggregate'),
             'source': 'bounded per-source correlation state in one observation window',
             'model_usage': 'input',
             'reason_for_inclusion': ('observed behaviour of one source in one bounded window'
                                      if not name.startswith('available_') else
                                      'tells the model the value was observed rather than absent')}
            for position, name in enumerate(MODEL_FEATURES)],
        'excluded_from_model': [{'name': name, 'reason': reason, 'model_usage': 'excluded'}
                                for name, reason in sorted(EXCLUDED_FROM_MODEL.items())],
        'never_model_input': [{'name': name, 'reason': reason,
                               'privacy': 'identity_or_decision',
                               'model_usage': 'never'}
                              for name, reason in sorted(NEVER_MODEL_INPUT.items())],
        'missing_value_policy': MISSING_POLICY,
        'label_schema': {'0': BENIGN, '1': MALICIOUS, 'meaning': LABEL_MEANING},
        'notes': ['one implementation: dataset rows and runtime tensors both come from '
                  'eye_for_an_eye.decision.features.FeatureTransformer',
                  'schema 1 contains no TTL, IP-ID, TCP-timestamp or p0f column',
                  'feature_family names the evidence family a column contributes to at '
                  'decision time; a family contributes at most once however many of its '
                  'features are present'],
    }


def select(tensor):
    if len(tensor) != len(INPUT_ORDER):
        raise ValueError('full feature tensor required')
    return [float(tensor[index]) for index in MODEL_INDEX]


def expand(values, fill=0.0):
    row = [fill] * len(INPUT_ORDER)
    for index, value in zip(MODEL_INDEX, values, strict=True):
        row[index] = float(value)
    return row


def sample_from_row(row, provenance=None):
    """Rebuild a DatasetSample from a parsed CSV row."""
    # A row written before feature schema 2 carries no authentication columns.
    # `upgrade` appends explicit unknowns rather than zeros: the capture made no
    # observation of authentication, which is a different statement from "no
    # authentication failed" and the availability flags keep them apart.
    present = [name for name in NAMES if 'raw_' + name in row]
    values = upgrade(tuple(None if row['raw_' + name] == '' else float(row['raw_' + name])
                           for name in present))
    vector = FeatureVector(values, float(row['observation_seconds']), int(row['sample_count']),
                           bool(int(row['capped'])),
                           None if row['loss_fraction'] == '' else float(row['loss_fraction']))
    return DatasetSample(
        dataset_version=row['dataset_version'], feature_schema_version=int(row['feature_schema_version']),
        sample_id=row['sample_id'],
        timestamp=datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')),
        source_type=row['source_type'], scenario_group=row['scenario_group'] or None,
        source_group=row['source_group'] or None, capture_group=row['capture_group'] or None,
        # Absent in a version 1 file, which means "written before sites existed"
        # rather than "belongs to no site". `.get` is the whole compatibility.
        site_group=row.get('site_group') or None,
        label=row['label'], label_source=row['label_source'], label_confidence=row['label_confidence'],
        features=vector, provenance=provenance if provenance is not None else {},
        scenario_id=row['scenario_id'] or None, split=row['split'] or None,
        dataset_schema_version=int(row['dataset_schema_version']))
