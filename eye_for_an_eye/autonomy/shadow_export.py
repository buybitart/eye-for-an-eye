"""Evidence for somebody else to evaluate. P15.5R §8, §9, §10, §11.

### What this is for

Every locked benchmark P15 produced was synthetic. The next thing this project
needs is evidence from a real deployment — what ordinary traffic on a real site
looks like to this decision path, which hard negatives nobody thought of, how
the profiles behave. That evidence has to leave the sensor in a form somebody
can evaluate without it becoming a record of who visited.

So: derived from the same `PipelineOutcome` the journal writes, through the same
bounded writer, in the same inspectable format. §8 is explicit that this must
not be a second evaluation-only data path, and the reason is the one this whole
cycle is about — a second path is a path that can disagree with the first, and
the disagreement is invisible from either side.

### The difference from the journal

The journal is *forensic*: the full record, for answering "why was this blocked"
about one decision, on the operator's own machine. This is *analytic*: a reduced,
pseudonymous row per decision, meant to be aggregated, shipped to an evaluation
tool and looked at in thousands. The journal keeps the raw address when the
operator asks for it; this never does, and it coarsens the timestamp, because a
precise time and a stable identifier together are a re-identification tool even
when neither is alone.

### On labels, which is the part that matters most

There is a `review` block in every row and it is **empty**. §9: a system decision
is never ground truth. `would_action = TEMP_BLOCK` does not mean malicious,
`ALLOW` does not mean benign, and an export that filled those in would produce a
training set whose labels were the thing being measured — a model that learned
to agree with itself and a benchmark that could never disagree.

Labels arrive later, from outside, attached by a person who knows something the
system does not: this is our monitoring host, that was a controlled test client,
this one was a confirmed incident. `label`, `label_source` and `label_confidence`
are the three fields that carry that, and every one of them stays null until
somebody who is not this software fills it in.
"""
import time

from .bounded_jsonl import BoundedJsonlWriter, WriterLimits
from .record import pseudonym

#: 2 as of P15S: every row now carries a `provenance` block. A version 1 row
#: does not, and a reader must not treat one as though it did — "this came from
#: a real deployment" and "this came from a controlled test" were
#: indistinguishable in version 1, which is the whole reason the block exists.
#: So this is a bump rather than a quiet addition, and an unknown version still
#: means refuse the row.
SHADOW_EXPORT_SCHEMA_VERSION = 2

#: §25. The export sits below the audit journal in the priority order, so it is
#: given the shorter write budget: it is the first thing to be dropped when
#: storage is struggling, and the drops are counted and visible.
EXPORT_SLOW_WRITE_SECONDS = 0.05

#: How coarse a timestamp is kept. An exact time plus a stable pseudonym is a
#: re-identification tool even though neither is one alone, and nothing an
#: evaluation of this evidence asks needs better than an hour.
TIMESTAMP_BUCKET_SECONDS = 3600

#: The label fields, named once. They exist in every row and are never written
#: by this software (§9).
UNLABELLED = {'label': None, 'label_source': None, 'label_confidence': None}

# --- provenance (P15S §12, §13) ----------------------------------------------
#
# The vocabulary is `dataset/schema.py`'s, not a new one. A row this sensor
# writes has to be ingestible by the dataset tooling that already exists, and a
# second set of names for the same four ideas is how two vocabularies drift
# until somebody writes a translation table nobody maintains.
#
# It is restated here rather than imported because `dataset/` is a development
# tree and is **not installed with the package** — the sensor cannot import it,
# and a runtime that tried would fail on a real deployment and not in any test
# run from the repository root. `tests/test_p15s_provenance.py` asserts these
# constants equal the dataset schema's, so a drift fails the build instead of
# producing evidence the dataset tooling silently refuses.

#: This sensor never reviews anything, so every row it writes is unlabelled
#: shadow. `SHADOW_REVIEWED` exists in the dataset schema and is reached by a
#: person attaching a label later, never by this software (§9, §14).
SOURCE_TYPE = 'SHADOW_UNLABELED'

#: How the row arrived, in `dataset.schema.INGESTION_MODES` spelling.
INGESTION = 'shadow_export'

#: Stated rather than left blank: an evaluation that cannot say where its labels
#: came from has no labels.
LABEL_AUTHORITY = 'none: observation without ground truth'

#: §31. Which collection this row belongs to. A controlled positive test against
#: an owned asset produces real runtime evidence and is *not* benign population
#: evidence, so the two are separated at the point of writing rather than by a
#: timestamp range somebody reconstructs afterwards.
REAL_SHADOW = 'real_shadow'
CONTROLLED_POSITIVE = 'controlled_positive'
COLLECTIONS = (REAL_SHADOW, CONTROLLED_POSITIVE)

#: How many reason codes an analytic row carries. The journal keeps all of them;
#: this is the analytic row's bound. It is named rather than written inline
#: because `autonomy/shadow_reconcile.py` compares the two files against each
#: other and has to be able to tell this bound from a disagreement.
EXPORT_REASON_CODE_LIMIT = 16

#: Every key the provenance block can contain. §13: none of these may become a
#: model feature, and `dataset.schema.NEVER_MODEL_INPUT` is what enforces that
#: on the dataset side — the test file checks this list against it.
PROVENANCE_KEYS = ('source_type', 'ingestion', 'label_authority', 'collection',
                   'sensor_placement', 'segment_id', 'scenario_kind')


def bucket(timestamp, *, size=TIMESTAMP_BUCKET_SECONDS):
    """A timestamp coarsened to the start of its bucket, as an ISO string."""
    import datetime as dt
    if isinstance(timestamp, str):
        try:
            moment = dt.datetime.fromisoformat(timestamp)
        except ValueError:
            return None
    elif isinstance(timestamp, (int, float)):
        moment = dt.datetime.fromtimestamp(float(timestamp), dt.timezone.utc)
    else:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    epoch = int(moment.timestamp())
    return dt.datetime.fromtimestamp(epoch - (epoch % int(size)),
                                     dt.timezone.utc).isoformat()


class ShadowExport:
    """One analytic row per decision, bounded and pseudonymous.

    Holds no privilege, writes only locally, and sends nothing anywhere: §2's
    "local filesystem only, no remote telemetry" applies here as much as to the
    journal. Getting the evidence off the machine is the operator's deliberate
    act, not this software's.
    """

    schema_version = SHADOW_EXPORT_SCHEMA_VERSION

    def __init__(self, path, *, limits=None, secret=None, clock=time.time,
                 timestamp_bucket=TIMESTAMP_BUCKET_SECONDS,
                 collection=REAL_SHADOW, sensor_placement='', segment_id=''):
        self.writer = BoundedJsonlWriter(
            path,
            limits=limits or WriterLimits(
                slow_write_seconds=EXPORT_SLOW_WRITE_SECONDS),
            clock=clock)
        self.secret = secret
        self.clock = clock
        self.timestamp_bucket = int(timestamp_bucket)
        if collection not in COLLECTIONS:
            # Refused rather than defaulted. A typo that silently became
            # `real_shadow` would file a controlled scan into the benign
            # population, which is the one mistake this field exists to prevent.
            raise ValueError(f'unknown collection {collection!r}; '
                             f'expected one of {COLLECTIONS}')
        self.collection = collection
        self.sensor_placement = str(sensor_placement)[:120]
        self.segment_id = str(segment_id)[:64]

    def provenance(self):
        """Where this row came from. P15S §12, §13.

        Fixed for the life of the writer, so a row cannot change collection
        half-way through a file. Changing it needs a configuration change and a
        restart, which §46 already says starts a new evidence segment.
        """
        return {'source_type': SOURCE_TYPE,
                'ingestion': INGESTION,
                'label_authority': LABEL_AUTHORITY,
                'collection': self.collection,
                'sensor_placement': self.sensor_placement,
                'segment_id': self.segment_id,
                'scenario_kind': 'observed'}

    @property
    def path(self):
        return self.writer.path

    @property
    def counters(self):
        return self.writer.counters

    @property
    def last_error(self):
        return self.writer.last_error

    # -- the row -------------------------------------------------------------

    def row(self, outcome, *, component_health=None):
        """One export row. Separated so a test can read it without writing it.

        Every field here is derived from the decision the runtime already made.
        Nothing is recomputed, nothing is re-derived from raw traffic, and
        nothing is invented — which is what §8's "derived from runtime
        DecisionRecords" means in practice.
        """
        record = outcome.record
        decision = record.explain()
        resolution = outcome.resolution
        return {
            'shadow_export_schema_version': SHADOW_EXPORT_SCHEMA_VERSION,
            # §13. Enough to tell a real deployment's row from a controlled
            # test's without reconstructing it from timestamps afterwards.
            'provenance': self.provenance(),
            'decision_id': record.decision_id,
            # Coarsened, deliberately. See TIMESTAMP_BUCKET_SECONDS.
            'timestamp_bucket': bucket(decision.get('timestamp'),
                                       size=self.timestamp_bucket),
            'bucket_seconds': self.timestamp_bucket,

            # -- who and where, pseudonymously -------------------------------
            'source_pseudonym': record.source_pseudonym,
            'site_pseudonym': (pseudonym(resolution.site_id, self.secret)
                               if resolution.site_id else None),
            'scope': resolution.scope,
            'profile_type': resolution.profile.name,

            # -- what was observed -------------------------------------------
            'features': {
                'schema_version': decision['features']['schema_version'],
                'observations': decision['features']['observations'],
                'observation_seconds': decision['features']['observation_seconds'],
                'data_quality': decision['features']['data_quality'],
                # Per-feature contributions: derived, bounded, and already the
                # only feature-shaped thing the record carries. The raw vector
                # is deliberately not here — a sanitised derived set is what §8
                # asks for, and contributions are that set.
                'contributions': decision['math']['contributions'],
            },
            'math_risk': decision['math']['risk'],
            'math_version': decision['math']['version'],
            'persistence': decision['math']['persistence'],
            'evidence_families': decision['evidence']['signal_families'],
            'signal_diversity': decision['evidence']['signal_diversity'],
            'behavioural_diversity': decision['evidence']['behavioural_diversity'],
            'evidence_band': decision['evidence']['band'],

            # -- what was computed -------------------------------------------
            'calibrated': decision['model']['calibrated'],
            'calibrated_probability': decision['model']['calibrated_probability'],
            'calibration_version': decision['model']['calibration_version'],
            'conservative_probability': decision['cost']['conservative_probability'],
            'ood_status': decision['model']['ood_status'],
            'ood_score': decision['model']['ood_score'],
            'drift_status': decision['model']['drift_status'],
            'model_health': decision['model']['health'],
            'uncertainty': decision['uncertainty'],
            'maturity': {'gates': decision['gates'],
                         'failed_assumptions': decision['assumptions']['failed']},
            'expected_loss': {'threshold': decision['cost']['threshold'],
                              'decision_margin': decision['cost']['decision_margin'],
                              'loss_allow': decision['cost']['loss_allow'],
                              'loss_block': decision['cost']['loss_block'],
                              'cost_policy_digest': decision['cost']['policy_digest']},
            'policy_guard': decision['policy_guard'],

            # -- what the system would have done, and what it did -------------
            #
            # Two separate fields on purpose. In shadow they differ, and the
            # difference is the whole point of a shadow deployment.
            'would_action': record.action,
            'actual_action': ('TEMP_BLOCK' if outcome.enforced else 'NONE'),
            'shadow': bool(record.shadow),
            'enforcement_withheld': outcome.enforcement_withheld,
            'reason_codes': list(record.reason_codes)[:EXPORT_REASON_CODE_LIMIT],
            'component_health': dict(component_health or {}),

            # -- ground truth, which this software never supplies -------------
            'review': dict(UNLABELLED),
            'label_policy': ('a system decision is never ground truth. '
                             'would_action is not a label, actual_action is not '
                             'a label, and these three fields are filled in by a '
                             'person from evidence this software does not have'),
        }

    def write(self, outcome, *, component_health=None):
        """Append one row. Returns whether it landed. Never raises.

        A `False` here is not a fault in the decision — it means the export is
        behind or storage is refusing, and §11 is explicit that runtime
        availability wins. Nothing upstream acts on the result.
        """
        try:
            row = self.row(outcome, component_health=component_health)
        except Exception as exc:                                   # noqa: BLE001
            self.writer.counters['failed'] += 1
            self.writer.last_error = f'{type(exc).__name__}: {exc}'[:200]
            return False
        return self.writer.write(row)

    # -- state ---------------------------------------------------------------

    def status(self):
        body = self.writer.status()
        body.update({
            'shadow_export_schema_version': SHADOW_EXPORT_SCHEMA_VERSION,
            'timestamp_bucket_seconds': self.timestamp_bucket,
            'pseudonym_secret_configured': self.secret is not None,
            'labels': 'never written by this software',
            'note': ('derived analytic rows for independent evaluation. Local '
                     'only; nothing here is sent anywhere'),
        })
        return body

    def metrics(self):
        return {'shadow_export_rows_total': self.counters['written'],
                'shadow_export_failures_total': self.counters['failed'],
                'shadow_export_dropped_total': self.counters['dropped_backpressure'],
                'shadow_export_bytes': self.writer.total_bytes}

    def close(self):
        self.writer.close()


def from_config(config, *, clock=time.time):
    """The export this configuration asks for, or `None`. Off by default."""
    settings = getattr(config, 'autonomy', None)
    path = str(getattr(settings, 'shadow_export_path', '') or '') if settings else ''
    if not path:
        return None
    secret = None
    secret_file = str(getattr(settings, 'pseudonym_secret_file', '') or '')
    if secret_file:
        try:
            from pathlib import Path
            secret = Path(secret_file).read_bytes().strip() or None
        except OSError:
            secret = None
    return ShadowExport(
        path,
        limits=WriterLimits(
            max_file_bytes=int(getattr(settings, 'shadow_export_max_file_bytes',
                                       WriterLimits.max_file_bytes)),
            max_files=int(getattr(settings, 'shadow_export_max_files',
                                  WriterLimits.max_files)),
            max_total_bytes=int(getattr(settings, 'shadow_export_max_total_bytes',
                                        WriterLimits.max_total_bytes)),
            max_records=int(getattr(settings, 'shadow_export_max_records',
                                    WriterLimits.max_records)),
            slow_write_seconds=EXPORT_SLOW_WRITE_SECONDS),
        collection=str(getattr(settings, 'shadow_export_collection', REAL_SHADOW)
                       or REAL_SHADOW),
        sensor_placement=str(getattr(settings, 'shadow_export_placement', '') or ''),
        segment_id=str(getattr(settings, 'shadow_export_segment', '') or ''),
        secret=secret, clock=clock,
        timestamp_bucket=int(getattr(settings, 'shadow_export_bucket_seconds',
                                     TIMESTAMP_BUCKET_SECONDS)))
