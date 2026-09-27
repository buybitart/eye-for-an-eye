"""Reading a shadow evidence period. P15S §18, §45, §50, §51, §52, §53.

Collection is the deployment's job. This module is what reads the result: it
summarises a period while it is running, freezes it when it is complete, and
verifies afterwards that the frozen files are still the ones a result was
computed from.

Named `shadow_evidence` rather than `evidence` because `autonomy/evidence.py` is
the evidence-*families* module, which answers a different question about a
single decision. This one is about a collection of them.

### The unit is a source, not a row

§18. One source produces many decision windows and they are not independent
observations of anything. A thousand windows from one monitoring host is one
piece of evidence about one monitoring host, and counting it as a thousand is
how a false-block rate acquires three digits of false precision.

So everything here aggregates to `source_pseudonym` first, and reports sources,
windows, profiles and time coverage as four separate numbers. A source counts as
would-blocked if *any* of its windows reached TEMP_BLOCK, because that is what
would have happened to it.

### Unreviewed traffic is not benign

§53, and it is the rule most easily broken by accident. A shadow deployment
produces mostly unreviewed traffic; treating it as benign would make the
denominator enormous and the false-block rate beautiful, and the number would
mean nothing at all. Unreviewed sources are counted, reported, and excluded
from every rate.

The same applies in the other direction: a source is not malicious because the
system would have blocked it. §9 and §14 forbid that, and nothing here derives a
label from a decision.

### Controlled positives are not the benign population

§31. A controlled scan against an owned asset is real runtime evidence about
detection, and is not evidence about how often ordinary traffic gets blocked.
The two are separated by the `provenance.collection` field the sensor writes at
the moment it writes the row -- never by a timestamp range reconstructed
afterwards.

### What this module will not do

It does not label anything, does not change a threshold, and does not decide a
gate. It reads labels a person wrote and reports counts; `autonomy/shadow_result.py`
computes the rates and the verdict from what this produces, against the
thresholds `autonomy/evaluation.py` has held since the decision authority was
written.
"""
from dataclasses import dataclass, field
import datetime as dt
import hashlib
import json
from pathlib import Path
import time

#: The label vocabulary is `autonomy/evaluation.py`'s, not a new one, and it is
#: imported rather than restated: a second spelling of BENIGN would divide the
#: evidence in half without failing anything. (`shadow_export.py` restates its
#: constants instead, for a reason that does not apply here -- that module runs
#: on a sensor where `dataset/` is not installed, and `evaluation` is.)
#:
#: A reviewer who cannot decide writes UNLABELED -- `autonomy/review.py` already
#: tells them so in the instructions it ships with every pack -- which is P15S
#: §15's UNCERTAIN under the name this codebase already uses.
from .evaluation import BENIGN, MALICIOUS_AUTOMATION, UNLABELED

SHADOW_EVIDENCE_SCHEMA_VERSION = 1

#: §15's one genuinely new state. IGNORE removes a source from every rate: our
#: own load balancer health check, say, which is neither a visitor nor an
#: attacker and would distort both numbers.
#:
#: It is also the obvious way to make an inconvenient result disappear, so it is
#: never silently applied. An ignored source is counted in every summary, and a
#: reader who suspects the ignore list is doing too much work can see exactly
#: how much of it there is.
IGNORE = 'IGNORE'

LABELS = (BENIGN, MALICIOUS_AUTOMATION, UNLABELED, IGNORE)

#: Not a label. Two reviewers, or one reviewer on two windows, disagreed about
#: the same source. `read_labels` refuses to pick a winner: calling it BENIGN
#: inflates the false-block numerator and calling it MALICIOUS_AUTOMATION hides
#: a false block, so a disagreement is reported as one and excluded from every
#: rate -- and counted separately from UNLABELED, so a review that disagreed
#: with itself a hundred times cannot look like a review nobody finished.
CONFLICT = 'CONFLICT'

#: `autonomy/evaluation.py`'s component words. A decision taken while a
#: component was DEGRADED or UNAVAILABLE is evidence about a degraded system.
DEGRADED_STATUSES = ('DEGRADED', 'UNAVAILABLE')

#: Collections, spelled as `autonomy/shadow_export.py` writes them.
REAL_SHADOW = 'real_shadow'
CONTROLLED_POSITIVE = 'controlled_positive'

#: A row this build cannot read is skipped and counted, never guessed at.
#: Version 1 in particular carries no provenance, so it cannot be told apart
#: from a controlled test -- which is exactly what must not be assumed.
SUPPORTED_EXPORT_SCHEMAS = (2,)


def _digest(path, *, chunk=1 << 20):
    """SHA-256 of a file, read in bounded pieces."""
    sha = hashlib.sha256()
    with open(path, 'rb') as handle:
        while block := handle.read(chunk):
            sha.update(block)
    return sha.hexdigest()


def period_files(path):
    """Every retained file of one export set, oldest first.

    The export is written through `autonomy/bounded_jsonl.py`, which rotates
    `export.jsonl` to `export.jsonl.1` and so on. Reading only the live path
    reads the newest file of the set -- by default one of four -- and reports a
    smaller period than was collected, with nothing raising and no count out of
    place. Every caller counting sources wants the whole set.
    """
    path = Path(path)
    parent = path.parent if str(path.parent) else Path('.')
    rotations = []
    for candidate in parent.glob(f'{path.name}.*'):
        suffix = candidate.name[len(path.name) + 1:]
        if suffix.isdigit() and candidate.is_file():
            rotations.append((int(suffix), candidate))
    found = [candidate for _index, candidate in sorted(rotations, reverse=True)]
    if path.is_file():
        found.append(path)
    return found


def _epoch(moment):
    """An ISO bucket or an epoch number, as seconds. None if it is neither."""
    if isinstance(moment, (int, float)):
        return float(moment)
    if isinstance(moment, str):
        try:
            parsed = dt.datetime.fromisoformat(moment)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()
    return None


def retention(summary, *, started_at=None, counters=None, tolerance_seconds=3600):
    """Did the window lose its own beginning? P15S §45, §51.

    The export is a bounded ring: `WriterLimits` retains four files of 20,000
    records inside a 32 MiB ceiling and then **deletes the oldest**. A shadow
    window long enough to see 3,000 distinct sources can rotate away its own
    first hours, and every count taken afterwards is of what survived. The
    arithmetic would be perfect and the denominator would be wrong.

    Two independent signals, because each one alone can be absent:

    * the writer's own `retention_deleted` and `failed` counters, which are
      exact but only available from the process that did the writing;
    * the gap between the window's declared start and the oldest row that is
      still there, which can be established from the evidence alone -- and is
      the only signal left once the files have been moved to another machine.

    The tolerance is one timestamp bucket, because `shadow_export.bucket()`
    coarsens to the hour and a window starting mid-hour would otherwise always
    look truncated.
    """
    counters = dict(counters or {})
    first = _epoch((summary.get('time_coverage') or {}).get('first_bucket'))
    began = _epoch(started_at)
    gap = None
    if first is not None and began is not None:
        gap = first - began
    reasons = []
    if counters.get('retention_deleted'):
        reasons.append(f"the writer deleted {counters['retention_deleted']} file(s) "
                       f'to stay inside its retention ceiling, so the window is '
                       f'missing its earliest records')
    if counters.get('failed'):
        reasons.append(f"{counters['failed']} rows failed to write, so decisions "
                       f'were taken that this evidence does not contain')
    if gap is not None and gap > tolerance_seconds:
        reasons.append(f'the window declares it began {round(gap / 3600, 2)} hours '
                       f'before the oldest surviving row')
    return {'complete': not reasons, 'reasons': reasons,
            'counters': counters,
            'seconds_missing_at_the_start': None if gap is None else round(gap, 3),
            'note': ('the export is a bounded ring that deletes its oldest file; '
                     'a window must be drained or sized so it cannot rotate away '
                     'its own evidence')}


def read_rows(paths, *, limit=None):
    """Export rows from one or more JSONL files, with an account of what was not read.

    A truncated last line is what a full disk leaves behind; it is skipped
    rather than allowed to abort the reading of the thousands of rows that are
    intact. A row declaring an unsupported export schema is skipped and counted
    separately, because "this file had a bad line" and "this file was written by
    a build I cannot read" are different problems.
    """
    rows, unparseable, unsupported = [], 0, 0
    targets = [paths] if isinstance(paths, (str, Path)) else list(paths)
    for path in targets:
        with open(path, encoding='utf-8') as stream:
            for line in stream:
                if not line.strip():
                    continue
                if limit is not None and len(rows) >= limit:
                    break
                try:
                    row = json.loads(line)
                except ValueError:
                    unparseable += 1
                    continue
                if row.get('shadow_export_schema_version') not in SUPPORTED_EXPORT_SCHEMAS:
                    unsupported += 1
                    continue
                rows.append(row)
    return rows, {'unparseable_lines': unparseable,
                  'unsupported_schema_rows': unsupported}


@dataclass
class Source:
    """Everything one source did during the period, aggregated.

    The unit §18 asks for. `windows` is kept alongside so a reader can see how
    much traffic one piece of evidence represents -- the number that makes
    "3,000 sources" mean something different from "3,000 rows".
    """

    pseudonym: str
    collection: str = ''
    windows: int = 0
    would_block_windows: int = 0
    profiles: set = field(default_factory=set)
    scopes: set = field(default_factory=set)
    buckets: set = field(default_factory=set)
    reason_codes: set = field(default_factory=set)
    segments: set = field(default_factory=set)
    degraded_components: set = field(default_factory=set)
    max_conservative: float = 0.0

    @property
    def would_blocked(self):
        """Any window reaching TEMP_BLOCK is what would have happened to it."""
        return self.would_block_windows > 0

    @property
    def degraded(self):
        """Was any decision about this source taken on a degraded system?"""
        return bool(self.degraded_components)

    def explain(self):
        return {'source_pseudonym': self.pseudonym,
                'collection': self.collection,
                'windows': self.windows,
                'would_block_windows': self.would_block_windows,
                'would_blocked': self.would_blocked,
                'profiles': sorted(self.profiles),
                'scopes': sorted(self.scopes),
                'hour_buckets': len(self.buckets),
                'reason_codes': sorted(self.reason_codes)[:16],
                'segments': sorted(self.segments),
                'degraded_components': sorted(self.degraded_components),
                'max_conservative_probability': round(self.max_conservative, 6)}


def sources(rows):
    """Aggregate export rows to sources. The first thing every caller does."""
    found = {}
    for row in rows:
        key = row.get('source_pseudonym')
        if not key:
            continue
        provenance = row.get('provenance') or {}
        collection = provenance.get('collection', '')
        source = found.get(key)
        if source is None:
            source = found[key] = Source(pseudonym=key, collection=collection)
        elif collection and collection != source.collection:
            # A source in two collections means two segments were merged: the
            # collection is fixed for the life of a writer, so this cannot
            # happen within one. Recorded rather than resolved, because the
            # right repair is to stop merging them.
            source.collection = 'MIXED'
        source.windows += 1
        if row.get('would_action') == 'TEMP_BLOCK':
            source.would_block_windows += 1
            source.reason_codes.update(row.get('reason_codes') or ())
        if row.get('profile_type'):
            source.profiles.add(row['profile_type'])
        if row.get('scope'):
            source.scopes.add(row['scope'])
        if row.get('timestamp_bucket'):
            source.buckets.add(row['timestamp_bucket'])
        if provenance.get('segment_id'):
            source.segments.add(provenance['segment_id'])
        for name, status in (row.get('component_health') or {}).items():
            if status in DEGRADED_STATUSES:
                source.degraded_components.add(f'{name}:{status}')
        conservative = row.get('conservative_probability')
        if isinstance(conservative, (int, float)):
            source.max_conservative = max(source.max_conservative, float(conservative))
    return found


def _row_label(row):
    """The label a completed review row carries, in either shape it can arrive in.

    Two files exist and both are real: `autonomy/review.py` hands a reviewer a
    blinded row with a top-level `label`, and a shadow export row carries a
    nested `review.label` that a person may fill in instead. Reading both is not
    permissiveness -- it is refusing to invent a third format for the sake of
    tidiness, and then having to explain to a reviewer why the file they filled
    in is the wrong one.
    """
    for candidate in (row.get('label'), (row.get('review') or {}).get('label')):
        if candidate:
            return str(candidate).strip().upper()
    return ''


def read_labels(paths):
    """§15, §53. Fold a completed review pack into labels per source.

    Returns `(labels, report)`, where `labels` maps `source_pseudonym` to one of
    `LABELS` and `report` says what was in the pack and what could not be used.

    Review happens per decision; the unit of evidence is the source (§18), so
    several reviewed windows can carry different labels for the same source.
    The rules, in order:

    * **IGNORE wins.** It is a statement about what the source *is* -- our own
      health checker -- not about one window, so one window is enough to
      establish it. It is also the easy way to make an inconvenient result
      disappear, which is why every summary counts ignored sources out loud.
    * **BENIGN against MALICIOUS_AUTOMATION is a conflict**, reported and
      excluded rather than resolved. See `CONFLICT`.
    * **A label this vocabulary does not contain is not guessed at.** It is
      counted as unusable, and the source stays unlabelled.

    Nothing here reads `would_action`. A review pack that has been joined back
    to the decisions is still a review, and a label derived from the decision
    would be §14's self-labelling with an extra file in the way.
    """
    # Read plainly rather than through `read_rows`. A blinded review row carries
    # no export schema version -- `autonomy/review.py` withholds it along with
    # the decision -- so the schema check that protects *decision* reading would
    # refuse the entire pack here. Worse, it would refuse only part of a pack
    # that mixed the two shapes, and dropping half a reviewer's work without
    # saying so is the kind of silence this cycle keeps finding. The authority
    # for a label is the person who wrote it, not the schema of the row it
    # arrived on.
    rows, skipped = [], {'unparseable_lines': 0}
    targets = [paths] if isinstance(paths, (str, Path)) else list(paths)
    for path in targets:
        with open(path, encoding='utf-8') as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    skipped['unparseable_lines'] += 1

    seen, unusable, unlabelled_rows = {}, {}, 0
    for row in rows:
        key = row.get('source_pseudonym')
        if not key:
            continue
        label = _row_label(row)
        if not label or label == UNLABELED:
            unlabelled_rows += 1
            continue
        if label not in LABELS:
            unusable[label] = unusable.get(label, 0) + 1
            continue
        seen.setdefault(key, set()).add(label)

    labels, conflicts = {}, []
    for key, found in seen.items():
        if IGNORE in found:
            labels[key] = IGNORE
        elif len(found) == 1:
            labels[key] = next(iter(found))
        else:
            conflicts.append(key)
    return labels, {
        'rows_read': len(rows),
        'skipped': skipped,
        'rows_without_a_label': unlabelled_rows,
        'unusable_labels': unusable,
        'sources_labelled': len(labels),
        'conflicting_sources': sorted(conflicts),
        'note': ('a conflicting source is excluded from every rate and is not '
                 'the same thing as an unreviewed one'),
    }


def probability_edges():
    """Histogram bins that are the decision boundaries, not round numbers.

    P15S §27 asks for the probability and conservative-bound distributions. Even
    deciles would answer the wrong question: every cost cutoff in this project
    sits between 0.667 and 0.999, so nine of the ten bins would be empty and the
    tenth would hold the entire decision. The bins here are the cutoffs
    themselves, read from `autonomy/cost.py`, so "how many windows were above
    the API cutoff" is a number a reader can point at rather than interpolate --
    and so the bins cannot drift away from the policy they describe.
    """
    from .cost import PROFILES
    return (0.0, *sorted({profile.threshold for profile in PROFILES.values()}), 1.0)


def histogram(values, edges):
    """Counts per half-open bin, with the top bin closed at the last edge."""
    edges = list(edges)
    counts = [0] * (len(edges) - 1)
    for value in values:
        number = _number(value)
        if number is None:
            continue
        for index in range(len(counts)):
            upper = edges[index + 1]
            if number < upper or (index == len(counts) - 1 and number <= upper):
                counts[index] += 1
                break
    return [{'from': round(edges[i], 6), 'to': round(edges[i + 1], 6),
             'count': counts[i]} for i in range(len(counts))]


def _number(value):
    return float(value) if isinstance(value, (int, float)) else None


def _tally(counter, names):
    for name in names:
        counter[name] = counter.get(name, 0) + 1


def distributions(rows, *, top=24):
    """§26, §27. What the period's decisions were made of.

    Reported over windows rather than sources, and labelled as such. A family
    that contributed to four hundred windows from one host is not four hundred
    pieces of evidence about that family, and `sources` above is the unit for
    anything that becomes a rate. These are for looking at, not for dividing.

    The suppression tally is §26's. A window counts as *suppressed* when the
    arithmetic preferred a block -- the conservative bound reached the profile's
    own threshold -- and no block was decided. If one gate or one assumption
    accounts for most of those, that is a possible runtime defect and worth
    investigating; §26 is explicit that the answer is never to weaken the
    assumption because it refuses too often.
    """
    families, codes, gates, assumptions = {}, {}, {}, {}
    probabilities, bounds, risks = [], [], []
    blocked_windows = suppressed = 0

    for row in rows:
        bound = _number(row.get('conservative_probability'))
        threshold = _number((row.get('expected_loss') or {}).get('threshold'))
        would_block = row.get('would_action') == 'TEMP_BLOCK'
        probabilities.append(row.get('calibrated_probability'))
        bounds.append(row.get('conservative_probability'))
        risks.append(row.get('math_risk'))

        if would_block:
            blocked_windows += 1
            _tally(families, [name for name, score
                              in (row.get('evidence_families') or {}).items()
                              if _number(score)])
            _tally(codes, row.get('reason_codes') or ())
        elif bound is not None and threshold is not None and bound >= threshold:
            suppressed += 1
            maturity = row.get('maturity') or {}
            _tally(gates, [name for name, passed
                           in (maturity.get('gates') or {}).items() if not passed])
            _tally(assumptions, maturity.get('failed_assumptions') or ())

    def ranked(counter):
        return [{'name': name, 'windows': count} for name, count
                in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:top]]

    edges = probability_edges()
    leading = ranked(gates)[:1]
    return {
        'unit': 'windows, not sources; nothing here is a rate',
        'would_block_windows': blocked_windows,
        'evidence_families': ranked(families),
        'reason_codes': ranked(codes),
        'calibrated_probability': histogram(probabilities, edges),
        'conservative_probability': histogram(bounds, edges),
        'math_risk': histogram(risks, edges),
        'histogram_edges': [round(edge, 6) for edge in edges],
        'histogram_note': ('the bin edges are the cost profile cutoffs, so a '
                           'count above an edge is the count of windows that '
                           'reached that profile threshold'),
        # §26.
        'suppression': {
            'suppressed_windows': suppressed,
            'failed_gates': ranked(gates),
            'failed_assumptions': ranked(assumptions),
            'leading_gate_share': (round(leading[0]['windows'] / suppressed, 4)
                                   if suppressed and leading else None),
            'note': ('a suppressed window is one where the conservative bound '
                     'reached the profile threshold and no block was decided. '
                     'One gate accounting for most of them is a reason to '
                     'investigate the runtime, never a reason to weaken the gate'),
        },
    }


def summarise(paths, *, labels=None, limit=None):
    """§50. What a period contains, without deciding anything about it.

    Safe to run while collection is still going, which is what it is for. Counts
    only: no rate is computed here, because a rate over a period that is still
    growing invites somebody to watch it move and stop when it looks right.
    """
    rows, skipped = read_rows(paths, limit=limit)
    by_source = sources(rows)
    labels = dict(labels or {})

    buckets = sorted({row['timestamp_bucket'] for row in rows
                      if row.get('timestamp_bucket')})
    profiles, segments, collections = {}, {}, {}
    for source in by_source.values():
        for profile in sorted(source.profiles) or ['(none)']:
            entry = profiles.setdefault(profile, {'sources': 0, 'would_block_sources': 0})
            entry['sources'] += 1
            entry['would_block_sources'] += int(source.would_blocked)
        for segment in sorted(source.segments) or ['(unset)']:
            segments[segment] = segments.get(segment, 0) + 1
        entry = collections.setdefault(
            source.collection or '(unset)',
            {'sources': 0, 'windows': 0, 'would_block_sources': 0})
        entry['sources'] += 1
        entry['windows'] += source.windows
        entry['would_block_sources'] += int(source.would_blocked)

    states = {state: 0 for state in LABELS}
    for key in by_source:
        state = labels.get(key, UNLABELED)
        # A label outside the vocabulary is counted under its own name rather
        # than quietly folded into one of the four. A caller who invented a
        # fifth state should see it in the report, not have it absorbed.
        states[state] = states.get(state, 0) + 1

    return {
        'shadow_evidence_schema_version': SHADOW_EVIDENCE_SCHEMA_VERSION,
        'rows_read': len(rows),
        'skipped': skipped,
        # §18: four separate numbers, never collapsed into one.
        'sources': len(by_source),
        'windows': sum(source.windows for source in by_source.values()),
        'profiles': profiles,
        'time_coverage': {'hour_buckets': len(buckets),
                          'first_bucket': buckets[0] if buckets else None,
                          'last_bucket': buckets[-1] if buckets else None},
        'collections': collections,
        'segments': segments,
        'would_block_sources': sum(1 for s in by_source.values() if s.would_blocked),
        'would_block_windows': sum(s.would_block_windows for s in by_source.values()),
        'label_states': states,
        # §26, §27. Kept in their own block, and labelled as window counts, so
        # nothing here can be mistaken for the source-unit numbers above.
        'distributions': distributions(rows),
        # A decision taken while a component was DEGRADED or UNAVAILABLE is
        # evidence about a degraded system. `docs/SHADOW_VALIDATION_PLAN.md`
        # fails a window where such decisions were left in the population, so
        # the count is surfaced here rather than left inside the rows.
        'degraded_sources': sum(1 for s in by_source.values() if s.degraded),
        # §53, stated rather than left to be inferred from the arithmetic.
        'note': ('unreviewed sources are counted here and excluded from every '
                 'rate. A source is not benign because nobody looked at it, and '
                 'not malicious because the system would have blocked it'),
    }


def manifest(*, export_paths, journal_paths=(), runtime_version='', git_commit='',
             config_digest='', calibrator_path=None, profile_mapping=None,
             started_at=None, ended_at=None, segment_id='', counters=None,
             clock=time.time):
    """§45. What this evidence is, and what produced it.

    Everything a later reader needs in order to establish that the numbers in a
    report came from these bytes, produced by that build, under that
    configuration. The hashes are of the files as they are now; freezing them is
    a separate act.
    """
    exports = [Path(p) for p in export_paths]
    journals = [Path(p) for p in journal_paths]
    mapping = dict(profile_mapping or {})
    return {
        'shadow_evidence_schema_version': SHADOW_EVIDENCE_SCHEMA_VERSION,
        'created_at': round(clock(), 3),
        'segment_id': segment_id,
        'runtime_version': runtime_version,
        'git_commit': git_commit,
        'config_digest': config_digest,
        'calibrator': ({'path': str(calibrator_path),
                        'sha256': _digest(calibrator_path)}
                       if calibrator_path and Path(calibrator_path).is_file()
                       else None),
        'profile_mapping': mapping,
        'profile_mapping_sha256': hashlib.sha256(
            json.dumps(mapping, sort_keys=True).encode()).hexdigest(),
        'period': {'started_at': started_at, 'ended_at': ended_at},
        # The writer's own account of what it could not keep. Exact, and
        # available only from the process that did the writing -- which is why
        # `retention()` has a second, weaker signal for evidence read later.
        'writer_counters': dict(counters or {}),
        'files': [{'path': str(path), 'role': role,
                   'bytes': path.stat().st_size, 'sha256': _digest(path)}
                  for paths, role in ((exports, 'shadow_export'),
                                      (journals, 'decision_journal'))
                  for path in paths if path.is_file()],
    }


def freeze(*, export_paths, labels=None, **fields):
    """§51. The manifest, plus the counts the evidence supports at this instant.

    After this the dataset is not changed. That is a discipline rather than a
    lock -- nothing here can stop somebody appending to a file -- which is why
    the record carries the hashes that make an append detectable.
    """
    document = manifest(export_paths=export_paths, **fields)
    document['summary'] = summarise(export_paths, labels=labels)
    document['retention'] = retention(
        document['summary'],
        started_at=document['period']['started_at'],
        counters=document['writer_counters'])
    document['frozen'] = True
    document['note'] = ('frozen for evaluation. The file hashes above are what '
                        'the evaluation was run against; a later append changes '
                        'them and invalidates the result rather than extending it')
    return document


def rebase(path, root):
    """Where a manifest's file is *now*, given the directory it was moved to.

    `Path('/evidence') / '/var/lib/e4e/export.jsonl'` is
    `/var/lib/e4e/export.jsonl`: joining an absolute path discards the root
    silently, which is the whole of the bug this function exists to prevent.
    Manifests record absolute paths, so the naive join made `--root` do nothing
    and report the relocated evidence as CHANGED -- an operator doing exactly
    the right thing, told their evidence had been tampered with.

    So an absolute entry is looked up by its name under `root`, which is what
    "the evidence is in this directory now" means, and a relative one keeps its
    shape.
    """
    path = Path(path)
    if root is None:
        return path
    return Path(root) / (path.name if path.is_absolute() else path)


def verify(document, *, root=None):
    """§45, §47. Are the files still the ones this manifest was made from?"""
    results = []
    for entry in document.get('files', []):
        path = rebase(entry['path'], root)
        if not path.is_file():
            results.append({**entry, 'status': 'MISSING'})
            continue
        digest = _digest(path)
        results.append({**entry, 'observed_sha256': digest,
                        'status': 'MATCH' if digest == entry['sha256'] else 'CHANGED'})
    if not results:
        status = 'EMPTY'
    elif all(row['status'] == 'MATCH' for row in results):
        status = 'MATCH'
    elif any(row['status'] == 'MISSING' for row in results):
        # Reported apart from CHANGED, which is not pedantry: "the bytes are
        # different" and "the file is not there" call for different next steps,
        # and the second one is what a wrong `--root` looks like.
        status = 'MISSING'
    else:
        status = 'CHANGED'
    return {'files': results, 'status': status}
