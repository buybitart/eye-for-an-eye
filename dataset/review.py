"""Manual review of unlabelled samples.

A reviewer sees a behaviour summary, never content. They may answer `benign_like`,
`malicious_automation_like` or `uncertain`, and `uncertain` is a real answer: forcing a binary
label onto insufficient evidence is how a dataset acquires wrong ground truth. Uncertain rows
stay out of supervised splits by default.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from eye_for_an_eye.decision.features import NAMES
from . import schema

DECISIONS = (schema.BENIGN, schema.MALICIOUS, schema.UNCERTAIN)
SUMMARY_FEATURES = ('connections_60s', 'connections_900s', 'ports_60s', 'ports_900s', 'destinations_60s',
                    'families_60s', 'repetition_60s', 'sequential_60s', 'anomaly_60s', 'credentials_60s',
                    'continuation_60s', 'persistence_900s', 'burst_10s', 'interarrival_mean_60s',
                    'interarrival_cv_60s', 'deception_60s')


def summarise(sample):
    values = dict(zip(NAMES, sample.features.values, strict=True))
    return {
        'sample_id': sample.sample_id,
        'observed_at': sample.timestamp.isoformat(),
        'source_type': sample.source_type,
        'provenance': sample.provenance,
        'current_label': sample.label,
        'current_label_source': sample.label_source,
        'system_opinion': sample.provenance.get('analysis_only'),
        'event_counts': {'observations': sample.features.sample_count,
                         'window_seconds': round(sample.features.observation_seconds, 2)},
        'evidence': {'observations': sample.features.sample_count,
                     'observation_seconds': round(sample.features.observation_seconds, 2),
                     'capped': sample.features.capped,
                     'loss_fraction': sample.features.loss_fraction},
        'behaviour': {name: (None if values[name] is None else round(float(values[name]), 4))
                      for name in SUMMARY_FEATURES},
        'decision': None,
        'reviewer_note': '',
    }


def review_record(row):
    """A manual label carries its annotation, its confidence and when it was made.

    The reviewer's identity is deliberately not part of the dataset.
    """
    confidence = row.get('confidence') if row.get('confidence') in ('MEDIUM', 'LOW') else 'MEDIUM'
    return {'decision': row['decision'],
            'confidence': 'LOW' if row['decision'] == schema.UNCERTAIN else confidence,
            'reason': str(row.get('reviewer_note', ''))[:500],
            'reviewed_at': row.get('reviewed_at') or datetime.now(timezone.utc).replace(
                microsecond=0).isoformat().replace('+00:00', 'Z')}


def queue(samples, *, limit=200, quantiles=None):
    """Review queue, most useful first.

    Priority is behavioural, never identity: model and mathematical baseline disagreeing, a
    high risk the policy did not act on, and features outside the training distribution are
    what make a sample worth a person's time.
    """
    from .statistics import out_of_distribution
    scored = []
    ood = out_of_distribution(samples, quantiles) if quantiles else {}
    for sample in samples:
        if sample.label not in (schema.UNLABELED, schema.UNCERTAIN):
            continue
        analysis = sample.provenance.get('analysis_only') or {}
        math_score = analysis.get('math_score')
        model_score = analysis.get('model_score')
        reasons, priority = [], 0.0
        if math_score is not None and model_score is not None:
            gap = abs(float(math_score) - float(model_score))
            if gap >= .4:
                priority += 2 * gap
                reasons.append(f'math and model disagree by {gap:.2f}')
        if analysis.get('risk') is not None and not analysis.get('would_block') and float(analysis['risk']) >= .6:
            priority += 1.0
            reasons.append('high fused risk that policy did not act on')
        deviation = ood.get(sample.sample_id, {}).get('deviation', 0.0)
        if deviation:
            priority += min(2.0, deviation)
            reasons.append(f'outside training quantiles on {ood[sample.sample_id]["features"]} features')
        if sample.features.sample_count <= 4:
            priority -= .5
            reasons.append('little evidence')
        scored.append({'sample_id': sample.sample_id, 'priority': round(priority, 4),
                       'reasons': reasons, 'source_type': sample.source_type,
                       'summary': summarise(sample)})
    scored.sort(key=lambda item: -item['priority'])
    return scored[:limit]


def export(samples, path, *, limit=500):
    """Write a review file. No payload, no address, no credential, no decision score."""
    rows = [summarise(sample) for sample in samples
            if sample.label in (schema.UNLABELED, schema.UNCERTAIN)][:limit]
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({'review_schema_version': 1, 'rows': len(rows),
                                  'allowed_decisions': list(DECISIONS),
                                  'guidance': ('answer uncertain whenever the evidence does not settle it; '
                                               'uncertain rows are excluded from supervised training'),
                                  'samples': rows}, indent=2) + '\n', encoding='utf-8')
    return {'file': str(target), 'rows': len(rows)}


def apply_decisions(samples, review_path):
    """Fold reviewed answers back in. Only a person's answer becomes a label."""
    review = json.loads(Path(review_path).read_text(encoding='utf-8'))
    if review.get('review_schema_version') != 1:
        raise ValueError('unsupported review schema')
    decisions = {row['sample_id']: row for row in review['samples'] if row.get('decision')}
    applied, skipped = 0, 0
    by_id = {sample.sample_id: sample for sample in samples}
    for sample_id, row in decisions.items():
        if row['decision'] not in DECISIONS:
            raise ValueError('unknown review decision: ' + str(row['decision']))
        sample = by_id.get(sample_id)
        if sample is None:
            skipped += 1
            continue
        sample.label = row['decision']
        sample.label_source = 'manual_review'
        sample.label_confidence = 'LOW' if row['decision'] == schema.UNCERTAIN else (
            row.get('confidence') if row.get('confidence') in ('MEDIUM', 'LOW') else 'MEDIUM')
        sample.provenance = dict(sample.provenance, review=review_record(row))
        if sample.source_type == schema.SHADOW_UNLABELED:
            sample.source_type = schema.SHADOW_REVIEWED
        applied += 1
    return {'applied': applied, 'skipped_unknown_ids': skipped,
            'note': 'a reviewed label is MEDIUM or LOW confidence; only deterministic controlled '
                    'ground truth is HIGH'}
