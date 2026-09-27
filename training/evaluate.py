"""Offline classification/calibration metrics; score is not a factual probability."""
from collections import Counter
import numpy as np
from sklearn.metrics import (average_precision_score, brier_score_loss, classification_report,
    confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score)


def metrics(labels, scores):
    labels, scores = np.asarray(labels), np.asarray(scores)
    predicted = scores >= .5
    tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
    reliability = []
    for lower in np.arange(0, 1, .1):
        mask = (scores >= lower) & (scores < lower + .1 if lower < .9 else scores <= 1)
        if mask.any():
            reliability.append({'count': int(mask.sum()), 'mean_score': float(scores[mask].mean()),
                'observed_positive_fraction': float(labels[mask].mean())})
    return {'confusion_matrix': [[int(tn), int(fp)], [int(fn), int(tp)]],
        'precision': float(precision_score(labels, predicted, zero_division=0)),
        'recall': float(recall_score(labels, predicted, zero_division=0)),
        'f1': float(f1_score(labels, predicted, zero_division=0)), 'false_positive_rate': float(fp / max(1, tn + fp)),
        'roc_auc': float(roc_auc_score(labels, scores)), 'pr_auc': float(average_precision_score(labels, scores)),
        'brier_score': float(brier_score_loss(labels, scores)), 'reliability': reliability,
        'ece_10_bins': sum(r['count'] * abs(r['mean_score'] - r['observed_positive_fraction']) for r in reliability) / len(labels),
        'per_class': classification_report(labels, predicted, output_dict=True, zero_division=0)}


def regression_gate(candidate, current, tolerance=0.0):
    if not 0 <= tolerance <= 1:
        raise ValueError('invalid false positive tolerance')
    return {'eligible_for_manual_review': candidate['false_positive_rate'] <= current['false_positive_rate'] + tolerance,
        'automatic_promotion': False, 'false_positive_tolerance': tolerance}


# --- risk-logreg-v1 evaluation ------------------------------------------------
# Thresholds are evaluated, never chosen here: the model returns a score and
# DecisionFusion/PolicyGuard decide the action.
THRESHOLDS = (.50, .60, .70, .75, .80, .85, .90, .95, .98)


def point_metrics(labels, scores, threshold=.5):
    """Security-oriented metrics at one score threshold, including block precision."""
    labels, scores = np.asarray(labels), np.asarray(scores)
    predicted = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
    benign, positives, flagged = tn + fp, tp + fn, tp + fp
    return {'threshold': float(threshold), 'confusion_matrix': [[int(tn), int(fp)], [int(fn), int(tp)]],
            'precision': float(tp / flagged) if flagged else None,
            'recall': float(tp / positives) if positives else None,
            'f1': float(2 * tp / (2 * tp + fp + fn)) if tp else 0.0,
            'false_positive_rate': float(fp / benign) if benign else None,
            'false_negative_rate': float(fn / positives) if positives else None,
            'specificity': float(tn / benign) if benign else None,
            'accuracy': float((tp + tn) / len(labels)),
            'positive_decisions': int(flagged),
            'block_precision': float(tp / flagged) if flagged else None,
            'false_blocks': int(fp),
            'false_blocks_per_1000_benign': float(1000 * fp / benign) if benign else None}


def ranking_metrics(labels, scores):
    labels, scores = np.asarray(labels), np.asarray(scores)
    single = len(set(labels.tolist())) < 2
    return {'rows': int(len(labels)), 'positives': int(labels.sum()), 'negatives': int((labels == 0).sum()),
            'roc_auc': None if single else float(roc_auc_score(labels, scores)),
            'pr_auc': None if single else float(average_precision_score(labels, scores)),
            'brier_score': float(brier_score_loss(labels, scores))}


def threshold_table(labels, scores, thresholds=THRESHOLDS):
    return [point_metrics(labels, scores, threshold) for threshold in thresholds]


def score_distribution(labels, scores):
    labels, scores = np.asarray(labels), np.asarray(scores)
    report = {}
    for name, mask in (('benign_like', labels == 0), ('malicious_automation_like', labels == 1)):
        column = scores[mask]
        report[name] = {'count': int(mask.sum())} if not mask.any() else {
            'count': int(mask.sum()), 'min': float(column.min()), 'median': float(np.median(column)),
            'mean': float(column.mean()), 'p90': float(np.percentile(column, 90)),
            'p95': float(np.percentile(column, 95)), 'p99': float(np.percentile(column, 99)),
            'max': float(column.max())}
    return report


def calibration(labels, scores, bins=10):
    """Brier plus reliability bins. Small synthetic corpora do not justify a calibrator."""
    labels, scores = np.asarray(labels), np.asarray(scores)
    reliability = []
    for index in range(bins):
        lower, upper = index / bins, (index + 1) / bins
        mask = (scores >= lower) & (scores < upper if index < bins - 1 else scores <= 1)
        if mask.any():
            reliability.append({'bin': [lower, upper], 'count': int(mask.sum()),
                                'mean_score': float(scores[mask].mean()),
                                'observed_positive_fraction': float(labels[mask].mean())})
    ece = sum(r['count'] * abs(r['mean_score'] - r['observed_positive_fraction']) for r in reliability) / len(labels)
    return {'brier_score': float(brier_score_loss(labels, scores)), 'reliability': reliability,
            'expected_calibration_error': float(ece),
            'output_name': 'model_score', 'calibrated': False,
            'note': 'reported as an uncalibrated model score, not a probability of maliciousness'}


def coefficient_table(names, coefficients, intercept):
    rows = [{'feature': name, 'coefficient': float(value), 'absolute_importance': abs(float(value)),
             'direction': 'towards_malicious_automation_like' if value > 0 else
                          'towards_benign_like' if value < 0 else 'no_influence'}
            for name, value in zip(names, coefficients, strict=True)]
    rows.sort(key=lambda item: item['absolute_importance'], reverse=True)
    return {'intercept': float(intercept), 'coefficients': rows,
            'top_positive': [r for r in rows if r['coefficient'] > 0][:8],
            'top_negative': [r for r in rows if r['coefficient'] < 0][:8],
            'zero_influence': [r['feature'] for r in rows if r['coefficient'] == 0]}


def contributions(names, coefficients, row, limit=5):
    terms = sorted(({'feature': n, 'value': float(v), 'contribution': float(c * v)}
                    for n, c, v in zip(names, coefficients, row, strict=True)),
                   key=lambda item: abs(item['contribution']), reverse=True)
    return terms[:limit]


def error_analysis(rows, scores, names, coefficients, threshold=.5, limit=12):
    """False positives and negatives with their strongest feature terms. No payload, ever."""
    scores = np.asarray(scores)
    false_positive, false_negative = [], []
    for row, score, tensor in zip(rows, scores, (r['tensor'] for r in rows), strict=True):
        predicted = int(score >= threshold)
        if predicted == row['label']:
            continue
        record = {'sample_id': row['sample_id'], 'scenario_id': row['scenario_id'],
                  'source_group': row['source_group'], 'label': row['label'], 'model_score': float(score),
                  'observations': row['vector'].sample_count,
                  'observation_seconds': round(row['vector'].observation_seconds, 2),
                  'top_terms': contributions(names, coefficients, tensor)}
        (false_positive if row['label'] == 0 else false_negative).append(record)
    for group in (false_positive, false_negative):
        group.sort(key=lambda item: item['model_score'], reverse=group is false_positive)
    return {'threshold': float(threshold),
            'false_positive_count': len(false_positive), 'false_negative_count': len(false_negative),
            'false_positive_scenarios': dict(sorted(Counter(r['scenario_id'] for r in false_positive).items())),
            'false_negative_scenarios': dict(sorted(Counter(r['scenario_id'] for r in false_negative).items())),
            'false_positive_examples': false_positive[:limit], 'false_negative_examples': false_negative[:limit]}


def by_scenario(rows, scores, threshold=.5):
    report = {}
    for row, score in zip(rows, np.asarray(scores), strict=True):
        entry = report.setdefault(row['scenario_id'], {'rows': 0, 'label': row['label'], 'flagged': 0,
                                                       'scores': []})
        entry['rows'] += 1
        entry['flagged'] += int(score >= threshold)
        entry['scores'].append(float(score))
    for entry in report.values():
        column = np.asarray(entry.pop('scores'))
        entry.update(median_score=float(np.median(column)), max_score=float(column.max()),
                     flagged_fraction=entry['flagged'] / entry['rows'])
    return dict(sorted(report.items()))


def false_positive_concentration(rows, scores, threshold=.5):
    """Where the false blocks come from, and what removing the worst family would change."""
    scores = np.asarray(scores)
    benign = [(row, score) for row, score in zip(rows, scores, strict=True) if row['label'] == 0]
    flagged = Counter(row['scenario_id'] for row, score in benign if score >= threshold)
    total_benign, total_false = len(benign), sum(flagged.values())
    top = max(flagged, key=flagged.get) if flagged else None
    remaining_benign = sum(1 for row, _ in benign if row['scenario_id'] != top)
    remaining_false = total_false - flagged.get(top, 0)
    return {'threshold': float(threshold), 'benign_rows': total_benign, 'false_blocks': total_false,
            'false_positive_rate': total_false / total_benign if total_benign else None,
            'by_scenario': dict(sorted(flagged.items(), key=lambda item: -item[1])),
            'dominant_scenario': top,
            'dominant_share_of_false_blocks': flagged.get(top, 0) / total_false if total_false else None,
            'false_positive_rate_excluding_dominant': remaining_false / remaining_benign if remaining_benign else None,
            'note': 'the counterfactual is descriptive; it is not a claim about deployment behaviour'}
