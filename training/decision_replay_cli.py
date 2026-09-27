"""Run the trusted final-decision evaluation and print what it found.

    python -m training.decision_replay_cli --corpus <samples.csv> [--json out.json]

Offline, deterministic, and it changes nothing. It reads a labelled corpus,
replays every trusted row through the whole decision path, and reports the
rare-class metrics for the *action* — which is the measurement P15 could not
make and P15.1 exists to produce.

Reports both views on purpose. A window is what the system evaluates; a source is
what it blocks, and §165's "of all sources autonomously TEMP_BLOCKed" is a
question about sources. Where the two disagree, the disagreement is the finding.
"""
import argparse
import json
from pathlib import Path
import sys


def load(corpus):
    from dataset.store import read
    return read(Path(corpus))


def run(corpus, *, models=Path('models'), classifier=True, resamples=400):
    from eye_for_an_eye.config import Config
    from .decision_replay import (ReplayComponents, replay, scenario_breakdown,
                                  summarise)
    samples = load(corpus)
    config = Config()
    config.decision.enabled = True
    components = ReplayComponents(config).open(
        classifier_path=models / 'risk-logreg-v1.onnx' if classifier else '',
        classifier_manifest=models / 'risk-logreg-v1.json' if classifier else '',
        anomaly_path=models / 'isolation-v1.onnx',
        anomaly_manifest=models / 'isolation-v1.json',
        distribution_path=models / 'risk-logreg-v1-distribution.json')
    try:
        decisions, dropped = replay(samples, components, classifier_authority=classifier)
        body = summarise(decisions, dropped, components=components, resamples=resamples)
        body['scenarios'] = scenario_breakdown(decisions)
    finally:
        components.close()
    return body


def render(body):
    lines = ['TRUSTED FINAL-DECISION EVALUATION', '',
             f'Rows scored:\n{body["rows_scored"]}', '',
             f'Rows dropped:\n{json.dumps(body["rows_dropped"]) or "none"}', '']
    for view in ('per_source', 'per_window'):
        report = body[view]
        metrics = report['decision_metrics']
        lines.append(f'--- {view.replace("_", " ")} ---')
        if metrics['status'] != 'MEASURED':
            lines += [f'  {metrics["status"]}', '']
            continue
        matrix = metrics['confusion_matrix']['matrix']
        lines += [
            '                        ALLOW    TEMP_BLOCK',
            f'  actual benign     {matrix[0][0]:9d} {matrix[0][1]:11d}',
            f'  actual malicious  {matrix[1][0]:9d} {matrix[1][1]:11d}',
            '',
            f'  benign sample            {metrics["benign_sample"]}',
            f'  positive sample          {metrics["positive_sample"]}',
            f'  class prevalence         {metrics["class_prevalence"]}',
            f'  precision                {metrics["precision"]}',
            f'  recall                   {metrics["recall"]}',
            f'  specificity              {metrics["specificity"]}',
            f'  false positive rate      {metrics["false_positive_rate"]}',
            f'  false negative rate      {metrics["false_negative_rate"]}',
            f'  block precision          {metrics["block_precision"]}',
            f'  false blocks / 1000      {metrics["false_blocks_per_1000_benign"]}',
            f'  ROC-AUC                  {report["ranking"].get("roc_auc")}',
            f'  PR-AUC                   {report["ranking"].get("pr_auc")}',
            f'  usefulness               {body[view]["usefulness"]}',
            f'  release gate             {report["release_gate"]["verdict"]}']
        for reason in report['release_gate'].get('reasons', ()):
            lines.append(f'    - {reason}')
        lines.append('')
    def auc(value):
        return f'{value:.3f}' if value is not None else '   — '

    lines += ['--- ranking quality: ROC-AUC per evidence stage ---',
              '  (sources aggregate with max, as the system does)', '',
              f'  {"stage":<42} {"window":>7} {"source":>8}']
    for name, entry in body.get('ranking_breakdown', {}).items():
        lines.append(f'  {name:<42} {auc(entry["per_window_roc_auc"]):>7} '
                     f'{auc(entry["per_source_roc_auc"]):>8}')
    lines.append('')
    blocked = [name for name, entry in body.get('scenarios', {}).items()
               if entry['blocked_windows']]
    lines += ['Scenario groups with at least one blocked window:',
              '  ' + (', '.join(blocked) if blocked else 'none'), '']
    lines += ['Assumptions:'] + [f'  - {line}' for line in body['assumptions']] + ['']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m training.decision_replay_cli',
        description='Replay a trusted labelled corpus to the final ALLOW/TEMP_BLOCK.')
    parser.add_argument('--corpus', required=True,
                        help='a processed dataset samples.csv')
    parser.add_argument('--models', default='models')
    parser.add_argument('--no-classifier', action='store_true',
                        help='withhold classifier authority and measure the '
                             'deterministic fallback alone')
    parser.add_argument('--resamples', type=int, default=400)
    parser.add_argument('--json', dest='json_path')
    args = parser.parse_args(argv)
    body = run(args.corpus, models=Path(args.models),
               classifier=not args.no_classifier, resamples=args.resamples)
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(body, indent=1), encoding='utf-8')
    print(render(body), end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
