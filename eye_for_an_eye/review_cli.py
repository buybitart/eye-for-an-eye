"""P9 operator commands for the review queue.

`review list` shows what is waiting, `review show` prints one entry in full,
`review answer` records a person's judgement, and `review export` writes the
answered rows out for the dataset builder.

None of these commands train anything, promote anything, or touch a firewall.
`review answer` is the only place in the whole project where a training label is
created, and a person has to type it.
"""
import argparse
import json
import sys
from pathlib import Path

from .config import load_config

ANSWER_WORDS = {'benign': 'BENIGN_LIKE', 'benign-like': 'BENIGN_LIKE',
                'automation': 'MALICIOUS_AUTOMATION_LIKE',
                'malicious-automation-like': 'MALICIOUS_AUTOMATION_LIKE',
                'uncertain': 'UNCERTAIN', 'ignore': 'IGNORE'}

GUIDANCE = (
    'What you are judging is one window of behaviour, not a person and not an intent.\n'
    'Answer "automation" only when the behaviour itself shows an automated pattern.\n'
    'Answer "uncertain" whenever the evidence does not settle it. Uncertain is a real\n'
    'answer: it keeps the row out of supervised training instead of guessing at it.\n'
    'Answer "ignore" for a window that is not worth anyone\'s time. That is not the\n'
    'same as calling it benign, and it produces no label at all.')


def _queue(config):
    """Open the configured review queue, or explain what is missing."""
    from .decision.review_queue import QueueLimits, ReviewQueue, ReviewQueueError
    reliability = config.reliability
    if not reliability.review_queue_path:
        raise ReviewQueueError('no reliability.review_queue_path is configured')
    if not reliability.review_queue_secret_file:
        raise ReviewQueueError('no reliability.review_queue_secret_file is configured')
    secret = Path(reliability.review_queue_secret_file).read_bytes().strip()
    if len(secret) < 32:
        raise ReviewQueueError('the review queue secret must be at least 32 bytes')
    return ReviewQueue(reliability.review_queue_path, secret=secret,
                       limits=QueueLimits(max_entries=reliability.review_queue_max_entries,
                                          per_source_entries=reliability.review_queue_per_source,
                                          per_day_entries=reliability.review_queue_per_day,
                                          ttl_days=reliability.review_queue_ttl_days,
                                          min_observations=reliability.review_queue_min_observations))


def _print_entry(entry, *, full=False):
    print(f'Entry:\n{entry.entry_id}\n')
    print(f'State:\n{entry.state}\n')
    print(f'First seen:\n{entry.created_at}\n')
    print(f'Times seen:\n{entry.occurrences}\n')
    print(f'Source group:\n{entry.source_key}  (a keyed digest, not an address)\n')
    print('Why it is here:')
    for reason in entry.reasons:
        print('  ' + reason)
    print()
    print('Evidence:')
    for name, value in sorted(entry.evidence.items()):
        print(f'  {name}: {value}')
    print()
    if full:
        print('Behaviour:')
        for name, value in sorted(entry.behaviour.items()):
            print(f'  {name}: {"not observed" if value is None else round(float(value), 4)}')
        print()
        if entry.analysis_only:
            print('What the system thought (context only, never a label):')
            for name, value in sorted(entry.analysis_only.items()):
                print(f'  {name}: {value}')
            print()
    if entry.reviewed_at:
        print(f'Answered:\n{entry.reviewed_at} ({entry.confidence})\n')
        if entry.reviewer_note:
            print(f'Note:\n{entry.reviewer_note}\n')


def review_command(argv, *, debug=False):
    parser = argparse.ArgumentParser(
        prog='eye-for-an-eye review',
        description='Human review of unclear behaviour. The only source of training labels.')
    parser.add_argument('action', choices=('list', 'show', 'answer', 'export', 'status', 'reset'))
    parser.add_argument('entry_id', nargs='?', default='')
    parser.add_argument('--answer', choices=sorted(ANSWER_WORDS),
                        help='benign, automation, uncertain or ignore')
    parser.add_argument('--note', default='', help='why you answered that way')
    parser.add_argument('--confidence', choices=('MEDIUM', 'LOW'), default='MEDIUM')
    parser.add_argument('--state', choices=('UNREVIEWED', 'BENIGN_LIKE',
                                            'MALICIOUS_AUTOMATION_LIKE', 'UNCERTAIN', 'IGNORE'))
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--out', default='', help='where to write the export file')
    parser.add_argument('--config')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    from .operator_cli import failure
    from .decision.review_queue import ReviewQueueError

    try:
        config = load_config(args.config)
        queue = _queue(config)

        if args.action == 'status':
            stats = queue.stats()
            if args.json:
                print(json.dumps(stats))
                return 0
            print('REVIEW QUEUE\n')
            print(f'Waiting for a person:\n{stats["by_state"]["UNREVIEWED"]}\n')
            print(f'Answered by a person:\n{stats["labelled_by_a_person"]}\n')
            print(f'Total entries:\n{stats["total"]} of {stats["limits"]["max_entries"]}\n')
            print(f'Distinct sources:\n{stats["distinct_sources"]}\n')
            print(f'Largest single source:\n{stats["largest_single_source"]} entries '
                  f'(limit {stats["limits"]["per_source_entries"]})\n')
            print('Note:\nAn entry is here because the evidence was unclear, not because the\n'
                  'system acted. Nothing here is labelled until you answer it.')
            return 0

        if args.action == 'list':
            entries = queue.entries(state=args.state or 'UNREVIEWED', limit=args.limit)
            if args.json:
                print(json.dumps({'schema_version': 1, 'rows': len(entries),
                                  'entries': [entry.to_row() for entry in entries]}))
                return 0
            print('REVIEW QUEUE\n')
            if not entries:
                print('Nothing is waiting for review.')
                return 0
            print(GUIDANCE + '\n')
            print(f'{"Entry":26} {"Priority":9} {"Seen":5} Why')
            for entry in entries:
                why = entry.reasons[0] if entry.reasons else ''
                print(f'  {entry.entry_id:24} {entry.priority:<9.2f} {entry.occurrences:<5} {why}')
            print(f'\n{len(entries)} shown. Use "review show <entry>" for the full behaviour.')
            return 0

        if args.action == 'show':
            if not args.entry_id:
                print('Which entry? Use "review list" to see the ids.', file=sys.stderr)
                return 2
            for entry in queue.entries(state=None, limit=1_000_000):
                if entry.entry_id == args.entry_id:
                    if args.json:
                        print(json.dumps(entry.to_row()))
                        return 0
                    _print_entry(entry, full=True)
                    print(GUIDANCE)
                    return 0
            print(f'No queue entry with id {args.entry_id}.', file=sys.stderr)
            return 2

        if args.action == 'answer':
            if not args.entry_id or not args.answer:
                print('Use: review answer <entry> --answer benign|automation|uncertain|ignore',
                      file=sys.stderr)
                return 2
            entry = queue.record_review(args.entry_id, ANSWER_WORDS[args.answer],
                                        note=args.note, confidence=args.confidence)
            if args.json:
                print(json.dumps({'schema_version': 1, 'entry_id': entry.entry_id,
                                  'state': entry.state, 'confidence': entry.confidence}))
                return 0
            print(f'Answered:\n{entry.entry_id} is now {entry.state} ({entry.confidence})\n')
            print('This is now a training label. Nothing has been trained or promoted.')
            return 0

        if args.action == 'reset':
            if not args.entry_id:
                print('Which entry?', file=sys.stderr)
                return 2
            entry = queue.reset_review(args.entry_id)
            print(f'{entry.entry_id} is back to UNREVIEWED.')
            return 0

        if args.action == 'export':
            if not args.out:
                print('Where should the export go? Use --out <file>.', file=sys.stderr)
                return 2
            summary = queue.export_labels(args.out)
            if args.json:
                print(json.dumps({'schema_version': 1, **summary}))
                return 0
            print(f'Written:\n{summary["file"]}\n')
            print(f'Rows:\n{summary["rows"]} answered by a person\n')
            print('Next:\nThese rows can go into a candidate dataset. Building a dataset and\n'
                  'training a model are separate steps that you start yourself.')
            return 0
        raise ValueError('unknown review action')
    except ReviewQueueError as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return failure(exc, machine=args.json, debug=debug)
