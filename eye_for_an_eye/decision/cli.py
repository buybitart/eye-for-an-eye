"""Offline replay and bounded stored decision explanations."""
import argparse
import json
import sqlite3
from pathlib import Path
from ..config import load_config
from ..event_types import EventType
from ..operator_cli import failure, output


def explain(argv):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye decision')
    parser.add_argument('action', choices=['explain'])
    parser.add_argument('id')
    parser.add_argument('--config')
    parser.add_argument('--storage-path')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        from ..storage.reader import Reader
        config = load_config(args.config)
        event = Reader(args.storage_path or config.storage.path, config.api).event(args.id)
        if event is None or event.event_type != EventType.DECISION:
            raise ValueError('decision not found in retained storage')
        output({'schema_version': 1, 'decision_id': event.event_id, **event.observations}, args.json)
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        return failure(exc, 1, args.json)


def simulate(argv):
    parser = argparse.ArgumentParser(prog='eye-for-an-eye simulate')
    parser.add_argument('pcap')
    parser.add_argument('--config')
    parser.add_argument('--output', required=True, help='new bounded JSONL event file')
    parser.add_argument('--report', required=True, help='new aggregate shadow report JSON')
    parser.add_argument('--max-packets', type=int, default=100000)
    args = parser.parse_args(argv)
    from ..offline import analyze_pcap
    from .shadow import ShadowReport
    report = ShadowReport()
    try:
        config = load_config(args.config)
        if config.enforcement.enabled or config.firewall.enabled or config.decision.mode != 'shadow':
            raise ValueError('simulate requires explicit shadow configuration without firewall/enforcement')
        if Path(args.report).exists():
            raise FileExistsError('report output already exists')
        with Path(args.output).open('x', encoding='utf-8') as stream:
            def write(line):
                stream.write(line)
                record = json.loads(line)
                if record['event_type'] == EventType.DECISION:
                    report.observe(record)
            stats = analyze_pcap(args.pcap, config, writer=write, max_packets=args.max_packets)
        with Path(args.report).open('x', encoding='utf-8') as stream:
            json.dump({'replay': stats, 'shadow': report.snapshot()}, stream, indent=2)
        return int(bool(stats.get('storage_dropped') or stats.get('output_dropped') or stats.get('packet_limit_reached')))
    except (OSError, ValueError, RuntimeError, ImportError, sqlite3.Error) as exc:
        return failure(exc, 1)
