"""Short-lived read-only connections, whitelisted SQL, deadlines and scan/page caps."""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import sqlite3
import time
from ..event_types import CLASSIFICATIONS, CONFIDENCES, EventType
from ..events import NetworkEvent
from .sqlite import APPLICATION_ID, SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class Query:
    start: float
    end: float
    limit: int
    cursor: int = 0
    event_type: str | None = None
    transport: str | None = None
    classification: str | None = None
    confidence: str | None = None
    source: str | None = None
    destination_port: int | None = None

    @classmethod
    def parse(cls, params, config, now=None):
        if set(params) - {'from', 'to', 'limit', 'cursor', 'event_type', 'transport', 'classification', 'confidence', 'source', 'destination_port'}:
            raise ValueError('unknown query filter')
        now = time.time() if now is None else now
        def stamp(key, default):
            if key not in params:
                return default
            value = datetime.fromisoformat(params[key].replace('Z', '+00:00'))
            if value.tzinfo is None:
                raise ValueError('time must have timezone')
            return value.timestamp()
        end = stamp('to', now)
        start = stamp('from', end - min(3600, config.max_range_seconds))
        limit, cursor = int(params.get('limit', min(20, config.max_page_size))), int(params.get('cursor', 0))
        if not 1 <= limit <= config.max_page_size or not 0 <= cursor <= 2**63 - 1 or not 0 <= start <= end or end - start > config.max_range_seconds:
            raise ValueError('page/cursor/time range limit')
        event_type = params.get('event_type')
        if event_type is not None:
            EventType(event_type)
        transport, label, confidence = params.get('transport'), params.get('classification'), params.get('confidence')
        if transport is not None and transport not in ('tcp', 'udp', 'icmp', 'icmpv6', 'other', 'unknown'):
            raise ValueError('invalid transport')
        if label is not None and label not in CLASSIFICATIONS or confidence is not None and confidence not in CONFIDENCES:
            raise ValueError('invalid classification/confidence')
        source = params.get('source')
        if source is not None:
            source = str(ipaddress.ip_address(source))
        port = int(params['destination_port']) if 'destination_port' in params else None
        if port is not None and not 0 <= port <= 65535:
            raise ValueError('invalid port')
        return cls(start, end, limit, cursor, event_type, transport, label, confidence, source, port)


class Reader:
    def __init__(self, path, config, *, allowed_versions=(SCHEMA_VERSION,)):
        self.path, self.config = Path(path).resolve(), config
        self.allowed_versions = allowed_versions

    @contextmanager
    def connect(self):
        if not self.path.is_file():
            raise sqlite3.OperationalError('storage unavailable')
        connection = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True,
                                    timeout=min(.1, self.config.max_query_seconds), isolation_level=None)
        try:
            deadline = time.monotonic() + self.config.max_query_seconds
            connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('PRAGMA temp_store=MEMORY')
            if (connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID or
                    connection.execute('PRAGMA user_version').fetchone()[0] not in self.allowed_versions):
                raise sqlite3.OperationalError('incompatible storage schema')
            yield connection
        finally:
            connection.close()

    @staticmethod
    def where(query, *, detections=False):
        clauses, args = ['observed_at>=?', 'observed_at<=?'], [query.start, query.end]
        index = 'event_time'
        for column, value, candidate in (('src_ip', query.source, 'event_source'), ('event_type', query.event_type, 'event_kind'),
                ('classification', query.classification, 'event_class'), ('dst_port', query.destination_port, 'event_port'),
                ('transport', query.transport, None), ('confidence', query.confidence, None)):
            if value is not None:
                clauses.append(column + '=?')
                args.append(value)
                if candidate and index == 'event_time':
                    index = candidate
        if query.cursor:
            clauses.append('seq<?')
            args.append(query.cursor)
        if detections:
            clauses.append('classification IS NOT NULL')
        return index, ' AND '.join(clauses), args

    def events(self, query, *, detections=False):
        index, where, args = self.where(query, detections=detections)
        with self.connect() as connection:
            rows = connection.execute(f'SELECT seq,event_json FROM events INDEXED BY {index} WHERE {where} '
                'ORDER BY seq DESC LIMIT ?', (*args, query.limit + 1)).fetchall()
        page = rows[:query.limit]
        return [(seq, NetworkEvent.from_json(encoded)) for seq, encoded in page], (page[-1][0] if len(rows) > query.limit else None)

    def event(self, event_id):
        if not 1 <= len(event_id) <= 128 or not all(char.isalnum() or char in '-_' for char in event_id):
            raise ValueError('invalid event identifier')
        with self.connect() as connection:
            row = connection.execute('SELECT event_json FROM events WHERE event_id=? LIMIT 1', (event_id,)).fetchone()
        return NetworkEvent.from_json(row[0]) if row else None

    def summaries(self, query, after_source=None):
        # Aggregate only a bounded recent sample. Lower bounds are explicit.
        index, where, args = self.where(query)
        with self.connect() as connection:
            rows = connection.execute(f'SELECT seq,observed_at,src_ip,dst_port,classification,confidence FROM events '
                f"INDEXED BY {index} WHERE {where} AND src_ip NOT IN ('runtime','unknown') ORDER BY seq DESC LIMIT ?",
                (*args, self.config.max_scan_rows + 1)).fetchall()
        partial = len(rows) > self.config.max_scan_rows
        groups = {}
        for seq, stamp, source, port, label, confidence in rows[:self.config.max_scan_rows]:
            group = groups.setdefault(source, {'source': source, 'first_seen': stamp, 'last_seen': stamp,
                'events': 0, 'ports': set(), 'classification': None, 'confidence': 'UNKNOWN', 'cursor': seq})
            group['first_seen'] = min(group['first_seen'], stamp)
            group['last_seen'] = max(group['last_seen'], stamp)
            group['events'] += 1
            if port is not None:
                group['ports'].add(port)
            if label and group['classification'] is None:
                group['classification'], group['confidence'] = label, confidence
        values = sorted((row for row in groups.values() if after_source is None or row['source'] > after_source),
                        key=lambda row: row['source'])
        page = values[:query.limit]
        for row in page:
            row['ports_seen'] = len(row.pop('ports'))
            for key in ('first_seen', 'last_seen'):
                row[key] = datetime.fromtimestamp(row[key], timezone.utc).isoformat()
        next_cursor = 's:' + page[-1]['source'] if page and len(values) > query.limit else None
        for row in page:
            row.pop('cursor')
        return page, partial, next_cursor

    def stats(self, query):
        index, where, args = self.where(query)
        with self.connect() as connection:
            rows = connection.execute(f'SELECT observed_at,dst_port,event_type,classification FROM events INDEXED BY {index} '
                f'WHERE {where} ORDER BY seq DESC LIMIT ?', (*args, self.config.max_scan_rows + 1)).fetchall()
        from collections import Counter
        bounded = rows[:self.config.max_scan_rows]
        return {'events_last_minute': sum(stamp >= query.end - 60 for stamp, _, _, _ in bounded),
                'events_last_hour': sum(stamp >= query.end - 3600 for stamp, _, _, _ in bounded),
                'top_destination_ports': Counter(port for _, port, _, _ in bounded if port is not None).most_common(10),
                'event_types': dict(Counter(kind for _, _, kind, _ in bounded)),
                'classification_counts': dict(Counter(label for _, _, _, label in bounded if label)),
                'sampled_events': len(bounded), 'partial': len(rows) > self.config.max_scan_rows}
