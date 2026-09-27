"""Single bounded selector per operational endpoint; database work has its own deadline."""
from dataclasses import asdict
import hmac
import ipaddress
import json
from pathlib import Path
import sqlite3
import secrets
import threading
from urllib.parse import parse_qsl, unquote, urlsplit
from ..config import Config
from ..enrichment.cache import TTLCache
from ..limits import TokenBucket
from ..network.listeners import SelectorServer
from ..observability.version import version_info
from ..storage.reader import Query, Reader
from .models import DetectionSummary, EventResponse, SourceSummary, StatsResponse, HealthResponse, ip_projection


def response(status, body, content_type='application/json'):
    encoded = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=True, separators=(',', ':')).encode()
    reasons = {200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
               405: 'Method Not Allowed', 413: 'Content Too Large', 429: 'Too Many Requests', 503: 'Service Unavailable'}
    header = (f'HTTP/1.0 {status} {reasons[status]}\r\nContent-Type: {content_type}\r\nContent-Length: {len(encoded)}\r\n'
              'Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n').encode()
    return header + encoded


class ReadOnlyAPI:
    def __init__(self, config, runtime):
        self.config, self.runtime = config, runtime
        self.reader = Reader(config.storage.path, config.api)
        self.rate = TokenBucket(config.api.requests_per_second)
        self.source_cursors = TTLCache(512, 300, max_bytes=1_048_576)
        self.token = None
        if config.api.token_file:
            with Path(config.api.token_file).open('rb') as stream:
                self.token = stream.read(4097).strip()
            if not 32 <= len(self.token) <= 256 or any(value < 33 or value > 126 for value in self.token):
                raise ValueError('API token must be 32..256 printable non-whitespace bytes')

    def handle(self, method, path, params, headers):
        self.runtime.registry.inc('api_requests_total')
        if not self.rate.allow():
            return 429, {'error': 'request_rate_limit'}
        if self.token and not hmac.compare_digest(headers.get(b'authorization', b''), b'Bearer ' + self.token):
            return 401, {'error': 'authentication_required'}
        # No CORS, browser cross-origin requests or cookie authentication.
        if b'origin' in headers:
            return 403, {'error': 'origin_not_allowed'}
        if method != 'GET':
            return 405, {'error': 'read_only'}
        try:
            if path in ('/health', '/ready'):
                if params:
                    raise ValueError('unexpected parameters')
                state = asdict(HealthResponse(**self.runtime.health_response()))
                return (200 if state['live' if path == '/health' else 'ready'] else 503), state
            if path == '/version':
                if params:
                    raise ValueError('unexpected parameters')
                return 200, version_info(self.config)
            if path == '/openapi.json' and self.config.api.docs_enabled:
                return 200, {'openapi': '3.1.0', 'info': {'title': 'Eye for an Eye read-only API', 'version': '1'},
                    'paths': {route: {'get': {'responses': {'200': {'description': 'Bounded JSON response'}}}} for route in
                              ('/health', '/ready', '/version', '/api/v1/events', '/api/v1/events/{event_id}',
                               '/api/v1/sources', '/api/v1/sources/{source}', '/api/v1/detections', '/api/v1/stats')}}
            if not (path in ('/api/v1/events', '/api/v1/detections', '/api/v1/sources', '/api/v1/stats') or
                    path.startswith(('/api/v1/events/', '/api/v1/sources/'))):
                return 404, {'error': 'not_found'}
            if not self.config.storage.enabled:
                return 503, {'error': 'storage_not_enabled'}
            if path.startswith('/api/v1/events/'):
                if params:
                    raise ValueError('unexpected parameters')
                event = self.reader.event(path[len('/api/v1/events/'):])
                return (200, EventResponse.from_event(event, self.config.api.redact_ip)) if event else (404, {'error': 'event_not_found'})
            source_path = path.startswith('/api/v1/sources/')
            after_source = None
            if path == '/api/v1/sources':
                params = dict(params)
                cursor = params.pop('cursor', None)
                if cursor:
                    if self.config.api.redact_ip:
                        cursor = self.source_cursors.get(cursor)
                        if cursor is None:
                            raise ValueError('expired source cursor')
                    if not cursor.startswith('s:'):
                        raise ValueError('invalid source cursor')
                    after_source = str(ipaddress.ip_address(cursor[2:]))
            if source_path:
                params = {**params, 'source': str(ipaddress.ip_address(path[len('/api/v1/sources/'):]))}
            query = Query.parse(params, self.config.api)
            window = {'from': query.start, 'to': query.end}
            if path in ('/api/v1/events', '/api/v1/detections'):
                detections = path.endswith('detections')
                rows, cursor = self.reader.events(query, detections=detections)
                items, last = [], None
                for seq, event in rows:
                    model = DetectionSummary if detections else EventResponse
                    item = model.from_event(event, self.config.api.redact_ip)
                    if len(json.dumps({'items': items + [item]}, ensure_ascii=True).encode()) > self.config.api.max_response_bytes - 1024:
                        if not items:
                            return 413, {'error': 'single_record_exceeds_response_limit'}
                        cursor = last
                        break
                    items.append(item)
                    last = seq
                return 200, {'items': items, 'next_cursor': str(cursor) if cursor else None, 'window': window}
            if path == '/api/v1/sources' or source_path:
                rows, partial, cursor = self.reader.summaries(query, after_source)
                items = [asdict(SourceSummary(**row)) for row in rows]
                if self.config.api.redact_ip:
                    items = ip_projection(items)
                    if cursor:
                        opaque = secrets.token_urlsafe(24)
                        self.source_cursors.set(opaque, cursor)
                        cursor = opaque
                if source_path:
                    return (200, {'source': items[0], 'partial': partial, 'window': window}) if items else (404, {'error': 'source_not_found'})
                return 200, {'items': items, 'partial': partial, 'next_cursor': cursor, 'window': window,
                             'limitations': ['aggregates_cover_bounded_recent_rows', 'classification_from_stored_P2_only']}
            if path == '/api/v1/stats':
                activity = self.reader.stats(query)
                state = self.runtime.control_snapshot()
                return 200, asdict(StatsResponse(activity, state['queue']['dropped'], state['metrics']['storage_bytes'],
                                               state.get('fallback_events', 0)))
            return 404, {'error': 'not_found'}
        except (ValueError, TypeError, OverflowError):
            return 400, {'error': 'invalid_query'}
        except (sqlite3.Error, OSError):
            self.runtime.registry.inc('api_errors_total')
            return 503, {'error': 'storage_unavailable_or_query_budget'}


class Endpoint:
    def __init__(self, config, runtime, *, metrics=False):
        self.config, self.runtime, self.metrics_only = config, runtime, metrics
        section = config.metrics if metrics else config.api
        self.api = ReadOnlyAPI(config, runtime)
        settings = Config()
        settings.network.bind_address, settings.network.port = section.bind_address, section.port
        settings.limits.max_connections = settings.limits.max_connections_per_ip = config.api.max_connections
        settings.limits.max_request_bytes, settings.limits.max_response_bytes = 8192, 65536
        settings.limits.first_byte_timeout = settings.limits.idle_timeout = 1
        settings.limits.total_timeout = 2
        settings.limits.connections_per_second = config.api.requests_per_second
        self.server = SelectorServer(settings, on_data=self.received)
        self.thread = None
        self.status = 'disabled'

    def received(self, peer, destination, data):
        if not data.endswith(b'\r\n\r\n'):
            if b'\r\n\r\n' not in data:
                return b''
            return response(400, {'error': 'request_body_or_pipeline_not_supported'})
        try:
            lines = data[:-4].split(b'\r\n')
            method, target, version = lines[0].decode('ascii').split(' ')
            if version not in ('HTTP/1.0', 'HTTP/1.1') or len(target) > 2048:
                raise ValueError('request framing')
            headers = {}
            for line in lines[1:]:
                key, sep, value = line.partition(b':')
                key = key.lower()
                if not sep or key in headers or not key or any(byte <= 32 or byte >= 127 for byte in key) or any(byte < 32 or byte == 127 for byte in value):
                    raise ValueError('invalid headers')
                headers[key] = value.strip()
            if b'transfer-encoding' in headers or headers.get(b'content-length', b'0') != b'0':
                raise ValueError('no request body')
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path.startswith('/') or parsed.fragment:
                raise ValueError('origin-form required')
            host = headers.get(b'host', b'').decode('ascii')
            section = self.config.metrics if self.metrics_only else self.config.api
            expected = {section.bind_address, f'{section.bind_address}:{section.port}', 'localhost',
                        f'localhost:{section.port}', f'[{section.bind_address}]', f'[{section.bind_address}]:{section.port}'}
            if host and host not in expected or version == 'HTTP/1.1' and not host:
                return response(403, {'error': 'host_not_allowed'})
            pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=12, strict_parsing=True)
            if len(dict(pairs)) != len(pairs):
                raise ValueError('duplicate query parameter')
            if self.metrics_only:
                if not self.api.rate.allow():
                    return response(429, {'error': 'request_rate_limit'})
                if self.api.token and not hmac.compare_digest(headers.get(b'authorization', b''), b'Bearer ' + self.api.token):
                    return response(401, {'error': 'authentication_required'})
                if method != 'GET' or parsed.path != '/metrics' or pairs:
                    return response(404, {'error': 'not_found'})
                if b'origin' in headers:
                    return response(403, {'error': 'origin_not_allowed'})
                return response(200, self.runtime.registry.prometheus().encode(), 'text/plain; version=0.0.4; charset=utf-8')
            status, body = self.api.handle(method, unquote(parsed.path), dict(pairs), headers)
            result = response(status, body)
            if len(result) > self.config.api.max_response_bytes:
                return response(413, {'error': 'response_byte_limit'})
            return result
        except (ValueError, UnicodeError):
            return response(400, {'error': 'invalid_http_request'})

    def start(self):
        self.thread = threading.Thread(target=self.server.serve_forever, name='metrics-http' if self.metrics_only else 'api-http', daemon=True)
        self.thread.start()
        self.server.ready.wait(1)
        self.status = 'unavailable' if self.server.error or not self.server.running else 'healthy'

    def close(self, timeout=1):
        self.server.stop()
        if self.thread:
            self.thread.join(timeout)
        self.status = 'disabled'
