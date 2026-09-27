"""P10 log reading and bounded memory.

Two groups. The first treats every log line as hostile text and checks nothing
raises, nothing leaks and nothing unbounded happens. The second checks that a
source generating a million distinct URLs costs the same as one generating
sixty-four — the attack where the protection becomes the outage.
"""
import json
import os
import time
import unittest
import tempfile
from pathlib import Path

from eye_for_an_eye.web.event import (MAX_PATH_SEGMENTS, WebEventError, build,
                                      normalise_method, normalise_path, query_shape,
                                      sensitive_categories, shannon_entropy)
from eye_for_an_eye.web.identity import ClientResolver
from eye_for_an_eye.web.nginx import (LOG_FORMAT, LogTailer, NginxReaderError, NginxSource,
                                      ReaderStats, parse_line, parse_time)
from eye_for_an_eye.web.state import DistinctRing, WebSourceTable

SECRET = b'k' * 32


def line(**overrides):
    record = {'time': '2026-09-10T12:00:00+00:00', 'remote_addr': '198.51.100.7',
              'method': 'GET', 'uri': '/index.html', 'args': '', 'status': 200,
              'bytes_sent': 1024, 'request_length': 300, 'request_time': 0.012,
              'protocol': 'HTTP/1.1', 'host': 'example.test',
              'user_agent': 'Mozilla/5.0', 'referer': 'https://example.test/'}
    record.update(overrides)
    return json.dumps(record).encode()


class TestLineParsing(unittest.TestCase):
    def setUp(self):
        self.resolver = ClientResolver([])
        self.stats = ReaderStats()

    def parse(self, raw):
        return parse_line(raw, self.resolver, secret=SECRET, stats=self.stats)

    def test_a_normal_line_becomes_an_event(self):
        event = self.parse(line())
        self.assertEqual(event.client, '198.51.100.7')
        self.assertEqual(event.method, 'GET')
        self.assertEqual(event.status, 200)
        self.assertEqual(event.extension, 'document')

    def test_a_line_that_is_not_json_is_counted_not_raised(self):
        self.assertIsNone(self.parse(b'not json at all'))
        self.assertEqual(self.stats.parse_errors, 1)

    def test_a_json_array_is_refused(self):
        self.assertIsNone(self.parse(b'[1, 2, 3]'))
        self.assertEqual(self.stats.parse_errors, 1)

    def test_an_empty_line_is_ignored(self):
        self.assertIsNone(self.parse(b''))

    def test_a_missing_address_drops_the_line(self):
        self.assertIsNone(self.parse(line(remote_addr='')))
        self.assertEqual(self.stats.parse_errors, 1)

    def test_a_very_long_line_is_dropped_rather_than_parsed(self):
        self.assertIsNone(self.parse(line(uri='/' + 'a' * 100_000)))
        self.assertEqual(self.stats.oversized, 1)

    def test_a_very_long_path_is_bounded(self):
        event = self.parse(line(uri='/' + 'b' * 5000))
        self.assertLessEqual(event.path_length, 2100)

    def test_a_long_user_agent_is_bounded_rather_than_stored(self):
        # Long, but inside the line limit, so the line is read and the value is
        # what gets bounded. A line long enough to blow the limit is covered above.
        event = self.parse(line(user_agent='U' * 4000))
        self.assertLessEqual(event.agent['agent_length'], 512)

    def test_a_deeply_nested_path_is_bounded(self):
        event = self.parse(line(uri='/' + '/'.join(str(n) for n in range(500))))
        self.assertLessEqual(event.path_depth, MAX_PATH_SEGMENTS)

    def test_control_characters_cannot_forge_a_log_line(self):
        """§112. A newline in a value must not survive into anything we write."""
        event = self.parse(line(user_agent='ok\r\nFAKE: injected', uri='/a\nb'))
        text = json.dumps(event.explain())
        self.assertNotIn('\\n', text)
        self.assertNotIn('FAKE', text)

    def test_invalid_unicode_does_not_crash(self):
        raw = b'{"remote_addr":"198.51.100.7","method":"GET","uri":"/\xff\xfe","status":200}'
        event = self.parse(raw)
        self.assertIsNotNone(event)

    def test_an_unknown_method_becomes_other_rather_than_a_new_string(self):
        event = self.parse(line(method='FROBNICATE'))
        self.assertEqual(event.method, 'OTHER')

    def test_a_huge_numeric_value_is_bounded(self):
        event = self.parse(line(bytes_sent=10 ** 30, status=999999))
        self.assertEqual(event.response_bytes, 0)
        self.assertEqual(event.status, 0)

    def test_an_ipv6_client_is_read(self):
        event = self.parse(line(remote_addr='2001:db8::5'))
        self.assertEqual(event.client, '2001:db8::5')

    def test_a_line_carrying_a_credential_field_is_dropped_whole(self):
        """A misconfigured log_format must fail loudly, not be quietly stripped."""
        for field in ('authorization', 'cookie', 'password', 'request_body'):
            with self.subTest(field=field):
                stats = ReaderStats()
                self.assertIsNone(parse_line(line(**{field: 'secret-value'}),
                                             self.resolver, stats=stats))
                self.assertEqual(stats.rejected_fields, 1)
                self.assertIn('credential field', stats.last_error)

    def test_a_bad_timestamp_falls_back_to_now(self):
        self.assertIsNotNone(parse_time('not-a-time'))
        self.assertIsNotNone(parse_time(''))
        self.assertIsNotNone(parse_time(None))


class TestPrivacy(unittest.TestCase):
    def setUp(self):
        self.resolver = ClientResolver([])

    def test_a_query_value_never_reaches_the_event(self):
        event = parse_line(line(uri='/reset', args='token=SUPERSECRET123&email=a@b.test'),
                           self.resolver, secret=SECRET)
        text = json.dumps(event.explain())
        self.assertNotIn('SUPERSECRET123', text)
        self.assertNotIn('a@b.test', text)
        self.assertTrue(event.query['query_present'])
        self.assertEqual(event.query['query_parameters'], 2)

    def test_a_path_is_not_stored_by_default(self):
        event = parse_line(line(uri='/users/12345/reset/abcdef'), self.resolver,
                           secret=SECRET)
        self.assertEqual(event.stored_path, '')
        self.assertNotIn('abcdef', json.dumps(event.explain()))

    def test_a_path_is_stored_only_when_asked_for(self):
        event = parse_line(line(uri='/users/12345'), self.resolver, secret=SECRET,
                           store_path=True)
        self.assertEqual(event.stored_path, '/users/12345')

    def test_the_user_agent_string_itself_is_never_kept(self):
        event = parse_line(line(user_agent='Mozilla/5.0 (secret build 9.9)'),
                           self.resolver, secret=SECRET)
        self.assertNotIn('secret build', json.dumps(event.explain()))
        self.assertEqual(event.agent['agent_family'], 'declared_browser')

    def test_the_host_is_kept_as_a_digest_not_a_name(self):
        event = parse_line(line(host='private-internal.example'), self.resolver,
                           secret=SECRET)
        self.assertNotIn('private-internal', json.dumps(event.explain()))
        self.assertTrue(event.host_key)

    def test_the_same_path_gives_the_same_key_and_a_different_one_differs(self):
        first = parse_line(line(uri='/a'), self.resolver, secret=SECRET)
        again = parse_line(line(uri='/a'), self.resolver, secret=SECRET)
        other = parse_line(line(uri='/b'), self.resolver, secret=SECRET)
        self.assertEqual(first.path_key, again.path_key)
        self.assertNotEqual(first.path_key, other.path_key)

    def test_without_a_secret_no_path_key_is_produced(self):
        event = parse_line(line(uri='/a'), self.resolver, secret=None)
        self.assertEqual(event.path_key, '')

    def test_the_event_says_what_it_contains(self):
        event = parse_line(line(), self.resolver, secret=SECRET)
        self.assertIn('no path', event.explain()['contents'])
        self.assertIn('no credential', event.explain()['contents'])


class TestNormalisation(unittest.TestCase):
    """§114, §115. One well-defined pass, for analysis only."""

    def test_dot_segments_are_resolved(self):
        self.assertEqual(normalise_path('/a/./b'), '/a/b')
        self.assertEqual(normalise_path('/a/b/../c'), '/a/c')
        self.assertEqual(normalise_path('/a/../../etc'), '/etc')

    def test_percent_encoding_is_decoded_once(self):
        self.assertEqual(normalise_path('/a/%2e/b'), '/a/b')
        self.assertEqual(normalise_path('/a%2fb'), '/a/b')

    def test_double_encoding_is_not_decoded_twice(self):
        """%252e decodes once to %2e and stops. Decoding again is how an analyser
        and its web server end up disagreeing about what was requested."""
        self.assertEqual(normalise_path('/a/%252e%252e/b'), '/a/%2e%2e/b')

    def test_invalid_encoding_does_not_raise(self):
        for path in ('/%', '/%zz', '/%2', '/%%%%'):
            with self.subTest(path=path):
                self.assertTrue(normalise_path(path).startswith('/'))

    def test_a_query_string_never_reaches_the_path(self):
        self.assertEqual(normalise_path('/a?b=c'), '/a')
        self.assertEqual(normalise_path('/a#frag'), '/a')

    def test_an_empty_path_becomes_root(self):
        self.assertEqual(normalise_path(''), '/')
        self.assertEqual(normalise_path(None), '/')

    def test_backslashes_are_treated_as_separators(self):
        self.assertEqual(normalise_path('/a\\b'), '/a/b')

    def test_unusual_unicode_does_not_crash(self):
        for path in ('/\u202e/admin', '/\x00x', '/\u65e5\u672c\u8a9e', '/' + '\ud800' * 5):
            with self.subTest(path=path):
                self.assertTrue(normalise_path(path).startswith('/'))

    def test_method_normalisation_is_case_insensitive(self):
        self.assertEqual(normalise_method('get'), 'GET')
        self.assertEqual(normalise_method('  post '), 'POST')

    def test_entropy_separates_generated_paths_from_real_ones(self):
        self.assertGreater(shannon_entropy('/a8f3k2x91zqw7'), shannon_entropy('/aaaaaaa'))

    def test_sensitive_categories_are_bounded_and_named(self):
        self.assertEqual(sensitive_categories('/.git/config'), ('version_control',))
        self.assertIn('cms', sensitive_categories('/wp-admin/'))
        self.assertEqual(sensitive_categories('/blog/about'), ())

    def test_a_query_with_many_parameters_is_bounded(self):
        shape = query_shape('&'.join(f'p{n}=v{n}' for n in range(10_000)))
        self.assertLessEqual(shape['query_parameters'], 64)
        self.assertLessEqual(shape['query_length'], 2048)


class TestBoundedMemory(unittest.TestCase):
    """§34, §136. A million unique URLs must cost what sixty-four cost."""

    def resolver(self):
        return ClientResolver([])

    def event(self, path, client='198.51.100.7', host='example.test', agent='x'):
        from datetime import datetime, timezone
        return build(timestamp=datetime.now(timezone.utc),
                     identity=self.resolver().resolve(client), method='GET', path=path,
                     status=404, host=host, user_agent=agent, secret=SECRET)

    def test_a_hundred_thousand_unique_paths_stay_bounded(self):
        table = WebSourceTable()
        for index in range(100_000):
            table.observe(self.event(f'/random-{index}'), index * 0.001)
        state = table.get('198.51.100.7')
        self.assertLessEqual(len(state.paths), 64)
        self.assertLessEqual(len(state.requests), 512)
        self.assertTrue(state.paths.saturated)
        self.assertEqual(state.total_requests, 100_000)

    def test_many_unique_hosts_stay_bounded(self):
        table = WebSourceTable()
        for index in range(10_000):
            table.observe(self.event('/', host=f'h{index}.test'), index * 0.01)
        self.assertLessEqual(len(table.get('198.51.100.7').hosts), 16)

    def test_many_unique_user_agents_stay_bounded(self):
        table = WebSourceTable()
        for index in range(10_000):
            table.observe(self.event('/', agent=f'agent-{index}'), index * 0.01)
        self.assertLessEqual(len(table.get('198.51.100.7').agents), 8)

    def test_many_unique_sources_stay_bounded(self):
        table = WebSourceTable(max_sources=100)
        for index in range(20_000):
            table.observe(self.event('/', client=f'198.51.{index // 250}.{index % 250}'),
                          index * 0.01)
        self.assertLessEqual(len(table), 100)
        self.assertGreater(table.evictions, 0)

    def test_a_flood_of_new_sources_does_not_evict_the_active_one_first(self):
        """Least-recently-used, so a busy source survives a flood of fresh ones."""
        table = WebSourceTable(max_sources=50)
        watched = '198.51.100.7'
        for index in range(500):
            table.observe(self.event('/', client=f'203.0.113.{index % 250}'), index)
            if index % 5 == 0:
                table.observe(self.event('/', client=watched), index)
        self.assertIsNotNone(table.get(watched))

    def test_quiet_sources_expire(self):
        table = WebSourceTable(ttl_seconds=60)
        table.observe(self.event('/', client='198.51.100.1'), 0.0)
        table.observe(self.event('/', client='198.51.100.2'), 10.0)
        self.assertEqual(table.expire(200.0), 2)
        self.assertEqual(len(table), 0)

    def test_the_distinct_ring_saturates_rather_than_growing(self):
        ring = DistinctRing(8)
        for index in range(10_000):
            ring.add(f'key-{index}')
        self.assertLessEqual(len(ring), 8)
        self.assertTrue(ring.saturated)

    def test_a_hundred_thousand_paths_run_in_reasonable_time(self):
        table = WebSourceTable()
        started = time.perf_counter()
        for index in range(100_000):
            table.observe(self.event(f'/p{index}'), index * 0.001)
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 30.0, f'100k requests took {elapsed:.1f}s')


class TestRotation(unittest.TestCase):
    """§39. A reader that misses logrotate stops working silently."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'access.log'
        self.path.write_bytes(b'')

    def append(self, *lines):
        with self.path.open('ab') as handle:
            for item in lines:
                handle.write(item + b'\n')

    def test_new_lines_are_read(self):
        tailer = LogTailer(path=str(self.path))
        self.assertTrue(tailer.open(from_end=True))
        self.append(line(), line())
        self.assertEqual(len(tailer.read()), 2)

    def test_a_first_open_does_not_replay_history(self):
        self.append(line(), line(), line())
        tailer = LogTailer(path=str(self.path))
        tailer.open(from_end=True)
        self.assertEqual(tailer.read(), [])

    def test_a_renamed_file_is_detected_and_reopened(self):
        tailer = LogTailer(path=str(self.path))
        tailer.open(from_end=True)
        self.append(line())
        tailer.read()
        os.rename(self.path, str(self.path) + '.1')
        self.path.write_bytes(b'')
        self.append(line(uri='/after-rotation'))
        events = tailer.read()
        self.assertEqual(tailer.stats.rotations, 1)
        self.assertEqual(len(events), 1)

    def test_a_truncated_file_is_detected(self):
        tailer = LogTailer(path=str(self.path))
        tailer.open(from_end=True)
        self.append(line(), line())
        tailer.read()
        self.path.write_bytes(b'')
        self.append(line(uri='/after-truncate'))
        self.assertEqual(len(tailer.read()), 1)
        self.assertEqual(tailer.stats.rotations, 1)

    def test_a_partial_line_is_not_read_until_it_is_complete(self):
        tailer = LogTailer(path=str(self.path))
        tailer.open(from_end=True)
        with self.path.open('ab') as handle:
            handle.write(b'{"remote_addr":"198.51.100.7"')
        self.assertEqual(tailer.read(), [])
        with self.path.open('ab') as handle:
            handle.write(b',"method":"GET","uri":"/","status":200}\n')
        self.assertEqual(len(tailer.read()), 1)

    def test_a_missing_file_is_reported_rather_than_raised(self):
        tailer = LogTailer(path=str(Path(self.directory.name) / 'nope.log'))
        self.assertFalse(tailer.open())
        self.assertEqual(tailer.read(), [])
        self.assertGreaterEqual(tailer.stats.reopen_failures, 1)
        self.assertIn('cannot open', tailer.stats.last_error)

    def test_one_poll_is_bounded(self):
        tailer = LogTailer(path=str(self.path))
        tailer.open(from_end=True)
        self.append(*[line() for _ in range(500)])
        self.assertEqual(len(tailer.read(max_lines=100)), 100)


class TestSource(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'access.log'
        self.path.write_bytes(b'')

    def source(self, **kwargs):
        return NginxSource(str(self.path), ClientResolver([]), secret=SECRET, **kwargs)

    def test_a_source_needs_a_path(self):
        with self.assertRaises(NginxReaderError):
            NginxSource('', ClientResolver([]))

    def test_polling_produces_events(self):
        source = self.source()
        source.start(from_end=True)
        with self.path.open('ab') as handle:
            handle.write(line() + b'\n')
            handle.write(b'garbage\n')
            handle.write(line(uri='/second') + b'\n')
        events = source.poll()
        self.assertEqual(len(events), 2)
        self.assertEqual(source.stats.parse_errors, 1)

    def test_health_reports_what_an_operator_needs(self):
        source = self.source()
        source.start()
        health = source.health()
        self.assertTrue(health['open'])
        self.assertFalse(health['trusted_proxies_configured'])
        self.assertIn('lines_read', health)

    def test_the_documented_log_format_requests_nothing_sensitive(self):
        lowered = LOG_FORMAT.lower()
        for forbidden in ('authorization', 'cookie', 'request_body', 'http_authorization'):
            self.assertNotIn(forbidden, lowered)
        self.assertIn('escape=json', lowered)


class TestEventValidation(unittest.TestCase):
    def test_an_event_refuses_a_forbidden_field(self):
        from datetime import datetime, timezone
        from eye_for_an_eye.web.event import WebEvent
        with self.assertRaises(WebEventError):
            WebEvent(timestamp=datetime.now(timezone.utc), client='1.2.3.4', peer='1.2.3.4',
                     identity_confidence='HIGH', network_enforceable=True, method='GET',
                     status=200, path_depth=1, path_length=2, path_entropy=0.1,
                     extension='none', query={'cookie': 'x'})

    def test_an_event_refuses_an_unnormalised_method(self):
        from datetime import datetime, timezone
        from eye_for_an_eye.web.event import WebEvent
        with self.assertRaises(WebEventError):
            WebEvent(timestamp=datetime.now(timezone.utc), client='1.2.3.4', peer='1.2.3.4',
                     identity_confidence='HIGH', network_enforceable=True,
                     method='FROBNICATE', status=200, path_depth=1, path_length=2,
                     path_entropy=0.1, extension='none')


if __name__ == '__main__':
    unittest.main()
