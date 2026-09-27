from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from eye_for_an_eye.config import Config
from eye_for_an_eye.enrichment.geoip import lookup_geoip
from eye_for_an_eye.enrichment.rdap import normalize_rdap, lookup_rdap


class ProviderTests(unittest.TestCase):
    def test_mmdb_missing_is_graceful_and_provenance_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'missing.mmdb')
            config = Config()
            config.enrichment.mmdb_path = path
            config.validate()
            self.assertEqual(lookup_geoip('192.0.2.1', path)['reason'], 'database_missing')
            Path(path).write_bytes(b'fake fixture')
            reader = Mock()
            reader.get.return_value = {'country': {'names': {'en': 'Fixture'}}}
            reader.metadata.return_value.build_epoch = 123
            context = Mock()
            context.__enter__ = Mock(return_value=reader)
            context.__exit__ = Mock(return_value=False)
            with patch('maxminddb.open_database', return_value=context):
                result = lookup_geoip('192.0.2.1', path)
            self.assertEqual(result['data_source'], 'maxmind-mmdb')
            self.assertEqual(result['build_epoch'], 123)
            self.assertIsInstance(result['database_mtime_ns'], int)
            context.__exit__.assert_called_once()

    def test_rdap_has_integer_asn_and_registration_semantics(self):
        result = normalize_rdap({'asn': '64512', 'network': {'name': 'Fixture', 'cidr': '192.0.2.0/24'}})
        self.assertEqual(result.asn, 64512)
        self.assertEqual(result.source, 'rdap')
        self.assertFalse(result.identity_claim)
        self.assertEqual(normalize_rdap({'asn': 'bad'}).status, 'not_found')
        with patch('ipwhois.IPWhois') as provider:
            provider.return_value.lookup_rdap.return_value = {'asn': '64512'}
            data = lookup_rdap('192.0.2.1', 1)
            provider.return_value.lookup_rdap.assert_called_once_with(depth=0, retry_count=0)
        self.assertEqual(data['asn'], asdict(result)['asn'])
        self.assertIsNotNone(data['data_version'])
