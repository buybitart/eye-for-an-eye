import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
from eye_for_an_eye.calibration import evaluate_corpus, evaluate_labels, load_corpus
from eye_for_an_eye.cli import main
from eye_for_an_eye.config import Config
from eye_for_an_eye.offline import analyze_pcap, packets

FIXTURES = Path(__file__).parent / 'fixtures' / 'p2'


class OfflineTests(unittest.TestCase):
    def test_offline_cli_no_sockets_workers_egress_or_input_changes(self):
        path = FIXTURES / 'scan.pcap'
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        output, status = io.StringIO(), io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('network')), \
                patch('threading.Thread.start', side_effect=AssertionError('worker')), \
                patch('sqlite3.connect', side_effect=AssertionError('database')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(status):
            self.assertEqual(main(['analyze-pcap', str(path)]), 0)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(json.loads(status.getvalue())['packets'], 32)
        classifications = [row['hypotheses']['behavior']['classification'] for row in records if row['event_type'] == 'correlation_result']
        self.assertIn('scanner', classifications)
        self.assertFalse(any(row['observations'].get('record_truncated') for row in records))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_malformed_reorder_duplicates_and_ipv6_are_explicit(self):
        lines = []
        stats = analyze_pcap(FIXTURES / 'malformed.pcap', Config(), writer=lines.append)
        self.assertEqual(stats['packets'], 5)
        self.assertGreaterEqual(stats['parse_errors'], 1)
        records = [json.loads(line) for line in lines]
        ipv6 = [row for row in records if row['observations'].get('feature') == 'ipv6']
        self.assertEqual(ipv6[0]['observations']['measurements']['flow_label'], 123)
        partial = [row for row in records if row['observations'].get('feature') == 'tcp_options' and row['observations']['status'] == 'partial']
        self.assertTrue(partial)

    def test_offline_forbids_active_registry_and_firewall_config(self):
        for section, field in (('enrichment', 'enabled'), ('enrichment', 'rdap_enabled'), ('active_probes', 'enabled')):
            config = Config()
            setattr(getattr(config, section), field, True)
            if section == 'active_probes':
                config.active_probes.allowed_cidrs = ['127.0.0.1/32']
            with self.subTest(section=section, field=field), self.assertRaises(ValueError):
                analyze_pcap(FIXTURES / 'noise.pcap', config, writer=lambda line: None)

    def test_record_length_budget_before_allocation_and_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'oversize.pcap'
            path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101) +
                             struct.pack('<IIII', 1, 0, 2**30, 2**30))
            config = Config()
            config.storage.enabled = True
            config.storage.path = str(Path(directory) / 'must-not-create.db')
            with patch('sqlite3.connect', side_effect=AssertionError('database created before input validation')), self.assertRaises(ValueError):
                analyze_pcap(path, config, writer=lambda line: None)
            self.assertFalse(Path(config.storage.path).exists())
            path.write_bytes(b'pcapng unsupported')
            with self.assertRaises(ValueError):
                list(packets(path))

    def test_packet_and_output_limits_report_incomplete_analysis(self):
        stats = analyze_pcap(FIXTURES / 'scan.pcap', Config(), writer=lambda line: None, max_packets=2)
        self.assertTrue(stats['packet_limit_reached'])
        self.assertEqual(stats['packets'], 2)
        stats = analyze_pcap(FIXTURES / 'scan.pcap', Config(), writer=lambda line: None, max_output_bytes=4096)
        self.assertGreater(stats['output_dropped'], 0)
        self.assertLessEqual(stats['output_bytes'], 4096)

    def test_calibration_fixture_contract_and_known_metric_denominators(self):
        result = evaluate_corpus(FIXTURES / 'corpus.json')
        self.assertEqual(result['confusion_matrix']['scanner']['scanner'], 1)
        self.assertEqual(result['confusion_matrix']['noise']['noise'], 1)
        self.assertFalse(result['calibrated'])
        measured = evaluate_labels(['noise', 'scanner', 'bot'], ['scanner', 'scanner', 'noise'])
        self.assertEqual(measured['per_class']['scanner']['precision'], .5)
        self.assertEqual(measured['per_class']['scanner']['recall'], 1)
        self.assertEqual(measured['per_class']['scanner']['false_positive_rate'], .5)
        self.assertEqual(measured['per_class']['bot']['false_negative_rate'], 1)
        self.assertIsNone(measured['per_class']['bot']['precision'])

    def test_corpus_hash_and_path_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('corpus.json', 'scan.pcap', 'noise.pcap'):
                shutil.copyfile(FIXTURES / name, root / name)
            data = json.loads((root / 'corpus.json').read_text())
            data['samples'][0]['pcap'] = '../outside.pcap'
            (root / 'corpus.json').write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                list(load_corpus(root / 'corpus.json'))
            shutil.copyfile(FIXTURES / 'corpus.json', root / 'corpus.json')
            with (root / 'scan.pcap').open('ab') as stream:
                stream.write(b'changed')
            with self.assertRaises(ValueError):
                list(load_corpus(root / 'corpus.json'))
