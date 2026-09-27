"""Production entrypoints exercised only with local files and loopback clients."""
import contextlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from scapy.all import IP, TCP, wrpcap
from eye_for_an_eye.cli import main

ROOT = Path(__file__).resolve().parents[1]


class CliIntegrationTests(unittest.TestCase):
    def test_passive_pcap_replay_has_no_sockets_or_egress(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / 'synthetic.pcap'
            settings = Path(directory) / 'capture.toml'
            # P2 emits one event per feature; keep this no-egress test independent
            # from the separately tested JSONL sampling policy.
            settings.write_text('[logging]\nevents_per_second=1000.0\nper_source_per_second=1000.0\n', encoding='utf-8')
            packets = []
            for index in range(3):
                packet = IP(src='192.0.2.1', dst='127.0.0.1', ttl=61, id=index) / TCP(
                    sport=23456, dport=80, flags='A', options=[('Timestamp', (1000 + index * 100, 0))])
                packet.time = 100 + index
                packets.append(packet)
            wrpcap(str(capture), packets)
            for command in ('ip_id', 'nat', 'uptime'):
                output = io.StringIO()
                with self.subTest(command=command), contextlib.redirect_stdout(output), \
                        patch('socket.socket', side_effect=AssertionError('PCAP replay opened a socket')):
                    self.assertEqual(main(['--pcap', str(capture), '--config', str(settings)], command=command), 0)
                events = [json.loads(line) for line in output.getvalue().splitlines()]
                base = [event for event in events if event['event_type'] == 'network_observation']
                self.assertEqual(len(base), 3)
                self.assertEqual(base[0]['observations']['ip_version'], 4)
                self.assertFalse(any(event['event_type'] == 'path_measurement' for event in events))
                self.assertEqual(events[-1]['event_type'], 'shutdown_metrics')

    def test_lab_cli_enforces_global_bytes_connections_and_time(self):
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        with tempfile.TemporaryDirectory() as directory:
            logfile = Path(directory) / 'lab.jsonl'
            process = subprocess.Popen([sys.executable, '-B', str(ROOT / '+garbage.py'), str(port), 'tcp',
                '--lab', '--lab-max-bytes', '64', '--lab-max-connections', '2', '--lab-max-duration', '.6',
                '--log-file', str(logfile)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            total = 0
            started = time.monotonic()
            try:
                deadline = started + 3
                while True:
                    try:
                        first = socket.create_connection(('127.0.0.1', port), timeout=.1)
                        break
                    except (ConnectionRefusedError, TimeoutError):
                        if process.poll() is not None or time.monotonic() >= deadline:
                            self.fail('lab listener did not start')
                        time.sleep(.02)
                with first:
                    first.settimeout(2)
                    while data := first.recv(128):
                        total += len(data)
                with socket.create_connection(('127.0.0.1', port), timeout=1) as second:
                    second.settimeout(2)
                    while data := second.recv(128):
                        total += len(data)
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout, '')
                self.assertEqual(total, 64)
                self.assertLess(time.monotonic() - started, 3)
                events = [json.loads(line) for line in logfile.read_text(encoding='utf-8').splitlines()]
                metrics = events[-1]['observations']['listener']
                self.assertEqual(metrics['accepted'], 2)
                self.assertEqual(metrics['closed'], 2)
                self.assertEqual(metrics['response_bytes'], 64)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)
