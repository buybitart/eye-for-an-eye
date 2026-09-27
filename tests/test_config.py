import unittest
import tempfile
from pathlib import Path
from eye_for_an_eye.config import Config, load_config


class ConfigTests(unittest.TestCase):
    def test_toml_unknown_keys_types_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            secret = Path(directory) / 'deception.secret'
            secret.write_bytes(b'\x00' * 32)
            path.write_text('[deception]\nsecret_file = "deception.secret"\n', encoding='utf-8')
            self.assertEqual(Path(load_config(path).deception.secret_file), secret)
            for content in ('[unknown]\nenabled = true', '[network]\nport = "80"',
                            '[limits]\nmax_connections = true', '[limits]\nunbounded = true',
                            '[active_probes]\nallowed_cidrs = [true]'):
                path.write_text(content, encoding='utf-8')
                with self.subTest(content=content), self.assertRaises(ValueError):
                    load_config(path)

    def test_defaults(self):
        config = Config().validate()
        self.assertEqual(config.network.bind_address, "127.0.0.1")
        self.assertFalse(config.active_probes.enabled)
        self.assertFalse(config.network.udp_responses)
        self.assertFalse(config.enrichment.enabled)

    def test_invalid_values(self):
        for name, value in [("port", 0), ("port", 65536), ("protocol", "icmp"),
                            ("bind_address", "hostname.invalid"), ("udp_responses", True)]:
            config = Config()
            setattr(config.network, name, value)
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                config.validate()
        for value in (0, -1, float('nan'), float('inf'), True, '2'):
            config = Config()
            config.limits.total_timeout = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                config.validate()

    def test_active_and_lab_require_policy(self):
        config = Config()
        config.active_probes.enabled = True
        with self.assertRaises(ValueError):
            config.validate()

    def test_worker_limits_rejected_in_config(self):
        for section, name, value in [('enrichment', 'queue_size', 10001),
                                     ('enrichment', 'timeout', 61),
                                     ('active_probes', 'timeout', 60)]:
            config = Config()
            setattr(getattr(config, section), name, value)
            with self.subTest(section=section, name=name), self.assertRaises(ValueError):
                config.validate()
        config = Config()
        config.lab.enabled = True
        config.network.bind_address = '0.0.0.0'
        with self.assertRaises(ValueError):
            config.validate()
