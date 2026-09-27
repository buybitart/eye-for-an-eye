"""The Quick start must not be able to turn blocking on. P16 §10, §43, §118.

§118 states the property: the README must not activate host autonomous
enforcement as an accidental side effect. That is a property of a sequence of
commands, so it is checked as one — the commands are extracted from the
README's own Quick start block and run, and what they produce is inspected.

The alternative, reading the README and agreeing it looks safe, is how a Quick
start drifts: somebody adds a step, the prose still says "safe path", and
nothing disagrees.
"""
from pathlib import Path
import re
import tempfile
import unittest

from eye_for_an_eye.config import load_config
from eye_for_an_eye.configuration import initialize

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / 'README.md'


def shell_blocks(heading, *, first_only=False):
    """Every fenced shell block under a heading, up to the next heading.

    P18 split the README's one Quick start into two, because they were doing two
    jobs. `## Quick start` is now the beginner path — download, check, install,
    setup, start — and `## Administrator quick start` is the sequence that makes
    each component answer for itself. Both must be safe, and only one of them
    has an ordering to defend, so this helper takes the heading.
    """
    body = README.read_text(encoding='utf-8')
    # Case-insensitive, because heading capitalisation is a style rule and this
    # helper is asserting about commands. The callers all check that a block was
    # found, so a heading this cannot locate fails the test rather than skipping it.
    found = re.search(re.escape(heading), body, re.IGNORECASE)
    if not found:
        return []
    section = body[found.end():].split('\n## ', 1)[0]
    blocks = re.findall(r'```sh\n(.*?)```', section, re.DOTALL)
    if first_only:
        blocks = blocks[:1]
    return [line.strip() for block in blocks
            for line in block.splitlines() if line.strip()]


def quickstart_block():
    """Kept for the tests below that read the beginner Quick start."""
    return '\n'.join(shell_blocks('## Quick start'))


class TestTheQuickStartIsTheSafePath(unittest.TestCase):
    """The beginner Quick start. §118's property: it cannot turn blocking on."""

    def setUp(self):
        self.commands = shell_blocks('## Quick start')
        self.assertTrue(self.commands, 'no Quick start shell block was found')
        self.primary = shell_blocks('## Quick start', first_only=True)
        self.assertTrue(self.primary)

    def test_it_is_the_beginner_path_and_names_no_profile_at_all(self):
        """The beginner never chooses a profile; the installer chooses the safe
        one. What must not appear is the profile that blocks."""
        joined = ' '.join(self.commands)
        self.assertNotIn('production-autonomous', joined,
                         'the Quick start names the profile that blocks')
        self.assertIn('sh install.sh', joined)
        self.assertIn('eye-for-an-eye setup', joined)

    def test_the_installer_it_points_at_writes_the_safe_profile(self):
        """Where the profile assertion moved to: the installer, which is what
        actually decides it for a beginner."""
        body = (ROOT / 'scripts' / 'install.sh').read_text(encoding='utf-8')
        self.assertIn('PROFILE="production-shadow"', body)
        self.assertNotIn('PROFILE="production-autonomous"', body)

    def test_no_command_in_the_path_it_recommends_needs_root(self):
        """The recommended sequence is the first block, and it needs no root."""
        for command in self.primary:
            with self.subTest(command=command):
                self.assertNotIn('sudo', command)
                self.assertFalse(command.startswith('su '))

    def test_the_only_root_command_anywhere_in_it_is_a_package_install(self):
        """§16 asks for `sudo apt install ./eye-for-an-eye_<version>_<arch>.deb`
        as the Debian alternative, and installing a system package genuinely
        needs root. Everything else in the section must not."""
        for command in self.commands:
            if 'sudo' not in command:
                continue
            with self.subTest(command=command):
                self.assertTrue(command.startswith('sudo apt install ./eye-for-an-eye'),
                                'the Quick start uses sudo for something other than '
                                'installing this project\'s own package')


class TestTheAdministratorQuickStartIsAlsoTheSafePath(unittest.TestCase):
    """The sequence P16 wrote and tested, under the heading it now lives at."""

    def setUp(self):
        self.commands = shell_blocks('## Administrator quick start')
        self.assertTrue(self.commands,
                        'no Administrator quick start shell block was found')

    def test_it_selects_the_shadow_profile_and_not_the_autonomous_one(self):
        joined = ' '.join(self.commands)
        self.assertIn('--profile production-shadow', joined)
        self.assertNotIn('production-autonomous', joined,
                         'the Quick start names the profile that blocks')

    def test_no_command_in_it_needs_root(self):
        for command in self.commands:
            with self.subTest(command=command):
                self.assertNotIn('sudo', command)
                self.assertFalse(command.startswith('su '))

    def test_no_firewall_or_enforcement_command_appears(self):
        joined = ' '.join(self.commands).lower()
        for forbidden in ('firewall', 'nft', 'iptables', 'autonomy enable'):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, joined)

    def test_it_checks_the_configuration_before_it_uses_it(self):
        """§43's order: initialise, validate, then look, then do something."""
        joined = '\n'.join(self.commands)
        for earlier, later in (('config init', 'config validate'),
                               ('config validate', 'doctor'),
                               ('doctor', 'autonomy preflight')):
            with self.subTest(step=f'{earlier} before {later}'):
                self.assertLess(joined.index(earlier), joined.index(later))

    def test_it_does_not_end_on_a_command_a_fresh_install_cannot_run(self):
        """§95, and the reason this test exists.

        The Quick start ended with `run` until a dry run on a clean clone
        showed what a new reader would see: *sensor requires capture.pcap_path
        or capture.ipc_socket*. A sensor needs a capture helper, the template
        cannot know where one is, and a first command that fails is a first
        impression that the software does not work. Choosing a traffic source
        is now a step of its own, below the Quick start, with both options
        named.
        """
        self.assertNotIn('eye-for-an-eye run', ' '.join(self.commands),
                         'the Quick start starts a sensor that a fresh install '
                         'has no traffic source for')


class TestTheProfileTheQuickStartSelects(unittest.TestCase):
    """Running what it says produces a configuration that enforces nothing."""

    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self._workspace.cleanup)
        path = Path(self._workspace.name) / 'shadow.toml'
        initialize(str(path), 'production-shadow')
        self.config = load_config(str(path))

    def test_it_validates(self):
        self.config.validate()

    def test_it_blocks_nothing(self):
        self.assertFalse(self.config.enforcement.host_enabled)
        self.assertFalse(self.config.enforcement.enabled)
        self.assertFalse(self.config.firewall.enabled)

    def test_it_still_decides(self):
        """Safe is not the same as switched off."""
        self.assertTrue(self.config.autonomy.enabled)
        self.assertEqual(self.config.autonomy.mode, 'shadow')


class TestTheReadmeStatesTheValidationPosition(unittest.TestCase):
    """§4, §42, §119. The pending status belongs where a reader will meet it."""

    def setUp(self):
        self.body = ' '.join(README.read_text(encoding='utf-8').split()).lower()

    def test_it_says_real_world_validation_is_pending(self):
        self.assertIn('real-world validation of autonomous blocking is pending',
                      self.body)

    def test_it_points_at_the_validation_matrix(self):
        self.assertIn('docs/validation_status.md', self.body)
        self.assertTrue((ROOT / 'docs' / 'VALIDATION_STATUS.md').is_file())

    def test_it_makes_no_claim_the_evidence_does_not_support(self):
        for claim in ('production-proven', 'production proven', 'internet-validated',
                      'zero false positives', 'perfect bot detection',
                      'safe for every website', 'unhackable', 'military-grade'):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, self.body)

    def test_it_says_installing_does_not_enable_blocking(self):
        self.assertIn('installing this software does not enable blocking',
                      self.body)


class TestThePublicIdentity(unittest.TestCase):
    """§29, §103. One name, one licence, one copyright holder."""

    def test_the_licence_is_mit_with_the_stated_holder(self):
        body = (ROOT / 'LICENSE').read_text(encoding='utf-8')
        self.assertTrue(body.startswith('MIT License'))
        self.assertIn('Copyright (c) 2026 Aliaksandr Zasinets', body)
        # The substantive clauses, so a truncated or altered licence fails here.
        for clause in ('Permission is hereby granted, free of charge',
                       'without restriction',
                       'THE SOFTWARE IS PROVIDED "AS IS"',
                       'WITHOUT WARRANTY OF ANY KIND'):
            with self.subTest(clause=clause[:32]):
                self.assertIn(clause, body)

    def test_no_additional_restriction_was_added(self):
        body = (ROOT / 'LICENSE').read_text(encoding='utf-8').lower()
        for foreign in ('non-commercial', 'noncommercial', 'gnu general public',
                        'affero', 'creative commons'):
            with self.subTest(term=foreign):
                self.assertNotIn(foreign, body)

    def test_the_package_metadata_agrees(self):
        body = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        self.assertIn('license = "MIT"', body)
        self.assertIn('Aliaksandr Zasinets', body)

    def test_no_organisation_or_affiliation_is_invented(self):
        readme = ' '.join(README.read_text(encoding='utf-8').split()).lower()
        for invented in ('inc.', 'llc', 'gmbh', 'foundation', 'a company'):
            with self.subTest(term=invented):
                self.assertNotIn(invented, readme)


if __name__ == '__main__':
    unittest.main()
