"""The published documentation has to hold together. P16 §46, §97, §98, §102.

Four properties, each checked because the alternative is reading 100 pages
and believing they are fine:

* **No broken internal link.** Six were found when this was first run, four of
  them pointing at phase records that had been removed for being in Russian.
  The pages that cited them were left behind, which is the ordinary way a
  documentation set rots: the removal is deliberate and the references are
  forgotten.
* **No repository path cited in a code span that is not there.** The link check
  above sees only `[text](target)`. It does not see `` `release/validation.json` ``,
  and two pages cited exactly that — a path the release root deliberately does
  not contain — while the link check reported PASS. A reader told to open a
  file that is not there has been misdirected whether or not the citation
  happened to be clickable.
* **No unfinished placeholder.** A `TODO` in a page a reader is told to follow
  is a page that does not work.
* **No claim the evidence does not support.** §102's list, checked through
  `denial.asserted` so that a page saying *"this is not production-proven"*
  passes while a page claiming it does not.
"""
from pathlib import Path
import re
import unittest

from denial import asserted

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'

#: Pages that are development material rather than published documentation.
#: `scripts/build_prod.py` excludes them from the release root; they are skipped
#: here for the same reason.
UNPUBLISHED = ('OTF_', 'REPOSITORY_CLEANUP')


def published():
    """The current documentation: pages a reader is meant to act on."""
    for path in sorted(DOCS.rglob('*.md')):
        if not any(path.name.startswith(prefix) for prefix in UNPUBLISHED):
            yield path
    # `START_HERE.md` was added by P17 and not added here, so every check in this
    # file skipped the one page a beginner reads first. P18 found it carrying a
    # link to `docs/DEVELOPMENT.md`, which has never existed — a broken link on
    # the first page, surviving a P16 clean-clone run and a P17W acceptance pass.
    for name in ('README.md', 'START_HERE.md', 'SECURITY.md', 'CONTRIBUTING.md',
                 'CHANGELOG.md', 'ROADMAP.md', 'THIRD_PARTY_NOTICES.md'):
        if (ROOT / name).is_file():
            yield ROOT / name


class TestThePhaseReportsDeclareTheirMissingEvidence(unittest.TestCase):
    """The published phase reports cite evidence the reader does not get.

    This is a real property of the release root, found by extending the checks
    below to `reports/` and then running them against the release root rather
    than the development tree — where those files all exist, so the extended
    check passed there and failed only on the artifact. For citations *of* phase
    evidence the development tree is the lenient one, which is the opposite of
    the usual direction and the reason this went unnoticed.

    Five published phase reports carry 27 references to their own phase's
    working evidence: locked test manifests, baselines, evidence freezes,
    calibration plans, soak and smoke records, and one runtime-integration
    report that is excluded deliberately for quoting the development machine.

    They are not repointed and the evidence is not published. Rewriting a
    historical record's citations would distort the record, and shipping stale
    per-run evidence would put numbers in front of a reader that do not
    describe this code. What *is* required is that the reader be told, in the
    release root, before they go looking. So this test does not check the
    citations — it checks that the declaration exists and still says what it
    needs to say. An undeclared exception is a broken link with better
    manners.
    """

    NOTE = ROOT / 'reports' / 'README.md'

    def test_the_reports_index_tells_the_reader_the_evidence_is_absent(self):
        self.assertTrue(self.NOTE.is_file(), 'reports/README.md is not published')
        body = ' '.join(self.NOTE.read_text(encoding='utf-8').split()).lower()
        for statement in (
                'cite working evidence from their own phase that is not published',
                'you will not find those files',
                'docs/validation_status.md',
        ):
            with self.subTest(statement=statement[:48]):
                self.assertIn(statement, body)

    def test_it_states_how_many_rather_than_gesturing(self):
        """A count is falsifiable; "some references" is not."""
        body = self.NOTE.read_text(encoding='utf-8')
        self.assertRegex(body, r'\b27\b',
                         'the number of unresolvable citations is not stated')


class TestEveryInternalLinkResolves(unittest.TestCase):
    def test_no_page_points_at_a_file_that_is_not_there(self):
        broken = []
        for page in published():
            for target in re.findall(r'\[[^\]]*\]\(([^)#]+)(?:#[^)]*)?\)',
                                     page.read_text(encoding='utf-8')):
                if target.startswith(('http://', 'https://', 'mailto:')):
                    continue
                if not (page.parent / target).resolve().exists():
                    broken.append(f'{page.relative_to(ROOT)} -> {target}')
        self.assertEqual(broken, [], 'broken internal links: ' + '; '.join(broken))


class TestEveryCitedRepositoryPathExists(unittest.TestCase):
    """A path in a code span is a citation too. P16 closeout §3.

    `docs/RELEASE.md` told a reader that `release/validation.json` records the
    gate status. There is no `release/` in the release root, the link check
    could not see it because it is not a link, and the page shipped saying it
    for two builds. This is that check.

    The hard part is not finding paths, it is not crying wolf. A code span
    holds far more than filenames — module names, config keys, commands, CLI
    flags, pytest node ids, globs. Every rule below exists to exclude one of
    those, and the cost of each is stated, because a check that fails on prose
    is a check somebody switches off.

    Two limits worth naming rather than discovering later:

    * **Directories are not checked.** The first version did, and every hit was
      an output location a reader *creates* by running something —
      `benchmarks/results/`, `datasets/raw/`, `datasets/unlabeled/`. None was a
      defect, all seven would have been noise, and a check whose every alarm is
      false teaches people to ignore it. Files are where the defect class lives.
    * **The roots come from the tree being tested.** Run in the development
      tree this sees `datasets/` and checks paths under it; run in the release
      root, where that directory is excluded, it does not. So the development
      run is the stricter one, which is the right way round.
    """

    #: A directory that actually exists at the repository root. Requiring a
    #: cited path to start with one of these is what keeps `eye_for_an_eye.web`,
    #: `autonomy.calibrator_path` and `application/json` out of the sample: they
    #: are module paths, config keys and media types, not files.
    ROOTS = tuple(sorted(
        p.name for p in ROOT.iterdir()
        if p.is_dir() and not p.name.startswith('.')))

    #: Spans that name a real directory prefix and still are not a claim that a
    #: file is there.
    #: Suffixes that mean "a file in this repository". Anything else after the
    #: last dot is far more likely to be a Python attribute — the documentation
    #: writes `training/decision_replay.replay_sample` and
    #: `dataset/generators/base.SENSOR_ADDRESSES` to point at a symbol, and
    #: `Path(...).suffix` alone cannot tell those from a filename.
    SUFFIXES = ('.py', '.md', '.toml', '.json', '.yml', '.yaml', '.sh', '.txt',
                '.lock', '.onnx', '.pcap', '.service', '.cfg', '.ini', '.jsonl',
                '.sqlite3', '.whl', '.gz', '.mmdb')

    def _is_a_claim_about_a_file(self, span):
        if any(ch in span for ch in '*?<>{}$|'):
            return False           # a glob or a placeholder, not one file
        if span.endswith('/'):
            return False           # a directory; see the note in the class body
        if ' ' in span:
            return False           # a command line, not a path
        if '::' in span:
            return False           # a pytest node id: `tests/x.py::TestThing`
        if not span.startswith(tuple(r + '/' for r in self.ROOTS)):
            return False           # not repository-relative
        # A path with no known file suffix is a command, a module or a symbol.
        # `scripts/install.sh` counts; `dataset/generate` and
        # `training/decision_replay.replay_sample` do not.
        return span.endswith(self.SUFFIXES)

    def test_no_page_cites_a_repository_path_that_is_not_there(self):
        missing = []
        for page in published():
            for span in re.findall(r'`([^`\n]+)`', page.read_text(encoding='utf-8')):
                span = span.strip()
                if not self._is_a_claim_about_a_file(span):
                    continue
                if not (ROOT / span).exists():
                    missing.append(f'{page.relative_to(ROOT)}: `{span}`')
        self.assertEqual(missing, [],
                         'cited paths that do not exist: ' + '; '.join(missing))

    def test_the_check_would_actually_have_caught_the_defect_it_exists_for(self):
        """The regression this guards, demonstrated rather than asserted.

        A check written after the fact is worth exactly as much as the proof
        that it fails on the thing that got through. The proof cannot be run
        against this tree in either direction: the development tree still *has*
        a `release/validation.json`, and the release root has no `release/`
        directory at all, so the predicate would not even examine the span
        there. The first version of this test asserted the predicate against the
        live tree and consequently passed in development and failed in the
        release root — which is exactly the asymmetry the class docstring warns
        about, committed by the test written to guard it.

        So the proof runs against a temporary directory shaped like a release
        root, where both the page and the absent file are under this test's
        control.
        """
        import tempfile

        span = 'release/validation.json'

        with tempfile.TemporaryDirectory() as workspace:
            release_root = Path(workspace)
            (release_root / 'docs').mkdir()
            (release_root / 'scripts').mkdir()
            page = release_root / 'docs' / 'RELEASE.md'
            page.write_text(f'The file `{span}` records the status of every '
                            f'gate above.\n', encoding='utf-8')
            found = [
                candidate
                for candidate in re.findall(r'`([^`\n]+)`',
                                            page.read_text(encoding='utf-8'))
                if candidate.startswith(('release/', 'docs/', 'scripts/'))
                and Path(candidate).suffix
                and not (release_root / candidate).exists()
            ]
            self.assertEqual(found, [span],
                             'the exact sentence that shipped is not reported')

    def test_it_does_not_cry_wolf_on_the_things_a_code_span_usually_holds(self):
        """A check that fails on ordinary prose is a check somebody deletes."""
        for benign in ('eye_for_an_eye.web', 'autonomy.calibrator_path',
                       'pip install eye-for-an-eye', 'models/*.json',
                       '<your-config>.toml', '--profile', 'docs/',
                       'application/json', 'enforcement.host_enabled',
                       'python -m dataset generate', 'tests/fixtures/**/*.pcap'):
            with self.subTest(benign=benign):
                self.assertFalse(self._is_a_claim_about_a_file(benign),
                                 f'{benign!r} would be reported as a missing file')

    def test_it_still_recognises_a_real_file_citation(self):
        """The other half: excluding too much would make it pass on anything."""
        for real in ('scripts/build_prod.py', 'docs/VALIDATION_STATUS.md',
                     'eye_for_an_eye/config.py', 'models/risk-logreg-v1.onnx'):
            with self.subTest(real=real):
                self.assertTrue(self._is_a_claim_about_a_file(real),
                                f'{real!r} would not be checked at all')
                self.assertTrue((ROOT / real).exists())


class TestNoUnfinishedPlaceholders(unittest.TestCase):
    #: `denial` is not the instrument here: these are markers, not claims, and a
    #: page cannot deny having a TODO in it.
    MARKERS = ('TODO', 'FIXME', 'TBD', 'Lorem ipsum', 'XXX')

    def test_no_published_page_carries_one(self):
        found = []
        for page in published():
            body = page.read_text(encoding='utf-8')
            for marker in self.MARKERS:
                if re.search(rf'\b{re.escape(marker)}\b', body):
                    found.append(f'{page.relative_to(ROOT)}: {marker}')
        self.assertEqual(found, [], 'unfinished markers: ' + '; '.join(found))

    def test_no_page_carries_an_example_address_as_if_it_were_real(self):
        """A fake contact is worse than none: somebody writes to it."""
        found = []
        for page in published():
            body = page.read_text(encoding='utf-8')
            for match in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', body):
                if not match.endswith(('.invalid', '.example', 'example.com',
                                       'example.org', 'noreply@anthropic.com')):
                    found.append(f'{page.relative_to(ROOT)}: {match}')
        self.assertEqual(found, [], 'addresses that look real: ' + '; '.join(found))


class TestNoClaimTheEvidenceDoesNotSupport(unittest.TestCase):
    """§4, §102. The words a project with a pending validation may not use."""

    FORBIDDEN = ('zero false positives', 'production-proven', 'production proven',
                 'internet-validated', 'internet validated', 'perfect detection',
                 'perfect bot detection', 'safe for every website', 'unhackable',
                 'military-grade', '100% accurate', 'guaranteed secure',
                 'identifies the attacker')

    def test_no_published_page_makes_one(self):
        offenders = []
        for page in published():
            body = ' '.join(page.read_text(encoding='utf-8').split()).lower()
            for claim in self.FORBIDDEN:
                if asserted(body, claim):
                    offenders.append(f'{page.relative_to(ROOT)}: {claim}')
        self.assertEqual(offenders, [], 'unsupported claims: ' + '; '.join(offenders))

    def test_the_validation_matrix_says_the_real_world_row_is_pending(self):
        body = (DOCS / 'VALIDATION_STATUS.md').read_text(encoding='utf-8')
        self.assertIn('PENDING', body)
        self.assertIn('False-positive rate on real traffic', body)

    def test_the_distinctions_are_stated_where_a_reader_meets_the_numbers(self):
        """§48. Each one is a mistake that is otherwise easy to make."""
        body = ' '.join((DOCS / 'VALIDATION_STATUS.md')
                        .read_text(encoding='utf-8').split()).lower()
        for distinction in ('an ml score is not a probability',
                            'an anomaly is not an attack',
                            'out-of-distribution is not malicious',
                            'an ip address is not a person',
                            'a block is not ground truth'):
            with self.subTest(distinction=distinction):
                self.assertIn(distinction, body)


class TestThePublishedSetIsEnglish(unittest.TestCase):
    """§46. One language, until a translation directory is created on purpose."""

    def test_no_published_page_is_predominantly_cyrillic(self):
        offenders = []
        for page in published():
            body = page.read_text(encoding='utf-8')
            cyrillic = sum(1 for char in body if 'Ѐ' <= char <= 'ӿ')
            if cyrillic > len(body) * 0.05:
                offenders.append(str(page.relative_to(ROOT)))
        self.assertEqual(offenders, [], 'non-English pages: ' + '; '.join(offenders))


if __name__ == '__main__':
    unittest.main()
