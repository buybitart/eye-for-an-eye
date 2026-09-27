"""Every record this package writes must be one the production reader accepts. P15.4.

Found by a corpus build failing outright, which is the friendly version of this
bug. `write_pcap` derived the microsecond field as
`round((stamp - int(stamp)) * 1000000)`, and a fractional part of 0.9999996
rounds to exactly 1000000 — one microsecond past the largest legal value. The
production reader refuses such a record with "invalid or oversized PCAP record",
correctly, so the whole capture becomes unreadable.

It had been latent since the function was written. It took the roughly quarter of
a million records of the P15.4 development corpus before a timestamp landed on
the boundary, which is exactly the shape of defect a round-trip property test
catches and an example-based test does not: nothing about the *behaviour* being
generated was unusual, only the arithmetic of one float.

So this file checks the property rather than the example — every record the
writer produces is legal, for timestamps chosen to sit on and around the
boundary — and then confirms the production reader really does read them back.
"""
from pathlib import Path
import struct
import unittest

from dataset.generators.packets import write_pcap
from eye_for_an_eye.offline import packets

#: The same limit `eye_for_an_eye.offline.packets` enforces. Stated here rather
#: than imported, because a test that reads its bound from the code it is
#: checking cannot notice that bound changing.
MICROSECOND_SCALE = 1000000
BASE = 1767225600.0


def records(path):
    """(seconds, microseconds, included, original) for every record in a file."""
    with Path(path).open('rb') as stream:
        header = stream.read(24)
        snaplen = struct.unpack('<I', header[16:20])[0]
        while True:
            frame = stream.read(16)
            if len(frame) != 16:
                return
            seconds, micros, included, original = struct.unpack('<IIII', frame)
            stream.read(included)
            yield seconds, micros, included, original, snaplen


class TestNoRecordCanCarryAnIllegalMicrosecond(unittest.TestCase):

    #: Fractional parts that round to a full second, that sit just below one,
    #: and a few ordinary ones for contrast. The first two are the bug.
    FRACTIONS = (0.9999996, 0.99999999, 0.9999995, 0.9999994, 0.999999, 0.5, 0.0,
                 0.000001, 0.0000004)

    def setUp(self):
        self.directory = Path(__file__).parent / 'fixtures' / 'p15_4_tmp'
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'writer.pcap'

    def tearDown(self):
        self.path.unlink(missing_ok=True)
        if self.directory.exists() and not any(self.directory.iterdir()):
            self.directory.rmdir()

    def test_every_written_microsecond_is_below_one_million(self):
        rows = [(BASE + offset + fraction, b'\x45' + bytes(39))
                for offset, fraction in enumerate(self.FRACTIONS)]
        write_pcap(self.path, rows)
        for seconds, micros, included, original, snaplen in records(self.path):
            with self.subTest(seconds=seconds, micros=micros):
                self.assertLess(micros, MICROSECOND_SCALE)
                self.assertLessEqual(included, snaplen)
                self.assertLessEqual(included, original)

    def test_a_microsecond_that_rounds_up_carries_into_the_seconds(self):
        """Not dropped, not clamped, not truncated: carried. A clamp to 999999
        would keep the file legal and move the packet backwards in time, which
        is a worse bug because nothing would ever fail."""
        write_pcap(self.path, [(BASE + 0.9999996, b'\x45' + bytes(39))])
        seconds, micros, *_ = next(iter(records(self.path)))
        self.assertEqual(seconds, int(BASE) + 1)
        self.assertEqual(micros, 0)

    def test_the_production_reader_accepts_what_the_writer_produces(self):
        """The property that actually matters. The two halves are in different
        packages and only a round trip can say they agree."""
        rows = [(BASE + offset + fraction, b'\x45' + bytes(39))
                for offset, fraction in enumerate(self.FRACTIONS)]
        write_pcap(self.path, rows)
        read = list(packets(self.path))
        self.assertEqual(len(read), len(rows))
        for (written, _), (stamp, _) in zip(rows, read, strict=True):
            with self.subTest(written=written):
                self.assertAlmostEqual(written, stamp, places=5)

    def test_ordinary_timestamps_are_written_exactly_as_before(self):
        """The fix may not move a record that was already legal — every corpus
        generated before it has to stay byte-reproducible."""
        write_pcap(self.path, [(BASE + 12.345678, b'\x45' + bytes(39))])
        seconds, micros, *_ = next(iter(records(self.path)))
        self.assertEqual(seconds, int(BASE) + 12)
        self.assertEqual(micros, 345678)


if __name__ == '__main__':
    unittest.main()
