# Project History

This folder held the development records written at the end of each early
phase: completion reports, diff summaries, a file inventory, one set of
performance measurements from a single machine, and an early design document
written before most of the code existed.

**They are not published.** They were written in Russian, and the public
documentation of this project is in English. The earlier version of this note
left that as an open decision for the maintainer: translate, keep, or remove.
The decision taken at the P16 release assembly was to remove them: they were
unmaintained, they described a much earlier version of the software, and
publishing a set of stale records in a second language would give a reader
something they could not check and would not be warned was out of date.

Several documentation pages still mention those records, because the
measurements in them were real and the pages say where their numbers came from.
Those references point here.

## What the Records Held, and Where the Same Information Is Now

| Record | What it held | Where to look instead |
|---|---|---|
| `P0`–`P7` completion reports | what each early phase finished, and its limits | [LIMITATIONS.md](../LIMITATIONS.md), [VALIDATION_STATUS.md](../VALIDATION_STATUS.md) |
| `P5`, `P6`, `P7` diff summaries | lists of changed files | the Git history |
| `P6_INVENTORY.md` | a file inventory of that era | [RELEASE_CONTENTS.md](../RELEASE_CONTENTS.md) |
| `P5_MEASUREMENTS.md` | fifty performance comparisons from one machine | [PERFORMANCE.md](../PERFORMANCE.md), and `python -m benchmarks.run` to measure your own hardware |
| the early design document | the design as first imagined | [ARCHITECTURE.md](../ARCHITECTURE.md), which describes the software that exists |

The benchmark output those measurements came from is regenerated rather than
shipped. [RELEASE_CONTENTS.md](../RELEASE_CONTENTS.md) lists which categories of
generated material are excluded from the published repository, and why.

## Why This Note Exists Rather Than Nothing at All

Deleting the folder outright would have left four documentation pages pointing
at files that are not there, and a reader following one of those links would
learn only that something was missing. A note saying what was removed, why, and
where the same information lives now is the smaller of the two gaps.
