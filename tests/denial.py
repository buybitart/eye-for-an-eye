"""Telling a claim apart from a denial of that claim, in a document or a message.

This exists because the same mistake has now been made three times in this
project's test suite, and it fails in a specific and damaging direction.

A documentation test wants to check that nothing claims, say, that drift means an
attack. The obvious implementation is `assertNotIn('attack', body)`. The document
that states the rule most clearly says *"drift is never evidence of an attack"* —
and fails. So does the page that opens with *"this is not the AI replacing itself
with a better AI"*, which is the single most useful sentence on it.

The failure mode is not the false positive. It is what somebody does about the
false positive at the end of a long day: delete the sentence. The test then
passes, the document is worse, and the rule it explained is now enforced by
nothing but everybody's memory.

So the check here asks a narrower question: does this phrase appear *outside* a
denial of it? A window of surrounding text is inspected for negation, and an
occurrence inside one does not count.

This is a heuristic and it is meant to be. It cannot parse English, and a
determined author could write a claim it misses. It handles the case that
actually occurs — a document quoting a wrong idea in order to reject it — and it
fails towards allowing text rather than towards deleting it, which is the right
direction for a test whose job is to protect prose.
"""

#: Words and phrases that turn a nearby occurrence into a denial of it.
DENIALS = ('not', 'never', 'no ', 'nothing', 'rather than', 'cannot', 'may be',
           'is not', 'does not', 'neither', 'without', 'instead of', 'stops being')

#: How much text either side of an occurrence is inspected. Wide enough to catch
#: a negation at the start of the sentence, narrow enough not to be satisfied by
#: an unrelated "not" two sentences away.
BEFORE = 120
AFTER = 40


def occurrences(text, phrase, *, denials=DENIALS, before=BEFORE, after=AFTER):
    """Windows around each occurrence of `phrase` that is not inside a denial.

    `text` should be lowercase and whitespace-normalised, which is how the
    documentation tests read a file.
    """
    found, start = [], 0
    while (index := text.find(phrase, start)) != -1:
        window = text[max(0, index - before):index + len(phrase) + after]
        if not any(denial in window for denial in denials):
            found.append(window)
        start = index + len(phrase)
    return found


def asserted(text, phrase, **options):
    """True when `phrase` is claimed somewhere rather than only denied."""
    return bool(occurrences(text, phrase, **options))
