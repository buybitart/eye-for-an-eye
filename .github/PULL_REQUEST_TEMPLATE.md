## What this changes

<!-- What behaviour differs after this, and why. -->

## Evidence

<!--
Which tests cover it, and their result. A change to detection needs its
evidence stated: what was measured, on what, and what the numbers do not say.
-->

## Checklist

- [ ] `pytest -q -m "not linux_lab"` passes.
- [ ] `ruff check` and `mypy eye_for_an_eye` pass.
- [ ] Documentation that describes this behaviour is updated in the same change.
- [ ] No new claim is made that the test suite does not support.
- [ ] This is not a security vulnerability report. (Those go through
      `SECURITY.md`, never a pull request, because a pull request is public.)
