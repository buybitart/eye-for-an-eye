# Publishing the repository and the release

Everything here is **prepared, not applied**. Nothing in this project can create a
repository, change a repository setting, or publish a release, and nothing has.
Each item below is an owner action with the exact text or setting to use.

See [GITHUB_SECURITY.md](GITHUB_SECURITY.md) for the security settings and
[RELEASE.md](RELEASE.md) for the build and gate process.

---

## About text

GitHub's **About** field, one sentence, 350 characters maximum:

```
Open-source protection for Linux websites and servers using mathematical behaviour analysis and local machine learning. Runs entirely on your own machine. Safe Monitoring by default; automatic blocking is opt-in and Linux only.
```

That is 224 characters. Every clause in it is true of the current build:

* *Linux websites and servers* — Linux is the platform with the complete feature
  set, and the platform table in `README.md` is what it claims.
* *mathematical behaviour analysis and local machine learning* — the maths engine
  is the primary path and the ONNX model is optional evidence.
* *Runs entirely on your own machine* — no cloud AI, no account, no telemetry. The
  one optional outbound feature, RDAP lookup, is off by default.
* *Safe Monitoring by default* — the installed profile is `production-shadow`.
* *automatic blocking is opt-in and Linux only* — it refuses to start until
  configured, and the enforcement backends refuse on other platforms.

It does not say *production-proven*, *AI-powered*, *stops every hacker* or *zero
false positives*, because none of those would be true.

---

## Topics

Ten, all of which describe something in the tree:

```
cybersecurity
network-security
web-security
intrusion-detection
bot-detection
honeypot
linux
python
onnx
machine-learning
```

Deliberately not used: `waf` (this is not a web application firewall),
`ai-security`, `zero-trust`, `enterprise`, `production-ready`.

---

## Release

**Title**

```
Eye for an Eye 0.8.0 RC1 — Public Beta
```

**Tag**: `v0.8.0rc1`

**Mark as pre-release: yes.** The version is a release candidate and real-world
validation of autonomous blocking is pending. It must not be labelled Stable or
Latest release while that is true.

**Body**: the contents of [RELEASE_NOTES.md](RELEASE_NOTES.md).

**Attachments**, all produced by the builders listed in
[DISTRIBUTION.md](DISTRIBUTION.md):

| File | Notes |
| --- | --- |
| `eye-for-an-eye-0.8.0rc1-linux-x86_64.tar.gz` | the primary Linux path |
| `eye-for-an-eye_0.8.0~rc1-1_all.deb` | Ubuntu 24.04 and derivatives with Python 3.12 |
| `Eye-for-an-Eye-0.8.0rc1-Windows.zip` | the Windows beginner path |
| `eye_for_an_eye-0.8.0rc1-py3-none-any.whl` | the Python package |
| `eye_for_an_eye-0.8.0rc1.tar.gz` | the source distribution |
| `sbom.cdx.json` | CycloneDX 1.6 |
| `SHA256SUMS` | hashes of everything above |

GitHub adds its own source archives automatically. Those are the repository at the
tag, not the curated release archive; the release notes should say which is which.

**Do not claim the artifacts are signed.** They are not. The release body points
at `SHA256SUMS` and says so.

---

## Badges

None are in `README.md`, on purpose. A CI badge and a release badge both report
state that does not exist until the first push has run and the first release is
published, and a badge that points nowhere is worse than no badge. Adding them is
an ordinary later commit, not part of the tagged release source.

Three are worth adding then, and no more:

| Badge | Why |
| --- | --- |
| CI status | says whether the test suite passes on the default branch |
| Licence | MIT, stated once at the top |
| Python version | 3.12 exactly, which is the single most common installation surprise |

Not worth adding: download counts, code coverage percentages, "maintained"
badges, chat badges for a chat that does not exist, and style badges.

---

## Owner actions, in order

1. Create the repository. Decide public or private first.
2. Verify the remote URL, then push. Nothing in this project infers permission to
   publish.
3. Set the About text and the topics above.
4. Enable Secret Scanning and Push Protection.
5. Enable Private Vulnerability Reporting, then add the `contact_links` entry in
   `.github/ISSUE_TEMPLATE/config.yml` with the real URL. It is commented out with
   a note saying exactly why.
6. Enable CodeQL default setup.
7. Create a ruleset on the default branch: pull request before merge, required CI,
   conversation resolution, no force push, no deletion.
8. Decide `CODEOWNERS`. It does not ship with the release: a review-routing file
   is repository maintenance, so it belongs in a later commit rather than in the
   tagged source.
9. Decide the commit-signing policy.
10. ~~Verify the pinned GitHub Action SHAs.~~ **Done.** All three tags — v4.4.0,
    v5.6.0 and v4.6.2 — were resolved against their official repositories with
    `git ls-remote`, confirmed to be lightweight tags pointing at commits,
    independently resolved by the owner to the same SHAs, and cross-checked
    against the workflow files. See
    [GITHUB_SECURITY.md](GITHUB_SECURITY.md#action-pins).
11. Supply the real Debian maintainer address to `build_deb.py --maintainer`, or
    confirm the one already used.
12. Create the release as described above, marked pre-release.

Until each of these is done on the real repository, it is an owner action and not
a completed step. No report in this project may record one as enabled on the
strength of having recommended it.
