# Repository and account hardening

This page is for whoever administers the published repository. It lists what to
turn on and what this project has already done, and it keeps those two apart:
a setting on a hosting account is not something a file in a repository can
assert.

Every remote setting below is reported as one of:

* **VERIFIED_ENABLED** — checked and on;
* **VERIFIED_DISABLED** — checked and off;
* **NOT_VERIFIED** — not checked from here;
* **OWNER_ACTION_REQUIRED** — cannot exist until the owner does something.

At the time of writing, none of these remote settings has been switched on and
none has been observed from here. Every one of them is therefore
`OWNER_ACTION_REQUIRED`, and nothing in this repository claims otherwise. A
setting is not enabled because a file recommends it.

## Account

* Two-factor authentication, with a hardware security key where possible and a
  TOTP application otherwise. SMS is the weakest of the three.
* SSH keys protected by a passphrase, held in an agent rather than on disk
  unprotected.
* Personal access tokens scoped to what they do and given an expiry. A token
  that can do everything is a token whose loss is unbounded.
* A password manager, and a different password from anything else.

## Repository settings

* **Private vulnerability reporting.** Settings → Code security → Private
  vulnerability reporting. This is the channel `SECURITY.md` describes, and
  until it is enabled that document describes a workflow rather than an
  available one.
* **Secret scanning** and **push protection**. Push protection is the one that
  matters most: it refuses the push rather than reporting the leak afterwards.
* **Code scanning.** Enable CodeQL through Settings → Code security → Code
  scanning → **Default setup**. This repository deliberately ships no CodeQL
  workflow file. A workflow would have to pin `github/codeql-action` to a commit
  SHA and then keep that pin current against an action that changes far more
  often than this project does; default setup is maintained by the hosting
  platform, needs no pin, and cannot go stale in a file nobody rereads. It is one
  layer and not proof of anything; a clean CodeQL run means CodeQL found nothing
  it knows how to look for.
* **Dependabot.** Configured in `.github/dependabot.yml` for Python and for
  GitHub Actions. Review every update; do not enable automatic merge. A
  dependency bot that merges on its own is a supply-chain path.

## Default branch ruleset

On the default branch, require:

* a pull request before merging;
* the `validate` status check to pass;
* conversation resolution before merging;
* no force push;
* no branch deletion.

Apply the ruleset to administrators too. A rule that the owner can bypass
silently is a rule that protects against nobody who matters.

## Signed commits and tags

Signing is not configured in this repository and no key was generated for it.
Enabling it is an owner action: create a signing key, register its public half
with the hosting account, and set `commit.gpgsign` or the equivalent for your
signing method. Release tags are worth signing even if commits are not.

Status: `COMMIT_SIGNING_OWNER_ACTION_REQUIRED`.

## What this repository already does

These are properties of files here, checkable by reading them:

* **Least privilege in continuous integration.** Workflows declare
  `permissions: contents: read`. Nothing requests write access it does not use.
* **No `pull_request_target`.** That trigger runs with the base repository's
  secrets and a fork's code, and this repository does not use it.
* **Third-party actions pinned to full commit SHAs**, with the version in a
  comment beside each one. A tag can be moved; a SHA cannot. See
  [Action pins](#action-pins) below for what has and has not been verified.
* **No secret is exposed to code from a fork.** Pull-request titles, bodies and
  branch names are not interpolated into shell.
* **A reviewed static-analysis baseline** in `security/bandit-reviewed.json`,
  pinned by exact code hash. Refreshing those hashes without review defeats the
  purpose of having them.
* **An install smoke test** that asserts the documented one-command install
  creates no firewall rule.

## Action pins

Three third-party actions are used, each pinned to a full 40-character commit SHA.
`ACTION_PINS = VERIFIED`.

| Action | Tag | Pinned SHA | Resolved from upstream | Object type | Result |
| --- | --- | --- | --- | --- | --- |
| `actions/checkout` | v4.4.0 | `11d5960a326750d5838078e36cf38b85af677262` | `11d5960a326750d5838078e36cf38b85af677262` | commit | **MATCH** |
| `actions/setup-python` | v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` | `a26af69be951a213d495a4c3e4e4022e16d87065` | commit | **MATCH** |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | commit | **MATCH** |

**How, and by whom.** Two independent checks, and they are worth keeping apart
because they establish different things.

The *upstream* half was machine-verified. Each tag was resolved directly against
its official repository — `https://github.com/actions/<name>.git` — with
`git ls-remote`, from a build environment with anonymous read access to those
repositories. Each `refs/tags/<tag>` resolves to the SHA in the table; each was
fetched and its object type confirmed to be `commit`, and no
`refs/tags/<tag>^{}` peeled reference exists for any of the three, which is how a
lightweight tag differs from an annotated one. That distinction matters: if these
were annotated tags, the SHA that `ls-remote` prints would be the *tag object*,
and a workflow pinned to a tag-object SHA would not resolve to the code anyone
reviewed. They are not annotated, so the SHA is the commit.

The project owner independently resolved the same three tags and reported the
same three SHAs. Two independent resolutions agreeing is the reason this table
says MATCH rather than "reported".

The *local* half was checked in the release root: that every SHA configured in
`.github/workflows/` is byte-identical to the SHA in the table, that all three
appear, that no fourth external action is used, and that nothing is pinned to a
tag or left unpinned. A verification list that does not correspond to what the
files actually contain proves nothing about the files.

Note the precision. What was resolved is patch releases — v4.4.0, v5.6.0,
v4.6.2 — and the comments beside the pins name those, not the major line. A
comment reading `# v4` beside a v4.4.0 pin is an invitation for somebody to
"update to the latest v4" and silently lose the mapping that was verified.

No SHA was invented, and no pin was replaced with a mutable tag or `@main` to make
a check pass.

**To re-verify** after any change to a pin. This needs no account, no token and
no `gh`; anonymous read access to the three public repositories is enough:

```sh
git ls-remote https://github.com/actions/checkout.git      refs/tags/v4.4.0
git ls-remote https://github.com/actions/setup-python.git   refs/tags/v5.6.0
git ls-remote https://github.com/actions/upload-artifact.git refs/tags/v4.6.2
```

Then check the tag is not annotated, because that is the step people skip:

```sh
git ls-remote https://github.com/actions/checkout.git 'refs/tags/v4.4.0^{}'
```

No output means a lightweight tag, so the SHA above is the commit. Output means
an annotated tag, and the *peeled* SHA on that second line is the commit to pin —
not the first one. If a SHA does not match, update the pin and the comment
together; a pin whose comment names a different version is worse than no comment.

## Before the first push

* Scan the history, not only the working tree. A secret removed in a later
  commit is still in the history, and publishing the history publishes it.
* Confirm the repository's visibility before the first push, not after.
* Confirm the remote URL. A typo can publish to an account that is not yours.
* Decide whether `CODEOWNERS` is wanted. This repository does not ship one. A
  single-maintainer project gains little from it, and a review-routing file is a
  repository-maintenance decision rather than part of a release, so adding one
  belongs in an ordinary later commit and not in the tagged source.

## After publication

* Enable the settings above in the order listed; push protection first.
* Watch the security advisories for the pinned dependencies.
* Re-run `scripts/security_scan.py` and `pip-audit` on a schedule rather than
  only when something prompts it.

## See also

* [Security policy](../SECURITY.md) — how to report a vulnerability
* [Threat model](THREAT_MODEL.md) — what this software defends against
* [Release process](../CONTRIBUTING.md) — how a change reaches a release
