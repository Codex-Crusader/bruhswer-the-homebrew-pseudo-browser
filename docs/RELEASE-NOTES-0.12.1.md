# bruhswer 0.12.1

**A release whose installer you can check came from this source.**

There is no application change in this release. Every `.py` file under `app/` and
`bruhswer.py` is byte-identical to 0.12.0 - the file manifest is unchanged and still
reports 43/43.

What changed is that CI now produces a signed build-provenance attestation for the
installer, and 0.12.0 shipped before it did. Rather than replace a published asset,
which would invalidate a checksum someone may already have recorded, this release exists
so that the current download can actually be verified.

---

## Verifying this release

```
gh attestation verify bruhswer-0.12.1-setup.exe \
  --repo Codex-Crusader/bruhswer-the-homebrew-pseudo-browser
```

That returns the commit, the ref and the workflow that built the file:

```
predicate  : https://slsa.dev/provenance/v1
built from : github.com/Codex-Crusader/bruhswer-the-homebrew-pseudo-browser
ref        : refs/heads/main
workflow   : .github/workflows/ci.yml
issuer     : token.actions.githubusercontent.com
```

The SHA-256 in `SHA256SUMS.txt` is still worth checking and is still published. The
attestation answers a different question: not *"is this the file the author intended to
publish"* but *"was this file built by this repository's CI, from source anyone can
read"*.

## What this does not do

**It is not a reproducible build.** You still cannot rebuild the tagged source yourself
and confirm you get the same bytes. This release measured that rather than assuming it:
rebuilding the identical commit produced an installer with a different SHA-256, because
Inno Setup embeds build-time state. `docs/ROADMAP.md` item 4 remains open.

You are trusting GitHub's runner to have done what it says. That is a smaller thing to
trust than an unexplained binary, and it is larger than nothing.

**It is not code signing.** The release is unsigned, SmartScreen will still warn about an
unrecognised publisher, and it is right to. There is no code-signing certificate for this
project and self-signing one to look official would be the behaviour this project exists
to complain about.

**v0.12.0 has no attestation** and verifying it returns HTTP 404. That is the honest
answer for an artifact built before the mechanism existed, not a failure. It has not been
replaced, deliberately: re-uploading a different binary under a published tag would
silently invalidate a checksum someone may have recorded, which is the same rule that
left v0.9.0's incorrect publisher string in place.

## The one defect this release fixes

0.12.0's README was changed to recommend `gh attestation verify` on the same day
provenance was added to CI, and named the 0.12.0 installer in the example - an artifact
that had already been published without one. The command returned 404.

Documentation asserting a verification that does not hold for the artifact it names is
the defect class this project treats as a vulnerability, and this one was in the
documentation about verification. It was found by running the command the README had just
started recommending, which is the only reason it was found at all.

The wording now states which releases carry an attestation and what 0.12.0 returns.

## Changes

| | |
|---|---|
| `.github/workflows/ci.yml` | Generates a provenance attestation for the installer and verifies it in the same run. Permissions scoped to that job alone; skipped on `pull_request`, where a fork's token cannot be granted them |
| `README.md`, `docs/ROADMAP.md` | State what provenance proves, which releases have it, and why it is not reproducibility |
| `docs/RELEASE-CHECKLIST.md` | Requires verifying provenance against the published asset, not the local build |
| `SECURITY.md` | Says there is one maintainer rather than implying a team, and names the version actually supported |

No `app/` source changed. The 322 assertions across 17 suites are unchanged and passing.
