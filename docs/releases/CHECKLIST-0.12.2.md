# Release checklist - 0.12.2

**Version:** 0.12.2
**Date:** 2026-09-10
**Released by:** Codex-Crusader
**Host:** Windows 11 Home Single Language 10.0.26200, Python 3.11.9, Edge 152.0.4191.66

---

## Tests

```
[x] Full suite passes                       python tests\run_all.py
[x] Run a second time, same result           17/17 both runs, no flakes
[x] No suite reported SKIPPED                network policy applied; 2 rules present
[x] Assertion count recorded here: 329       (read from the run output)
[x] Real-world GUI walkthrough passes        37 OK, 0 problems
[ ] CI green on the release commit            - not yet pushed at time of writing
[ ] CodeQL green, no open alerts              - same
```

The walkthrough had to be REPAIRED before it could be run: it had been hanging at step
14 since `open_security_panel()` became asynchronous, so steps 14-33 were not executing
at all. See the release notes. Both suite runs and the walkthrough above are against the
repaired harness.

## Security

```
[x] No dev mode, debug mode or test bypass in the shipped application
[x] No localhost API, DevTools endpoint or remote debugging
[x] AST security scans pass (no shell=True, no eval/exec, no listener)
[x] Localhost attack surface re-measured; result matches what the docs claim
[x] Firewall enforcement verified: router BLOCKED, LAN BLOCKED, internet REACHED
[x] Browser tamper resistance verified
[x] Download quarantine verified with a REAL download in a REAL browser
[x] Disposable session destroyed, including its quarantine, and verified gone
[x] Persistent profile ACLs verified by real read/write probe
[x] Host Guard detection, remediation and rollback verified
[x] bruhswer runs unelevated; running elevated is reported as FAIL
```

All by `test_localhost_surface.py`, `test_network_regression.py`, `test_user_path.py`
and `test_browser_ui.py` in the two full runs above, plus the walkthrough.

## Claims

```
[x] Every verdict shown in the UI was checked against what the system actually does
[x] No new claim was added without a test that proves it
[x] Anything unprovable reads NOT ENFORCEABLE or UNKNOWN, not PASS
[x] LIMITATIONS.md reviewed; nothing has quietly become worse or better
[x] Test counts in README / TESTING / release notes match the actual run (329)
```

This release exists mostly because three checks could NOT say UNKNOWN when they should
have. Each fix was confirmed by a regression test that fails against the pre-fix code:
8 errors + 1 failure in `test_overclaim_regressions.py`, 5 errors in `test_integrity.py`.

## Packaging

```
[x] Installer builds                        ISCC.exe installer\bruhswer.iss
[x] Installer contents reviewed             (no tests, no .venv, no profiles, no logs)
[ ] Clean install tested                     - see note
[ ] Launch from Start Menu shortcut tested   - see note
[ ] Launch from Desktop shortcut tested      - see note
[ ] Installed app runs from a clean working directory, with no IDE   - see note
[ ] Prerequisite refusals fire correctly     - NEEDS a Windows image with no Python
                                               and no Edge. Unverified since 0.9.1 and
                                               still unverified. Carried forward.
[ ] Uninstall tested                         - see note
[ ] Uninstall leaves user data alone unless explicitly confirmed   - see note
[ ] Uninstall leaves nothing behind          - see note
[x] pip wheel . does not silently produce a broken artifact
      pyproject.toml builds no distribution, deliberately; see its header comment
```

**Note on the install/uninstall boxes:** `tools/verify_install.py` automates all of
them and reported `OK 43 43` against the 0.11.0 installer. It was NOT re-run against
this build, because it installs and uninstalls for real against the live
`%LOCALAPPDATA%\BRUHWSER`, and this machine holds the working profile. Left unticked
rather than ticked on the strength of a previous release - that is the whole point of
this file.

## Repository

```
[x] No secrets, keys or credentials
[x] No personal information: username, real IPs, MAC, hostname, SSID, email
[x] No absolute developer paths        (hygiene grep, includes *.md)
[x] No placeholder text (REPLACE-ME, TODO-before-release, lorem)
[x] .gitignore verified against the REAL file list with git check-ignore
[x] LICENSE present, correct holder, no unfilled boilerplate
[ ] Screenshots and demo regenerated if the UI changed
      UI did not change in this release. Screenshots remain behind the 0.10.0 UI
      (PANIC light, account banner). Carried forward.
[ ] Demo recording is a REAL capture   - still does not exist. ROADMAP item 11.
[x] Docs describe the CURRENT build
```

## Artifacts

```
[x] SHA-256 generated from the FINAL binary, after the last rebuild
[x] Checksum matches in SHA256SUMS.txt and the release body
[x] Published asset downloaded and re-hashed after upload
[x] Release notes written, including what changed and what is still not guaranteed
[x] Signing status stated honestly (unsigned, and the notes say so)
[x] Provenance verified against the PUBLISHED asset
      9f7f521d... -> commit 5b4a6b4, .github/workflows/ci.yml, github-hosted runner
[x] Tag pushed
```

**The published asset had to be replaced once, and this is why.** The release first went
out with the LOCALLY built installer (`F9501F96...`). CI attests the artifact *it*
builds, and Inno Setup embeds build-time state, so the two binaries differ and
`gh attestation verify` on the published file returned HTTP 404 - against release notes
that told the reader to run exactly that command.

This is the same defect 0.12.1 was cut to fix: documentation asserting a verification
that does not hold for the artifact it names. It was caught by running the command
rather than assuming it, at zero downloads and about five minutes after publishing, and
the CI-built binary (`9F7F521D...`) replaced it along with `SHA256SUMS.txt`.

**The rule for future releases: publish the CI artifact, not the local build.** The
local build is still worth producing, because it proves the installer script compiles
on the release machine, but it is not the thing to upload.

## After release

```
[x] Release page renders correctly
[ ] Install from the published artifact, not the local build   - see packaging note
[x] ROADMAP updated
[x] Known issues carried forward into LIMITATIONS.md
```

---

## Notes

**The manifest was regenerated as the last source step**, after the final edit and
before `ISCC`, and re-verified at 43/43. A manifest generated too early ships a build
that reports FAIL on a good install.

**Line endings bit again, mildly.** Editing files with a Python script on Windows wrote
CRLF into thirteen files that git stores as LF. `integrity.hash_file` normalises line
endings, so the manifest verified either way - which is exactly the fix that went in
for 0.10.0 doing its job. The files were normalised back to LF anyway so the working
tree stays uniform.

**A near-miss worth recording.** During the comment cull, rewriting `urls.py` by hand
replaced the `\u` escapes in its bidi-character class with the literal characters. The
string value was identical, so an AST comparison could not see it - and the result was
invisible, direction-reversing text sitting in the source file whose entire job is to
refuse exactly that. It was caught by adding a second check that compares the set of
non-ASCII characters in the source before and after. **An AST diff is not sufficient to
prove a prose-only edit is prose-only.**

**What the automated suites still cannot catch** is unchanged and worth restating: the
walkthrough hang in this release was invisible to all 329 assertions, and was only
found by running the walkthrough and noticing it never finished. A harness that hangs
is worse than one that fails, because a failure is reported and a hang looks like
patience.
