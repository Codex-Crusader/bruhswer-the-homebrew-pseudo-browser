# Release checklist - 0.9.1

Filled in from [`../RELEASE-CHECKLIST.md`](../RELEASE-CHECKLIST.md).

**A box is ticked only when the thing was actually done on the machine being released
from.** Items that were not done are left `[ ]` with the reason next to them. There are
several. That is the point of the file.

---

**Version:** 0.9.1
**Date:** 2026-08-10
**Released by:** Bhargavaram Krishnapur
**Host:** Windows 11 Home Single Language 10.0.26200 / Python 3.11 / Edge (stable, hosted and measured live)

---

## Tests

```
[x] Full suite passes                       151 assertions, 7 suites, 0 failures
[x] Run a second time, same result           run repeatedly during this pass
[ ] No suite reported SKIPPED                see note - one suite FAILED once, then passed
[x] Assertion count recorded here: 151       read from the run, not from memory
[x] Real-world GUI walkthrough passes        19 OK, 0 problems
[ ] CI green on the release commit           not observable until the commit is pushed
[ ] CodeQL green, no open alerts             same
```

> **The SKIPPED box is deliberately not ticked.** No suite skipped, but
> `test_browser_ui.py` **failed once inside `run_all.py` and then passed 29/29
> standalone** with no code change between. The cause is unknown. A flaky suite is a
> defect by this checklist's own words, and ticking a box next to it would be the
> behaviour this project exists to argue against. Recorded in `../TESTING.md`.

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

New UI actions were checked specifically for bypass: **Check again** re-runs
`controller.verify()`, **Try again** re-runs `controller.start()` with full
verification. Neither can launch a browser the verifier refused.

## Claims

```
[x] Every verdict shown in the UI was checked against what the system actually does
[x] No new claim was added without a test that proves it
[x] Anything unprovable reads NOT ENFORCEABLE or UNKNOWN, not PASS
[x] LIMITATIONS.md reviewed; nothing has quietly become worse or better
[x] Test counts in README / TESTING / release notes match the actual run (151)
```

Two claims were **weakened** this release because they were broader than the
measurement: "browser can't undo it" now names the tested configuration, and
"no known flaky tests" is gone.

## Packaging

```
[x] Installer builds                        ISCC.exe installer\bruhswer.iss
[x] Installer contents reviewed             no tests, no .venv, no profiles, no logs
[ ] Clean install tested                    NOT DONE - needs a machine that is not this one
[ ] Launch from Start Menu shortcut tested  NOT DONE - depends on the install above
[ ] Launch from Desktop shortcut tested     NOT DONE - same
[ ] Installed app runs from a clean working directory, with no IDE   NOT DONE - same
[ ] Prerequisite refusals fire correctly    NOT DONE - needs a host with no Python / no Edge
[ ] Uninstall tested                        NOT DONE - nothing was installed to uninstall
[ ] Uninstall leaves user data alone unless explicitly confirmed     NOT DONE - same
[ ] Uninstall leaves nothing behind         NOT DONE - same
[x] pip wheel . does not silently produce a broken artifact          it now refuses loudly
```

> **Eight unticked boxes, one reason.** Install and uninstall behaviour cannot be
> verified without installing to a real machine, and that was not done for this release.
> The installer compiles and its file list was reviewed; nothing here says it installs
> correctly. Anyone relying on that should test it before deploying.

## Repository

```
[x] No secrets, keys or credentials
[x] No personal information: username, real IPs, MAC, hostname, SSID, email
[x] No absolute developer paths
[x] No placeholder text (REPLACE-ME, TODO-before-release, lorem)
[x] .gitignore verified against the REAL file list with git check-ignore
[x] LICENSE present, correct holder, no unfilled boilerplate
[ ] Screenshots and demo regenerated if the UI changed    PARTIAL - see note
[x] Screenshots checked for personal data before publishing
[x] Demo recording is a REAL capture, not a rendered animation      no demo shipped
[x] Docs describe the CURRENT build; historical material is under docs/research/
```

> **Screenshots are from 0.9.0** and still show the panels accurately, but they predate
> the window-geometry fix and the address-field inset. They were not regenerated. The
> demo recording remains outstanding - ROADMAP item 11, with a shot list.

## Artifacts

```
[x] SHA-256 generated from the FINAL binary, after the last rebuild
[x] Checksum matches in: SHA256SUMS.txt and the release notes
[ ] Published asset downloaded and re-hashed after upload    to be done at publish time
[x] Release notes written, including what changed and what is still not guaranteed
[x] Signing status stated honestly (unsigned, and said so)
[x] Tag pushed
```

## After release

```
[ ] Release page renders correctly, images load
[ ] Install from the published artifact, not the local build
[x] ROADMAP updated: anything completed marked done
[x] Known issues carried forward into LIMITATIONS.md and TESTING.md
```

---

## Notes

**This release was produced with substantial AI assistance, and one regression was
introduced and caught during it.** While attempting to make startup feel faster, the
fixed delay before hosting Edge's window was shortened from 1200ms to 250ms. That delay
was load-bearing: it gives Chromium time to build its compositor surface, and
reparenting inside that window produces a hosted browser that reports success and then
paints nothing. It was caught by looking at the screen, not by the test suite, and it is
the reason `is_paint_ready` now exists and the constant carries a "do not shorten this"
comment.

**Nothing in the suite would have caught it.** `test_browser_ui.py` asserts the window
is hosted and that the OS confirms the parent relationship. It does not assert that the
hosted surface paints anything. A test for that does not exist and should.

The flaky-suite failure remains unexplained. The harness now preserves stderr so the
next occurrence produces evidence.
