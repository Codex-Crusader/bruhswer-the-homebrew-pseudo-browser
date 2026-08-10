# Release checklist - 0.9.2

Filled in from [`../RELEASE-CHECKLIST.md`](../RELEASE-CHECKLIST.md).

**A box is ticked only when the thing was actually done on the machine being released
from.** Items not done are left `[ ]` with the reason next to them.

---

**Version:** 0.9.2
**Date:** 2026-08-10
**Released by:** Bhargavaram Krishnapur
**Host:** Windows 11 Home Single Language 10.0.26200 / Python 3.11 / Edge stable

---

## Tests

```
[x] Full suite passes                       152 assertions, 7 suites, 0 failures
[x] Run a second time, same result           run repeatedly through this pass
[ ] No suite reported SKIPPED                see note - the 0.9.1 flake is unexplained
[x] Assertion count recorded here: 152       read from the run, not from memory
[x] Real-world GUI walkthrough passes        19 OK, 0 problems
[x] CI green on the release commit           checked after push
[x] CodeQL green, no open alerts             0 open alerts
```

> The flaky `test_browser_ui.py` failure from 0.9.1 has **not recurred and has not been
> explained.** `run_all.py` now prints the child's stderr on a crash, and as of this
> release also scans stderr for assertion markers, so the next occurrence should leave
> usable evidence. Until it is understood this box stays unticked.

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

## Claims

```
[x] Every verdict shown in the UI was checked against what the system actually does
[x] No new claim was added without a test that proves it
[x] Anything unprovable reads NOT ENFORCEABLE or UNKNOWN, not PASS
[x] LIMITATIONS.md reviewed; nothing has quietly become worse or better
[x] Test counts in README / TESTING / release notes match the actual run (152)
[x] Claims made by the PREVIOUS release re-checked, and one retracted
```

The retraction is the headline of this release. 0.9.1 asserted a cause for the blank
browser it had never reproduced; measurement showed the mechanism is impossible. The
code comments, the notes, the 0.9.1 checklist and the published 0.9.1 release page were
all corrected.

Two further overclaims introduced during 0.9.1 were found by review and fixed: a
"session still open and still protected" message that could be false and never
re-checked, and a "revealed onto a settled page" comment that was false by 640ms.

## Packaging

```
[x] Installer builds                        ISCC.exe installer\bruhswer.iss
[x] Installer contents reviewed             asserted, not eyeballed - see below
[x] Clean install tested                    22 checks, 0 failures
[x] Launch from Start Menu shortcut tested  shortcut created and removed; see note
[ ] Launch from Desktop shortcut tested     NOT DONE - task not selected in the run
[x] Installed app runs from a clean working directory, with no IDE
[ ] Prerequisite refusals fire correctly    NOT DONE - needs a host with no Python/Edge
[x] Uninstall tested
[x] Uninstall leaves user data alone unless explicitly confirmed
[x] Uninstall leaves nothing behind
[x] pip wheel . does not silently produce a broken artifact
```

> **Repeatable now:** `tools/verify_install.py`. The first automated attempt passed its
> "no tests/ in the install" assertions **while looking at a directory the installer
> never writes to** - the application is nested one level down under `{app}\bruhswer`.
> Those passes were vacuous. The layout is asserted explicitly so that cannot recur.
>
> The Start Menu box is ticked for creation and removal of the shortcut, not for
> double-clicking it. The prerequisite refusals remain the real gap and need a clean
> Windows image.

## Repository

```
[x] No secrets, keys or credentials
[x] No personal information: username, real IPs, MAC, hostname, SSID, email
[x] No absolute developer paths
[x] No placeholder text
[x] .gitignore verified with git check-ignore
[x] LICENSE present, correct holder, no unfilled boilerplate
[ ] Screenshots regenerated                 NOT DONE - see note, deliberate
[x] Screenshots checked for personal data before publishing
[x] Demo recording is a REAL capture, not a rendered animation   no demo shipped
[x] Docs describe the CURRENT build; historical material under docs/research/
```

> **Screenshots were deliberately not regenerated.** A fresh capture contained the
> owner's account avatar and their location via the Edge weather widget. The published
> screenshots are clean - example.com, no avatar - so they were kept. Regenerating
> properly needs a session signed out inside Edge. Publishing a face and a town to make
> an image marginally more current is a bad trade.

## Artifacts

```
[x] SHA-256 generated from the FINAL binary, after the last rebuild
[x] Checksum matches in SHA256SUMS.txt and the release body
[x] Published asset downloaded and re-hashed after upload
[x] Release notes written, including what changed and what is still not guaranteed
[x] Signing status stated honestly (unsigned, and said so)
[x] Tag pushed
```

## After release

```
[x] Release page renders correctly
[ ] Install from the published artifact, not the local build   local build verified;
    the published asset was re-hashed and is byte-identical to it
[x] ROADMAP updated
[x] Known issues carried forward into LIMITATIONS.md and TESTING.md
```

---

## Notes

**Efficacy of the seven fixes was checked, not assumed.** Three were demonstrated by
executing the old and new logic side by side:

| Fix | Old | New |
|---|---|---|
| `_is_within` resolves both sides | `False` | `True` |
| paint helper on an unreadable window | would read as blank | returns `None` = UNKNOWN |
| `run_all` scans stderr | markers not found | markers found |

The other four - the watcher rescheduling, clearing the controller handle, the
unconditional `stop()`, and the reveal ordering - were confirmed by inspecting the code
shape rather than by observing them at runtime. **That is weaker evidence.** Reproducing
the watcher's polling behaviour would need a browser dying mid-session on demand, which
was not done.

**The pattern across 0.9.1 and 0.9.2 worth recording:** three separate times, a
plausible mechanism was written down as fact before being tested - the compositor race,
the "still protected" reassurance, and the "already settled" page. Each was caught
afterwards, twice by review and once by measurement. The suite caught none of them.
