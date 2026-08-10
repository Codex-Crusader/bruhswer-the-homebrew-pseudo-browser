# bruhswer 0.9.2

**A correction release.** It fixes seven defects found by an independent review of the
0.9.1 work, retracts a false claim 0.9.1 made, and closes the verification gap that made
0.9.1 weaker than 0.9.0.

No new features. Nothing bruhswer enforces has changed.

---

## The retraction

**0.9.1 stated a cause it never established.** Its notes said the blank-browser problem
seen during development was caused by reparenting Edge's window before Chromium built
its compositor surface, and that shortening a delay from 1200ms to 250ms reproduced it.

Neither was true:

```
each attempt to locate Edge's window   ~258ms   (a PowerShell round trip)
the compositor gap being "raced"        ~52ms
```

Every attempt already costs five times the window it was supposedly racing, so no poll
interval can hit it. Deliberately re-introducing the change did not reproduce a blank
browser either. **A blank stage was genuinely seen, while several bruhswer instances
were running at once, and its cause remains unknown.**

The compositor check stays because it is cheap and correct, but it is a defensive gate,
not a fix for a diagnosed defect. The published 0.9.1 release page now carries this
correction too.

---

## Fixed

### Two claims that were wrong in the same way the release was arguing against

- **"The session is still open and still protected"** was shown whenever the hosted
  window died while `is_running()` returned true - then the watcher **stopped polling**.
  `is_running()` is a ~258ms process snapshot taken within 1500ms of the window dying,
  so on an ordinary close it usually still sees Edge tearing down. The result was a
  reassurance that could be false and would never correct itself. It keeps polling now
  and settles on the truth.
- **"Revealed onto a page that has already settled"** was written in a comment and in
  the 0.9.1 notes while the stage was revealed at 260ms and the final resize ran at
  900ms, leaving 640ms of visible repainting. The reveal now follows the last fit.

### The rest

- **"New session" could leave a disposable profile on disk.** The teardown was behind an
  `is_running()` guard which is false once the browser window has closed, so the profile
  and quarantine the user had just confirmed deleting survived until the next launch.
- **A dead window handle was left in the controller.** Windows recycles handle values,
  so a later stop could have posted `WM_CLOSE` to an unrelated application's window.
- **The test harness misreported assertion failures as crashes.** `run_all.py` scanned
  only stdout, but `test_security.py` runs `unittest`, which writes `FAIL:` to stderr.
  The crash-reporting improvement added in 0.9.1 was itself misreporting.
- **The new paint check could have failed a working browser.** It left the bitmap
  selected into the device context across `GetDIBits` and checked no return codes; when
  GDI refuses it returns zero and writes nothing, and a zero-filled buffer is
  indistinguishable from a blank window. It now reports "could not read" as UNKNOWN.
- **`_is_within` resolved only one side of the path comparison.** Not exploitable as
  configured here, but an unresolvable parent would make a critical check PASS for a
  profile that is the user's real browser data.

---

## The suite can now tell a blank browser from a working one

Until 0.9.2 the suite proved Edge's window was **parented** and that the OS agreed. It
never proved anything was **drawn** in it. A completely blank stage passed every
assertion in the project.

`test_browser_ui.py` now samples the hosted window's client area through GDI and fails
below 8 distinct colours - a blank surface is one or two, a real page is over a thousand.
Validated at ~1,400 on a working build.

**It has not been validated against a genuinely blank window**, because the blank state
has never been reproduced on demand. It guards a failure that was seen once and is not
understood.

---

## Install and uninstall are verified again

0.9.1 shipped with eight unticked boxes because install behaviour was never tested. That
is closed: **22 checks, 0 failures**, covering install, the file layout, that tests and
virtualenvs did not ship, uninstall registration, shortcuts, running the installed copy
from a clean working directory, uninstall, and that user data survives it.

It is repeatable now rather than a manual ritual: `tools/verify_install.py`.

The first automated attempt **passed its "no tests shipped" assertions while looking at
a directory the installer never writes to** - the application is nested one level down.
A check that passes because it is looking in the wrong place is worse than no check, so
the layout is asserted explicitly.

**Still not verified:** the prerequisite refusals, which need a Windows image with no
Python and no Edge.

---

## Verification

| | |
|---|---|
| Full suite | **152 assertions across 7 suites, 0 failures** |
| Real-world GUI walkthrough | **19 OK, 0 problems** |
| Install / uninstall | **22 checks, 0 failures** |
| Lint | ruff clean |
| CodeQL | no open alerts |

Each of the seven fixes was checked for whether it actually changes behaviour. Three
were demonstrated by executing old and new logic side by side; four were confirmed
structurally, which is weaker evidence and is labelled as such in
`releases/CHECKLIST-0.9.2.md`.

---

## Install

Unsigned, as before. SmartScreen will warn and it is right to. Verify against
`SHA256SUMS.txt`. Upgrading from 0.9.0 or 0.9.1 needs nothing: no profile format
changed, no data migrates.
