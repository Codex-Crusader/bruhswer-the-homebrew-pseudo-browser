# bruhswer 0.9.1

**A correctness and presentation release.** No new features, no new security claims, and
no change to what bruhswer enforces. One real defect fixed, one user-visible rendering
bug fixed, and one honesty correction to the documentation.

Still `0.9.x`, still a research-grade beta, still unsigned. What keeps it below `1.0.0`
is unchanged and listed in the [README](../README.md#release-status).

---

## The one that matters

### The status lights were invisible

The window opened at a size whose bottom edge sat underneath the Windows taskbar. The
status bar is the bottom 43 pixels of that window, so on a 1920x1080 display at 125%
scaling **the six verdict lights - HOST, NETWORK, PRIVACY, DOWNLOADS, LOCALHOST, VPN -
could not be seen at all.**

Measured before and after:

```
before   window bottom 1080, usable work area ends 1020   -> 60px hidden
after    window bottom  963, usable work area ends 1020   -> 57px clear
```

That display is the whole honest-verdict surface of the product. `LOCALHOST` reading
amber `NOT ENFORCEABLE` is the single most important thing bruhswer shows anyone, and it
was behind the taskbar. The window is now fitted to the taskbar-free work area.

---

## Fixed

### Profile collision used a string prefix, not path ancestry

`browser_guard` decided whether the profile pointed at your real Edge or Chrome data
using `str.startswith`. A directory named `User Data-Evil` starts with `User Data` while
being a completely different folder, so it counted as a collision.

`browser.profile.separate` is a **critical** check, so the effect was a false `FAIL` and
a refused launch. It failed in the safe direction - it never let a real collision
through - but it was wrong, and it is now path ancestry with case handled explicitly.
Five regression tests pin each case, including the sibling-prefix one that caused it.

### bruhswer could report the browser as closed while it was still running

The window watcher treated "the hosted window handle is gone" as "the browser closed".
Those are different facts. A session whose window was reparented or replaced is still
running, still under firewall policy, and still holding a profile.

It now asks whether the process is actually alive and says which is true. If the session
is still up, it says so and offers to bring the window back rather than claiming a
shutdown that did not happen. That rule already existed in the code as SS34; this was a
place that broke it.

### The page could appear before it had painted

The curtain came down the instant the window was reparented, so the frame appeared first
and the page resized and repainted itself for the next 900ms. The stage is now revealed
once, after the fit has settled, so bruhswer and Edge appear together.

Hosting also waits for Chromium's compositor surface rather than trusting a clock alone.
Measured: the Edge window appears with its render widget already sized, but the
`Intermediate D3D Window` does not exist until ~52ms later.

**That gate is defensive, and an earlier version of these notes overclaimed it.** They
said reparenting inside that gap had been reproduced as the cause of a blank stage. It
had not. Each host attempt already costs a ~258ms PowerShell round trip to find Edge's
PIDs, which is five times the 52ms gap, so no poll interval can race it. A blank stage
was genuinely seen during development, while several bruhswer instances were running at
once, and **its cause is still unknown.** The gate is cheap and correct so it stays, but
it is not a fix for a diagnosed defect and this file will not pretend otherwise.

### Smaller

- Every dead-end state now offers the action it implies instead of "use the menu":
  **What failed** / **Check again** on a blocked launch, **Bring it back** on an
  un-hosted session, **New session** after a close. None of them is an override - each
  re-runs the full verification, and a blocked launch stays blocked.
- The address field had no text inset; the caret and placeholder rendered flush against
  its edge.
- Importing anything from `app/` on a non-Windows machine died with a bare `KeyError`
  naming an environment variable. It now says bruhswer is Windows-only and why.

---

## Documentation

- `docs/ARCHITECTURE.md`, `docs/SECURITY-MODEL.md`, `docs/LIMITATIONS.md` and
  `docs/TESTING.md` describe the shipping build. The Stage 1 design documents that used
  to sit in the main documentation path - and were being read as current - moved to
  `docs/research/` behind an index that says plainly they are evidence, not guidance.
- The README leads with what bruhswer is and includes the whole security model as a
  single screen of `PASS` / `NOT ENFORCEABLE` / `UNKNOWN` / `OUT OF SCOPE`.
- The trusted computing base is now stated explicitly: **1,789 lines of the
  application's 4,620**. The rest is UI, orchestration and presentation.
- "Browser can't undo it" was too broad a claim for what was measured. It now reads:
  *an unelevated Edge process could not create, delete or disable the configured
  firewall rules under the tested configuration.*

### One correction

`docs/TESTING.md` said "no known flaky tests". **That is no longer true and the page no
longer says it.** `test_browser_ui.py` failed once inside `run_all.py` and then passed
29/29 standalone minutes later with no code change. The cause is not known.

That failure also exposed a defect in the harness: `run_all.py` printed only assertion
failures and **discarded the child's stderr**, so a suite that crashed rather than
failing an assertion reported `FAIL` with no evidence at all. It now prints the stderr
tail whenever a suite produces no assertion failure.

---

## Verification

| | |
|---|---|
| Full suite | **151 assertions across 7 suites, 0 failures** |
| Static security analysis | 52 assertions, including 5 new ones for the profile-collision defect |
| Real-world GUI walkthrough | **19 OK, 0 problems** |
| Lint | ruff clean |
| Rendering | verified visually on a 1920x1080 display at 125% scaling |

**What was not verified for this release:** clean install and uninstall on a machine
other than the development machine, and the prerequisite refusals. The installer
compiles and its contents were reviewed; its install-time behaviour was not re-tested.
See `releases/CHECKLIST-0.9.1.md`, where those boxes are left explicitly unticked.

---

## Install

Same as before. The release is **unsigned** - SmartScreen will warn about an
unrecognised publisher and it is right to. Verify the SHA-256 against `SHA256SUMS.txt`.

`AppPublisher` in the installer now carries the real copyright holder's name. 0.9.0's
published binary was deliberately never rebuilt so its checksum stayed valid; this build
picks the change up.

---

## Upgrading from 0.9.0

Nothing to do. No profile format changed, no setting moved, no data migrates. Install
over the top, or uninstall first if you prefer - your profile and quarantine live under
`%LOCALAPPDATA%\BRUHWSER` and are untouched either way.
