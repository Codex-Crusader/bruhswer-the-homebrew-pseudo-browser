# bruhswer 0.11.0

**A verdict now says how it knows.**

0.10.0 removed three claims that were being made without measurement. This release goes
after the shape of the problem rather than its instances: every check bruhswer performs
now declares what KIND of evidence it rests on, and the UI is required to show it.

It also fixes a bug that could block a launch and blame the user's firewall for it.

---

## The problem this release exists for

A `PASS` answers "did this check succeed". It does not answer "what does bruhswer
actually know, and how does it know it" - and those come apart badly. Three checks all
rendered as the same green dot:

```
browser.sandbox        read the live renderer tokens on this machine, this pass
downloads.quarantine   read two keys out of a JSON file
net.tamper             reasoned from bruhswer's own privilege level
```

The first measured the property it names. The second measured a SETTING and said
nothing about what a download actually does. The third measured a **different process**
entirely and reached its conclusion by argument. No amount of careful wording in the
detail text fixes that, because the dot is what people read.

## Every check now declares its evidence

`EvidenceKind` has four values, and the weakest is the default so that forgetting to
declare one understates what bruhswer knows rather than overstating it:

| Kind | Means | Does **not** mean |
|---|---|---|
| `LIVE` | bruhswer observed the property itself, this pass | |
| `READ_BACK` | it read a setting back from Windows or the profile, just now | that the setting is enforced |
| `HISTORICAL` | a Stage 4 experiment established it once | that it was re-run this session |
| `INFERENCE` | derived from other facts | that anything was measured |

`tests/test_evidence_model.py` gates it. A new check that is not in the frozen
check-id table, an UNKNOWN with no reason code, or a `ProbeStatus` nobody mapped now
fails the build rather than shipping.

## Three claims reworded because they were stronger than their evidence

### 1. Downloads

```
was:  "Downloads go to quarantine"
      "Downloads are directed to bruhswer's quarantine folder, and the browser
       will not ask where to save."

now:  "Download folder is set to quarantine"
      "The profile's download preferences point at bruhswer's quarantine folder
       and have 'ask where to save' turned off. Read back from the profile just
       now; bruhswer has not downloaded a file during this check to watch where
       it lands."
```

Both old sentences are statements about what will happen to a file, made entirely on
the strength of reading two keys out of JSON. The check still catches the defect it was
written for - Edge ignoring `--download-directory` and using the real Downloads folder -
because that showed up as the preference being absent.

### 2. Firewall rules

The PASS read "Present, enabled, scoped to the browser, covering all ranges." Next to a
green dot, a reader takes that to mean the browser cannot reach those ranges. What
bruhswer did was read the rule's own definition back out of Windows. That the rule
*stops Edge* is a separate claim resting on gate A16, which nothing re-runs.

### 3. Tamper resistance

`net.tamper` reported PASS with "Firewall policy requires Administrator; the browser
does not have it. Measured in Stage 4 gate A17." The only thing measured during the
pass is `is_elevated()`, which reports **bruhswer's** token, not the browser's. The
conclusion follows from Edge being launched as a child of an unelevated process, which
is sound reasoning and is still reasoning. The verdict is unchanged; it is now labelled
`INFERENCE` and states the chain.

## UNKNOWN now says why

"UNKNOWN" alone tells a user a control could not be verified. It does not tell them
whether their Windows edition lacks the feature, whether bruhswer was refused the rights
to look, or whether a helper process was simply slow. Those are three different next
actions, so they are now three different reason codes: `TIMEOUT`,
`PERMISSION_DENIED`, `UNSUPPORTED`, `LAUNCH_FAILED`, `MALFORMED_OUTPUT`, `PROBE_ERROR`,
`NO_SESSION`, `NO_PROFILE_YET`, `UNREADABLE`, `PARTIAL_EVIDENCE`, `NEVER_MEASURED`,
`NOT_APPLICABLE`.

This required changing `sysquery`'s contract. It used to return `""` on an OSError, on a
timeout, and `[]` from every list accessor when anything went wrong - so three
genuinely different facts were indistinguishable at the call site:

```
"asked Windows, and the answer is none"
"asked Windows, and it refused"
"could not ask Windows at all"
```

Every query now returns a `Probe` carrying its status, and every PowerShell script runs
inside an envelope that always emits `ok`/`err`/`data`. Without the envelope,
`ConvertTo-Json` on an empty array writes nothing at all, which is byte-identical to a
script that died before producing output.

---

## Fixed: a failed query could block a launch and blame your firewall

`sysquery.bruhswer_rules()` returned a bare `[]` whether the rules were genuinely
missing or PowerShell had timed out under load. Every `net.rule.*` check is
`critical=True`, so a single slow query produced:

- **"Rule is not present. Run Network Policy setup."** - a false statement about the
  user's machine, sending them to fix something that was fine
- **a blocked launch**, because critical + FAIL blocks
- once re-verification existed, a red **"something changed while you were browsing"**
  curtain over a session where nothing had

Fail-closed is preserved: UNKNOWN on a critical check still blocks. What changed is
that bruhswer now says it could not look, instead of asserting a finding it never made.

## Fixed: stale state could cross a session boundary

Four related defects, none of which any existing suite covered:

- `stop()` bumped its generation **after** a teardown that can take 12 seconds, and
  `panic_stop()` after terminating processes. A verification finishing in that window
  carried a matching generation and was applied to a session being destroyed.
- Two passes within one session could not be ordered, so a pass that hit a 60-second
  timeout could land after the one that replaced it and move the lights backwards.
  Results now carry a `verification_id`.
- `VerifyWorker._previous` survived `stop()` -> `start()`, so a new session's first pass
  was compared against the previous session's last one.
- `_warned_ids` survived a session change, so session B's first clean pass withdrew a
  warning about session A and tore down session B's own curtain to do it.

`tests/test_session_races.py` covers all four. Each test was verified to FAIL against
the pre-fix code; a regression test that would have passed before the fix documents
nothing.

## Fixed: a crashed guard took the whole pass with it

One guard raising aborted the entire verification, costing the user every other light
including the critical ones. Each guard is now independent: a crash costs exactly its
own checks and surfaces as an UNKNOWN naming the guard. A crash while *publishing* a
result also used to kill the re-verification thread outright.

---

## The UI

- **Shapes as well as colour.** The whole product is a row of coloured dots, and a
  red-green colour blindness made PASS and FAIL identical. Every verdict now has its
  own shape.
- **Windows high-contrast mode** is detected and a palette is applied whose contrast
  ratios are *computed* by `tests/test_accessibility.py`, not asserted in a comment.
- **Light mode.** bruhswer follows the Windows apps-theme setting. The verdict hues are
  darkened rather than reused: the dark theme's green is about 1.9:1 on a light panel,
  which would have made the status lights unreadable.
- **A regression banner that persists.** "Keep browsing" is a legitimate choice, since a
  regression can be a PowerShell timeout - but dismissing the curtain erased every
  trace, so a degraded session looked identical to a healthy one.
- **Quarantine count**, not just a coloured dot. A disposable session destroys those
  files on close, and a dot never said there was anything to lose.
- **Disposable session elapsed time** on the badge.
- Evidence kind is printed beside every verdict in BRUH CHECK and the Network panel.

## Performance

A full verification pass was re-measured, not estimated:

```
0.10.0   8.31 s   15 helper processes
0.11.0   5.5  s   14 helper processes
```

HostGuard's seven queries are independent and now run concurrently; each still runs its
own fixed script and keeps its own reason code, because a batched god-script would have
turned seven attributions into one. A duplicate IPv6 probe was removed and the elevation
query is measured once per process. Only a definite True/False is cached: memoising a
failed measurement would have blocked every launch for the process lifetime, since
`controller.privilege` is critical.

## Internals

`browser_window.py` was 1012 lines covering three jobs. It is now three files, as
mixins over a shared `WindowShell` that declares the state and cross-half calls:

```
browser_window.py     layout and actions
session_lifecycle.py  startup, hosting, teardown
verification_ui.py    lights, regressions, banners
```

The mixins previously produced 149 unresolved references between them - noise that would
have hidden a real one. `tests/test_window_surface.py` pins that at zero, asserts no
stub survives onto the assembled class, and checks that neither mixin shadows a method
of the other.

Hosting no longer uses fixed 200/900/950 ms timers. It resizes, confirms the resize
landed with a new `embed.is_fitted()`, and retries at most three times.
`is_paint_ready()` could not do this job: it tests that a compositor surface exists,
which stays true across a resize.

---

## The installer, and three things found by shipping it

This release was first published with **no installer at all**. Every previous release
shipped one; this one shipped an empty release page. Building it then surfaced three
further defects, each recorded in `docs/releases/CHECKLIST-0.11.0.md` rather than
quietly fixed.

### A silent uninstall deleted browsing data without asking

The uninstaller offers a Yes/No prompt before removing your profile, quarantine and
logs, with `MB_DEFBUTTON2` so **No** is the focused button. The assumption was that
`/SUPPRESSMSGBOXES` would therefore answer No. It does not: it answers **Yes**, and
`MB_DEFBUTTON2` only sets what a human sees highlighted. A silent uninstall destroyed a
real 110 MB profile during this release's own verification.

`CurUninstallStepChanged` now returns early when `UninstallSilent` is true. Silent means
nobody was asked, and *nobody was asked* must not resolve to *yes, delete it* for the one
action here that cannot be undone. An interactive uninstall still offers the choice.

### The check that was supposed to catch that reported PASS

```
[PASS] user data left alone, not silently deleted
```

printed at the moment the data was being deleted. It asserted `USER_DATA.exists()` - and
the uninstaller deliberately keeps `state\` so the Host Guard rollback record survives,
so the root directory always exists afterwards. **The assertion could never fail.**

It now takes a per-folder census of file counts and bytes before the install and compares
after the uninstall. `logs/` is asserted not to *shrink* rather than to be identical,
since the verification runs the installed copy and it writes a log. `verify_install.py`
also backs the real user data up before it risks it, and keeps the backup.

### The uninstaller's cleanup advice pointed at files it had just deleted

bruhswer's firewall rules and any Host Guard change are system-wide and outlive the
uninstall by design, because removing them needs Administrator and this installer never
asks for it. The old message had three problems: it **guessed** ("If you applied
bruhswer's network policy"), it named `bruhswer-netpolicy.ps1` which ships under the
install folder and is **deleted with everything else**, and it offered no way to act.

Now it checks with a read-only `netsh` query, says nothing when there is nothing to say,
copies both scripts plus a written guide to `%LOCALAPPDATA%\BRUHWSER\cleanup\` before the
files go, and **offers to remove the rules through a normal UAC prompt** - then re-checks
whether they are actually gone rather than reporting success for having asked. It still
never elevates itself.

The kit is written even on a silent uninstall: saving a file is not a dialog, and a
scripted uninstall leaving no instructions is the same defect without a human present.

### Install verification

`tools/verify_install.py` now reports **32/32**, and the install-time file-manifest check
added in 0.10.0 **executed against a built installer for the first time**:

```
[PASS] installed files match the shipped manifest  -  OK 43 43 () () ()
```

The installer asset was replaced twice on this tag. All three hashes are in the
checklist, because a replaced asset invalidates any checksum already recorded and doing
it twice does not make it acceptable to present the last one as though it were the first.

---

## Known gaps, stated rather than implied

- **Nothing clicks the shortcuts.** The Start Menu and Desktop shortcuts are asserted to
  be created and removed; launching bruhswer from one is not tested.
- **Prerequisite refusals remain unverified.** They need a Windows image with no Python
  and no Edge, and have been unverified since 0.9.1.
- Screenshots are further behind the build than they were: the UI gained shapes, an
  evidence column, a regression banner and a quarantine count this release.
- IPv6 rule effectiveness remains `NEVER_MEASURED`. Nothing changed there.
- DNS encryption remains `UNKNOWN` for the same reason as every previous release.
- The full suite was stressed 10x on the eleven browser-free suites only (10/10 clean).
  The six browser suites were run twice, not ten times.
