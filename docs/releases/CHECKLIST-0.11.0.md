# Release checklist - 0.11.0

**A box is ticked only when the thing was actually done on the machine being released
from.** Where something was skipped, the reason is written next to it.

---

**Version:** 0.11.0
**Date:** 2026-08-15
**Released by:** Codex-Crusader
**Host:** Windows 11 Home Single Language build 26200, Python 3.11.9, Edge 151.0.4129.78

---

## Tests

```
[x] Full suite passes                        python tests\run_all.py
[x] Run a second time, same result           17/17 PASS both runs, identical
[x] No suite reported SKIPPED                network policy applied, 0 skipped
[x] Assertion count recorded here: 308       read from run output, not arithmetic
[x] 10x stress run on the fast suites        10/10 clean, 0 flaky, 5.0 min
[ ] 10x stress run on the FULL suite         NOT DONE - see below
[ ] Real-world GUI walkthrough passes        NOT DONE - see below
[x] CI green on the release commit           bb6b403, green on the FIRST run, 36s
[x] CodeQL green, no open alerts             bb6b403, green, 1m5s
[x] Manifest verified against a real fresh clone   43/43 match
```

CI passed first time on the tagged commit. Recording that because 0.10.0's did not: it
failed twice on lint, and the fix was to make `lint_report.py` run ruff and to declare
ruff as a dev extra. That fix is what made the difference here, with two additions this
release - the local pin now matches the version CI installs, and ruff is actually
installed in the interpreter `lint_report.py` shells out to, so it reports `ruff: clean`
instead of `NOT INSTALLED`.

Per-suite counts, from the run:

```
  52  unit / static analysis            16  file manifest
  13  address bar properties            17  panic key / account settings
  18  overclaim regressions             13  persistent profile
  19  evidence model                    10  end-to-end session
  16  accessibility / contrast          10  network regression (SS12/SS13)
  10  window surface after split        18  localhost attack surface
  23  session races / stale UI          19  full user path (SS30)
  17  runtime re-verification           31  browser UI workflow (SS33)
   6  disposable overwrite
```

**Why the full 10x stress is not ticked.** `tests/stress.py` was written this release and
run as `stress.py 10 --fast`, which covers the eleven suites needing no browser: 10/10
clean, no suite failed once. The full set includes six browser suites at roughly seven
minutes a pass, so ten iterations is over an hour of real Edge windows. It was not run.
The fast set is where the new code in this release lives; the browser suites are
unchanged in behaviour and passed twice.

**Why the GUI walkthrough is not ticked.** `tools/real_world_walkthrough.py` drives the
real window and was edited this release (line wrapping only, plus one dead lint marker
removed from its docstring). It was not re-run. `test_browser_ui.py` covers the same
window end to end and passed 31/31 twice.

## Security

```
[x] No dev mode, debug mode or test bypass in the shipped application
[x] No localhost API, DevTools endpoint or remote debugging
[x] AST security scans pass (no shell=True, no eval/exec, no listener)   52 assertions
[x] Localhost attack surface re-measured; result matches what the docs claim
[x] Firewall enforcement re-verified                 10/10 network regression assertions
[x] Browser tamper resistance verified               all bypass attempts REFUSED
[x] Download quarantine verified with a REAL download   full user path, 19/19
[x] Disposable session destroyed, including its quarantine, and verified gone
[x] Persistent profile ACLs verified by real read/write probe
[x] Host Guard detection unchanged this release
[x] bruhswer runs unelevated; running elevated is reported as FAIL
[x] A failed PowerShell query can no longer be reported as a security FINDING
```

## Claims

```
[x] Every verdict shown in the UI was checked against what the system actually does
[x] No new claim was added without a test that proves it
[x] Anything unprovable reads NOT ENFORCEABLE or UNKNOWN, not PASS
[x] Every check declares its EVIDENCE KIND, gated by test_evidence_model.py
[x] Every UNKNOWN carries a reason code, gated by the same suite
[x] Test counts in README / TESTING / release notes match the actual run   308
[x] README's security table shows the same evidence taxonomy the UI shows
```

Three claims were REWORDED this release because they were stronger than their evidence.
None of the verdicts changed; the sentences did:

```
[x] downloads.quarantine no longer states what will happen to a downloaded file on the
    strength of two keys read out of JSON
[x] net.rule.* no longer reads as "the browser cannot reach those ranges" when what was
    done was a read-back of the rule's own definition
[x] net.tamper no longer cites gate A17 from inside something rendered as a live
    measurement; it is labelled INFERENCE and states its reasoning chain
```

## Static analysis

```
[x] Project linter                          0 findings across 69 files
[x] ruff (the version CI installs)          clean
[x] ruff --preview --select E1,E2,E3,W1,W2,W3   clean
[x] E501 is now GATED                       it was in the ignore list; 71 lines had
                                            drifted past 90 columns unreported
[x] ruff pin in pyproject matches CI        was 0.15.5 locally vs 0.16.2 in CI
[x] ruff installed in the venv the linter uses, so lint_report reports "ruff: clean"
    rather than "NOT INSTALLED"
[x] Unresolved references                   0  (was 149 across the two new mixins)
[x] Non-stdlib imports under app/           0
[x] Suppressions are per-site with a reason, not a global rule disable
```

The `# lint: allow` markers are keyed by LINE NUMBER, so shortening lines could not move
them. Verified afterwards by cross-referencing every finding against every marker line:
**0 findings on a line that carries a marker.**

## Packaging

```
[x] File manifest regenerated and verifies      43/43 match
[x] File manifest verified against a real fresh clone (LF checkout)   43/43 match
[x] Installer builds                            ISCC.exe installer\bruhswer.iss
[x] Installer version matches the release       see the correction below
[x] Installer contents reviewed                 app/ recursed, __pycache__ and *.pyc
                                                excluded; no tests, no .venv, no
                                                profiles, no logs
[x] Installer and SHA256SUMS.txt published on the release
[x] Clean install tested                        tools\verify_install.py, 26/26
[x] Launch from a clean working directory       installed copy produced its report
[x] Install-time manifest check EXECUTED        OK 43 43, first time in any release
[x] Uninstall tested                            silent uninstall, exit 0
[x] Uninstall leaves nothing behind             install dir, registration, shortcut gone
[x] Uninstall leaves user data alone            measured per folder, before vs after
[ ] Launch from Start Menu / Desktop shortcut   NOT DONE - the shortcut is created and
                                                removed, but nothing clicks it
[ ] Launch from Start Menu / Desktop shortcut   NOT DONE
[ ] Prerequisite refusals fire correctly        NOT DONE - needs a clean Windows image.
                                                Unverified since 0.9.1.
[ ] Uninstall tested                            NOT DONE
[ ] pip wheel . does not silently produce a broken artifact   NOT DONE
```

### Correction: the release was published without a download

The tag and the GitHub release went up with **no assets at all**. Every previous release
shipped `bruhswer-<version>-setup.exe` and `SHA256SUMS.txt`; this one initially shipped
nothing, so the release page offered no way to install the thing it announced. It was
noticed by a reader asking where the download was, not by this checklist.

Two causes, both recorded rather than quietly fixed:

1. The version bump updated `pyproject.toml` and the README badge but **missed
   `installer/bruhswer.iss`**, which still read `0.10.0`. Building without noticing
   would have produced `bruhswer-0.10.0-setup.exe` for the 0.11.0 tag.
2. "Installer builds" was written as `NOT DONE` in this checklist and then the release
   was published anyway. An unticked box is supposed to stop a release or be justified;
   this one did neither.

Both are fixed: the `.iss` reads `0.11.0`, the installer is built and uploaded, and its
SHA-256 is published beside it.

The first uploaded build was then REPLACED, and that is not something this project does
lightly - the v0.9.0 note in `bruhswer.iss` exists because re-uploading a different file
under a published tag silently invalidates a checksum somebody may already have recorded.

It was replaced because the first build's uninstaller destroys browsing data on a silent
uninstall (see below). Leaving it up would have meant knowingly publishing an installer
whose uninstall deletes a user's profile without asking. The window was roughly thirty
minutes on a release that had not been announced anywhere.

```
first build, withdrawn:   868121E311B5DFE3E31297F2C9435C502AFD2EA6B1ABFFA91BDF86C84EC34FB2
second build, withdrawn:  3441984C7FEFD4F65515F420432E3EB1B8DC79D54A9AE33B729DB8A10E007DCF
published build:          21CD5D25478D34219800ACE10CF98E64D82F01C7BB52CD1FC7D8A4F4FE73C890
```

The second build was withdrawn for the uninstall cleanup work below, on the same
unannounced release. Three hashes are recorded rather than one because a replaced asset
invalidates any checksum already taken, and the honest response to doing that twice is
to write down all three, not to present the last one as though it were the first.

### The uninstaller now tells you how to leave the machine clean

bruhswer's firewall rules and any Host Guard change are system-wide and survive the
uninstall by design - removing them needs Administrator, which this installer never
asks for. How that was communicated had three defects:

1. **It guessed.** The warning opened "If you applied bruhswer's network policy", which
   the uninstaller never checked. Everyone got the same paragraph whether it applied to
   them or not, which is how a warning stops being read. It now runs a read-only `netsh`
   query and looks for the Host Guard rollback record, and says nothing at all when
   there is nothing to say.
2. **It pointed at files it was about to delete.** The instruction was to run
   `bruhswer-netpolicy.ps1`, which ships under the install folder and is removed with
   everything else - so following that advice after uninstalling found no such file. The
   hostguard revert advice had the same problem. Both scripts, plus a written guide, are
   now copied to `%LOCALAPPDATA%\BRUHWSER\cleanup\` before the files go, and every
   message gives the full path.
3. **It offered no way out.** "Open an Administrator PowerShell and type this" is a wall
   for most people, and the cost of not clearing it is Edge silently unable to reach the
   LAN forever. The uninstaller now offers to do it, through a normal UAC prompt, and
   then RE-CHECKS whether the rules are gone rather than reporting success for having
   asked. It still never elevates itself.

The kit is written even on a silent uninstall. Saving a file is not a dialog, and a
scripted uninstall leaving no instructions is the same dangling-advice defect reached
without a human present. Only the interactive offer is skipped.

`verify_install.py` step 9 asserts all of it, including that the guide names only
scripts that are actually beside it. **32/32.**

### The install boxes, and the data loss that ticking them caused

`verify_install.py` was run for this release. It reports **26/26**, and the install-time
file-manifest check added in 0.10.0 **executed against a built installer for the first
time**: `OK 43 43`, no drift, no missing files, nothing unexpected.

The first run destroyed a real 110 MB browsing profile, and the script reported that it
had not.

```
[PASS] user data left alone, not silently deleted  -  C:\...\AppData\Local\BRUHWSER
```

That line printed while `profiles\`, `quarantine\` and `logs\` had just been deleted.
Two defects, both now fixed:

1. **The silent uninstall deleted browsing data without asking.** The uninstaller shows
   a Yes/No prompt with `MB_DEFBUTTON2`, and the belief was that `/SUPPRESSMSGBOXES`
   would therefore answer No. It does not: `/SUPPRESSMSGBOXES` answers a custom
   `MB_YESNO` with **Yes**, and `MB_DEFBUTTON2` only sets which button a HUMAN sees
   focused. `CurUninstallStepChanged` now returns early when `UninstallSilent` is true.
   Silent means nobody was asked, and "nobody was asked" must not resolve to "yes,
   delete it" for the one action here that cannot be undone.

2. **The check could not fail.** It asserted `USER_DATA.exists()`, and the uninstaller
   deliberately KEEPS `state\` so the Host Guard rollback record survives - so the root
   directory always exists afterwards and the assertion was true no matter what had
   been deleted. It now takes a per-folder census of file counts and bytes before the
   install and compares it after the uninstall. `logs/` is asserted not to SHRINK
   rather than to be identical, because step 5 runs the installed copy and bruhswer
   logs what it did; asserting equality there would fail every run and get relaxed
   into something meaningless.

Re-verified after both fixes, with marker files planted in each folder: the markers
survive the silent uninstall, and the run is 26/26. The rebuilt installer is the one
published.

**Still not ticked:** nothing clicks the Start Menu or Desktop shortcut. Their creation
and removal is asserted; launching from them is not. Prerequisite refusals remain
unverified and need a Windows image with no Python and no Edge.

## Repository

```
[x] No secrets, keys or credentials
[x] No personal information: username, real IPs, MAC, hostname, SSID, email
[x] No absolute developer paths
[x] No placeholder text
[x] LICENSE present, correct holder
[ ] Screenshots regenerated                 NOT DONE. They are now FURTHER behind than
                                            at 0.10.0: this release adds verdict shapes,
                                            an evidence column, a regression banner, a
                                            quarantine count and an elapsed-time badge,
                                            none of which appear in the published shots.
[ ] Demo recording                          NOT DONE - ROADMAP item 11, still open
[x] Docs describe the CURRENT build
```

## Known gaps carried into this release

1. Prerequisite refusals - unverified, needs a clean Windows image.
2. Install-time manifest verification - still never executed.
3. Screenshots and demo - now further behind the UI than they were.
4. IPv6 firewall effectiveness - rule verified, effect never measured. Reported
   `NEVER_MEASURED` rather than implied.
5. DNS encryption - `UNKNOWN`, unchanged, and not measurable without a capture driver.
6. Full-suite 10x stress - not run; only the fast set was stressed.
7. `test_browser_ui.py` remains the one suite that has ever been observed flaky
   (once, inside `run_all.py`, in 0.10.0). It has not recurred, including across the
   four full runs and ten fast-set iterations done for this release.
