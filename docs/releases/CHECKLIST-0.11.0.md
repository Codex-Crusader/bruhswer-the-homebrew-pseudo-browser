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
[ ] Installer builds                            NOT DONE this release
[ ] Clean install tested                        NOT DONE - see below
[ ] Launch from Start Menu / Desktop shortcut   NOT DONE
[ ] Prerequisite refusals fire correctly        NOT DONE - needs a clean Windows image.
                                                Unverified since 0.9.1.
[ ] Uninstall tested                            NOT DONE
[ ] pip wheel . does not silently produce a broken artifact   NOT DONE
```

**Why the install boxes are not ticked, again.** `tools/verify_install.py` performs them
automatically but refuses to run while bruhswer is already installed. It was not run for
this release either. The install-time file-manifest check added in 0.10.0 has **still
never executed against a built installer**, and this is the second release in a row that
is true of.

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
