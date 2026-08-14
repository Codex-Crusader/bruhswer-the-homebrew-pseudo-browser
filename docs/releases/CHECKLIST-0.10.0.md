# Release checklist - 0.10.0

**A box is ticked only when the thing was actually done on the machine being released
from.** Where something was skipped, the reason is written next to it.

---

**Version:** 0.10.0
**Date:** 2026-08-14
**Released by:** Codex-Crusader
**Host:** Windows 11 Home Single Language build 26200, Python 3.11.9, Edge 151.0.4129.78

---

## Tests

```
[x] Full suite passes                       python tests\run_all.py
[x] Run a second time, same result           13/13 PASS both runs, identical
[x] No suite reported SKIPPED                network policy applied, 0 skipped
[x] Assertion count recorded here: 240       read from run output, not arithmetic
[x] Real-world GUI walkthrough passes        37 OK, 0 problems
[ ] CI green on the release commit           NOT YET - runs after push
[ ] CodeQL green, no open alerts             NOT YET - runs after push
```

Per-suite counts, from the run:

```
  52  unit / static analysis            16  file manifest
  13  address bar properties            17  panic key / account settings
  18  overclaim regressions             13  persistent profile
  17  runtime re-verification           10  end-to-end session
   6  disposable overwrite              10  network regression (SS12/SS13)
  18  localhost attack surface          19  full user path (SS30)
  31  browser UI workflow (SS33)
```

## Security

```
[x] No dev mode, debug mode or test bypass in the shipped application
[x] No localhost API, DevTools endpoint or remote debugging
[x] AST security scans pass (no shell=True, no eval/exec, no listener)   52 assertions
[x] Localhost attack surface re-measured; result matches what the docs claim
        19 of 19 probed paths reached a local service; reported NOT ENFORCEABLE
[x] Firewall enforcement verified: router BLOCKED, LAN BLOCKED, internet REACHED
        ERR_NETWORK_ACCESS_DENIED on the router, 57927 bytes returned from the internet
[x] Browser tamper resistance verified       all 5 bypass attempts REFUSED:CimException
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
[x] Test counts in README / TESTING / release notes match the actual run   240
```

Three claims were REMOVED this release because they were never measured. Each is
recorded in the release notes:

```
[x] renderer sandbox no longer PASSes while a renderer token is unreadable
[x] unreadable Preferences no longer reports "no Microsoft account is signed in"
[x] IPv6 no longer reads BLOCKED; it reads RULE SET, EFFECT NOT MEASURED
```

## Packaging

```
[x] Installer builds                        ISCC.exe installer\bruhswer.iss
[x] Installer contents reviewed             (no tests, no .venv, no profiles, no logs)
[x] File manifest ships and verifies inside the install
[x] Manifest verified against a simulated fresh clone (all 61 sources
    converted to CRLF): 40/40 match
[ ] Clean install tested                    NOT DONE - see below
[ ] Launch from Start Menu shortcut tested  NOT DONE - see below
[ ] Launch from Desktop shortcut tested     NOT DONE - see below
[ ] Installed app runs from a clean working directory, with no IDE   NOT DONE
[ ] Prerequisite refusals fire correctly    NOT DONE - needs a Windows image with
                                            no Python and no Edge. Unverified since
                                            0.9.1 and still unverified.
[ ] Uninstall tested                        NOT DONE - see below
[ ] Uninstall leaves user data alone unless explicitly confirmed   NOT DONE
[ ] Uninstall leaves nothing behind         NOT DONE
[ ] pip wheel . does not silently produce a broken artifact   NOT DONE
```

**Why the install boxes are not ticked.** `tools/verify_install.py` performs all of them
automatically, but it refuses to run when bruhswer is already installed - deliberately,
because uninstalling somebody's real installation to satisfy a checklist would be rude.
It was not run for this release. The install-time file-manifest check added in 0.10.0
has therefore **never executed against a built installer**, and that is stated in the
release notes rather than implied to be covered.

## Repository

```
[x] No secrets, keys or credentials
[x] No personal information: username, real IPs, MAC, hostname, SSID, email
[x] No absolute developer paths
[x] No placeholder text (REPLACE-ME, TODO-before-release, lorem)
[x] .gitignore verified against the REAL file list with git check-ignore
[x] LICENSE present, correct holder, no unfilled boilerplate
[ ] Screenshots regenerated                 NOT DONE - deliberately. The published
                                            shots are clean; a fresh capture previously
                                            leaked an account avatar and a town name via
                                            the Edge weather widget. The UI gained a
                                            PANIC light and an account banner this
                                            release, so the shots are now slightly
                                            behind the build.
[ ] Demo recording                          NOT DONE - ROADMAP item 11, still open
[x] Docs describe the CURRENT build; historical material is under docs/research/
```

## Static analysis

```
[x] Project linter                          0 findings across 61 files
[x] Type checking                           0 errors project-wide
[x] Unresolved references                   0
[x] Non-stdlib imports under app/           0
[x] Suppressions are per-site with a reason, not a global rule disable, and a
    deliberately-introduced new violation was confirmed still caught
```

## Known gaps carried into this release

1. Prerequisite refusals - unverified, needs a clean Windows image.
2. Install-time manifest verification - never executed.
3. Screenshots and demo - behind the current UI.
4. IPv6 firewall effectiveness - rule verified, effect never measured, and bruhswer
   cannot measure it from inside itself.
