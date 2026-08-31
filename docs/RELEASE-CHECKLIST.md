# Release checklist

Copy this file to `docs/releases/CHECKLIST-<version>.md`, fill it in, and commit it with
the release. Each release keeps its own signed-off record.

**A box is ticked only when the thing was actually done on the machine being released
from.** "Should be fine" is not a tick. If something was skipped, write why next to it
rather than leaving it blank - a checklist with quiet gaps is worse than no checklist.

---

**Version:**
**Date:**
**Released by:**
**Host:** (Windows build, Python version, Edge version)

---

## Tests

```
[ ] Full suite passes                       python tests\run_all.py
[ ] Run a second time, same result           (flakiness is a defect, not noise)
[ ] No suite reported SKIPPED                (SKIPPED is not a pass)
[ ] Assertion count recorded here: ______    (read from the run, not from memory)
[ ] Real-world GUI walkthrough passes        python tools\real_world_walkthrough.py
[ ] CI green on the release commit
[ ] CodeQL green, no open alerts
```

## Security

```
[ ] No dev mode, debug mode or test bypass in the shipped application
[ ] No localhost API, DevTools endpoint or remote debugging
[ ] AST security scans pass (no shell=True, no eval/exec, no listener)
[ ] Localhost attack surface re-measured; result matches what the docs claim
[ ] Firewall enforcement verified: router BLOCKED, LAN BLOCKED, internet REACHED
[ ] Browser tamper resistance verified
[ ] Download quarantine verified with a REAL download in a REAL browser
[ ] Disposable session destroyed, including its quarantine, and verified gone
[ ] Persistent profile ACLs verified by real read/write probe
[ ] Host Guard detection, remediation and rollback verified
[ ] bruhswer runs unelevated; running elevated is reported as FAIL
```

## Claims

The one that matters most for this project.

```
[ ] Every verdict shown in the UI was checked against what the system actually does
[ ] No new claim was added without a test that proves it
[ ] Anything unprovable reads NOT ENFORCEABLE or UNKNOWN, not PASS
[ ] LIMITATIONS.md reviewed; nothing has quietly become worse or better
[ ] Test counts in README / RELEASE-CANDIDATE / release notes match the actual run
```

## Packaging

```
[ ] Installer builds                        ISCC.exe installer\bruhswer.iss
[ ] Installer contents reviewed             (no tests, no .venv, no profiles, no logs)
[ ] Clean install tested
[ ] Launch from Start Menu shortcut tested
[ ] Launch from Desktop shortcut tested (if offered)
[ ] Installed app runs from a clean working directory, with no IDE
[ ] Prerequisite refusals fire correctly    (no Python / old Python / no Edge)
[ ] Uninstall tested; app and shortcuts removed
[ ] Uninstall leaves user data alone unless explicitly confirmed
[ ] Uninstall leaves nothing behind         (check for __pycache__ and empty dirs)
[ ] pip wheel . does not silently produce a broken artifact
```

## Repository

```
[ ] No secrets, keys or credentials
[ ] No personal information: username, real IPs, MAC, hostname, SSID, email
[ ] No absolute developer paths
[ ] No placeholder text (REPLACE-ME, TODO-before-release, lorem)
[ ] .gitignore verified against the REAL file list with git check-ignore,
    not by reading it
[ ] LICENSE present, correct holder, no unfilled boilerplate
[ ] Screenshots and demo regenerated if the UI changed
[ ] Screenshots checked for personal data before publishing
    (SSID, hostname, account name, synced favourites, real IPs)
[ ] Demo recording is a REAL capture, not a rendered animation
    (see ROADMAP item 11 for the shot list; shot 6 is not optional)
[ ] Docs describe the CURRENT build; historical material is under docs/research/
```

## Artifacts

```
[ ] SHA-256 generated from the FINAL binary, after the last rebuild
[ ] Checksum matches in: SHA256SUMS.txt, release notes, release report
[ ] Published asset downloaded and re-hashed after upload
[ ] Release notes written, including what changed and what is still not guaranteed
[ ] Signing status stated honestly (unsigned is fine; pretending is not)
[ ] Provenance verified against the PUBLISHED asset, not the local build:
      gh attestation verify <asset> --repo <this repo>
[ ] Tag pushed
```

## After release

```
[ ] Release page renders correctly, images load
[ ] Install from the published artifact, not the local build
[ ] ROADMAP updated: anything completed marked done
[ ] Known issues carried forward into LIMITATIONS.md
```

---

## Notes

Anything skipped, anything that surprised you, anything a future release should watch.
Write it here rather than in a commit message nobody will find again.
