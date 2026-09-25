# Release checklist - 0.13.0

**Version:** 0.13.0
**Date:** 2026-09-25
**Released by:** Codex-Crusader
**Host:** Windows 11 Home Single Language 10.0.26200, Python 3.11.9, Edge 153.0.4234.48

---

## Tests

```
[ ] Full suite passes                       python tests\run_all.py
      357 of 358 assertions passed. The one failure is the router probe in
      test_network_regression.py; see the note below. Left unticked: the runner
      printed "Do not ship", and that is recorded rather than overridden silently.
[x] Run a second time, same result           identical per-suite counts, same single failure
[x] No suite reported SKIPPED                network policy applied; 2 rules present
[x] Assertion count recorded here: 358       (read from the run output)
[x] Real-world GUI walkthrough passes        37 OK, 0 problems
[ ] CI green on the release commit            - checked after the merge, see Notes
[ ] CodeQL green, no open alerts              - same
```

**The one failing assertion is this network, not bruhswer.** "An UNRELATED program still
reaches the router" fetches `http://<gateway>/` with curl and needs a web page there.
This network's gateway refuses port 80. Measured on the release machine:

- curl: `connect to <gateway> port 80 ... failed: Connection refused`. A refusal is the
  router answering, so curl's packet was not blocked on this PC.
- `Test-Connection <gateway>` from a non-Edge process: True.
- Both BRUHWSER rules name only `msedge.exe` (read back with
  `Get-NetFirewallApplicationFilter`).
- The same assertion fails the same way on the code before this release.

So rule scoping holds. The probe should not depend on the router serving HTTP; that is a
test fix for a later release.

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
[ ] Host Guard detection, remediation and rollback verified
      Detection ran in every suite. The remediation script's lookup changed (group
      resource ID instead of display name) and only its read-only status action was
      run: it found the same 32 rules by ID as by name. Apply and rollback were not
      run, because they change the host's firewall.
[x] bruhswer runs unelevated; running elevated is reported as FAIL
```

## Claims

```
[x] Every verdict shown in the UI was checked against what the system actually does
[x] No new claim was added without a test that proves it
[x] Anything unprovable reads NOT ENFORCEABLE or UNKNOWN, not PASS
[x] LIMITATIONS.md reviewed; section 14 added (the firewall rules cover every Edge
    window on the PC)
[x] Test counts in README / TESTING / release notes match the actual run (358)
```

Every fix has a regression test that fails against the pre-fix code: 10 of 10 guard
crashes allowed launch, the export test found no stream, 10 lookalike signers passed
the old substring check, and the sharing and status-row tests failed on the old names.

## Packaging

```
[x] Installer builds                        ISCC.exe installer\bruhswer.iss
[x] Publish the CI artifact, not the local build
[ ] Installer contents reviewed              - verify_install.py asserts the layout;
                                               not run, see note
[ ] Clean install tested                     - see note
[ ] Launch from Start Menu shortcut tested   - see note
[ ] Launch from Desktop shortcut tested      - see note
[ ] Installed app runs from a clean working directory, with no IDE   - see note
[ ] Prerequisite refusals fire correctly     - needs a Windows image with no Python
                                               and no Edge. Unverified since 0.9.1.
[ ] Uninstall tested                         - see note
[ ] Uninstall leaves user data alone unless explicitly confirmed   - see note
[ ] Uninstall leaves nothing behind          - see note
[x] pip wheel . does not silently produce a broken artifact
      pyproject.toml builds no distribution, deliberately
```

**Note on the install boxes:** `tools/verify_install.py` automates them, but it installs
and uninstalls for real against the live `%LOCALAPPDATA%\BRUHWSER`, and this machine
holds the working profile. Not run, as in 0.12.2. Left unticked rather than ticked on the
strength of an earlier release.

## Repository

```
[x] No secrets, keys or credentials
[x] No personal information: username, real IPs, MAC, hostname, SSID, email
[x] No absolute developer paths        (hygiene grep, includes *.md)
[x] No placeholder text (REPLACE-ME, TODO-before-release, lorem)
[x] LICENSE present, correct holder, no unfilled boilerplate
[ ] Screenshots and demo regenerated if the UI changed
      The UI changed only in wording (quarantine warnings). Screenshots remain behind
      the 0.10.0 UI. Carried forward.
[ ] Demo recording is a REAL capture   - still does not exist. ROADMAP item 11.
[x] Docs describe the CURRENT build
```

## Artifacts

```
[ ] SHA-256 generated from the FINAL binary, after the last rebuild
[ ] Checksum matches in SHA256SUMS.txt and the release body
[ ] Published asset downloaded and re-hashed after upload
[x] Release notes written, including what changed and what is still not guaranteed
[x] Signing status stated honestly (unsigned, and the notes say so)
[ ] Provenance verified against the PUBLISHED asset
[ ] Tag pushed
```

The artifact boxes are filled in on the release page and the notes of the commit that
follows, because the CI installer only exists after this commit is merged.

## After release

```
[ ] Release page renders correctly
[ ] Install from the published artifact, not the local build   - see packaging note
[x] ROADMAP updated
[x] Known issues carried forward into LIMITATIONS.md
```

---

## Notes

**The manifest was regenerated as the last source step** and re-verified at 43/43.

**The comment cull was checked two ways.** An AST comparison (docstrings removed) proves
no code changed, but it cannot see an escape such as `\u202e` swapped for the literal
character, which the 0.12.2 notes record as a near-miss. So a second check compares the
exact source text of every code token. It was proven to catch that swap, and it passes
on this release.

**The 0.12.2 near-miss happened again, in the docs.** Writing the text `\u202e` into
these release notes produced the real right-to-left override character, in both this file
and the notes. A scan for bidi and invisible characters across every tracked text file
caught it before commit. Run that scan on docs too, not only on code.

**A shell trap worth recording.** On this machine, a Bash heredoc collapsed `\\` to `\`
in edit scripts. It was caught by an anchor that failed to match; the edit scripts were
then written to files instead.

**Export to FAT32 or exFAT is now refused**, because the copy could not carry Mark of the
Web. That refusal path is tested with a mock only; no such drive was available.
