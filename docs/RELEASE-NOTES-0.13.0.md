# bruhswer 0.13.0

**A crashed check can no longer let the browser launch, exported files keep their
internet mark, and the security pass takes half as long.**

This release fixes eight findings from an external review, closes the four items those
fixes left open, and makes the verification pass run its checks in parallel. Every fix
has a regression test, and each test was confirmed to fail against the code before the
fix.

---

## Fixed

### A guard that crashed could let the browser launch

`verify_all()` replaced a crashed guard with one UNKNOWN check marked `critical=False`.
The critical checks that guard would have produced were simply missing, and
`blocks_launch()` only looks at critical checks. So a crash in the Edge, browser or
network guard could leave `may_launch` True.

The replacement check is now critical for every guard, so any crash blocks launch. A new
test makes each of the 10 guards raise in turn and asserts that launch is blocked. It
fails for all 10 against the old code.

### A crashed guard left its status row green

The crash check was named `sandbox.guard` or `integrity.guard`, which matched no status
row. The BROWSER or CONTROLLER row stayed green while launch was blocked. The check is
now named under the category its checks report in, for example `browser.guard.sandbox`.

The same review found that `edge.` checks reached no row at all, so an unsigned browser
left every row green. Edge checks now count toward the BROWSER row. The rows are one
table, `STATUS_ROWS`, and a test holds every guard category to a row.

### A check that vanished mid-session was never reported

The recheck worker compared only the checks present in the new pass. When a guard
crashed during a session, the checks it used to produce simply disappeared, and nothing
warned. A check that passed and then vanishes is now reported when a guard in its
category crashed. A check that vanishes for a normal reason, such as a closed session,
is still not reported.

### Exported files lost their Mark of the Web

Export used `shutil.copy2`, which drops the `Zone.Identifier` stream on Python 3.11
(measured). SmartScreen and Office Protected View then did not warn when the user opened
the exported file.

Export now writes `ZoneId=3` on the copy and reads it back. If the destination drive
cannot hold the stream (FAT32, exFAT, some network shares), the copy is removed and the
export is refused. **This is a visible change: exporting to a typical USB stick is now
refused.** The test reads the stream back with PowerShell, not with the code that wrote
it.

A file named `a` exposed a second bug on the way: `Path.with_name("a:Zone.Identifier")`
reads `a:` as a drive and raises `ValueError`, which escaped after the copy and left it
unmarked. Fixed and tested.

### Disk images and macro documents drew no warning

`.iso`, `.img`, `.vhd` and `.vhdx` files, and macro-enabled Office and OneNote files, now
carry their own warning in the quarantine panel. They stay out of the executable list,
so a program named `invoice.iso` keeps its mismatch warning.

### The Edge signer check used a substring match

The check passed when "Microsoft Corporation" appeared anywhere in the certificate
subject. It now compares whole fields: the subject's CN and O, and the issuer's O. The
issuer's CN is not pinned, because Microsoft rotates it (PCA 2011, PCA 2024).

### Sharing groups were matched by English display name

On a non-English Windows, `DisplayGroup` is translated, so no rule matched and every
sharing group read "0 of 0 enabled", which showed PASS. The probe and the Host Guard
remediation script now match on the group resource IDs, read back from
`FirewallAPI.dll`. The detail now tells "this PC has no such rules" apart from "none of
its rules apply to the Public profile".

### Smaller fixes

- `importlib` joins the banned listener imports in the static scan.
- The docs no longer say `sysquery.py` is the only place a program runs.
  `ARCHITECTURE.md` lists the four other modules and every value they format.
- The README, `LIMITATIONS.md` section 14 and the netpolicy script now say that the
  firewall rules apply to every Edge window on the PC, not only bruhswer's.

---

## Faster

The verification pass ran its 10 guards one after another. They are independent, read
only, and spend almost all their time waiting on PowerShell, so they now run at once.
Measured on the release machine, 5 cold passes each:

| | median |
|---|---|
| serial | 4,683 ms |
| parallel | 2,413 ms |

Results are still collected in a fixed order, so the order of checks never depends on
thread timing. A test proves the guards overlap with a barrier, not a timer, so it
cannot flake.

`sharing_groups` walked all 702 firewall rules once per group. One call now names all
three groups: 2,023 ms down to 1,246 ms, cold.

The slowest remaining probe is the read-back of bruhswer's own firewall rules. It walks
the whole rule table, and Windows offers no faster filter for it.

---

## Also in this release: the comment cull

Comments and docstrings were 23% of all Python lines. They are now 11%. Comments that
restated the code were deleted; comments that record a measured fact the code cannot
show were kept and shortened.

Two checks prove the cull moved no code. Every changed file has the same syntax tree
once docstrings are removed. And every code token has the same source text, which also
catches an escape such as `\u202e` being swapped for the invisible character itself, a
change the syntax tree cannot see.

---

## Verifying this release

```powershell
gh attestation verify bruhswer-0.13.0-setup.exe `
  --repo Codex-Crusader/bruhswer-the-homebrew-pseudo-browser
```

The published installer is the one CI built and attested. The SHA-256 is in
`SHA256SUMS.txt` and on the release page, not in this file, because this file ships
inside the installer.

Still true: this is not a reproducible build, and it is not code signed.

---

## Tests

358 assertions across 17 suites, run twice with identical per-suite counts. 357 passed
both times. GUI walkthrough: 37 OK, 0 problems. The network policy was applied, so no
suite was SKIPPED.

The one failure is the router probe in `test_network_regression.py`. It fetches a web
page from the gateway, and the release machine's network gateway refuses port 80. The
router answered with a refusal, a ping from a non-Edge program reached it, and both
firewall rules name only `msedge.exe`, so the scoping this probe protects holds. The
same assertion fails the same way on the previous code. Making the probe independent of
the router's web page is left for a later release.
