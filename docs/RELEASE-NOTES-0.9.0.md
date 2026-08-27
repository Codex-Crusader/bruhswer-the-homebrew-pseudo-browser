# bruhswer 0.9.0 - first public release

> **Browse the internet. Trust absolutely nothing.**

**Pre-1.0, and labelled that way on purpose.** Everything below has been measured on
real hardware and the test suite is green, but this is the first release anyone
outside the project has run. `0.9.0` says "believed correct, not yet proven by
anyone else", and calling it `1.0.0` would be claiming a confidence nobody has earned
yet.

---

## Artifacts

| File | What it is |
|---|---|
| `bruhswer-0.9.0-setup.exe` | Windows installer, per-user, no Administrator required |
| `SHA256SUMS.txt` | Checksum for the installer |
| Source | This repository at tag `v0.9.0` |

### Verify before you install

```powershell
Get-FileHash .\bruhswer-0.9.0-setup.exe -Algorithm SHA256
```

```
3BDDDAD6C81BB81B127E1D4B85146F6AF54E1F4E8298C98C1217766E510C62E1
```

Size: 2,277,401 bytes.

> ### ⚠️ These artifacts are UNSIGNED
>
> There is no code-signing certificate for this project. Windows SmartScreen will warn
> you about an unrecognised publisher, and **that warning is correct** - treat it as
> you would for any unsigned download.
>
> Self-signing a certificate and describing it as trusted publisher authentication
> would be misleading, so it was not done. Checking the SHA-256 above is the real
> verification available to you.

---

## Requirements

- Windows 10 or 11
- **Python 3.11 or newer**, with the `py` launcher. The installer checks the actual
  interpreter version and refuses rather than installing something that cannot run.
- **Microsoft Edge**. The installer checks for it too.

bruhswer is not frozen into a standalone `.exe`. Bundling a second Python interpreter
and a packaging toolchain would add components you cannot easily audit to a tool whose
central argument is that it adds no new trust roots - and it would make what you
install much harder to compare against the published source.

**No `pip install` step. No dependencies. Standard library only.**

---

## Installing

1. Verify the checksum.
2. Run `bruhswer-0.9.0-setup.exe`. It installs to `%LOCALAPPDATA%\Programs\bruhswer`
   and asks for **no** Administrator rights.
3. Choose your shortcuts.
4. Turn on network protection - this is the one step that needs Administrator, and it
   stays separate because changing your firewall is a real change to your PC:

```powershell
# Administrator PowerShell
.\tools\bruhswer-netpolicy.ps1 -Action apply
```

Until you do, bruhswer **will refuse to launch the browser** and will tell you which
check failed. That is deliberate - it fails closed.

### What the installer does and does not do

Creates: the program folder, the shortcuts you tick, and the ordinary per-user
uninstall registration so bruhswer appears in "Installed apps".

Does **not** create: a service, a scheduled task, a startup entry, a background
updater, or any listening port. Does not touch Defender, SmartScreen, your firewall,
or any Windows setting outside its own folder. Installs no drivers, no QEMU, no WSL,
no Hyper-V, no redistributables.

### Uninstalling

Removes the program and shortcuts. Your browsing data is a **separate, explicit
question** that defaults to keeping it. The Host Guard rollback record is kept even
then - it is the only record of any change Host Guard made to your PC, and deleting it
would strand that change permanently.

The firewall rules **survive uninstall by design**, and the uninstaller says so, twice.
Leaving them behind means Edge stays blocked with nothing left on the machine to
explain why. Remove them first with `-Action remove`.

---

## What's in this release

### Verified

- Fail-closed startup - no browser unless critical checks pass, and no override
- Router and LAN blocked for the browser, internet preserved, both measured live
- The browser's own token cannot alter those firewall rules
- Downloads quarantined; the real Downloads folder stays untouched; nothing is executed
- Disposable sessions destroyed and verified gone - **including their downloads**
- Privacy settings written into the profile and **read back** to confirm they stuck
- Host Guard detection, remediation and rollback, on a real host
- Edge's Authenticode signature checked at every launch
- No telemetry - there is no network client anywhere in bruhswer's own code

**146 assertions across 7 suites, 0 failures**, run repeatedly, no known flaky tests.

### Not provided, and never claimed

- **Localhost is reachable and bruhswer cannot stop it.** Windows Firewall does not
  filter loopback. Measured 19 ways - `localhost`, `127.0.0.1`, `127.0.0.2`, decimal
  and hex address forms, IPv6 `[::1]`, the host's own LAN address, by navigation and by
  page-driven `fetch`/`POST`/WebSocket. Every one got through. Reported as
  `NOT ENFORCEABLE` everywhere, enforced by a regression test.
- Not a virtual machine. The browser *process* is not sandboxed (Chromium's sandbox
  contains renderers).
- No VPN - reports `UNSUPPORTED`.
- DNS encryption reports `UNKNOWN`, not a guess.
- IPv6 only partly verified.
- Not anonymity, not malware protection, and no defence against a compromised PC.

---

## Changes in this release

First public release, so everything is new. The security work that produced it:

**Fixed - disposable sessions leaked their downloads.** Destroying a disposable
session removed the profile and reported "destroyed and verified gone" while leaving
every file downloaded during that session on disk permanently. The orphan sweep only
looked at profiles, and the quarantine panel only lists the current session - so those
files were unreachable from the UI while remaining readable on disk. They are now
destroyed with the session, after a warning that lists exactly what will go, and
orphans left by a crash are swept at next start.

**Fixed - every text mode crashed when its output was redirected.** Printing the moai
raised `UnicodeEncodeError` whenever stdout was a pipe rather than a console, killing
`--check`, `--hostguard`, `--uninstall` and the entire test suite under CI.

**Removed - a control channel that was never built.** `config.py` reserved a named
pipe and a verb allow-list for IPC that was never implemented and never needed; the UI
and controller share a process. A test now parses the source and fails the build if
anything imports `socket`, `http.server`, `asyncio` or `flask`, calls `listen`, or
opens a named pipe.

**Fixed - the privacy panel showed intentions as state.** It rendered every setting as
a green "ON" because it appeared in the settings list, not because it was present in
the profile - while the project already documented two preferences Chromium silently
reverts. It now reads the profile back and shows `CONFIRMED` / `NOT APPLIED`.

**Hardened - recursive deletion against directory junctions.** In both the application
and the uninstaller. Along the way: `Path.is_symlink()` returns `False` for a Windows
junction, so the obvious-looking guard was completely inert. Replaced with the
reparse-point attribute test, and proven with a test that plants a real junction.

**Fixed - `.gitignore` would have published a broken repository.** An unanchored
`downloads/` pattern matched `bruhswer/app/downloads/`, so the published source would
have been missing the entire download-quarantine module.

Full detail: [`RELEASE-CANDIDATE.md`](RELEASE-CANDIDATE.md).

---

## Known limitations

| | |
|---|---|
| Localhost / loopback | **NOT ENFORCEABLE** - platform limitation, measured |
| DNS encryption | **UNKNOWN** - cannot be confirmed without a driver this project won't install |
| IPv6 | **NOT FULLY VERIFIED** - what was testable was tested |
| VPN | **UNSUPPORTED** |
| VM isolation | **NOT PROVIDED** |
| Browser-process isolation | **NOT PROVIDED** |
| Code signing | **NONE** - artifacts are unsigned |

---

## Reporting a security problem

**Privately, please.** Use GitHub's "Report a vulnerability" on this repository. Full
policy, scope and disclosure expectations: [`SECURITY.md`](../SECURITY.md).

## Licence

[Apache-2.0](../LICENSE).
