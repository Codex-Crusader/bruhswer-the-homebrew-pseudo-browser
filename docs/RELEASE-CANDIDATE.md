# 🗿 bruhswer - RELEASE CANDIDATE

**Date:** 2026-08-09 · **Host:** Windows 11 Home Single Language 25H2 (26200.8973) · **Runtime:** Microsoft Edge 151.0.4129.72

> **Browse the internet. Trust absolutely nothing.**

---

## Verdicts

| Area | Verdict | Evidence |
|---|---|---|
| **Browser** | **PASS** | Window opens, Edge hosted and OS-confirmed as a child of bruhswer's frame, address bar navigates, tabs work, relaunch works |
| **Security** | **PASS** | Fail-closed startup, browser-scoped firewall enforcement, browser cannot alter its own rules (5 bypass attempts refused) |
| **Privacy** | **PASS** | 21 settings verified from disk; 34 properties compared with stock Edge; 9/9 identity values identical |
| **Network** | **PASS (remote) / NOT ENFORCEABLE (local)** | Router and LAN blocked, internet preserved; loopback cannot be filtered by Windows Firewall |
| **Host Guard** | **PASS** | Applied, verified, rolled back and independently re-measured on the real host |
| **Downloads** | **PASS** | Real download landed in quarantine; real Downloads folder untouched |
| **Persistent sessions** | **PASS** | Settings survive 3 consecutive launches; profile kept |
| **Disposable sessions** | **PASS** | Profile destroyed and verified gone, every run |
| **Reliability** | **PASS** | 7 suites, 146 assertions, repeated clean runs; no flaky tests remaining |
| **Performance** | **MEASURED** | 16 ms setup, −7 ms page load, +4 MB memory vs stock Edge |
| **Data protection** | **PASS / PARTIAL** | ACLs verified by real read/write probe; disposable downloads now destroyed with the session. **PARTIAL:** no encryption at rest is added by bruhswer - a documented trade-off, not a gap |
| **GitHub readiness** | **PARTIAL** | Licence, SECURITY.md, .gitignore, CI and installer all in place. **Blocked on one item:** the `REPLACE-ME` repository URL |

**No security score is given.** A number would imply a precision this project does not have.

---

## Post-RC fixes from real use

The first release candidate was declared on automated evidence. Actually using it found three things the tests did not, which is worth recording rather than quietly patching - the suite passed 114 assertions while the browser was unusable.

**1. You could not type in it.** A reparented window still belongs to a different process, and Windows gives every GUI thread its own input queue. `SetParent` moves the window but does not merge those queues, so keyboard focus never crossed from bruhswer's thread to Edge's: the page rendered, the mouse mostly worked, and every keystroke went nowhere. Fixed with `AttachThreadInput`, the documented way to share focus across threads - no injection, no hooks, no synthesised messages, nothing touching Edge's security. Clicks on the page area now also hand focus back to the browser, because Tk otherwise keeps it on its own address bar.

*Honest cost:* attached input queues share focus state between the two threads, so if one blocks the other can feel it. That is the trade for a browser you can type in. The attachment is released on session close and on exit.

**2. Startup flashed a stream of console windows** - one per PowerShell verification query. Every helper process now passes `CREATE_NO_WINDOW`. A new test fails if a future call site forgets, and it immediately caught one that had been missed.

**3. The page did not render properly.** Tk is DPI-unaware by default; Edge is per-monitor-aware. Hosting one inside the other with that mismatch makes Windows virtualise the parent's coordinates but not the child's. Fixed by setting per-monitor-v2 DPI awareness before any window exists, sizing the hosted window immediately after hosting rather than 300 ms later, and forcing a real repaint - Chromium sizes its compositor from the first `WM_SIZE` it receives.

**What this says about the test suite.** All three were invisible to it: the tests drive the UI programmatically, so they never *typed*, never *watched* the screen, and never looked at whether a console appeared. Automated evidence is not the same as use. The download-directory bug in Stage 6 was the same lesson - a feature verified only against its own stated intent.

---

## Browser - PASS

A real Edge window is hosted inside the bruhswer frame using `SetParent`, a documented Win32 call. **No DLL injection, no modified Edge binary, no disabled sandbox, no SmartScreen or Safe Browsing changes, no TLS weakening, no DevTools port.**

```
[PASS] edge window hosted                                hwnd=4393614
[PASS] OS confirms it is a child of bruhswer's frame     parent=789584 stage=789584
[PASS] navigated and the browser actually fetched the page   server saw 1 request(s)
[PASS] new tab opened without a new window
[PASS] relaunch opens a browser again
```

Tabs, back, forward and reload are Edge's own native controls - not reimplementations, not fake tabs. bruhswer's address bar opens a real new tab by handing the URL to the running session as a separate argv element.

**Alternatives rejected, with reasons:** CEF Python (bundles an unsigned third-party Chromium - the QEMU/B17 mistake); WebView2 + pythonnet (WebView2 itself is fine and installed, but the Python bridge is a real dependency; kept as a documented fallback); DevTools protocol (a localhost control channel into the browser, and Stage 4 measured that a compromised browser can reach localhost and nothing can stop it).

**If hosting fails** bruhswer says so and the browser continues in its own window, still protected. It does not pretend.

---

## Security - PASS

Fail-closed startup: a critical check must return `PASS`. `UNKNOWN` blocks exactly like `FAIL`. No "continue anyway" button, and nothing reachable from web content can disable it.

Browser-privilege bypass attempts, run **unelevated in the browser's own token class**:

```
[PASS] cannot DELETE its own block rule            REFUSED
[PASS] cannot DISABLE its own block rule           REFUSED
[PASS] cannot MODIFY its own block rule            REFUSED
[PASS] cannot CREATE a permissive replacement rule REFUSED
[PASS] cannot DISABLE the firewall profile         REFUSED
```

Static analysis parses every source file with `ast` (not grep) and fails on `shell=True`, `eval`, `exec`, `compile`, `os.system`, `os.popen`, `pickle.load`, any generic-execution verb, or a string first argument to `subprocess`. It also fails if it scanned fewer than 10 files. **37 unit tests pass, including the whole browser-UI additions.**

Privilege, tested rather than inspected: `bruhswer running elevated: False`, `controller.privilege -> PASS`.

---

## Privacy - PASS

21 settings written to bruhswer's own profile and **read back from disk**, never assumed. Compared with a fresh stock-Edge profile across 34 properties using controlled local pages - no third-party tracking sites.

Seven differ, and every one removes a collection surface rather than changing a reported value: five permissions (prompt → denied), third-party cookies (allowed → blocked), WebRTC candidates (1 → 0).

```
ua  platform  languages  timezone  screen
hardwareConcurrency  deviceMemory  canvas  webgl     ALL 9 IDENTICAL TO STOCK EDGE
```

**The claim is "no added fingerprint entropy on the measured surface" - not "fingerprint-proof".** The entropy that identifies a user is Edge's; reducing it would mean changing values, which would make the configuration rarer and easier to single out.

**No telemetry.** No server, no account, no sync. 864 log lines audited: **0 contained a URL or a secret-shaped word.**

---

## Network - PASS (remote) / NOT ENFORCEABLE (local)

```
Internet     ALLOWED
Router       BLOCKED           ERR_NETWORK_ACCESS_DENIED
LAN devices  BLOCKED
Localhost    NOT ENFORCEABLE   Windows Firewall cannot filter loopback
This PC's IP NOT ENFORCEABLE   same mechanism
Dev services NOT ENFORCEABLE   same mechanism
IPv6         rules exist; effect UNVERIFIED - no IPv6 path on this network
DNS          UNKNOWN - a local resolver sits in the path
VPN          UNSUPPORTED
```

Rules remain scoped to the browser only - verified by confirming an unrelated program still reaches the router.

`LOCALHOST` is permanently amber in the UI. It is never green, and no fake localhost proxy was added to make a dashboard look better.

---

## Host Guard - PASS

Full cycle exercised on the real host: `original → remediation → VERIFIED hardened → rollback → VERIFIED original → re-applied`. Verdicts came from re-reading state, never from an exit code.

Current state: Public-profile sharing rules 17 → 0, Private-profile rules unchanged at 17, SMB signing required. One command reverts it.

Port 30002 is Seagate Toolkit (`ToolkitService.exe`, valid Seagate signature). Its LAN reachability is **`[INFERRED]` as blocked**, not measured. Untouched, and deliberately not turned into a confirmed vulnerability.

---

## Downloads - PASS

The download location is a **profile preference**, verified as a **critical** launch check. A wrong path fails the launch closed.

```
[PASS] browser is told to download into quarantine
[PASS] verifier confirms the download path
[PASS] download landed in quarantine
[PASS] real Downloads folder untouched
```

Edge holds unverified downloads as `.crdownload` pending a Keep decision - SmartScreen working correctly, which bruhswer does not disable. The file is in quarantine, unrun, either way.

---

## Reliability - PASS

```
PASS  unit / static analysis          47
PASS  persistent profile              13
PASS  end-to-end session              10
PASS  network regression              10
PASS  localhost attack surface        18
PASS  full user path                  19
PASS  browser UI workflow             29
                                     ---
                                     146 assertions, 0 failures
```

Measured 2026-08-10, twice, with identical results. Taken from the run output, not
from arithmetic: this number drifted twice during the hardening pass, so it is now
read off `tests/run_all.py` plus the unittest total rather than recalculated by hand.

Flakiness was root-caused, not tolerated: the test servers used single-threaded `HTTPServer`, so a browser holding a keep-alive connection blocked every other request. All four harnesses now use `ThreadingHTTPServer`.

Filesystem review: no executables under the data root, **0 leftover disposable profiles**, quarantine cleared of test artifacts.

---

## Performance - MEASURED

```
                       SETUP     COLD     WARM       MEM
Stock Edge               0ms    0.73s    0.48s     507MB
bruhswer Standard       16ms    0.64s    0.47s     511MB
bruhswer Disposable     19ms    0.80s    0.50s     508MB
```

Setup 16 ms, page load −7 ms, memory +4 MB. **No meaningful regression from the UI work.**

An earlier run showed 1177 MB and "132% idle CPU" for one row. 132% cannot be idle - the sampler caught startup work. A second run reproduced normal figures across all three profiles, so the outlier is noise, not a regression. **The CPU-idle column is not a reliable measurement and is not offered as one.**

---

## Known limitations

1. **Localhost is NOT ENFORCEABLE.** Windows Firewall cannot filter loopback. Services on this PC - including development servers - stay reachable from the browser. No configuration fixes this.
2. **The browser process is not sandboxed.** Chromium sandboxes its *renderers*; the browser process is the broker that builds that sandbox. Stage 4 measured that it cannot be wrapped in an AppContainer.
3. **This is not a VM** and provides no VM-level isolation.
4. **DNS status is UNKNOWN.** A local resolver (NextDNS) sits in the path, and packet capture needs a driver this project will not install.
5. **IPv6 enforcement is unverified.** Rules exist for `fc00::/7` and `fe80::/10`; this network has no global IPv6 path to test against.
6. **VPN is UNSUPPORTED.** No kill switch has been demonstrated, so none is claimed.
7. **The browser password manager is not disabled.** Chromium reverts external changes to that preference - correct anti-tampering behaviour.
8. **The account is a local administrator** (UAC-filtered). Firewall tamper-resistance depends on UAC, so a successful elevation or a socially-engineered prompt defeats it.
9. **Window hosting is not in-process embedding.** If it fails, the browser runs in its own window.
10. **Host Guard's "unexpected listener" check is a delta** against a baseline observed once, not a service audit.

---

## Unverified claims - things NOT proven

- Port 30002's external reachability (`[INFERRED]` from firewall policy; would need a second device).
- IPv6 rule effect.
- Whether DNS queries actually leave encrypted.
- Third-party cookie blocking across genuinely different registrable domains - the local test uses two loopback host strings, which Chromium may treat as one site.
- Cross-origin referrer behaviour beyond the same-origin case.
- Host Guard rollback against a host modified by something *else* between apply and revert.

---

## Technical debt

- `app_ui.py` (the standalone panel) and `browser_window.py` duplicate some presentation code. Behaviour is shared through the guards; only rendering is repeated.
- The browser-UI suite drives Tk by pumping `update()` rather than `mainloop()`. Effective, but it is a test harness pattern, not a framework.
- Window hosting polls for the Edge window (up to ~20 s) instead of being event-driven.
- `BrowserWindow` reaches into `controller._hosted_hwnd` to read the window title.
- Firewall rules keep the historical `BRUHWSER-` prefix while the product is `bruhswer` - deliberate, since renaming is a migration with a fail-closed failure mode, but it is an inconsistency.
- No installer, no updater, no code signing for bruhswer itself.
- **The test suite cannot see the screen.** It drives the UI programmatically, so it verifies behaviour but not appearance, focus, or whether a stray window appeared. Three real defects got past it. A screenshot or input-level check would close part of that gap; nothing currently does.
- `AttachThreadInput` couples bruhswer's focus state to a browser thread. Standard practice for hosted windows, but it is a coupling that did not exist before.
- Startup takes roughly 35 s, almost all of it PowerShell verification queries run serially before the browser is allowed to open. They could be parallelised or cached.

---

## Definition of done (§50)

> **"I opened bruhswer, typed a URL, and browsed the web in bruhswer."**

Measured: the window opens, the address bar accepts a URL, the browser fetches the page (confirmed server-side), tabs work, navigation works, downloads are quarantined, disposable sessions are destroyed and verified, and a relaunch works.

Every limitation above is stated in the product itself, not only in this document - `LOCALHOST` is amber on the front page, `VPN` reads `UNSUPPORTED`, and DNS reads `UNKNOWN`.

**When bruhswer cannot provide a protection, it says so instead of pretending.**

---

# 0.9.0 publication hardening pass

**Date:** 2026-08-10 · **Version:** 0.9.0 (pre-1.0) · **Reviewers:** Claude (implementation) + Codex (independent, read-only)

The final sweep before public release. No new architecture, no new stage - hardening,
honesty checks, packaging and publication preparation only.

## Final verdicts

| Area | Verdict |
|---|---|
| Browser | **PASS** |
| Security | **PASS** |
| Privacy | **PASS** |
| Network | **PASS (routed) / NOT ENFORCEABLE (loopback)** |
| Host Guard | **PASS** |
| Downloads | **PASS** |
| Persistent sessions | **PASS** |
| Disposable sessions | **PASS** - now including their downloads |
| Reliability | **PASS** - 146 assertions, 7 suites, 0 failures, repeated |
| Data protection | **PASS / PARTIAL** - see encryption coverage below |
| Installer | **PASS** - install, run, uninstall verified on a real machine |
| GitHub readiness | **PASS** - published |

## Test counts - measured, not calculated

```
PASS  unit / static analysis          47
PASS  persistent profile              13
PASS  end-to-end session              10
PASS  network regression              10
PASS  localhost attack surface        18   <- new in this pass
PASS  full user path                  19
PASS  browser UI workflow             29
                                     ---
                                     146 assertions, 0 failures
```

Plus a 19-step real-world GUI walkthrough (`tools/real_world_walkthrough.py`),
**19 OK, 0 problems** - it drives the actual window, opens every panel, exercises the
new confirmation dialog including its cancel path, and verifies disposable destruction.
It exists because this project's own history records three user-visible bugs that the
automated suite passed straight through.

## Localhost coverage - the honest table

Every path measured against a real local service, observed **server-side** (a request
that arrives proves reachability regardless of what CORS then does to the response).

| Path | Result |
|---|---|
| `localhost` by name | NOT ENFORCEABLE |
| `127.0.0.1` | NOT ENFORCEABLE |
| `127.0.0.2` (alternate loopback) | NOT ENFORCEABLE |
| `2130706433` (decimal form) | NOT ENFORCEABLE |
| `0x7f000001` (hex form) | NOT ENFORCEABLE |
| IPv6 `[::1]` | NOT ENFORCEABLE |
| Host's own LAN address | NOT ENFORCEABLE |
| Page-driven `fetch` GET / POST / WebSocket, to each of the above | NOT ENFORCEABLE |

**19 of 19 probed paths reached a local service.** Windows Firewall does not filter
loopback and no configuration changes it. The suite asserts on what bruhswer *does*
control - that it creates no listener itself, that it refuses the URL schemes which
would bypass its controls, and that **its own UI and documentation describe this as
`NOT ENFORCEABLE`**. That last check is the point: if a future change ever painted
localhost green, the build fails.

**Third-party services** listening on this host were inventoried and reported, never
probed and never modified. **None belong to bruhswer** - confirmed zero.

## Encryption coverage

| Item | Encrypted by bruhswer | Actually protected by |
|---|---|---|
| Persistent profile | No | Per-user ACL with inheritance removed; Chromium DPAPI for cookies/credentials; BitLocker if enabled |
| Disposable profile | No | Same, and destroyed on close |
| Quarantine | No | Per-user ACL |
| Log | No | Holds nothing sensitive by construction |
| Host Guard rollback | No | Holds prior firewall settings, not secrets |

**bruhswer adds no encryption at rest - a trade-off, decided against, not a claim that
encryption is useless.** The corrected reasoning is in `DATA-INVENTORY.md` §4: an
earlier draft wrongly asserted encryption "would defend against nothing", which
understated DPAPI's value against offline disk theft. Codex caught it; it is corrected
in place rather than quietly removed.

## Codex findings

7 findings raised. **7 accepted**, 0 rejected outright, **1 severity corrected after
measurement** (C1 - the described junction escape does not occur on this platform;
`shutil.rmtree` refuses to follow one, so the un-guarded code was a silent no-op rather
than a delete-anything primitive).

One defect was found by **Claude and missed by Codex**, which had explicitly reviewed
the file and pronounced it clean: an unanchored `.gitignore` pattern that would have
published a repository missing `bruhswer/app/downloads/quarantine.py` entirely. Found
by running `git check-ignore` over the real tree rather than reading the file.

## Dependency inventory

| Runtime dependency | Source | Trusted because |
|---|---|---|
| Python 3.11+ standard library | python.org | Prerequisite, user-installed, not bundled |
| Microsoft Edge | In-box Windows | Microsoft-signed; signature verified at every launch |
| Windows PowerShell 5.1 | In-box Windows | Fixed absolute path; only constant scripts |
| `icacls.exe` | In-box Windows | Fixed absolute path; explicit argument list |

**Third-party Python packages: zero.** Enforced by CI, which fails if a
`requirements.txt` appears.

Build-time only: Inno Setup 6.7.3, downloaded from the official `jrsoftware/issrc`
GitHub releases, Authenticode **Valid**, signer `Pyrsys B.V.` via Sectigo. Not shipped
to users.

## Release artifact

```
bruhswer-0.9.0-setup.exe
  bytes  : 2,277,401
  sha256 : 3BDDDAD6C81BB81B127E1D4B85146F6AF54E1F4E8298C98C1217766E510C62E1
  signed : NO - unsigned, and documented as unsigned
```

Verified on a real machine: install → shortcuts created → `--check` returns
`bruhswer READY` (exit 0) → uninstall → program and shortcuts removed → **user data
preserved** (the deletion prompt defaults to keeping it).

Also verified: a junction planted inside the install tree does **not** redirect the
uninstaller's recursive delete. Packaged contents confirmed to exclude tests, the
research spikes, `.venv`, `.idea`, browser profiles, quarantine content and logs.

## Accepted risks

- **Loopback reachability.** Platform limitation. Documented everywhere, test-enforced.
- **Time-of-check/time-of-use** in the deletion guards. Needs handle-based APIs Python
  does not expose on Windows. An attacker who could win that race already runs as the
  user, which the threat model states is not defended against.
- **Unsigned artifacts.** No certificate exists; self-signing and calling it trusted
  publisher authentication was refused.
- **Same-user compromise.** Out of scope by design, and stated as such.

## Outstanding before publication

**One item, and it cannot be resolved without the repository owner:**

- `REPLACE-ME` must be replaced with the real repository URL in `README.md`,
  `installer/bruhswer.iss` and `pyproject.toml`. A CI hygiene job **fails the build**
  while any occurrence remains, so it cannot ship by accident.

## Release checklist

```
[x] Full baseline recorded before any change
[x] Browser works normally (19-step real-world walkthrough)
[x] No dev mode, no debug mode, no test bypass
[x] No localhost API, no DevTools endpoint, no remote debugging
[x] No IPC listener - reserved constants removed, AST test added
[x] Localhost attack surface reviewed and measured (19 paths)
[x] Remaining localhost limitation documented and test-enforced
[x] Download quarantine verified with a real browser
[x] Firewall verified (IPv4 + IPv6, program-scoped)
[x] Browser tamper resistance verified
[x] Host Guard verified
[x] Persistent profile ACLs reviewed by real read/write probe
[x] Disposable profile verified - now including downloads
[x] Sensitive data inventory complete
[x] Encryption decisions documented, and corrected after review
[x] No hardcoded secrets (scanned)
[x] No personal information (username, IPs, SSID sanitised)
[x] No machine-specific artifacts
[x] Git history reviewed - none exists; repo not yet initialised
[x] README rewritten for a public audience, with logo
[x] SECURITY.md written (GitHub private advisories, no personal email)
[x] PRIVACY.md / THREAT-MODEL.md / ARCHITECTURE.md reconciled
[x] LICENSE present (Apache-2.0, canonical text, boilerplate filled)
[x] .gitignore reviewed AND verified against the real tree
[x] CI added, honest about what it cannot verify
[x] Static security scan passes
[x] Codex review completed, findings recorded with verdicts
[x] Claude review completed
[x] Full regression passes, twice
[x] Installer built, and install/run/uninstall verified
[x] Release artifact reviewed, checksummed, documented as unsigned
[x] Repository URL set (Codex-Crusader/bruhswer-the-homebrew-pseudo-browser)
```

**Verdict: published.** Repository created, tagged v0.9.0, release published.
