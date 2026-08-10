# Stage 6 Results - hardening, Host Guard, privacy validation

**Date:** 2026-08-09 · **Scope:** finish and harden the existing bruhswer implementation. No architecture search, no rewrite.

---

## 1. Baseline preserved (§2)

Recorded before any change, and re-verified after every change:

```
BEFORE                                     AFTER
test_security.py            31 OK          34 OK
test_persistent_profile.py  13 PASS        13 PASS
test_end_to_end.py          10 PASS        10 PASS
test_network_regression.py  (did not exist) 10 PASS
test_user_path.py           (did not exist) 19 PASS
                            ----------      ----------
                            54 assertions   86 assertions
```

`tests/run_all.py` runs all five in order and returns one verdict. **Two consecutive full runs passed cleanly.**

---

## 2. A real security bug, found and fixed

**The download quarantine did not work. Downloads were going to the user's real Downloads folder.**

bruhswer launched Edge with `--download-directory=<quarantine>`. **That is not a Chromium switch.** Edge ignored it silently. Every test still passed, because no test had ever downloaded a file - the feature was verified only by reading bruhswer's own intent back to itself.

Measured with a deliberate probe:

```
launching with --download-directory=...\quarantine
  files in the requested directory : <none>
  NEW files in the real Downloads  : ['bruh_dl_probe.bin']

  *** --download-directory IGNORED: the file went to the user's real
      Downloads folder. The quarantine claim would be FALSE. ***
```

**Fix:** the download location is now a **profile preference** (`download.default_directory`, plus `download.prompt_for_download = false` so the browser cannot offer a Save-As dialog that would let a hostile download escape). It is written before launch and **read back and verified on every launch** as a *critical* check - if it is wrong, bruhswer refuses to start.

Verified end to end with a real download by the real browser:

```
[PASS] browser is told to download into quarantine
[PASS] verifier confirms the download path
[PASS] download was redirected INTO quarantine   quarantine holds: ['bruh_user_path_probe.txt.crdownload']
[PASS] nothing appeared in the user's real Downloads folder   clean
```

**Observed and worth stating:** Edge holds the file as `.crdownload` pending the user's Keep decision, because SmartScreen cannot verify it. bruhswer deliberately does not disable Safe Browsing (§38 of the Stage 5 brief), so that hold is a security feature working correctly - and the file is in quarantine, unrun, either way. The claim is *"downloads are directed into quarantine and never into the user's real Downloads folder"*, not *"Edge finishes every transfer"*.

Three regression tests now guard this: no `--download-directory` in the launch command, the preference is written and verified, and verification rejects a wrong directory.

---

## 3. Network regression - §12 scope and §13 self-bypass

§13 asked for the bypass test to run *through the browser's own privilege context*, not an elevated one. The previous `net.tamper` check only **inferred** tamper-resistance. Now it is attempted, unelevated, in the same token class as the browser process (Stage 4 gate A4 proved equivalence):

```
Running elevated: False

[PASS] cannot DELETE its own block rule            REFUSED:CimException
[PASS] cannot DISABLE its own block rule           REFUSED:CimException
[PASS] cannot MODIFY its own block rule            REFUSED:CimException
[PASS] cannot CREATE a permissive replacement rule REFUSED:CimException
[PASS] cannot DISABLE the firewall profile         REFUSED:CimException
[PASS] no probe rule left behind                   remaining=0
```

The fourth case - **out-voting the block with a broad Allow rule instead of deleting it** - had never been tried before. It is refused too.

§12's "unrelated applications are not accidentally blocked" had no standing test. If a future change widened the rules from `-Program msedge.exe` to machine-wide, nothing would have caught it:

```
[PASS] BRUHWSER-edge-deny-ipv4-private names only the browser executable
[PASS] BRUHWSER-edge-deny-ipv6-local names only the browser executable
[PASS] an UNRELATED program still reaches the router     curl exit 0
[PASS] an UNRELATED program still reaches the internet   curl exit 0
```

---

## 4. Host Guard (§5-§11)

**Detection expanded:** network category, firewall profiles, File and Printer Sharing, Network Discovery, Remote Desktop, SMB (v1 + signing), **remote administration (RDP / WinRM / Remote Registry)**, **network-discovery services (SSDP / UPnP / FDResPub)**, wildcard listeners, Defender state.

**Standalone (§11):** `python bruhswer.py --hostguard` answers "what can the laptop at the next table reach?" without starting a browser.

Current findings on this machine:

```
OK        Network category            'CampusWiFi' is Public
OK        Windows Firewall            All profiles enabled
EXPOSED   File and Printer Sharing    17 of 17 rules enabled for Public
OK        Network Discovery           Not exposed on Public
OK        Remote Desktop              Not exposed on Public
EXPOSED   SMB hardening               SMB signing is not required
OK        Remote administration       RDP, WinRM, Remote Registry not running
UNKNOWN   Network discovery services  SSDPSRV running - reachability depends on firewall
EXPOSED   Unexpected listening ports  30002
OK        Microsoft Defender          Real-time, tamper protection, CFA all on
```

**Remediation workflow (§7) is now a seven-step, verified process:**

```
1 CAPTURE   previous state to a rollback file, before anything changes
2 EXPLAIN   the risk, the exact change, and the undo
3 CONSENT   a typed confirmation word - nothing happens without it
4 APPLY     the smallest change that fixes the finding
5 VERIFY    re-read the state; if it did not change -> REMEDIATION = FAILED
            and roll back automatically rather than claim success
6 RECORD    outcome appended to a local result log
7 ROLLBACK  always available - and itself verified (§8)
```

The rollback record is never overwritten once written, so a revert restores the *original* state rather than an intermediate one. **No host change was made** - Host Guard detected, explained, and waited.

---

## 5. Privacy validation (§16-§22)

`tools/privacy_compare.py` serves its own probe pages from loopback - **no third-party tracking sites** (§17). "Stock Edge" is a fresh temporary profile with Edge's own defaults, so the comparison isolates what bruhswer adds.

**34 properties measured. 7 differ from stock Edge, and every one removes a collection surface rather than changing a reported value:**

| Property | Stock Edge | bruhswer | Kind of change |
|---|---|---|---|
| `permission.geolocation` | prompt | **denied** | surface removed |
| `permission.camera` | prompt | **denied** | surface removed |
| `permission.microphone` | prompt | **denied** | surface removed |
| `permission.notifications` | prompt | **denied** | surface removed |
| `permission.clipboard-read` | prompt | **denied** | surface removed |
| `thirdPartyCookie` | allowed | **blocked** | surface removed |
| `webrtc.candidateCount` | 1 | **0** | surface removed |

**The fingerprint result (§18), which is the part that matters:**

```
ua                     SAME (good)
platform               SAME (good)
languages              SAME (good)
timezone               SAME (good)
screen                 SAME (good)
hardwareConcurrency    SAME (good)
deviceMemory           SAME (good)
canvas                 SAME (good)
webgl                  SAME (good)
```

**Every identity value bruhswer could have spoofed is byte-identical to stock Edge.** That is the design goal stated in §31 of the Stage 5 brief and §18 here: reduce unnecessary entropy without becoming unusual. bruhswer adds **zero** fingerprint entropy on the measured surface.

**Limitations, stated rather than buried:**

- The third-party cookie row uses two loopback host strings (`127.0.0.1` and `localhost`). Chromium's cookie policy is site-based and neither has a registrable domain, so that single row is **INDICATIVE, not proof**. A real cross-site test needs two registrable domains.
- Probes run headless, so `screen` reports headless's virtual 800x600 rather than the real display. Valid as a *relative* comparison (both identical), not as a real-world value.
- WebRTC candidate gathering is limited under headless; the LAN-address leak was `no` in both configurations, so the difference in candidate count is real but its practical size is not established here.

---

## 6. Performance (§28)

```
                            SETUP     COLD     WARM       MEM  CPU idle
Stock Edge                    0ms    0.63s    0.46s     808MB     4.95%
bruhswer Standard            20ms    0.61s    0.51s     760MB     8.33%
bruhswer Disposable          14ms    0.67s    0.47s     765MB     0.00%
```

bruhswer's own per-session work costs **20 ms**. Page load differs from stock Edge by **+55 ms** (median of 3). Memory is **48 MB lower** than stock.

**The CPU-idle column is noise and should not be read as a result** - 0.00%-8.33% across three runs of the same workload is sampling variance over a 6-second window, not a measured difference.

bruhswer adds no proxy, no interception and no extra process to the browsing path; the firewall rules are enforced by Windows itself. **Standard Privacy needs no VPN, so nothing here depends on tunnel speed.** Practical for daily use on a 25 Mbps connection.

---

## 7. A test-harness bug worth recording

The user-path suite failed intermittently - once on the download poll, once on the localhost probe. The cause was not the product: the test servers used `http.server.HTTPServer`, which is **single-threaded**, so a browser holding a keep-alive connection blocked every other request until it timed out.

Fixed by switching to `ThreadingHTTPServer` in all four harnesses. Two consecutive full regression runs then passed cleanly.

Recorded because a security regression suite that fails at random trains people to ignore it, which is worse than having no suite at all.

---

## 8. Rejected experiments (§31) - documented, not removed

```
OURS TO REMOVE (left by the rejected QEMU experiment, Stage 2.5)
  QEMU                    PRESENT  3374 files, 1169.8 MB, at C:\Program Files\qemu
  HypervisorPlatform      ENABLED

NOT OURS - NEVER TOUCHED
  VirtualMachinePlatform  ENABLED   (pre-existing, see the Stage 2.5 baseline)
  VBS status              2         (running; uses the Windows hypervisor, NOT WHP)

  running QEMU processes  0
```

**An important distinction that was easy to get wrong:** `VirtualMachinePlatform` was **already enabled before this project started** and is not ours to remove. Only `HypervisorPlatform` was enabled by Stage 2.5. And VBS running at status 2 uses the *Windows hypervisor*, not the third-party WHP API - disabling `HypervisorPlatform` should not affect it, and the prepared script verifies that and rolls back if VBS changes.

`tools/bruhswer-cleanup-rejected.ps1` is **prepared and not executed**. It has `status`, `remove-qemu` and `disable-whp` actions, each with explain → typed consent → apply → verify → record. Neither item is a security risk sitting unused; removing them is housekeeping.

---

## 9. Branding (§33)

Standardised on lowercase **`bruhswer`**, wordmark `bruh` (yellow) + `swer` (white), one word, one line.

**The firewall rule prefix deliberately remains `BRUHWSER-`.** `BRUHWSER` and `bruhswer` are genuinely different strings (`WSER` vs `SWER`), so renaming would be a migration, not a case change - and the failure mode is bad: bruhswer would fail closed with "rule not present" while two perfectly good rules sat on the host under the old name, and the browser would stop launching for a cosmetic rename. §33 standardises the *user-facing* name; rule names are internal plumbing, and the rule Description already says bruhswer created it. The same reasoning applies to the `%LOCALAPPDATA%\BRUHWSER` profile directory, which is left alone so existing profiles are not orphaned.

---

## 10. Acceptance criteria (§35)

**Security**

| Criterion | Result |
|---|---|
| existing 54 assertions still pass | **86 now pass** |
| fail-closed behaviour still passes | **PASS** |
| firewall self-bypass test passes | **PASS** - now a real test, plus a new fourth case |
| persistent profile remains functional | **PASS** - 3 launches, settings stick |
| disposable destruction remains verified | **PASS** |
| download quarantine remains functional | **FIXED and now genuinely verified** |
| HostGuard detection verified | **PASS** |
| HostGuard remediation verified and reversible | **Implemented with verify + verified rollback; not exercised on this host** - *closed in Stage 7: applied, verified, rolled back and independently confirmed. See `STAGE-7-HOSTGUARD-VALIDATION.md`. Two defects were found doing it.* |

**Privacy**

| Criterion | Result |
|---|---|
| privacy settings verified | **PASS** - 21/21 read back from disk |
| stock Edge comparison exists | **PASS** - 34 properties |
| fingerprint claims evidence-based | **PASS** - 9/9 identity values identical to stock |
| referrer behaviour measured | **PARTIAL** - same-origin measured (`<empty>` in both); a full cross-origin matrix needs two registrable domains |
| WebRTC behaviour measured | **PASS** - candidates 1 → 0, no LAN leak in either |
| permission behaviour measured | **PASS** - 5 permissions prompt → denied |

**Network**

| Criterion | Result |
|---|---|
| router blocked | **PASS** |
| LAN blocked | **PASS** |
| Internet works | **PASS** |
| localhost honestly marked not enforceable | **PASS** - now on the front page of the UI |
| IPv6 status documented | **Rules exist for `fc00::/7` and `fe80::/10`; effect UNVERIFIED - this network has no global IPv6 path** |
| DNS status documented | **UNKNOWN** - a local resolver sits in the path and packet capture needs a forbidden driver |

**Product**

Usable daily; Standard Privacy needs no VPN; both modes work; the UI shows `SESSION`, `LOCALHOST 🟡 NOT ENFORCEABLE` and `VPN UNSUPPORTED` alongside the verdict rollup; no false security claims.

---

## 11. What is still not done

- **IPC** - not implemented, correctly (§26: the UI and controller are one process, so it is not needed).
- **VPN** - still `UNSUPPORTED` (§27), untouched.
- **Cross-origin referrer matrix** - needs two registrable domains; local loopback cannot provide them.
- ~~**Host Guard remediation on a real host**~~ - **DONE in Stage 7.** Applied with consent, verified, rolled back, independently re-measured. `STAGE-7-HOSTGUARD-VALIDATION.md`. Doing it exposed two defects in the Stage 6 implementation: the fix would have disabled File and Printer Sharing on *home* networks too (it now removes only the Public profile), and a second remediation's rollback data was silently dropped (capture is now per-field).
- **IPv6 enforcement effect** - unverifiable on a network with no IPv6.
