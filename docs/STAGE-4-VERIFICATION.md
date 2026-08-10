# Stage 4 Verification - A-gate results

**Date:** 2026-08-09
**Host:** Windows 11 Home Single Language, 25H2, build 26200.8973, Ryzen 7 7840HS, 15.3 GB
**Browsers:** Microsoft Edge 151.0.4129.72 · Google Chrome 151.0.7922.76
**Network:** SSID `CampusWiFi`, category **Public**, host `10.0.0.50/22`, gateway `10.0.0.1`, IPv6 connectivity `NoTraffic`

Verdicts are only `PASS` / `FAIL` / `UNKNOWN`. Evidence classes are `[DOCUMENTED]`, `[MEASURED]`, `[INFERRED]`, `[ASSUMED]`.

---

## Status board

```
A1  AppContainer availability                  PASS      [MEASURED]
A2  AppContainer process creation (browser)    FAIL      [MEASURED]   <-- load-bearing
A3  Chromium sandbox compatibility             measured, see below
A4  Filesystem isolation                       FAIL      [MEASURED]   <-- load-bearing
A5  Registry isolation                         FAIL      [MEASURED]
A6  Process isolation                          FAIL      [MEASURED]   <-- load-bearing
A7  Credential isolation                       FAIL      [MEASURED]   <-- load-bearing
A10 Host network isolation                     FAIL      [MEASURED]   <-- load-bearing
A11 LAN isolation                              PASS      [MEASURED]   <-- load-bearing
A12 IPv4 isolation                             PASS (remote) / FAIL (local)
A13 IPv6 isolation                             UNKNOWN   (no global IPv6 path exists here)
A14 Loopback isolation                         FAIL      [MEASURED]   <-- load-bearing
A15 Development-service isolation              FAIL      [MEASURED]
A16 Host-side firewall enforcement             PASS (remote) / FAIL (loopback+host IP)
A17 Browser-side bypass resistance             PASS      [MEASURED]   <-- load-bearing
A18 Secure DNS                                 UNKNOWN   <-- load-bearing
A19 Plain DNS leakage                          UNKNOWN   <-- load-bearing
      (measured underneath: a working plaintext DNS path exists and Windows
       will not auto-upgrade; whether the BROWSER uses it is not established)
A20 Local-network exposure                     measured - exposures found
A21 Public Wi-Fi host protection               FAIL      [MEASURED]
A22 VPN tunnel functionality                   UNSUPPORTED (no VPN configured)
A23 VPN kill switch                            UNSUPPORTED  <-- load-bearing if VPN
A24 VPN bypass resistance                      UNSUPPORTED  <-- load-bearing if VPN
A8  Device isolation                           NOT MEASURED - reachable, deprioritized
A9  GPU isolation                              NOT MEASURED - reachable, deprioritized
A33 Process mitigation effectiveness           NOT MEASURED - reachable, deprioritized
A25 Browser process lifecycle                  NOT MEASURED (no controller built)
A26 Disposable profile destruction             NOT MEASURED (no controller built)
A27 Persistent/disposable separation           NOT MEASURED (no controller built)
A28 Controller privilege                       NOT MEASURED (no controller built)
A29 Controller IPC security                    NOT MEASURED (no controller built)
A30 Fail-closed startup                        NOT MEASURED (no controller built)
A31 Download quarantine                        NOT MEASURED (no controller built)
A32 Host export security                       NOT MEASURED (no controller built)
A34 Host security preservation                 PASS      [MEASURED]
```

**On the NOT MEASURED gates - two different reasons, and they should not be confused.**

- **A25-A32 were blocked.** They all describe behaviour of a controller that does not exist. Brief §65 says to build only the minimum harness needed, and building a controller was not justified once A2, A4-A7 and A16 had established that the boundary it would manage is not achievable.
- **A8, A9 and A33 were not blocked - they were deprioritized.** Each was reachable with the harness already built: device isolation from the Windows privacy settings for desktop apps, GPU from Edge's actual rendering configuration, and process mitigations via `GetProcessMitigationPolicy` on the browser process. They were dropped once the architecture's outcome was established, and are recorded as gaps in this stage's coverage rather than as impossibilities.

**Under §31 none of them counts as a pass.**

**A2 is the gate the proposed primary mechanism rested on, and it failed.** Section §6 of the Stage 4 brief named Windows AppContainer as "the primary OS-level boundary". It cannot hold a Chromium browser process on this machine. The architecture consequence is recorded under A2 and developed in `STAGE-4-ARCHITECTURE.md`.

---

## A1 - AppContainer availability - **PASS**

**Claim:** this Windows 11 Home Single Language installation can create an AppContainer profile, launch a process inside it, and delete the profile.

**Threat addressed:** none directly - a precondition for A2 and for every containment mechanism built on AppContainers.

**Environment:** unelevated Python 3.11.9, `tools/stage4/a2_launch_diagnostics.py`. No elevation, no installs, no firewall or registry changes.

**Configuration:** `CreateAppContainerProfile` with a single capability, `internetClient` (`S-1-15-3-1`). Child process is System32 `curl.exe` at a fixed absolute path - deliberately a trivial program, so the container mechanism is measured independently of any browser behaviour.

**Exact test:** create profile → derive SID → `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` → poll `GetExitCodeProcess` → read stdout through an inherited handle → `DeleteAppContainerProfile`.

**Expected (for PASS):** profile created, SID returned, child runs to completion with exit 0 and produces output, profile deleted with `hr=0`.

**Observed:**

```
container SID: S-1-15-2-989528396-1408278322-4223705584-1328288634-4074068788-822048416-3589386813

--- curl.exe --version (AppContainer) ---
  pid            : 7472
  exited after   : 0.21 s
  exit code      : 0  0x00000000
  captured output: 4 line(s)
    | curl 8.21.0 (Windows) libcurl/8.21.0 Schannel zlib/1.3.2 WinIDN WinLDAP
    | Release-Date: 2026-06-24
    ...

  profile deleted   : hr=0x00000000
```

**Verdict: PASS.** The AppContainer mechanism is fully available on this edition. Windows Home does not restrict it - unlike Hyper-V and Windows Sandbox, which Stage 3 measured as absent entirely.

**Limitations:** proves the mechanism works for a small console program. It says nothing about whether a complex GUI application can run inside one - that is A2, and it is a different question with a different answer.

**Residual risk:** none introduced. Profile created and deleted within the run.

**Architecture consequence:** AppContainer is available as a building block. This gate also serves as the **positive control** for A2: because `curl.exe` runs in the same container that the browsers die in, the A2 failures are properties of the browsers, not defects in the harness.

---

## A2 - AppContainer process creation (Chromium browser) - **FAIL**

**Claim:** a Chromium-based browser process can run inside an AppContainer created by this project's controller.

**Threat addressed:** Threat Model A - host compromise. This was the intended primary OS-level boundary around the entire browser process tree.

**Environment:** unelevated. `tools/stage4/a2a3_appcontainer_chromium_spike.py`, `tools/stage4/a2_launch_diagnostics.py`, `tools/stage4/a2_variants.py`.

**Configuration:** AppContainer holding `internetClient` only. A dedicated user-data-dir under `%LOCALAPPDATA%\BrowserMaker\...`, granted **to the specific container SID only** via `icacls /grant *<SID>:(OI)(CI)F` - deliberately **not** to `ALL APPLICATION PACKAGES` (`S-1-15-2-1`), which would grant every AppContainer on the machine and would be a genuine weakening of the host. Browsers launched with `--user-data-dir=<dedicated>`, `--no-first-run`, `--no-default-browser-check`, `about:blank`; no existing user profile touched.

**Exact test:** `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`; poll `GetExitCodeProcess` for up to 20 s recording lifetime and exit status; capture Chromium's own `--enable-logging=stderr --v=1` output through an inherited handle; enumerate surviving processes from the host side and read their tokens.

**Expected (for PASS):** the browser process tree persists, and its renderer processes hold sandboxed tokens.

**Observed - first run, no logging:**

```
Microsoft Edge  CreateProcessW OK, pid=22360 -> 0 surviving processes after 14 s
Google Chrome   CreateProcessW OK, pid=3612  -> 0 surviving processes after 14 s
```

**Observed - with Chromium logging and flag variants:**

```
Google Chrome, ALL THREE variants:
  v1 --disable-breakpad                 exited 3.62s  0x80000003 STATUS_BREAKPOINT
  v2 --disable-breakpad --disable-gpu   exited 3.82s  0x80000003 STATUS_BREAKPOINT
  v3 --disable-breakpad --no-sandbox    exited 3.62s  0x80000003 STATUS_BREAKPOINT

  identical single log line in every case:
  [FATAL:third_party\crashpad\crashpad\client\crashpad_client_win.cc:323]
      Check failed: . CreateNamedPipe: Access is denied. (0x5)

Microsoft Edge, ALL THREE variants:
  v1 --disable-breakpad                 exited 7.83s  0xC0000005 STATUS_ACCESS_VIOLATION
  v2 --disable-breakpad --disable-gpu   exited 8.67s  0xC0000005 STATUS_ACCESS_VIOLATION
  v3 --disable-breakpad --no-sandbox    exited 7.83s  0xC0000005 STATUS_ACCESS_VIOLATION
  ~300 log lines each; profile initialised, extensions loaded, about:blank rendered,
  component updater contacted -- then the process faults mid-operation.
```

**Container read access to the browsers' own files was verified as NOT the cause:**

```
C:\Program Files (x86)\Microsoft\Edge\Application
    APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
    APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)
C:\Program Files\Google\Chrome\Application
    APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
    APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

**Verdict: FAIL.**

**Mechanism - stated at the confidence each case actually supports:**

- **Chrome: cause established `[MEASURED]`.** Crashpad calls `CreateNamedPipe`, an AppContainer is refused access to the named-pipe namespace, and Crashpad's `CHECK` aborts the process. It is deterministic, it happens before the browser does any work, and **`--no-sandbox` does not change it** - so this is not a conflict with Chromium's own sandbox, it is the AppContainer restricting the browser process itself.
- **Edge: cause NOT established `[MEASURED behaviour, UNKNOWN cause]`.** The fault is reproducible - three variants, three faults, 7.8-8.7 s, same exit code - but the crash is an unattributed access violation and, because Crashpad cannot run inside the container either, no crash report is produced. It would be inference, not measurement, to assert it is the same named-pipe restriction. **It is recorded as: reproducible failure, cause unestablished.**

**What `--no-sandbox` proves.** It was run as a *diagnostic only* and is never a proposed configuration. Both browsers fail identically with it, which rules out "Chromium's own sandbox conflicts with the outer AppContainer" as the explanation. The outer AppContainer is incompatible with the browser process regardless.

**Limitations:** two browsers, one Windows build, one capability set (`internetClient`). A larger capability set was not tried; it is possible some capability combination admits a browser, but adding capabilities weakens the container, which is self-defeating for the purpose the container was meant to serve.

**Residual risk:** none introduced - all profiles and directories were created and deleted within each run.

**Architecture consequence - this is the significant one.**

The Stage 4 brief §6 designated AppContainer as **the primary OS-level boundary**. It cannot hold a Chromium browser process on this machine. Therefore:

1. The architecture **cannot** put the browser process tree inside a project-created AppContainer.
2. Any remaining containment must come from mechanisms that do **not** require wrapping the browser process: host-side firewall rules scoped by program, ACLs on data directories, job objects, and process mitigation policies applied at creation time.
3. The claim that the product adds a Windows application-isolation layer *around* Chromium is **not supported by evidence and must not be made.**

---

## A3 - Chromium sandbox compatibility - measured

**Claim:** Chromium's own Windows sandbox provides a measurable containment boundary for its child processes on this machine.

**Threat addressed:** Threat Model A, partially - renderer compromise.

**Environment:** unelevated. `tools/stage4/a3_stock_sandbox_measure.py`. Each browser launched **normally** (ordinary user token, no AppContainer) against a dedicated user-data-dir. Process attribution is by walking the parent chain from the PID this script created, so the user's own running browser could never be inspected or terminated.

**Exact test:** for every process in the tree, read `TokenIsAppContainer`, `TokenAppContainerSid`, `TokenIntegrityLevel`, `TokenHasRestrictions`, `TokenGroups` and `TokenCapabilities` from the host side.

**Observed - Microsoft Edge (20 processes):**

```
PID     TYPE               IS_AC  LPAC   INTEGRITY RESTR  CAPABILITIES
744     renderer           True   ?      UNTRUSTED True   (none)
2000    renderer           True   ?      UNTRUSTED True   (none)
3172    browser            False  ?      MEDIUM    True   (none)
3736    crashpad-handler   False  ?      MEDIUM    True   (none)
5200    renderer           True   ?      UNTRUSTED True   (none)
...     (10 renderers total, all identical)
15420   gpu-process        False  ?      LOW       True   (none)
17384   utility            False  ?      MEDIUM    True   (none)
19568   utility            False  ?      UNTRUSTED True   (none)

distinct package SID: S-1-15-2-3251537155-1984446955-2931258699-841473695-...
```

**Observed - Google Chrome (9 processes):**

```
PID     TYPE               IS_AC  LPAC   INTEGRITY RESTR
5184    gpu-process        False  ?      LOW       True
15488   renderer           False  ?      UNTRUSTED True
18028   renderer           False  ?      UNTRUSTED True
20764   renderer           False  ?      UNTRUSTED True
22256   browser            False  ?      MEDIUM    True
22420   crashpad-handler   False  ?      MEDIUM    True
11140   utility            False  ?      MEDIUM    True
13500   utility            False  ?      UNTRUSTED True
6840    renderer           <OpenProcess failed, error 87 - process exited during enumeration>
```

**Decoder validated before these numbers were trusted.** A3 initially reported empty capability and group lists for every process, which could equally have meant "the decoder is broken". `tools/stage4/_token_decoder_selftest.py` ran the same decoder against an ordinary process and returned **14 groups from a 436-byte buffer, 0 capabilities** - the correct answer for an ordinary token. The decoder works, so the empty capability lists above are a real property of those tokens.

**Verdict: measured, and the two browsers differ materially.**

- **Edge renderers are AppContainer tokens** at **UNTRUSTED** integrity, restricted, holding **zero capabilities** - an AppContainer with no capabilities cannot open a network socket at all, which is correct, since renderer networking is brokered.
- **Chrome renderers on this machine are NOT AppContainer tokens.** They are restricted tokens at UNTRUSTED integrity. That is still a strong sandbox, but it is measurably one mechanism short of Edge's.

**Limitations, stated precisely:**

- **LPAC status is `UNKNOWN`.** The detection method - looking for `S-1-15-2-1` (ALL APPLICATION PACKAGES) versus `S-1-15-2-2` (ALL RESTRICTED APPLICATION PACKAGES) in `TokenGroups` - returned **neither** SID for any process. The method did not discriminate, so no LPAC claim is made in either direction. This is recorded as a failure of the measurement, not as a property of the tokens.
- **The `RESTR` column above is not discriminating and must not be read as one.** It is `TokenHasRestrictions`, which A4's control run showed returns `True` even for an ordinary unrestricted process holding **zero** restricting SIDs. The fields that actually discriminate are restricted-SID count, privilege count, integrity level and AppContainer status - all measured under A4 Part 1.
- One Chrome renderer could not be opened (error 87); it exited between enumeration and inspection. Nine of ten Edge renderers and three of four Chrome renderers were read successfully - enough for the pattern, but the enumeration is a snapshot of a moving tree.
- This measures **tokens**, which is what the OS enforces on. It does not measure whether Chromium's broker correctly refuses dangerous requests over its IPC.

**Residual risk - and it is the central one for this whole architecture:**

**The browser process itself runs at MEDIUM integrity with an ordinary user token in both browsers.** Chromium's sandbox contains *renderers*. It does not contain the *browser process*, because the browser process **is** the broker that builds the sandbox. Any compromise that reaches the browser process is, on the evidence above, running with the user's full rights. A2 established that this project cannot wrap that process in an AppContainer. Gates A4 and A7 measure exactly how far that reach extends.

**Architecture consequence:** if a base browser is chosen on measured sandbox strength and on supply chain (Stage 2.5 B17), **Microsoft Edge is the better base on this machine**: its renderers hold a strictly stronger token, and it is Microsoft-signed, in-box, and serviced by Windows Update. Recorded as a finding; not yet a decision.

---

## A4 / A5 / A6 / A7 - reach of the browser-process token

**Environment:** unelevated. `tools/stage4/a4a7_browser_token_reach.py`, plus two PowerShell probes for the Controlled Folder Access attribution.

**Method, and why it is sound without elevation.** Running a probe with the browser's *actual* token would require `SE_ASSIGNPRIMARYTOKEN`, i.e. elevation, which this project's runtime must never hold. Instead the script first **measures token equivalence** between the Edge browser process and an ordinary control process, then runs reach probes from that token class. The equivalence is measured, so the conclusion is not an assumption.

### Part 1 - token equivalence - **EQUIVALENT [MEASURED]**

```
PROCESS                INTEGRITY IS_AC  HASRESTR RESTR_SID GROUPS  PRIVS
this probe (control)   MEDIUM    False  True     0         14      5
Edge BROWSER process   MEDIUM    False  True     0         14      5
Edge renderer          UNTRUSTED True   True     1         14      0

user SIDs:
  this probe (control)   S-1-5-21-915860357-1263187065-3401390842-1001
  Edge BROWSER process   S-1-5-21-915860357-1263187065-3401390842-1001
  Edge renderer          S-1-5-21-915860357-1263187065-3401390842-1001
```

The browser process and the control probe match on **every measured dimension**: same user SID, same integrity, both non-AppContainer, both zero restricting SIDs, same group count, same privilege count. **What the probe can reach, the browser process can reach.**

The renderer row is the contrast that makes this meaningful: 1 restricting SID, **0 privileges**, UNTRUSTED integrity, AppContainer token. Chromium's sandbox is real - it is just not applied to the browser process.

### A4 - Filesystem isolation - **FAIL**

**Threat addressed:** Threat Model A - a compromised browser process reading host data.

**Data handling (brief §55):** no real secret was read or printed. Sentinels are synthetic files created and deleted by the script. Real directories were tested for **listability only**; entry counts are reported, names and contents were never read.

```
Synthetic sentinels (stand-ins for the SS13/SS17 categories):
  ssh_private_key        READ OK    (content matched)
  git_credentials        READ OK    (content matched)
  api_keys               READ OK    (content matched)
  password_manager_db    READ OK    (content matched)
  crypto_wallet          READ OK    (content matched)
  personal_document      READ OK    (content matched)

Real user directories - LISTABILITY ONLY:
  Desktop                LISTABLE   (103 entries)
  Documents              LISTABLE   (22 entries)
  Downloads              LISTABLE   (15 entries)
  .ssh                   LISTABLE   (3 entries)
  Credentials store      LISTABLE   (2 entries)
  DPAPI master keys      LISTABLE   (3 entries)
  Chrome profile         LISTABLE   (62 entries)
  Edge profile           LISTABLE   (70 entries)
  project repo           LISTABLE   (5 entries)
```

**Verdict: FAIL.** Every category the brief §13 says must not be exposed is readable and listable by the browser-process token. There is no filesystem boundary around the browser process.

**Write side - one real host control was found active, and it is a genuine partial mitigation:**

```
Documents (CFA default)   BLOCKED
Desktop   (CFA default)   WRITE OK
Downloads (not default)   WRITE OK
LOCALAPPDATA              WRITE OK
```

Attribution is not inferred - Defender's own log names the blocking mechanism and the blocked binary:

```
EnableControlledFolderAccess : 1      ControlledFolderAccessProtectedFolders : (none added)

Microsoft-Windows-Windows Defender/Operational, Event ID 1123:
  "C:\...\Python311\python.exe has been blocked from modifying
   %userprofile%\Documents\ by Controlled Folder Access."
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe has been blocked
   from modifying %userprofile%\Documents\ by Controlled Folder Access."
```

**Controlled Folder Access is already enabled on this host and blocks writes to Documents by any process not on Defender's allow list - including a compromised browser.** It does **not** block reads, and on this machine it did **not** block writes to Desktop or Downloads, so it is a partial control, not a boundary. It must never be disabled (brief §3, §46), and the architecture may lean on it for the write side only.

**Residual risk:** read access to every sensitive location is unmitigated.

### A5 - Registry isolation - **FAIL**

```
HKCU\Software              READ OK
HKCU\...\CurrentVersion\Run  READ OK  (4 values; not printed)
HKLM\...\Winlogon          READ OK  (32 values; not printed)

Persistence write test (value created, then deleted by the script):
HKCU\...\CurrentVersion\Run  WRITE + DELETE OK   <-- persistence would be possible
```

**Verdict: FAIL.** The browser-process token can read security-relevant keys and can write a Run key, so a compromised browser process could establish user-level startup persistence.

### A6 - Process isolation - **FAIL (partial protection observed)**

Handles only. Nothing was injected, written or terminated.

```
services.exe   pid 1776   DENIED (error 5)
lsass.exe      pid 1804   DENIED (error 5)
winlogon.exe   pid 1460   DENIED (error 5)
explorer.exe   pid 9052   OPEN OK (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
```

**Verdict: FAIL for the stated goal.** SYSTEM processes are protected by Windows - that protection is real and is not this project's doing. But `explorer.exe`, an unrelated same-user process, could be opened with `PROCESS_VM_READ` **granted**. The desired result in brief §16 was "cannot meaningfully interact with unrelated host processes", and that is not met.

**Precisely what this shows.** The access right was **granted**; no memory was actually read, and none was attempted. That an open with `PROCESS_VM_READ` succeeds is what makes the subsequent read possible, but the read itself is `[INFERRED]`, not `[MEASURED]`. Deliberately not pursued - demonstrating reachability was the point, and reading another process's memory would have been intrusive and unnecessary.

### A7 - Credential isolation - **FAIL**

Probed with a deliberately impossible filter, so the call proves reachability without enumerating anything real:

```
CredEnumerateW("bm-stage4-nonexistent-target-*") -> GetLastError=1168 ERROR_NOT_FOUND
```

**Verdict: FAIL.** `ERROR_NOT_FOUND` means the API was reachable and the filter matched nothing; `ERROR_ACCESS_DENIED` would have meant refusal. Windows Credential Manager is reachable from the browser-process token. Combined with A4 (DPAPI master key directory listable, browser profiles listable), there is no credential boundary.

**No real credential was enumerated, read, or printed at any point.**

### Architecture consequence of A4-A7 - the central finding of Stage 4

Chromium's sandbox contains **renderers**. It does not contain the **browser process**, because the browser process *is* the broker that builds the sandbox. A2 established that this project cannot wrap that process in an AppContainer. A4-A7 establish that the browser process therefore retains the user's full read access to files, credentials, registry and same-user process memory.

For Threat Model A the honest statement is:

> **Renderer compromise is contained by Chromium's own sandbox. Browser-process compromise is not contained at all.**

Windows itself supplies two real partial controls that were measured active and are not this project's work: SYSTEM-process protection (A6) and Controlled Folder Access on Documents (A4). Neither is a substitute for a boundary.

---

## A10-A15 - network reach baseline - **measured, no control in place yet**

**Environment:** unelevated. `tools/stage4/a10a17_network_baseline.py`. Targets are either listeners the script starts itself on predetermined high ports, or the two single predetermined addresses recorded in Stage 2. **No scanning, no LAN enumeration, no port sweeps** (brief §22, §25).

```
A14 loopback        127.0.0.1:18080                REACHED
A13 IPv6 loopback   [::1]:18082                    REACHED
A10 host own IP     10.0.0.50:18081             REACHED
A15 dev service     127.0.0.1:18443 (stand-in)     REACHED
A11/A12 remote LAN  router 10.0.0.1:80           REACHED
A12 internet        1.1.1.1:443                    REACHED   (control - must stay up)
```

**Verdict: baseline established.** With no rules in place the browser-process token reaches everything the policy in brief §20 says must be denied. This is the "before" half of the enforcement measurement; the "after" half is A16.

**A13 IPv6 - UNKNOWN, and the reason is environmental.** This network reports `IPv6Connectivity: NoTraffic`, and the host holds only link-local `fe80::/10` addresses plus `::1`. There is **no global IPv6 path on this network to test egress against**, so IPv6 egress isolation cannot be measured here at all. Per brief §26 this is recorded as a limitation, not as a pass: on a network that does provide IPv6, this gate must be re-run before any IPv6 claim is made.

---

## A17 - browser-side firewall bypass resistance - **PASS**

**Claim:** a process holding the browser-process token cannot add, remove, or disable Windows Firewall rules.

**Threat addressed:** the defect class this project rejected in Stage 2 - a security control that the compromised component can itself edit. If the browser can delete its own network restrictions, host-side firewall rules are not a boundary.

**Environment:** unelevated, browser-process token class (equivalence proven under A4 Part 1). Every attempt below was expected to fail; the script removes any rule that unexpectedly succeeds, and verified afterwards that none existed.

**Exact test:** attempt rule creation, rule deletion, and profile disablement through the modern `NetSecurity` cmdlets, then repeat rule creation through the older `netsh advfirewall` API.

```
attempt to create an outbound Block rule          -> REFUSED: CimException
attempt to remove that rule                       -> REFUSED: CimJobException
attempt to disable the Public firewall profile    -> REFUSED: CimException

netsh add rule -> rc=1  "The requested operation requires elevation (Run as administrator)."

running elevated (IsInRole Administrator): False
[cleanup] BM-S4-A17-* rules present: 0
```

**Verdict: PASS.** Both the modern and legacy APIs refuse. Firewall policy is administrator-owned; the browser-process token is not administrator. **Host-side firewall rules survive compromise of the browser process** - this is precisely the property WSL2's architecture could not deliver, and it is the strongest positive result of Stage 4.

**Limitations, and one of them is significant:**

1. **This account is a member of `BUILTIN\Administrators` (`S-1-5-32-544` appears in the token's groups); the token is UAC-filtered rather than genuinely non-administrative.** The refusals above are enforced by integrity level and UAC filtering, not by the account lacking the right. A compromised browser process therefore cannot *silently* change firewall policy, but it operates on a machine where an elevation path exists and where a convincing UAC prompt could be socially engineered (threat T8), and where UAC-bypass techniques are a known class. The measured claim is **"cannot change policy without a successful elevation"** - not "cannot ever change policy."
2. Only rule creation, deletion and profile disablement were tested. Other tampering routes - service manipulation, WFP filter injection, registry-level policy edits - were not, and each would also require elevation `[ASSUMED, not measured]`.

**Residual risk:** on an account that was *not* an administrator, this result would be stronger. Running the browser under a standard (non-admin) account is a real hardening option and is recorded as a recommendation rather than something measured.

**Architecture consequence:** network policy is the one axis in this architecture where a host-side control is both applicable and tamper-resistant. It is where the remaining security value of this backend is concentrated.

---

## A16 - host-side firewall enforcement against the browser - **PASS (remote) / FAIL (loopback and host's own IP)**

**Claim:** a Windows Firewall outbound Block rule scoped by `-Program` to the browser executable prevents the browser reaching the addresses named in the rule, while leaving internet access intact.

**Threat addressed:** Threat Model A and C - a compromised browser reaching host services, development services, the router and LAN peers.

**Environment:** rules created and removed by an **elevated one-shot** (`tools/stage4/a16_rules.py`, explicit user consent); probes run **unelevated** (`tools/stage4/a16_probe.py`), which is how the browser actually runs.

**A discarded first attempt is recorded here because it matters.** The original design ran rules *and* probes in one elevated process. Every Edge probe returned an empty DOM **including the baseline**, so the probe - not the firewall - was broken; Chromium does not behave normally under an elevated parent. The baseline control caught it. **No A16 verdict was taken from that run**, the rules were removed, and the test was rebuilt as a split design.

**Configuration:** three outbound Block rules, `-Profile Any`, scoped by `-Program` to `msedge.exe`. Readback confirmed each:

```
BM-S4-A16-edge-deny-loopback  enabled=True action=Block remote=127.0.0.1        program=...\msedge.exe
BM-S4-A16-edge-deny-hostip    enabled=True action=Block remote=10.0.0.50     program=...\msedge.exe
BM-S4-A16-edge-deny-rfc1918   enabled=True action=Block remote=10.0.0.0/255.0.0.0,
                                       172.16.0.0/255.240.0.0,192.168.0.0/255.255.0.0,
                                       169.254.0.0/255.255.0.0                  program=...\msedge.exe
```

**Exact test:** `msedge.exe --headless=new --dump-dom <url>` against four targets, in three phases. Verdict is taken from the DOM (unique marker = reached, Chromium `ERR_*` page = blocked) because **Edge returns exit code 0 even when it renders an error page**. `curl.exe` is probed alongside as a scope control: the rules name `msedge.exe` only, so curl must be unaffected in every phase.

**Raw evidence:**

```
                            BEFORE            DURING                        AFTER
EDGE loopback 127.0.0.1     REACHED           REACHED                       REACHED
EDGE host-own-ip .112       REACHED           REACHED                       REACHED
EDGE router 10.0.0.1      REACHED           BLOCKED ERR_NETWORK_ACCESS_DENIED  REACHED
EDGE internet 1.1.1.1       REACHED           REACHED                       REACHED
curl router (scope control) REACHED           REACHED                       REACHED
curl internet (control)     REACHED           REACHED                       REACHED
```

**Verdict - split, because the mechanism genuinely splits:**

- **PASS for remote addresses.** The router shows the full attributable sequence `REACHED → BLOCKED → REACHED`, with a specific Windows-originated error (`ERR_NETWORK_ACCESS_DENIED`, i.e. the OS refused the socket, not the peer). Internet access was unaffected throughout, and curl was unaffected throughout - so the block is attributable to the rule, is scoped to the browser, and did not become a machine-wide outage.
- **FAIL for loopback and for the host's own LAN IP.** Both remained reachable *with rules explicitly naming those exact addresses and confirmed present by readback*. Windows Firewall does not filter loopback, and traffic to the host's own address is delivered over the loopback path, so it is exempt for the same reason.

**This is the finding that removes a layer the architecture was counting on.** Stage 2.5 built a deliberate two-layer design: AppContainer covered loopback and the host's own IP, program-scoped firewall rules covered remote LAN, and each covered the other's gap. **A2 removed the AppContainer layer, and A16 now confirms the firewall cannot cover its gap.** There is no remaining host-side mechanism in this architecture that stops the browser reaching `127.0.0.1` or the host's own IP.

Consequently:

- **A10 host network isolation = FAIL.** The browser can reach services on the host's own address.
- **A14 loopback isolation = FAIL.** No available control.
- **A15 development-service isolation = FAIL.** Local development servers, databases and localhost APIs are reachable by a compromised browser. Brief §23 called this out as particularly important, and it is not achievable here.
- **A11 LAN isolation = PASS**, and **A12 = PASS for remote / FAIL for local**.

**Limitations:** one browser (Edge), one rule set, IPv4 only, and `-Package` scoping (by AppContainer SID) was not tested since A2 removed the AppContainer route. The router is one predetermined address, not a survey of LAN peers - no scanning was performed (brief §25).

**Residual risk:** any service bound to `127.0.0.1` or to the host's LAN address is exposed to a compromised browser process. On a developer machine that is a large and realistic surface.

**Host change audit for this gate:** three rules created, three rules removed, verified `0` remaining both by the elevated script and independently from the unelevated session (`BM-S4-A16-* = 0`, `BM-* = 0`). No profile, Defender, SmartScreen, CFA, service, or persistence change.

---

## A10 confirmed against real host services - **FAIL**

A16 established that no host-side control can block the browser from `127.0.0.1` or the host's own IP. `tools/stage4/a10_a18_hostsvc_and_dns.py` then tested what is actually listening there. **Bare TCP connect, closed immediately - no SMB or RPC protocol exchange, no authentication attempt, no NTLM.**

```
loopback SMB                     127.0.0.1:445      CONNECTED
host-own-IP SMB                  10.0.0.50:445   CONNECTED
loopback RPC endpoint mapper     127.0.0.1:135      CONNECTED
host-own-IP RPC endpoint mapper  10.0.0.50:135   CONNECTED
host-own-IP NetBIOS session      10.0.0.50:139   CONNECTED
loopback PyCharm service         127.0.0.1:63342    CONNECTED
loopback NextDNS                 127.0.0.1:65008    CONNECTED
```

**This is Stage 2's G3/G8 failure reproduced in the new architecture.** In Stage 2 the WSL2 guest reached host SMB and RPC because traffic was SNAT'd to the host's identity and guest-scoped rules never matched. Here the browser reaches the same services for a different reason - loopback is exempt from firewall filtering - and with the AppContainer layer removed by A2 there is **no available mitigation**. The severity bound from Stage 2 still applies and is repeated deliberately: *proven* - a TCP-reachable path to host SMB/RPC. *Not proven* - a usable SMB/RPC session, and therefore not NTLM coercion or relay.

`127.0.0.1:63342` is a live PyCharm service, so brief §24's development-service protection requirement is concretely, not hypothetically, unmet.

---

## A18 - secure DNS - **UNKNOWN** · A19 - plain DNS leakage - **FAIL**

**A discarded first attempt is recorded because it would have produced a false result.** The initial run dumped Cloudflare's diagnostic page while it still read `AS Name: Checking...`, i.e. before its asynchronous probes completed. Its `DoH: No` could have been a placeholder default. The retest used `--virtual-time-budget=20000` and confirmed the page had settled (`AS Name: Tier 4 Cloud Services`, no `Checking` placeholders) before any value was read.

**OS-level configuration [MEASURED]:**

```
Windows DoH templates registered      : 12  (Quad9, Google, Cloudflare, v4 and v6)
templates with auto-upgrade enabled   : 0
netsh dns show encryption             : "Auto-upgrade : no" for every entry
configured Wi-Fi resolvers            : 8.8.8.8, 4.2.2.2, 1.1.1.1, 139.5.47.155
  of those, with NO DoH template      : 4.2.2.2, 139.5.47.155
NextDNS running                       : C:\Program Files (x86)\NextDNS\NextDNS.exe
                                        listening 127.0.0.1:65008
```

**Plaintext DNS reachability [MEASURED]** - single predetermined resolvers, one benign name, no scanning:

```
139.5.47.155   ANSWERED over plaintext UDP/53  -> 104.20.23.154, 172.66.147.243
8.8.8.8        ANSWERED over plaintext UDP/53  -> 104.20.23.154, 172.66.147.243
```

**A19 verdict: UNKNOWN - with a measured fact underneath it.**

*Measured:* a functioning plaintext DNS path exists on this network, is answered by the configured resolvers, and **Windows is not configured to avoid it** - twelve DoH templates are registered but none has auto-upgrade enabled, and two of the four configured resolvers have no DoH template at all. Nothing in the OS configuration *prevents* plaintext DNS.

*Not established:* that the browser actually sends plaintext DNS. A19 asks about leakage, which is the same unresolved question as A18 approached from the other side - and it is unresolved for the same reason: NextDNS sits in the resolver path and may carry queries over an encrypted upstream. **Marking A19 as FAIL while marking A18 as UNKNOWN would be two different verdicts drawn from identical evidence.** Both are UNKNOWN, and under §31 neither is a pass.

**A18 verdict: UNKNOWN, and the reason is specific.** Cloudflare's diagnostic reported `Using DNS over HTTPS (DoH): No` and `Connected to 1.1.1.1: No` on a settled page - but **NextDNS is running as a local resolver on this machine**, so the browser's queries go to NextDNS, not to Cloudflare. Cloudflare can only report on queries that reach Cloudflare. That result therefore does **not** establish that the browser's DNS is unencrypted; NextDNS may well use an encrypted upstream. **Neither "DNS is encrypted" nor "DNS is leaking" is established.**

A definitive end-to-end answer needs packet capture, which requires a capture driver - an install this project's constraints forbid (brief §3, §46). **So A18 is UNKNOWN, and under §31 it is not a pass.** A18 is load-bearing under §52.

**Architecture consequence (brief §28):** browser-level DoH is a **browser setting**. A compromised browser process turns it off, which is the same defect class as a guest-side firewall - a control inside the thing it is meant to constrain. It is therefore defence for Threat Model B only, and **never** a boundary for Threat Model A. OS-level DoH would be host-side and tamper-resistant, but it is a **system-wide change to the user's network stack**, which brief §33 forbids making blindly. That is a decision for the user, not a change to slip in.

---

## A20 - local-network exposure · A21 - public Wi-Fi host protection - **FAIL**

Read-only audit of **this machine's own** configuration and sockets. No LAN scanning, probing or enumeration (brief §22, §25). `tools/stage4/a20a21a34-host-exposure-audit.ps1`.

```
Network: "CampusWiFi"   category Public   IPv4 Internet   IPv6 NoTraffic
Firewall: Domain/Private/Public all Enabled=True

LISTENING TCP, WILDCARD (reachable from the Wi-Fi):
  135 svchost      445 System       5040 svchost     30002 ToolkitService
  49664 lsass      49665 wininit    49666 svchost    49667 svchost
  49668 spoolsv    49669 SeagateSecureService        49670 services
LISTENING TCP, bound to 10.0.0.50:  139 System
LISTENING TCP, loopback only: 6188 cef_server, 6189/63342 pycharm64, 65008 NextDNS

LanmanServer  Running (Automatic)      TermService  Stopped     RemoteRegistry Disabled
SMB1 False · SMB2 True · RequireSecuritySignature FALSE · EnableSecuritySignature FALSE
SMB shares: ADMIN$, C$, IPC$

Public-profile inbound rule groups, enabled:
  File and Printer Sharing   17 of 17 rules apply to Public and are ENABLED
  Network Discovery           0 of 22
  Remote Desktop              0 of 0
```

**Verdict: FAIL for the §33 goals.** On an untrusted university network the machine currently exposes SMB (445), NetBIOS (139), the RPC endpoint mapper (135) and a range of RPC service ports on the wildcard address, with **File and Printer Sharing enabled for the Public profile** and **SMB signing neither required nor enabled**. Two third-party services (`SeagateSecureService`, `ToolkitService` on 30002) also listen on the wildcard.

**Limitation, stated plainly:** this is a *configuration and socket* audit. Whether a peer on `CampusWiFi` can actually complete a connection to port 445 was **not tested**, because that would require either scanning (forbidden by §22/§25) or a second device. Reachability from the LAN is therefore `[INFERRED]`, not `[MEASURED]`. The listening state and the enabled Public-profile rules are `[MEASURED]`.

**Architecture consequence:** these are host-hardening items, entirely separate from the browser. Brief §33 explicitly warns against blindly reconfiguring the user's network stack, so **no change was made**. Narrow, reversible remediations are listed in `NETWORK-PRIVACY.md` for the user to decide on.

---

## A22 / A23 / A24 - VPN - **UNSUPPORTED**

No VPN is configured on this machine, and brief §60 forbids hard-coding or recommending a provider. A kill switch could therefore not be demonstrated. Per brief §31 the honest outcome is stated as the brief itself directs:

```
VPN MODE = UNSUPPORTED
```

rather than claiming an untested feature works. A23 and A24 are load-bearing *if VPN mode is supported*; it is not, so no VPN claim of any kind may be made.

**One precondition was measured and is worth carrying forward:** A16 proved that `-Program` scoped rules genuinely block the browser's remote traffic and that A17's tamper-resistance holds. A kill switch built on the same mechanism - deny the browser all remote addresses except the VPN endpoint and the tunnel interface - therefore rests on a mechanism that has been measured to work for remote destinations. **That is a measured precondition, not a measured kill switch.**

---

## A34 - host security preservation - **PASS**

```
Defender realtime            : True          Defender antispyware : True
Tamper protection            : True          Controlled Folder Access : 1
VBS status                   : 2 (running)   Security services running : 2 (HVCI)
Firewall Domain/Private/Public: all Enabled
Defender exclusion paths     : 1 (pre-existing; not created by this project)
BM-* firewall rules remaining: 0
```

**Verdict: PASS.** Every protection the brief forbids weakening is intact and matches the Stage 3 baseline. Nothing was disabled, excluded, or downgraded at any point in Stage 4.

**Two measurement caveats:** `Confirm-SecureBootUEFI` requires elevation and returned "query failed" in this unelevated audit - Secure Boot was measured as `1` in Stage 3 and nothing in Stage 4 could have changed it, but this run did not re-confirm it. The Explorer `SmartScreenEnabled` registry value returned empty, which on current Windows builds does not mean SmartScreen is off - the setting has moved - so **no SmartScreen claim is made in either direction**.

---

## Stage 4 host change audit

| Change | Disposition |
|---|---|
| AppContainer profiles `bm-s4-*` created for A1/A2 | created → tested → **deleted** (`hr=0x00000000` each run) |
| Dedicated data directories under `%LOCALAPPDATA%\BrowserMaker\` | created → **removed**, verified absent |
| ACL grants to specific container SIDs on those directories | removed with the directories; **never granted to `ALL APPLICATION PACKAGES`** |
| 3 firewall rules `BM-S4-A16-*` (elevated, consented) | created → tested → **removed**; `0` remaining, verified twice, independently |
| 1 firewall rule attempt `BM-S4-A17-PROBE` | **refused by Windows** (that was the test); `0` present afterwards |
| Registry value `HKCU\...\Run\BM_STAGE4_PROBE` | created → **deleted** within the same call |
| One write probe into `%USERPROFILE%\Documents` | **blocked by Controlled Folder Access**; no file created |
| Write probes into Desktop / Downloads / LOCALAPPDATA | created → **deleted** immediately |
| Sentinel tree `%LOCALAPPDATA%\BrowserMaker\S4Sentinels` | synthetic content only → **removed**, verified absent |
| New files under `tools/stage4/` and `docs/` | retained deliberately (deliverables) |

**No persistent host change remains from Stage 4.** Defender, SmartScreen, Secure Boot, VBS, HVCI, CFA, firewall profiles, services, scheduled tasks, drivers, certificates, proxy and DNS configuration were all left exactly as found. No elevation was used except the one consented A16 rule create/remove pair.

**Carried over from Stage 2.5 and still awaiting the user's decision:** `HypervisorPlatform` remains enabled with a reboot pending, and QEMU 11.0.50 remains installed at `C:\Program Files\qemu` (rejected by B17, must not be used). Stage 4 did not touch either.

---

## Stage 4 decision (brief §62)

```
REVISE - APPLICATION ISOLATION INSUFFICIENT
```

**Grounds.** Brief §52 designates nineteen gates as load-bearing. Of those actually reachable in this stage:

| Load-bearing gate | Result |
|---|---|
| A4 filesystem isolation | **FAIL** |
| A6 process isolation | **FAIL** |
| A7 credential isolation | **FAIL** |
| A10 host network isolation | **FAIL** |
| A14 loopback isolation | **FAIL** |
| A16 host-side firewall enforcement | **PASS** remote / **FAIL** loopback + host IP |
| A18 secure DNS | **UNKNOWN** |
| A19 plain DNS leakage | **UNKNOWN** |
| A11 LAN isolation | **PASS** |
| A17 browser-side bypass resistance | **PASS** |
| A34 host security preservation | **PASS** |
| A13 IPv6 | **UNKNOWN** (no IPv6 path exists on this network) |
| A23/A24 VPN | **UNSUPPORTED** |
| A28-A32 controller, IPC, fail-closed, export | **NOT MEASURED** (no controller built) |

Brief §52: *"A failure in a critical isolation gate means: DO NOT CLAIM THE FEATURE IS SECURE."* Six load-bearing gates failed outright, three more are UNKNOWN, and under §31 unknown is not a pass. The primary objective in §1 - *reduce the damage a malicious or compromised website/browser process can cause to the Windows host* - **is not met for a compromised browser process**, which is the case the whole project exists to survive.

**Why REVISE rather than STOP.** Three results are real, tamper-resistant, and worth keeping: renderer sandboxing by Chromium itself (A3), network isolation from the router and LAN that the browser cannot remove (A16 + A17), and zero weakening of host protections (A34). That is a defensible **defence-in-depth and network-privacy** product. It is **not** a host-isolation product, and it must not be sold as one.

**Why not PROCEED.** Proceeding would mean shipping something whose central claim is false. The gap is structural - the browser process cannot be contained on this SKU with these mechanisms - not a matter of tuning.

**What "revise" means concretely.** Either:

1. **Reduce the claimed scope** to what was measured: a hardened-configuration browser with LAN/router network isolation, host hardening advice, and privacy settings - explicitly documented as *not* protecting the host from a compromised browser process; or
2. **Return to a VM backend**, which on this machine requires Windows 11 Pro (Stage 3, `H1 = FAIL`) and still carries the unverified network hypothesis recorded in `HYPERV-ARCHITECTURE.md` §4.

The choice between them is the user's, and it is a scope decision rather than an engineering one.
