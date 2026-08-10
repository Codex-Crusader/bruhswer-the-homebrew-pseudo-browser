# Backend Verification - B-gate results (QEMU + WHPX candidate)

**Date:** 2026-08-08 · **Status:** B1 and B7-pre answered. B2-B14 **blocked pending consent** for two host changes.

Verdicts are only `PASS` / `FAIL` / `UNKNOWN`. No "mostly passed", no "acceptable".

## Status board

```
B1  - WHPX availability                 PASS (feature ENABLED; reboot pending)  [MEASURED]
B17 - QEMU binary authenticity          FAIL  (signing cert expired 2023)       [MEASURED]
B15 - QEMU runnable in AppContainer     PARTIAL: ACL precondition satisfied     [MEASURED]
```

<details><summary>previous status line, retained</summary>

```
B1  - WHPX availability                 PARTIAL: feature present but DISABLED  [MEASURED]
B7pre - AppContainer network isolation  PASS for loopback+host / FAIL for remote LAN  [MEASURED]
B2  - QEMU launches safely              UNKNOWN (blocked: QEMU not installed)
B3  - VM privilege model                UNKNOWN (blocked)
B4  - Minimal virtual device inventory  UNKNOWN (blocked)
B5  - No host filesystem exposure       UNKNOWN (blocked)
B6  - No clipboard/device redirection   UNKNOWN (blocked)
B7  - Guest -> host network isolation   UNKNOWN (blocked)
B8  - Guest -> LAN isolation            UNKNOWN (blocked)
B9  - IPv6 isolation                    UNKNOWN (blocked)
B10 - Internet connectivity             UNKNOWN (blocked)
B11 - Host -> guest control path        UNKNOWN (blocked)
B12 - Guest -> host control-plane iso   UNKNOWN (blocked)
B13 - VM lifecycle / destruction        UNKNOWN (blocked)
B14 - Persistent/disposable separation  UNKNOWN (blocked)
B15 - QEMU runnable inside AppContainer UNKNOWN (new gate, added below)
B16 - Firewall -Program scoping         PASS  [MEASURED]
```

</details>

**Network boundary status: both layers now measured and passing.** AppContainer covers loopback and the host's own IP (B7-pre); program-scoped firewall rules cover remote LAN while preserving internet (B16). Together they express the full policy required by the brief §10, entirely host-side. What remains unproven is whether **QEMU specifically** inherits these properties (B15, B2, B7) - the layers were measured with `curl.exe` as a stand-in.

Two gates were added beyond the brief's fourteen, because the design introduced two new security boundaries that did not exist when the list was written. The brief (§24) explicitly invites this.

---

## B1 - WHPX availability - **PARTIAL**

**Claim:** Windows Hypervisor Platform is available on this Windows 11 Home installation.
**Threat addressed:** none directly; a precondition for the whole backend.
**Test environment:** unelevated PowerShell, host as surveyed.

**Exact test:** `Get-CimInstance Win32_OptionalFeature`, plus presence checks for the WHP API DLLs.

**Observed:**

```
HypervisorPlatform                DISABLED
VirtualMachinePlatform            ENABLED
Microsoft-Windows-Subsystem-Linux DISABLED
(Microsoft-Hyper-V and Containers-DisposableClientVM: ABSENT from enumeration)

WinHvPlatform.dll        True
WinHvEmulation.dll       True
vmcompute.exe            True
WindowsSandbox.exe       False

CPU: AMD Ryzen 7 7840HS   Cores/Threads 8/16
VirtualizationFirmwareEnabled: True    HypervisorPresent: True
Secure Boot: 1   VBS: 2 (running)   HVCI: 1   Defender RTP: True
```

**Verdict: PARTIAL.** The WHP API is present on disk and the feature is **installable** - it reports `DISABLED`, not `ABSENT`. Hardware virtualization is available. But the feature is **not enabled**, so QEMU cannot use WHPX yet.

Note the stronger evidence for the SKU limitation than Stage 1 had: `Microsoft-Hyper-V` and `Containers-DisposableClientVM` do not appear in the feature enumeration **at all** on this edition.

**Residual risk:** enabling WHP requires elevation and a reboot. It does not weaken any security feature - WHP is a virtualization API that coexists with VBS/HVCI by design `[DOC]` - but it is persistent host state.

**Architecture consequence:** B2 onward cannot run until this is enabled. Consent required.

---

## B7-pre - AppContainer network isolation - **PASS (loopback/host) / FAIL (remote LAN)**

**Claim:** An AppContainer holding only `internetClient` blocks the contained process from reaching loopback and RFC1918 addresses while still reaching the internet.

**Threat addressed:** the exact failure that killed WSL2 - hostile guest code reaching host services. Under SLIRP, guest sockets are issued by the QEMU process, so confining that process confines the guest's network reach.

**Test environment:** unelevated. `tools/stage25/appcontainer_netisolation_test.py`. Child process is System32 `curl.exe` at a fixed absolute path - **deliberately not QEMU**, so the AppContainer property is measured in isolation from QEMU's behaviour. Output captured via an inherited handle rather than a path, so no filesystem ACL grant is needed.

**Configuration:** AppContainer profiles created and deleted within the run. Capability sets tested: `internetClient` alone (S-1-15-3-1), and `internetClient + privateNetworkClientServer` (S-1-15-3-3).

**Targets:** local HTTP listeners on `127.0.0.1:18080` and `10.0.0.50:18081`; the router `10.0.0.1` as a single predetermined remote LAN peer; `1.1.1.1` as internet. No scanning, no device enumeration.

**Raw evidence:**

```
=== CONTROL: no AppContainer (ordinary process) ===
  loopback  127.0.0.1                REACHABLE    raw='HTTP_200'
  host-own-ip 10.0.0.50           REACHABLE    raw='HTTP_200'
  REMOTE LAN router 10.0.0.1       REACHABLE    raw='HTTP_302'
  internet  1.1.1.1                  REACHABLE    raw='HTTP_301'

=== APPCONTAINER: internetClient ONLY (proposed design) ===
  loopback  127.0.0.1                BLOCKED (curl exit 28)   raw='HTTP_000'
  host-own-ip 10.0.0.50           BLOCKED (curl exit 28)   raw='HTTP_000'
  REMOTE LAN router 10.0.0.1       REACHABLE                raw='HTTP_302'
  internet  1.1.1.1                  REACHABLE                raw='HTTP_301'

=== APPCONTAINER: internetClient + privateNetworkClientServer ===
  loopback  127.0.0.1                BLOCKED (curl exit 28)
  host-own-ip 10.0.0.50           BLOCKED (curl exit 28)
  REMOTE LAN router 10.0.0.1       REACHABLE                raw='HTTP_302'
  internet  1.1.1.1                  REACHABLE                raw='HTTP_301'

Network category: Public   (SSID "CampusWiFi", IPv4 Internet, IPv6 NoTraffic)
```

The control run is what makes this meaningful: every target is reachable from an ordinary process, so the blocks are caused by the AppContainer and not by an absent listener or an unrelated filter.

**Verdict:**
- **PASS** - loopback and the host's own LAN IP are blocked. Windows Firewall *cannot* filter loopback, so this is a property only AppContainer supplies, and it is precisely the WSL2 failure mode.
- **FAIL** - the remote LAN router remained reachable under **both** capability sets.

**Interpretation, and why the FAIL is a design finding rather than a defect:** this network's `NetworkCategory` is `Public`. Windows classifies a Public network as "the internet", so `internetClient` authorises the local subnet and `privateNetworkClientServer` is never consulted `[MEASURED, cause inferred]`.

**Residual risk:** a control whose behaviour depends on the network category Windows happens to assign is not dependable. If this machine joins a network classified `Private`, AppContainer's behaviour toward LAN peers would differ. **The design must therefore never rely on AppContainer for LAN blocking.**

**Architecture consequence:** the network boundary needs two complementary host-side mechanisms, because each covers the other's gap:

| Layer | Provides | Cannot provide |
|---|---|---|
| AppContainer (`internetClient` only) | loopback + host-own-IP blocking | remote LAN blocking (category-dependent) |
| Windows Firewall outbound deny, scoped `-Program` / `-Package` | remote LAN + RFC1918 blocking, category-independent | loopback blocking (loopback is exempt) |

Both are host-side and outside the guest, satisfying the rule that a control inside a compromised guest is not a boundary.

---

## New gates added

### B15 - Can QEMU actually run inside an AppContainer?

**Why added:** the entire loopback protection above depends on QEMU running *inside* the container. QEMU needs read/write on its disk image and read on BIOS/ROM files; an AppContainer has no access to arbitrary paths without an explicit ACL grant to the container SID.

**If it fails:** loopback protection is unavailable, the guest can reach host services through SLIRP exactly as it did under WSL, and the backend must be re-scored - this would be a B7 FAIL, not a pass with a caveat. If it proves impractical to launch QEMU this way, that will be reported as impractical rather than half-built.

### B16 - Do firewall rules scoped by program actually block remote LAN? - **PASS**

**Why added:** B7-pre proved AppContainer does *not* cover remote LAN here, so the firewall layer is load-bearing rather than defence in depth. Stage 2 is the cautionary precedent: the Hyper-V Firewall cmdlets also existed, accepted rules, and reported success - and the boundary still did not hold. Efficacy had to be measured.

**Claim:** an outbound Block rule scoped by `-Program` prevents the named program reaching RFC1918 while leaving internet access intact.

**Test environment:** elevated one-shot script `tools/stage25/b16-firewall-program-scope-test.ps1`. Stand-in program is System32 `curl.exe` - **QEMU is not installed and nothing here installed it**. Exactly one firewall rule created, then removed in a `finally` block.

**Configuration:** `-Direction Outbound -Action Block -Program C:\WINDOWS\System32\curl.exe -RemoteAddress 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 -Profile Any`. Rule readback confirmed the program filter and all four address ranges applied.

**Raw evidence:**

```
--- BASELINE (no rule) ---
REMOTE LAN router 10.0.0.1       REACHED    (curl exit 0)
INTERNET 1.1.1.1                   REACHED    (curl exit 0)

--- WITH RULE ACTIVE ---
REMOTE LAN router 10.0.0.1       BLOCKED    (curl exit 7)
INTERNET 1.1.1.1                   REACHED    (curl exit 0)

--- POST-CLEANUP (rule removed) ---
REMOTE LAN router 10.0.0.1       REACHED    (curl exit 0)
INTERNET 1.1.1.1                   REACHED    (curl exit 0)

[cleanup] verified: rule absent      BM-Stage25 rules remaining: 0
```

**Verdict: PASS.** The before/after/revert sequence is what makes this conclusive: the router was reachable, became unreachable (`curl exit 7`, could not connect) only while the rule existed, and became reachable again once it was removed. Internet access was unaffected throughout. The block is attributable to the rule and to nothing else.

**Limitation - one probe in this test was inconclusive and is not evidence.** The `127.0.0.1:135` loopback probe reported BLOCKED (`curl exit 28`) in *all three* states including baseline, because HTTP against an RPC port simply hangs. It says nothing about whether the firewall filters loopback. **No loopback claim is made from this gate.** Loopback is covered by AppContainer (B7-pre, measured); the documented firewall loopback exemption `[DOC]` is not relied upon in either direction here.

**Residual risk:** only `-Program` scoping was tested. `-Package` scoping (by AppContainer SID), which is the more precise variant for a contained QEMU, remains **untested** `[ASSUMPTION]`. Rule efficacy was measured with `curl.exe`, not with QEMU; whether QEMU's SLIRP sockets are attributed identically is untested until B2/B15.

**Architecture consequence:** the two-layer network design is now **evidence-backed on both layers**:

| Layer | Blocks | Measured |
|---|---|---|
| AppContainer, `internetClient` only | loopback + host's own LAN IP | **PASS** (B7-pre) |
| Firewall outbound deny, `-Program` scoped | remote LAN / RFC1918, internet preserved | **PASS** (B16) |

Each covers the other's gap, both are host-side, and neither depends on a control living inside the untrusted guest. This is the property WSL2 could not provide, because its kernel SNAT destroyed traffic attribution.

Baseline for the host audit: **0 outbound Block rules existed before this test, and 0 remain** `[MEASURED]`.

---

## B17 - QEMU binary authenticity - **FAIL / UNRESOLVED**

> **Full investigation: [`B17-QEMU-PROVENANCE.md`](B17-QEMU-PROVENANCE.md).**
> Outcome: `B17 UNRESOLVED - QEMU BACKEND CANNOT PROCEED`.
> Recommendation: `ROLL BACK QEMU AND USE WINDOWS 11 PRO / HYPER-V PATH`.
>
> Two findings from that investigation supersede the summary below:
> 1. The PE's own `signingTime` is **2026-05-01**, against a certificate that expired
>    **2023-12-09** - signing occurred ~2.4 years after expiry, confirmed from the PE
>    itself rather than inferred from the file date.
> 2. The distributor **declares this as permanent policy**: *"All newer installers are
>    signed with an expired certificate. Sorry, but a new certificate for code signing is
>    too expensive."* No newer build resolves it; **upgrading is not a remedy**.
>
> Also measured: the bundled DLLs (the large majority of 3374 installed files) are
> **entirely unsigned**, so even a valid `.exe` signature would not have covered them.

**Why this gate exists:** brief §22 requires verifying package authenticity before trusting a new virtualization stack. This gate was not in the original B1-B14 list; it was added when verification was actually performed.

**Claim:** the installed QEMU binaries carry a valid Authenticode signature that Windows can verify.

**Test:** `Get-AuthenticodeSignature` plus an explicit X509 chain build on `C:\Program Files\qemu\qemu-system-x86_64.exe`.

**Raw evidence:**

```
Status:        UnknownError
StatusMessage: A required certificate is not within its validity period when verifying
               against the current system clock or the timestamp in the signed file
Subject:       CN=Universität Mannheim, O=Universität Mannheim, S=Baden-Württemberg, C=DE
Issuer:        CN=GEANT Code Signing CA 4, O=GEANT Vereniging, C=NL
NotBefore:     12/09/2022 05:30:00
NotAfter:      12/10/2023 05:29:59      <-- EXPIRED
Expired:       True
Thumbprint:    2F92CB990D57719BDCCA2D72134378614A040D9B
Chain builds OK: False
  status: NotTimeValid
Timestamped by: CN=Sectigo Public Time Stamping Signer R36, O=Sectigo Limited
Binary SHA256: B396EB9B669F6282EC60F0D46E6ADDCA8C669992E67A34365BE44CD3CB97C9A7
Binary built:  05/01/2026        QEMU version 11.0.50 (v11.0.0-12631-g54e84cdc7a)
```

**Verdict: FAIL.**

**Interpretation, carefully bounded.** The binary *is* signed and *is* timestamped, but with a code-signing certificate that expired **2023-12-09 23:59:59 UTC** (rendered above as `12/10/2023 05:29:59` in host local time, UTC+05:30), while the binary was built **2026-05-01** - roughly two and a half years after expiry. Timestamping normally preserves a signature past certificate expiry by proving the signing happened while the certificate was valid; it cannot help here, because the signing demonstrably happened afterwards. Windows therefore builds no valid chain, and treats this binary as effectively unsigned.

The signer, `Universität Mannheim`, is consistent with the maintainer of the `qemu.weilnetz.de` Windows builds. Nothing here indicates tampering, and these builds are in wide use.

**What may NOT be concluded:** that the binary is malicious, modified, or unsafe. That is not shown and is not claimed.

**What this does mean:** Windows Authenticode provides **no publisher assurance** for this binary. The only integrity control in the install path is the winget SHA256 match - which protects the download against tampering *in transit* and against a compromised mirror, but not against a compromised build host, and the manifest itself is community-maintained. SmartScreen and Defender will treat these binaries as unsigned.

**Residual risk:** this is now the **largest single risk of the QEMU backend**, larger than any device-emulation concern, because it sits upstream of everything else. Accepting it is a user decision, not an engineering one. Mitigations available: version pinned to 11.0.50, binary SHA256 recorded above for future comparison, and no auto-update.

**Architecture consequence:** `BACKEND-REDESIGN.md` §6 is upgraded from "not Microsoft-signed" to "**carries no verifiable signature at all**". This is a real difference from what was described when consent was sought, and is reported rather than absorbed.

---

## B15 - QEMU runnable inside an AppContainer - **PARTIAL (precondition satisfied)**

**Claim:** QEMU can execute inside an AppContainer, which the loopback protection in B7-pre depends on.

**The anticipated obstacle** was that an AppContainer has no access to arbitrary paths, so QEMU's binaries, ROMs and disk image would each need explicit ACL grants to the container SID - potentially impractical.

**Measured:**

```
C:\Program Files\qemu ACL:
  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES             ReadAndExecute, Synchronize  Allow  (inherited)
  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES  ReadAndExecute, Synchronize  Allow  (inherited)

Install footprint: 3374 files, 1169.8 MB
qemu-system-x86_64.exe True | qemu-img.exe True | qemu-ga.exe True
```

**Verdict: PARTIAL.** The read/execute precondition is **already satisfied by inheritance from Program Files** - no ACL modification to Program Files is needed, removing the main anticipated obstacle and a host change that would otherwise have been required.

**Still unproven:** that QEMU actually launches and runs a guest inside the container, and that its **writable** disk image (which will live outside Program Files) can be granted to the container SID. Full B15 requires the reboot.

**Note for the guest build:** `qemu-ga.exe` (QEMU Guest Agent) ships with the host install. That is harmless on the host, but per `BACKEND-THREAT-MODEL.md` §4 it must **never** be installed into a guest - it is the QEMU-shaped equivalent of WSL's interop socket.

---

## Host changes so far in Stage 2.5

| Change | Disposition |
|---|---|
| Created and deleted two AppContainer profiles (`bm-test-inet`, `bm-test-inet-priv`) | changed → tested → **restored** (`DeleteAppContainerProfile` returned `0x00000000` for both) |
| Temporary HTTP listeners on `127.0.0.1:18080` and `10.0.0.50:18081` | process-lifetime only, torn down |
| New repository files under `tools/stage25/` and `docs/` | retained deliberately (deliverables) |

| One outbound firewall rule `BM-Stage25-B16-curl-deny-rfc1918` (B16) | changed → tested → **restored**; 0 remain, verified independently |
| **Enabled Windows optional feature `HypervisorPlatform`** (elevated, `-NoRestart`) | **PERSISTENT** - `Disabled` → `Enabled`. `RebootPending = True`. Script deliberately did not reboot. |
| **Installed QEMU 11.0.50** to `C:\Program Files\qemu` (elevated, winget, version-pinned) | **PERSISTENT** - 3374 files, 1169.8 MB. Installer hash verified by winget. |

Defender, SmartScreen, Secure Boot, VBS, HVCI, ASLR/DEP/CFG unchanged. No services, scheduled tasks, startup entries, drivers, certificates, proxy or DNS changes. No registry security changes. No reboot performed.

**Two changes are now persistent** and were made with explicit consent. Both are reversible: the feature via `Disable-WindowsOptionalFeature`, QEMU via `winget uninstall`.

**Pending user action:** a reboot is required before WHPX acceleration is usable. `B2` and everything depending on hardware acceleration are blocked until then. `B15`'s remaining half can also only be completed after the reboot.

---

## What is required to continue

B2 onward cannot proceed without two host changes, both requiring elevation, neither of which will be performed without explicit consent:

1. **Enable the `HypervisorPlatform` optional feature** - elevation plus a reboot. Does not weaken any security feature.
2. **Install QEMU 11.0.50** - elevation, NSIS installer, third-party build host (`qemu.weilnetz.de`), not Microsoft-signed. See `BACKEND-REDESIGN.md` §6.

No `PROCEED` / `REVISE` / `UNSUITABLE` decision under brief §33 is recorded, because the evidence to support one does not exist yet.
