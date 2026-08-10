# Project History - backends attempted, and why each was abandoned

**Date:** 2026-08-09 · **Status:** current as of the Stage 3 halt.

This document exists so that the superseded design documents can be read correctly. `THREAT-MODEL.md`, `ARCHITECTURE.md`, `BACKEND-THREAT-MODEL.md` and `BACKEND-VERIFICATION.md` describe backends that were **evaluated and rejected**. They are preserved unedited except for correction notes, because the evidence in them is the reason later decisions were made.

**Hyper-V was not the original plan.** It is the third candidate, reached only after the first was measured to fail and the second was rejected on supply chain. Nothing in the Hyper-V documents should be read as though it had been the intended design from the start.

---

## 1. Chronology

| # | Stage | Backend under evaluation | Outcome |
|---|---|---|---|
| 1 | Stage 1 - design | **WSL2** | Design accepted for verification. Nothing measured. |
| 2 | Stage 2 - empirical verification (G1-G8) | **WSL2** | **Measured FAIL.** G1, G3, G8. |
| 3 | Stage 2.5 - backend redesign (B1-B16) | **QEMU + WHPX** | Network design measured sound; backend blocked at B17. |
| 4 | B17 - binary provenance hard stop | **QEMU + WHPX** | **Rejected on supply chain.** `UNRESOLVED - cannot proceed`. |
| 5 | Stage 3 - Hyper-V evaluation (H1-H22) | **Hyper-V on Windows 11 Pro** | **Halted at H1 = FAIL.** Host is Windows 11 Home; Hyper-V cannot be installed. |
| 6 | Stage 4 - Windows app isolation (A1-A34) | **AppContainer + Chromium sandbox + firewall** | **REVISE - application isolation insufficient.** Not a VM, and measurably weaker. |
| 7 | Stage 5 - BRUHWSER implementation | **Windows-native defence in depth around Edge** | **Built.** Scope reduced to what Stage 4 measured as achievable. |

No browser implementation code has ever been written. Every stage to date has been design plus measurement.

---

## 2. Stage 1 - WSL2 selected on paper

WSL2 was chosen because it delivers a Microsoft-signed, in-box, hardware-accelerated Linux VM on Windows 11 **Home**, which was - and remains - this machine's actual SKU. Windows Sandbox and Hyper-V were both unavailable on Home, so WSL2 was the only in-box hypervisor-backed option.

Documents: `SECURITY.md`, `THREAT-MODEL.md`, `ARCHITECTURE.md`, `IMPLEMENTATION-PLAN.md`.

The design already recorded the structural objections that later proved decisive:

- `wslservice.exe` runs as **LocalSystem**, so a guest-facing control-channel bug escalates a guest compromise straight to SYSTEM - worse than a hypervisor escape, which lands in a low-privilege worker.
- WSL2 runs all distributions inside **one utility VM**, so Mode A (persistent) and Mode B (disposable) could be separated only in time (invariant MX-1), never in space.

These were known costs, accepted pending measurement. They are not what killed the backend.

## 3. Stage 2 - WSL2 measured, and it failed

```
G1  /dev/dxg isolation       FAIL
G2  WSL interop              PASS (with residual)
G3  IPv4 network isolation   FAIL
G4  IPv6 isolation           UNKNOWN
G5  RDP isolation            UNKNOWN (not reached - stop condition)
G6  Shared utility VM        PASS (shared VM confirmed; MX-1 necessary)
G7  Filesystem isolation     PASS (with residual)
G8  Firewall enforcement     FAIL
```

Evidence: `STAGE-2-RESULTS.md`.

**G1 - `/dev/dxg` could not be removed.** `guiApplications=false` disables WSLg but leaves the GPU paravirtualisation device present, world read/write, and **openable by an unprivileged process** - a direct ioctl path from a compromised renderer to the host's `dxgkrnl` kernel driver.

**G3/G8 - the load-bearing network control did not hold, and the mechanism was established rather than guessed.** Host-side Hyper-V Firewall rules (`New-NetFirewallHyperVRule`) successfully blocked the router, LAN peers and non-allowlisted ports, but did **not** stop the guest reaching the Windows host's own SMB (445) and RPC (135). The reason, measured from the host:

```
--- HOST view, established connections on port 445 ---
LocalAddress   LocalPort  RemoteAddress   RemotePort  OwningProcess
10.0.0.50   445        10.0.0.50    52256       4

--- established connections from WSL subnet 172.16.x ---
NONE
```

Guest→host traffic is **source-NAT'd to the host's own LAN IP** before the filter sees it, so guest-scoped rules never match. The traffic arrives wearing the host's identity.

Severity was bounded honestly at the time and still is: *proven* - a TCP-reachable path to host SMB/RPC. *Not proven* - a usable SMB/RPC session, and therefore not NTLM coercion or relay.

**Trust boundary TB-3 was therefore not established**, and under the project's fail-closed rule the browser could not launch on this backend.

## 4. Stage 2.5 - WSL2 rejected; QEMU + WHPX evaluated

`BACKEND-REDESIGN.md` records the rejection. The brief for that stage forbade the obvious escape routes, and they were not taken: no additional guest-side firewall rules, no reliance on `nftables`, no disabling SMB or RPC on Windows. **Reconfiguring the Windows host to compensate for a weak guest isolation boundary is not a substitute for a strong one**, and a control that lives inside the compromised guest is not a boundary at all.

QEMU with Windows Hypervisor Platform (WHPX) became the candidate because WHPX *is* installable on Home. Documents: `BACKEND-THREAT-MODEL.md`, `BACKEND-VERIFICATION.md`.

The important work of this stage was the **host-side, two-layer network design**, and both layers were measured with a stand-in program before any dependence was placed on them:

| Layer | Blocks | Cannot block | Gate |
|---|---|---|---|
| AppContainer holding `internetClient` only | loopback **and the host's own LAN IP** | remote LAN (network-category dependent) | B7-pre **PASS** |
| Windows Firewall outbound deny, `-Program` scoped | remote LAN / RFC1918, internet preserved | loopback (exempt from the firewall) | B16 **PASS** |

Each covers the other's gap, both sit outside the guest, and neither depends on traffic attribution that a NAT can destroy. This is precisely what WSL2 could not offer.

## 5. B17 - QEMU rejected on supply chain

A hard stop was called before building anything on QEMU, to answer one question: can these binaries be trusted enough to enter the trusted computing base? Full investigation: `B17-QEMU-PROVENANCE.md`.

- The Windows binaries are signed by `CN=Universität Mannheim` with a certificate that expired **2023-12-09 23:59:59 UTC**. The PE's own `signingTime` attribute reads **2026-05-01 11:32:05 UTC** - signing occurred roughly 2.4 years *after* expiry, so the RFC3161 timestamp cannot rescue it. Windows independently decodes that timestamp and still returns `NotTimeValid`.
- The bundled DLLs - the large majority of 3374 installed files - are **unsigned outright**, so even a valid `.exe` signature would not have covered them.
- The maintainer declares it permanent policy: *"All newer installers are signed with an expired certificate. Sorry, but a new certificate for code signing is too expensive."* **Upgrading is not a remedy.**
- The QEMU project does not build official Windows binaries; it endorses an individual maintainer's personal build host. The winget SHA256 match proves **integrity in transit only**, not authenticity, and the manifest is community-maintained.

What was **not** concluded, and is still not claimed: that the binary is malicious, tampered with, or unsafe. No evidence of that exists. Wide use was explicitly refused as a security argument.

```
B17 UNRESOLVED - QEMU BACKEND CANNOT PROCEED
ROLL BACK QEMU AND USE WINDOWS 11 PRO / HYPER-V PATH
```

The recommendation rests on one asymmetry: every QEMU route on Home ends in binaries Windows cannot validate and adds a **new** trust root; the Microsoft hypervisor is **already loaded and already trusted** on this machine (Secure Boot 1, VBS 2 running, HVCI 1), so a Hyper-V route adds none. That is a supply-chain property and nothing more - it is not a claim that Hyper-V is architecturally safer.

MSYS2 was assessed as genuinely better-provenanced than the installed build (GPG keyring, master-key signing policy, project CI) and remains the strongest QEMU-preserving option if the machine stays on Home. Local source compilation was assessed and **not** chosen: it inherits the MSYS2 toolchain anyway, still yields an unsigned binary, and trades a provenance gain for patch latency on the exact component that faces hostile input.

## 6. Stage 3 - Hyper-V, halted before it began

`H1 = FAIL`. The machine is `Microsoft Windows 11 Home Single Language` (`EditionID: CoreSingleLanguage`), genuinely licensed via OEM_DM. `Microsoft-Hyper-V` and `Containers-DisposableClientVM` are **absent from the optional-feature enumeration entirely** - not `Disabled`, which would mean installable. `vmms.exe` and `vmconnect.exe` are not on disk.

No unsupported force-install was attempted. Documents: `HYPERV-VERIFICATION.md`, `HYPERV-ARCHITECTURE.md`, `HYPERV-THREAT-MODEL.md` - all design-only, all explicitly unmeasured.

The central question a Pro licence would let the project answer is stated in `HYPERV-ARCHITECTURE.md` §4 and remains open: **does `Set-VMNetworkAdapterExtendedPortAcl` enforce at the VM's switch port before NAT translation?** If it does, it is a genuinely different enforcement point from the Hyper-V Firewall that failed in Stage 2. If it does not, this backend fails on the same axis as WSL2.

---

## 6a. Stage 4 - Windows application isolation, without a VM

The machine had to stay on Windows 11 Home, so the fourth candidate abandoned virtualization entirely: Windows AppContainer as the OS-level boundary, Chromium's own sandbox beneath it, host-side firewall enforcement, encrypted DNS, and optional VPN. Documents: `STAGE-4-ARCHITECTURE.md`, `STAGE-4-THREAT-MODEL.md`, `STAGE-4-VERIFICATION.md`, `NETWORK-PRIVACY.md`.

**The primary mechanism failed at the first substantive gate.** A2 measured that neither Edge nor Chrome survives inside a project-created AppContainer - Chrome dies on a Crashpad `CreateNamedPipe: Access is denied`, Edge faults reproducibly at ~8 s - and **`--no-sandbox` changes neither**, so it is not a conflict with Chromium's own sandbox. A trivial control program runs fine in the same container.

Without an outer container, A4-A7 measured what remains: the Edge **browser process** is token-equivalent to an ordinary user process (same user SID, MEDIUM integrity, 0 restricting SIDs, 5 privileges), and can read every sensitive location, write a `HKCU\...\Run` persistence value, reach Credential Manager, and open `explorer.exe` with memory-read access. Chromium's sandbox contains **renderers** - measured as AppContainer tokens at UNTRUSTED integrity with **0 privileges** - but not the broker that builds it.

A16 then removed the last hope for the network layer. Program-scoped firewall rules **do** block the browser from the router and LAN (`REACHED → BLOCKED → REACHED`, `ERR_NETWORK_ACCESS_DENIED`), and A17 measured that the browser **cannot remove them** - genuinely valuable results. But rules explicitly naming `127.0.0.1` and the host's own IP did **not** block either, because loopback is exempt from firewall filtering. Stage 2.5's two-layer design had AppContainer covering exactly that gap, and A2 had already removed it. Host SMB, RPC, NetBIOS and a live PyCharm service were confirmed TCP-reachable from the browser - **Stage 2's G3/G8 failure reproduced, with no mitigation available.**

```
REVISE - APPLICATION ISOLATION INSUFFICIENT
```

Kept as genuine results: Chromium's renderer sandbox, LAN/router network isolation that survives browser compromise, and zero weakening of any host protection. **What is not achievable on this SKU is a boundary around the browser process.**

## 6b. Stage 5 - BRUHWSER, the implementation

Stage 4's `REVISE` verdict offered two paths: reduce the claimed scope to what was measured, or buy a Windows 11 Pro licence and return to a VM. **Path one was taken.** BRUHWSER is that product: a privacy and security control plane around Microsoft Edge, built only on mechanisms Stage 4 measured working.

It keeps what was proven and refuses to claim what was not:

| Kept, because it was measured | Refused, because it was measured |
|---|---|
| Chromium's renderer sandbox (A3) | any claim of VM-level isolation |
| Firewall rules blocking router and LAN (A16 PASS) | blocking localhost or this PC's own IP (A16 FAIL) |
| Those rules surviving browser compromise (A17 PASS) | containing the browser process (A2 FAIL) |
| Zero weakening of host protections (A34 PASS) | any DNS encryption claim (A18/A19 UNKNOWN) |

The `NOT ENFORCEABLE` state exists in the UI specifically so the loopback limitation is visible on the front page rather than buried - Stage 4's finding that host SMB, RPC and a live PyCharm service are reachable from the browser is a permanent, unfixable property of this architecture, and the product says so.

Base browser: **Microsoft Edge**, chosen on two measured grounds - its renderers hold a strictly stronger token than Chrome's on this machine (A3), and it is in-box and Microsoft-signed, so it adds no new supply-chain trust root, which is the criterion that rejected QEMU at B17. BRUHWSER adds **zero third-party dependencies** for the same reason.

Code lives in `bruhswer/`. Documentation: `BRUHWSER-SECURITY.md`, `PRIVACY.md`, `NETWORK-PRIVACY.md`, `bruhswer/README.md`.

## 7. What survives all three backends

Almost nothing transfers between backends - that is the point of re-verifying from scratch each time. These do, because they are properties of **Windows**, not of any hypervisor:

| Result | Gate | Status |
|---|---|---|
| AppContainer with `internetClient` only blocks loopback and the host's own LAN IP while internet still works | B7-pre | **PASS**, backend-independent |
| Windows Firewall outbound deny scoped by `-Program` blocks remote LAN while preserving internet | B16 | **PASS**, backend-independent |

Both were measured with `curl.exe` as a stand-in program, so they are properties of the Windows mechanisms themselves and do not depend on which hypervisor sits behind them.

**One further Stage 2 result carries forward, but as a hypothesis rather than a measurement - the distinction matters.** G3/G8 measured that *WSL2's* NAT source-NATs guest traffic to the host's own identity, defeating guest-scoped host-side filtering. That is a measured property of **WSL2**, not of Windows, and nothing about Hyper-V's Default Switch has been measured. It carries forward only as a **risk flag**: the Default Switch is documented to use the same NAT-based host connectivity mechanism, so H7 must be treated as at genuine risk of repeating the failure. Listing it beside the two PASSes above would blur measurement into inference.

Two design invariants also survive unchanged, having never depended on the backend: the controller exposes **no generic command execution primitive**, and every guest-derived string is treated as hostile input - host-generated filenames, opaque IDs instead of paths, fixed argv, no shell, no `eval`/`exec`.

## 8. Reading the document set

| Document | Backend | Read as |
|---|---|---|
| `SECURITY.md` | WSL2 | Entry point. §3 describes the **rejected** WSL2 architecture; §4 carries the measured failures. |
| `THREAT-MODEL.md`, `ARCHITECTURE.md`, `IMPLEMENTATION-PLAN.md` | WSL2 | Historical. Corrected in place after Stage 2 to mark what was disproven. |
| `STAGE-2-RESULTS.md` | WSL2 | **Evidence.** Still authoritative - the measurements are real. |
| `BACKEND-REDESIGN.md`, `BACKEND-THREAT-MODEL.md` | QEMU | Historical. |
| `BACKEND-VERIFICATION.md` | QEMU | **Evidence.** B7-pre and B16 remain authoritative; B1/B15/B17 are history. |
| `B17-QEMU-PROVENANCE.md` | QEMU | **Evidence.** The rejection rationale. |
| `HYPERV-*.md` | Hyper-V | **Design only, unmeasured.** Blocked at H1. |

## 9. Open items at the Stage 3 halt

1. **Windows 11 Pro licence** - the prerequisite for H2-H22. A purchase decision, with the §4 caveat above stated *before* the money is spent, not after.
2. **Rollback decision outstanding from Stage 2.5** - `HypervisorPlatform` remains **enabled with a reboot pending**, and QEMU 11.0.50 remains installed at `C:\Program Files\qemu`. Both were left in place awaiting a decision. **The QEMU binaries are rejected and must not be used regardless of their presence on disk.**
3. **No backend decision is recorded** under Stage 3 §37. Unknown security state is not a pass.
