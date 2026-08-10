# Hyper-V Architecture - design (UNVERIFIED)

**Date:** 2026-08-08 · **Status: DESIGN ONLY. Nothing here has been measured.**

`H1 = FAIL` - Hyper-V cannot be enabled on this machine (Windows 11 Home). This document exists so the backend can be evaluated *before* a licence is purchased, and so verification can start immediately if it is. Every claim is `[DOC]` or `[ASSUMPTION]` until an H-gate says otherwise.

The project's own operating principle applies with full force here: **a documented security mechanism is not necessarily an effective security boundary.** WSL2 taught that lesson expensively, and §4 of this document is where it bites hardest.

---

## 1. Trusted computing base (brief §5)

| Component | Classification |
|---|---|
| Windows kernel | **Trusted** |
| Hyper-V hypervisor (`hvix64`/`hvax64`) | **Trusted** - and already loaded on this machine (VBS 2, HVCI 1, `[MEASURED]`) |
| `vmms.exe` (VM Management Service, SYSTEM) | **Trusted, security-sensitive** - a control-plane bug here is a host compromise |
| `vmwp.exe` (per-VM worker, virtual account) | **Partially trusted** - parses guest-driven device I/O; runs under a per-VM restricted identity, so a device-model bug lands low-privilege |
| Virtual switch / VMSwitch extension stack (kernel) | **Trusted, security-sensitive** - sees guest packets in kernel mode |
| Integration Services / VMBus channels | **Security-sensitive interface** - the Hyper-V analogue of WSL interop |
| Host controller (this project) | **Trusted, must be minimal** |
| **Guest OS kernel** | **UNTRUSTED** - assumed fully compromised |
| **Chromium** | **UNTRUSTED** - its sandbox is defence in depth, never the boundary |

**The key structural argument for this backend, stated precisely:** the Microsoft hypervisor is *already* running on this machine and is *already* in its TCB. Enabling Hyper-V adds management components (`vmms.exe`, the switch stack) but introduces **no new supply-chain trust root**. Every QEMU route added one (B17). That is the specific, bounded advantage - it is a supply-chain property, **not** a claim that Hyper-V is architecturally safer.

---

## 2. Windows Sandbox vs dedicated Hyper-V VM (brief §6, §36)

| Requirement | Windows Sandbox | Dedicated Hyper-V VM |
|---|---|---|
| Disposable by construction | **Yes** - discarded on close | Yes, via checkpoint revert or disk recreation |
| Persistent private profile | **No** - cannot persist state by design | Yes, a second VM |
| Per-VM virtual-switch port ACLs | **No - see below** | **Yes** (`Set-VMNetworkAdapterExtendedPortAcl`) |
| Choice of virtual switch | No - tied to the Default Switch (NAT) | Yes - Private / Internal / External |
| Device surface control | Coarse (`.wsb` toggles) | Fine-grained per device |
| Guest OS choice | Windows only | Any; a minimal Linux is far smaller |
| Lifecycle automation | Launch a `.wsb` file | Full PowerShell/WMI control |
| Fail-closed verification | Weak - little inspectable state | Strong - VM config is queryable |

### The exact security property Windows Sandbox cannot provide (§36)

**Per-VM virtual switch port ACLs.** A Windows Sandbox instance is not surfaced through the Hyper-V VM management API - `Get-VM` does not return it - so `Set-VMNetworkAdapterExtendedPortAcl` **cannot be applied to it** `[DOC / ASSUMPTION]`. Its networking is fixed to the Default Switch NAT.

That leaves only two enforcement options for Sandbox, and Stage 2 already measured both as inadequate:

- **Guest-side firewall** - inside the compromised boundary. Rejected on principle, and gate H11 exists precisely to test removal resistance.
- **Hyper-V Firewall** (`New-NetFirewallHyperVRule`) - **measured FAIL** in Stage 2 G3/G8 for guest→host.

Combined with the inability to hold a persistent profile, this is a concrete, evidence-linked disqualification rather than "less flexible". **Provisional selection: dedicated Hyper-V VM**, to be confirmed by measurement, not asserted.

---

## 3. Intended VM configuration (brief §7, §17)

Generation 2, minimal. Every device needs a reason.

| Component | Purpose | Host interaction | Security impact | Required |
|---|---|---|---|---|
| 2-4 vCPU, 4 GB static RAM | run Chromium | scheduler | baseline | yes |
| Gen2 firmware + **Secure Boot ON in guest** | guest boot integrity | none | raises guest LPE cost | yes |
| VHDX on host disk | guest root fs | a **file**, not a share | storage device model | yes |
| Synthetic NIC | internet | vSwitch (kernel) | **the critical surface - §4** | yes |
| Video / keyboard / mouse via VMBus | display + input | basic session only | small | yes |
| **Dynamic memory** | | - | more host/guest interaction | **NO - static** |
| **Checkpoints** | | - | state persists on host disk unexpectedly | **NO for disposable** |
| **vTPM** | | - | adds a host-backed key surface | **NO initially** |
| **GPU-P / RemoteFX** | | - | **host GPU kernel driver - this is what failed WSL2 G1** | **FORBIDDEN** |
| **Guest Service Interface** | | host↔guest file copy (`Copy-VMFile`) | **the Hyper-V analogue of WSL interop / QEMU guest agent** | **FORBIDDEN** |
| Other Integration Services (heartbeat, shutdown, time sync, KVP, VSS) | | VMBus channels to `vmms` | each is a host-facing channel | **disable all not proven necessary** |
| **DVD drive** | install only | ISO file | removable after install | remove post-install |
| COM ports, floppy | | - | | **NO** |

**GPU (brief §8):** software rendering only. Chromium runs with GPU acceleration disabled. If hardware acceleration is ever wanted it gets its own gate (H16) and its own explicit decision - it must not creep in for performance.

---

## 4. Network design - the gate that decides this backend

**This is where WSL2 died, and there is specific reason to think the failure could repeat.**

Stage 2 measured that WSL2 guest→host traffic is **source-NAT'd to the host's own LAN IP**, so guest-scoped Hyper-V Firewall rules never matched it and the guest reached host SMB/RPC. Windows Sandbox and Hyper-V's **Default Switch** use the same NAT-based host connectivity mechanism `[DOC]`. **It must therefore be assumed, until measured, that the Default Switch reproduces the WSL2 G3 failure.** Gate H7 is not a formality.

### Switch options

| Switch | Guest→internet | Host on the switch? | Assessment |
|---|---|---|---|
| **Default Switch** (NAT) | yes | **yes** | **Presumed to repeat WSL2 G3.** Not usable without proof. |
| **Internal + host NAT** | via host NAT | **yes** | Same structural risk - the host is a participant. |
| **Private** | **no** | no | Strongest isolation, but no internet - unusable alone. |
| **External**, `-AllowManagementOS $false` | yes, directly | **no** - the host has no vNIC on this switch | Guest is on the physical LAN (violates H8 by default) **but the host is not a participant**, so guest→host must traverse the physical network and is filterable as an ordinary LAN peer. |

### The central hypothesis to test

**`Set-VMNetworkAdapterExtendedPortAcl` enforces in the virtual switch, at the VM's port, before any NAT translation** `[DOC / ASSUMPTION]`. That is a *different enforcement point* from the Hyper-V Firewall that failed in Stage 2 - which is why this backend deserves evaluation rather than dismissal on the WSL2 precedent.

Provisional design, entirely unverified:

```
External switch, AllowManagementOS = $false     (host not on the switch)
  + extended port ACLs on the VM's adapter:
        DENY  outbound -> 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
        DENY  outbound -> host LAN IP
        DENY  outbound -> IPv6 ULA fc00::/7, link-local fe80::/10
        ALLOW outbound -> everything else, TCP 80/443, UDP 443
  + guest nftables as DEFENCE IN DEPTH ONLY (H11 tests its removal)
```

If extended port ACLs do not hold - including after the guest's own firewall is deliberately removed (H11) - **this backend fails on the same axis as WSL2** and the honest outcome is `WINDOWS HYPERVISOR BACKENDS UNSUITABLE`. That possibility must be stated before a licence is purchased, not after.

---

## 5. Display (brief §9)

**Basic session via VMConnect**, not Enhanced Session Mode.

- **Basic session:** video, keyboard and mouse over VMBus. No clipboard, no drive redirection, no printers, no USB, no audio capture, no smart cards.
- **Enhanced Session Mode:** an RDP channel into the guest, which is exactly the redirection surface §9 wants closed. It can be disabled host-wide (`Set-VMHost -EnableEnhancedSessionMode $false`) and per-VM `[DOC]`.

Design default: **ESM disabled and verified disabled** (H17). Cost: no clipboard integration and no host↔guest file transfer - both of which are requirements, not regressions.

---

## 6. Control plane (brief §14, §15, §16)

Host-initiated only:

```
HOST ──(Hyper-V PowerShell/WMI, fixed argv)──► GUEST      allowed, narrow
GUEST ─────────────────────X───────────────► HOST        blocked
```

Verbs stay closed and fixed: `START_SESSION`, `STOP_SESSION`, `VERIFY_SESSION`, `GET_STATUS`, `RESET_DISPOSABLE_SESSION`. No `execute_command`, no shell, no Hyper-V parameter ever derived from guest content, a URL, a filename, or a download.

**Open question for H4/H20:** Hyper-V management normally requires membership in the **Hyper-V Administrators** group. That is not local Administrator, so an unelevated runtime may be achievable - but the group is itself powerful (VM management implies broad host influence). Whether the runtime controller can operate with it, and whether granting it is acceptable, is an unresolved design question, not a solved one.

**Guest Service Interface must stay disabled.** It provides host→guest file injection via `Copy-VMFile`; a bug or misuse there is a direct control-plane crossing. Same category as WSL's interop socket and QEMU's guest agent, both of which this project already forbids.

---

## 7. Disposable lifecycle (brief §21)

```
create VM from a pinned base VHDX (differencing or fresh copy)
   -> VERIFY configuration: no shares, no GSI, ESM off, ACLs present, no GPU
   -> start VM
   -> VERIFY security controls actually active (measured, not assumed)
   -> start Chromium
   -> browse
   -> stop VM
   -> DELETE the VM and its differencing disk
   -> VERIFY destruction
```

No state reuse between disposable sessions. No automatic host copy. No automatic execution. Persistent mode is **not** designed yet - brief §22 requires disposable to be proven first.

**Mode separation (§23):** separate VMs mean independent kernels and independent virtual hardware, which *should* make the WSL-era MX-1 mutual-exclusion invariant unnecessary. That is a property to **prove at H19**, not to assume. MX-1 stays in force until then.

---

## 8. Fail-closed (brief §31)

The browser does not launch unless the controller positively verifies, from the host side: no shared folders or mapped drives; Guest Service Interface disabled; Enhanced Session Mode disabled; expected port ACLs present; no GPU adapter; the VM is the expected VM; the controller's own privilege state is as expected. Any check that cannot be performed reads *unknown*, and unknown refuses the launch.

---

## 9. Honest pre-purchase summary

**What a Pro licence would buy:** an isolation backend whose trust root is already in this machine's TCB, a per-VM enforcement point (`extended port ACLs`) that WSL2 structurally lacked, fine-grained device control, a genuinely disposable VM lifecycle, and a persistent-mode path.

**What it does not buy, and must not be assumed:** that the network boundary works. Windows Sandbox is provisionally disqualified on a specific property (no per-VM port ACLs, no persistence), and the dedicated-VM design rests on an **unverified hypothesis** about where extended port ACLs are enforced. If that hypothesis fails, Hyper-V fails on the same axis as WSL2.

Two Windows-level results already measured (`AppContainer` loopback blocking, program-scoped firewall rules) carry forward and are backend-independent.

**No decision under brief §37 is recorded.** The gates that would justify one cannot be run.
