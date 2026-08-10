# Backend Threat Model - QEMU + WHPX candidate

**Date:** 2026-08-08 · **Status:** design; most properties unverified pending B2-B16.

This is a **new** threat model for a **new** backend, not an edit of the WSL2 one. `THREAT-MODEL.md` remains the WSL2 record and is preserved as historical evidence.

---

## 1. Assets

Unchanged from `THREAT-MODEL.md` §1: host code execution; host credentials (Credential Manager, DPAPI, `.ssh`, `.aws`, `.azure`, `.gitconfig`, host browser profiles, password managers, wallets); host filesystem including **this project's repository, `.git`, `.venv` and PyCharm configuration**; LAN reachability; sensors; browsing linkage; integrity of the controller itself.

---

## 2. Attackers

Unchanged: T1 trackers, T2 malicious sites, **T3 browser exploit chain (assumed to succeed)**, **T4 full guest root (assumed to succeed)**, T5 escape from the VM, T6 supply chain, T7 extensions, T8 the socially-engineered user.

T6 is materially **larger** than under WSL2 because the VMM is now third-party (`BACKEND-REDESIGN.md` §6).

The assumption chain the design must survive:

```
browser compromised → guest OS compromised → attacker is root in the guest
```

and the attacker must still cross a hypervisor/device/network boundary to affect Windows.

---

## 3. Trust boundaries

```
                         INTERNET   (fully attacker-controlled)
                             │
              ═══ TB-0 ══════╪══════  Chromium renderer sandbox + Site Isolation
                             │        DEFENCE IN DEPTH ONLY - assumed breached (T3)
                             ▼
                     Guest OS / kernel
              ═══ TB-1 ══════╪══════  Linux user separation, seccomp
                             │        DEFENCE IN DEPTH ONLY - assumed breached (T4)
                             ▼
   ══════════════ UNTRUSTED ZONE ENDS ══════════════
                             │
   ╔═════════ TB-2 ══════════╪═══════════════════════════════════════════╗
   ║  PRIMARY BOUNDARY: Microsoft hypervisor via WHPX                     ║
   ║  + QEMU virtual device models (USER-MODE host process)                ║
   ╚═════════════════════════╪═══════════════════════════════════════════╝
                             ▼
              ┌──────── QEMU process ────────┐
              │  CONFINED, not trusted:      │   ══ TB-3 ══ network
              │  AppContainer (internetClient│   AppContainer blocks loopback +
              │  only) + job object          │   host-own-IP; firewall -Program/
              │  A device-model bug lands    │   -Package blocks remote LAN.
              │  HERE, not in LocalSystem    │   BOTH host-side. BOTH required.
              └──────────────┬───────────────┘
                             │  ══ TB-4 ══ filesystem: ZERO sharing
                             │  ══ TB-5 ══ privilege: unelevated runtime
                             ▼
                      WINDOWS HOST (trusted)
```

**Key structural improvement over WSL2:** the device models and the SLIRP network stack run in a **user-mode process that we confine**. Under WSL2 the equivalent control plane was `wslservice.exe` running as **LocalSystem**. A device-emulation bug now lands in an AppContainer-confined process rather than at SYSTEM.

**Chromium's sandbox is not the primary boundary. The guest kernel is not trusted.**

---

## 4. Virtual hardware policy

Per brief §7, every device needs a documented reason. The **inventory below is the plan, not a measurement** - QEMU instantiates defaults that must be enumerated at gate **B4** before this table can be called accurate.

Policy: start from `-nodefaults` and add only what is justified.

| Device | Purpose | Host integration | Attack surface | Removable? | Retained because |
|---|---|---|---|---|---|
| CPU (WHPX) | execution | hypervisor | WHPX / hypervisor escape | no | required |
| RAM | | none | | no | required |
| virtio-blk (disk) | guest root fs | a **file** on host, no directory sharing | virtio-blk emulation | no | required |
| virtio-net + SLIRP | internet | sockets from QEMU process | libslirp (notable CVE history) | no | required; the attributability it gives is the point |
| Display adapter (emulated, `-vga std` / virtio-gpu) | pixels | none - **no host GPU path** | in-process framebuffer | no | required; **must never become passthrough** |
| Input (kbd/mouse) | user input | none | small | no | required |
| RTC | clock | none | small | maybe | evaluate at B4 |
| **GPU passthrough / paravirt** | | - | **host kernel driver** | **YES** | **FORBIDDEN - this is what failed G1** |
| **9p / virtiofs shared fs** | | - | host filesystem | **YES** | **FORBIDDEN - brief §13** |
| **USB / audio / camera / smartcard / serial** | | - | various | **YES** | **FORBIDDEN unless individually justified** |
| **QEMU Guest Agent** | | - | host control channel | **YES** | **FORBIDDEN - the QEMU-shaped equivalent of WSL's interop socket** |
| **QMP/HMP monitor exposed to guest** | | - | full VM control | **YES** | **FORBIDDEN - host-side only, never guest-reachable** |

---

## 5. Network paths

Goal:

```
Guest → Internet    ALLOWED (80/443/QUIC)
Guest → Host        BLOCKED      Guest → LAN/Router/NAS  BLOCKED
Guest → localhost   BLOCKED      Guest → Dev services    BLOCKED
Host  → Guest       MINIMAL / CONTROLLED
```

Enforcement, with measured status:

| Path | Mechanism | Status |
|---|---|---|
| Guest → host loopback / host-own-IP | AppContainer, `internetClient` only | **PASS** `[MEASURED]` B7-pre |
| Guest → remote LAN / RFC1918 | Windows Firewall outbound deny, `-Program` / `-Package` | **UNTESTED** `[ASSUMPTION]` gate B16 |
| Guest → internet | AppContainer `internetClient` + firewall allow | **PASS** for the container `[MEASURED]`; end-to-end untested |
| IPv6 | to be disabled in guest **and** matching deny rules | **UNKNOWN** gate B9 |
| DNS | design pending; no claim made | **UNKNOWN** |
| Host → guest | no inbound listener planned; control is host-initiated only | **UNKNOWN** gate B11 |

**AppContainer is explicitly NOT trusted for LAN blocking** - B7-pre showed that property depends on Windows' network category, which was `Public` here. That dependency disqualifies it as a control.

---

## 6. Host integration surface

The design target is **none**. Enumerated so each absence is deliberate:

| Channel | Decision |
|---|---|
| Shared folders (9p/virtiofs/SMB/mapped drives) | **none** |
| Clipboard | **off**, no channel created |
| Guest agent | **none** |
| QMP / HMP monitor | host-side only, never reachable from the guest |
| USB / audio / camera / mic / smartcard / serial | **none** |
| GPU | **none** |
| File transfer | later, host-pull by opaque ID only; guest never names a host path |

**Control plane:** host-initiated only. No guest-initiated channel, no host listening socket the guest can reach. Verbs are fixed and closed: `START_SESSION`, `STOP_SESSION`, `VERIFY_SESSION`, `GET_STATUS`, `RESET_DISPOSABLE_SESSION`, `EXPORT_FILE`. There is no generic command execution primitive, and no QEMU command-line parameter is ever derived from guest or web content.

---

## 7. Guest → host attack surface inventory

| # | Surface | Disposition |
|---|---|---|
| Q1 | Microsoft hypervisor via WHPX | **Residual, unmitigated** |
| Q2 | QEMU device models (virtio-blk, virtio-net, display, input) | **Residual, reduced** - user-mode and AppContainer-confined |
| Q3 | libslirp user-mode TCP/IP stack | **Residual** - significant CVE history; confined to the QEMU process |
| Q4 | Network reach to host/LAN | **Partly controlled** - see §5; one layer measured, one untested |
| Q5 | Host GPU kernel driver | **ELIMINATED by construction** - no GPU device exposed. Re-adding passthrough reopens G1 |
| Q6 | Host filesystem | **ELIMINATED by construction** - no sharing device; the disk is a plain host file |
| Q7 | Guest agent / interop channel | **ELIMINATED by construction** - none exists |
| Q8 | QMP/HMP monitor | **Not guest-reachable by construction** |
| Q9 | Display protocol | **UNKNOWN** - deferred until after B7, deliberately (same reasoning that deferred G5) |

Compare Q5-Q8 with the WSL2 equivalents S3, S4, S6, S7, all of which were residual or failed. The improvement is structural: those surfaces do not exist here rather than being configured off.

---

## 8. Host → guest threats

The controller must treat the guest as hostile input: malformed or oversized responses, path traversal attempts, command/argument injection, resource exhaustion. Mitigations carried over unchanged - fixed argv, no shell, size caps, timeouts, strict schemas, host-generated filenames, validated identifiers, and no dynamic code execution anywhere.

---

## 9. Mode separation

Per brief §19, MX-1 is **not** carried over blindly and **not** dropped. Separate per-session VMs *should* give genuine spatial isolation - independent kernels, independent virtual hardware, no shared disk - which is exactly what WSL2 could not provide (G6 measured one shared kernel).

**MX-1 remains in force until gate B14 proves the separation.** Convenience is not a reason to remove it.

---

## 10. Residual risks

1. Hypervisor / WHPX escape - unmitigated.
2. QEMU device-model and libslirp vulnerabilities - reduced by minimisation and confinement, not removed.
3. **Supply chain** - third-party QEMU builds; the largest new risk versus WSL2.
4. Firewall efficacy for remote LAN - unverified.
5. Whether QEMU runs at all under AppContainer - unverified; if it does not, the loopback protection is unavailable.
6. Display path - undesigned, undetermined.
7. IPv6, DNS - undetermined; no claim made.
8. Isolation is still not anonymity: public IP, account identity, and voluntary credentials are unchanged by any of this.
