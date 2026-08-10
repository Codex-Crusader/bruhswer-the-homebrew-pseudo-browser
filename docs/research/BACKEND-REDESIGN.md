# Backend Redesign - after the WSL2 rejection

**Date:** 2026-08-08 · **Stage:** 2.5 · **Status:** candidate selected, verification incomplete (consent pending)

Confidence markers `[MEASURED]` / `[DOC]` / `[ASSUMPTION]` as defined in `THREAT-MODEL.md`.

---

## 1. Why WSL2 was rejected

Required statement, per the Stage 2.5 brief §30:

> **WSL2 was empirically evaluated and rejected as the primary isolation backend for the current security target because `/dev/dxg` remained reachable and the intended host-side network boundary could not be established.**

This is not a revision of history. The Stage 1 architecture genuinely selected WSL2, Stage 2 genuinely tested it, and Stage 2 genuinely disproved two of its load-bearing claims. `STAGE-2-RESULTS.md` is preserved unmodified as the evidence.

### G1 - `/dev/dxg` `[MEASURED]`

`[wsl2] guiApplications=false` disables WSLg but does **not** remove the GPU paravirtualisation device. The node persisted, world read/write, and was **opened read-write by an unprivileged guest process** - the privilege level at which the browser runs. A compromised renderer therefore retained a direct ioctl path to the host's `dxgkrnl` kernel driver.

### G3 / G8 - host-side network boundary `[MEASURED]`

With `DefaultOutboundAction=Block`, `LoopbackEnabled=False`, `AllowHostPolicyMerge=False`, and explicit deny rules covering `10.0.0.0/8`, the guest still completed TCP connections to host services on **445** and **135**.

Root cause, determined rather than assumed: guest→host traffic is source-NAT'd to the **host's own LAN IP** before it reaches the host TCP stack, so guest-scoped Hyper-V Firewall rules never match. Confirmed by observing an ESTABLISHED connection on host PID 4 with `RemoteAddress` equal to the host's own address.

**Deliberately not claimed:** a usable SMB session, authentication, NTLM relay, or exploitation. Only a completed TCP connection was demonstrated. The conclusion that matters is narrower and sufficient: *the intended host-side network isolation boundary is not established.*

### What WSL2 did deliver

Recorded so the rejection is not read as "WSL2 is useless": host **user data** filesystem isolation (G7), the host→guest / guest→host execution asymmetry (G2), egress port allowlisting, and remote-LAN/router blocking. The rejection is specific to the two failures above.

---

## 2. Alternatives considered

| Option | Available here | Fixes G1? | Fixes G3? | Cost / objection |
|---|---|---|---|---|
| **WSL2 (hardened)** | yes | **No** `[MEASURED]` | **No** `[MEASURED]` | Rejected. |
| Patch around WSL2 (guest nftables, disable host SMB/RPC) | yes | no | no | **Forbidden by brief §1.** A control inside a compromised guest is not a boundary; reconfiguring the host to compensate for weak guest isolation is not a substitute. |
| **QEMU + WHPX** | needs 2 host changes | **Yes, structurally** | **Plausibly - see §4** | Third-party binaries; WHP feature enable + reboot. **Selected candidate.** |
| Windows Hypervisor Platform used directly | n/a | | - | WHP is an API, not a VMM. Using it directly means writing a hypervisor - forbidden by the original brief §4. |
| **Windows Sandbox** | **No** `[MEASURED]` | yes | yes (per-VM ACLs) | Requires Windows 11 Pro. `Containers-DisposableClientVM` does not appear in the feature enumeration on this SKU. |
| **Hyper-V** | **No** `[MEASURED]` | yes | yes | Requires Windows 11 Pro. `Microsoft-Hyper-V` absent from feature enumeration. |
| VirtualBox / VMware / Docker Desktop | installable | yes | ? | **Excluded by brief §4.** Kernel drivers, large stacks, worse escape record. |

**Honest note, repeated rather than buried:** the two strongest options are behind a Windows 11 Pro licence, not behind engineering effort. Stage 1's matrix ranked them highest; Stage 2 removed the free option that was chosen instead. That remains the single cleanest resolution.

---

## 3. Why QEMU + WHPX is the candidate

**G1 is solved structurally, not incidentally.** With an emulated display adapter (`-vga std` or virtio-gpu) and no passthrough, the guest's graphics device is implemented **inside the QEMU user-mode process**. There is no host kernel graphics driver, no ioctl path, and no `dxgkrnl` equivalent exposed to the guest. Recorded explicitly so nobody later re-enables GPU acceleration and silently reopens the surface: **adding host GPU passthrough or paravirtualisation would reintroduce exactly the surface that failed G1.**

**G3 is addressable because traffic becomes attributable.** QEMU without kernel drivers uses SLIRP user-mode networking: guest packets are translated by libslirp *inside the QEMU process* into ordinary Windows sockets. Unlike WSL - where the kernel SNAT'd guest traffic to the host's identity and destroyed attribution - every guest connection is now issued by a specific host process, which Windows can filter by program **and** by AppContainer package SID `[MEASURED]`.

---

## 4. The network design, and the evidence behind it

Windows offers two enforcement mechanisms, and **each covers the other's gap**. Neither alone is sufficient.

| Mechanism | Blocks | Does NOT block | Evidence |
|---|---|---|---|
| **AppContainer**, `internetClient` capability only | loopback `127.0.0.1`; the **host's own LAN IP** | remote LAN peers | `[MEASURED]` - see below |
| **Windows Firewall**, outbound deny scoped by `-Program` / `-Package` | remote LAN peers, RFC1918 ranges | **loopback - Windows Firewall does not filter loopback** `[DOC]` | `-Program` and `-Package` parameters confirmed present `[MEASURED]`; rule efficacy **not yet tested** `[ASSUMPTION]` |

### Measured AppContainer behaviour (`tools/stage25/appcontainer_netisolation_test.py`)

Tested with System32 `curl.exe`, deliberately **not** with QEMU, so the AppContainer property is isolated from QEMU's own behaviour. A control run in an ordinary process proves every target is genuinely reachable.

```
=== CONTROL: no AppContainer (ordinary process) ===
  loopback  127.0.0.1          REACHABLE   HTTP_200
  host-own-ip 10.0.0.50     REACHABLE   HTTP_200
  REMOTE LAN router 10.0.0.1 REACHABLE   HTTP_302
  internet  1.1.1.1            REACHABLE   HTTP_301

=== APPCONTAINER: internetClient ONLY (proposed design) ===
  loopback  127.0.0.1          BLOCKED (curl exit 28)
  host-own-ip 10.0.0.50     BLOCKED (curl exit 28)
  REMOTE LAN router 10.0.0.1 REACHABLE   HTTP_302     <-- gap
  internet  1.1.1.1            REACHABLE   HTTP_301
```

**This is the single most important result of Stage 2.5 so far.** The exact failure mode that killed WSL2 - a guest reaching the host at the host's own LAN IP - is **structurally blocked** by AppContainer, and blocked by a mechanism Windows Firewall cannot provide, because loopback is exempt from firewall filtering.

**And the honest limitation.** Adding `privateNetworkClientServer` changed nothing, and the remote LAN router remained reachable in **both** capability sets. Root cause `[MEASURED]`: this network's `NetworkCategory` is **`Public`**. Windows treats a Public network as "the internet", so `internetClient` covers the local subnet and the private-network capability is never consulted.

**Consequence - a control that depends on network category is not a control.** If this machine joins a network Windows classifies as Private, AppContainer's behaviour toward LAN peers would change. The design therefore must **not** rely on AppContainer for LAN blocking. LAN blocking must come from firewall rules scoped to the program/package, which are category-independent.

---

## 5. Security tradeoffs of QEMU + WHPX vs WSL2

**Better:**
- No `/dev/dxg` or any host kernel graphics path.
- Guest traffic is attributable to a filterable host process - the property WSL destroyed.
- Device models run in a **user-mode** host process that can itself be confined (AppContainer, job object, low integrity), so a device-emulation bug lands in a sandboxed process rather than in `wslservice.exe` (LocalSystem).
- Per-session VMs with independent kernels - likely removes the need for MX-1 (to be proven, §19).
- No interop socket, no plan9 driver mount, no guest agent.

**Worse:**
- **Supply chain.** See §6. WSL2 is Microsoft-signed and shipped with Windows; QEMU is not.
- **Larger emulated device surface.** libslirp and QEMU's device models have a substantial CVE history. Mitigated by minimising devices and confining the process, not eliminated.
- Requires enabling a Windows feature and a reboot.
- Software rendering only; no hardware video decode. Accepted deliberately - brief §8 is explicit that security outranks graphics performance.

---

## 6. Supply chain - stated plainly `[MEASURED]`

```
winget id      : SoftwareFreedomConservancy.QEMU
Version        : 11.0.50
Publisher label: "QEMU Community"
Homepage       : https://qemu.weilnetz.de/
Installer URL  : https://qemu.weilnetz.de/w64/2026/qemu-w64-setup-20260501.exe
Installer type : nullsoft (NSIS)
SHA256         : a8b29572afb4c6ad024b7de129c81033e9fd191b9e054e3a52ea0bed24ac19ef
```

The package name and publisher label suggest official Software Freedom Conservancy provenance. **They are misleading.** The homepage and installer URL both point at `qemu.weilnetz.de`, a **third-party build host**, not QEMU project CI and not Microsoft-signed. The QEMU project links to these builds as the de-facto Windows binaries, so this is the normal channel - but it is not first-party.

winget verifies the manifest SHA256, which protects against tampering **in transit only**. It does not protect against a compromised build host, and the manifest itself is community-maintained.

**Residual supply-chain risk: accepted only if the user accepts it explicitly.** Mitigations available: pin version 11.0.50 and its hash, record both in the SBOM, verify the Authenticode signature of the installed binaries after install, and never auto-update.

---

## 7. Invariants locked in now

1. **No guest agent.** This is the QEMU-shaped equivalent of WSL's interop socket. Stated as an invariant, not a preference.
2. **No shared folders** - no 9p, no virtiofs, no SMB, no mapped drives. Zero host filesystem exposure.
3. **No clipboard channel** by default.
4. **No GPU passthrough or host GPU paravirtualisation.** Reintroducing it reopens G1.
5. **No USB, audio, smart-card, serial, or camera device** unless individually justified.
6. **MX-1 stays in force** until spatial isolation is *proven*, per brief §19 - not dropped for convenience.
7. **Fail closed.** Any unverifiable isolation property refuses the launch.

---

## 8. Remaining risks

1. Hypervisor / WHPX escape. Unmitigated, as before.
2. QEMU device-model and libslirp vulnerabilities - reduced by device minimisation and process confinement, not removed.
3. Supply chain (§6) - the largest new risk relative to WSL2.
4. Firewall rule efficacy for remote-LAN blocking is **unverified** `[ASSUMPTION]`.
5. Whether QEMU can actually run inside an AppContainer with the required file ACLs is **unverified** `[ASSUMPTION]` - if impractical, the loopback protection above is not available and the backend must be re-scored.
6. Everything downstream of B2 is untested pending consent.

**No decision under brief §33 is recorded yet.** Recording one now would violate §34: the backend is not approved because it is QEMU; it is approved only if measurement says so.
