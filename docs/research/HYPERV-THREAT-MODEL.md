# Hyper-V Threat Model - design (UNVERIFIED)

**Date:** 2026-08-08 · **Status: DESIGN ONLY.** `H1 = FAIL`; no mitigation below has been measured on this backend.

A new threat model for a new backend. `THREAT-MODEL.md` (WSL2) and `BACKEND-THREAT-MODEL.md` (QEMU) are preserved unchanged as historical evidence - see `docs/PROJECT-HISTORY.md`.

---

## 1. Assets

Unchanged across all backends: host code execution; host credentials (Credential Manager, DPAPI, `.ssh`, `.aws`, `.azure`, `.gitconfig`, host browser profiles, password managers, wallets); host filesystem **including this project's repository, `.git`, `.venv` and PyCharm configuration**; LAN/router/NAS reachability; camera, microphone, location; browsing linkage; integrity of the controller and its update path.

## 2. Attackers

Unchanged: T1 trackers · T2 malicious sites · **T3 browser exploit chain (assumed to succeed)** · **T4 full guest root (assumed to succeed)** · T5 VM escape · T6 supply chain · T7 extensions · T8 socially-engineered user.

T6 is **materially smaller** here than for QEMU: the virtualization stack ships with Windows and is serviced by Windows Update. It does not vanish - the guest OS, Chromium packages, and controller dependencies remain third-party.

The assumption chain the design must survive:

```
browser compromised -> guest OS compromised -> attacker is root in the guest
```

and the attacker must still fail to reach the host, its files, its credentials, its services, the LAN, or persistence.

## 3. Trust boundaries

```
                    INTERNET  (attacker-controlled)
                        │
        ═══ TB-0 ═══════╪══  Chromium sandbox + Site Isolation
                        │     DEFENCE IN DEPTH ONLY - assumed breached (T3)
                        ▼
                  Guest OS kernel
        ═══ TB-1 ═══════╪══  Linux user separation, seccomp
                        │     DEFENCE IN DEPTH ONLY - assumed breached (T4)
                        ▼
   ═══════════ UNTRUSTED ZONE ENDS ═══════════
                        │
   ╔═══════ TB-2 ═══════╪═══════════════════════════════════════╗
   ║ PRIMARY BOUNDARY: Hyper-V hypervisor + synthetic devices    ║
   ║ device I/O parsed in vmwp.exe (per-VM restricted identity)  ║
   ╚════════════════════╪═══════════════════════════════════════╝
                        │
     ══ TB-3 ══ network │  vSwitch extended port ACLs (UNVERIFIED - §4)
     ══ TB-4 ══ filesys │  ZERO shares; VHDX is a host file, not a mount
     ══ TB-5 ══ control │  host-initiated only; GSI disabled; ESM disabled
                        ▼
                 WINDOWS HOST (trusted)
```

## 4. Guest → host attack surface

| # | Surface | Disposition |
|---|---|---|
| V1 | Hyper-V hypervisor | **Residual, unmitigated.** Escapes exist historically. No project-level mitigation. |
| V2 | Synthetic device models in `vmwp.exe` (net, storage, video, input) | **Residual, reduced.** Runs under a per-VM virtual account, not SYSTEM, so a device bug lands low-privilege. Reduced further by removing devices. |
| V3 | `vmms.exe` (SYSTEM) VM management service | **Residual, security-sensitive.** The Hyper-V analogue of WSL's `wslservice.exe`. Reachable only via VMBus control channels; minimised by disabling Integration Services. |
| V4 | **Guest Service Interface** (`Copy-VMFile` host→guest injection) | **ELIMINATED by configuration.** Same category as WSL interop and QEMU guest agent. Must be verified off (H14). |
| V5 | Other Integration Services (KVP, VSS, time sync, shutdown, heartbeat) | **Reduced** - disable all not proven necessary; each is a VMBus channel to `vmms`. |
| V6 | Enhanced Session Mode / RDP redirection | **ELIMINATED by configuration.** Basic session only; verified at H17. |
| V7 | **Virtual switch and NAT path** | **THE CRITICAL UNKNOWN.** WSL2's NAT SNAT'd guest traffic to the host's identity (G3 FAIL). Default Switch presumed to behave the same. See `HYPERV-ARCHITECTURE.md` §4. Gates H7/H12. |
| V8 | Host GPU driver | **ELIMINATED by construction** - no GPU-P, no RemoteFX. Re-adding it recreates the WSL2 G1 failure. |
| V9 | Host filesystem | **ELIMINATED by construction** - no shares, no mapped drives; the VHDX is a plain host file the guest never names. |
| V10 | vTPM / host key material | **Not enabled initially.** |
| V11 | Checkpoints / saved state written to host disk | **Disabled for disposable VMs** - otherwise guest state persists on the host unexpectedly. |

Compare with WSL2, where S3 (`/dev/dxg`) and S8 (network) were measured failures and S4/S6 remained reachable: V4, V6, V8, V9 are absent **by construction** here rather than configured off. V7 is the one that must be proven.

## 5. Guest → network

Policy: internet allowed on 80/443/QUIC; host, LAN, router, NAS, localhost and development services all blocked; IPv6 must not bypass.

Enforcement intent is **vSwitch extended port ACLs**, applied at the VM's switch port, host-side, outside the guest - with guest `nftables` as defence in depth only. **H11 deliberately removes the guest firewall** to confirm the host-side layer alone holds. If it does not, the boundary is not established, exactly as in Stage 2.

DNS remains undesigned; no DNS or anonymity claim is made.

## 6. Host → guest (controller treats the guest as hostile)

Malformed, oversized or adversarial guest output; path traversal in any guest-supplied string; command and argument injection; resource exhaustion. Mitigations carried forward unchanged: fixed argv, no shell, no `eval`/`exec`, hard size caps, timeouts, strict schemas, host-generated filenames, validated identifiers, opaque IDs instead of paths.

## 7. Controller

Risks: privilege escalation via the management interface; command or path injection; trusting malformed VM state; unsafe subprocess use.

Mitigations: unelevated at runtime; closed verb set; setup separated from runtime; no generic execution primitive; fail-closed on any unverifiable property. **Open question (H4/H20):** whether Hyper-V management is workable from a non-elevated account via the *Hyper-V Administrators* group, and whether granting that group is acceptable - it is powerful, and this is unresolved.

## 8. Supply chain

| Element | Trust root | Note |
|---|---|---|
| Hypervisor, `vmms`, vSwitch | **Microsoft, via Windows Update** | Already in this machine's TCB - the specific advantage over QEMU (B17) |
| Guest OS | distribution's signing keys | must be a maintained release with real security updates |
| Chromium in guest | distribution or vendor repo | pinned, documented |
| Controller dependencies | pinned, hashed, SBOM | unchanged policy |
| Configuration files | local, integrity-checked | fail closed on mismatch |

## 9. Residual risks

1. **Hypervisor escape (V1)** - unmitigated.
2. **`vmms.exe` control-plane vulnerability (V3)** - SYSTEM impact; reduced surface, not removed.
3. **The network boundary is unproven (V7)** - and has a specific, measured precedent for failing on this exact axis.
4. Guest OS and Chromium vulnerabilities and their patch cadence.
5. Social engineering and user-initiated export (T8) - unchanged by any backend.
6. **Isolation is not anonymity.** Public IP, account identity, voluntary disclosure and fingerprinting are unaffected by Hyper-V. No such claim is made.
7. Everything in this document is **design, not measurement.**
