# Stage 4 Threat Model - Windows application isolation backend

**Date:** 2026-08-09 · **Status:** grounded in the A-gate measurements in `STAGE-4-VERIFICATION.md`. Where a mitigation is claimed, the gate that measured it is named. Where none exists, that is stated.

**This is not a VM.** OS-level application isolation is a **weaker boundary** than a correctly configured hardware-virtualized VM, and Stage 4 measured exactly how much weaker. Nothing in this document should be read as equivalence.

---

## 1. Assets

Unchanged across every backend this project has evaluated: host code execution; host credentials (Credential Manager, DPAPI, `.ssh`, git credentials, API keys, password managers, wallets); host filesystem including this project's repository; LAN, router and NAS reachability; camera, microphone, location; browsing activity; the integrity of the controller and its update path.

## 2. Attackers, and what the evidence says about each

| # | Attacker | Contained? |
|---|---|---|
| **W1** | Malicious website (script, ads, drive-by) | **Yes, by Chromium's renderer sandbox.** A3 measured Edge renderers as AppContainer tokens at UNTRUSTED integrity, 1 restricting SID, **0 privileges**, 0 capabilities. This is a real boundary and it is Chromium's, not ours. |
| **W2** | Renderer exploit (escape from web content into the renderer process) | **Contained, same mechanism.** The renderer still holds the token above. Escaping *the renderer sandbox* is a further step. |
| **W3** | **Compromised browser process (broker)** | **NOT CONTAINED.** A4 Part 1 measured the Edge browser process as token-equivalent to an ordinary user process: MEDIUM integrity, non-AppContainer, 0 restricting SIDs, 5 privileges, same user SID. A2 measured that it cannot be wrapped in an AppContainer. **This is the defining weakness of the backend.** |
| **W4** | Local network observer (university/public Wi-Fi operator) | **Partially reduced.** HTTPS protects content. DNS is `UNKNOWN` (A18). Destination IPs, timing and volume remain visible - always. |
| **W5** | Malicious device on the same LAN | **Not adequately mitigated.** A20/A21 found SMB, NetBIOS and RPC listening on the wildcard address with File and Printer Sharing enabled for the Public profile and SMB signing off. |
| **W6** | Malicious download | **Not mitigated yet.** A31/A32 not measured; no controller exists. |
| **W7** | Controller compromise | **Not applicable yet** - no controller was built (brief §65). |
| **W8** | Supply-chain attacker | **Materially reduced.** Both candidate browsers carry valid Authenticode signatures (Edge: `CN=Microsoft Corporation`; Chrome: `CN=Google LLC`), unlike the QEMU binaries rejected at B17. No new trust root is added. |
| **W9** | Windows kernel compromise | **Out of scope and explicitly not defended against.** Every boundary here is a Windows kernel boundary; if the kernel falls, all of them fall together. |

### The assumption chain, and where it breaks

```
malicious site -> renderer compromised  ......  CONTAINED   (Chromium sandbox, A3)
               -> browser process compromised .  NOT CONTAINED (A2, A4-A7)
               -> host files, credentials, registry, same-user process memory
```

## 3. Trust boundaries - measured, not assumed

```
                    INTERNET  (attacker-controlled)
                        │
        ═══ TB-0 ═══════╪══  Chromium renderer sandbox
                        │     AppContainer + UNTRUSTED integrity + 0 privileges  [A3]
                        │     *** THIS IS THE ONLY REAL PROCESS BOUNDARY ***
                        ▼
                 Browser process (broker)
        ┅┅┅ TB-1 ┅┅┅┅┅┅┅╪┅┅  *** NO BOUNDARY EXISTS HERE ***
                        │     token-equivalent to an ordinary user process  [A4]
                        │     AppContainer wrapping measured impossible     [A2]
                        ▼
                 WINDOWS USER SESSION  (files, registry, credentials - all reachable)
                        │
     ══ TB-2 ══ network │  firewall -Program rules: hold for REMOTE addresses [A16]
                        │  and cannot be edited by the browser               [A17]
                        │  BUT do not cover loopback or the host's own IP    [A16]
                        ▼
                 Windows kernel  (trusted; not defended against)
```

**TB-1 is drawn as a dashed line deliberately.** In the WSL2 and Hyper-V designs this position held a hypervisor. Here it holds nothing.

## 4. Attack surface

| # | Surface | Disposition |
|---|---|---|
| P1 | Web content → renderer | **Mitigated** by Chromium's sandbox (A3). Defence in depth only - assumed breachable. |
| P2 | Renderer → browser process (Mojo IPC) | **Residual.** Chromium's broker is the only thing validating these requests, and it is unprotected by anything we add. |
| P3 | Browser process → host filesystem | **UNMITIGATED for reads** (A4). Writes to Documents blocked by Controlled Folder Access; Desktop, Downloads and LOCALAPPDATA writable. |
| P4 | Browser process → registry | **UNMITIGATED** (A5), including a writable `HKCU\...\Run` - user-level persistence is possible. |
| P5 | Browser process → credentials | **UNMITIGATED** (A7). Credential Manager reachable; DPAPI and browser-profile directories listable. |
| P6 | Browser process → other processes | **Partially mitigated by Windows.** SYSTEM processes refused; `explorer.exe` opened with `VM_READ` (A6). |
| P7 | Browser → remote LAN / router | **MITIGATED** by program-scoped firewall rules (A16 PASS, A17 tamper-resistant). |
| P8 | Browser → loopback and host's own IP | **UNMITIGATED, no mechanism available** (A16 FAIL). Host SMB/RPC/NetBIOS and a live PyCharm service confirmed TCP-reachable. |
| P9 | Browser → IPv6 | **UNKNOWN** (A13) - this network has no global IPv6 path to test. |
| P10 | DNS | **UNKNOWN** (A18); a working plaintext path exists (A19). |
| P11 | LAN peer → this host | **Not adequately mitigated** (A20/A21). |
| P12 | Downloads | **Not addressed yet** - no quarantine built. |
| P13 | GPU | **Not measured** (A9). Design position is software rendering, carried from the WSL2 G1 failure. |
| P14 | Devices (camera, mic, location) | **Not measured** (A8). The capability-based route was removed by A2; only Chromium's permission prompts remain, which brief §18 says are not sufficient alone. |

## 5. What this backend does and does not defend

**Defends against:** ordinary malicious web content, tracking, renderer-level exploits, browser access to the router and LAN devices, and - because firewall policy is administrator-owned (A17) - a compromised browser trying to lift its own network restrictions.

**Does not defend against:** a compromised browser process reading host files, credentials or registry; reaching localhost or host services; establishing user-level persistence; reading another same-user process's memory. Nor against a Windows kernel compromise, LAN peers reaching this host's SMB, or any anonymity threat.

## 6. Residual risks

1. **No boundary around the browser process (W3).** The single largest risk, and it is structural, not a configuration gap.
2. **Loopback and host-own-IP are unreachable by any host-side control** (A16) - Stage 2's G3 failure reproduced with no mitigation available.
3. **A18 DNS is UNKNOWN** and load-bearing.
4. **The account is a local administrator** (`S-1-5-32-544` present, UAC-filtered). A17's refusals depend on UAC, so a successful elevation or a socially-engineered prompt defeats them.
5. **Host inbound exposure on untrusted Wi-Fi** (A20/A21).
6. **No controller, no quarantine, no export path** - A25-A32 unmeasured.
7. **Isolation is not anonymity.** Public IP, account identity, fingerprinting and traffic metadata are unaffected by anything here.
