# Implementation Plan - Privacy-First Disposable Browser

**Status:** Stage 1 complete (this document + `THREAT-MODEL.md` + `ARCHITECTURE.md`). No implementation code written.

---

> ## STAGE 2 EXECUTED - 2026-08-08
>
> ```
> G1  /dev/dxg isolation       FAIL
> G2  WSL interop              PASS (residual: interop sockets still connectable)
> G3  IPv4 network isolation   FAIL
> G4  IPv6 isolation           UNKNOWN (no IPv6 on this network)
> G5  RDP isolation            UNKNOWN (not reached - stop condition)
> G6  Shared utility VM        PASS (shared VM confirmed; MX-1 necessary)
> G7  Filesystem isolation     PASS (residual: read-only driver-store mount)
> G8  Firewall enforcement     FAIL
> ```
>
> **Verdict: REVISE ARCHITECTURE AND REPEAT STAGE 2. Stage 3 is blocked.**
> Full evidence and raw output: `STAGE-2-RESULTS.md`. The gate table below is the
> original plan, retained for reference.

## Stage 2 verification gates - run before any implementation

The architecture leans on seven empirical claims that have **not** been tested on this machine. Each is a short experiment in a throwaway distribution. **If a gate fails, the design changes and the claim gets reworded - the finding does not get reshaped to fit the design.**

| Gate | Claim under test | Method | If it fails |
|---|---|---|---|
| **G1** | `[wsl2] guiApplications=false` actually removes `/dev/dxg` | `ls -l /dev/dxg` with the setting on, then off | Surface S3 (GPU paravirtualisation to host `dxgkrnl`) becomes **residual**, not eliminated. Dashboard wording and `SECURITY.md` change accordingly. |
| **G2** | `[interop] enabled=false` blocks guest→host execution, **while `wsl.exe -d X -- cmd` from the host still works** | Attempt to exec a Windows PE from the guest; then run a host-initiated command into the guest | The entire host-pull control plane (ARCHITECTURE §9) must be redesigned. **This is the highest-impact gate.** |
| **G3** | `DefaultOutboundAction=Block` + allowlist yields internet access while host/LAN/link-local are unreachable | From the guest: `curl https://…` (expect success); `curl` host LAN IP, NAT gateway, `169.254.x`, a `192.168.x` device (expect failure). Confirm rule granularity and priority ordering | The network section changes shape. If per-address deny rules are not expressible, fall back to a narrower allow-only model or reconsider the backend. |
| **G4** | IPv6 is genuinely covered | Repeat G3 over IPv6: link-local, ULA, public v6 | Disable IPv6 in-guest as the primary control rather than a secondary one. |
| **G5** | Host can reach guest RDP with `localhostForwarding=false`, while guest→host stays blocked | Connect `mstsc` to the guest IP:3390; simultaneously confirm guest→host is denied | Display path needs rework - possibly a narrowly-scoped forwarding exception, which must then be justified and documented. |
| **G6** | All WSL distros share one utility VM (basis for invariant MX-1) | Install two distros; check kernel boot ID / VM instance identity from both | If they are in fact separated, MX-1 can be relaxed and both modes may run concurrently - a usability win. |
| **G7** | `automount.enabled=false` leaves **no** host path reachable | Enumerate mounts **from the host side** (what WSL reports), not only `/proc/mounts` in the guest - a compromised guest can lie about its own mount table | Filesystem isolation claim (TB-4) is downgraded until a working configuration is found. |
| **G8** | Hyper-V Firewall enforcement actually engages | Does it require `[wsl2] firewall=true` in `.wslconfig` to take effect? Does `Set-NetFirewallHyperVVMSetting -DefaultOutboundAction Block` demonstrably stop guest egress? | TB-3 loses its host-side enforcement point. Guest-side `nftables` alone is **not** an acceptable substitute (useless against T4), so the backend decision would have to be revisited. |

**Already settled by measurement (2026-08-08):** the Hyper-V Firewall **read** path succeeds unelevated and the **write** path is denied unelevated. Fail-closed check #4 is therefore runnable by the never-elevated runtime controller, and rule creation correctly belongs to `bm-setup`. The privilege split in `ARCHITECTURE.md §10` holds.

Gate results are recorded in `docs/STAGE-2-RESULTS.md` with raw command output, and the dashboard's wording is derived from them.

---

## Stages

| Stage | Deliverable | Definition of done |
|---|---|---|
| **1** ✅ | `SECURITY.md`, `THREAT-MODEL.md`, `ARCHITECTURE.md`, this plan | Reviewed and approved |
| **2** | Minimal isolation prototype | Gates G1-G7 answered with recorded output; a Chromium window from the guest is visible on the host through the controlled RDP path |
| **3** | **BLOCKED** - verify host isolation | Cannot start: Stage 2 G3/G8 showed LAN/host-service isolation is not achieved on the WSL2 backend. The adversarial suite would fail on "host services unreachable" by construction. Unblocking requires a decision on the three directions in `STAGE-2-RESULTS.md` §Recommendation. |
| **4** | Browser privacy configuration | Managed policy files rendered and verified against `chrome://policy`; permission defaults locked; fingerprinting-entropy decisions made and their tradeoffs documented |
| **5** | Mode A - persistent private | Profile lives inside the guest; bookmarks persist; `RESET PRIVATE PROFILE` works and shows its deletion list first |
| **6** | Mode B - disposable | Ephemeral distro per session; `DESTROY SESSION` verified; **MX-1 enforced and tested regardless of G6's outcome** - a mis-measured gate must not be able to silently remove the constraint. Relaxing MX-1 requires a deliberate, documented decision, not a passing test |
| **7** | Downloads and export | Manifest, opaque-ID pull, host-generated names, quarantine, Zone.Identifier, honest warnings |
| **8** | Security dashboard | Every row backed by a real measurement in `assertions/`. Unverified rows render as *unknown*. No "safe" indicator |
| **9** | Testing and fuzzing | Malformed/oversized/unexpected guest output; corrupt and hostile config; path-handling fuzzing |
| **10** | Installer and packaging | Minimum privileges; states exactly what it changes; verified binaries; clean uninstall |
| **11** | CI/CD security | Pinned actions by SHA, least-privilege token, SBOM, dependency audit, secret scanning; serious findings fail the build |
| **12** | Final security audit | The §50 second pass - assume the implementation is wrong - plus the §51 red-team checklist answered item by item, in writing |

---

## Decisions deliberately deferred

Recording these so they are made with evidence rather than by default.

| Decision | Stage | Sketch of the tradeoff |
|---|---|---|
| Guest browser: Debian Chromium vs. Brave vs. Firefox | 4 | Chromium has the strongest sandbox; Brave adds built-in blocking but its own network callbacks; Firefox has better content blocking but a weaker Linux sandbox |
| Content blocking: network-layer (DNS/proxy blocklist) vs. extension (uBO Lite) | 4 | Network-layer is auditable, extension-free, and works in Mode B where §15 forbids auto-installing extensions. Leaning that way, but measure breakage first |
| Guest distribution base image | 2 | Debian preferred over Ubuntu - no snap, simpler `chromium` packaging in WSL |
| Controller UI toolkit | 5 | Constraint already fixed: native, no embedded web view. Tkinter costs nothing in supply chain but is unpleasant for daily use |
| DoH resolver default | 4 | Any choice concentrates DNS visibility somewhere; must be user-selectable and honestly documented |
| Whether "Mode A-lite" (host dedicated account) ships at all | 5 | Only as an explicit, clearly-labelled downgrade for users who need hardware video decode |

---

## Decisions taken by the user (2026-08-08)

| Decision | Choice | Consequence |
|---|---|---|
| **Isolation backend** | **Hardened WSL2 now** | Proceed on the existing WSL 2.7.3 + Microsoft hypervisor + host-side Hyper-V Firewall. The two accepted weaknesses are on the record: `wslservice.exe` runs as LocalSystem (surface S6), and Mode A/B separation is temporal via invariant MX-1, not a separate VM. Work still goes behind the `IsolationBackend` interface so a Pro-SKU backend remains addable without rework. |
| **Global `.wslconfig`** | **Proceed, with backup** | `bm-setup` backs up any existing `%UserProfile%\.wslconfig` before writing, `bm-uninstall` restores it. The file stays plain text and readable - no obfuscation. Every key it sets is justified line by line in `SECURITY.md`. |

---

## Document deliverables

The brief names three documents (§40, §41, §42). Status:

| Document | State | Note |
|---|---|---|
| `ARCHITECTURE.md` | **Done** (Stage 1) | Trust boundaries marked in the diagrams |
| `SECURITY.md` | **Done** (Stage 1) | Entry point covering §41's required headings, including vulnerability reporting; delegates depth to `THREAT-MODEL.md` |
| `THREAT-MODEL.md` | **Done** (Stage 1) | Assets, adversaries, boundaries, attack surface, dangerous defaults, residual risks |
| `PRIVACY.md` | **Deferred to Stage 7** - deliberately | It must state exactly what leaves the device: the chosen DoH resolver, Safe Browsing's hash-prefix lookups, the content-blocking mechanism, and the download/export flow. Those are Stage 4 and Stage 7 decisions. Writing it now would mean guessing, and a privacy document that guesses is worse than one that waits. |
| `LIMITATIONS.md` | Stage 12 | May be folded into `SECURITY.md` if it stays short |

## Working rules for every subsequent stage

- No `shell=True`, no `eval`, no `exec`, no dynamic code execution, anywhere.
- No guest-derived or website-derived string is ever passed as a subprocess argument or used to build a host path.
- No security-relevant claim ships without a test that fails when the claim is false.
- Any action that materially affects host security **stops and asks first** (brief §54).
- Unverified state is displayed as *unknown*, never as passing.
