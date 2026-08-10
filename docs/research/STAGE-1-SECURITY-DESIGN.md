> **RENAMED.** This file was `docs/SECURITY.md` until the 0.9.0 publication pass.
> It was renamed to `docs/STAGE-1-SECURITY-DESIGN.md` because the repository root now
> carries a `SECURITY.md` in the place GitHub looks for vulnerability-reporting
> instructions, and two files with the same name saying different things is exactly the
> sort of ambiguity a security document should not have.
>
> Historical documents elsewhere in `docs/` still refer to this file as `SECURITY.md`.
> Those references were deliberately left alone: they are records of what existed at the
> time, and editing them would falsify the history they exist to preserve.
>
> For the CURRENT security policy and how to report a vulnerability, see
> [`/SECURITY.md`](../../SECURITY.md).

# Security - Privacy-First Disposable Browser

**Status:** design only. No implementation code exists yet, so nothing here describes shipped behaviour.

> **BACKEND SUPERSEDED - read this first.** This document was written at Stage 1, when the isolation backend was WSL2. **WSL2 was subsequently measured to fail (Stage 2: G1, G3, G8) and was rejected**, and its QEMU replacement was rejected on supply chain (B17). No backend is currently selected. §3 below therefore describes an architecture that **is no longer the plan**; it is retained unedited because §4 records what was measured against it. For the full chronology and the current position, read **[`PROJECT-HISTORY.md`](../PROJECT-HISTORY.md)**.

This is the security entry point. It states the claims, the assumptions, and the things that are explicitly *not* claimed, and points to where each is developed in depth.

| Topic (brief §41) | Where |
|---|---|
| **Which backend is current, and why the others were abandoned** | **`PROJECT-HISTORY.md`** |
| Threat model, attacker capabilities, assumptions | `THREAT-MODEL.md` §1-2 |
| Trust boundaries | `THREAT-MODEL.md` §3-4 |
| Security architecture, isolation mechanisms | `ARCHITECTURE.md` §3-6 |
| IPC design | `ARCHITECTURE.md` §9 |
| Update security, dependency security | `THREAT-MODEL.md` §8, and §5 below |
| Known limitations, residual risks | `THREAT-MODEL.md` §10, and §4 below |
| Vulnerability reporting | §6 below |

---

## 1. What this project claims

**It protects the Windows host from the browser.** The browser runs behind a hypervisor boundary, with no host filesystem mounted, no host-binary execution path, no clipboard channel by default, and network egress restricted by a firewall enforced on the host side - outside anything a compromised guest can edit.

**It reduces what websites collect.** Third-party cookies restricted, permissions denied by default, tracking protection, fingerprint entropy reduced and stabilised, no telemetry.

**It gives suspicious links a genuinely disposable environment** - created fresh, destroyed afterwards.

## 2. What this project does *not* claim

- **Not anonymity.** Websites see your real public IP. Logging into any account identifies you completely. A VM changes nothing about either.
- **Not immunity to exploits.** Browser zero-days, hypervisor escapes and Windows kernel bugs are all possible. The design assumes the browser *will* eventually be exploited and puts a machine boundary behind it.
- **Not protection from yourself.** Exporting a file and running it breaks isolation for that file, by design and permanently.
- **Not forensic erasure.** `DESTROY SESSION` removes the session; it does not guarantee the underlying disk blocks are unrecoverable.
- **Not perfect fingerprint protection.** No such thing exists. Randomising per request makes things *worse*, not better - see `THREAT-MODEL.md` §7.

## 3. The security architecture in one paragraph

**[SUPERSEDED - the WSL2 backend described here was rejected after Stage 2. Retained as the design §4's measurements were taken against.]**

Chromium runs inside a hardened WSL2 Linux guest. Chromium's own renderer sandbox and Linux user separation are **defence in depth, not the boundary** - the design assumes both are breached. The boundary is the Microsoft hypervisor (TB-2), backed by host-side network policy (TB-3) and a zero-mount filesystem model with pull-only export (TB-4). The controller on the host runs unelevated, never invokes a shell, exposes no listening socket the guest can reach, and treats every byte from the guest as hostile input. Privileged setup is a separate one-shot tool that the runtime can never invoke.

## 4. The weaknesses worth knowing before you rely on this

Stated plainly rather than buried in a limitations appendix:

1. **`wslservice.exe` runs as LocalSystem.** A vulnerability in WSL's guest-facing control channel escalates a guest compromise to SYSTEM on the host - a worse outcome than a hypervisor escape, which lands in a low-privilege VM worker account. This is the weakest structural point of the WSL2 backend and it cannot be removed while using WSL2. It disappears on a Windows 11 Pro upgrade with the Windows Sandbox or Hyper-V backend.

2. **Mode A and Mode B are separated in time, not in space.** WSL2 runs all distributions in one utility VM, so there is no hypervisor boundary between the persistent profile and a disposable session. The controller enforces mutual exclusion (invariant MX-1) instead: launching one mode terminates the other and verifies it stopped. The cost is that you cannot have both open at once.

3. **The load-bearing network control was tested and partially FAILED.** Stage 2 gates G3 and G8 measured host-side Hyper-V Firewall enforcement. It successfully blocks the router, LAN devices, and non-allowlisted ports. It **fails to block the guest from reaching the Windows host's own SMB (445) and RPC (135) services**, because guest→host traffic is source-NAT'd to the host's own IP and so never matches guest-scoped rules. **TB-3 is not established.** Under the fail-closed rule, the browser must not launch on this backend until the gap is closed. Evidence: `STAGE-2-RESULTS.md` §G3/G8.

4. **`/dev/dxg` cannot be removed on this backend.** `guiApplications=false` disables WSLg but leaves the GPU paravirtualisation device present and openable by an unprivileged process - a direct ioctl path from a compromised renderer to the host's `dxgkrnl` kernel driver. Stage 2 gate G1 = FAIL.

## 5. Security properties the implementation must hold

These are commitments, and each one gets a test that fails when the property is false.

**Fail closed.** If any of the eight preflight checks in `THREAT-MODEL.md` §9 cannot be *positively verified*, the browser does not launch. Unverified state is displayed as *unknown*, never as passing. There is no "safe" indicator anywhere in the UI.

**Least privilege.** The runtime controller never elevates - no UAC prompt during normal use. Rule-writing and feature-enabling live in `bm-setup`, which is elevated, one-shot, interactive, takes no arguments from the runtime, and prints its exact change list before doing anything.

**No host weakening, ever.** Windows Defender, SmartScreen, Secure Boot, VBS, HVCI, ASLR, DEP and CFG are never modified. No services, scheduled tasks, startup persistence, driver installs, certificate installs, proxy changes or registry security changes. The only host-global change is `%UserProfile%\.wslconfig`, which is backed up before writing, restored on uninstall, kept plain text, and justified key by key.

**No dangerous primitives.** No `shell=True`, `eval`, `exec`, or dynamic code execution. No TLS verification disabled. No hard-coded secrets. On Windows, Python builds a command string even with `shell=False`, so **argument injection remains possible** - therefore no guest-derived or website-derived string is ever passed as a subprocess argument or used to construct a host path. Identifiers are validated against strict patterns.

**Untrusted input handling.** Guest output is size-capped, timed out, schema-validated, and rejected on unknown fields. Host filenames for exported files are generated by the host; the guest supplies an opaque ID and never a path. This eliminates traversal, UNC paths, device paths, symlinks, junctions, alternate data streams and null bytes as a class rather than filtering them individually.

**Supply chain.** Dependencies justified in writing, pinned with hashes, standard library preferred. No `curl … | powershell` in build, install or setup. Updates are signature-verified against a pinned publisher and fail closed - never "download then execute." CI uses least-privilege tokens, actions pinned to commit SHAs, and never runs untrusted fork content with credentials. SBOM generated; serious scanner findings fail the build rather than being suppressed.

**Logging.** No passwords, cookies, tokens, page contents, clipboard contents or full URLs with sensitive query parameters. A safe-diagnostic mode exists. Crash dumps stay local, are never auto-uploaded, and carry a warning about what they may contain.

**Telemetry.** None. No analytics, no remote logging, no silent network calls. Any future crash reporting would be opt-in, minimal, scrubbed, and documented as to exactly what leaves the device.

**AI.** Optional, absent by default, and never granted host command execution, arbitrary filesystem access, or unrestricted network access. The security architecture must not depend on it.

## 6. Reporting a vulnerability

*(Placeholder - to be completed at Stage 10 when a distribution channel exists.)*

Intended policy: report privately, not via a public issue. A security contact and, if practical, a public key will be published here before any release. Expect acknowledgement within a stated window, a coordinated disclosure timeline, and credit unless the reporter prefers otherwise.

Especially wanted: anything that lets a webpage reach the host filesystem, execute host code, reach `localhost` or the LAN, escape the export flow, or cause the dashboard to display a control as active when it is not. **That last category counts as a vulnerability in its own right** - a security indicator that lies is worse than no indicator.

## 7. Audit trail

Stage 12 is a full security audit that assumes the implementation is wrong (brief §50) and answers the red-team checklist (brief §51) item by item in writing. Every "yes" gets minimised, documented, controlled and tested. That document ships with the project; it is not an internal exercise.
