# Architecture - Privacy-First Disposable Browser

**Status:** Stage 1 (design only, no implementation).
Read `THREAT-MODEL.md` first. Confidence markers `[MEASURED]` / `[DOC]` / `[ASSUMPTION]` are used as defined there.

---

## 1. Target machine capability survey

Measured on this machine, 2026-08-08, from an **unelevated** shell:

| Capability | Result | Consequence |
|---|---|---|
| OS | Windows 11 Home Single Language, build 10.0.26200 `[MEASURED]` | Edition ID `CoreSingleLanguage` |
| CPU / RAM / disk | Ryzen 7 7840HS, 8C/16T, 15.3 GB, 400 GB free `[MEASURED]` | Comfortable for one guest VM |
| Hypervisor present | Yes `[MEASURED]` | Microsoft hypervisor is loaded |
| VBS / HVCI | VBS running (status 2), HVCI enabled `[MEASURED]` | Host is already hardened; **must not be disabled** |
| Secure Boot | Enabled `[MEASURED]` | Keep |
| **Windows Sandbox** | **`WindowsSandbox.exe` absent** `[MEASURED]` | **Unavailable - Home SKU** |
| **Hyper-V VM role** | Not installable on Home `[DOC]`; `vmcompute.exe`/`vmwp.exe` present `[MEASURED]` | **The management stack (`New-VM`, virtual switches) is unavailable.** The underlying HCS runtime that WSL2 uses *is* present. |
| WSL | 2.7.3.0, kernel 6.6.114.1, WSLg 1.0.73 `[MEASURED]` | Installed and current |
| Installed distributions | **None** `[MEASURED]` | Clean slate - no existing dev workflow to break |
| `%UserProfile%\.wslconfig` | Does not exist `[MEASURED]` | Nothing to merge yet |
| **Hyper-V Firewall - surface** | Cmdlets present; WSL VM creator `{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}` exposed with `DefaultOutboundAction: Allow`, `DefaultInboundAction: Block`; 16 existing rules enumerable `[MEASURED]` | The host-side control surface for guest networking **exists** on this SKU. |
| **Hyper-V Firewall - enforcement** | **PARTIAL - fails guest→host** `[MEASURED]` | Stage 2 G3/G8 = **FAIL**. Egress port allowlisting works (22 blocked, 80/443 allowed); router and LAN devices are blocked. But the guest still reaches host **445/135** because guest→host traffic is SNAT'd to the host's own IP. TB-3 is **not** established. See `STAGE-2-RESULTS.md`. |
| **Hyper-V Firewall - privilege split** | Read succeeds unelevated; write returns `Access is denied` unelevated `[MEASURED]` | Confirms the model directly: the runtime controller can **verify** rules without elevation (fail-closed check #4 is runnable), while **writing** them is confined to the elevated one-shot `bm-setup`. |
| Third-party hypervisors | None installed `[MEASURED]` | No pre-existing kernel drivers |
| Privilege | Member of Administrators, currently **unelevated** `[MEASURED]` | The "elevated one-shot setup / never-elevated runtime" split is achievable |
| Browsers | Chrome 151, Edge 151 `[MEASURED]` | Host browsers stay out of scope; guest gets its own |

### Immediate consequence

**The architecture requested in the brief - Windows Sandbox or a hardened Hyper-V VM - cannot be built on this machine as it is currently licensed.** Per §3 of the brief, the response is to say so and downgrade deliberately rather than to weaken anything to compensate. Options are in §3 below.

Note the deliberate split in the three Hyper-V Firewall rows above. What is *measured* is that the control surface exists and that its privilege boundary behaves correctly. What is *assumed* is that the enforcement works as intended. The design depends on the second, so it is a Stage 2 gate rather than a settled claim - the same standard this project applies to its own dashboard.

---

## 2. Why not embed a browser in a desktop application

The common approach - CEF, WebView2, `pywebview`, Electron - is rejected, and it is worth being concrete about why, because the failure is structural rather than a matter of configuration:

- **The renderer runs under the application's own token.** A renderer escape does not need to cross a machine boundary; it is already the application's user, with the application's file handles, environment variables, registry access, and network identity.
- **The controller's own privileges become the blast radius.** Anything the app can do - write config, invoke the update system, talk to a helper - the escaped renderer can do.
- **There is no kernel boundary.** Host and web content share one kernel, so a Windows LPE turns a renderer bug into a full host compromise with no additional obstacle.
- **Disposability is fake.** "Clear the profile" is a directory deletion; it does not undo anything the compromised process did to the user account.
- **The IPC surface faces the wrong way.** Embedded frameworks expose native bridges *by design*; every one is a candidate path from page content to host code.

The design instead keeps the entire browser on the far side of a hypervisor boundary and gives the controller no ability to run guest-supplied content.

---

## 3. Isolation backend selection

| Backend | Available here | Boundary strength | Admin / driver cost | Disposability | Per-mode separation | Host-side network control | Verdict |
|---|---|---|---|---|---|---|---|
| **Windows Sandbox** | **No** (Home) | Very strong - purpose-built disposable VM | None once on Pro | Excellent (fresh every launch) | Excellent (separate VM) | Weak - no per-VM ACL; guest-side firewall only | **Best fit for Mode B, blocked by SKU** |
| **Hyper-V VM role** | **No** (Home) | Very strong | Feature enable (admin) | Good (checkpoints) | Excellent | Excellent (`Set-VMNetworkAdapterExtendedPortAcl`) | **Best overall, blocked by SKU** |
| **WSL2, hardened** | **Yes** `[MEASURED]` | Strong for browser→host (hypervisor). **Weak between modes** (shared VM) | None at runtime; admin once for firewall rules | Good (`wsl --unregister` + delete VHDX) | Container-grade only → needs MX-1 | **Excellent** (Hyper-V Firewall, verified present) | **Chosen for v1** |
| **QEMU + WHPX** | Yes, after install | Strong; device models run in a *user-mode* host process that can itself be sandboxed | No kernel driver (WHPX is an OS feature), but ships a large binary | Excellent (per-session disk) | Excellent (separate VM per session) | Good (host process, filterable by program) | **Backend C - strong future option; heavier supply chain** |
| **VirtualBox / VMware** | Yes, after install | Real VM, but the worst public VM-escape record of the options | **Kernel drivers + admin** → brief §54 stop condition | Excellent (snapshots) | Excellent | Fair | **Rejected** - worse boundary than the hypervisor already present, at higher host risk |
| **AppContainer / dedicated user only** | Yes | **No VM boundary.** Shared kernel with the host | None at runtime | Poor | Poor | Fair | **Rejected as primary**; acceptable only as an explicitly-chosen "Mode A-lite" downgrade |

### Decision

**v1 uses a hardened WSL2 backend**, behind an `IsolationBackend` interface with a deliberately narrow contract:

```python
class IsolationBackend(Protocol):
    def preflight(self) -> CapabilityReport: ...      # can we start at all?
    def create_session(self, spec: SessionSpec) -> Session: ...
    def assert_isolated(self, s: Session) -> list[AssertionResult]: ...  # measured, not assumed
    def launch_browser(self, s: Session, url: str | None) -> None: ...
    def destroy(self, s: Session) -> DestroyReport: ...
```

`WindowsSandboxBackend`, `HyperVBackend` and `QemuWhpxBackend` implement the same interface later. **Nothing above this interface may assume WSL.**

**Rule for `assert_isolated()`: every assertion must be measurable from the host.** After T4 (guest root) the guest is a lying witness - asking it to read its own `/proc/mounts`, its own firewall rules, or its own browser policy and trusting the answer is worthless precisely when it matters. Where a guest-side reading is the only one available, it is recorded as *unverified*, not as passing. This is why `assertions/` is its own module: measurement gets exactly one home, and its trust level is explicit at every call site.

### Honest ranking of what was given up

Choosing WSL2 costs three things relative to the brief's ideal:

1. **No hypervisor boundary between Mode A and Mode B** - mitigated by invariant MX-1, at the cost of not running both modes at once.
2. **`wslservice.exe` runs as LocalSystem** `[DOC]` - a WSL control-plane bug escalates to SYSTEM, whereas a Windows Sandbox device-model bug lands in a low-privilege VM worker account. This is a genuinely worse failure mode.
3. **Global `.wslconfig`** - `networkingMode`, `firewall`, `guiApplications` and `localhostForwarding` are per-user, not per-distro `[DOC]`. Installing this app changes WSL behaviour for the whole user account.

All three disappear on a Windows 11 Pro upgrade. That is a real option, not a footnote.

---

## 4. System architecture

```
┌─────────────────────────────────────── WINDOWS HOST (trusted) ──────────────────────────────────────┐
│                                                                                                      │
│   ┌──────────────┐   ┌────────────────┐   ┌───────────────┐   ┌──────────────────────────────────┐  │
│   │  Native UI   │──▶│   Controller   │──▶│ Policy Engine │   │  bm-setup (SEPARATE TOOL)        │  │
│   │  (no web     │   │  (unelevated,  │   │ renders guest │   │  ── ELEVATED, ONE-SHOT ──        │  │
│   │   content    │◀──│   fixed argv,  │   │ policy + .rdp │   │  installs distro, writes         │  │
│   │   ever)      │   │   no shell)    │   └───────────────┘   │  Hyper-V FW rules, ACLs quarantine│  │
│   └──────────────┘   └───────┬────────┘                       │  NEVER invoked at runtime  ══TB-5══│  │
│          ▲                   │                                └──────────────────────────────────┘  │
│          │            host-pull only                                                                 │
│   ┌──────┴───────┐    (wsl.exe, fixed argv,                ┌───────────────────────────────────┐    │
│   │ Quarantine   │     capped stdout, strict schema)       │  Hyper-V Firewall  ══ TB-3 ══     │    │
│   │ %LOCALAPPDATA│           │                             │  default outbound = BLOCK         │    │
│   │ non-exec ext │           │        ┌────────────────┐   │  ENFORCED OUTSIDE THE GUEST       │    │
│   │ Zone.Id = 3  │           │        │ mstsc (RDP)    │   └─────────────┬─────────────────────┘    │
│   └──────────────┘           │        │ ALL redirection│                 │                          │
│                              │        │ channels OFF   │                 │                          │
│                              │        └───────┬────────┘                 │                          │
└──────────────────────────────┼────────────────┼──────────────────────────┼──────────────────────────┘
   ╔══════════════════════ TB-2 ═╪════ MICROSOFT HYPERVISOR ═╪══════════════╪═════════════════════════╗
   ╚═════════════════════════════╪══════════════════════════╪══════════════╪═════════════════════════╝
┌─────────────────────────────── ▼ ──────── WSL2 GUEST (UNTRUSTED) ─────── ▼ ─────────────────────────┐
│   no /mnt/c   ·   interop OFF   ·   no /dev/dxg   ·   no WSLg   ·   nftables (defence in depth)      │
│                                                                                                      │
│   xrdp ──▶ Chromium (unprivileged user, managed policy files, verifiable at chrome://policy)         │
│                                    │                                                                 │
│            /home/browser/Downloads │ (export = host-pull by opaque ID; guest never names a host file)│
└────────────────────────────────────┼─────────────────────────────────────────────────────────────────┘
                                     ▼
                                 INTERNET  (80/443/QUIC only, RFC1918 blocked host-side)
```

---

## 5. Display path

**Decision: one display path for both modes - local RDP into the guest, every redirection channel explicitly disabled.**

Rationale:

- Each redirection channel (clipboard, drives, printers, USB, cameras, smart cards, audio capture, location) becomes an explicit, per-session, **host-side** setting written by the controller into a generated `.rdp`. Clipboard "off" means the channel is never negotiated - a control enforced *outside* the untrusted guest, not a setting inside it.
- It removes WSLg, and with it `/dev/dxg` and the WSLg clipboard/audio bridge (surfaces S3 and S5).
- `mstsc.exe` is a mature, signed Microsoft component. Windows Sandbox itself uses an RDP-based presentation path `[DOC]`.
- One path instead of two means less code and fewer places to leave a hole.

**Cost, stated up front:** no GPU acceleration and no hardware video decode in the guest. Chromium renders in software. Scrolling and normal pages are fine on a 7840HS; **1080p video will be CPU-bound and 4K is not realistic.** This is the main daily-use consequence of choosing isolation over convenience, and it is the reason a "Mode A-lite" host-account variant is offered as an explicit, clearly-labelled downgrade rather than being silently unavailable.

---

## 6. Network design (TB-3) - **DISPROVEN IN PART, Stage 2**

> **Measured outcome 2026-08-08.** The design below was tested and **partially failed**.
>
> | Intent | Result |
> |---|---|
> | Block guest → router / LAN devices | **Works** - `10.0.0.1:80/443` filtered |
> | Restrict egress to an allowlist | **Works** - TCP 22 blocked, 80/443/QUIC allowed |
> | Block guest → host services | **FAILS** - host `445` (SMB) and `135` (RPC) remain reachable |
> | Block guest → `10.255.255.254` (WSL host-forward) | **FAILS** - reachable; DNS flows through it |
> | Express `::1` as a blocked range | **FAILS** - rejected, Windows error 87 |
>
> Cause: guest→host traffic is source-NAT'd to the host's own LAN IP before reaching the
> host TCP stack, so guest-scoped Hyper-V rules never match it. Neither `LoopbackEnabled=False`
> nor `AllowHostPolicyMerge=False` changed this. Confirmed by observing an ESTABLISHED
> connection on the host to PID 4 (kernel SMB) with `RemoteAddress` = the host's own IP.
>
> The rest of this section is retained as the *intent*, and remains accurate for the
> guest→LAN and guest→internet directions. It must not be cited as establishing TB-3.

Enforcement point is **Hyper-V Firewall on the host**, because rules inside the guest can be removed by a guest-root attacker (T4).

```
Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-...}' -DefaultOutboundAction Block
```

then a minimal allowlist:

| Direction | Allow | Why |
|---|---|---|
| Outbound | TCP 443, TCP 80, UDP 443 (QUIC) to **public** addresses | Browsing |
| Outbound | Chosen DoH resolver, 443 only | DNS (§7) |
| Inbound | Host → guest, RDP port only | Display |
| **Denied** | `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `127/8`, host LAN address, multicast/broadcast | Router admin, NAS, printers, dev servers, host services |
| **Denied** | IPv6 equivalents - `fc00::/7`, `fe80::/10`, `::1` | **v4-only rules are theatre if v6 routes around them** |

Guest-side `nftables` mirrors this as defence in depth - useful against a browser-level compromise (T3), useless against guest root (T4), and never counted as the control.

**Open, must be measured in Stage 2 (gate G3):** whether `New-NetFirewallHyperVRule` supports address-based deny rules with usable priority ordering, and whether blocking `172.16/12` breaks the NAT gateway path that RDP replies and DNS depend on. The rule shape above is the *intent*; the exact expression follows measurement.

**IPv6 decision:** disable IPv6 in the guest **and** write matching v6 deny rules. Belt and braces, decided now rather than in Stage 6.

---

## 7. DNS

There is no honest way to make DNS anonymous here, so the goal is to make it *predictable and documented*.

- WSL's default generates `/etc/resolv.conf` pointing at the NAT gateway, which forwards to the host's resolver `[DOC]`. That means the host DNS cache and the ISP/router see every domain visited.
- **Design:** Chromium resolves over DoH directly (`DnsOverHttpsMode: secure`) to a user-chosen resolver on 443. Browser DNS then never touches the guest resolver or the host stack.
- Non-browser guest DNS (package updates) keeps a plain resolver, which the firewall confines.
- **What this actually buys:** it moves DNS visibility from the ISP/router to the DoH provider. It is **not** anonymity, and `PRIVACY.md` will say exactly that. Failure handling (DoH unreachable) must fail closed rather than silently falling back to plaintext DNS.

---

## 8. Downloads and export (TB-4)

Zero host folders are mounted, so export is an explicit, controller-driven pull:

1. The guest writes downloads to `/home/browser/Downloads`. They stay there.
2. The controller lists downloads by running a fixed guest helper that emits a **strict, size-capped manifest**: opaque ID, size, SHA-256, guest-side MIME, original filename **as display text only**.
3. To export, the controller runs the helper with an **opaque ID** - never a path - and streams the bytes to a host file.
4. **The host filename is generated by the host.** No guest-supplied string ever reaches a filesystem call. This eliminates path traversal, UNC paths, `\\?\` device paths, symlinks/junctions, alternate data streams, null bytes and shell metacharacters as a class, rather than filtering them one by one.
5. The file lands in `%LOCALAPPDATA%\...\Quarantine\<session>\`, with a **non-executing extension appended**, its `Zone.Identifier` set to Zone 3 (Internet) so SmartScreen and Defender engage on any later attempt to open it, and a host-computed SHA-256.
6. Nothing is ever executed, and the app never calls `ShellExecute` on a quarantined file.
7. The UI states plainly: **exporting a file breaks isolation for that file, permanently.** Executables, scripts, installers and macro-capable documents get a stronger warning. A hash is an identifier, not a safety verdict.

---

## 9. IPC (TB-5)

**Design decision: there is no guest-initiated channel. At all.**

- No host listening socket, no named pipe, no server the guest can connect to.
- The controller drives everything host→guest via `wsl.exe` with fixed argv. The only guest→host data flow is the **stdout of specific fixed commands the controller chose to run**.
- That output is treated as hostile: hard byte cap, timeout, strict schema, unknown fields rejected, no dynamic evaluation of any kind.
- The asymmetry this relies on - that `[interop] enabled=false` blocks *guest→host* execution while `wsl.exe -d X -- cmd` from the host still works - is **`[ASSUMPTION]`, Stage 2 gate G2.** If it does not hold, the control plane must be redesigned.

The verb set is closed and small: `GET_STATUS`, `LIST_DOWNLOADS`, `EXPORT_FILE(id)`, `RESET_SESSION`, `DESTROY_SESSION`. There is no `EXECUTE_COMMAND`, and no AI feature will ever be given one (brief §21).

---

## 10. Privilege model

| Phase | Privilege | Does what |
|---|---|---|
| `bm-setup` | **Elevated, one-shot, interactive** | Enables required Windows features if missing, imports the pinned guest image, writes Hyper-V Firewall rules, creates the quarantine directory with restrictive ACLs. Prints the exact list first and requires typed confirmation. Takes **no arguments from the runtime** and is never invoked by it. |
| Runtime controller | **Standard user, never elevates** | Everything else. No UAC prompt during normal use, ever. |
| `bm-uninstall` | Elevated, one-shot | Removes exactly what setup created, including firewall rules. |

Windows Defender, SmartScreen, Secure Boot, VBS, HVCI and ASLR/DEP/CFG are **never** touched. There are no services, scheduled tasks, startup entries, certificate installations, registry security changes or driver installs.

---

## 11. Session lifecycle

```
launch(mode) →
  preflight()                     # capability + fail-closed checks
  enforce MX-1                    # terminate the other mode, verify Stopped
  provision:
     Mode A → reuse persistent distro  (profile lives INSIDE the guest, never on a host path)
     Mode B → clone pinned base image into an ephemeral distro  bm-disp-<random>
  assert_isolated()               # measured, not assumed - refuse to launch on any failure
  write policy files + generate .rdp with all redirection off
  start Chromium as unprivileged guest user
  connect mstsc
  ...
destroy() →
  terminate Chromium, terminate distro,
  Mode B: wsl --unregister + delete VHDX,
  verify nothing remains running,
  REPORT anything that could not be removed - never claim forensic erasure
```

**RESET PRIVATE PROFILE** (Mode A) clears cookies, cache, local storage, IndexedDB, service workers, history and permissions while preserving explicitly chosen items such as bookmarks - with the exact deletion list shown before it runs.

`DESTROY SESSION` never claims complete forensic erasure. VHDX deletion does not guarantee the underlying blocks are unrecoverable, and the documentation will say so.

---

## 12. Technology and language choices

| Component | Choice | Why |
|---|---|---|
| Browser engine | **Not written.** Chromium from a pinned distribution repository, inside the guest | Brief §4. Mature security model, Site Isolation, managed-policy support |
| Isolation | **Not written.** Microsoft hypervisor via WSL2 | Brief §4. No homemade sandbox, no homemade hypervisor |
| TLS / crypto | **Not written.** Chromium's stack in the guest; OS primitives on the host | Brief §4 |
| Controller | Python 3.11 (already scaffolded) | Never renders web content, never runs untrusted input in-process. Adequate, and the existing project is set up for it. |
| Controller UI | Native toolkit, **no embedded web view** | A web view in the controller would recreate exactly the coupling §2 rejects. Toolkit choice is Stage 5; the constraint is fixed now. |
| Guest browser config | Managed policy JSON files | Enforced, survive relaunch, independently verifiable at `chrome://policy` |

**Dependency policy:** each dependency needs a written justification; standard library preferred; versions pinned with hashes; no package that runs arbitrary install scripts without cause; SBOM generated. The current `pyproject.toml` has zero dependencies and that is the correct starting point.

---

## 13. Project structure

```
browser-maker/
├── docs/            THREAT-MODEL.md  ARCHITECTURE.md  IMPLEMENTATION-PLAN.md
│                    (later: SECURITY.md  PRIVACY.md  LIMITATIONS.md)
├── src/bm/
│   ├── capability/  host capability detection, fail-closed preflight
│   ├── isolation/   IsolationBackend protocol + wsl2/ backend  (+ future sandbox/, qemu/)
│   ├── session/     lifecycle, MX-1 invariant, destroy + verification
│   ├── policy/      Chromium policy rendering, .rdp generation
│   ├── network/     Hyper-V Firewall rule modelling and verification
│   ├── downloads/   manifest parsing, host-side naming, quarantine, Zone.Identifier
│   ├── assertions/  runtime security assertions feeding the dashboard
│   ├── ui/          native UI, mode banner, dashboard  (no web content, ever)
│   ├── config/      schema-validated config, safe defaults, path canonicalisation
│   └── log/         redacting logger, safe-diagnostic mode
├── tools/           bm-setup (elevated, one-shot), bm-uninstall
└── tests/
    ├── unit/
    └── security/    the adversarial suite (brief §35) - the one that actually matters
```

No file mixes unrelated responsibilities. `assertions/` exists as its own module because the dashboard must report *measured* state, and that is easiest to guarantee when measurement has exactly one home.
