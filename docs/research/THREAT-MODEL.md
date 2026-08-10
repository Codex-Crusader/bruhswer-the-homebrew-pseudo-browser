# Threat Model - Privacy-First Disposable Browser

**Status:** Stage 1 (design only, no implementation).
**Target machine survey date:** 2026-08-08.

Every factual claim below carries a confidence marker:

| Marker | Meaning |
|---|---|
| `[MEASURED]` | Verified on this machine on the survey date. |
| `[DOC]` | From vendor documentation or established public knowledge. Not verified here. |
| `[ASSUMPTION]` | Design assumption. **Must be empirically verified in Stage 2** before anything depends on it. |

Nothing in this document claims that malware or browser exploits are made impossible.

---

## 1. What we are protecting (assets)

Ordered roughly by how badly the user is hurt if it is lost.

| # | Asset | Why it matters |
|---|---|---|
| A1 | Host code execution (as user, or as SYSTEM) | Game over. Every other asset follows. |
| A2 | Host credentials - Windows Credential Manager, DPAPI blobs, `.ssh`, `.aws`, `.azure`, `.gitconfig`, host Chrome/Edge profiles, password-manager databases, crypto wallets | Directly monetisable, and re-compromise survives a reinstall. |
| A3 | Host filesystem contents - Desktop, Documents, source repos, private certificates | Exfiltration and ransomware. |
| A4 | LAN reachability - router admin, NAS, printers, dev servers, `localhost` services | The browser becoming a pivot into the network is a classic and under-defended path. |
| A5 | Sensors - camera, microphone, precise location | Direct physical privacy. |
| A6 | Browsing linkage - cookies, storage, fingerprint stability, IP | The everyday harm; the reason Mode A exists. |
| A7 | Integrity of this application itself - its config, its update channel | A subverted controller can disable every control below it. |

---

## 2. Adversaries and assumed capabilities

| ID | Adversary | Assumed capability | Do we assume it succeeds? |
|---|---|---|---|
| **T1** | Commodity tracker / ad network | JS, third-party requests, storage, fingerprinting, bounce tracking | Yes - it is always present. Mitigation is reduction, not prevention. |
| **T2** | Malicious website / malvertising | Full control of HTML, JS, WASM, CSS, iframes, redirects, media, downloads, permission-prompt spam, social engineering copy | Yes. |
| **T3** | Browser exploit chain - renderer RCE **plus** Chromium sandbox escape | Arbitrary native code as the browser user, inside the guest | **Yes. Assumed to succeed.** This is the design's central premise. |
| **T4** | Full guest compromise - local privilege escalation to root in the Linux guest | Arbitrary root code in the guest; can rewrite guest firewall rules, guest browser policies, guest filesystem | **Yes. Assumed to succeed.** |
| **T5** | Guest → host escape - hypervisor, VMBus device model, or WSL control-plane vulnerability | Code on the Windows host | **We do not claim to prevent this.** We minimise the reachable surface and enumerate it in §5. |
| **T6** | Supply chain - malicious PyPI package, compromised distro package, compromised update channel, compromised CI | Code execution at install/build/update time, at the privilege of whoever runs it | Treated as a first-class threat (§8). |
| **T7** | Malicious or compromised browser extension | Full access to all pages, all cookies, all storage in that profile | Yes - hence extensions are denied by default. |
| **T8** | The user, socially engineered | Willingly exports a file, runs it, types a password into a phishing page, enables clipboard, allows a permission | **Yes - and this is the most likely real-world compromise path.** No isolation layer defends against it; only UI honesty reduces it. |

### Explicitly out of scope

Physical access and evil-maid attacks; firmware/UEFI implants; a Windows host that is *already* compromised; malicious hardware; the user's ISP; targeted nation-state exploit chains against the hypervisor; and de-anonymisation via accounts the user voluntarily logs into. This tool does not provide anonymity - see §7.

---

## 3. Trust boundaries

```
                              INTERNET  (fully attacker-controlled)
                                  │
              ══════════ TB-0 ════╪════════════  Chromium renderer sandbox + Site Isolation
                                  │              DEFENCE IN DEPTH ONLY - assumed breachable (T3)
                                  ▼
                        Chromium browser process
                                  │
              ══════════ TB-1 ════╪════════════  Linux user separation, seccomp, namespaces
                                  │              DEFENCE IN DEPTH ONLY - assumed breachable (T4)
                                  ▼
                        Linux guest kernel  ── UNTRUSTED ZONE ENDS HERE ──
                                  │
   ╔══════════════════ TB-2 ══════╪═══════════════════════════════════════╗
   ║   PRIMARY SECURITY BOUNDARY: Microsoft hypervisor + WSL device surface ║
   ╚══════════════════════════════╪═══════════════════════════════════════╝
                                  │
      ┌───────────────────────────┼───────────────────────────┐
      │                           │                           │
  ══ TB-3 ══                  ══ TB-4 ══                  ══ TB-5 ══
  Network policy              Filesystem                  Privilege
  *** NOT ESTABLISHED ***     (no host user data;         (unelevated runtime;
  Hyper-V Firewall blocks      driver-store mount          elevated setup is a
  LAN/router/ports, but        residual;                   separate, one-shot tool)
  FAILS to block guest->       host-pull export only)      VERIFIED - Stage 2
  HOST 445/135. G3/G8 FAIL.   VERIFIED - Stage 2 G7
      │                           │                         │
      └───────────────────────────┴───────────────────────────┘
                                  │
                                  ▼
                          WINDOWS HOST  (trusted)
```

Plus a boundary that is **temporal, not spatial**:

```
  ══ TB-6 ══   Mode A (persistent) ↔ Mode B (disposable)
               WSL2 runs ALL distros in ONE shared utility VM.  [DOC]
               There is therefore NO hypervisor boundary between modes -
               only Linux namespace separation (container-grade).
               → Enforced instead by MUTUAL EXCLUSION (§4).
```

### The single most important statement in this document

**TB-0 and TB-1 are inside the untrusted zone.** Once T3 and T4 are assumed to succeed - and they are - Chromium's sandbox and Linux's user model contribute defence in depth but are not the boundary the design rests on.

**The design rests on TB-2, TB-3 and TB-4.** If any of those three cannot be verified at launch time, the correct behaviour is to refuse to start (§9).

> **Stage 2 outcome (2026-08-08): TB-3 is NOT established.** Gates G3 and G8 failed. The
> guest can reach the Windows host's SMB (445) and RPC (135) services because guest→host
> traffic is source-NAT'd to the host's own IP and therefore never matches guest-scoped
> Hyper-V Firewall rules. TB-4 and the host→guest/guest→host execution asymmetry *were*
> verified. Full evidence in `STAGE-2-RESULTS.md`. Under the fail-closed rule in §9, the
> browser must not launch on this backend until TB-3 is established by other means.

---

## 4. TB-6: why mode mutual exclusion is a controller invariant

WSL2 does not give each distribution its own virtual machine. All installed distributions share a single utility VM and therefore a single Linux kernel. `[DOC]` - **Stage 2 gate G6 verifies this.**

Consequence: if a persistent Mode A distro and a disposable Mode B distro are running at the same time, a guest-root compromise (T4) in the disposable session needs only a *namespace* escape - not a *hypervisor* escape - to reach the persistent browser profile, its cookies, and its saved sessions. That would directly violate §6 ("as though the machine is freshly created") and §7 ("do not expose browser profiles").

This is not something to document and accept. It is fixed in the controller:

> **Invariant MX-1.** At most one browsing mode may have a running distribution at any time. Before launching either mode, the controller terminates the other mode's distribution and verifies via `wsl -l -v` that its state is `Stopped`. If that state cannot be confirmed, the launch is refused.

**Usability cost, stated plainly:** you cannot have a persistent window and a disposable window open simultaneously. Switching modes closes the other one. This is a real daily-use limitation and it is the direct price of WSL2's shared-VM design. It disappears if the isolation backend is later changed to Windows Sandbox or per-session VMs (§ARCHITECTURE).

---

## 5. Attack surface inventory: guest → host

This is the surface that matters, because everything above TB-2 is assumed hostile. Each item is either **eliminated**, **reduced**, or **residual**.

| # | Surface | Reachable how | Disposition | Mechanism |
|---|---|---|---|---|
| **S1** | Microsoft hypervisor | Guest kernel executing privileged instructions, VMBus ring buffers | **Residual - cannot be removed** | Smallest and best-audited surface available on this SKU. A VM escape here defeats the entire design. Disclosed in limitations. |
| **S2** | VMBus / virtio device models in `vmwp.exe` | Guest device drivers | **Residual - reduced** | `vmwp.exe` runs under a per-VM virtual account (`NT VIRTUAL MACHINE\<GUID>`), not SYSTEM `[DOC]`, so a device-model bug lands in a low-privilege context. Reduced further by removing devices (S3, S5). |
| **S3** | `/dev/dxg` - GPU paravirtualisation to host `dxgkrnl` | Guest opens `/dev/dxg` | **RESIDUAL - elimination FAILED** | `[wsl2] guiApplications=false` disables WSLg but **does not remove `/dev/dxg`**. `[MEASURED]` 2026-08-08, Stage 2 gate **G1 = FAIL**: the node is present, world read/write, and was **opened rw by an unprivileged user** - the privilege level the browser runs at. An unprivileged compromised renderer therefore has a direct ioctl path to the host's `dxgkrnl` kernel driver. See `STAGE-2-RESULTS.md` §G1. |
| **S4** | `binfmt_misc` Windows interop - guest executes host `.exe` | `/init` registers a handler; guest runs `powershell.exe` | **Execution refused host-side; endpoint NOT removed** | `/etc/wsl.conf` → `[interop] enabled=false`, `appendWindowsPath=false`. `[MEASURED]` Stage 2 **G2 = PASS**: PE execution fails with the host refusing the vsock connection (errno 110) - enforcement is correctly host-side, and the Windows `PATH` leak drops from 35 entries to 0. **But the `/run/WSL/*_interop` sockets remain present and connectable from the guest.** The surface is refused, not removed; it feeds S6. |
| **S5** | WSLg - RDP channel, PulseAudio, shared clipboard, `/mnt/wslg` | Present whenever GUI apps are enabled | **Target: eliminated** | Same `guiApplications=false`. WSLg shares the clipboard bidirectionally by default `[DOC]`, which alone violates §8. Replaced by our own controlled RDP path. |
| **S6** | `wslservice.exe` control channel over hvsocket | Guest `/init` ↔ host service | **Residual - the most serious remaining item** | `wslservice.exe` runs as **LocalSystem** `[DOC]`. A protocol-parsing bug here escalates a guest compromise straight to SYSTEM - a *worse* outcome than a hypervisor escape into `vmwp.exe`. Cannot be removed while using WSL2. **This is the strongest technical argument for the Windows Sandbox / Hyper-V backend on a Pro SKU.** |
| **S7** | Plan9 / virtiofs file server for `/mnt/c` | Guest mounts host drives | **Host user data eliminated; driver-store mount residual** | `[automount] enabled=false`, `mountFsTab=false`. `[MEASURED]` Stage 2 **G7 = PASS**: `/mnt/c` is gone, the project sentinel is unreadable, the host user profile is unreachable. **Residual:** a read-only 9p mount at `/usr/lib/wsl/drivers` still exposes **851 host driver packages** (`ro,nosuid,nodev`, no exec/write). No user data, but it discloses exact host hardware and driver versions and is live host-backed surface. |
| **S8** | NAT gateway - guest → host IP, guest → LAN | Guest routes to `172.x.x.1` and beyond | **PARTIAL - guest→LAN blocked, guest→HOST NOT blocked** | `[MEASURED]` Stage 2 **G3/G8 = FAIL**. Hyper-V Firewall successfully blocks the router, LAN devices, and non-allowlisted ports. It **does not** stop the guest reaching host services on **445 (SMB)** and **135 (RPC)**: guest→host traffic is SNAT'd to the host's own LAN IP, so guest-scoped rules never match. Confirmed on the host: an ESTABLISHED connection to PID 4 (kernel SMB) with `RemoteAddress = 10.0.0.50`. `LoopbackEnabled=False` and `AllowHostPolicyMerge=False` did not help. |
| **S9** | `localhostForwarding` - guest ports appear on host `127.0.0.1` | Default `true` `[DOC]` | **Target: eliminated** | `.wslconfig` → `localhostForwarding=false`. |
| **S10** | `\\wsl.localhost\<distro>` - host reads guest filesystem | Host-initiated | **Reduced** | Direction is host→guest, so it is not an escape path. But the host must never open guest-controlled content through it. Export uses the host-pull design instead (§ARCHITECTURE), never this share. |
| **S11** | RDP redirection channels - drives, clipboard, printers, smart cards, USB, cameras, audio capture | Negotiated by the RDP client | **Eliminated by default, per-channel** | Every channel explicitly disabled in a controller-generated `.rdp`. See §6. |
| **S12** | The controller process itself | Parses guest stdout; holds config | **Reduced** | Unelevated; fixed argv; no shell; strict output caps and schemas; host-generated filenames only. |

---

## 6. Dangerous defaults inventory

Every one of these is *on* or *permissive* out of the box and must be explicitly turned off. This table is the checklist Stage 3 tests against.

### WSL

| Default | Risk | Action |
|---|---|---|
| `automount.enabled = true` | Entire `C:\` at `/mnt/c` with the host user's rights - total loss of A2/A3 | `false` |
| `interop.enabled = true` | Guest executes host binaries (S4) | `false` |
| `interop.appendWindowsPath = true` | Host PATH leaked into guest; eases S4 | `false` |
| `localhostForwarding = true` | Guest services on host loopback (S9) | `false` |
| `guiApplications = true` | Pulls in `/dev/dxg` + WSLg clipboard/audio (S3, S5) | `false` |
| `networkingMode` | `mirrored` gives the guest the **host's** network identity and host-loopback access - strictly worse | Pin to `nat`; never `mirrored` |
| Hyper-V Firewall `DefaultOutboundAction = Allow` `[MEASURED]` | Guest reaches host, LAN, router, NAS, dev servers | `Block` + explicit allowlist |
| `[user] default = root` in some images | Browser would run as root in the guest | Dedicated unprivileged user |
| `generateResolvConf = true` | Guest DNS silently forwarded through host resolver | Deliberate DNS design (§ARCHITECTURE) |

### RDP client (`mstsc`)

| Default | Risk | Action |
|---|---|---|
| `redirectclipboard:i:1` | Bidirectional clipboard - §8 violation | `0` |
| `drivestoredirect:s:*` | Host drives inside the guest - catastrophic | empty |
| `redirectprinters:i:1` | Printer channel (§6 forbids) | `0` |
| `audiocapturemode` / `camerastoredirect` / `usbdevicestoredirect` / `devicestoredirect` / `redirectsmartcards` / `redirectlocation` | Microphone, camera, USB, smart card, location bridged into the guest | all disabled/empty |

### Chromium

Defaults that must be overridden include: third-party cookies, notification/geolocation/camera/microphone/USB/Bluetooth/serial/sensor/filesystem prompts, popups, automatic downloads, metrics reporting, background mode, sign-in and Sync, network prediction, search suggestions, and extension installation. These are enforced through **managed policy files**, not command-line flags, because policies survive relaunch and are independently verifiable at `chrome://policy` (§48). Full policy set is Stage 4 work.

### Host application (Python)

| Default | Risk | Action |
|---|---|---|
| `subprocess` with `shell=True` | Command injection | Never used. `shell=False`, fixed absolute executable paths only. |
| Python on Windows builds a command **string** via `list2cmdline` even with `shell=False` `[DOC]` | **Argument injection** is still possible if any argument contains quotes or trailing backslashes | No guest-derived or website-derived string is ever passed as an argument. Identifiers are validated against strict patterns (e.g. distro names `^bm-[a-z0-9-]{1,32}$`). |
| Unbounded `stdout` read from the guest | Memory exhaustion by a compromised guest | Hard byte cap + timeout on every read. |

---

## 7. Isolation ≠ Privacy ≠ Anonymity

These are three different properties and the UI must never blur them.

| Property | What this project provides |
|---|---|
| **Isolation** | Strong. Protects the *host* from the *browser*. This is the main deliverable. |
| **Privacy** | Meaningful reduction of what sites collect and how well they link sessions. Not elimination. |
| **Anonymity** | **Not provided.** A VM does not hide your IP address. Websites see the same public IP as your host. Logging into any account identifies you completely, regardless of isolation. |

Any optional VPN or Tor support added later will be presented as clearly optional, with its own limitations documented, and will never be described as making the browser "anonymous."

Fingerprinting is handled by **reducing and stabilising** entropy, not randomising it - randomisation per request produces a distinctive "this user randomises" signal that is itself a fingerprint. Tradeoffs are Stage 4 work.

---

## 8. Supply chain (T6)

The build and install path is a security boundary, not a convenience.

- No dependency is added without a written reason; standard library preferred.
- Versions pinned; hashes recorded where the toolchain supports it; transitive dependencies reviewed.
- No `curl … | powershell` anywhere in build, install, or setup.
- The guest base image is built from a pinned distribution release with signature verification, and the built image is recorded by hash.
- Updates must be signature-verified against a pinned publisher and **fail closed**. No "download then execute."
- CI uses least-privilege tokens, actions pinned to commit SHAs, and never runs untrusted fork content with credentials.
- SBOM generated; dependency and secret scanning run in CI; serious findings fail the build rather than being suppressed.

---

## 9. Fail-closed rules

If any of these cannot be **positively verified**, the browser does not launch and the user is shown the specific failed check:

1. The expected distribution exists and is the expected one.
2. No host path is mounted in the guest.
3. Interop is disabled in the guest.
4. Hyper-V Firewall default outbound action is `Block` and the expected allowlist rules are present.
5. The generated `.rdp` has every redirection channel disabled.
6. The expected browser policy files are present with the expected content hash.
7. The browser is running as the expected unprivileged guest user.
8. MX-1 holds - the other mode's distribution is `Stopped`.

Check 4 is confirmed runnable by the unelevated runtime controller: reading Hyper-V Firewall rules and VM settings succeeds without elevation, while writing them is denied `[MEASURED]`. The privilege split therefore does not compromise the ability to verify.

**Every check must be measurable from the host.** After T4 the guest is a lying witness - asking a compromised guest to report its own mounts, its own firewall rules or its own browser policy and believing the answer is worthless exactly when it matters most. Where only a guest-side reading exists, the result is recorded as *unverified*, not as passing.

The dashboard shows measured state only. A check that has not actually been performed is displayed as *unknown*, never as passing. There is no "100% safe" indicator.

---

## 10. Residual risks - stated without hedging

1. **Hypervisor escape (S1).** No mitigation within this project.
2. **`wslservice.exe` escalation (S6).** A WSL control-plane vulnerability yields SYSTEM. This is the weakest structural point of the WSL2 backend and the main reason a Pro-SKU backend is worth considering.
3. **Windows kernel vulnerabilities** reachable from the reduced device surface.
4. **User-initiated export and execution (T8).** Exporting a file breaks isolation *for that file*, permanently and by design.
5. **Mode A ↔ Mode B separation is temporal, not spatial (TB-6).** It depends on MX-1 being correctly implemented and on `wsl --terminate` actually tearing the distro down.
6. **Compromised dependency, distro package, or update infrastructure (T6).**
7. **Fingerprinting and account-based identification.** Logging in defeats all of it.
8. **DNS and IP are not anonymised.**
9. **Firmware and hardware vulnerabilities.**
10. **Social engineering**, which no boundary in this document addresses.
