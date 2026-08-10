# Stage 4 Architecture - Windows application isolation backend

**Date:** 2026-08-09 · **Status:** revised against measurement. The architecture the Stage 4 brief proposed did not survive gate A2; what follows is what the evidence supports.

**This is not a VM and must never be described as one.** It does not protect against every Windows kernel vulnerability, and OS-level application isolation is a materially weaker boundary than a correctly configured hardware-virtualized VM.

---

## 1. What the brief proposed, and what measurement did to it

Brief §6 named **Windows AppContainer as the primary OS-level boundary** around the browser process tree. Gate A2 measured that this is not possible on this machine:

- **Chrome** dies in 3.6 s with a Crashpad `CHECK` on `CreateNamedPipe: Access is denied` - identically with `--disable-breakpad`, `--disable-gpu`, and `--no-sandbox`.
- **Edge** dies reproducibly at 7.8-8.7 s with `STATUS_ACCESS_VIOLATION`, again identically across all three variants. Cause unestablished.
- A trivial program (`curl.exe`) runs fine in the same container, so the harness is sound.

Because `--no-sandbox` changes nothing, this is **not** a conflict with Chromium's own sandbox - the AppContainer is simply incompatible with a Chromium browser process.

**Consequence: the architecture has no outer container.** Every claim about "Windows application isolation wrapping the browser" is withdrawn.

## 2. Trusted computing base

| Component | Classification |
|---|---|
| Windows kernel | **Trusted.** Every boundary here is one of its boundaries. |
| Windows Firewall / WFP | **Trusted, and measured effective for remote addresses** (A16), **tamper-resistant** (A17) |
| Microsoft Defender + Controlled Folder Access | **Trusted, measured active**, partial write protection (A4) |
| Chromium browser process (broker) | **UNTRUSTED in effect, but unconstrained** - the central contradiction of this backend |
| Chromium renderer processes | **Untrusted and genuinely constrained** (A3) |
| Web content | **Untrusted** |
| Host controller (not built) | would be trusted and must be minimal |

## 3. Base browser selection - **Microsoft Edge**

Chosen on two measured grounds, not preference:

| | Edge 151.0.4129.72 | Chrome 151.0.7922.76 |
|---|---|---|
| Renderer token (A3) | **AppContainer + UNTRUSTED + restricted** | restricted + UNTRUSTED, **not AppContainer** |
| Authenticode | Valid, `CN=Microsoft Corporation` | Valid, `CN=Google LLC` |
| Supply chain | **In-box, serviced by Windows Update - already in this machine's TCB** | Third-party updater |
| A2 behaviour | fails at ~8 s | fails at ~3.6 s |

Edge's renderers hold a **strictly stronger token**, and it adds no new supply-chain trust root - the same criterion that decided B17 against QEMU. Neither browser is modified; no browser engine is written (brief §7).

## 4. The architecture that the evidence actually supports

```
   Windows host (user session, MEDIUM integrity, local admin, UAC-filtered)
   │
   ├── Controller (NOT BUILT - see §7)
   │
   └── Microsoft Edge, launched with a dedicated profile
         │
         ├── browser process   MEDIUM integrity, ordinary user token
         │                     *** NOT CONTAINED - A2, A4-A7 ***
         │
         ├── renderers         AppContainer, UNTRUSTED, 0 privileges   [A3]
         ├── gpu-process       LOW integrity                            [A3]
         └── utility           MEDIUM / UNTRUSTED depending on role     [A3]

   Host-side controls that DO work and that the browser cannot edit:
     · Windows Firewall outbound Block, -Program scoped   -> remote LAN   [A16 PASS]
     · administrator-owned firewall policy                -> tamper-proof [A17 PASS]
     · Defender Controlled Folder Access                  -> Documents writes [A4]
     · dedicated profile directory, ACL'd to the user only

   Host-side controls that are NOT AVAILABLE:
     · anything covering 127.0.0.1 or the host's own IP    [A16 FAIL]
     · any container around the browser process            [A2 FAIL]
```

## 5. Network design - the one part that works, and its exact limit

Stage 2.5 designed two complementary host-side layers because each covered the other's gap:

| Layer | Covers | Status now |
|---|---|---|
| AppContainer, `internetClient` only | loopback + host's own IP | **GONE** - A2 removed it |
| Firewall outbound deny, `-Program` scoped | remote LAN, internet preserved | **WORKS** - A16 PASS, A17 tamper-resistant |

**The surviving layer cannot cover the lost layer's gap.** A16 measured it directly: with rules explicitly naming `127.0.0.1` and `10.0.0.50`, confirmed present by readback, Edge still reached both. Windows Firewall does not filter loopback, and the host's own address is delivered over the loopback path.

Measured policy outcome against brief §20:

```
Browser -> Internet          ALLOWED    [A16, preserved throughout]
Browser -> Router            DENIED     [A16 PASS, ERR_NETWORK_ACCESS_DENIED]
Browser -> LAN devices       DENIED     [A16 PASS, same rule]
Browser -> Host services     REACHABLE  [A16 FAIL - SMB 445, RPC 135, NetBIOS 139]
Browser -> localhost         REACHABLE  [A16 FAIL]
Browser -> Development apps  REACHABLE  [A16 FAIL - live PyCharm service on 63342]
Browser -> IPv6              UNKNOWN    [A13 - no global IPv6 path on this network]
```

Four of the eight required denials are not achievable.

## 6. Filesystem design

A dedicated profile directory (`%LOCALAPPDATA%\<Project>\BrowserData`), ACL'd narrowly, keeps browser state out of the user's own browser profiles and gives disposable/persistent separation a place to live. **It does not confine the browser** - A4 measured that the browser-process token reads the whole user profile regardless of where its own data lives. The directory is hygiene, not a boundary, and must be described that way.

One rule adopted from A2's implementation and worth keeping permanently: grants go to a **specific SID**, never to `ALL APPLICATION PACKAGES` (`S-1-15-2-1`), which would grant every AppContainer on the machine.

## 7. Controller - deliberately not built

Brief §65 says to build only the minimum harness needed for A1-A34 and stop. Once A2, A4-A7 and A16 had established that the boundary a controller would manage does not exist, building one would have produced a component that verifies and reports a boundary that is not there - which brief §50 correctly calls a vulnerability in its own right.

The design constraints stand for whenever one is built: unelevated at runtime; fixed verb set (`START`, `STOP`, `STATUS`, `VERIFY`); no `execute_command`/`run_shell`/`run_powershell`; no `shell=True`, `eval` or `exec`; explicit argv arrays; nothing derived from a URL, header, filename or downloaded content; named-pipe IPC with strict ACLs rather than a localhost HTTP API, because **localhost is not trusted here - A16 proved a hostile browser can reach it.**

## 8. Fail-closed

The rule from brief §27 and §50 applies with unusual force given these results: a security indicator may only report **verified** state. On this backend an honest indicator would have to read:

```
NETWORK (remote LAN)  : VERIFIED
NETWORK (localhost)   : NOT PROTECTED
FILESYSTEM            : NOT PROTECTED
CREDENTIALS           : NOT PROTECTED
DNS                   : UNKNOWN
ISOLATION             : RENDERER ONLY
```

Displaying "Protected", "Secure", "Sandboxed" or "Private" on this architecture would be false.

## 9. Honest summary

**What this architecture genuinely provides:** an unmodified, Microsoft-signed Chromium browser whose renderers are strongly sandboxed by Chromium itself; host-side network policy that blocks the router and LAN devices and that a compromised browser cannot remove; a dedicated profile; and no weakening of any Windows protection.

**What it does not provide:** any boundary around the browser process. Host files, credentials, registry, same-user process memory, localhost and host services are all reachable once the browser process is compromised - which is precisely the scenario the project was built to survive.

**Compared with the VM designs:** materially weaker, on the specific axis the project cares most about. The security target has not been met and has not been quietly redefined.
