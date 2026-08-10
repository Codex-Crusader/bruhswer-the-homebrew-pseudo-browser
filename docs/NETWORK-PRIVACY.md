# Network Privacy - what is protected, what is not, and what is merely unknown

**Date:** 2026-08-09 · Evidence: `STAGE-4-VERIFICATION.md` gates A10-A24, A34.
**Measured on:** SSID `CampusWiFi`, network category **Public**, host `10.0.0.50/22`, gateway `10.0.0.1`, IPv6 connectivity `NoTraffic`.

This document covers three different problems that must not be collapsed into one: what the **browser** can reach (Threat Model A), what the **network operator** can see (B), and what **other devices on the Wi-Fi** can reach on this machine (C).

---

## 1. HTTPS

Used by default; certificate validation is Chromium's own and is left untouched.

**Hard rules, held (brief §35, §36):** no custom root CA is installed, no HTTPS interception, no MITM proxy, no certificate substitution, no TLS verification disabled. **This project does not decrypt the user's traffic and must never become its own surveillance proxy.**

## 2. DNS - **UNKNOWN**, and the reason is specific

| Fact | Evidence |
|---|---|
| Windows has 12 DoH templates registered (Quad9, Google, Cloudflare, v4+v6) | `[MEASURED]` |
| **Auto-upgrade is `no` on every one of them** | `[MEASURED]` `netsh dns show encryption` |
| Configured resolvers: `8.8.8.8, 4.2.2.2, 1.1.1.1, 139.5.47.155` | `[MEASURED]` |
| `4.2.2.2` and `139.5.47.155` have **no DoH template at all** | `[MEASURED]` |
| Plaintext DNS on UDP/53 is answered by `139.5.47.155` and `8.8.8.8` | `[MEASURED]` |
| **NextDNS runs locally** (`NextDNS.exe`, listening `127.0.0.1:65008`) | `[MEASURED]` |
| Cloudflare's diagnostic reports `DoH: No`, `Connected to 1.1.1.1: No` | `[MEASURED]`, page confirmed settled |

**A18 (secure DNS) = UNKNOWN** and **A19 (plain DNS leakage) = UNKNOWN.** They are the same unresolved question approached from two sides, so they get the same verdict.

*What is measured:* a working plaintext DNS path exists, is answered, and Windows is not configured to avoid it.

*What is not established:* whether the browser actually uses it. The Cloudflare result does **not** prove the browser's DNS is unencrypted, because NextDNS sits in the resolver path and Cloudflare can only report on queries that reach Cloudflare - NextDNS may well use an encrypted upstream. A definitive answer needs packet capture, which requires installing a capture driver, forbidden by the project's constraints. **Neither "encrypted" nor "leaking" is established, and under §31 UNKNOWN is not a pass.**

**Where DoH can and cannot be a control (brief §28):**

- **Browser-level DoH is a browser setting.** A compromised browser process turns it off. It is the same defect class as a guest-side firewall, and it is therefore defence for Threat Model B only - **never** a boundary for Threat Model A.
- **OS-level DoH** would be host-side and tamper-resistant, but enabling it is a **system-wide change to the user's network stack**, which brief §33 forbids making blindly. It is offered as a user decision in §6 below, not applied.

## 3. Encrypted DNS is not anonymity (brief §29)

Encrypted DNS does **not** hide: destination IP addresses, traffic timing, traffic volume, connection metadata, TLS SNI in many configurations, browser identity, or account identity. A network operator watching this connection still learns which servers are contacted and when. **No anonymity claim is made anywhere in this project.**

## 4. What the browser can reach - measured

```
Browser -> Internet          ALLOWED    preserved under all rule sets   [A16]
Browser -> Router            DENIED     ERR_NETWORK_ACCESS_DENIED       [A16 PASS]
Browser -> LAN devices       DENIED     same rule                       [A16 PASS]
Browser -> Host SMB 445      REACHABLE  TCP connect confirmed           [A16 FAIL]
Browser -> Host RPC 135      REACHABLE  TCP connect confirmed           [A16 FAIL]
Browser -> NetBIOS 139       REACHABLE  TCP connect confirmed           [A16 FAIL]
Browser -> localhost         REACHABLE  no mechanism can block it       [A16 FAIL]
Browser -> PyCharm 63342     REACHABLE  a real, live service            [A16 FAIL]
Browser -> IPv6              UNKNOWN    no global IPv6 path here        [A13]
```

**The remote half works and is tamper-resistant** - A17 measured that the browser-process token cannot create, delete or disable firewall rules through either the `NetSecurity` cmdlets or `netsh` ("The requested operation requires elevation").

**The local half cannot be fixed within this architecture.** Windows Firewall does not filter loopback, and traffic to the host's own address travels the loopback path. Stage 2.5 covered this with an AppContainer; gate A2 measured that a Chromium browser cannot run in one.

## 5. VPN - **UNSUPPORTED**

No VPN is configured, and brief §60 forbids hard-coding or recommending a provider. A kill switch could not be demonstrated, so per brief §31:

```
VPN MODE = UNSUPPORTED
```

**Precondition that was measured:** program-scoped rules genuinely block the browser's remote traffic (A16) and cannot be removed by it (A17), so a kill switch built on that mechanism - deny all remote addresses except the VPN endpoint and tunnel interface - rests on a mechanism measured to work. That is a **measured precondition, not a measured kill switch.**

**If a VPN is added later, these must be stated:** the VPN provider becomes a new trust party that can see destination traffic; a VPN does not provide anonymity; and a kill switch must be enforced host-side, never inside the browser, because the browser is assumed compromised.

**Performance (brief §32):** no VPN was measured, so no bandwidth or latency figures are claimed. Standard mode must remain usable without a VPN on a 25 Mbps connection, and nothing in the working part of this design (firewall rules) adds measurable overhead.

## 6. Host exposure on untrusted Wi-Fi - Threat Model C

Measured on the Public profile (`[MEASURED]` unless noted):

```
Listening on WILDCARD (LAN-reachable):
  135 svchost   445 System   5040 svchost   30002 ToolkitService
  49664 lsass   49665 wininit   49666/49667 svchost   49668 spoolsv
  49669 SeagateSecureService   49670 services
Listening on 10.0.0.50:  139 System
LanmanServer Running · SMB2 on · RequireSecuritySignature FALSE · SigningEnabled FALSE
Shares: ADMIN$, C$, IPC$
File and Printer Sharing: 17 of 17 Public-profile rules ENABLED
Network Discovery: 0 of 22 enabled     Remote Desktop: 0 rules
```

**Whether a peer on this Wi-Fi can actually complete a connection to 445 was NOT tested** - that would need scanning (forbidden, §22/§25) or a second device. Listening state and enabled rules are measured; LAN reachability is `[INFERRED]`.

**No change was made.** Brief §33 forbids blindly reconfiguring the user's network stack. These are narrow, reversible options for the user to decide on:

| Option | Effect | Reversible |
|---|---|---|
| Disable **File and Printer Sharing** for the **Public profile only** | removes SMB/NetBIOS inbound on untrusted networks; home/office unaffected | yes, per-profile rule group |
| Enable **SMB signing** (`RequireSecuritySignature`) | raises the cost of SMB relay | yes |
| Review `SeagateSecureService` and `ToolkitService` (port 30002) | third-party services listening on the wildcard | vendor-dependent |
| Keep the network marked **Public** | already correct - Windows applies the restrictive profile | n/a |

**Not recommended:** disabling unrelated Windows services, or anything touching Defender, SmartScreen, Secure Boot, VBS, HVCI or the firewall itself.

## 7. Claims this project does NOT make

Directly per brief §58, and now backed by measurement rather than caution:

- **Not** "you cannot get infected."
- **Not** "malware cannot escape." A4-A7 measured that a compromised browser process reaches host files, credentials and registry.
- **Not** "the university cannot see your browsing." Destination IPs, timing and volume remain visible; DNS status is UNKNOWN.
- **Not** "you are anonymous."
- **Not** "the browser is sandboxed from Windows." Only its **renderers** are, and that is Chromium's doing.

## 8. Claims that the evidence does support

- "The browser's renderer processes run in Windows AppContainers at untrusted integrity with no privileges." `[A3]`
- "The browser is blocked from reaching the router and other devices on the local network." `[A16]`
- "Those network restrictions cannot be removed by the browser itself, because firewall policy requires administrator rights the browser does not have." `[A17]`
- "No Windows security feature is disabled or weakened by this project." `[A34]`
- "The browser cannot write to your Documents folder, because Windows Controlled Folder Access blocks it." `[A4]`

Each of those is narrow, and each is true.
