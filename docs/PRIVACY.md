# BRUHWSER - Privacy

**Date:** 2026-08-09 · Companion to `BRUHWSER-SECURITY.md` and `NETWORK-PRIVACY.md`.

Privacy and security are kept separate here on purpose (brief §44). A privacy feature is not a security feature, and neither one is anonymity.

**BRUHWSER makes no absolute privacy claim.** It does not make you impossible to fingerprint, and it does not make you anonymous.

---

## 1. What websites may learn

| Data | How | Reduced? | How much | Trade-off |
|---|---|---|---|---|
| Third-party cookies | embedded trackers | **Yes** | blocked by default | a few third-party logins need an exception |
| First-party cookies | the site you visit | Persistent: kept · **Disposable: destroyed** | full removal in disposable mode | signed out each session |
| localStorage / IndexedDB / service workers | any page | Persistent: kept · **Disposable: destroyed** | full | as above |
| Referrer | navigation | Partly - Edge's default trims cross-origin referrers to the origin | moderate | none noticeable |
| Location | Geolocation API | **Yes** | denied by default | map sites need a manual grant |
| Camera / microphone | getUserMedia | **Yes** | denied by default | calls need a manual grant |
| Notifications | Push API | **Yes** | denied by default | no site notifications |
| Motion sensors | Sensor APIs | **Yes** | denied by default | negligible on a PC |
| USB / Bluetooth / serial | WebUSB, Web Bluetooth, Web Serial | **Yes** | denied by default | those apps stop working |
| Clipboard | Async Clipboard API | **Yes** | denied by default | some paste buttons need a grant |
| Payment method presence | Payment Request API | **Yes** | `canMakePayment` disabled | sites fall back to normal checkout |
| **Local network IP** | WebRTC ICE candidates | **Yes** | `default_public_interface_only` closes the LAN-address leak without breaking calls | some P2P calls take a slower path |
| Public IP | every request | **No** | none | a VPN would shift this, not remove it |
| User-Agent, screen, timezone, locale, fonts, canvas, WebGL, CPU, memory | passive fingerprinting | **No - deliberately** | none | see §2 |

## 2. Fingerprinting: what BRUHWSER refuses to do, and why

The rule (brief §31): **a change that makes BRUHWSER more unusual is rejected**, because rarity is exactly what fingerprinting feeds on. A browser reporting four CPU cores, a 1000×1000 screen and a UTC timezone on a Windows laptop is *rarer* than one telling the truth.

| Rejected | Reason |
|---|---|
| **Disabling the browser password manager** | **MEASURED.** Chromium treats `credentials_enable_service` as a *tracked preference* and reverts an externally written value - three launches in a row confirmed it. That protection exists to stop malware silently reconfiguring the browser, and it is working correctly; fighting it would mean weakening a security feature for a privacy setting. The only alternative is machine-wide Edge policy, which would change every Edge profile on the PC. **If you want it off in persistent mode, turn it off inside Edge's own settings during a BRUHWSER session.** Disposable sessions discard it anyway. |
| User-Agent override | A non-standard UA is rarer than the real one and is contradicted by feature detection. Increases entropy. |
| Screen resolution spoofing | The reported size then disagrees with the actual window - itself a signal. |
| Timezone / locale spoofing | Contradicts HTTP language headers and observable latency. |
| Canvas / WebGL noise | Detectable as noise, and unstable output is a *stronger* identifier than a common GPU string. |
| `hardwareConcurrency` / `deviceMemory` spoofing | Cannot be applied consistently from outside the engine; partial spoofing is worse than none. |
| Disabling WebRTC entirely | Breaks video calling for a leak that `ip_handling_policy` already closes. |
| Disabling Safe Browsing | Trades real malware protection for a marginal metadata gain. |

What BRUHWSER does instead is turn off *collection surfaces* and turn on protections Edge already ships - configurations millions of Edge users share, so they do not single anyone out.

**Measured in Stage 6.** `tools/privacy_compare.py` compared 34 properties across a fresh stock-Edge profile and a bruhswer profile, using controlled local pages and no third-party tracking sites. Result:

```
ua  platform  languages  timezone  screen
hardwareConcurrency  deviceMemory  canvas  webgl     ALL 9 IDENTICAL TO STOCK EDGE
```

Seven properties differ, and **every one removes a collection surface rather than changing a reported value**: five permissions (prompt → denied), third-party cookies (allowed → blocked), and WebRTC candidates (1 → 0).

**So the claim bruhswer makes is:** it adds **no fingerprint entropy** on the measured surface, and it denies specific named APIs. It does **not** claim to make you harder to fingerprint than stock Edge - the entropy that identifies you is the same entropy Edge already exposes, and reducing that would require changing values, which would make you rarer instead.

**Limitations of that measurement:** probes ran headless, so `screen` reports headless's virtual 800×600 rather than your real display - valid as a relative comparison, not as a real-world value. The third-party cookie row uses two loopback host strings, which Chromium may treat as one site, so it is indicative rather than proof. Full detail in `STAGE-6-RESULTS.md` §5.

## 3. What local networks may learn

Covered in detail in `NETWORK-PRIVACY.md`. In summary: destination IP addresses, traffic timing, traffic volume and connection metadata remain visible to whoever runs the Wi-Fi, regardless of anything BRUHWSER does. HTTPS protects content. **DNS status is UNKNOWN** - a local resolver sits in the path and packet-level verification needs a driver this project will not install, so neither "encrypted" nor "leaking" is claimed.

## 4. What Microsoft may receive

BRUHWSER runs Edge, so Edge's own services apply. Being straight about this matters more than the marketing would prefer:

- **Safe Browsing / SmartScreen is left ON.** It sends URL metadata to Microsoft for malware and phishing checks. This is a **security** control and BRUHWSER does not disable it for a marginal privacy gain (brief §38). If that trade is unacceptable to you, it is a setting you can change - and you should know you are trading away malware protection.
- **Search suggestions are OFF**, so address-bar keystrokes are not streamed to a search provider.
- **Background networking and autorun services are disabled** at launch.
- Edge may still contact Microsoft for component and certificate updates. BRUHWSER does not attempt to block that; blocking a browser's update path would be a security regression.

## 5. What BRUHWSER itself collects

**Nothing.**

No telemetry, no analytics, no account, no synchronisation, no server, and no network requests of its own. Local logs record timestamps, event names, check IDs, verdicts, rule names and error codes - never URLs, page contents, cookies, tokens, passwords, form data or history. The log formatter redacts anything URL-shaped or secret-shaped even if a caller passes it by mistake. The logs are files on your disk; delete them whenever you like.

## 6. If you use a VPN

VPN mode is currently **UNSUPPORTED** - no VPN is configured and a kill switch has not been demonstrated, so BRUHWSER will not pretend to offer one.

If one is added later, these hold: the VPN provider becomes a new party that can see your destination traffic; a VPN does not make you anonymous; websites can still identify you; traffic metadata still exists; and logging into any account identifies you completely regardless.

## 7. What disposable mode removes - and what it cannot

**Removed** (the profile directory is deleted and the deletion is verified): cookies, cache, localStorage, IndexedDB, service workers, site permissions, browsing history, session data, form data - **and anything still sitting in that session's quarantine**.

That last item was previously false. Until 0.9.0, destroying a disposable session removed the profile and reported "destroyed and verified gone" while leaving every file downloaded during that session on disk permanently, under `quarantine\<session id>`. Nothing ever cleaned them up, and because the quarantine panel only lists the *current* session, they were unreachable from the UI while remaining perfectly readable on disk. They are now destroyed with the session, and orphans left behind by a crash are swept at the next start.

### A disposable session is fresh. It is **not** anonymous.

**Measured 2026-08-10, on a brand-new windowed profile:** Edge signs the profile into
the Windows Microsoft account by itself, within seconds of launch. The `account_info`
record - email, full name, account id, tenant id - is written to the profile, the
user's synced favourites appear on the bookmarks bar, and `sync_consent_recorded`
becomes true.

bruhswer passes `--disable-sync`. Measured on a fresh profile, twice:

| | account record | sync consent |
|---|---|---|
| without the flag | present, with email | **recorded** |
| with the flag | still present | not recorded |

So the flag **stops the syncing** and is worth having. It does **not** stop the
sign-in, and nothing on the command line does. The only mechanism that does is
machine-wide Edge policy (`BrowserSignin=0`), which would change every Edge profile on
the PC - far broader than bruhswer is permitted to be, for the same reason it refuses
to write enterprise policy anywhere else.

**This is reported, never hidden.** `privacy_guard.verify_account_signin()` reads the
profile at every launch and the BRUH CHECK panel shows `NOT ENFORCEABLE` whenever an
account is present. It never shows green while you are signed in. The email itself is
never logged or displayed - only the fact that an account exists.

**What you can do about it:** sign out inside the bruhswer session, in Edge's own
**Settings → Profiles**. In a disposable session that has to be done each time,
because the profile is new every time.

Because closing a disposable session **deletes downloads**, bruhswer asks first. Closing one with files in quarantine shows a dialog listing exactly what is about to go, so you can export anything you want to keep. Choosing to keep the session leaves everything untouched.

**Not removed, and not claimed:**

- files you exported from quarantine on purpose
- anything the site already sent to its own servers
- Windows-level artefacts outside the profile folder
- forensic recovery of deleted disk blocks

If deletion fails, BRUHWSER reports the failure and says how many items remain. It never claims a session was destroyed when it was not.

**Disposable mode is a privacy and session-isolation mechanism. It is not a sandbox and it is not a VM.** It gives a website a fresh empty profile and throws it away. It does not stop a browser exploit.
