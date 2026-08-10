# BRUHWSER - Security

**Date:** 2026-08-09 · **Status:** current. This describes the implemented product.
Superseded designs are preserved in `PROJECT-HISTORY.md`; the Stage 1 `SECURITY.md`, `ARCHITECTURE.md` and `THREAT-MODEL.md` describe the rejected WSL2 architecture and are kept as evidence, not as guidance.

---

## 1. What BRUHWSER does NOT guarantee

Stated first, and in full, because every previous stage of this project was killed by a claim that turned out to be untrue.

BRUHWSER does **not** guarantee:

- immunity from malware
- immunity from browser exploits
- immunity from Windows kernel exploits
- **VM-level isolation** - it is not a VM, it is not equivalent to Hyper-V, and it must never be described as either
- anonymity
- invisibility from network operators
- protection against a fully compromised Windows host
- protection against AppContainer escapes or privilege escalation
- protection against malicious signed software

**It does not guarantee that a compromised browser process cannot compromise Windows.** That is the honest headline, and it follows from a measurement, not from caution.

## 2. What BRUHWSER does aim to do

- reduce browser-to-host exposure
- reduce LAN exposure, in both directions
- reduce tracking and persistent browser state
- reduce unnecessary information disclosure
- keep downloads out of the user's real folders until they choose otherwise
- provide **measurable** security controls
- **fail closed** when a critical control cannot be verified

## 3. The boundary, precisely

```
        web content
   ═══════╪═══  Chromium renderer sandbox   <-- THE ONLY REAL PROCESS BOUNDARY
           │     AppContainer token, UNTRUSTED integrity, 0 privileges  [A3]
           ▼
     Edge browser process (broker)
   ┅┅┅┅┅┅┅╪┅┅┅  *** NO BOUNDARY HERE ***
           │     ordinary user token, MEDIUM integrity                  [A4]
           ▼
     Windows user session
   ═══════╪═══  firewall -Program rules: hold for REMOTE addresses      [A16]
           │     and the browser cannot delete them                      [A17]
           │     they do NOT cover loopback or this PC's own IP          [A16]
           ▼
     Windows kernel  (trusted; not defended against)
```

The dashed line is drawn dashed on purpose. In the WSL2 and Hyper-V designs that position held a hypervisor. Here it holds nothing, and no amount of configuration puts something there - Stage 4 gate A2 measured that neither Edge nor Chrome survives inside a project-created AppContainer, identically with `--no-sandbox`, so it is not a conflict with Chromium's own sandbox.

## 4. Controls that are real, with the measurement behind each

| Control | Evidence | Verdict |
|---|---|---|
| Renderer sandboxing | Edge renderers hold AppContainer tokens, UNTRUSTED integrity, 0 privileges | A3 `[MEASURED]` |
| Browser cannot reach router or LAN | `REACHED → BLOCKED → REACHED`, `ERR_NETWORK_ACCESS_DENIED`, internet unaffected, other programs unaffected | A16 **PASS** |
| Browser cannot delete its own network rules | both `NetSecurity` cmdlets and `netsh` refuse without elevation | A17 **PASS** |
| No Windows protection is weakened | Defender, tamper protection, CFA, VBS, HVCI, all firewall profiles intact | A34 **PASS** |
| Writes to Documents are blocked | Defender Controlled Folder Access, confirmed by event ID 1123 | A4 `[MEASURED]` |
| Browser runtime is authentic | Authenticode `Valid`, `CN=Microsoft Corporation`, checked at every launch | verified per launch |

## 5. Controls that are NOT achievable, and why

| Wanted | Reality |
|---|---|
| Block browser → `127.0.0.1` | **Impossible.** Windows Firewall does not filter loopback. Rules naming it were measured not blocking Edge (A16). |
| Block browser → this PC's own IP | **Impossible**, same mechanism. Host SMB (445), RPC (135) and NetBIOS (139) are TCP-reachable from the browser. |
| Block browser → local dev services | **Impossible**, same mechanism. A live PyCharm service on 63342 was confirmed reachable. |
| Contain the browser process | **Impossible** on this SKU (A2). |
| Prove DNS is encrypted | **UNKNOWN.** A local resolver (NextDNS) sits in the path and packet capture needs a driver this project will not install. |
| IPv6 egress isolation | **UNKNOWN** on the measured network - it has no global IPv6 path to test against. Rules are written for `fc00::/7` and `fe80::/10` but their effect is unverified. |

Each of these is displayed in the UI as `NOT ENFORCEABLE` or `UNKNOWN`. None is ever shown green.

## 6. Fail-closed

The browser does not launch unless every **critical** check returns `PASS`. `UNKNOWN` blocks exactly like `FAIL`, because a control that could not be checked is not a control that is present.

Critical checks: browser present, browser signature valid, profile inside BRUHWSER, profile separate from the user's real browser data, no security-weakening flags, exactly one profile argument, both firewall rules present and correctly scoped, no unrecognised rules under BRUHWSER's prefix, and BRUHWSER itself running unelevated.

There is no "continue anyway" button, and nothing reachable from web content can disable any of this.

**One deliberate exception:** a control that is *known impossible* (loopback) does not block launch. It is shown permanently as `NOT ENFORCEABLE`. Blocking startup forever would change nothing about the user's exposure while making the product unusable, and dishonesty by omission is the failure mode this project cares about - so it is shown loudly instead.

## 7. Privilege

BRUHWSER runs **unelevated**, and refuses to launch a browser if it finds itself running as Administrator - an elevated browser is a worse outcome, not a better one.

Elevation exists only in two one-shot scripts under `tools/`, which are never invoked by the app and never reachable from browser content. Each prints its exact change list, requires a typed confirmation word, records the previous state before touching anything, and has a matching revert. The host-guard rollback record is never overwritten once written, so a revert restores the true original state rather than an intermediate one.

## 8. Code-level rules, enforced by tests

No `execute_command`, `run_shell`, `run_powershell`, `eval`, `exec`, `compile`, `os.system`, `os.popen`, or `pickle.load`. No dispatcher mapping a string to code. `subprocess` always receives an explicit argument list, never a string; `shell=True` appears nowhere.

These are checked by `tests/test_security.py`, which parses every source file with `ast` rather than grepping - the first version of that test produced a false positive on the *sentence* promising `shell=True` is unused, which is a good illustration of why text search is not verification. The suite also fails if it scanned fewer than ten files.

Untrusted input is handled by construction, not by filtering: download filenames are rebuilt from scratch rather than escaped, so traversal, UNC paths, drive letters, alternate data streams, reserved device names and null bytes are removed as a class. Export destinations come from the user's own folder picker and can never come from a webpage. Session IDs are generated by BRUHWSER and validated as 16 hex characters before any deletion, and a recursive delete refuses any path outside the disposable profile or quarantine root - and refuses a **reparse point** outright, so a directory junction planted under either root cannot redirect the delete somewhere else. (`Path.is_symlink()` is not the check: it returns `False` for a Windows junction, so the file-attribute test is used instead.)

## 9. Supply chain

| Component | Trust root | Note |
|---|---|---|
| Microsoft Edge | Microsoft, via Windows Update | already in this machine's TCB; signature verified at every launch |
| Python 3.11 standard library | python.org | already installed |
| tkinter | ships with Python | no new dependency |
| BRUHWSER itself | local source | no updater, no network calls of its own |

**Zero third-party packages.** This is deliberate: the QEMU backend was rejected at gate B17 precisely because it added a trust root the machine did not already depend on. BRUHWSER adds none.

## 10. Logging and telemetry

Logs record timestamps, event names, check IDs, verdicts, rule names and error codes. They never record URLs, page contents, cookies, tokens, passwords, form data or browsing history - and the formatter redacts anything URL-shaped or secret-shaped even if a caller passes it by mistake.

**There is no telemetry.** BRUHWSER has no server, no account system, no synchronisation, and makes no network requests of its own.

## 11. Residual risks

1. **No boundary around the browser process.** The largest risk, and it is structural.
2. **Loopback and host-own-IP are reachable** by a compromised browser, with no available mitigation.
3. **DNS status is UNKNOWN.**
4. **The account is a local administrator** (UAC-filtered). A17's tamper resistance depends on UAC, so a successful elevation or a socially-engineered prompt defeats it. Running as a standard user would strengthen this materially.
5. **Privacy settings are written to Chromium's `Preferences` file.** Chromium owns that file and may normalise or ignore entries, which is why BRUHWSER reads them back and reports how many actually stuck rather than assuming.
6. **Host inbound exposure** persists until the user chooses to run Host Guard's remediation.
7. **Disposable sessions delete files.** They do not guarantee that disk blocks are unrecoverable, nor that Windows kept no artefact elsewhere.
8. **Host Guard's "unexpected listening services" check is a delta, not a detector.** It compares wildcard-bound ports against a baseline of standard Windows services observed on one machine. It will flag genuinely unusual listeners, but it is not a general-purpose service audit, and a port absent from its baseline is not automatically malicious.
9. **The browser password manager is not disabled.** Chromium reverts external changes to `credentials_enable_service`, which is correct anti-tampering behaviour. See `PRIVACY.md` §2.
10. **Fingerprint comparison has now been run** (Stage 6). All 9 identity values measured - UA, platform, languages, timezone, screen, hardware concurrency, device memory, canvas, WebGL - are **identical to stock Edge**, so bruhswer adds no fingerprint entropy. It still makes **no claim of reduced fingerprintability**: the entropy that identifies a user is Edge's, and reducing it would mean changing values, which would make the configuration rarer. See `STAGE-6-RESULTS.md` §5 for the measurement and its limitations.
11. **Downloads were not actually quarantined until Stage 6.** bruhswer passed `--download-directory`, which is not a real Chromium switch; Edge ignored it silently and downloads went to the user's real Downloads folder, while every test still passed. It is now a profile preference, verified as a **critical** check on every launch. Recorded here rather than quietly fixed, because the failure mode - a feature verified only against its own stated intent - is exactly what this project has to keep watching for.

## 12. Reporting a vulnerability

Especially wanted: anything that lets a webpage reach the host filesystem, execute host code, escape the quarantine flow, reach the controller, or **cause BRUHWSER to display a control as active when it is not**. That last category counts as a vulnerability in its own right - a security indicator that lies is worse than no indicator.
