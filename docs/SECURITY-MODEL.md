# Security model

**Status: current.** What bruhswer defends against, what it verifies, what it refuses
to claim, and what the four verdicts mean.

For *how to report* a vulnerability, see [`/SECURITY.md`](../SECURITY.md).
For *how to test*, see [`SECURITY-TESTING.md`](SECURITY-TESTING.md).
For the long-form version of this document, see
[`BRUHWSER-SECURITY.md`](BRUHWSER-SECURITY.md).

---

## 1. Verdict semantics

This is the core of the design, so it comes first.

| Verdict | Meaning | Shown as |
|---|---|---|
| `PASS` | Measured, and the property holds. | green |
| `FAIL` | Measured, and the property does not hold. | red |
| `UNKNOWN` | bruhswer could not establish the state. **Not** a pass. | amber |
| `NOT ENFORCEABLE` | The platform cannot provide this guarantee. No configuration fixes it. | amber, never green |

Two rules follow from this, and they are the whole project:

1. **A critical check that is not `PASS` blocks launch.** `UNKNOWN` blocks. There is no
   override, no "continue anyway" button, and no environment variable that disables
   verification.
2. **`NOT ENFORCEABLE` never renders green and never blocks.** Blocking on a permanent
   platform limitation would just mean the application never starts, so it is reported
   permanently and prominently instead.

> **A false verdict is a vulnerability here, not a documentation bug.** If bruhswer
> reports something as verified, blocked or enforced when it is not, that is in scope
> for a security report. Every serious defect this project has found in itself was of
> that shape.

---

## 2. Threat model

### Who bruhswer defends against

| Adversary | Capability assumed | Defended? |
|---|---|---|
| **A malicious website** | Runs arbitrary script in a renderer; may attempt drive-by download, LAN/router access, permission abuse, fingerprinting | **Partly.** This is the primary adversary |
| **A hostile file you downloaded** | Sits on disk waiting to be run | **Partly.** Quarantined, never executed, never auto-opened. bruhswer does not claim it is safe |
| **Another device on the same network** | Scans and connects to this PC | **Partly.** Host Guard detects exposure and offers narrow, reversible fixes |
| **A passive network observer** | Sees traffic on the Wi-Fi | **Barely.** HTTPS protects content. Destination IPs, timing and volume remain visible, always |
| **A compromised Edge renderer** | Code execution inside the sandbox | **Relies on Edge.** Renderers run AppContainer / UNTRUSTED integrity, measured live |
| **A compromised Edge browser process** | Code execution as the user | **No.** Explicitly out of scope, see below |
| **Malware already running as you** | Full user-token access | **No.** Cannot be defended by a user-mode process |
| **A local Administrator** | Everything | **No.** This is Windows' model |
| **Physical access to an unlocked machine** | Everything | **No.** |

### The boundary that is actually ours

```
hostile page -> renderer          Edge's boundary. Report Chromium bugs to Microsoft.
renderer     -> browser process   Chromium's boundary. The broker is NOT sandboxed.
browser      -> bruhswer          OURS.
bruhswer     -> Administrator     OURS.
```

The interesting question, and the one worth attacking, is: **what can a compromised
browser process, running as the user, do to or through bruhswer?** The answer is meant
to be "very little", because bruhswer opens no endpoint and lets no browser-controlled
value reach a path, an argv element or a PowerShell string.

---

## 3. What is actually verified

Each of these is measured at runtime, on the machine it runs on, not inferred from
documentation.

| Guarantee | How it is established |
|---|---|
| **Fail-closed startup** | ~29 checks run before launch; any critical non-PASS blocks it |
| **The browser is the one we expect** | Authenticode signature and signer checked at every launch, from a fixed absolute path never resolved via `PATH` |
| **Renderer sandbox** | Process tokens of the live renderers are read. Integrity level and AppContainer membership are measured, not asserted |
| **Router and LAN unreachable from the browser** | Program-scoped Windows Firewall rules; probed with the same `msedge.exe` the rule names, verdict taken from the DOM |
| **The browser cannot undo those rules** | The browser's token cannot create, delete or disable them without elevation |
| **No security-weakening browser flags** | `DANGEROUS_FLAGS` are refused by `build_command`, not filtered out |
| **Profile confinement** | Path checked against the data root; ACLs applied then proved with a real write/read probe, because a zero exit code is not evidence |
| **Downloads quarantined** | Set as a profile preference and **read back**; verified against a real download by a real browser |
| **Disposable destruction** | Profile and its quarantine deleted, then re-checked; leftovers are reported, never assumed away |
| **Privacy settings applied** | Written, then read back out of the profile. Settings Chromium reverts are reported as not applied |
| **bruhswer opens no local endpoint** | AST scan of the source plus a runtime check of the process's own listening sockets |
| **No dangerous primitives** | AST scan: no `eval`, `exec`, `os.system`, `shell=True`, `pickle`, no generic execution verb |
| **bruhswer runs unelevated** | Queried from the OS at every launch; running as Administrator is a `FAIL` |

---

## 4. What bruhswer does not guarantee

Stated plainly. None of these is a bug, and all are reported in the product itself.

| Non-guarantee | Verdict shown | Why |
|---|---|---|
| **Localhost / loopback isolation** | `NOT ENFORCEABLE` | Windows Firewall does not filter loopback. Measured 19 ways; every one reached |
| **Anonymity, or a session unlinked from you** | `NOT ENFORCEABLE` | Edge signs profiles into the Windows Microsoft account by itself, including disposable ones |
| **Encrypted DNS** | `UNKNOWN` | Cannot be confirmed without a packet-capture driver this project will not install |
| **Full IPv6 parity** | Partly verified | What was testable was tested; the rest says so |
| **VPN or traffic origin control** | `UNSUPPORTED` | None is configured and no kill switch has been demonstrated |
| **VM isolation** | Not provided | Tried, measured, rejected. See [`PROJECT-HISTORY.md`](PROJECT-HISTORY.md) |
| **Browser-process isolation** | Not provided | Chromium's sandbox contains renderers, not the broker |
| **Malware detection** | Not provided | Quarantine means a file was not let out. It does not mean the file is safe |
| **Fingerprinting resistance** | Not claimed | bruhswer adds no entropy; it does not make you harder to fingerprint than stock Edge |
| **Encryption at rest by bruhswer** | Not provided | A documented trade-off, not an oversight |
| **Signed release artifacts** | Not provided | No certificate exists. Self-signing and calling it trusted was refused |

Full detail, with the measurements: [`LIMITATIONS.md`](LIMITATIONS.md).

---

## 5. Data

Everything bruhswer writes lives under `%LOCALAPPDATA%\BRUHWSER`. No registry keys, no
`ProgramData`, no service, no scheduled task, no startup entry. The installer
additionally makes the ordinary per-user uninstall registration and the shortcuts you
choose.

There is **no telemetry**, and there is no network client anywhere in bruhswer's own
code, so it cannot phone home even by accident.

Logs record timestamps, check IDs, verdicts, rule names and PIDs. Never URLs, cookies,
form data, history or download contents - and the formatter redacts anything that looks
like a URL, an email address or a secret before writing, because "the caller should not
have done that" is not a control.

Inventory, ACLs and the encryption reasoning: [`DATA-INVENTORY.md`](DATA-INVENTORY.md).

---

## 6. Privileges

| Component | Privilege |
|---|---|
| bruhswer itself | Unelevated. Running as Administrator is reported as `FAIL` |
| The browser | Unelevated, inherits nothing extra |
| Renderers | Edge-managed: AppContainer, UNTRUSTED integrity, zero privileges |
| Firewall policy, Host Guard remediation | Administrator, in a **separate one-shot** the user runs knowingly, which explains the change, requires a typed confirmation, and records a rollback |

bruhswer never elevates itself and nothing a webpage does can trigger a privileged
operation.

---

## 7. Reporting

Privately, through GitHub's **Security tab -> Report a vulnerability**. Scope,
timelines and disclosure expectations are in [`/SECURITY.md`](../SECURITY.md); the
researcher guide with trust boundaries, environment setup and an already-known table
is in [`SECURITY-TESTING.md`](SECURITY-TESTING.md).

bruhswer holds no security certification and has had no third-party audit. It has been
reviewed by its author, by an independent model review
([`CODEX-REVIEW-0.9.0.md`](CODEX-REVIEW-0.9.0.md)), and by static analysis. That is
all, and it is stated so nobody has to infer it.
