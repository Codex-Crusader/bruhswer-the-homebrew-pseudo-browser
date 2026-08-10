# Hyper-V Verification - H-gate results

**Date:** 2026-08-08 · **Status:** halted at the prerequisite gate. `H1 = FAIL`.

Verdicts are only `PASS` / `FAIL` / `UNKNOWN`.

---

## H1 - Windows Pro / Hyper-V availability - **FAIL**

**Gate:** H1
**Claim:** this machine runs a Windows edition on which Hyper-V can be enabled.
**Threat addressed:** none directly - a hard prerequisite for every other H-gate.
**Environment:** unelevated PowerShell, host as found. Nothing modified.

**Exact test:** re-read the Windows edition, licensing channel, optional-feature enumeration, and the presence of the Hyper-V management binaries and PowerShell module. Assumed nothing from earlier stages.

**Expected (for PASS):** `EditionID` of `Professional`/`Enterprise`/`Education`, `Microsoft-Hyper-V-All` present in the feature enumeration, `vmms.exe` present.

**Observed:**

```
Caption          : Microsoft Windows 11 Home Single Language
EditionID        : CoreSingleLanguage
DisplayVersion   : 25H2         Build 10.0.26200  UBR=8973
Licensing        : Windows(R), CoreSingleLanguage edition - OEM_DM channel - Licensed

--- optional feature enumeration (Hyper-V related) ---
HypervisorPlatform      ENABLED
VirtualMachinePlatform  ENABLED
  (Microsoft-Hyper-V, Microsoft-Hyper-V-All and Containers-DisposableClientVM
   DO NOT APPEAR IN THE ENUMERATION AT ALL)

--- management binaries ---
WindowsSandbox.exe   False        vmconnect.exe  False        vmms.exe  False
vmcompute.exe        True         vmwp.exe       True
Hyper-V PowerShell module available : False
Get-VM cmdlet available             : False

systeminfo: "A hypervisor has been detected. Features required for Hyper-V will not be displayed."
```

**Verdict: FAIL.**

Hyper-V cannot be enabled on this machine. The evidence is convergent and not merely an absent flag:

1. The edition is `CoreSingleLanguage` (Home), genuinely licensed through the OEM_DM channel.
2. `Microsoft-Hyper-V` and `Containers-DisposableClientVM` are **absent from the feature enumeration entirely** - not `Disabled`, which would mean installable. Contrast `HypervisorPlatform`, which reported `Disabled` in Stage 2.5 and *was* installable.
3. `vmms.exe` (Hyper-V Virtual Machine Management Service) and `vmconnect.exe` are **not present on disk**.
4. The Hyper-V PowerShell module and `Get-VM` do not exist.

Windows Sandbox is unavailable for the same reason.

**Residual risk:** none introduced - nothing was changed.

**Architecture consequence:** **H2-H22 cannot be executed.** Per the Stage 3 brief §4, work stops here and the prerequisite is reported. No unsupported Hyper-V installation was attempted on Windows Home; third-party scripts exist that force-install Hyper-V on Home SKUs, and using one would place an unsupported, unserviced virtualization stack into the trusted computing base - the same class of defect that caused the QEMU rejection in B17.

---

## H2 - H22 - **UNKNOWN (blocked)**

```
H2  Hyper-V install / host security preservation   UNKNOWN (blocked by H1)
H3  Minimal VM creation                            UNKNOWN (blocked by H1)
H4  VM privilege model                             UNKNOWN (blocked by H1)
H5  Filesystem isolation                  LOAD-BEARING · UNKNOWN (blocked)
H6  Clipboard / device integration isolation       UNKNOWN (blocked)
H7  Guest -> host network isolation       LOAD-BEARING · UNKNOWN (blocked)
H8  Guest -> LAN isolation                LOAD-BEARING · UNKNOWN (blocked)
H9  IPv6 isolation                        LOAD-BEARING · UNKNOWN (blocked)
H10 Internet connectivity                          UNKNOWN (blocked)
H11 Guest firewall removal resistance     LOAD-BEARING · UNKNOWN (blocked)
H12 Host-side enforcement verification    LOAD-BEARING · UNKNOWN (blocked)
H13 Host -> guest control path                     UNKNOWN (blocked)
H14 Guest -> host control-plane isolation LOAD-BEARING · UNKNOWN (blocked)
H15 VM device inventory                            UNKNOWN (blocked)
H16 GPU isolation                                  UNKNOWN (blocked)
H17 Display isolation                              UNKNOWN (blocked)
H18 Disposable VM destruction             LOAD-BEARING · UNKNOWN (blocked)
H19 Persistent / disposable spatial separation     UNKNOWN (blocked)
H20 Runtime controller privilege          LOAD-BEARING · UNKNOWN (blocked)
H21 Fail-closed behaviour                 LOAD-BEARING · UNKNOWN (blocked)
H22 Host state restoration                         UNKNOWN (blocked)
```

Under brief §31, unknown security state is not a pass. No backend decision under §37 is recorded.

---

## Results that carry forward from earlier stages

Two Stage 2.5 measurements are properties of **Windows itself**, not of any backend, so they survive the backend change and do not need re-testing from scratch. Everything else measured for WSL2 or QEMU is void.

| Result | Measured | Relevance to Hyper-V |
|---|---|---|
| AppContainer with `internetClient` only blocks loopback **and the host's own LAN IP**, while internet still works | Stage 2.5 B7-pre, **PASS** | Applies to any host-side process needing confinement. Windows Firewall cannot filter loopback, so this remains the only mechanism that covers it. |
| Windows Firewall outbound deny scoped by `-Program` blocks remote LAN while preserving internet | Stage 2.5 B16, **PASS** | A category-independent, host-side enforcement point usable regardless of backend. |
| Hyper-V Firewall (`New-NetFirewallHyperVRule`) does **not** stop guest→host 445/135 for the WSL VM; guest traffic is SNAT'd to the host's own IP | Stage 2 G3/G8, **FAIL** | **Directly relevant and unresolved.** See `HYPERV-ARCHITECTURE.md` §4 - the same NAT mechanism may underlie Hyper-V's Default Switch, so H7 must be treated as at genuine risk of repeating the WSL2 failure. |

---

## Host change audit - Stage 3

**No host changes were made during Stage 3.** The stage halted at its prerequisite gate before any modification.

### Repository changes during Stage 3

The host was untouched, but Stage 3 did write to the repository. Recorded here so this audit is complete rather than technically true:

| File | Change | Requested by the brief? |
|---|---|---|
| `docs/HYPERV-VERIFICATION.md` | created (this file) | **Yes** - Stage 3 deliverable |
| `docs/HYPERV-ARCHITECTURE.md` | created | **Yes** - Stage 3 deliverable |
| `docs/HYPERV-THREAT-MODEL.md` | created | **Yes** - Stage 3 deliverable |
| `docs/PROJECT-HISTORY.md` | created | **No** - resolves a dangling link introduced by `HYPERV-THREAT-MODEL.md`, and serves brief §34 |
| `docs/BACKEND-VERIFICATION.md` | **edited** - B17 prose said the signing certificate expired `2023-10-12`; corrected to `2023-12-09 23:59:59 UTC`, which is what the raw evidence and `B17-QEMU-PROVENANCE.md` both show. A transposition of the local-time rendering `12/10/2023`. | **No** - factual correction to a prior stage's evidence document |
| `docs/SECURITY.md` | **edited** - added a superseded-backend banner, a §3 marker, and a table row pointing to `PROJECT-HISTORY.md`. No existing text altered. | **No** - the entry point still asserted the rejected WSL2 architecture as current |

The last two touch **previously approved deliverables from earlier stages** and were not asked for. They are disclosed rather than absorbed, and both are reversible on request.

State as recorded 2026-08-08:

```
Windows            : 11 Home Single Language, 25H2, build 26200.8973, Licensed
CPU / RAM          : AMD Ryzen 7 7840HS, 8C/16T, 15.3 GB, VirtFirmwareEnabled=True
Secure Boot: 1     VBS: 2 (running)   HVCI: 1
Defender realtime  : True             Firewall: Domain/Private/Public all True
WSL distros        : none             .wslconfig: absent
BM firewall rules  : 0
```

**Residue still present from Stage 2.5, carried deliberately and not yet reversed:**

| Item | State | Reversal |
|---|---|---|
| `HypervisorPlatform` optional feature | **ENABLED**, `RebootPending = True` | `Disable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform` |
| QEMU 11.0.50 at `C:\Program Files\qemu` | **Installed** (rejected by B17; must not be used) | `winget uninstall SoftwareFreedomConservancy.QEMU` |

Both were left in place because Stage 2.5 ended awaiting a rollback decision that has not yet been given. **The QEMU binaries remain rejected and must not be used** regardless of their presence on disk.
