# B17 - QEMU Binary Provenance Investigation

**Date:** 2026-08-08 · **Status:** investigation complete · **Verdict: B17 UNRESOLVED - QEMU BACKEND CANNOT PROCEED**

Scope: establish whether the installed QEMU binary can be trusted enough to become part of this project's trusted computing base. No implementation was performed. The host was not rebooted, nothing was uninstalled, and gates B2/B4/B5/B7-B14 were not run.

---

## 1. Exact artifact

| Field | Value | Source |
|---|---|---|
| Package identifier | `SoftwareFreedomConservancy.QEMU` | winget `[MEASURED]` |
| Package version | `11.0.50` | winget `[MEASURED]` |
| QEMU version string | `QEMU emulator version 11.0.50 (v11.0.0-12631-g54e84cdc7a)` | binary `--version` `[MEASURED]` |
| winget source | `winget` (`https://cdn.winget.microsoft.com/cache`) | `winget source list` `[MEASURED]` |
| Manifest version | `1.12.0`, `ManifestType: installer` | GitHub manifest `[MEASURED]` |
| Installer URL | `https://qemu.weilnetz.de/w64/2026/qemu-w64-setup-20260501.exe` | manifest `[MEASURED]` |
| Installer type | `nullsoft` (NSIS) | manifest `[MEASURED]` |
| Installer SHA256 (manifest) | `a8b29572afb4c6ad024b7de129c81033e9fd191b9e054e3a52ea0bed24ac19ef` | manifest `[MEASURED]` |
| Install scope / location | machine · `C:\Program Files\qemu` | manifest `[MEASURED]` |
| Release date | `2026-05-01` | manifest `[MEASURED]` |
| Installed footprint | 3374 files, 1169.8 MB | filesystem `[MEASURED]` |
| Installed binary | `qemu-system-x86_64.exe`, 24.1 MB | filesystem `[MEASURED]` |
| Installed binary SHA256 | `B396EB9B669F6282EC60F0D46E6ADDCA8C669992E67A34365BE44CD3CB97C9A7` | `Get-FileHash` `[MEASURED]` |
| Producer | **Stefan Weil**, `qemu.weilnetz.de` - an individual third-party maintainer | qemu.org `[MEASURED]` |

**The package identifier is misleading.** `SoftwareFreedomConservancy.QEMU` and the publisher label "QEMU Community" suggest first-party or foundation provenance. The manifest's own `InstallerUrl` shows the binary is produced by an individual maintainer's personal build host. Software Freedom Conservancy did not build this binary.

---

## 2. Signature analysis

`signtool.exe` is not installed on this host, so the PE security directory was parsed directly (`tools/stage25/b17-read-authenticode-time.ps1`) to obtain the authoritative signing time rather than inferring it.

```
File            : C:\Program Files\qemu\qemu-system-x86_64.exe
PE magic        : 0x20B (PE32+)
Security dir    : offset=25259520 size=13448

Primary signer  : CN=Universität Mannheim, O=Universität Mannheim, S=Baden-Württemberg, C=DE
  issuer        : CN=GEANT Code Signing CA 4, O=GEANT Vereniging, C=NL
  NotBefore     : 2022-12-09 00:00:00 UTC
  NotAfter      : 2023-12-09 23:59:59 UTC
  primary signingTime : 2026-05-01 11:32:05 UTC      <-- 2.4 YEARS AFTER EXPIRY

Countersigners  : 0
  unsigned attr : 1.3.6.1.4.1.311.3.3.1   (RFC3161 nested timestamp present)
```

### Reconciling an apparent contradiction in this evidence

The script's own closing line reads `No decodable signingTime found; cannot determine when signing occurred`, which appears to contradict the `2026-05-01` value printed a few lines above it. It does not, and the reason matters because this is the most load-bearing number in the report.

The verdict block only inspected `CounterSignerInfos`, of which there are **0** - this binary carries an **RFC3161** timestamp in an *unsigned attribute* (`1.3.6.1.4.1.311.3.3.1`) rather than a legacy countersignature. So the verdict logic never saw the `signingTime` the script had already extracted from the primary `SignedAttributes`. **The RFC3161 timestamp value itself was not decoded here.**

That distinction is important for how much weight the number carries: the primary `signingTime` is an attribute **asserted by the signer**, not by a trusted third party. Taken alone it would be weak evidence.

**The conclusion therefore rests on three convergent signals, not on the signer's own assertion:**

1. The signer-asserted `signingTime` of `2026-05-01`, against a certificate expiring `2023-12-09`.
2. **Windows independently decodes the RFC3161 timestamp** - which this analysis did not - and still returns `NotTimeValid`. Had the timestamp shown signing within the validity window, Windows would have accepted it. This is the strongest of the three.
3. The maintainer's own published statement that the certificate is expired (§3), from a party with no incentive to misreport it against their own distribution.

Windows' own verdict:

```
Status:        UnknownError
StatusMessage: A required certificate is not within its validity period when verifying
               against the current system clock or the timestamp in the signed file
Chain builds OK: False   ChainStatus: NotTimeValid
Timestamped by:  CN=Sectigo Public Time Stamping Signer R36, O=Sectigo Limited
```

### Signature scope across the install

```
qemu-system-x86_64.exe    status=UnknownError   signer=CN=Universität Mannheim
qemu-system-x86_64w.exe   status=UnknownError   signer=CN=Universität Mannheim
qemu-img.exe              status=UnknownError   signer=CN=Universität Mannheim
qemu-ga.exe               status=UnknownError   signer=CN=Universität Mannheim

brlapi-0.8.dll            status=NotSigned      <UNSIGNED>
libaom.dll                status=NotSigned      <UNSIGNED>
libatk-1.0-0.dll          status=NotSigned      <UNSIGNED>
libavif-16.dll            status=NotSigned      <UNSIGNED>
libbrotlicommon.dll       status=NotSigned      <UNSIGNED>
libbrotlidec.dll          status=NotSigned      <UNSIGNED>
```

**Only the executables carry any signature at all. The bundled DLLs - the large majority of the 3374 installed files, including the libraries QEMU loads at runtime - are entirely unsigned.** Even a valid `.exe` signature would not have covered them.

---

## 3. Is the signature failure expected? - **YES, and permanently**

This was the question the brief (§5) required be answered from evidence rather than assumption. Candidate explanations were: an actually invalid signature; an expired certificate that was valid at signing time; a missing/invalid timestamp; a certificate rollover issue; a build-system problem.

The answer is none of those. Two independent lines of evidence:

1. **The PE's own `signingTime` attribute is `2026-05-01`, and the certificate expired `2023-12-09`.** Signing demonstrably occurred ~2.4 years after expiry. Timestamping preserves a signature past certificate expiry only by proving signing happened *while* the certificate was valid; it cannot help here. Windows, which decodes the RFC3161 timestamp, independently concludes `NotTimeValid`.

2. **The distributor states it as policy.** From `https://qemu.weilnetz.de/w64/`:

   > *"All newer installers are signed with an expired certificate. Sorry, but a new certificate for code signing is too expensive."*

**This is decisive and forward-looking.** The failure is not a defect in build 11.0.50 that a later build would fix. Every newer installer from this channel is affected, by the maintainer's own declared policy. Checking for a newer version - `qemu-w64-setup-20260805.exe` (2026-08-05) is the latest - cannot resolve B17. **Upgrading is not a remedy.**

### What is and is not established

- **Established:** the installed binaries carry no verifiable publisher signature; Windows treats them as effectively unsigned; SmartScreen and Defender will do the same; the bundled DLLs are unsigned outright; this condition is permanent for this distribution channel.
- **NOT established, and not claimed:** that the binary is malicious, tampered with, or unsafe. No evidence of that exists. The signer identity is consistent with the known maintainer, and these builds are in wide use. Wide use is not a security argument and is not offered as one.

---

## 4. Package provenance - integrity vs authenticity

| Question (brief §3) | Answer |
|---|---|
| Which winget source supplied it? | `winget` community source, `cdn.winget.microsoft.com` |
| Which manifest? | `microsoft/winget-pkgs`, `manifests/s/SoftwareFreedomConservancy/QEMU/11.0.50` |
| Manifest SHA256? | `a8b29572…19ef` |
| Does the on-disk hash match the manifest? | **Not comparable.** The manifest hashes the **installer**; `B396EB9B…` is the **extracted binary**. Different artifacts. |
| Was the installer hash verified? | Yes - winget logged `Successfully verified installer hash`. **But the installer is no longer on disk** (absent from the winget cache and `%TEMP%`), so this can no longer be independently re-verified. |
| Publisher/URL consistent with intended distribution? | Consistent with Stefan Weil's channel; **inconsistent with the package name**, which implies SFC. |
| Official QEMU release, third-party, or other? | **Third-party build of QEMU git master** (`v11.0.0-12631-g54e84cdc7a` - a development snapshot, not a tagged QEMU release). |
| Does the manifest identify the third-party maintainer? | Only implicitly, via the `qemu.weilnetz.de` URL. No maintainer, signature, or publisher-authentication field. |
| Does hash verification prove authenticity? | **No.** It proves **integrity in transit** only - that the bytes received match the bytes the manifest author recorded. It says nothing about who produced them or whether the build host was compromised. Authenticity would require a signature chain, which is exactly what is missing. |

The site publishes SHA-512 checksum files alongside the installers. **A checksum served from the same host as the binary provides no independent authenticity** - an attacker controlling the host controls both. No GPG signatures are offered.

---

## 5. Upstream provenance

From `https://www.qemu.org/download/`:

> *"Stefan Weil provides binaries and installers for both 32-bit and 64-bit Windows."*

**The QEMU project does not build or distribute official Windows binaries.** It delegates to a named individual third party, and says so plainly. MSYS2 is listed as an alternative route.

So the trust chain is:

```
QEMU project (source)
   -> endorses, but does not build for Windows
Stefan Weil / Universitat Mannheim  (individual maintainer, personal build host)
   -> produces installer, signed with a knowingly expired certificate
winget-pkgs community manifest      (records URL + SHA256; no publisher authentication)
   -> this machine
```

Two of the three links carry no cryptographic assurance whatsoever.

---

## 6. Alternative builds assessed

### A. Official QEMU Windows binary
**Does not exist.** Confirmed from qemu.org. Not an option.

### B. Weilnetz build (currently installed)
- **Advantages:** explicitly endorsed by the QEMU project; widely used; single installer; actively maintained and tracks upstream closely; winget-managed and version-pinnable.
- **Disadvantages:** no valid signature, permanently and by declared policy; DLLs unsigned; a development snapshot of git master rather than a tagged release; single-maintainer, single-host build with no reproducibility story; checksums are not independent of the host serving the binary.

### C. MSYS2 packages
- **Advantages:** a **real signing chain** - packages and repository databases are GPG-signed, packager keys must be in `msys2-keyring` and signed by at least three master keys; public `PKGBUILD` build recipes; built by project CI rather than one person's machine.
- **Disadvantages:** the trust root moves to the MSYS2 project rather than disappearing; MSYS2 is a large development environment, so it adds a substantial new TCB of its own; still no Authenticode, so Windows still sees unsigned binaries; awkward to package into a shippable product.
- **Assessment: genuinely better provenance than B**, and the strongest option that keeps the QEMU backend alive on Windows 11 Home.

### D. Build QEMU locally from verified source
- **Advantages:** best provenance *in principle* - the QEMU source repository and release tags can be verified independently, the revision pinned, and the toolchain documented.
- **Disadvantages, and they are serious for this project:**
  - Building QEMU on Windows requires MSYS2/mingw, so **the MSYS2 toolchain TCB is inherited anyway** - this does not escape option C, it adds to it.
  - The output is still an unsigned binary Windows cannot validate.
  - Every QEMU security update requires a manual rebuild. For a single-maintainer project, **a local build that lags on security patches is plausibly worse than a maintained third-party build**, because unpatched QEMU device-emulation bugs are a live guest→host risk.
  - The currently installed artifact is a git-master snapshot; reproducing or verifying *that specific* build is not practical.
- **Assessment:** not chosen. Source compilation was not selected merely because the packaged binary has a signature problem - the trust models were compared, and a local build trades a provenance gain for a patch-latency loss on the exact component that faces hostile input.

### E. Windows 11 Pro - Hyper-V / Windows Sandbox
- **Advantages:** the decisive structural point is not that Microsoft is more trustworthy in the abstract. It is that **the Microsoft hypervisor is already running on this machine and already in its TCB** - measured: VBS status 2 (running), HVCI enabled, Secure Boot on. Enabling Hyper-V or Windows Sandbox therefore **adds no new supply-chain trust root**. Binaries are Microsoft-signed, in-box, and serviced through Windows Update.
- **Disadvantages, stated fairly:** this resolves the *supply-chain* dimension only. It does **not** automatically make the architecture more secure. Hyper-V is a large, privileged component with its own escape history. Stage 1 already recorded that Windows Sandbox offers no per-VM network ACLs, which is directly relevant given that network isolation is what defeated WSL2. A Pro backend would require its own complete verification suite from scratch, and it is not a free win.
- Cost is a real consideration for the user but is **not** part of this security assessment.

---

## 7. Trust model comparison

| | Weilnetz (installed) | MSYS2 | Local source build | Hyper-V / Sandbox |
|---|---|---|---|---|
| New trust root added to TCB | Individual + personal build host | MSYS2 project | MSYS2 toolchain + us | **None - already trusted** |
| Cryptographic publisher assurance | **None** (permanent) | GPG, keyring policy | Source signatures only | Authenticode, Microsoft |
| Windows-verifiable signature | **No** | No | No | **Yes** |
| Unsigned DLLs shipped | **~3300** | packaged, signed at package level | self-built | n/a |
| Security-patch latency | maintainer-driven, low | project CI, low | **manual, high risk** | Windows Update |
| Available on Win 11 Home | Yes | Yes | Yes | **No** |

---

## 8. Final B17 assessment

```
B17 UNRESOLVED - QEMU BACKEND CANNOT PROCEED
```

No trusted build was identified, and no verified local build was performed. The failure is permanent for the endorsed distribution channel by the maintainer's own declared policy, so it cannot be resolved by upgrading, re-downloading, or re-verifying. B17 is **not** marked resolved on the basis of the SHA256 matching the manifest - that establishes integrity in transit, not authenticity.

---

## 9. Recommendation

```
ROLL BACK QEMU AND USE WINDOWS 11 PRO / HYPER-V PATH
```

**Grounds - supply chain, not cost or convenience.** This project's own architecture designates the virtualization backend as part of the trusted computing base. Every QEMU route on Windows 11 Home terminates in binaries that Windows cannot validate and that introduce a **new** trust root the machine does not currently depend on. The Hyper-V route uses a hypervisor that is **already loaded and already trusted** on this machine, adding no new supply-chain trust root at all. That asymmetry is a security property, and it is the specific property B17 exists to evaluate.

**Required caveats, so this recommendation is not over-read:**

1. It resolves the **supply-chain** dimension only. It makes no claim that Hyper-V or Windows Sandbox is architecturally more secure. That requires its own analysis and its own gate suite, and Stage 1 already identified a concrete weakness - Windows Sandbox provides no per-VM network ACLs, and network isolation is exactly what defeated WSL2.
2. The Pro backend must be verified from scratch. **Nothing verified for the QEMU candidate transfers**, except the two host-side network results (AppContainer loopback blocking, program-scoped firewall rules), which are properties of Windows rather than of any backend.
3. The licence purchase is the user's decision. If they prefer to remain on Home, **MSYS2 (option C) is the strongest QEMU-preserving alternative** and would need its own B17-equivalent investigation before adoption.
4. If rolled back: `Disable-WindowsOptionalFeature -FeatureName HypervisorPlatform` and `winget uninstall SoftwareFreedomConservancy.QEMU` reverse both persistent changes.

---

## 10. Current host state - preserved, unchanged during this investigation

```
HypervisorPlatform : Enabled, REBOOT PENDING   (not rebooted)
QEMU 11.0.50       : Installed at C:\Program Files\qemu   (not uninstalled)
B17                : FAIL / UNRESOLVED
B2, B4, B5, B7-B14 : not run
AppContainer runtime : not created
VM                 : not created
Browser            : not implemented
```

This investigation was read-only apart from creating `tools/stage25/b17-read-authenticode-time.ps1` and this document. No reboot, no feature change, no firewall change, no uninstall, no additional installs. Defender, SmartScreen, Secure Boot, VBS, HVCI unchanged.

**Awaiting explicit approval before any further action.**

---

## Sources

- [QEMU - Download](https://www.qemu.org/download/) - confirms QEMU does not build official Windows binaries and names Stefan Weil
- [QEMU for Windows - Installers (64 bit)](https://qemu.weilnetz.de/w64/) - the expired-certificate statement and latest builds
- [winget-pkgs manifest, SoftwareFreedomConservancy.QEMU 11.0.50](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/s/SoftwareFreedomConservancy/QEMU/11.0.50/SoftwareFreedomConservancy.QEMU.installer.yaml) - installer URL and SHA256
- [MSYS2 - Signing packages](https://www.msys2.org/wiki/Signing-packages/) - MSYS2 GPG keyring and master-key signing policy
