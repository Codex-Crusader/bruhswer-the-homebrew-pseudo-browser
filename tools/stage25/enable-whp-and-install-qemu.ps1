# Stage 2.5: enable Windows Hypervisor Platform and install QEMU.
#
# ELEVATED, ONE-SHOT, INTERACTIVE. The runtime controller never calls this.
# All values are fixed in source. Nothing is taken from arguments, the guest, or the web.
#
# THIS SCRIPT DOES NOT REBOOT. It uses -NoRestart and reports that a reboot is pending.
# Rebooting is the user's decision.
#
# Reversible with: tools\stage25\revert-whp-and-qemu.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$FEATURE   = 'HypervisorPlatform'
$PKG       = 'SoftwareFreedomConservancy.QEMU'
$PKGVER    = '11.0.50'
$EXPECTED_SHA256 = 'A8B29572AFB4C6AD024B7DE129C81033E9FD191B9E054E3A52EA0BED24AC19EF'

Write-Host '=== EXACT CHANGES THIS SCRIPT MAKES ===' -ForegroundColor Cyan
Write-Host "  1. Enable Windows optional feature: $FEATURE  (-NoRestart)"
Write-Host "     This is a virtualization API. It coexists with VBS/HVCI by design."
Write-Host "     It does NOT disable Defender, SmartScreen, Secure Boot, VBS, HVCI, ASLR, DEP or CFG."
Write-Host "  2. Install $PKG version $PKGVER via winget (pinned, not 'latest')."
Write-Host "     Binary origin: qemu.weilnetz.de - a THIRD-PARTY build host."
Write-Host "     Not QEMU project CI. Not Microsoft-signed. winget verifies SHA256 in transit."
Write-Host "     Expected installer SHA256: $EXPECTED_SHA256"
Write-Host '  3. Verify the installed binaries: version + Authenticode signature.'
Write-Host ''
Write-Host '  It does NOT reboot. It does NOT create services, scheduled tasks, startup'
Write-Host '  entries, drivers, certificates, firewall rules, or registry security changes.' -ForegroundColor Yellow
Write-Host ''

# --- 1. optional feature ------------------------------------------------------
$before = Get-WindowsOptionalFeature -Online -FeatureName $FEATURE
Write-Host "[1/3] $FEATURE current state: $($before.State)"
if ($before.State -eq 'Enabled') {
    Write-Host '      already enabled - no change made' -ForegroundColor Green
    $rebootPending = $false
} else {
    $r = Enable-WindowsOptionalFeature -Online -FeatureName $FEATURE -NoRestart -All
    $rebootPending = [bool]$r.RestartNeeded
    $after = Get-WindowsOptionalFeature -Online -FeatureName $FEATURE
    Write-Host "      new state: $($after.State)   RestartNeeded: $rebootPending" -ForegroundColor Green
}

# --- 2. QEMU ------------------------------------------------------------------
Write-Host ''
Write-Host "[2/3] installing $PKG $PKGVER (pinned)" -ForegroundColor Cyan
$wingetArgs = @(
    'install', '--id', $PKG, '--version', $PKGVER, '--exact',
    '--accept-package-agreements', '--accept-source-agreements',
    '--disable-interactivity', '--source', 'winget'
)
& winget.exe @wingetArgs
Write-Host "      winget exit code: $LASTEXITCODE"

# --- 3. verify ----------------------------------------------------------------
Write-Host ''
Write-Host '[3/3] verifying installed binaries' -ForegroundColor Cyan
$candidates = @(
    "$env:ProgramFiles\qemu\qemu-system-x86_64.exe",
    "${env:ProgramFiles(x86)}\qemu\qemu-system-x86_64.exe"
)
$qemu = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $qemu) {
    Write-Warning '      qemu-system-x86_64.exe NOT FOUND in the expected locations.'
} else {
    Write-Host "      found: $qemu" -ForegroundColor Green
    $fi = Get-Item $qemu
    Write-Host "      size: $([math]::Round($fi.Length/1MB,1)) MB   modified: $($fi.LastWriteTime)"
    $sig = Get-AuthenticodeSignature $qemu
    Write-Host "      Authenticode status : $($sig.Status)"
    Write-Host "      Authenticode signer : $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '<unsigned>' })"
    Write-Host "      SHA256 of binary    : $((Get-FileHash $qemu -Algorithm SHA256).Hash)"
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $qemu --version | Select-Object -First 2 | ForEach-Object { Write-Host "      $_" }
    $ErrorActionPreference = $prev
    Write-Host ''
    Write-Host '      Accelerators reported by this build:' -ForegroundColor Cyan
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $qemu -accel help | ForEach-Object { Write-Host "        $_" }
    $ErrorActionPreference = $prev
}

Write-Host ''
if ($rebootPending) {
    Write-Host '=== REBOOT REQUIRED before WHPX acceleration is usable. ===' -ForegroundColor Yellow
    Write-Host 'This script deliberately did not reboot. Restart when convenient.' -ForegroundColor Yellow
} else {
    Write-Host '=== No reboot flagged. ===' -ForegroundColor Green
}
