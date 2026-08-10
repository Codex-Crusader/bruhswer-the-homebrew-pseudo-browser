<#
.SYNOPSIS
    Reverse the two host changes left behind by the rejected QEMU experiment.

.DESCRIPTION
    PREPARED, NOT AUTOMATIC. Stage 6 SS31 is explicit: do not remove these merely
    because the project no longer uses them. This script exists so the cleanup is
    ready, documented and reversible when the user decides to run it - and it does
    nothing at all until they type the confirmation word.

    WHAT IS OURS TO REMOVE
      QEMU 11.0.50 at C:\Program Files\qemu   installed by this project in Stage 2.5,
                                              rejected at gate B17, never used since
      HypervisorPlatform optional feature     enabled by this project in Stage 2.5

    WHAT IS **NOT** OURS AND IS NEVER TOUCHED
      VirtualMachinePlatform                  was ALREADY enabled before this project
                                              started (recorded in the Stage 2.5
                                              baseline). Not ours to remove.
      Anything else                           Defender, SmartScreen, Secure Boot, VBS,
                                              HVCI, firewall, services, drivers.

    A NOTE ON VBS, because it looks alarming and is not:
      This machine reports VirtualizationBasedSecurityStatus = 2 (running). VBS uses
      the WINDOWS HYPERVISOR. `HypervisorPlatform` is a different thing - it is the
      third-party API (WHP) that lets applications such as QEMU drive that hypervisor.
      Removing WHP does not disable VBS or HVCI. If the verification step after the
      change finds VBS is no longer running, this script says so loudly rather than
      reporting success.

    Removing HypervisorPlatform requires a REBOOT to take full effect, and the script
    will not reboot for you.

.PARAMETER Action
    status        show exactly what is present, change nothing
    remove-qemu   uninstall QEMU 11.0.50 via winget
    disable-whp   disable the HypervisorPlatform optional feature (reboot needed)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\bruhswer-cleanup-rejected.ps1 -Action status
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('status', 'remove-qemu', 'disable-whp')]
  [string]$Action
)

$ErrorActionPreference = 'Stop'
$QemuPath   = 'C:\Program Files\qemu'
$QemuId     = 'SoftwareFreedomConservancy.QEMU'
$StateDir   = Join-Path $env:LOCALAPPDATA 'BRUHWSER\state'
$ResultLog  = Join-Path $StateDir 'cleanup-results.log'

function Write-Head($t) {
  Write-Host ''; Write-Host ('=' * 74); Write-Host $t; Write-Host ('=' * 74)
}

function Test-Admin {
  ([Security.Principal.WindowsPrincipal] `
   [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FeatureState($name) {
  $f = Get-CimInstance Win32_OptionalFeature -Filter "Name='$name'" -ErrorAction SilentlyContinue
  if (-not $f) { return 'ABSENT' }
  if ($f.InstallState -eq 1) { return 'ENABLED' }
  return 'Disabled'
}

function Get-VbsStatus {
  $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
  if ($dg) { return [int]$dg.VirtualizationBasedSecurityStatus }
  return -1
}

function Write-Result($action, $verdict, $detail) {
  if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  }
  Add-Content -LiteralPath $ResultLog -Encoding utf8 -Value (
    '{0}  {1,-14} {2,-8} {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
                                  $action, $verdict, $detail)
}

function Show-Status {
  Write-Host 'OURS TO REMOVE (left by the rejected QEMU experiment, Stage 2.5)'
  if (Test-Path -LiteralPath $QemuPath) {
    $files = Get-ChildItem $QemuPath -Recurse -File -ErrorAction SilentlyContinue
    $mb = [math]::Round((($files | Measure-Object Length -Sum).Sum / 1MB), 1)
    Write-Host ('  QEMU                    PRESENT  {0} files, {1} MB, at {2}' -f `
                $files.Count, $mb, $QemuPath)
  } else {
    Write-Host '  QEMU                    absent'
  }
  Write-Host ('  HypervisorPlatform      {0}' -f (Get-FeatureState 'HypervisorPlatform'))
  Write-Host ''
  Write-Host 'NOT OURS - NEVER TOUCHED BY THIS SCRIPT'
  Write-Host ('  VirtualMachinePlatform  {0}   (pre-existing, see Stage 2.5 baseline)' -f `
              (Get-FeatureState 'VirtualMachinePlatform'))
  Write-Host ('  VBS status              {0}   (2 = running; uses the Windows' -f (Get-VbsStatus))
  Write-Host '                                    hypervisor, NOT the WHP API)'
  Write-Host ''
  Write-Host 'IS ANYTHING USING THEM?'
  $procs = @(Get-Process -Name 'qemu*' -ErrorAction SilentlyContinue)
  Write-Host ('  running QEMU processes  {0}' -f $procs.Count)
  Write-Host ''
  Write-Host 'Neither of these is a security risk sitting there unused. Removing them'
  Write-Host 'is housekeeping, not remediation. bruhswer does not need either one.'
}

Write-Head "bruhswer cleanup of rejected experiments  -  action: $Action"

if ($Action -eq 'status') { Show-Status; exit 0 }

if (-not (Test-Admin)) {
  Write-Host 'REFUSING TO RUN: this needs Administrator.'
  Write-Host 'bruhswer itself never elevates.'
  exit 2
}

switch ($Action) {

  'remove-qemu' {
    if (-not (Test-Path -LiteralPath $QemuPath)) {
      Write-Host 'Nothing to do: QEMU is not installed.'
      exit 0
    }
    $procs = @(Get-Process -Name 'qemu*' -ErrorAction SilentlyContinue)
    if ($procs.Count -gt 0) {
      Write-Host ('REFUSING: {0} QEMU process(es) are running. Close them first.' -f $procs.Count)
      exit 3
    }
    $files = Get-ChildItem $QemuPath -Recurse -File -ErrorAction SilentlyContinue
    $mb = [math]::Round((($files | Measure-Object Length -Sum).Sum / 1MB), 1)

    Write-Host '[EXPLAIN]'
    Write-Host ('  Uninstall QEMU 11.0.50 ({0} files, {1} MB) using winget.' -f $files.Count, $mb)
    Write-Host '  This is the build rejected at gate B17 for having no verifiable'
    Write-Host '  publisher signature. bruhswer has never used it and never will.'
    Write-Host '  REVERSIBLE: winget install --id ' + $QemuId + ' --version 11.0.50'
    Write-Host '  NOT CHANGED: Windows features, Defender, firewall, anything else.'
    Write-Host ''
    $answer = Read-Host 'Type REMOVE to uninstall QEMU, or anything else to cancel'
    if ($answer -ne 'REMOVE') { Write-Host 'Cancelled. Nothing was changed.'; exit 0 }

    Write-Host '[APPLY] running winget uninstall ...'
    & winget uninstall --id $QemuId --exact --silent | Out-Host

    Write-Host '[VERIFY]'
    $still = Test-Path -LiteralPath $QemuPath
    Write-Host ('  C:\Program Files\qemu still present: {0}' -f $still)
    if ($still) {
      $leftover = @(Get-ChildItem $QemuPath -Recurse -File -ErrorAction SilentlyContinue).Count
      Write-Host ('  {0} file(s) remain.' -f $leftover)
      Write-Host ''
      Write-Host 'CLEANUP = INCOMPLETE' -ForegroundColor Yellow
      Write-Host '  winget reported done but the folder is still there. Inspect it'
      Write-Host '  before deleting anything by hand - this script will not.'
      Write-Result 'remove-qemu' 'PARTIAL' ("{0} files remain" -f $leftover)
      exit 6
    }
    Write-Result 'remove-qemu' 'OK' 'uninstalled and folder gone'
    Write-Host ''
    Write-Host 'CLEANUP = OK' -ForegroundColor Green
  }

  'disable-whp' {
    $state = Get-FeatureState 'HypervisorPlatform'
    if ($state -ne 'ENABLED') {
      Write-Host ('Nothing to do: HypervisorPlatform is {0}.' -f $state)
      exit 0
    }
    $vbsBefore = Get-VbsStatus

    Write-Host '[EXPLAIN]'
    Write-Host '  Disable the HypervisorPlatform (WHP) optional feature, which this'
    Write-Host '  project enabled in Stage 2.5 for QEMU and has not used since.'
    Write-Host '  A REBOOT is required for it to take full effect. This script will'
    Write-Host '  NOT reboot for you.'
    Write-Host ('  VBS is currently {0} and must stay that way. It uses the Windows' -f $vbsBefore)
    Write-Host '  hypervisor, not this API. The verify step re-checks it.'
    Write-Host '  REVERSIBLE: Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform'
    Write-Host '  NOT CHANGED: VirtualMachinePlatform (pre-existing, not ours),'
    Write-Host '               Defender, Secure Boot, VBS, HVCI, firewall.'
    Write-Host ''
    Write-Host '  If you ever want WSL2, Windows Sandbox, or any VM tool later, you'
    Write-Host '  may need this back. Leaving it enabled is harmless.'
    Write-Host ''
    $answer = Read-Host 'Type DISABLE to turn it off, or anything else to cancel'
    if ($answer -ne 'DISABLE') { Write-Host 'Cancelled. Nothing was changed.'; exit 0 }

    Write-Host '[APPLY] disabling HypervisorPlatform ...'
    Disable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart | Out-Null

    Write-Host '[VERIFY]'
    $after = Get-FeatureState 'HypervisorPlatform'
    $vmpAfter = Get-FeatureState 'VirtualMachinePlatform'
    $vbsAfter = Get-VbsStatus
    Write-Host ('  HypervisorPlatform      {0} -> {1}  (reboot pending)' -f $state, $after)
    Write-Host ('  VirtualMachinePlatform  {0}   (must be unchanged)' -f $vmpAfter)
    Write-Host ('  VBS status              {0} -> {1}   (must be unchanged)' -f $vbsBefore, $vbsAfter)

    if ($vbsAfter -ne $vbsBefore) {
      Write-Host ''
      Write-Host 'CLEANUP = FAILED' -ForegroundColor Red
      Write-Host '  VBS changed. Re-enabling HypervisorPlatform and stopping.'
      Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart | Out-Null
      Write-Result 'disable-whp' 'FAILED' ("VBS {0} -> {1}, rolled back" -f $vbsBefore, $vbsAfter)
      exit 6
    }
    Write-Result 'disable-whp' 'OK' 'disabled, reboot pending, VBS unchanged'
    Write-Host ''
    Write-Host 'CLEANUP = OK  -  reboot when convenient.' -ForegroundColor Green
  }
}

exit 0
