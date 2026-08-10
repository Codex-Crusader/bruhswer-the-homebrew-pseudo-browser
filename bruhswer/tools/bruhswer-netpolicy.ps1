<#
.SYNOPSIS
    BRUHWSER network policy - apply, remove, or show the browser's firewall rules.

.DESCRIPTION
    REQUIRES ADMINISTRATOR. This is the ONLY part of BRUHWSER that changes host state,
    and it is deliberately separate from the app: BRUHWSER itself runs unelevated and
    can only VERIFY these rules, never create them (Stage 5 brief SS16).

    What it creates: outbound Block rules scoped by -Program to the Microsoft Edge
    executable, denying private IPv4 ranges and local IPv6 ranges.

    Why this specific mechanism: Stage 4 gate A16 measured it working against the real
    browser - the router went REACHED -> BLOCKED -> REACHED with
    ERR_NETWORK_ACCESS_DENIED, the internet stayed up, and other programs were
    unaffected. Gate A17 measured that the browser cannot delete these rules, because
    firewall policy needs Administrator and the browser does not have it.

    What it CANNOT do: block 127.0.0.1 or this PC's own IP. Windows Firewall does not
    filter loopback. Gate A16 measured rules explicitly naming those addresses failing
    to block Edge. Nothing here pretends otherwise.

    It touches nothing else. No firewall profile is enabled or disabled, no Defender,
    SmartScreen, Secure Boot, VBS or HVCI setting is read or written, no service is
    changed, and no persistence is created.

.PARAMETER Action
    apply | remove | status

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\bruhswer-netpolicy.ps1 -Action status
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('apply', 'remove', 'status')]
  [string]$Action
)

$ErrorActionPreference = 'Stop'
$PREFIX = 'BRUHWSER'

$EdgeCandidates = @(
  'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
  'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
)

$Rules = @(
  @{ Name = "$PREFIX-edge-deny-ipv4-private"
     Remote = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16')
     What = 'private IPv4 ranges: router, LAN devices, NAS, printers' },
  @{ Name = "$PREFIX-edge-deny-ipv6-local"
     Remote = @('fc00::/7', 'fe80::/10')
     What = 'IPv6 unique-local and link-local ranges' }
)

function Write-Head($text) {
  Write-Host ''
  Write-Host ('=' * 74)
  Write-Host $text
  Write-Host ('=' * 74)
}

function Get-EdgePath {
  foreach ($p in $EdgeCandidates) { if (Test-Path -LiteralPath $p) { return $p } }
  return $null
}

function Get-BruhRules {
  Get-NetFirewallRule -DisplayName "$PREFIX-*" -ErrorAction SilentlyContinue
}

function Show-Status {
  $existing = @(Get-BruhRules)
  Write-Host ("BRUHWSER rules present: {0}" -f $existing.Count)
  foreach ($r in $existing) {
    $a = $r | Get-NetFirewallAddressFilter
    $p = $r | Get-NetFirewallApplicationFilter
    Write-Host ('  {0}' -f $r.DisplayName)
    Write-Host ('      enabled={0} action={1} direction={2}' -f $r.Enabled, $r.Action, $r.Direction)
    Write-Host ('      program={0}' -f $p.Program)
    Write-Host ('      remote ={0}' -f ($a.RemoteAddress -join ', '))
  }
  if ($existing.Count -eq 0) {
    Write-Host '  (none - BRUHWSER will refuse to launch until these exist)'
  }
}

# --- elevation gate -------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Head "BRUHWSER network policy  -  action: $Action"

if ($Action -eq 'status') {
  Show-Status
  exit 0
}

if (-not $isAdmin) {
  Write-Host 'REFUSING TO RUN: this needs Administrator.'
  Write-Host 'Right-click PowerShell, choose "Run as administrator", and run it again.'
  Write-Host 'BRUHWSER itself never elevates - that is the point.'
  exit 2
}

$edge = Get-EdgePath
if (-not $edge) {
  Write-Host 'REFUSING TO RUN: Microsoft Edge was not found at a known location.'
  exit 3
}

# --- remove ----------------------------------------------------------------------
if ($Action -eq 'remove') {
  Write-Host 'PREVIOUS STATE, before this script changes anything:'
  Show-Status
  Write-Host ''
  Write-Host 'REMOVING every firewall rule whose name starts with BRUHWSER-.'
  $existing = @(Get-BruhRules)
  if ($existing.Count -eq 0) {
    Write-Host '  nothing to remove.'
  } else {
    $existing | Remove-NetFirewallRule
  }
  $left = @(Get-BruhRules).Count
  Write-Host ('  rules remaining: {0}  (must be 0)' -f $left)
  Write-Host ''
  Write-Host 'Your browser can now reach the local network again.'
  exit ([int]($left -ne 0))
}

# --- apply -----------------------------------------------------------------------
Write-Host 'EXACTLY what this will change, before it changes it:'
Write-Host ''
Write-Host ('  browser: {0}' -f $edge)
foreach ($r in $Rules) {
  Write-Host ''
  Write-Host ('  CREATE  {0}' -f $r.Name)
  Write-Host  '          direction=Outbound  action=Block  profile=Any'
  Write-Host ('          scoped to this program only: {0}' -f (Split-Path $edge -Leaf))
  Write-Host ('          blocks: {0}' -f ($r.Remote -join ', '))
  Write-Host ('          that is: {0}' -f $r.What)
}
Write-Host ''
Write-Host '  NOT changed: firewall profiles, Defender, SmartScreen, Secure Boot,'
Write-Host '               VBS, HVCI, services, scheduled tasks, registry security.'
Write-Host '  NOT possible: blocking 127.0.0.1 or this PC own IP. Windows Firewall'
Write-Host '               does not filter loopback. Measured, not assumed.'
Write-Host ''
Write-Host '  Undo at any time:  bruhswer-netpolicy.ps1 -Action remove'

$existing = @(Get-BruhRules)
if ($existing.Count -gt 0) {
  Write-Host ''
  Write-Host ('REFUSING: {0} rule(s) with the BRUHWSER prefix already exist.' -f $existing.Count)
  Write-Host 'Run -Action remove first, so this script never silently overwrites'
  Write-Host 'something it did not create.'
  exit 4
}

Write-Host ''
$answer = Read-Host 'Type APPLY to make these changes, or anything else to cancel'
if ($answer -ne 'APPLY') {
  Write-Host 'Cancelled. Nothing was changed.'
  exit 0
}

$created = @()
$failed = @()
foreach ($r in $Rules) {
  try {
    New-NetFirewallRule -DisplayName $r.Name -Direction Outbound -Action Block `
      -Program $edge -RemoteAddress $r.Remote -Profile Any -Enabled True `
      -Description 'Created by BRUHWSER. Remove with bruhswer-netpolicy.ps1 -Action remove.' `
      -ErrorAction Stop | Out-Null
    $created += $r.Name
    Write-Host ('  created  {0}' -f $r.Name) -ForegroundColor Green
  } catch {
    $failed += $r.Name
    Write-Host ('  FAILED   {0} -> {1}' -f $r.Name, $_.Exception.Message) -ForegroundColor Red
  }
}

if ($failed.Count -gt 0) {
  Write-Host ''
  Write-Host 'One or more rules could not be created. Rolling back the ones that were,'
  Write-Host 'so the machine is left exactly as it was found.'
  Get-BruhRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  Write-Host ('  rules remaining: {0}' -f @(Get-BruhRules).Count)
  exit 5
}

Write-Head 'RESULT'
Show-Status
Write-Host ''
Write-Host 'Done. Start BRUHWSER and it will verify these rules for itself -'
Write-Host 'it does not take this script word for it.'
exit 0
