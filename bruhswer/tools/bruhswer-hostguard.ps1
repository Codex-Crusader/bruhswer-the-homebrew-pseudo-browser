<#
.SYNOPSIS
    bruhswer Host Guard - narrow, reversible, VERIFIED fixes for this PC's exposure
    on an untrusted network.

.DESCRIPTION
    REQUIRES ADMINISTRATOR. Separate from the app on purpose: bruhswer detects and
    explains, but never changes host-wide settings by itself (Stage 6 SS6, SS9).

    The workflow every remediation follows (Stage 6 SS7), in order:

        1. CAPTURE   record the previous state to a rollback file, before anything
        2. EXPLAIN   print the exact change, the risk, and the undo
        3. CONSENT   wait for a typed confirmation word
        4. APPLY     make the smallest change that fixes the finding
        5. VERIFY    re-read the state and confirm it actually changed
        6. RECORD    append the outcome to a local result log
        7. ROLLBACK  always available, and itself verified (SS8)

    If step 5 does not confirm the change:

        REMEDIATION = FAILED

    and the script rolls back automatically rather than reporting a success it did
    not achieve. "The command exited 0" is not evidence - an earlier bug in this
    project taught that lesson expensively.

    It NEVER touches: Defender, SmartScreen, Secure Boot, VBS, HVCI, the firewall
    profiles' enabled/disabled state, network adapters, system services, registry
    security, installed software, or anything unrelated to what it names. It is not
    a Windows optimiser (SS9).

.PARAMETER Action
    status      show what is exposed, change nothing
    fix-sharing disable File and Printer Sharing on the PUBLIC profile only
    fix-smb     require SMB signing
    revert      restore everything this script changed, and verify the restore

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\bruhswer-hostguard.ps1 -Action status
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('status', 'plan', 'fix-sharing', 'fix-smb', 'revert')]
  [string]$Action
)

$ErrorActionPreference = 'Stop'
$StateDir     = Join-Path $env:LOCALAPPDATA 'BRUHWSER\state'
$StateFile    = Join-Path $StateDir 'hostguard-rollback.json'
$ResultLog    = Join-Path $StateDir 'hostguard-results.log'
$SharingGroup = 'File and Printer Sharing'

function Write-Head($t) {
  Write-Host ''
  Write-Host ('=' * 74)
  Write-Host $t
  Write-Host ('=' * 74)
}

function Test-Admin {
  ([Security.Principal.WindowsPrincipal] `
   [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PublicSharingRules {
  Get-NetFirewallRule -DisplayGroup $SharingGroup -ErrorAction SilentlyContinue |
    Where-Object { $_.Profile -match 'Public' -or $_.Profile -eq 'Any' }
}

function Count-EnabledSharing {
  @(Get-PublicSharingRules | Where-Object { $_.Enabled -eq 'True' }).Count
}

function Expand-Profile([string]$profileValue) {
  # "Any" is shorthand for all three. Everything else is a comma-separated list.
  if ($profileValue -eq 'Any') { return @('Domain', 'Private', 'Public') }
  return @($profileValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Remove-PublicFromProfile([string]$profileValue) {
  # Returns the profile list with Public removed, or $null if nothing would remain.
  $kept = @(Expand-Profile $profileValue | Where-Object { $_ -ne 'Public' })
  if ($kept.Count -eq 0) { return $null }
  return $kept
}

function Read-State {
  if (Test-Path -LiteralPath $StateFile) {
    return Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
  }
  return $null
}

function Save-State($obj) {
  if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  }

  # "First capture wins" applies PER FIELD, not per file.
  #
  # The earlier version refused to write at all if a record already existed. That is
  # right for a field already captured - re-capturing would record OUR change as the
  # "original" - but it silently dropped every other field. Running fix-sharing then
  # fix-smb meant the SMB original value was never recorded, so -Action revert would
  # quietly skip restoring it and report success. An incomplete rollback that reports
  # OK is worse than one that fails loudly.
  $existing = @{}
  if (Test-Path -LiteralPath $StateFile) {
    $loaded = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    foreach ($p in $loaded.PSObject.Properties) { $existing[$p.Name] = $p.Value }
  }

  $added = @()
  $kept = @()
  foreach ($key in $obj.Keys) {
    $incoming = $obj[$key]
    $isEmpty = ($null -eq $incoming) -or
               (($incoming -is [array]) -and ($incoming.Count -eq 0))
    if ($isEmpty) { continue }

    $already = $existing.ContainsKey($key) -and ($null -ne $existing[$key]) -and
               -not (($existing[$key] -is [array]) -and ($existing[$key].Count -eq 0))
    if ($already) { $kept += $key; continue }

    $existing[$key] = $incoming
    $added += $key
  }

  ([pscustomobject]$existing) | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $StateFile -Encoding utf8
  Write-Host ('  [1/7 CAPTURE] previous state recorded: {0}' -f $StateFile)
  if ($added.Count -gt 0) { Write-Host ('                captured: {0}' -f ($added -join ', ')) }
  if ($kept.Count -gt 0)  { Write-Host ('                already held (original kept): {0}' -f ($kept -join ', ')) }
}

function Write-Result($action, $verdict, $detail) {
  if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  }
  $line = '{0}  {1,-14} {2,-8} {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
                                        $action, $verdict, $detail
  Add-Content -LiteralPath $ResultLog -Value $line -Encoding utf8
  Write-Host ('  [6/7 RECORD ] {0}' -f $ResultLog)
}

function Show-Status {
  foreach ($p in Get-NetConnectionProfile) {
    Write-Host ('Network       : {0}  category={1}  ipv4={2}' -f `
                $p.Name, [string]$p.NetworkCategory, [string]$p.IPv4Connectivity)
  }
  foreach ($fp in Get-NetFirewallProfile) {
    Write-Host ('Firewall {0,-8}: enabled={1}' -f $fp.Name, $fp.Enabled)
  }
  $sharing = @(Get-PublicSharingRules)
  Write-Host ('File+Printer  : {0} of {1} Public-profile rules enabled' -f `
              (Count-EnabledSharing), $sharing.Count)
  $smb = Get-SmbServerConfiguration
  Write-Host ('SMB           : v1={0} signing-required={1}' -f `
              $smb.EnableSMB1Protocol, $smb.RequireSecuritySignature)
  foreach ($n in @('TermService','WinRM','RemoteRegistry')) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($s) { Write-Host ('{0,-14}: {1}' -f $n, $s.Status) }
  }
  if (Read-State) { Write-Host 'Rollback      : a bruhswer rollback record exists (-Action revert)' }
  else            { Write-Host 'Rollback      : nothing changed by bruhswer' }
}

function Confirm-Or-Exit($word) {
  Write-Host ''
  $answer = Read-Host "[3/7 CONSENT] Type $word to make this change, or anything else to cancel"
  if ($answer -ne $word) { Write-Host 'Cancelled. Nothing was changed.'; exit 0 }
}

Write-Head "bruhswer Host Guard  -  action: $Action"

if ($Action -eq 'status') { Show-Status; exit 0 }

if ($Action -eq 'plan') {
  # Read-only. Shows exactly what -Action fix-* WOULD do. Changes nothing, needs no
  # elevation, and is safe to run at any time.
  Write-Host 'READ-ONLY PLAN. Nothing below has been applied.'
  Write-Host ''
  $net = Get-NetConnectionProfile | Select-Object -First 1
  Write-Host ('Network: {0}  category={1}' -f $net.Name, [string]$net.NetworkCategory)
  Write-Host ''

  $rules = @(Get-PublicSharingRules | Where-Object { $_.Enabled -eq 'True' })
  Write-Host ('== PLAN 1: File and Printer Sharing  ({0} rule(s) affected) ==' -f $rules.Count)
  if ($rules.Count -eq 0) {
    Write-Host '  nothing to do - already off for Public'
  } else {
    Write-Host '  WHY IT MATTERS'
    Write-Host '    On a Public network these rules let other devices reach this PC''s'
    Write-Host '    file and printer sharing, including SMB and NetBIOS.'
    Write-Host ''
    Write-Host '  WHAT CHANGES  (Public is removed from each rule''s profile list;'
    Write-Host '                 every other profile the rule had is kept)'
    Write-Host ''
    Write-Host ('    {0,-52} {1,-16} {2}' -f 'RULE', 'CURRENT', 'TARGET')
    foreach ($r in $rules) {
      $kept = Remove-PublicFromProfile ([string]$r.Profile)
      $target = if ($null -eq $kept) { '<disable rule>' } else { ($kept -join ',') }
      $name = $r.DisplayName
      if ($name.Length -gt 52) { $name = $name.Substring(0, 52) }
      Write-Host ('    {0,-52} {1,-16} {2}' -f $name, [string]$r.Profile, $target)
    }
    Write-Host ''
    Write-Host '  HOW IT IS VERIFIED'
    Write-Host '    Every rule re-read: Public must be gone, and every other original'
    Write-Host '    profile must still be there. Any mismatch => REMEDIATION = FAILED'
    Write-Host '    plus an automatic rollback.'
    Write-Host '  HOW IT IS ROLLED BACK'
    Write-Host '    The exact original profile string of every rule is saved first.'
    Write-Host '    -Action revert restores each one and re-reads to confirm.'
  }

  Write-Host ''
  $smb = Get-SmbServerConfiguration
  Write-Host '== PLAN 2: SMB signing =='
  if ($smb.RequireSecuritySignature) {
    Write-Host '  nothing to do - already required'
  } else {
    Write-Host '  WHY IT MATTERS'
    Write-Host '    Unsigned SMB sessions are easier to tamper with or relay.'
    Write-Host ('  WHAT CHANGES   RequireSecuritySignature: {0} -> True' -f $smb.RequireSecuritySignature)
    Write-Host '  SIDE EFFECT    very old devices that cannot sign may fail to connect'
    Write-Host '                 to shares hosted on this PC'
    Write-Host '  VERIFIED BY    re-reading Get-SmbServerConfiguration afterwards'
    Write-Host '  ROLLED BACK BY restoring the previous value, then re-reading it'
  }

  Write-Host ''
  Write-Host 'NOT CHANGED BY EITHER PLAN: Defender, SmartScreen, Secure Boot, VBS,'
  Write-Host 'HVCI, firewall on/off state, services (including the Seagate Toolkit'
  Write-Host 'service on port 30002), adapters, registry security, QEMU,'
  Write-Host 'HypervisorPlatform, and bruhswer''s own browser firewall rules.'
  exit 0
}

if (-not (Test-Admin)) {
  Write-Host 'REFUSING TO RUN: this needs Administrator.'
  Write-Host 'bruhswer itself never elevates. Run this script as administrator instead.'
  exit 2
}

switch ($Action) {

  'fix-sharing' {
    $rules = @(Get-PublicSharingRules | Where-Object { $_.Enabled -eq 'True' })
    if ($rules.Count -eq 0) {
      Write-Host 'Nothing to do: File and Printer Sharing is already off for Public.'
      exit 0
    }

    # WHY THIS SCOPES THE PROFILE INSTEAD OF DISABLING THE RULE
    #
    # These rules are shared across profiles: on this machine 15 of 17 are
    # "Private, Public" and 2 are "Any". Disable-NetFirewallRule would switch them
    # off EVERYWHERE, so file sharing would also break on the user's home and work
    # networks - while this script claimed "Public only". That would have been a
    # false statement, and an unrelated change the user never agreed to.
    #
    # Removing Public from each rule's profile list is the smallest change that
    # actually does what is promised. Private and Domain keep working untouched.
    $plan = @()
    foreach ($r in $rules) {
      $kept = Remove-PublicFromProfile ([string]$r.Profile)
      $plan += [pscustomobject]@{
        Name = $r.Name; Display = $r.DisplayName
        Original = [string]$r.Profile
        Target = if ($null -eq $kept) { '<disable rule>' } else { ($kept -join ',') }
        Kept = $kept
      }
    }

    Write-Host '[2/7 EXPLAIN]'
    Write-Host '  THE RISK'
    Write-Host '    Windows file sharing is reachable on networks marked Public. On'
    Write-Host '    university, cafe or hotel Wi-Fi, other devices may reach this PC.'
    Write-Host '  THE CHANGE'
    Write-Host ('    Remove the Public profile from {0} "{1}" rule(s).' -f $plan.Count, $SharingGroup)
    Write-Host '    Each rule keeps every other profile it already had, so file sharing'
    Write-Host '    on Private (home) and Domain (work) networks is UNAFFECTED.'
    Write-Host ''
    foreach ($p in $plan) {
      Write-Host ('      {0,-56} {1,-16} -> {2}' -f `
                  $p.Display.Substring(0, [Math]::Min(56, $p.Display.Length)),
                  $p.Original, $p.Target)
    }
    Write-Host ''
    Write-Host '  HOW IT IS VERIFIED'
    Write-Host '    Each rule is re-read afterwards. Public must be gone AND every'
    Write-Host '    other original profile must still be present. Any mismatch =>'
    Write-Host '    REMEDIATION = FAILED and an automatic rollback.'
    Write-Host '  THE UNDO'
    Write-Host '    bruhswer-hostguard.ps1 -Action revert   (restores each exact value)'
    Write-Host '  NOT CHANGED: Defender, SmartScreen, Secure Boot, VBS, HVCI, firewall'
    Write-Host '               on/off state, services, adapters, registry security,'
    Write-Host '               the Toolkit service, QEMU, HypervisorPlatform.'

    Confirm-Or-Exit 'FIX'

    Save-State @{ SharingProfiles = @($plan | ForEach-Object {
                                        @{ Name = $_.Name; Profile = $_.Original } })
                  SharingRuleNames = @()
                  SmbRequireSigning = $null }

    Write-Host '  [4/7 APPLY  ] removing Public from each rule'
    $applyErrors = @()
    foreach ($p in $plan) {
      try {
        if ($null -eq $p.Kept) { Disable-NetFirewallRule -Name $p.Name -ErrorAction Stop }
        else { Set-NetFirewallRule -Name $p.Name -Profile $p.Kept -ErrorAction Stop }
      } catch {
        $applyErrors += ('{0}: {1}' -f $p.Display, $_.Exception.Message)
      }
    }

    Write-Host '  [5/7 VERIFY ] re-reading every rule'
    $problems = @($applyErrors)
    foreach ($p in $plan) {
      $now = Get-NetFirewallRule -Name $p.Name -ErrorAction SilentlyContinue
      if (-not $now) { $problems += ('{0}: rule vanished' -f $p.Display); continue }
      $nowProfiles = Expand-Profile ([string]$now.Profile)
      if ($now.Enabled -eq 'True' -and $nowProfiles -contains 'Public') {
        $problems += ('{0}: still applies to Public' -f $p.Display)
      }
      foreach ($keep in (Expand-Profile $p.Original | Where-Object { $_ -ne 'Public' })) {
        if ($nowProfiles -notcontains $keep) {
          $problems += ('{0}: lost the {1} profile, which it should have kept' -f $p.Display, $keep)
        }
      }
    }
    $stillPublic = Count-EnabledSharing
    Write-Host ('    enabled sharing rules still applying to Public: {0}' -f $stillPublic)
    Write-Host ('    verification problems: {0}' -f $problems.Count)

    if ($problems.Count -gt 0 -or $stillPublic -ne 0) {
      Write-Host ''
      Write-Host 'REMEDIATION = FAILED' -ForegroundColor Red
      foreach ($p in $problems) { Write-Host ('    {0}' -f $p) }
      Write-Host '  Rolling back automatically.'
      foreach ($p in $plan) {
        try {
          Set-NetFirewallRule -Name $p.Name -Profile (Expand-Profile $p.Original) -ErrorAction Stop
          Enable-NetFirewallRule -Name $p.Name -ErrorAction SilentlyContinue
        } catch { }
      }
      Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
      Write-Result 'fix-sharing' 'FAILED' (($problems -join '; ') + " stillPublic=$stillPublic")
      exit 6
    }

    Write-Result 'fix-sharing' 'OK' ("removed Public from {0} rule(s)" -f $plan.Count)
    Write-Host '  [7/7 ROLLBACK] available: -Action revert'
    Write-Host ''
    Write-Host 'REMEDIATION = VERIFIED' -ForegroundColor Green
  }

  'fix-smb' {
    $smb = Get-SmbServerConfiguration
    if ($smb.RequireSecuritySignature) {
      Write-Host 'Nothing to do: SMB signing is already required.'
      exit 0
    }
    Write-Host '[2/7 EXPLAIN]'
    Write-Host '  THE RISK'
    Write-Host '    Without signing, SMB sessions are easier to tamper with or relay.'
    Write-Host '  THE CHANGE'
    Write-Host '    Set RequireSecuritySignature = true on the SMB server. One setting.'
    Write-Host '  SIDE EFFECT, stated honestly'
    Write-Host '    Very old devices that cannot sign may fail to connect to shares on'
    Write-Host '    this PC. Undo restores the previous value exactly.'
    Write-Host '  THE UNDO'
    Write-Host '    bruhswer-hostguard.ps1 -Action revert'

    Confirm-Or-Exit 'FIX'

    Save-State @{ SharingRuleNames  = @()
                  SmbRequireSigning = [bool]$smb.RequireSecuritySignature }

    Write-Host '  [4/7 APPLY  ] setting RequireSecuritySignature'
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

    $now = (Get-SmbServerConfiguration).RequireSecuritySignature
    Write-Host ('  [5/7 VERIFY ] SMB signing required: {0}' -f $now)
    if (-not $now) {
      Write-Host ''
      Write-Host 'REMEDIATION = FAILED' -ForegroundColor Red
      Write-Host '  The setting did not take effect. Rolling back automatically.'
      Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
      Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
      Write-Result 'fix-smb' 'FAILED' 'setting did not take effect, rolled back'
      exit 6
    }
    Write-Result 'fix-smb' 'VERIFIED' 'RequireSecuritySignature=true'
    Write-Host '  [7/7 ROLLBACK] available: -Action revert'
    Write-Host ''
    Write-Host 'REMEDIATION = VERIFIED' -ForegroundColor Green
  }

  'revert' {
    $state = Read-State
    if (-not $state) {
      Write-Host 'Nothing to revert: bruhswer has no rollback record on this machine.'
      exit 0
    }
    Write-Host 'Restoring the state recorded before bruhswer made any change.'
    $problems = @()

    # Profile-scoping rollback: restore each rule's EXACT original profile string.
    $profiles = @($state.SharingProfiles)
    if ($profiles.Count -gt 0) {
      Write-Host ('  restoring the original profile on {0} rule(s)' -f $profiles.Count)
      foreach ($entry in $profiles) {
        try {
          Set-NetFirewallRule -Name $entry.Name -Profile (Expand-Profile $entry.Profile) -ErrorAction Stop
          Enable-NetFirewallRule -Name $entry.Name -ErrorAction SilentlyContinue
        } catch {
          $problems += ("could not restore {0}: {1}" -f $entry.Name, $_.Exception.Message)
        }
      }
      # SS8: never assume the rollback worked. Re-read every rule and compare.
      $mismatched = @()
      foreach ($entry in $profiles) {
        $r = Get-NetFirewallRule -Name $entry.Name -ErrorAction SilentlyContinue
        if (-not $r) { $mismatched += ("{0}: missing" -f $entry.Name); continue }
        $want = @(Expand-Profile $entry.Profile | Sort-Object)
        $have = @(Expand-Profile ([string]$r.Profile) | Sort-Object)
        if (($want -join ',') -ne ($have -join ',')) {
          $mismatched += ("{0}: profile is '{1}', expected '{2}'" -f $entry.Name, ($have -join ','), ($want -join ','))
        }
      }
      Write-Host ('  VERIFY: {0} of {1} rule(s) restored exactly' -f `
                  ($profiles.Count - $mismatched.Count), $profiles.Count)
      $problems += $mismatched
    }

    # Legacy record from the older disable-based implementation.
    $names = @($state.SharingRuleNames)
    if ($names.Count -gt 0) {
      Write-Host ('  re-enabling {0} firewall rule(s) (legacy record)' -f $names.Count)
      foreach ($n in $names) {
        try { Enable-NetFirewallRule -Name $n -ErrorAction Stop }
        catch { $problems += ("could not re-enable {0}: {1}" -f $n, $_.Exception.Message) }
      }
    }

    if ($null -ne $state.SmbRequireSigning) {
      $want = [bool]$state.SmbRequireSigning
      Write-Host ('  restoring SMB signing to {0}' -f $want)
      Set-SmbServerConfiguration -RequireSecuritySignature $want -Force
      $now = (Get-SmbServerConfiguration).RequireSecuritySignature
      Write-Host ('  VERIFY: SMB signing required = {0}' -f $now)
      if ($now -ne $want) { $problems += "SMB signing did not return to its original value" }
    }

    if ($problems.Count -gt 0) {
      Write-Host ''
      Write-Host 'ROLLBACK = FAILED' -ForegroundColor Red
      foreach ($p in $problems) { Write-Host ('  {0}' -f $p) }
      Write-Host '  The rollback record has been KEPT so you can retry.'
      Write-Result 'revert' 'FAILED' ($problems -join '; ')
      exit 7
    }

    Remove-Item -LiteralPath $StateFile -Force
    Write-Result 'revert' 'OK' 'original state restored and verified'
    Write-Host '  rollback record removed.'
    Write-Host ''
    Write-Host 'ROLLBACK = OK' -ForegroundColor Green
    Write-Head 'STATE AFTER REVERT'
    Show-Status
  }
}

exit 0
