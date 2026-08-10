<#
Stage 4 gates A20 / A21 / A34 - host exposure on an untrusted network, and host
security preservation.

A20/A21 are Threat Model C: what can OTHER DEVICES on the university/public Wi-Fi
reach on this machine? That is a different question from the browser's own network
isolation (A10-A16) and must not be collapsed into it.

A34 is the standing requirement that this project never weakens the host: Defender,
SmartScreen, Secure Boot, VBS, HVCI and the firewall must be exactly as found.

READ-ONLY. This script changes nothing. It enumerates only THIS machine's own
configuration and listening sockets - it does not scan, probe, or enumerate the LAN
(brief SS22, SS25).
#>

$ErrorActionPreference = 'Continue'

function Section($t) {
  Write-Host ""
  Write-Host ("=" * 74)
  Write-Host $t
  Write-Host ("=" * 74)
}

Section "A21 - NETWORK PROFILE AND FIREWALL STATE"
Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory,
  IPv4Connectivity, IPv6Connectivity | Format-List
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction,
  DefaultOutboundAction, AllowInboundRules | Format-Table -AutoSize

Section "A20 - LISTENING TCP SOCKETS (this machine only; no LAN scanning)"
Write-Host "Sockets bound to a WILDCARD or the LAN address are reachable from the Wi-Fi."
Write-Host "Sockets bound to 127.0.0.1 / ::1 are reachable only from this machine."
Write-Host ""
$listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
$rows = foreach ($c in $listen) {
  $procName = try { (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { '<unknown>' }
  $scope = if ($c.LocalAddress -in @('0.0.0.0','::')) { 'WILDCARD (LAN-reachable)' }
           elseif ($c.LocalAddress -in @('127.0.0.1','::1')) { 'loopback only' }
           else { 'specific: ' + $c.LocalAddress }
  [pscustomobject]@{ Port = $c.LocalPort; Scope = $scope; Process = $procName }
}
$rows | Sort-Object Scope, Port | Group-Object Scope | ForEach-Object {
  Write-Host ("--- {0} : {1} socket(s) ---" -f $_.Name, $_.Count)
  $_.Group | Sort-Object Port -Unique | Format-Table Port, Process -AutoSize | Out-String | Write-Host
}

Section "A20 - HIGH-VALUE INBOUND SERVICES"
foreach ($svc in @('LanmanServer','TermService','RemoteRegistry','SSDPSRV','FDResPub','upnphost','WinRM')) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($s) { Write-Host ("{0,-16} status={1,-8} startup={2}" -f $svc, $s.Status, $s.StartType) }
  else    { Write-Host ("{0,-16} NOT PRESENT" -f $svc) }
}
Write-Host ""
Write-Host "SMB server configuration:"
try {
  Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol,
    RequireSecuritySignature, EnableSecuritySignature, RestrictNamedPipeAccess |
    Format-List
} catch { Write-Host ("  Get-SmbServerConfiguration failed: {0}" -f $_.Exception.Message) }
Write-Host "SMB shares (names only):"
try { (Get-SmbShare -ErrorAction Stop | Select-Object -ExpandProperty Name) -join ', ' }
catch { Write-Host ("  Get-SmbShare failed: {0}" -f $_.Exception.Message) }

Section "A21 - INBOUND FIREWALL EXPOSURE ON THE PUBLIC PROFILE"
Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
  Where-Object { $_.Profile -match 'Public' -or $_.Profile -eq 'Any' } |
  Group-Object DisplayGroup |
  Sort-Object Count -Descending | Select-Object -First 12 |
  Format-Table @{n='EnabledInboundRules';e={$_.Count}}, Name -AutoSize

Write-Host "Network discovery / file sharing group state (Public profile):"
foreach ($g in @('Network Discovery','File and Printer Sharing','Remote Desktop')) {
  $r = Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue |
       Where-Object { $_.Profile -match 'Public' -or $_.Profile -eq 'Any' }
  $on = @($r | Where-Object { $_.Enabled -eq 'True' }).Count
  Write-Host ("  {0,-28} enabled rules applying to Public: {1} of {2}" -f $g, $on, @($r).Count)
}

Section "A34 - HOST SECURITY PRESERVATION (must match the Stage 3 baseline)"
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  Write-Host ("Defender realtime            : {0}" -f $mp.RealTimeProtectionEnabled)
  Write-Host ("Defender antispyware enabled : {0}" -f $mp.AntispywareEnabled)
  Write-Host ("Tamper protection            : {0}" -f $mp.IsTamperProtected)
} catch { Write-Host ("Get-MpComputerStatus failed: {0}" -f $_.Exception.Message) }
try {
  $pref = Get-MpPreference -ErrorAction Stop
  Write-Host ("Controlled Folder Access     : {0}" -f $pref.EnableControlledFolderAccess)
  Write-Host ("Defender exclusion paths     : {0}" -f @($pref.ExclusionPath).Count)
} catch { }
try { Write-Host ("Secure Boot                  : {0}" -f (Confirm-SecureBootUEFI)) }
catch { Write-Host "Secure Boot                  : query failed" }
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($dg) {
  Write-Host ("VBS status                   : {0}" -f $dg.VirtualizationBasedSecurityStatus)
  Write-Host ("Security services running    : {0}" -f ($dg.SecurityServicesRunning -join ','))
}
Write-Host ("SmartScreen (Explorer)       : {0}" -f (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled)
Write-Host ""
Write-Host "Firewall rules created by this project that still exist (must be 0):"
Write-Host ("  BM-* : {0}" -f @(Get-NetFirewallRule -DisplayName 'BM-*' -ErrorAction SilentlyContinue).Count)
