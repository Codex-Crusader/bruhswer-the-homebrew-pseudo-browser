# Stage 2.5 gate B16: does a Windows Firewall outbound rule scoped by -Program
# actually block the named program from reaching RFC1918 addresses?
#
# WHY THIS MATTERS
# B7-pre measured that AppContainer blocks loopback and the host's own IP but does
# NOT block remote LAN peers on this network (NetworkCategory=Public). So the firewall
# layer is load-bearing, not defence in depth. Stage 2 is the cautionary precedent:
# the Hyper-V Firewall cmdlets existed, accepted rules, reported success - and the
# boundary still did not hold. Efficacy must be measured, not assumed.
#
# STAND-IN: System32 curl.exe. QEMU is NOT installed and nothing here installs it.
#
# HOST IMPACT: creates exactly ONE outbound firewall rule, tests, and removes it in a
# finally block so it is removed even on error. No other host state is touched.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RULE = 'BM-Stage25-B16-curl-deny-rfc1918'
$CURL = Join-Path $env:SystemRoot 'System32\curl.exe'
$PRIVATE = @('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16')

# Predetermined targets only. No scanning, no device enumeration.
$ROUTER   = 'http://10.0.0.1/'          # remote LAN peer  -> MUST become blocked
$INTERNET = 'https://1.1.1.1/'            # internet         -> MUST stay reachable
$LOOPBACK = 'http://127.0.0.1:135/'       # host RPC listener-> firewall cannot filter loopback

function Probe([string]$label, [string]$url) {
    # curl exit: 0 ok | 7 couldn't connect | 28 timeout | 52/56 connected but not HTTP
    # NOTE: no '2>&1' here. In PowerShell 5.1 redirecting a native command's stderr wraps
    # each line in an ErrorRecord, which ErrorActionPreference='Stop' turns terminating.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # No '-w ""' here: PowerShell drops an empty-string argument, so curl would consume
    # the URL as the value of -w and fail with "no URL specified" (exit 2).
    & $CURL -s -m 6 -o NUL $url | Out-Null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    $reached = $code -in 0, 52, 56
    $verdict = if ($reached) { 'REACHED' } else { 'BLOCKED' }
    '{0,-34} {1,-10} (curl exit {2})' -f $label, $verdict, $code
}

Write-Host '=== EXACT CHANGE THIS SCRIPT MAKES ===' -ForegroundColor Cyan
Write-Host "  Creates ONE outbound Block rule '$RULE'"
Write-Host "  scoped to program: $CURL"
Write-Host "  for remote addresses: $($PRIVATE -join ', ')"
Write-Host '  Then removes it. Nothing else on the host is modified.'
Write-Host ''

Write-Host '--- BASELINE (no rule) ---' -ForegroundColor Yellow
Probe 'REMOTE LAN router 10.0.0.1' $ROUTER
Probe 'INTERNET 1.1.1.1'             $INTERNET
Probe 'LOOPBACK 127.0.0.1:135'       $LOOPBACK

try {
    New-NetFirewallRule -DisplayName $RULE -Name $RULE `
        -Direction Outbound -Action Block -Enabled True `
        -Program $CURL -RemoteAddress $PRIVATE -Profile Any | Out-Null
    Write-Host ''
    Write-Host '--- RULE ACTIVE ---' -ForegroundColor Green
    Get-NetFirewallRule -Name $RULE |
        Select-Object Name, Direction, Action, Enabled, Profile | Format-Table -AutoSize | Out-String -Width 160
    (Get-NetFirewallRule -Name $RULE | Get-NetFirewallAddressFilter |
        Select-Object RemoteAddress | Format-Table -AutoSize | Out-String -Width 160)
    (Get-NetFirewallRule -Name $RULE | Get-NetFirewallApplicationFilter |
        Select-Object Program | Format-Table -AutoSize | Out-String -Width 160)

    Write-Host '--- WITH RULE ACTIVE ---' -ForegroundColor Yellow
    Probe 'REMOTE LAN router 10.0.0.1' $ROUTER
    Probe 'INTERNET 1.1.1.1'             $INTERNET
    Probe 'LOOPBACK 127.0.0.1:135'       $LOOPBACK
}
finally {
    if (Get-NetFirewallRule -Name $RULE -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -Name $RULE
        Write-Host ''
        Write-Host "[cleanup] removed rule $RULE" -ForegroundColor Cyan
    }
    $left = Get-NetFirewallRule -Name $RULE -ErrorAction SilentlyContinue
    if ($left) { Write-Warning 'RULE STILL PRESENT' } else { Write-Host '[cleanup] verified: rule absent' -ForegroundColor Green }
}

Write-Host ''
Write-Host '--- POST-CLEANUP (should match baseline) ---' -ForegroundColor Yellow
Probe 'REMOTE LAN router 10.0.0.1' $ROUTER
Probe 'INTERNET 1.1.1.1'             $INTERNET
