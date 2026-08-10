# Stage 2 verification: apply host-side Hyper-V Firewall policy to the WSL utility VM.
#
# ELEVATED, ONE-SHOT, INTERACTIVE. The runtime controller never calls this.
# Every value below is fixed in source. Nothing is taken from arguments, the guest,
# or any web content. There is no generic command execution path here.
#
# Reversible with: tools\stage2\revert-hyperv-firewall.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The WSL VM creator ID, as reported by Get-NetFirewallHyperVVMSetting on this host.
$VMCREATOR = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
$PREFIX    = 'BM-Stage2'
$STATEFILE = "$env:LOCALAPPDATA\bm-stage2\original-vmsetting.json"
$LOG       = "$env:LOCALAPPDATA\bm-stage2\apply-firewall.log"

# Address ranges the browsing guest must never reach.
$PRIVATE_V4 = @('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','127.0.0.0/8')
# NOTE: both '::1/128' and bare '::1' are rejected by New-NetFirewallHyperVRule with
# Windows error 87 (measured 2026-08-08). Range form is attempted instead.
# Blocking the guest's OWN loopback here is in any case near-meaningless: guest loopback
# traffic never traverses the vNIC, so the host-side firewall never sees it. Host loopback
# is controlled by -LoopbackEnabled False, and WSL's 10.255.255.254 host-forwarding
# address is already covered by the 10.0.0.0/8 rule.
$PRIVATE_V6 = @('fc00::/7','fe80::/10','::1-::1')

Start-Transcript -Path $LOG -Force | Out-Null

Write-Host "=== EXACT CHANGES THIS SCRIPT MAKES ===" -ForegroundColor Cyan
Write-Host "Scope: Hyper-V Firewall policy for VMCreatorId $VMCREATOR (the WSL utility VM) ONLY."
Write-Host "  1. Record current VM setting to $STATEFILE"
Write-Host "  2. Set DefaultOutboundAction = Block   (currently Allow)"
Write-Host "  3. Set DefaultInboundAction  = Block"
Write-Host "  4. Set LoopbackEnabled       = False   (blocks guest -> host loopback)"
Write-Host "  5. Create BLOCK rules (priority 100) for: $($PRIVATE_V4 -join ', ')"
Write-Host "  6. Create BLOCK rules (priority 101) for: $($PRIVATE_V6 -join ', ')"
Write-Host "  7. Create ALLOW rules (priority 1000+) for outbound TCP 80, TCP 443, UDP 443"
Write-Host ""
Write-Host "It does NOT touch: Windows Defender, SmartScreen, the host firewall profiles," -ForegroundColor Yellow
Write-Host "Secure Boot, VBS, HVCI, services, scheduled tasks, drivers, certificates, or the registry." -ForegroundColor Yellow
Write-Host ""

# --- 0. make re-runs safe ------------------------------------------------------
# Remove any rules this script previously created, so re-running after a partial
# failure does not collide on rule names.
$stale = Get-NetFirewallHyperVRule -PolicyStore ActiveStore | Where-Object { $_.Name -like "$PREFIX-*" }
foreach ($r in $stale) { Remove-NetFirewallHyperVRule -Name $r.Name -ErrorAction Continue; Write-Host "  cleared stale rule $($r.Name)" }

# --- 1. record original state so revert is exact -------------------------------
# GUARDED: only capture once. Re-running after the defaults have already been
# changed must not overwrite the true pre-change values with the hardened ones.
New-Item -ItemType Directory -Force (Split-Path $STATEFILE) | Out-Null
if (Test-Path $STATEFILE) {
    Write-Host "[1/7] Original VM setting ALREADY recorded - not overwriting:" -ForegroundColor Yellow
} else {
    $orig = Get-NetFirewallHyperVVMSetting -Name $VMCREATOR -PolicyStore ActiveStore
    [pscustomobject]@{
        Name                  = $VMCREATOR
        DefaultInboundAction  = "$($orig.DefaultInboundAction)"
        DefaultOutboundAction = "$($orig.DefaultOutboundAction)"
        LoopbackEnabled       = "$($orig.LoopbackEnabled)"
        Enabled               = "$($orig.Enabled)"
        CapturedUtc           = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json | Set-Content -Path $STATEFILE -Encoding utf8
    Write-Host "[1/7] Original VM setting recorded:" -ForegroundColor Green
}
Get-Content $STATEFILE

# --- 2-4. VM-level defaults ----------------------------------------------------
# AllowHostPolicyMerge defaults to True (measured 2026-08-08). With it True, host
# firewall policy merges into the VM's policy, which was measured to let the guest
# reach host services on 445/135 despite an explicit deny for 10.0.0.0/8.
Set-NetFirewallHyperVVMSetting -Name $VMCREATOR `
    -DefaultOutboundAction Block `
    -DefaultInboundAction  Block `
    -LoopbackEnabled       False `
    -AllowHostPolicyMerge  False
Write-Host "[2-4/7] VM defaults: Block/Block, LoopbackEnabled=False, AllowHostPolicyMerge=False" -ForegroundColor Green

# --- 5-6. explicit deny rules for private space (highest precedence) -----------
# Priority is evaluated low-number-first, so these are considered before the allows.
# Each rule is attempted independently. A range the platform rejects is recorded as a
# GAP rather than aborting the run - an aborted run would leave the guest with Block
# defaults and no allowlist, and would hide which ranges are actually enforceable.
$script:gaps = @()
function New-DenyRule([string]$name, [string]$cidr, [int]$prio) {
    try {
        New-NetFirewallHyperVRule -Name $name -DisplayName "$PREFIX Deny $cidr" `
            -VMCreatorId $VMCREATOR -Direction Outbound -Action Block `
            -Protocol Any -RemoteAddresses $cidr -RulePriority $prio -Enabled True -ErrorAction Stop | Out-Null
        Write-Host "  blocked $cidr" -ForegroundColor Green
    } catch {
        $script:gaps += $cidr
        Write-Host "  GAP: platform REJECTED $cidr -> $($_.Exception.Message)" -ForegroundColor Red
    }
}
$i = 0; foreach ($cidr in $PRIVATE_V4) { $i++; New-DenyRule "$PREFIX-DenyV4-$i" $cidr 100 }
$i = 0; foreach ($cidr in $PRIVATE_V6) { $i++; New-DenyRule "$PREFIX-DenyV6-$i" $cidr 101 }
Write-Host "[5-6/7] Deny rules processed. Unenforceable ranges: $(if($script:gaps){$script:gaps -join ', '}else{'none'})" -ForegroundColor Cyan

# --- 7. minimal egress allowlist ----------------------------------------------
New-NetFirewallHyperVRule -Name "$PREFIX-AllowHttps" -DisplayName "$PREFIX Allow TCP 443" `
    -VMCreatorId $VMCREATOR -Direction Outbound -Action Allow `
    -Protocol TCP -RemotePorts 443 -RulePriority 1000 -Enabled True | Out-Null
New-NetFirewallHyperVRule -Name "$PREFIX-AllowHttp" -DisplayName "$PREFIX Allow TCP 80" `
    -VMCreatorId $VMCREATOR -Direction Outbound -Action Allow `
    -Protocol TCP -RemotePorts 80 -RulePriority 1001 -Enabled True | Out-Null
New-NetFirewallHyperVRule -Name "$PREFIX-AllowQuic" -DisplayName "$PREFIX Allow UDP 443 (QUIC)" `
    -VMCreatorId $VMCREATOR -Direction Outbound -Action Allow `
    -Protocol UDP -RemotePorts 443 -RulePriority 1002 -Enabled True | Out-Null
Write-Host "[7/7] Egress allowlist created (TCP 80, TCP 443, UDP 443)" -ForegroundColor Green

Write-Host ""
Write-Host "=== RESULTING STATE ===" -ForegroundColor Cyan
Get-NetFirewallHyperVVMSetting -Name $VMCREATOR -PolicyStore ActiveStore |
    Select-Object Name, DefaultInboundAction, DefaultOutboundAction, LoopbackEnabled, Enabled |
    Format-List
Get-NetFirewallHyperVRule -PolicyStore ActiveStore |
    Where-Object { $_.Name -like "$PREFIX-*" } |
    Select-Object Name, Direction, Action, Protocol, RemotePorts, RemoteAddresses, Priority |
    Format-Table -AutoSize | Out-String -Width 200

Stop-Transcript | Out-Null
Write-Host "Done. Revert with tools\stage2\revert-hyperv-firewall.ps1" -ForegroundColor Cyan
