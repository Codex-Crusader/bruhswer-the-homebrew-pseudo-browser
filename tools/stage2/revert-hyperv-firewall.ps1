# Stage 2 verification: revert everything apply-hyperv-firewall.ps1 changed.
# ELEVATED, ONE-SHOT. Restores the WSL VM firewall setting captured before the change
# and removes only rules named with the BM-Stage2 prefix.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$VMCREATOR = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
$PREFIX    = 'BM-Stage2'
$STATEFILE = "$env:LOCALAPPDATA\bm-stage2\original-vmsetting.json"

Write-Host "=== REVERTING Stage 2 Hyper-V Firewall changes ===" -ForegroundColor Cyan

# Remove only our own rules, identified by the BM-Stage2 name prefix.
$ours = Get-NetFirewallHyperVRule -PolicyStore ActiveStore | Where-Object { $_.Name -like "$PREFIX-*" }
if ($ours) {
    foreach ($r in $ours) {
        Remove-NetFirewallHyperVRule -Name $r.Name -ErrorAction Continue
        Write-Host "  removed rule $($r.Name)"
    }
} else {
    Write-Host "  no $PREFIX-* rules present"
}

# Restore the recorded VM defaults. Fail loudly rather than guessing.
if (Test-Path $STATEFILE) {
    $o = Get-Content $STATEFILE -Raw | ConvertFrom-Json
    # AllowHostPolicyMerge was measured as True before any Stage 2 change. It is not in
    # the original state file (added to the apply script later), so it is restored explicitly.
    Set-NetFirewallHyperVVMSetting -Name $VMCREATOR `
        -DefaultInboundAction  $o.DefaultInboundAction `
        -DefaultOutboundAction $o.DefaultOutboundAction `
        -LoopbackEnabled       $o.LoopbackEnabled `
        -AllowHostPolicyMerge  True
    Write-Host "  restored: Inbound=$($o.DefaultInboundAction) Outbound=$($o.DefaultOutboundAction) Loopback=$($o.LoopbackEnabled) HostPolicyMerge=True" -ForegroundColor Green
} else {
    Write-Warning "  $STATEFILE missing - cannot restore defaults automatically."
    Write-Warning "  Pre-change values measured on 2026-08-08 were: Inbound=Block Outbound=Allow"
}

Write-Host "=== RESULTING STATE ===" -ForegroundColor Cyan
Get-NetFirewallHyperVVMSetting -Name $VMCREATOR -PolicyStore ActiveStore |
    Select-Object Name, DefaultInboundAction, DefaultOutboundAction, LoopbackEnabled, Enabled | Format-List
$left = Get-NetFirewallHyperVRule -PolicyStore ActiveStore | Where-Object { $_.Name -like "$PREFIX-*" }
if ($left) { Write-Warning "Rules still present: $($left.Name -join ', ')" } else { Write-Host "No BM-Stage2 rules remain." -ForegroundColor Green }
