# B17: extract the AUTHORITATIVE Authenticode signing time from a PE file.
#
# WHY: Get-AuthenticodeSignature reports the timestamper's certificate but not the
# signing time itself. The B17 question - was the binary signed BEFORE or AFTER its
# signing certificate expired? - can only be answered from the countersignature's
# signingTime attribute. signtool.exe is not installed on this host, so the PE
# security directory is parsed directly.
#
# Read-only. Modifies nothing.

param([string]$Path = 'C:\Program Files\qemu\qemu-system-x86_64.exe')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security

$bytes = [System.IO.File]::ReadAllBytes($Path)

# --- locate the certificate table in the PE optional header -------------------
$peOff = [BitConverter]::ToInt32($bytes, 0x3C)
if ([System.Text.Encoding]::ASCII.GetString($bytes, $peOff, 4) -ne "PE`0`0") { throw 'not a PE file' }
$optOff = $peOff + 24
$magic  = [BitConverter]::ToUInt16($bytes, $optOff)
# PE32+ (0x20B) puts the data directories at +112; PE32 (0x10B) at +96.
$ddOff  = $optOff + $(if ($magic -eq 0x20B) { 112 } else { 96 })
$secRva = [BitConverter]::ToInt32($bytes, $ddOff + 4 * 8)       # IMAGE_DIRECTORY_ENTRY_SECURITY
$secSize= [BitConverter]::ToInt32($bytes, $ddOff + 4 * 8 + 4)

Write-Host "File            : $Path"
Write-Host "PE magic        : 0x$($magic.ToString('X3'))  ($(if($magic -eq 0x20B){'PE32+'}else{'PE32'}))"
Write-Host "Security dir    : offset=$secRva size=$secSize"
if ($secRva -eq 0 -or $secSize -eq 0) { Write-Host 'NO EMBEDDED SIGNATURE'; return }

# WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2) then bCertificate
$pkcs7 = New-Object byte[] ($secSize - 8)
[Array]::Copy($bytes, $secRva + 8, $pkcs7, 0, $secSize - 8)

$cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
$cms.Decode($pkcs7)

$OID_SIGNING_TIME = '1.2.840.113549.1.9.5'

function Show-SigningTime($signerInfo, [string]$label) {
    foreach ($attr in $signerInfo.SignedAttributes) {
        if ($attr.Oid.Value -eq $OID_SIGNING_TIME) {
            foreach ($v in $attr.Values) {
                $t = New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime (, $v.RawData)
                Write-Host "$label signingTime : $($t.SigningTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" -ForegroundColor Cyan
                return $t.SigningTime.ToUniversalTime()
            }
        }
    }
    return $null
}

$signer = $cms.SignerInfos[0]
Write-Host ''
Write-Host "Primary signer  : $($signer.Certificate.Subject)"
Write-Host "  issuer        : $($signer.Certificate.Issuer)"
Write-Host "  NotBefore     : $($signer.Certificate.NotBefore.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Host "  NotAfter      : $($signer.Certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
$null = Show-SigningTime $signer '  primary'

Write-Host ''
Write-Host "Countersigners  : $($signer.CounterSignerInfos.Count)"
$tsTime = $null
foreach ($cs in $signer.CounterSignerInfos) {
    Write-Host "  counterSigner : $($cs.Certificate.Subject)"
    $t = Show-SigningTime $cs '  timestamp'
    if ($t) { $tsTime = $t }
}

# RFC3161 timestamps live in an unsigned attribute rather than a countersigner.
if (-not $tsTime) {
    foreach ($attr in $signer.UnsignedAttributes) {
        Write-Host "  unsigned attr : $($attr.Oid.Value) $($attr.Oid.FriendlyName)"
        if ($attr.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1') {
            Write-Host '    (RFC3161 nested timestamp present - value not decoded here)' -ForegroundColor Yellow
        }
    }
}

Write-Host ''
Write-Host '=== VERDICT ===' -ForegroundColor Cyan
if ($tsTime) {
    $na = $signer.Certificate.NotAfter.ToUniversalTime()
    $nb = $signer.Certificate.NotBefore.ToUniversalTime()
    if ($tsTime -gt $na) {
        Write-Host "SIGNED AFTER CERTIFICATE EXPIRY. timestamp=$($tsTime.ToString('yyyy-MM-dd')) > NotAfter=$($na.ToString('yyyy-MM-dd'))" -ForegroundColor Red
        Write-Host 'Timestamping cannot rescue this: it proves signing happened after expiry.' -ForegroundColor Red
    } elseif ($tsTime -lt $nb) {
        Write-Host "Signed BEFORE certificate validity began - anomalous." -ForegroundColor Red
    } else {
        Write-Host "Signed WHILE certificate was valid. Expiry alone should NOT invalidate it." -ForegroundColor Green
        Write-Host 'If Windows still reports NotTimeValid, the cause lies elsewhere in the chain.' -ForegroundColor Yellow
    }
} else {
    Write-Host 'No decodable signingTime found; cannot determine when signing occurred.' -ForegroundColor Yellow
}
