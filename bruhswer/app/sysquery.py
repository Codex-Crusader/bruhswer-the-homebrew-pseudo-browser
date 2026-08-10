"""The ONLY place bruhswer runs an external program. Read-only queries.

Why this module exists at all: some Windows state (firewall rules, network profile,
Defender status) has no usable Python binding in the standard library, and adding a
dependency for it would grow the trusted stack (brief SS49). So a small number of
fixed, audited PowerShell queries are used instead.

The rules this module enforces, and they are not negotiable (brief SS15, SS48):

  - subprocess is ALWAYS given an explicit argument list. `shell=True` appears nowhere
    in bruhswer.
  - the executable is a fixed absolute path from config, never resolved via PATH.
  - every script is a CONSTANT authored in bruhswer's own source. The only values ever
    substituted are bruhswer's own literals from config.py -- never a URL, filename,
    header, downloaded file, or anything else a webpage can influence.
  - nothing here modifies system state. Changes go through the elevated one-shot in
    tools/, with explicit consent and a rollback (brief SS70).

There is deliberately no generic `run(command)` function. A caller cannot ask this
module to execute something arbitrary, because no such entry point is exposed.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from . import config
from .logging_setup import get_logger

_log = get_logger("sysquery")

_TIMEOUT = 60


def _run_ps(script: str) -> str:
    """Run one constant PowerShell script and return stdout. Never raises on failure."""
    try:
        # No -ExecutionPolicy Bypass. It was pointless here - execution policy applies
        # to script FILES, not to -Command - and a security tool should not carry a
        # flag whose name is "Bypass" for no reason.
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_TIMEOUT, shell=False, creationflags=config.NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _log.warning("sysquery failed: %s", exc.__class__.__name__)
        return ""
    return (proc.stdout or "").strip()


def _run_ps_json(script: str) -> Any:
    raw = _run_ps(script)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        _log.warning("sysquery returned non-JSON output")
        return None


# --- constant scripts -----------------------------------------------------------

# NetworkCategory is an enum: ConvertTo-Json serialises it as an integer, which is
# useless to compare against. Cast every enum to its name inside PowerShell.
_Q_NETWORK_PROFILE = (
    "@(Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,"
    "@{n='NetworkCategory';e={[string]$_.NetworkCategory}},"
    "@{n='IPv4Connectivity';e={[string]$_.IPv4Connectivity}},"
    "@{n='IPv6Connectivity';e={[string]$_.IPv6Connectivity}}) | "
    "ConvertTo-Json -Compress -Depth 3"
)

_Q_FIREWALL_PROFILES = (
    "@(Get-NetFirewallProfile | Select-Object Name,"
    "@{n='Enabled';e={[bool]$_.Enabled}}) | ConvertTo-Json -Compress -Depth 3"
)

_Q_SHARING_GROUPS = (
    "$out=@(); foreach ($g in @('File and Printer Sharing','Network Discovery',"
    "'Remote Desktop')) { $r = Get-NetFirewallRule -DisplayGroup $g "
    "-ErrorAction SilentlyContinue | Where-Object { $_.Profile -match 'Public' "
    "-or $_.Profile -eq 'Any' }; $out += [pscustomobject]@{ Group=$g; "
    "Total=@($r).Count; Enabled=@($r | Where-Object { $_.Enabled -eq 'True' }).Count } }; "
    "$out | ConvertTo-Json -Compress -Depth 3"
)

_Q_LISTENERS = (
    "@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
    "Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } | "
    "Select-Object LocalPort,OwningProcess) | ConvertTo-Json -Compress -Depth 3"
)

_Q_DEFENDER = (
    "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
    "$p = Get-MpPreference -ErrorAction SilentlyContinue; "
    "[pscustomobject]@{ RealTime=[bool]$s.RealTimeProtectionEnabled; "
    "Tamper=[bool]$s.IsTamperProtected; CFA=[int]$p.EnableControlledFolderAccess } | "
    "ConvertTo-Json -Compress"
)

_Q_SMB = (
    "$c = Get-SmbServerConfiguration -ErrorAction SilentlyContinue; "
    "[pscustomobject]@{ SMB1=[bool]$c.EnableSMB1Protocol; SMB2=[bool]$c.EnableSMB2Protocol; "
    "RequireSigning=[bool]$c.RequireSecuritySignature } | ConvertTo-Json -Compress"
)

_Q_IS_ADMIN = (
    "([Security.Principal.WindowsPrincipal]"
    "[Security.Principal.WindowsIdentity]::GetCurrent())"
    ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
)

_Q_DOH = (
    "@(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | "
    "Select-Object ServerAddress,DohTemplate,AutoUpgrade) | ConvertTo-Json -Compress -Depth 3"
)

_Q_DNS_SERVERS = (
    "@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
    "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
    "Select-Object InterfaceAlias,ServerAddresses) | ConvertTo-Json -Compress -Depth 3"
)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def network_profiles() -> list[dict[str, Any]]:
    return _as_list(_run_ps_json(_Q_NETWORK_PROFILE))


def firewall_profiles() -> list[dict[str, Any]]:
    return _as_list(_run_ps_json(_Q_FIREWALL_PROFILES))


def sharing_groups() -> list[dict[str, Any]]:
    return _as_list(_run_ps_json(_Q_SHARING_GROUPS))


def wildcard_listeners() -> list[dict[str, Any]]:
    return _as_list(_run_ps_json(_Q_LISTENERS))


def defender_status() -> dict[str, Any] | None:
    result = _run_ps_json(_Q_DEFENDER)
    return result if isinstance(result, dict) else None


def smb_config() -> dict[str, Any] | None:
    result = _run_ps_json(_Q_SMB)
    return result if isinstance(result, dict) else None


def is_elevated() -> bool | None:
    raw = _run_ps(_Q_IS_ADMIN).strip().lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    return None


_Q_REMOTE_ADMIN = (
    "$out = @(); foreach ($n in @('TermService','WinRM','RemoteRegistry','SSDPSRV',"
    "'upnphost','FDResPub')) { $s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
    "if ($s) { $out += [pscustomobject]@{ Name=$n; Status=[string]$s.Status; "
    "StartType=[string]$s.StartType } } else { $out += [pscustomobject]@{ Name=$n; "
    "Status='ABSENT'; StartType='ABSENT' } } }; $out | ConvertTo-Json -Compress -Depth 3"
)


def remote_admin_status() -> list[dict[str, Any]]:
    """Remote-management surfaces (brief SS5). Read-only service state."""
    return _as_list(_run_ps_json(_Q_REMOTE_ADMIN))


def doh_servers() -> list[dict[str, Any]]:
    return _as_list(_run_ps_json(_Q_DOH))


def dns_servers() -> list[dict[str, Any]]:
    return _as_list(_run_ps_json(_Q_DNS_SERVERS))


def authenticode(exe_path: str) -> dict[str, Any] | None:
    """Authenticode status and signer for one of bruhswer's OWN constant paths.

    This lives here rather than in edge.py so that nothing outside this module has to
    reach for `_run_ps_json`. The rule that there is no public "run this script for me"
    entry point is the whole point of the module, and a caller poking at the private one
    quietly erodes it.

    `exe_path` must be a path bruhswer itself resolved (config.EDGE_CANDIDATES), never
    anything derived from input.
    """
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath '" + exe_path + "'; "
        "[pscustomobject]@{ Status=[string]$s.Status; "
        "Subject=[string]$s.SignerCertificate.Subject } | ConvertTo-Json -Compress"
    )
    result = _run_ps_json(script)
    return result if isinstance(result, dict) else None


def bruhswer_rules() -> list[dict[str, Any]]:
    """bruhswer's own firewall rules and the addresses they cover.

    The rule prefix is a bruhswer constant from config, so nothing external reaches
    this string.
    """
    script = (
        "@(Get-NetFirewallRule -DisplayName '" + config.RULE_PREFIX + "-*' "
        "-ErrorAction SilentlyContinue | ForEach-Object { "
        "$a = $_ | Get-NetFirewallAddressFilter; "
        "$p = $_ | Get-NetFirewallApplicationFilter; "
        "[pscustomobject]@{ Name=$_.DisplayName; Enabled=[string]$_.Enabled; "
        "Action=[string]$_.Action; Direction=[string]$_.Direction; "
        "Remote=@($a.RemoteAddress); Program=[string]$p.Program } }) | "
        "ConvertTo-Json -Compress -Depth 4"
    )
    return _as_list(_run_ps_json(script))
