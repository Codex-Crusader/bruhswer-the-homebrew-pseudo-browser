"""bruhswer's read-only PowerShell queries, for Windows state with no stdlib binding.

Rules: an argument list and never a shell; a fixed PowerShell path; every script a
constant authored here; nothing modifies the system. There is no generic run(command).
edge.py, embed.py, controller.py and browser_guard.py also run programs, under the same
rules (docs/ARCHITECTURE.md).

Every query returns a `Probe` carrying a status, so "none found", "refused" and "timed
out" are different answers. Scripts run inside `_ENVELOPE`, which always writes one
JSON object: a bare ConvertTo-Json of an empty array writes nothing, like a crash.
"""

from __future__ import annotations

import enum
import json
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from . import config
from .logging_setup import get_logger

_log = get_logger("sysquery")

_TIMEOUT = 60

T = TypeVar("T")


class ProbeStatus(enum.Enum):
    """Why a query did or did not answer; becomes the reason code on an UNKNOWN."""

    OK = "OK"
    TIMEOUT = "TIMEOUT"
    # Expected for some state: bruhswer runs unelevated on purpose.
    PERMISSION_DENIED = "PERMISSION_DENIED"
    # The cmdlet does not exist on this edition of Windows.
    UNSUPPORTED = "UNSUPPORTED"
    LAUNCH_FAILED = "LAUNCH_FAILED"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    PROBE_ERROR = "PROBE_ERROR"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Probe(Generic[T]):
    """One query's result and its status. `value` is always usable, never raises."""

    value: T
    status: ProbeStatus
    duration_ms: float
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is ProbeStatus.OK

    def reason(self) -> str:
        """Short evidence string: the status and, if any, the cause."""
        if self.ok:
            return f"status=OK in {self.duration_ms:.0f}ms"
        return (f"status={self.status} in {self.duration_ms:.0f}ms"
                + (f" detail={self.detail[:120]}" if self.detail else ""))


# `{body}` is the only substitution, always a constant from this module.
# [Console]::Out.Write, because Write-Output can wrap the JSON on a narrow console.
_ENVELOPE = (
    "$ErrorActionPreference='Stop'; "
    "try {{ $d = @( {body} ); "
    "$o = [pscustomobject]@{{ ok=$true; err=''; data=$d }} }} "
    "catch {{ $o = [pscustomobject]@{{ ok=$false; "
    "err=[string]$_.Exception.Message; data=@() }} }}; "
    "[Console]::Out.Write((ConvertTo-Json -Compress -Depth 6 -InputObject $o))"
)

_DENIED_SIGNS = ("access is denied", "unauthorizedaccess", "requires elevation",
                 "requested operation requires elevation", "administrator privilege",
                 "permission denied")

_UNSUPPORTED_SIGNS = ("is not recognized as the name of a cmdlet",
                      "commandnotfoundexception", "is not supported",
                      "not supported on this platform", "no matching",
                      "unable to find type")


def _classify(message: str) -> tuple[ProbeStatus, str]:
    low = message.lower()
    if any(sign in low for sign in _DENIED_SIGNS):
        return ProbeStatus.PERMISSION_DENIED, message
    if any(sign in low for sign in _UNSUPPORTED_SIGNS):
        return ProbeStatus.UNSUPPORTED, message
    return ProbeStatus.PROBE_ERROR, message


def _run_probe(name: str, body: str) -> Probe[list[Any]]:
    """Run one constant script inside the envelope. Never raises. On failure `value`
    is [] and the status says which failure."""
    script = _ENVELOPE.format(body=body)
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_TIMEOUT, shell=False, creationflags=config.NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        elapsed = (time.perf_counter() - started) * 1000.0
        _log.warning("probe %s timed out after %.0fms", name, elapsed)
        return Probe([], ProbeStatus.TIMEOUT, elapsed,
                     f"no result within {_TIMEOUT}s")
    except OSError as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        _log.warning("probe %s could not start PowerShell: %s",
                     name, exc.__class__.__name__)
        return Probe([], ProbeStatus.LAUNCH_FAILED, elapsed, exc.__class__.__name__)

    elapsed = (time.perf_counter() - started) * 1000.0
    raw = (proc.stdout or "").strip()
    if not raw:
        # The envelope always writes, so no output means PowerShell died.
        stderr = (proc.stderr or "").strip()
        _log.warning("probe %s produced no envelope (rc=%s)", name, proc.returncode)
        return Probe([], ProbeStatus.MALFORMED_OUTPUT, elapsed,
                     stderr[:200] or f"no output, exit {proc.returncode}")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _log.warning("probe %s returned non-JSON output", name)
        return Probe([], ProbeStatus.MALFORMED_OUTPUT, elapsed, raw[:200])

    if not isinstance(parsed, dict) or "ok" not in parsed:
        _log.warning("probe %s returned JSON that is not the envelope", name)
        return Probe([], ProbeStatus.MALFORMED_OUTPUT, elapsed, raw[:200])

    if not parsed.get("ok"):
        status, detail = _classify(str(parsed.get("err", "")))
        _log.warning("probe %s failed: %s (%s)", name, status, detail[:120])
        return Probe([], status, elapsed, detail)

    # ConvertTo-Json turns a one-element array into a bare object.
    data = parsed.get("data")
    if data is None:
        data = []
    elif not isinstance(data, list):
        data = [data]
    _log.debug("probe %s ok in %.0fms rows=%d", name, elapsed, len(data))
    return Probe(data, ProbeStatus.OK, elapsed)


# SilentlyContinue appears ONLY where the cmdlet throws on "no rows" and no rows is a
# real answer. Elsewhere a refusal must reach _classify(), not look like an empty result.

# Enums are cast to their names; ConvertTo-Json would write integers.
_Q_NETWORK_PROFILE = (
    "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,"
    "@{n='NetworkCategory';e={[string]$_.NetworkCategory}},"
    "@{n='IPv4Connectivity';e={[string]$_.IPv4Connectivity}},"
    "@{n='IPv6Connectivity';e={[string]$_.IPv6Connectivity}}"
)

_Q_FIREWALL_PROFILES = (
    "Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[bool]$_.Enabled}}"
)

# One rule-table walk for all three groups: one per group cost 3N (2,023 ms cold
# against 1,224 ms, 702 rules). Matched on the Group resource ID, because DisplayGroup
# is translated and on non-English Windows matched nothing: "0 of 0 enabled", PASS.
# The IDs were read back from FirewallAPI.dll. InGroup counts rules before the Public
# filter, so "no such rules" and "none apply to Public" stay distinct.
_Q_SHARING_GROUPS = (
    "$groups = [ordered]@{ 'File and Printer Sharing'='@FirewallAPI.dll,-28502'; "
    "'Network Discovery'='@FirewallAPI.dll,-32752'; "
    "'Remote Desktop'='@FirewallAPI.dll,-28752' }; "
    "$all = @(Get-NetFirewallRule -Group @($groups.Values) "
    "-ErrorAction SilentlyContinue); "
    "foreach ($g in $groups.Keys) { "
    "$in = @($all | Where-Object { $_.Group -eq $groups[$g] }); "
    "$r = @($in | Where-Object { $_.Profile -match 'Public' -or $_.Profile -eq 'Any' }); "
    "[pscustomobject]@{ Group=$g; InGroup=$in.Count; Total=$r.Count; "
    "Enabled=@($r | Where-Object { $_.Enabled -eq 'True' }).Count } }"
)

_Q_LISTENERS = (
    "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
    "Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } | "
    "Select-Object LocalPort,OwningProcess"
)

# No SilentlyContinue: with another AV installed this cmdlet is absent (UNSUPPORTED).
_Q_DEFENDER = (
    "$s = Get-MpComputerStatus; $p = Get-MpPreference; "
    "[pscustomobject]@{ RealTime=[bool]$s.RealTimeProtectionEnabled; "
    "Tamper=[bool]$s.IsTamperProtected; CFA=[int]$p.EnableControlledFolderAccess }"
)

# No SilentlyContinue: this is often refused unelevated, and that is PERMISSION_DENIED.
_Q_SMB = (
    "$c = Get-SmbServerConfiguration; "
    "[pscustomobject]@{ SMB1=[bool]$c.EnableSMB1Protocol; "
    "SMB2=[bool]$c.EnableSMB2Protocol; "
    "RequireSigning=[bool]$c.RequireSecuritySignature }"
)

_Q_IS_ADMIN = (
    "([Security.Principal.WindowsPrincipal]"
    "[Security.Principal.WindowsIdentity]::GetCurrent())"
    ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
)

_Q_REMOTE_ADMIN = (
    "foreach ($n in @('TermService','WinRM','RemoteRegistry','SSDPSRV',"
    "'upnphost','FDResPub')) { $s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
    "if ($s) { [pscustomobject]@{ Name=$n; Status=[string]$s.Status; "
    "StartType=[string]$s.StartType } } else { [pscustomobject]@{ Name=$n; "
    "Status='ABSENT'; StartType='ABSENT' } } }"
)

# No SilentlyContinue: the DoH cmdlet does not exist before Windows 10 2004.
_Q_DOH = (
    "Get-DnsClientDohServerAddress | "
    "Select-Object ServerAddress,DohTemplate,AutoUpgrade"
)

_Q_DNS_SERVERS = (
    "Get-DnsClientServerAddress -AddressFamily IPv4 | "
    "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
    "Select-Object InterfaceAlias,ServerAddresses"
)


def network_profiles() -> Probe[list[dict[str, Any]]]:
    return _run_probe("network_profiles", _Q_NETWORK_PROFILE)


def firewall_profiles() -> Probe[list[dict[str, Any]]]:
    return _run_probe("firewall_profiles", _Q_FIREWALL_PROFILES)


def sharing_groups() -> Probe[list[dict[str, Any]]]:
    return _run_probe("sharing_groups", _Q_SHARING_GROUPS)


def wildcard_listeners() -> Probe[list[dict[str, Any]]]:
    return _run_probe("wildcard_listeners", _Q_LISTENERS)


def defender_status() -> Probe[dict[str, Any] | None]:
    probe = _run_probe("defender_status", _Q_DEFENDER)
    first = probe.value[0] if probe.value and isinstance(probe.value[0], dict) else None
    return Probe(first, probe.status, probe.duration_ms, probe.detail)


def smb_config() -> Probe[dict[str, Any] | None]:
    probe = _run_probe("smb_config", _Q_SMB)
    first = probe.value[0] if probe.value and isinstance(probe.value[0], dict) else None
    return Probe(first, probe.status, probe.duration_ms, probe.detail)


def remote_admin_status() -> Probe[list[dict[str, Any]]]:
    """Remote-management service state."""
    return _run_probe("remote_admin_status", _Q_REMOTE_ADMIN)


def doh_servers() -> Probe[list[dict[str, Any]]]:
    return _run_probe("doh_servers", _Q_DOH)


def dns_servers() -> Probe[list[dict[str, Any]]]:
    return _run_probe("dns_servers", _Q_DNS_SERVERS)


# Elevation cannot change during a process's life, so the first DEFINITE answer is
# cached. A failure is not cached: controller.privilege is critical, and a cached None
# would block every launch.
_elevated_cache: Probe[bool | None] | None = None


def is_elevated() -> bool | None:
    """True/False if Windows answered, None if the query failed."""
    return is_elevated_probe().value


def is_elevated_probe() -> Probe[bool | None]:
    """Elevation with its reason code, cached once definite."""
    global _elevated_cache
    if _elevated_cache is not None:
        return _elevated_cache
    probe = _measure_elevation()
    if probe.value is not None:
        _elevated_cache = probe
    return probe


def _measure_elevation() -> Probe[bool | None]:
    probe = _run_probe("is_elevated", _Q_IS_ADMIN)
    value: bool | None = None
    if probe.ok and probe.value:
        raw = str(probe.value[0]).strip().lower()
        if raw in ("true", "1"):
            value = True
        elif raw in ("false", "0"):
            value = False
    if probe.ok and value is None:
        return Probe(None, ProbeStatus.MALFORMED_OUTPUT, probe.duration_ms,
                     f"expected a boolean, got {probe.value!r}")
    return Probe(value, probe.status, probe.duration_ms, probe.detail)


def reset_elevation_cache() -> None:
    """Drop the cached elevation answer. For tests only."""
    global _elevated_cache
    _elevated_cache = None


def authenticode(exe_path: str) -> Probe[dict[str, Any] | None]:
    """Authenticode status, subject and issuer of a path from config.EDGE_CANDIDATES.

    A quote in the path is refused: it would close the PowerShell string literal.
    """
    if "'" in exe_path or "`" in exe_path:
        _log.error("refusing to build a signature query from a quoted path")
        return Probe(None, ProbeStatus.PROBE_ERROR, 0.0, "unquotable path")
    body = (
        "$s = Get-AuthenticodeSignature -LiteralPath '" + exe_path + "'; "
        "[pscustomobject]@{ Status=[string]$s.Status; "
        "Subject=[string]$s.SignerCertificate.Subject; "
        "Issuer=[string]$s.SignerCertificate.Issuer }"
    )
    probe = _run_probe("authenticode", body)
    first = probe.value[0] if probe.value and isinstance(probe.value[0], dict) else None
    return Probe(first, probe.status, probe.duration_ms, probe.detail)


def bruhswer_rules() -> Probe[list[dict[str, Any]]]:
    """bruhswer's own firewall rules and their addresses. No rules is a normal answer
    before the elevated script has run, so SilentlyContinue stays."""
    body = (
        "Get-NetFirewallRule -DisplayName '" + config.RULE_PREFIX + "-*' "
        "-ErrorAction SilentlyContinue | ForEach-Object { "
        "$a = $_ | Get-NetFirewallAddressFilter; "
        "$p = $_ | Get-NetFirewallApplicationFilter; "
        "[pscustomobject]@{ Name=$_.DisplayName; Enabled=[string]$_.Enabled; "
        "Action=[string]$_.Action; Direction=[string]$_.Direction; "
        "Remote=@($a.RemoteAddress); Program=[string]$p.Program } }"
    )
    return _run_probe("bruhswer_rules", body)
