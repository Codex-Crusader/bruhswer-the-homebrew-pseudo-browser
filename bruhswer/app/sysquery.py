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

EVERY QUERY RETURNS A `Probe`, not a bare list. The old accessors returned `[]` for
"there are none", for "Windows refused" and for "PowerShell timed out" alike, so a
caller could not tell a measurement that did not happen from one that did. The status
now travels with the value, so an UNKNOWN verdict can say WHY.

Each script body runs inside `_ENVELOPE`, which always writes one JSON object with
`ok`/`err`/`data`. Without it, `ConvertTo-Json` on an empty array writes nothing at
all - byte-identical to a script that died before producing output.
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
    """Why a query did or did not produce an answer.

    These become the reason codes on an UNKNOWN verdict. A missing cmdlet, a refused
    query and a timeout call for three different responses from the user.
    """

    OK = "OK"
    # The helper process did not finish inside its timeout. Says nothing about the
    # control being measured - only that the measurement did not complete.
    TIMEOUT = "TIMEOUT"
    # Windows refused the query. bruhswer runs unelevated on purpose, so this is an
    # expected answer for some state, not a malfunction.
    PERMISSION_DENIED = "PERMISSION_DENIED"
    # The cmdlet does not exist on this edition of Windows. The control may be absent
    # or may simply be unmeasurable from here; either way bruhswer did not measure it.
    UNSUPPORTED = "UNSUPPORTED"
    # PowerShell itself could not be started.
    LAUNCH_FAILED = "LAUNCH_FAILED"
    # It ran and wrote something that is not the envelope this module asked for.
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    # It ran, the envelope parsed, and the script reported an error that is none of the
    # more specific kinds above.
    PROBE_ERROR = "PROBE_ERROR"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Probe(Generic[T]):
    """One query's result, with the reason it is what it is.

    `value` is always usable - an empty list or None, never an exception - but it can
    no longer be mistaken for the whole answer, because reaching it means going through
    an object that is also carrying the status.
    """

    value: T
    status: ProbeStatus
    duration_ms: float
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is ProbeStatus.OK

    def reason(self) -> str:
        """Short evidence string naming the status and, when there is one, the cause."""
        if self.ok:
            return f"status=OK in {self.duration_ms:.0f}ms"
        return (f"status={self.status} in {self.duration_ms:.0f}ms"
                + (f" detail={self.detail[:120]}" if self.detail else ""))


# --- the envelope ---------------------------------------------------------------
# Every script body runs inside this. `{body}` is the ONLY substitution, and every
# body is a constant authored below - never anything derived from input.
#
# [Console]::Out.Write rather than Write-Output, so PowerShell's formatter cannot wrap
# or truncate the JSON on a narrow console.
_ENVELOPE = (
    "$ErrorActionPreference='Stop'; "
    "try {{ $d = @( {body} ); "
    "$o = [pscustomobject]@{{ ok=$true; err=''; data=$d }} }} "
    "catch {{ $o = [pscustomobject]@{{ ok=$false; "
    "err=[string]$_.Exception.Message; data=@() }} }}; "
    "[Console]::Out.Write((ConvertTo-Json -Compress -Depth 6 -InputObject $o))"
)

# Substrings Windows uses when it refuses a query for want of rights. Matched
# case-insensitively against the exception message the envelope reports.
_DENIED_SIGNS = ("access is denied", "unauthorizedaccess", "requires elevation",
                 "requested operation requires elevation", "administrator privilege",
                 "permission denied")

# ...and when the cmdlet is simply not present on this edition of Windows.
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
    """Run one constant script inside the envelope. Never raises.

    Returns the `data` array on success, and an EMPTY list on every failure - with the
    status saying which failure it was. The empty list is never evidence of anything;
    that is the entire reason the status travels with it.
    """
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
        # The envelope ALWAYS writes an object, so nothing on stdout means the script
        # never reached its own final line - PowerShell died, or was killed.
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

    # ConvertTo-Json collapses a one-element array to a bare object, so `data` comes
    # back as a dict when exactly one row was found. Re-wrap it, or every caller would
    # need the same special case and one of them would forget.
    data = parsed.get("data")
    if data is None:
        data = []
    elif not isinstance(data, list):
        data = [data]
    _log.debug("probe %s ok in %.0fms rows=%d", name, elapsed, len(data))
    return Probe(data, ProbeStatus.OK, elapsed)


# --- constant script bodies -----------------------------------------------------
# Each body produces OBJECTS; the envelope does the serialising. `-ErrorAction
# SilentlyContinue` is kept ONLY where "no rows" is a legitimate answer and the cmdlet
# throws rather than returning nothing. Everywhere else it is deliberately absent, so
# that a refusal or a missing cmdlet reaches _classify() instead of being flattened
# into an empty result that looks like a clean measurement.

# NetworkCategory is an enum: ConvertTo-Json serialises it as an integer, which is
# useless to compare against. Cast every enum to its name inside PowerShell.
_Q_NETWORK_PROFILE = (
    "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,"
    "@{n='NetworkCategory';e={[string]$_.NetworkCategory}},"
    "@{n='IPv4Connectivity';e={[string]$_.IPv4Connectivity}},"
    "@{n='IPv6Connectivity';e={[string]$_.IPv6Connectivity}}"
)

_Q_FIREWALL_PROFILES = (
    "Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[bool]$_.Enabled}}"
)

# SilentlyContinue KEPT: a display group that is not present on this machine is a real
# answer, reported as Total=0, not a failed measurement.
_Q_SHARING_GROUPS = (
    "foreach ($g in @('File and Printer Sharing','Network Discovery',"
    "'Remote Desktop')) { $r = Get-NetFirewallRule -DisplayGroup $g "
    "-ErrorAction SilentlyContinue | Where-Object { $_.Profile -match 'Public' "
    "-or $_.Profile -eq 'Any' }; [pscustomobject]@{ Group=$g; "
    "Total=@($r).Count; Enabled=@($r | Where-Object { $_.Enabled -eq 'True' }).Count } }"
)

# SilentlyContinue KEPT: Get-NetTCPConnection throws when no connection matches the
# filter, and "nothing is listening on a wildcard address" is a legitimate finding.
_Q_LISTENERS = (
    "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
    "Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } | "
    "Select-Object LocalPort,OwningProcess"
)

# SilentlyContinue REMOVED on purpose. A machine with Defender replaced by another AV
# product has no Get-MpComputerStatus at all, and that must report UNSUPPORTED rather
# than the same empty answer as a machine whose Defender is off.
_Q_DEFENDER = (
    "$s = Get-MpComputerStatus; $p = Get-MpPreference; "
    "[pscustomobject]@{ RealTime=[bool]$s.RealTimeProtectionEnabled; "
    "Tamper=[bool]$s.IsTamperProtected; CFA=[int]$p.EnableControlledFolderAccess }"
)

# SilentlyContinue REMOVED on purpose. Get-SmbServerConfiguration is one of the queries
# most likely to be refused to an unelevated process, and PERMISSION_DENIED is a
# materially different report from "SMB is not hardened".
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

# SilentlyContinue KEPT on Get-Service: 'ABSENT' is produced explicitly below, so a
# service that does not exist is already a first-class answer rather than a failure.
_Q_REMOTE_ADMIN = (
    "foreach ($n in @('TermService','WinRM','RemoteRegistry','SSDPSRV',"
    "'upnphost','FDResPub')) { $s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
    "if ($s) { [pscustomobject]@{ Name=$n; Status=[string]$s.Status; "
    "StartType=[string]$s.StartType } } else { [pscustomobject]@{ Name=$n; "
    "Status='ABSENT'; StartType='ABSENT' } } }"
)

# SilentlyContinue REMOVED on both DNS queries. Get-DnsClientDohServerAddress does not
# exist before Windows 10 2004, and "this Windows cannot tell me" is not the same fact
# as "no encrypted-DNS servers are configured".
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
    """Remote-management surfaces (brief SS5). Read-only service state."""
    return _run_probe("remote_admin_status", _Q_REMOTE_ADMIN)


def doh_servers() -> Probe[list[dict[str, Any]]]:
    return _run_probe("doh_servers", _Q_DOH)


def dns_servers() -> Probe[list[dict[str, Any]]]:
    return _run_probe("dns_servers", _Q_DNS_SERVERS)


# --- elevation, measured once ---------------------------------------------------
# A process cannot change its own elevation while it runs. Windows decides it at
# CreateProcess time from the token the process is started with, and there is no API
# that moves a running process between elevated and unelevated - becoming elevated
# means starting a NEW process. So this is a property of the process lifetime, and
# re-measuring it costs a ~250ms PowerShell round trip on every single verification
# pass for an answer that provably cannot have changed.
#
# ONLY A DEFINITE ANSWER IS CACHED, and this is the part that has to be right.
# `controller.privilege` is critical=True, so under the fail-closed rule in verdict.py
# an UNKNOWN there BLOCKS LAUNCH. Memoising a None - one PowerShell timeout under load
# at startup - would therefore brick every launch for the rest of the process's life,
# with no way to recover short of restarting bruhswer. A failed measurement is not a
# fact about the world and is never cached; the next pass simply asks again.
_elevated_cache: Probe[bool | None] | None = None


def is_elevated() -> bool | None:
    """True/False if Windows answered, None if the query failed."""
    return is_elevated_probe().value


def is_elevated_probe() -> Probe[bool | None]:
    """The measurement with its reason code. Cached once the answer is definite.

    Both `_controller_checks` and `net.tamper` want this, and each was paying its own
    ~250ms round trip for an answer that cannot change while the process runs.
    """
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
    """Drop the memoised elevation answer. For tests only.

    Present so a test can exercise both branches in one process. Nothing in `app/`
    calls it, because nothing in `app/` has a reason to: the value it caches cannot
    change while bruhswer is running.
    """
    global _elevated_cache
    _elevated_cache = None


def authenticode(exe_path: str) -> Probe[dict[str, Any] | None]:
    """Authenticode status and signer for one of bruhswer's OWN constant paths.

    This lives here rather than in edge.py so that nothing outside this module has to
    reach for the probe runner. The rule that there is no public "run this script for
    me" entry point is the whole point of the module, and a caller poking at the
    private one quietly erodes it.

    `exe_path` must be a path bruhswer itself resolved (config.EDGE_CANDIDATES), never
    anything derived from input.
    """
    body = (
        "$s = Get-AuthenticodeSignature -LiteralPath '" + exe_path + "'; "
        "[pscustomobject]@{ Status=[string]$s.Status; "
        "Subject=[string]$s.SignerCertificate.Subject }"
    )
    probe = _run_probe("authenticode", body)
    first = probe.value[0] if probe.value and isinstance(probe.value[0], dict) else None
    return Probe(first, probe.status, probe.duration_ms, probe.detail)


def bruhswer_rules() -> Probe[list[dict[str, Any]]]:
    """bruhswer's own firewall rules and the addresses they cover.

    The rule prefix is a bruhswer constant from config, so nothing external reaches
    this string.

    SilentlyContinue is KEPT here: no rules at all is the normal state before the
    elevated one-shot has ever been run, and it must report as an empty list rather
    than as a failed query.
    """
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
