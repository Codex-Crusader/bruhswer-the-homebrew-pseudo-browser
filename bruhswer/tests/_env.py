"""Test environment discovery, so the suites are not tied to one network.

The gateway is discovered at run time, and the tests refuse to run without one; a
hardcoded address once "passed" on other machines. Read-only, no scanning.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402

_Q_GATEWAY = (
    "@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
    "Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop) | "
    "ConvertTo-Json -Compress"
)


def default_gateway() -> str | None:
    """The IPv4 default gateway, or None if this machine has no route to the internet."""
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             _Q_GATEWAY],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None

    raw = (proc.stdout or "").strip()
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if not isinstance(value, str):
        return None

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    # A public gateway is not covered by the rules, so it would measure nothing.
    if address.is_private and not address.is_loopback:
        return address.compressed
    return None


def require_gateway() -> str:
    """Gateway or a clear refusal. Never a fabricated address."""
    gateway = default_gateway()
    if gateway is None:
        raise SystemExit(
            "No private IPv4 default gateway found. The LAN-blocking tests need a real "
            "local router to probe, and inventing one would make the result meaningless."
        )
    return gateway


_Q_LAN_IP = (
    "@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
    "Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and "
    "$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | "
    "Sort-Object SkipAsSource | Select-Object -First 1 -ExpandProperty IPAddress) | "
    "ConvertTo-Json -Compress"
)


def host_lan_ip() -> str | None:
    """This machine's LAN address, or None. It is in the blocked ranges yet never
    leaves the machine, so the localhost suite measures which way it behaves."""
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             _Q_LAN_IP],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None

    raw = (proc.stdout or "").strip()
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address.compressed if not address.is_loopback else None
