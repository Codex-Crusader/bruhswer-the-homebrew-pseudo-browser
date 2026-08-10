"""Test environment discovery — so the suite is not tied to one machine's network.

The network tests need a real LAN peer to prove the firewall rules block it. That was
hardcoded to the gateway of the machine bruhswer was developed on, which meant the suite
would still "pass" on someone else's PC while probing an address that does not exist -
a test that quietly proves nothing.

The gateway is discovered at run time instead, and the tests refuse to run if there
isn't one rather than testing a made-up address.

Read-only. No scanning: the default gateway is a single address the OS already knows.
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
    # A gateway outside the private ranges would not be covered by bruhswer's rules,
    # so a test using it as the "blocked LAN peer" would be measuring nothing.
    return str(address) if address.is_private and not address.is_loopback else None


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
    """This machine's own address on the LAN, or None.

    The localhost suite needs it for one specific question that nothing else answers:
    the host's own IP sits INSIDE the private ranges bruhswer's firewall rules block,
    yet traffic a program sends to its own address never leaves the machine and is
    therefore never seen by the firewall. Whether that address behaves like "blocked
    LAN" or like "unfilterable loopback" is exactly the sort of thing that must be
    measured rather than reasoned about.
    """
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
    return str(address) if not address.is_loopback else None
