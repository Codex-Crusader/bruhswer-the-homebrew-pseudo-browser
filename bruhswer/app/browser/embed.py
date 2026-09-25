"""Host a real Edge window inside the bruhswer window with `SetParent`.

Edge keeps its own processes, sandbox and profile; only its parent window changes. No
injection, no patched binaries, no undocumented API.

Rejected: CEF (an unsigned Chromium build in the trusted stack), WebView2 (needs
pythonnet), and DevTools (needs --remote-debugging-port, a localhost control channel a
compromised browser could reach).

Limitation: this is window hosting, not embedding. Tabs, back/forward and reload are
Edge's own controls.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import subprocess
import winreg
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..logging_setup import get_logger

_log = get_logger("embed")

USER32 = ctypes.WinDLL("user32", use_last_error=True)
KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)

GWL_STYLE = -16
WS_CHILD = 0x40000000
WS_POPUP = 0x80000000
WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
SWP_NOZORDER = 0x0004
SWP_FRAMECHANGED = 0x0020
SWP_SHOWWINDOW = 0x0040
SW_SHOW = 5

RDW_INVALIDATE = 0x0001
RDW_ERASE = 0x0004
RDW_ALLCHILDREN = 0x0080
RDW_UPDATENOW = 0x0100
SPI_GETWORKAREA = 0x0030

# DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
DPI_PER_MONITOR_AWARE_V2 = ctypes.c_void_p(-4)

EDGE_WINDOW_CLASS = "Chrome_WidgetWin_1"

USER32.SetParent.restype = wt.HWND
USER32.SetParent.argtypes = [wt.HWND, wt.HWND]
USER32.GetParent.restype = wt.HWND
USER32.GetParent.argtypes = [wt.HWND]
USER32.GetWindowLongW.restype = ctypes.c_long
USER32.GetWindowLongW.argtypes = [wt.HWND, ctypes.c_int]
USER32.SetWindowLongW.restype = ctypes.c_long
USER32.SetWindowLongW.argtypes = [wt.HWND, ctypes.c_int, ctypes.c_long]
USER32.IsWindowVisible.argtypes = [wt.HWND]
USER32.IsWindow.argtypes = [wt.HWND]
USER32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
USER32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, ctypes.c_uint]
# Every prototype is declared: an undeclared one defaults to c_int, which is how the
# SetWindowLongW sign-overflow bug hid.
USER32.EnumWindows.argtypes = [ctypes.c_void_p, wt.LPARAM]
USER32.EnumWindows.restype = wt.BOOL
USER32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
USER32.GetWindowThreadProcessId.restype = wt.DWORD
USER32.EnumChildWindows.argtypes = [wt.HWND, ctypes.c_void_p, wt.LPARAM]
USER32.EnumChildWindows.restype = wt.BOOL
USER32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
USER32.GetWindowRect.restype = wt.BOOL
USER32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
USER32.GetClassNameW.restype = ctypes.c_int
USER32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
USER32.GetWindowTextW.restype = ctypes.c_int
USER32.GetWindowTextLengthW.argtypes = [wt.HWND]
USER32.GetWindowTextLengthW.restype = ctypes.c_int
USER32.RedrawWindow.argtypes = [wt.HWND, ctypes.c_void_p, wt.HANDLE, ctypes.c_uint]
USER32.RedrawWindow.restype = wt.BOOL
USER32.UpdateWindow.argtypes = [wt.HWND]
USER32.UpdateWindow.restype = wt.BOOL
USER32.PostMessageW.argtypes = [wt.HWND, ctypes.c_uint, wt.WPARAM, wt.LPARAM]
USER32.PostMessageW.restype = wt.BOOL
USER32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
USER32.SetProcessDpiAwarenessContext.restype = wt.BOOL
USER32.SetProcessDPIAware.restype = wt.BOOL
USER32.SystemParametersInfoW.argtypes = [wt.UINT, wt.UINT, ctypes.c_void_p,
                                         wt.UINT]
USER32.SystemParametersInfoW.restype = wt.BOOL
USER32.GetSystemMetrics.argtypes = [ctypes.c_int]
USER32.GetSystemMetrics.restype = ctypes.c_int

_U32 = 0xFFFFFFFF


def _to_signed32(value: int) -> int:
    """SetWindowLongW takes a SIGNED long; a style with bit 31 set (WS_POPUP) otherwise
    raises "int too long to convert"."""
    value &= _U32
    return value - 0x100000000 if value >= 0x80000000 else value


_WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

# The only substituted value is a profile folder name bruhswer generated.
_PS_PIDS = (
    "@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
    "Where-Object {{ $_.CommandLine -like '*{marker}*' }} | "
    "Select-Object -ExpandProperty ProcessId) -join ','"
)


def edge_pids_for_profile(profile_dir: Path) -> set[int]:
    """PIDs of Edge processes using this profile, matched by profile folder name."""
    marker = profile_dir.name
    if not marker.replace("_", "").replace("-", "").isalnum():
        _log.error("refusing to match processes on a non-alphanumeric marker")
        return set()
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             _PS_PIDS.format(marker=marker)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    raw = (proc.stdout or "").strip()
    return {int(x) for x in raw.split(",") if x.strip().isdigit()}


_PS_RENDERERS = (
    "@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
    "Where-Object {{ $_.CommandLine -like '*{marker}*' -and "
    "$_.CommandLine -like '*--type=renderer*' }} | "
    "Select-Object -ExpandProperty ProcessId) -join ','"
)


def renderer_pids_for_profile(profile_dir: Path) -> list[int] | None:
    """PIDs of this session's renderers. [] = asked, none found; None = could not ask."""
    marker = profile_dir.name
    if not marker.replace("_", "").replace("-", "").isalnum():
        return None
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             _PS_RENDERERS.format(marker=marker)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    raw = (proc.stdout or "").strip()
    return [int(x) for x in raw.split(",") if x.strip().isdigit()]


# For the panic key, which KILLS processes, so attribution must be exact: the folder
# name match above would hit any Edge whose command line contains "persistent", and a
# PID can be recycled into another msedge.exe. So this returns the full command line
# (matched in Python on the absolute --user-data-dir) and the creation FILETIME, which
# is re-read from the opened handle before terminating.
_PS_EDGE_DETAIL = (
    "@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
    "ForEach-Object { [pscustomobject]@{ Pid=$_.ProcessId; "
    "Created=[string]$_.CreationDate.ToFileTimeUtc(); "
    "Cmd=[string]$_.CommandLine } }) | ConvertTo-Json -Compress -Depth 3"
)


@dataclass(frozen=True)
class EdgeProcess:
    """One Edge process, identified strongly enough to be a termination target."""

    pid: int
    created: int        # FILETIME, UTC. With the pid, identifies a process INSTANCE.


def _normalise_cmdline(text: str) -> str:
    """Lowered and unquoted: subprocess quotes a path only when it has a space."""
    return text.replace('"', "").lower()


def attributed_edge_processes(profile_dir: Path) -> list[EdgeProcess] | None:
    """Edge processes provably belonging to THIS profile. None if the query failed."""
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             _PS_EDGE_DETAIL],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None

    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return None

    # The exact flag edge.build_command writes.
    needle = _normalise_cmdline(f"--user-data-dir={profile_dir}")

    out: list[EdgeProcess] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cmd = entry.get("Cmd")
        if not isinstance(cmd, str) or needle not in _normalise_cmdline(cmd):
            continue
        raw_pid = entry.get("Pid")
        raw_created = entry.get("Created")
        if raw_pid is None or raw_created is None:
            continue
        try:
            pid = int(raw_pid)
            created = int(raw_created)
        except (TypeError, ValueError):
            continue
        if pid > 0 and created > 0:
            out.append(EdgeProcess(pid, created))
    return out


PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
# Needed by WaitForSingleObject. Measured: without it the wait fails at once and
# confirmed_exited was always 0.
PROCESS_SYNCHRONIZE = 0x00100000
_INVALID_HANDLE = wt.HANDLE(-1).value
_WAIT_OBJECT_0 = 0x0

KERNEL32.OpenProcess.restype = wt.HANDLE
KERNEL32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
KERNEL32.CloseHandle.argtypes = [wt.HANDLE]
KERNEL32.CloseHandle.restype = wt.BOOL
KERNEL32.TerminateProcess.argtypes = [wt.HANDLE, ctypes.c_uint]
KERNEL32.TerminateProcess.restype = wt.BOOL
KERNEL32.GetProcessTimes.argtypes = [wt.HANDLE, ctypes.POINTER(wt.FILETIME),
                                     ctypes.POINTER(wt.FILETIME),
                                     ctypes.POINTER(wt.FILETIME),
                                     ctypes.POINTER(wt.FILETIME)]
KERNEL32.GetProcessTimes.restype = wt.BOOL
KERNEL32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
KERNEL32.WaitForSingleObject.restype = wt.DWORD


@dataclass(frozen=True)
class TerminationReport:
    """What the panic path did. `refused` counts processes whose identity no longer
    matched, so a refusal cannot read as a success."""

    terminated: int = 0
    already_gone: int = 0
    refused: int = 0
    failed: int = 0
    confirmed_exited: int = 0

    @property
    def attempted(self) -> int:
        return self.terminated + self.already_gone + self.refused + self.failed


def _creation_filetime(handle) -> int | None:
    creation = wt.FILETIME()
    exited = wt.FILETIME()
    kernel = wt.FILETIME()
    user = wt.FILETIME()
    if not KERNEL32.GetProcessTimes(handle, ctypes.byref(creation),
                                    ctypes.byref(exited), ctypes.byref(kernel),
                                    ctypes.byref(user)):
        return None
    return (creation.dwHighDateTime << 32) | creation.dwLowDateTime


def same_process_instance(enumerated: int, from_handle: int) -> bool:
    """Same process instance? Compared at microseconds, not with `==`.

    GetProcessTimes has 100ns resolution; CIM CreationDate is truncated to microseconds
    (measured difference: 8 ticks). With `==` the panic key refused every process.
    """
    return enumerated // 10 == from_handle // 10


def terminate_attributed(processes: list[EdgeProcess]) -> TerminationReport:
    """Terminate processes whose creation time, read from the opened handle, still
    matches. Anything not positively identified is refused.

    TerminateProcess is asynchronous: `confirmed_exited` counts only processes seen to
    exit.
    """
    terminated = already_gone = refused = failed = confirmed = 0

    for entry in processes:
        handle = KERNEL32.OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
            | PROCESS_SYNCHRONIZE, False, entry.pid)
        if not handle or handle == _INVALID_HANDLE:
            already_gone += 1
            continue
        try:
            actual = _creation_filetime(handle)
            if actual is None or not same_process_instance(entry.created, actual):
                refused += 1
                _log.error("panic refused pid %d: identity changed since enumeration "
                           "(PID was reused)", entry.pid)
                continue
            if not KERNEL32.TerminateProcess(handle, 1):
                failed += 1
                continue
            terminated += 1
            if KERNEL32.WaitForSingleObject(
                    handle, config.PANIC_EXIT_WAIT_MS) == _WAIT_OBJECT_0:
                confirmed += 1
        finally:
            KERNEL32.CloseHandle(handle)

    if refused or failed:
        _log.warning("panic termination: %d refused, %d failed", refused, failed)
    return TerminationReport(terminated, already_gone, refused, failed, confirmed)


def find_browser_window(pids: set[int]) -> int | None:
    """The visible, titled top-level Edge window belonging to one of these PIDs."""
    if not pids:
        return None
    matches: list[int] = []

    def _cb(hwnd, _lparam):
        pid = wt.DWORD()
        USER32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value not in pids or not USER32.IsWindowVisible(hwnd):
            return True
        cls = ctypes.create_unicode_buffer(256)
        USER32.GetClassNameW(hwnd, cls, 256)
        if cls.value != EDGE_WINDOW_CLASS:
            return True
        length = USER32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        matches.append(hwnd)
        return True

    USER32.EnumWindows(ctypes.cast(_WNDENUMPROC(_cb), ctypes.c_void_p), 0)
    return matches[0] if matches else None


def window_title(hwnd: int) -> str:
    if not hwnd or not USER32.IsWindow(hwnd):
        return ""
    length = USER32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(length + 1)
    USER32.GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def host_window(hwnd: int, parent_hwnd: int) -> bool:
    """Reparent the Edge window into a bruhswer frame. Returns True only if verified."""
    if not hwnd or not USER32.IsWindow(hwnd):
        return False
    style = USER32.GetWindowLongW(hwnd, GWL_STYLE) & _U32
    drop = WS_POPUP | WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX
    child_style = (style & ~drop & _U32) | WS_CHILD
    try:
        USER32.SetWindowLongW(hwnd, GWL_STYLE, _to_signed32(child_style))
        USER32.SetParent(hwnd, parent_hwnd)
        USER32.ShowWindow(hwnd, SW_SHOW)
    except (ctypes.ArgumentError, OSError) as exc:
        _log.error("window hosting failed: %s", exc.__class__.__name__)
        return False

    actual = USER32.GetParent(hwnd)
    ok = bool(actual) and int(actual) == int(parent_hwnd)
    _log.info("window hosting %s", "verified" if ok else "FAILED")
    return ok


def fit(hwnd: int, width: int, height: int) -> None:
    """Size the hosted window and force a repaint; SetWindowPos alone left Chromium's
    surface stale."""
    if not (hwnd and USER32.IsWindow(hwnd) and width > 0 and height > 0):
        return
    USER32.SetWindowPos(wt.HWND(hwnd), wt.HWND(0), 0, 0, width, height,
                        SWP_NOZORDER | SWP_FRAMECHANGED | SWP_SHOWWINDOW)
    USER32.RedrawWindow(hwnd, None, None,
                        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW)
    USER32.UpdateWindow(hwnd)


def work_area() -> tuple[int, int, int, int]:
    """Desktop area without the taskbar, as (left, top, width, height).

    Tk only knows the full screen, which put the status lights under the taskbar.
    """
    rect = wt.RECT()
    try:
        if USER32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            return (rect.left, rect.top,
                    rect.right - rect.left, rect.bottom - rect.top)
    except (OSError, ctypes.ArgumentError):
        pass
    return 0, 0, USER32.GetSystemMetrics(0), USER32.GetSystemMetrics(1)


def enable_dpi_awareness() -> str:
    """Make this process DPI-aware. Must run before the first window exists.

    Tk is DPI-unaware and Edge is per-monitor aware; the mismatch scales or clips the
    hosted page.
    """
    try:
        if USER32.SetProcessDpiAwarenessContext(DPI_PER_MONITOR_AWARE_V2):
            return "per-monitor-v2"
    except (AttributeError, OSError):
        pass
    try:
        shcore = ctypes.WinDLL("shcore", use_last_error=True)
        if shcore.SetProcessDpiAwareness(2) == 0:      # PROCESS_PER_MONITOR_DPI_AWARE
            return "per-monitor"
    except (AttributeError, OSError):
        pass
    try:
        if USER32.SetProcessDPIAware():
            return "system"
    except (AttributeError, OSError):
        pass
    return "unavailable"


def is_paint_ready(hwnd: int) -> bool:
    """True once Chromium has built its compositor surface.

    Measured: the D3D window appears ~52ms after the top-level window. Defensive only;
    no bug was ever traced to that gap. Without D3D (software rendering) the render
    widget counts, so this cannot block hosting forever.
    """
    if not is_alive(hwnd):
        return False
    found = {"d3d": False, "widget": False}

    def _visit(child, _):
        name = _class_name(child)
        if "D3D" in name:
            found["d3d"] = True
        elif name == "Chrome_RenderWidgetHostHWND":
            width, height = _client_size(child)
            found["widget"] = width > 1 and height > 1
        return True

    try:
        USER32.EnumChildWindows(wt.HWND(hwnd), _WNDENUMPROC(_visit), 0)
    except (ctypes.ArgumentError, OSError):
        return False
    return found["d3d"] or found["widget"]


SPI_GETHIGHCONTRAST = 0x0042
HCF_HIGHCONTRASTON = 0x00000001


class _HIGHCONTRAST(ctypes.Structure):
    _fields_ = [("cbSize", wt.UINT), ("dwFlags", wt.DWORD),
                ("lpszDefaultScheme", ctypes.c_wchar_p)]


def high_contrast() -> bool | None:
    """True if Windows high contrast is on. None if it could not be asked, never a
    guessed False."""
    info = _HIGHCONTRAST()
    info.cbSize = ctypes.sizeof(_HIGHCONTRAST)
    try:
        if not USER32.SystemParametersInfoW(SPI_GETHIGHCONTRAST, info.cbSize,
                                            ctypes.byref(info), 0):
            return None
    except (OSError, ctypes.ArgumentError, AttributeError):
        return None
    return bool(info.dwFlags & HCF_HIGHCONTRASTON)


def prefers_dark() -> bool | None:
    """Whether Windows apps use dark mode, read from HKCU. None if unreadable."""
    try:
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            value, _kind = winreg.QueryValueEx(key, "AppsUseLightTheme")
    except (OSError, ValueError):
        return None
    return not bool(value)


def is_fitted(hwnd: int, width: int, height: int, tolerance: int = 2) -> bool:
    """True once the hosted window AND its render widget are the requested size.

    Chromium resizes the outer window at once and the render widget later, so the outer
    one alone reports fitted too early.
    """
    if not (is_alive(hwnd) and width > 0 and height > 0):
        return False
    outer_w, outer_h = _client_size(hwnd)
    if abs(outer_w - width) > tolerance or abs(outer_h - height) > tolerance:
        return False

    widget = {"seen": False, "ok": False}

    def _visit(child, _):
        if _class_name(child) == "Chrome_RenderWidgetHostHWND":
            widget["seen"] = True
            child_w, child_h = _client_size(child)
            widget["ok"] = (abs(child_w - width) <= tolerance
                            and abs(child_h - height) <= tolerance)
        return True

    try:
        USER32.EnumChildWindows(wt.HWND(hwnd), _WNDENUMPROC(_visit), 0)
    except (ctypes.ArgumentError, OSError):
        return False
    return widget["ok"] if widget["seen"] else True


def _class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    USER32.GetClassNameW(wt.HWND(hwnd), buf, 256)
    return buf.value


def _client_size(hwnd: int) -> tuple[int, int]:
    rect = wt.RECT()
    USER32.GetWindowRect(wt.HWND(hwnd), ctypes.byref(rect))
    return rect.right - rect.left, rect.bottom - rect.top


def is_alive(hwnd: int) -> bool:
    return bool(hwnd) and bool(USER32.IsWindow(hwnd))


WM_CLOSE = 0x0010

USER32.AttachThreadInput.argtypes = [wt.DWORD, wt.DWORD, wt.BOOL]
USER32.AttachThreadInput.restype = wt.BOOL
USER32.SetFocus.argtypes = [wt.HWND]
USER32.SetFocus.restype = wt.HWND
USER32.GetWindowThreadProcessId.restype = wt.DWORD

_attached: tuple[int, int] | None = None


def attach_input(hosted_hwnd: int, host_hwnd: int) -> bool:
    """Join the two threads' input queues, or keystrokes never reach the hosted page.

    SetParent moves the window but not its input queue. Released on teardown.
    """
    global _attached
    if not is_alive(hosted_hwnd):
        return False
    edge_thread = USER32.GetWindowThreadProcessId(hosted_hwnd, None)
    host_thread = USER32.GetWindowThreadProcessId(host_hwnd, None)
    if not edge_thread or not host_thread or edge_thread == host_thread:
        return False
    if not USER32.AttachThreadInput(host_thread, edge_thread, True):
        _log.warning("AttachThreadInput failed; typing may not reach the browser")
        return False
    _attached = (host_thread, edge_thread)
    _log.info("input queues attached")
    return True


def detach_input() -> None:
    """Release the input-queue attachment."""
    global _attached
    if _attached is None:
        return
    host_thread, edge_thread = _attached
    USER32.AttachThreadInput(host_thread, edge_thread, False)
    _attached = None
    _log.info("input queues detached")


def focus(hwnd: int) -> None:
    """Give the hosted browser keyboard focus. Only works once input is attached."""
    if is_alive(hwnd):
        USER32.SetFocus(hwnd)


def focus_host(host_hwnd: int) -> None:
    """Take focus back from the browser: with attached queues, clicking a Tk field
    does not."""
    if host_hwnd and USER32.IsWindow(host_hwnd):
        USER32.SetFocus(host_hwnd)


def request_close(hwnd: int) -> bool:
    """Close the browser the way a user would. A kill marks the profile as crashed,
    and the next launch offers to restore the old tabs."""
    if not is_alive(hwnd):
        return False
    USER32.PostMessageW(wt.HWND(hwnd), WM_CLOSE, 0, 0)
    return True
