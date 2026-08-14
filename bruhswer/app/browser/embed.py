"""Host a real Edge window inside the bruhswer window, using documented Win32 calls.

WHAT THIS IS
    `SetParent` window reparenting. Edge runs as its own process tree, with its own
    Chromium sandbox, its own renderer processes and its own profile - exactly as
    before. The only thing that changes is which window is its parent.

WHAT THIS IS NOT, and why (brief SS6)
    No DLL injection. No modification of Edge binaries. No disabling of the sandbox,
    SmartScreen, Safe Browsing or TLS validation. No undocumented API. Nothing about
    Edge's security posture is touched.

ALTERNATIVES CONSIDERED AND REJECTED
    CEF Python          bundles its own Chromium build - a brand-new unsigned
                        third-party binary in the trusted stack. That is precisely the
                        mistake gate B17 rejected QEMU for (SS48).
    WebView2 + pythonnet
                        WebView2 itself is Microsoft-signed and already installed
                        (v151.0.4129.72 measured). But driving it from Python needs
                        pythonnet plus .NET interop packages. Kept as a documented
                        fallback; not adopted, because reparenting was measured to work
                        with zero new dependencies.
    DevTools protocol   `--remote-debugging-port` is already in bruhswer's
                        DANGEROUS_FLAGS. Stage 4 measured that a compromised browser CAN
                        reach localhost and that nothing can block it, so a localhost
                        control channel into the browser is the one thing that must not
                        exist (SS25). Rejected outright.

HONEST LIMITATION
    This is window hosting, not in-process embedding. Edge draws its own tab strip and
    toolbar inside the hosted window, so tabs, back/forward and reload are Edge's real
    native controls. bruhswer supplies the frame, the address bar, the security chrome
    and the session lifecycle around them.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import subprocess
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
# The rest of the prototypes. Declaring every one is not bookkeeping: an undeclared
# function defaults to c_int returns and unchecked arguments, which is exactly how the
# SetWindowLongW sign-overflow bug hid until it hit a window with bit 31 set.
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

_U32 = 0xFFFFFFFF


def _to_signed32(value: int) -> int:
    """Window styles are 32-bit flags, but SetWindowLongW takes a SIGNED long.

    This is not cosmetic. GetWindowLongW returns a signed value, so a style with bit 31
    set (WS_POPUP) comes back NEGATIVE. Python's bitwise operators then sign-extend it
    infinitely, so the computed style stays negative and huge, and ctypes raises
    "int too long to convert".

    An early spike of this code happened to run against a window whose style had bit 31
    clear, so it worked - and then failed on a different window. Masking to 32 bits and
    converting explicitly removes the luck.
    """
    value &= _U32
    return value - 0x100000000 if value >= 0x80000000 else value

_WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

# CONSTANT script. The only substituted value is a profile directory name that bruhswer
# generated itself (a hex session id or a fixed literal), never anything external.
_PS_PIDS = (
    "@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
    "Where-Object {{ $_.CommandLine -like '*{marker}*' }} | "
    "Select-Object -ExpandProperty ProcessId) -join ','"
)


def edge_pids_for_profile(profile_dir: Path) -> set[int]:
    """PIDs of Edge processes using this profile. Attribution by profile directory
    name, so the user's own browser is never matched."""
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


# Renderer processes carry --type=renderer on their command line. Matching on the
# profile marker AND the type keeps this to this session's page processes only.
_PS_RENDERERS = (
    "@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | "
    "Where-Object {{ $_.CommandLine -like '*{marker}*' -and "
    "$_.CommandLine -like '*--type=renderer*' }} | "
    "Select-Object -ExpandProperty ProcessId) -join ','"
)


def renderer_pids_for_profile(profile_dir: Path) -> list[int] | None:
    """PIDs of this session's renderer processes - the ones that run web content.

    Returns None when the QUERY ITSELF failed, and a list (possibly empty) when it
    succeeded. The distinction is load-bearing and used to be missing.

    This returned a bare [] for three different situations: the query timed out, the
    query could not be started, and the query ran fine and found no renderers. The
    caller could not tell them apart, so a single PowerShell hiccup during a live
    session produced a sandbox check reading "No browser session is running, so there
    is nothing to measure yet" - a statement that was plainly false with the browser
    on screen - and, once re-verification was added, a red "something changed while
    you were browsing" curtain over a session where nothing had.

    An empty list now means "asked, and there are none". None means "could not ask".
    """
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


# --- attributed process identity, for the panic path ----------------------------
#
# WHY THIS EXISTS SEPARATELY FROM edge_pids_for_profile()
#
# The panic key TERMINATES processes. That raises the bar on attribution from "good
# enough to count" to "good enough to kill", and the existing PID query does not clear
# it, for two reasons:
#
#   1. It matches with a PowerShell `-like '*<marker>*'` on the profile DIRECTORY NAME
#      only. For a disposable session that name is 16 random hex characters and is
#      effectively unique, but for the persistent session it is the literal string
#      "persistent" - which would also match a completely unrelated Edge process whose
#      command line happened to contain that word.
#   2. Even with a perfect query, a PID can be RECYCLED between the moment it is listed
#      and the moment OpenProcess runs. Checking the image name afterwards is not
#      enough: it rules out killing a recycled PID that became notepad.exe, but NOT one
#      that became another msedge.exe - which is precisely the user's own browser, the
#      one thing bruhswer must never kill.
#
# So this query returns the FULL command line and the process CREATION TIME as a
# FILETIME, matching is done in Python against the absolute --user-data-dir value, and
# the creation time is re-read from the OPENED HANDLE before anything is terminated.
# A FILETIME plus a PID identifies a specific process instance: if the handle's
# creation time differs from the one observed at enumeration, the PID was reused and
# bruhswer refuses to touch it.
#
# Matching in Python rather than in the query is also what avoids escaping an absolute
# Windows path into a PowerShell wildcard, where `[` and `]` are metacharacters.
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
    """Lowered, with quotes removed, so a quoted and unquoted path compare equal.

    subprocess quotes an argument only when it contains a space, so the same profile
    appears as --user-data-dir=C:\\x on one machine and --user-data-dir="C:\\a b\\x" on
    another. Both must match.
    """
    return text.replace('"', "").lower()


def attributed_edge_processes(profile_dir: Path) -> list[EdgeProcess] | None:
    """Edge processes provably belonging to THIS profile. None if the query failed.

    None and [] are different answers, for the same reason as
    renderer_pids_for_profile: "could not ask" must never be reported as "there are
    none", least of all on a path that then tells the user everything was stopped.
    """
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

    # The exact flag bruhswer itself builds in edge.build_command. Anything that does
    # not carry this precise absolute path is not ours and is not a target.
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
# REQUIRED for WaitForSingleObject on a process handle, and easy to omit because
# terminating works perfectly well without it. MEASURED: without SYNCHRONIZE the wait
# fails immediately instead of blocking, so `confirmed_exited` came back 0 every time
# and the panic report permanently understated what it had achieved - claiming less
# than the truth, which is the safe direction to be wrong but still wrong.
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
    """What the panic path ACTUALLY did. Every field is reported to the user.

    `refused` is the important one: it counts processes bruhswer declined to touch
    because their identity no longer matched. Reporting only `terminated` would let a
    refusal read as a success.
    """

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
    """Do these two creation times describe the SAME process instance?

    NOT `==`, and that is not a loosening - it is the difference between a working
    guard and an inert one.

    MEASURED. The two values come from different Windows APIs with different
    precision:

        GetProcessTimes        134311582068932898     full 100ns resolution
        CIM CreationDate       134311582068932890     truncated to MICROSECONDS
        difference                              8 ticks

    Win32_Process.CreationDate is a CIM datetime with six fractional digits, so
    `.ToFileTimeUtc()` is always a multiple of 10 in 100ns ticks, while GetProcessTimes
    generally is not. Exact equality therefore essentially NEVER holds, and the panic
    key refused every single process it was asked to stop: a real walkthrough reported
    "0 terminated; 9 left alone (identity no longer matched)" with nine live Edge
    processes still running.

    The unit test did not catch this because it read BOTH sides with GetProcessTimes,
    so it was self-consistent and proved nothing about the path that actually runs.

    Comparing at microsecond resolution is exact at the precision the coarser source
    actually carries. Two different processes sharing a PID *and* being created inside
    the same microsecond is not a realistic collision, so this keeps the whole point of
    the guard - refusing a recycled PID, including one recycled into another
    msedge.exe - while letting it match the process it is looking at.
    """
    return enumerated // 10 == from_handle // 10


def terminate_attributed(processes: list[EdgeProcess]) -> TerminationReport:
    """Immediately terminate processes whose identity still checks out.

    THE IDENTITY RE-CHECK IS THE POINT, not a formality. Between the enumeration that
    produced `processes` and this call, Windows may have recycled a PID. Terminating on
    the strength of the PID alone would eventually kill somebody else's process, and
    because the recycled PID could belong to another msedge.exe, checking only the
    image name would not catch it. Comparing the creation FILETIME read from the OPENED
    HANDLE against the one observed at enumeration identifies the process INSTANCE, and
    a mismatch is refused rather than guessed at.

    Fails closed throughout: anything that cannot be positively identified is left
    alone and counted in `refused`.

    TerminateProcess is ASYNCHRONOUS - a True return means termination was requested,
    not that the process is gone and its file locks are released. So each handle is
    waited on briefly and `confirmed_exited` counts only the ones actually observed to
    have exited. The caller must not describe the rest as stopped.
    """
    terminated = already_gone = refused = failed = confirmed = 0

    for entry in processes:
        handle = KERNEL32.OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
            | PROCESS_SYNCHRONIZE, False, entry.pid)
        if not handle or handle == _INVALID_HANDLE:
            # Gone already, or not ours to open. Either way, nothing to do.
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

    # Verify rather than assume - the project's standing rule.
    actual = USER32.GetParent(hwnd)
    ok = bool(actual) and int(actual) == int(parent_hwnd)
    _log.info("window hosting %s", "verified" if ok else "FAILED")
    return ok


def fit(hwnd: int, width: int, height: int) -> None:
    """Size the hosted window to the frame, and make sure it actually repaints.

    SetWindowPos alone was not enough: Chromium composites its own surface and would
    show a stale or blank area until something forced a paint. RedrawWindow with
    INVALIDATE|ERASE|ALLCHILDREN|UPDATENOW pushes the repaint through immediately.
    """
    if not (hwnd and USER32.IsWindow(hwnd) and width > 0 and height > 0):
        return
    USER32.SetWindowPos(wt.HWND(hwnd), wt.HWND(0), 0, 0, width, height,
                        SWP_NOZORDER | SWP_FRAMECHANGED | SWP_SHOWWINDOW)
    USER32.RedrawWindow(hwnd, None, None,
                        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW)
    USER32.UpdateWindow(hwnd)


def work_area() -> tuple[int, int, int, int]:
    """The desktop area excluding the taskbar, as (left, top, width, height).

    Tk only exposes the full screen size, so a window sized from winfo_screenheight
    runs underneath the taskbar. bruhswer's status lights are the bottom 43px of the
    window, so that is exactly the strip that disappears. Falls back to the full
    screen if the query fails, which is the pre-existing behaviour.
    """
    rect = wt.RECT()
    try:
        if USER32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            return (rect.left, rect.top,
                    rect.right - rect.left, rect.bottom - rect.top)
    except (OSError, ctypes.ArgumentError):
        pass
    return (0, 0, USER32.GetSystemMetrics(0), USER32.GetSystemMetrics(1))


def enable_dpi_awareness() -> str:
    """Make this process DPI-aware BEFORE any window exists.

    Tk is DPI-unaware by default. Edge is per-monitor DPI-aware. Hosting one inside the
    other with a mismatch makes Windows virtualise coordinates for the parent but not
    the child, so the page renders at the wrong scale or gets clipped inside the frame -
    which looks exactly like "the web page does not render properly".

    Must run before the first window is created; Windows ignores it afterwards.
    """
    try:
        # Per-monitor v2 - the mode that keeps a hosted child correct across monitors.
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
    """True once Chromium has built the compositor surface for this window.

    Measured on this machine: the top-level window appears with its render widget
    already present and sized, but the "Intermediate D3D Window" - the compositor
    surface - does not exist for another ~52ms.

    This gate is DEFENSIVE, not a fix for a diagnosed bug. Reparenting inside that gap
    is a plausible way to get a window that hosts successfully and paints nothing, but
    it was never reproduced: each host attempt already costs a ~258ms PowerShell round
    trip to find Edge's PIDs, so the gap cannot be hit by polling faster. The check is
    cheap and correct, so it stays; it should not be cited as the cause of anything.

    Falls back to the render widget when there is no D3D surface at all, which is what
    software rendering looks like, so this can never block hosting forever.
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
    """Join the two windows' input queues so typing and clicking reach the browser.

    THIS IS WHY TYPING DID NOT WORK.

    A reparented window still belongs to a DIFFERENT process, and Windows gives each
    GUI thread its own input queue. `SetParent` moves the window but does not merge
    those queues, so keyboard focus never crosses from bruhswer's thread to Edge's:
    the page renders, the mouse mostly works, and every keystroke goes nowhere.

    `AttachThreadInput` merges the queues, which is the documented way to share focus
    across threads. It is not a hack and it changes nothing about Edge's security - no
    injection, no hooks, no messages synthesised into another process.

    The cost, stated honestly: attached input queues mean the two threads share focus
    state, so if one blocks, the other can feel it. That is the accepted trade for a
    browser you can actually type in, and the attachment is released on teardown.
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
    """Release the attachment. Leaving it behind would tie bruhswer's focus state to a
    browser thread that no longer exists."""
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
    """Take keyboard focus BACK from the hosted browser.

    Needed because attaching the input queues cuts both ways: once focus is on the Edge
    window, clicking a Tk widget does not necessarily move it back, so bruhswer's own
    fields would accept a click but silently receive no keystrokes. That is the
    "the search bar works sometimes" symptom, and it is caused by the same mechanism
    that made typing work at all.
    """
    if host_hwnd and USER32.IsWindow(host_hwnd):
        USER32.SetFocus(host_hwnd)


def request_close(hwnd: int) -> bool:
    """Ask the browser window to close the way a user would.

    This matters beyond tidiness. Force-killing Edge leaves the profile marked as
    crashed, so the next launch shows a "Restore pages" bubble and offers to reopen the
    previous session's tabs - which is both a poor experience and a privacy problem for
    a browser whose whole point is controlled session state. A real WM_CLOSE lets Edge
    shut down cleanly and record a normal exit.
    """
    if not is_alive(hwnd):
        return False
    USER32.PostMessageW(wt.HWND(hwnd), WM_CLOSE, 0, 0)
    return True
