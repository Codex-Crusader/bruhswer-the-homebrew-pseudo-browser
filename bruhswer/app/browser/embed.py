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
import subprocess
from pathlib import Path

from .. import config
from ..logging_setup import get_logger

_log = get_logger("embed")

USER32 = ctypes.WinDLL("user32", use_last_error=True)

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


def renderer_pids_for_profile(profile_dir: Path) -> list[int]:
    """PIDs of this session's renderer processes - the ones that run web content."""
    marker = profile_dir.name
    if not marker.replace("_", "").replace("-", "").isalnum():
        return []
    try:
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             _PS_RENDERERS.format(marker=marker)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return []
    raw = (proc.stdout or "").strip()
    return [int(x) for x in raw.split(",") if x.strip().isdigit()]


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
