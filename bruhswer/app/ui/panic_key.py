"""A global panic hotkey: Ctrl+Shift+End stops this session's browser at once.

WHY A DEDICATED THREAD, AND NOT A TK `after()` TICK
    `RegisterHotKey(NULL, ...)` posts WM_HOTKEY to the REGISTERING THREAD's message
    queue as a thread message - one with no target window. Tk owns and pumps the main
    thread's queue inside `mainloop`, so registering there and hoping to observe the
    message from a periodic `PeekMessageW` is a race with Tk's own pump: Tk can remove
    and discard the thread message first, and `DispatchMessage` has no window to
    deliver a NULL-hwnd hotkey to anyway.

    That design would appear to work when tested by hand and silently drop the key in
    use, which for a panic control is the worst possible failure - the user believes
    they have an escape hatch and finds out otherwise at the moment they need it.

    So the hotkey is registered on a thread bruhswer owns, which does nothing but block
    in `GetMessageW`. It never touches Tk.

WHAT THIS THREAD DOES NOT DO
    It does not enumerate processes, terminate anything, or read a profile. The
    enumeration alone is a PowerShell round trip that can take up to a minute, and
    doing it here would make the hotkey non-immediate AND prevent a bounded teardown.
    This thread's entire job is to notice the key and put a token on a queue. All the
    work happens on the Tk side, off this thread.

IF REGISTRATION FAILS
    Another application may already own Ctrl+Shift+End - including a second copy of
    bruhswer. `available` then reads False and the UI says so, prominently. There is
    deliberately no fallback to a Tk-level binding: a key that works only while
    bruhswer has focus is not a panic key, because the whole point is to fire while the
    hosted browser has focus, and offering it under the same name would be a claim
    bruhswer cannot keep.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import queue
import threading

from .. import config
from ..logging_setup import get_logger

_log = get_logger("panickey")

USER32 = ctypes.WinDLL("user32", use_last_error=True)
KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)

WM_QUIT = 0x0012
WM_HOTKEY = 0x0312
PM_NOREMOVE = 0x0000

USER32.RegisterHotKey.argtypes = [wt.HWND, ctypes.c_int, wt.UINT, wt.UINT]
USER32.RegisterHotKey.restype = wt.BOOL
USER32.UnregisterHotKey.argtypes = [wt.HWND, ctypes.c_int]
USER32.UnregisterHotKey.restype = wt.BOOL
USER32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
USER32.GetMessageW.restype = ctypes.c_int
USER32.PeekMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT,
                                wt.UINT]
USER32.PeekMessageW.restype = wt.BOOL
USER32.PostThreadMessageW.argtypes = [wt.DWORD, wt.UINT, wt.WPARAM, wt.LPARAM]
USER32.PostThreadMessageW.restype = wt.BOOL
KERNEL32.GetCurrentThreadId.restype = wt.DWORD

# Returned by RegisterHotKey's GetLastError when the combination is already taken.
ERROR_HOTKEY_ALREADY_REGISTERED = 1409


class PanicHotkey:
    """Owns the listener thread. Created and driven from the Tk thread."""

    def __init__(self) -> None:
        self.events: queue.Queue[str] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._thread_id: int | None = None
        self._ready = threading.Event()
        self._registered = False
        self._error = ""

    # --- Tk-thread API ----------------------------------------------------------

    @property
    def available(self) -> bool:
        """True only if the key is actually registered with Windows right now."""
        return self._registered

    @property
    def status_text(self) -> str:
        if self._registered:
            return f"Panic key armed: {config.PANIC_HOTKEY_LABEL}"
        return f"Panic key UNAVAILABLE - {self._error or 'not started'}"

    def start(self) -> bool:
        """Start the listener and wait briefly for it to report registration."""
        if self._thread is not None:
            return self._registered
        self._ready.clear()
        self._thread = threading.Thread(
            target=self._loop, name="bruhswer-panic-key", daemon=True)
        self._thread.start()
        # Block only until the thread has tried to register, so the caller can show an
        # accurate armed/unavailable state immediately rather than guessing.
        self._ready.wait(timeout=config.PANIC_JOIN_TIMEOUT_SECONDS)
        if self._registered:
            _log.info("panic hotkey registered (%s)", config.PANIC_HOTKEY_LABEL)
        else:
            _log.warning("panic hotkey NOT registered: %s", self._error)
        return self._registered

    def stop(self) -> None:
        """Ask the listener to exit, and wait a bounded time for it."""
        thread, thread_id = self._thread, self._thread_id
        if thread is None:
            return
        if thread_id is not None:
            # WM_QUIT to the THREAD, not a window - GetMessageW returns 0 on it and the
            # loop unwinds through its finally, unregistering the key.
            USER32.PostThreadMessageW(wt.DWORD(thread_id), WM_QUIT, 0, 0)
        thread.join(timeout=config.PANIC_JOIN_TIMEOUT_SECONDS)
        self._thread = None
        self._thread_id = None
        self._registered = False

    # --- listener thread --------------------------------------------------------

    def _loop(self) -> None:
        """Register, then block on GetMessageW. Touches no Tk object, ever."""
        message = wt.MSG()

        # Force this thread's message queue into existence BEFORE registering or
        # posting to it. A thread has no queue until it first calls a message
        # function, and PostThreadMessageW to a thread without one silently fails -
        # which would make stop() unable to wake this thread at all.
        USER32.PeekMessageW(ctypes.byref(message), None, 0, 0, PM_NOREMOVE)
        self._thread_id = int(KERNEL32.GetCurrentThreadId())

        try:
            ok = USER32.RegisterHotKey(
                None, config.PANIC_HOTKEY_ID,
                config.PANIC_HOTKEY_MODIFIERS, config.PANIC_HOTKEY_VK)
            if not ok:
                code = ctypes.get_last_error()
                self._error = (
                    f"another application already uses {config.PANIC_HOTKEY_LABEL}"
                    if code == ERROR_HOTKEY_ALREADY_REGISTERED
                    else f"Windows refused the hotkey (error {code})")
                self._registered = False
                # CLEAR THE THREAD HANDLE so a later start() actually tries again.
                # Without this the dead thread stayed recorded, start() early-returned
                # on `self._thread is not None`, and bruhswer remained permanently
                # UNAVAILABLE for the rest of the run - even after the application
                # holding Ctrl+Shift+End released it. Honestly red rather than falsely
                # green, but a safety control left dead for no reason.
                self._thread = None
                return
            self._registered = True
        finally:
            # Set AFTER _registered/_error are final, so start() never reads a
            # half-written state.
            self._ready.set()

        try:
            while True:
                result = USER32.GetMessageW(ctypes.byref(message), None, 0, 0)
                if result == 0:          # WM_QUIT
                    break
                if result == -1:         # error; do not spin on it
                    _log.error("panic key message loop failed")
                    break
                if message.message == WM_HOTKEY:
                    _log.warning("PANIC KEY PRESSED")
                    self.events.put("panic")
        finally:
            USER32.UnregisterHotKey(None, config.PANIC_HOTKEY_ID)
            self._registered = False
            _log.info("panic hotkey released")
