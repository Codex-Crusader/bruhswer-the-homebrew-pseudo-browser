"""Global panic hotkey: Ctrl+Shift+End stops this session's browser at once.

Registered on its own thread that only blocks in GetMessageW: WM_HOTKEY goes to the
registering thread's queue, and on the Tk thread mainloop can discard it. The thread
only queues a token; the work happens elsewhere.

If another program owns the key, `available` is False and the UI says so. No Tk
fallback: a key that works only while bruhswer has focus is not a panic key.
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
        if self._thread is not None and self._thread.is_alive():
            return self._registered
        self._ready.clear()
        self._thread = threading.Thread(
            target=self._loop, name="bruhswer-panic-key", daemon=True)
        self._thread.start()
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
            # WM_QUIT to the thread: GetMessageW returns 0 and the key is unregistered.
            USER32.PostThreadMessageW(wt.DWORD(thread_id), WM_QUIT, 0, 0)
        thread.join(timeout=config.PANIC_JOIN_TIMEOUT_SECONDS)
        self._thread = None
        self._thread_id = None
        self._registered = False


    def _loop(self) -> None:
        """Register, then block on GetMessageW. Touches no Tk object, ever."""
        message = wt.MSG()

        # Create the message queue first, or stop()'s PostThreadMessageW fails silently.
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
                return
            self._registered = True
        finally:
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
