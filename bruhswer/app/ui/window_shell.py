"""The state and the cross-half calls that BrowserWindow's two mixins share.

WHY THIS FILE EXISTS
    browser_window.py was split into three: layout/actions here in BrowserWindow,
    startup/hosting/teardown in session_lifecycle.py, and the verification display in
    verification_ui.py. The two halves are mixins woven into one object, so they freely
    use `self.root`, `self.controller`, `self.set_status(...)` - attributes and methods
    that BrowserWindow.__init__ creates and that the mixin's own file never mentions.

    That works at runtime and is unreadable to every static checker: 90 unresolved
    references in session_lifecycle.py and 59 in verification_ui.py. Those warnings are
    not cosmetic. They are the noise that hides a REAL unresolved reference - a genuine
    typo in a teardown path would have sat in that list indistinguishable from the 149
    false ones.

    So the shared surface is declared once, here, and both mixins inherit it. The
    annotations give the checker the types; the method stubs give it the signatures.

WHY THE STUBS RAISE
    A stub that returned None would let a half-wired mixin fail silently at runtime.
    Every one of these is overridden - by BrowserWindow itself or by the other mixin -
    and tests/test_window_surface.py asserts that none survives on the assembled class.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable

from ..controller import controller as ctrl
from ..security import verifier
from . import panic_key
from .verify_worker import VerifyWorker


class WindowShell:
    """Declared, never instantiated. BrowserWindow provides all of it."""

    # --- widgets, built in BrowserWindow._build ---------------------------------
    root: tk.Tk
    stage: tk.Frame
    address: tk.Entry
    status_text: tk.Label
    session_badge: tk.Label
    bruh_button: tk.Button
    panic_hint: tk.Label
    curtain: tk.Label
    curtain_actions: tk.Frame
    account_banner: tk.Frame
    account_banner_text: tk.Label
    regression_banner: tk.Frame
    regression_text: tk.Label
    lights: dict[str, tk.Label]
    light_labels: dict[str, tk.Label]

    # --- session and verification state -----------------------------------------
    controller: ctrl.Controller
    result: verifier.VerificationResult | None
    hosted_hwnd: int | None
    high_contrast: bool | None

    _verifier: VerifyWorker
    _panic_hotkey: panic_key.PanicHotkey
    _panic_fired: bool
    _warned_ids: set[str]
    _applied_verification_id: int
    _closing: bool
    _placeholder: bool
    _host_attempts: int
    _jobs: set[str]
    _watch_job: str | None
    _drain_job: str | None
    _verify_in_flight: bool

    # --- implemented in BrowserWindow -------------------------------------------
    def _unimplemented(self) -> str:
        """Message for a stub that was reached, naming what failed to provide it."""
        return (f"{type(self).__name__} reached a WindowShell stub; the class that "
                f"mixes it in must implement this")

    def _after(self, delay_ms: int, callback):
        raise NotImplementedError(self._unimplemented())

    def _cancel_all_jobs(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _show_curtain(self, message: str, colour: str,
                      actions: list | None = None) -> None:
        raise NotImplementedError(self._unimplemented())

    def _hide_curtain(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def set_status(self, text: str) -> None:
        raise NotImplementedError(self._unimplemented())

    def clear_placeholder(self, _event=None) -> None:
        raise NotImplementedError(self._unimplemented())

    def open_security_panel(self) -> None:
        raise NotImplementedError(self._unimplemented())

    # --- implemented in VerificationUIMixin --------------------------------------

    def refresh_lights(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def update_session_badge(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _arm_panic_key(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _refresh_panic_indicator(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _start_reverification(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _stop_reverification(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _verify_async(
            self, mode: str,
            on_done: Callable[[verifier.VerificationResult], None]) -> None:
        raise NotImplementedError(self._unimplemented())

    # --- implemented in SessionLifecycleMixin ------------------------------------

    def close_session(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def on_close(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _on_panic(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _new_persistent(self) -> None:
        raise NotImplementedError(self._unimplemented())

    def _rehost(self) -> None:
        raise NotImplementedError(self._unimplemented())
