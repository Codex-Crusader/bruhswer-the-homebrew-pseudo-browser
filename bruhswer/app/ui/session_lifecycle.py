"""Session lifecycle for the browser window: verify, launch, host, tear down.

A mixin because these methods share BrowserWindow's state and the tests drive them as
window methods.
"""

from __future__ import annotations

import tkinter as tk

from .. import config
from ..browser import embed
from ..security import verifier
from ..sessions import session_manager
from . import dialogs
from .window_shell import WindowShell


class SessionLifecycleMixin(WindowShell):
    """Startup, window hosting and teardown. Mixed into BrowserWindow."""

    def startup(self) -> None:
        """Verify, off the Tk thread; the browser appears only if the checks allow it."""
        # Before verification, so a blocked launch still has a panic key.
        self._arm_panic_key()
        self.set_status("Running security verification...")
        self._verify_async(session_manager.PERSISTENT, self._on_startup_verified)

    def _on_startup_verified(self, result: verifier.VerificationResult) -> None:
        self.result = result
        self.refresh_lights()

        if self.result.blockers:
            reasons = "\n".join(f"  • {c.title}" for c in self.result.blockers)
            self._show_curtain(
                f"BRUH. NO.\n\nRequired security controls could not be verified.\n"
                f"Browser launch has been blocked.\n\n{reasons}",
                config.BAD_RED,
                [("What failed", self.open_security_panel),
                 ("Check again", self.startup)])
            self.set_status("Launch blocked")
            return

        self.open_session(session_manager.PERSISTENT)

    def open_session(self, mode: str) -> None:
        embed.detach_input()

        # Replacing a disposable session destroys its downloads: same warning as close.
        if not self._confirm_disposable_downloads():
            self._reattach_input()
            self.set_status("Kept the current session; no new session started.")
            return

        self._stop_reverification()

        # Painted before stop(), which can block for ~22s.
        self._show_curtain(f"Starting {mode} session...", config.FG_DIM)
        self.root.update_idletasks()

        # Unconditional: a disposable profile outlives its closed browser window.
        _stopped, message = self.controller.stop()
        if message:
            self.set_status(message)
        self.hosted_hwnd = None
        self._host_attempts = 0

        outcome = self.controller.start(mode)
        self.result = outcome.result
        self.refresh_lights()

        if not outcome.launched:
            self._show_curtain(f"BRUH. NO.\n\n{outcome.message}", config.BAD_RED,
                               [("What failed", self.open_security_panel),
                                ("Try again", self._new_persistent)])
            self.set_status("Launch blocked")
            return

        self.update_session_badge()
        self.set_status(outcome.message)

        self._start_reverification()
        # 1200ms is what shipped builds use; 250ms was never proven worse.
        self._after(1200, self._try_host)

    def _try_host(self) -> None:
        """Poll for this session's Edge window, then host it."""
        self._host_attempts += 1
        hwnd = self.controller.find_browser_window()
        if (hwnd and not embed.is_paint_ready(hwnd)
                and self._host_attempts < config.HOST_MAX_ATTEMPTS):
            self._after(120, self._try_host)
            return
        if hwnd:
            self.root.update_idletasks()
            if embed.host_window(hwnd, self.stage.winfo_id()):
                self.hosted_hwnd = hwnd
                self.controller.set_hosted_window(hwnd)
                embed.attach_input(hwnd, self.root.winfo_id())
                embed.focus(hwnd)
                # The curtain stays up until the resize is confirmed, not on a timer.
                self._settle_hosted()
                self._watch_job = self._after(1500, self._watch)
                return

        if self._host_attempts < config.HOST_MAX_ATTEMPTS:
            self._after(800, self._try_host)
            return

        self._show_curtain(
            "The browser is running, but bruhswer could not host\n"
            "its window inside this frame.\n\n"
            "It is open as a separate window and is still fully protected -\n"
            "firewall policy, quarantine and session rules all still apply.",
            config.WARN_AMBER,
            [("Try again", self._rehost), ("Close the session", self.close_session)])
        self.set_status("Browser running in its own window")

    def _reveal_stage(self) -> None:
        """Drop the curtain onto a page that has already been sized and painted."""
        if not self.hosted_hwnd or not embed.is_alive(self.hosted_hwnd):
            return          # _watch will report it
        self._hide_curtain()
        self.set_status("WE GOOD")

    def _new_persistent(self) -> None:
        self.open_session(session_manager.PERSISTENT)

    def _rehost(self) -> None:
        """Try to pull a still-running session's window back into the frame."""
        self._host_attempts = 0
        self.set_status("Looking for the browser window...")
        self._try_host()

    def _focus_address(self, _event=None) -> None:
        """Take keyboard focus back from the hosted browser, then into the field."""
        embed.focus_host(self.root.winfo_id())
        self.address.focus_force()
        self.clear_placeholder()

    def _focus_browser(self, _event=None) -> None:
        """Focus the hosted page, unless the user is in the address bar."""
        if not self.hosted_hwnd:
            return
        try:
            if self.root.focus_get() is self.address:
                return
        except (KeyError, tk.TclError):
            pass
        embed.focus(self.hosted_hwnd)

    def _fit_hosted(self, _event=None) -> None:
        if self.hosted_hwnd and embed.is_alive(self.hosted_hwnd):
            embed.fit(self.hosted_hwnd, self.stage.winfo_width(),
                      self.stage.winfo_height())

    def _settle_hosted(self, attempt: int = 1) -> None:
        """Resize, confirm it landed, retry a bounded number of times, then reveal.
        Not the <Configure> handler, which must stay one cheap fit per user resize."""
        if not self.hosted_hwnd or not embed.is_alive(self.hosted_hwnd):
            return          # _watch will report it

        self.root.update_idletasks()
        self._fit_hosted()

        width, height = self.stage.winfo_width(), self.stage.winfo_height()
        settled = (embed.is_fitted(self.hosted_hwnd, width, height)
                   and embed.is_paint_ready(self.hosted_hwnd))
        if settled or attempt >= config.FIT_MAX_ATTEMPTS:
            self._reveal_stage()
            return
        self._after(config.FIT_RETRY_MS, lambda: self._settle_hosted(attempt + 1))

    def _watch(self) -> None:
        """Notice if the browser goes away."""
        try:
            if not self.root.winfo_exists():
                return
        except tk.TclError:
            return  # window already destroyed

        if self.hosted_hwnd and not embed.is_alive(self.hosted_hwnd):
            self.hosted_hwnd = None
            # Windows recycles handles; a stale one could get another window's WM_CLOSE.
            self.controller.set_hosted_window(None)
            # The window going is not the browser closing, and is_running() may still
            # see processes mid-teardown, so keep polling rather than latch a message.
            if self.controller.is_running():
                self._show_curtain(
                    "The browser is no longer inside bruhswer's frame.\n\n"
                    "Checking whether the session is still running...",
                    config.WARN_AMBER,
                    [("Bring it back", self._rehost),
                     ("Close the session", self.close_session)])
                self.set_status("Window not hosted; re-checking the session")
            else:
                self._show_curtain("The browser window closed.", config.WARN_AMBER,
                                   [("New session", self._new_persistent)])
                self.set_status("Browser closed")
            self.update_session_badge()
            self._watch_job = self._after(1500, self._watch)
            return

        if self.hosted_hwnd is None and not self.controller.is_running():
            if self.status_text.cget("text").startswith("Window not hosted"):
                self._show_curtain("The browser window closed.", config.WARN_AMBER,
                                   [("New session", self._new_persistent)])
                self.set_status("Browser closed")
                self.update_session_badge()
            self._watch_job = self._after(1500, self._watch)
            return
        title = self.controller.browser_title()
        if title:
            self.status_text.config(
                text=title.replace(" - Microsoft Edge", "")[:90])
        self._watch_job = self._after(1500, self._watch)

    def _on_panic(self) -> None:
        """Stop this session's browser at once, with no prompt. One-shot, so a held key
        cannot start a second teardown."""
        if self._panic_fired:
            return
        self._panic_fired = True

        # Detach first, or bruhswer's window hangs with its dying browser thread.
        embed.detach_input()
        self._stop_reverification()
        self.hosted_hwnd = None

        self._show_curtain("PANIC\n\nStopping this session's browser...",
                           config.BAD_RED)
        self.root.update_idletasks()

        ok, message = self.controller.panic_stop()
        self.update_session_badge()
        self._refresh_panic_indicator()
        self._show_curtain(
            f"PANIC\n\n{message}", config.OK_GREEN if ok else config.BAD_RED,
            [("New session", self._new_persistent), ("Close bruhswer", self.on_close)])
        self.set_status(message)

    def on_close(self) -> None:
        # Detach before the modal dialog below; a grab with shared input queues hangs.
        embed.detach_input()

        if not self._confirm_disposable_downloads():
            self._reattach_input()
            self.set_status("Still open. Export your downloads, then close again.")
            return

        # First, so an already-queued drain callback returns at once.
        self._closing = True
        self._stop_reverification()

        self._cancel_all_jobs()

        if self.controller.is_running():
            # Painted before stop(), which can block for ~22s.
            self._show_curtain("Closing bruhswer...", config.FG_DIM)
            self.root.update_idletasks()
            ok, message = self.controller.stop()
            if not ok:
                dialogs.cleanup_incomplete(self.root, message, self.root.destroy)
                return
        self.root.destroy()

    def _reattach_input(self) -> None:
        """Re-join the input queues after a cancelled close."""
        if self.hosted_hwnd and embed.is_alive(self.hosted_hwnd):
            embed.attach_input(self.hosted_hwnd, self.root.winfo_id())
            embed.focus(self.hosted_hwnd)

    def _confirm_disposable_downloads(self) -> bool:
        """Ask before destroying downloads. Returns False if the user cancels."""
        pending = self.controller.pending_disposable_downloads()
        if not pending:
            return True
        return dialogs.confirm_disposable_downloads(self.root, pending)

    def close_session(self) -> None:
        embed.detach_input()
        if not self._confirm_disposable_downloads():
            self._reattach_input()
            self.set_status("Session left open.")
            return
        self._stop_reverification()

        # Painted before stop(), which can block for ~22s.
        self._show_curtain("Closing session...", config.FG_DIM)
        self.root.update_idletasks()

        ok, message = self.controller.stop()
        self.hosted_hwnd = None
        self._show_curtain(message, config.OK_GREEN if ok else config.BAD_RED,
                           [("New session", self._new_persistent)])
        self.update_session_badge()
        self.set_status(message)
