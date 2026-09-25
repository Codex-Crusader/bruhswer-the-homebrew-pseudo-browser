"""Verification display for the browser window: lights, regressions, banners, the
re-verification worker and the panic indicator. It renders verdicts; it never decides
one."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from typing import Callable

from .. import config
from ..controller import controller as ctrl
from ..logging_setup import get_logger
from ..privacy import privacy_guard
from ..security import verifier
from ..sessions import session_manager
from ..verdict import Verdict
from . import verify_worker
from .panels import chrome
from .window_shell import WindowShell

_COLOUR = chrome.COLOUR
_log = get_logger("ui")


class VerificationUIMixin(WindowShell):
    """Status lights, regression warnings and the account banner."""

    def _verify_async(
            self, mode: str,
            on_done: Callable[[verifier.VerificationResult], None]) -> None:
        """Run ONE pass off the Tk thread and deliver it on the Tk thread.

        Not through the worker, whose regression baseline this pass must not become.
        Refuses a second call while one runs: two overlapping startup() calls would
        each open a session and tear down the other's.
        """
        if self._verify_in_flight:
            self.set_status("Security verification is already running.")
            return
        self._verify_in_flight = True

        request = self.controller.verification_request(mode)
        result_box: queue.Queue = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                result_box.put(ctrl.run_verification(request))
            except Exception:                # noqa: BLE001  # lint: allow broad-except - a crashed pass must not vanish silently
                _log.exception("one-shot verification pass failed")
                result_box.put(None)

        threading.Thread(target=worker, daemon=True,
                         name="bruhswer-verify-once").start()

        def poll() -> None:
            try:
                if self._closing or not self.root.winfo_exists():
                    return
            except tk.TclError:
                return        # interpreter already gone
            try:
                result = result_box.get_nowait()
            except queue.Empty:
                self._after(config.VERIFY_DRAIN_MS, poll)
                return
            self._verify_in_flight = False
            if result is None:
                self.set_status("Security verification failed to run. Try again.")
                return
            on_done(result)

        poll()

    def _arm_panic_key(self) -> None:
        """Register the panic hotkey at startup, including when launch is blocked, and
        show its real state on a permanent indicator."""
        self._panic_fired = False
        self._panic_hotkey.start()
        self._refresh_panic_indicator()

    def _refresh_panic_indicator(self) -> None:
        """The PANIC light, driven by whether the key is registered RIGHT NOW."""
        armed = self._panic_hotkey.available
        self.lights["PANIC"].config(
            fg=config.OK_GREEN if armed else config.BAD_RED)
        self.panic_hint.config(
            text=(config.PANIC_HOTKEY_LABEL if armed else "UNAVAILABLE"),
            fg=config.FG_DIM if armed else config.BAD_RED)

    def _reset_verification_state(self) -> None:
        """Forget the previous session's warnings, or B's first pass withdraws A's."""
        self._warned_ids.clear()
        self._applied_verification_id = 0
        self._refresh_regression_banner()

    def _start_reverification(self) -> None:
        """Begin (or re-aim) the background re-verification for the current session."""
        self._arm_panic_key()
        self._verifier.start()
        session = self.controller.snapshot()
        self._verifier.submit(self.controller.verification_request(
            session.mode if session.active else session_manager.PERSISTENT))
        if self._drain_job is None:
            self._drain_job = self._after(config.VERIFY_DRAIN_MS, self._drain)

    def _drain(self) -> None:
        """Apply whatever the worker finished. Tk thread only, and the only place a
        worker result reaches a widget."""
        self._drain_job = None
        try:
            if self._closing or not self.root.winfo_exists():
                return
        except tk.TclError:
            return      # interpreter already gone

        try:
            self._panic_hotkey.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self._on_panic()
            return

        for update in self._verifier.drain():
            # The session changed during this pass; its verdicts describe a dead one.
            if update.generation != self.controller.generation:
                continue

            # Superseded within the session; applying it would move the lights backwards.
            if update.verification_id < self._applied_verification_id:
                continue
            self._applied_verification_id = update.verification_id

            # The pass measured nothing: say so, or the old lights look current.
            if update.measurement_failed:
                self.set_status("Security re-check FAILED to run - lights below are "
                                "from the last successful check, not from now.")
                continue

            self.result = update.result
            self.refresh_lights()
            if update.regressions:
                self._warn_regressions(update.regressions)
            else:
                self._clear_regression_warning(update)

        self._drain_job = self._after(config.VERIFY_DRAIN_MS, self._drain)

    def _refresh_account_banner(self) -> None:
        """Show or hide the account banner from the latest verdict each pass.

        Not via find_regressions: privacy.account is unenforceable and moves UNKNOWN to
        FAIL, and neither is reported as a regression.
        """
        if self.result is None:
            return
        session = self.controller.snapshot()
        checks = [c for c in self.result.checks if c.check_id == "privacy.account"]
        if not checks or not session.active:
            self.account_banner.pack_forget()
            return
        check = checks[0]

        if check.verdict is Verdict.FAIL:
            kind = "disposable" if session.is_disposable else "persistent"
            self.account_banner_text.config(
                text=(f"BRUH. Edge signed this {kind} session into a Microsoft "
                      f"account by itself. Syncing is off, but your identity is "
                      f"attached, so this session is NOT anonymous. bruhswer cannot "
                      f"prevent this - only machine-wide Edge policy can, and it "
                      f"refuses to change every Edge profile on your PC."),
                fg=config.WARN_AMBER)
        elif (check.verdict is Verdict.UNKNOWN
              and check.evidence == privacy_guard.PREFS_UNREADABLE):
            self.account_banner_text.config(
                text=("bruhswer could not read this profile, so it cannot tell whether "
                      "Edge has signed the session into a Microsoft account. Treat it "
                      "as NOT anonymous until it can."),
                fg=config.FG_DIM)
        else:
            self.account_banner.pack_forget()
            return

        self.account_banner.pack(fill="x", padx=12, pady=(0, 6), before=self.stage)

    def on_open_account_settings(self) -> None:
        """Open Edge's sign-out page. Reports only that a tab was opened."""
        _opened, message = self.controller.open_account_settings()
        self.set_status(message)

    def _clear_regression_warning(self, update) -> None:
        """Withdraw the warning once every control it named passes again; a one-cycle
        UNKNOWN would otherwise leave it up forever."""
        if not self._warned_ids:
            return
        recovered = self._warned_ids & verify_worker.passing_ids(update.result)
        self._warned_ids -= recovered
        self._refresh_regression_banner()
        if self._warned_ids:
            return
        self._hide_curtain()
        self.set_status("Controls are verifying again.")

    def _refresh_regression_banner(self) -> None:
        """Keep a banner up while the session is degraded, even after the curtain is
        dismissed."""
        if self._closing:
            return
        try:
            if not self.regression_banner.winfo_exists():
                return
        except tk.TclError:
            return
        if not self._warned_ids:
            self.regression_banner.pack_forget()
            return
        count = len(self._warned_ids)
        self.regression_text.config(
            text=(f"BRUH.  {count} security control(s) that verified when this session "
                  f"started do not verify now.  The browser is still open."))
        self.regression_banner.pack(fill="x", padx=12, pady=(0, 6), before=self.stage)

    def _warn_regressions(self, regressions: tuple[tuple[str, str], ...]) -> None:
        """Warn that a control stopped verifying. Never closes the session: a timeout
        under load would otherwise destroy unexported downloads."""
        self._warned_ids |= {check_id for check_id, _title in regressions}
        self._refresh_regression_banner()
        named = "\n".join(f"  - {title}" for _check_id, title in regressions)
        self._show_curtain(
            f"BRUH. Something changed while you were browsing.\n\n"
            f"These controls verified when this session started, and do not now:\n\n"
            f"{named}\n\n"
            f"The browser is still open. bruhswer did not close it for you.",
            config.BAD_RED,
            [("What changed", self.open_security_panel),
             ("Close the session", self.close_session),
             ("Keep browsing", self._hide_curtain)])
        self.set_status(f"{len(regressions)} control(s) no longer verify")

    def _stop_reverification(self) -> None:
        if self._drain_job is not None:
            try:
                self.root.after_cancel(self._drain_job)
            except tk.TclError:
                pass
            # A cancelled job never runs _after's self-removal.
            self._jobs.discard(self._drain_job)
            self._drain_job = None
        self._verifier.stop()
        self._panic_hotkey.stop()
        self._reset_verification_state()

        # This unregisters the hotkey, so it must repaint the PANIC light.
        if not self._closing:
            self._refresh_panic_indicator()

    def _set_light(self, key: str, colour: str, shape: str) -> None:
        """Colour AND shape, for red-green colour blindness."""
        self.lights[key].config(fg=colour, text=shape)

    def _refresh_downloads_count(self) -> None:
        """Show the quarantined file count; a disposable session destroys them."""
        pending = self.controller.pending_disposable_downloads()
        label = self.light_labels.get("DOWNLOADS")
        if label is None:
            return
        label.config(text=f"DOWNLOADS {len(pending)}" if pending else "DOWNLOADS")

    def refresh_lights(self) -> None:
        if self.result is None:
            return
        mapping = {"HOST": "host.", "NETWORK": "net.", "PRIVACY": "privacy.",
                   "DOWNLOADS": "downloads."}
        for key, prefix in mapping.items():
            checks = self.result.by_prefix(prefix)
            if not checks:
                self._set_light(key, config.OFF_GREY, config.SHAPE_UNKNOWN)
                continue
            verdict = self.result.category(prefix)
            self._set_light(key, _COLOUR[verdict], chrome.SHAPE[verdict])

        # Never green: a measured platform limitation.
        self._set_light("LOCALHOST", config.WARN_AMBER, config.SHAPE_LIMITATION)
        self._set_light("VPN", config.OFF_GREY, config.SHAPE_LIMITATION)
        self._refresh_downloads_count()
        self._refresh_panic_indicator()

        worst = self.result.category("net.")
        blocked = bool(self.result.blockers)
        self.bruh_button.config(
            fg=config.BAD_RED if blocked else
            (config.OK_GREEN if worst is Verdict.PASS else config.WARN_AMBER))

        self._refresh_account_banner()

    def update_session_badge(self) -> None:
        session = self.controller.snapshot()
        if not session.active or not self.controller.is_running():
            self.session_badge.config(text="NO SESSION", fg=config.FG_DIM)
            return
        elapsed = session.elapsed_text()
        self.session_badge.config(
            text=f"{session.badge}  {elapsed}" if elapsed else session.badge,
            fg=config.WARN_AMBER if session.is_disposable else config.OK_GREEN)
