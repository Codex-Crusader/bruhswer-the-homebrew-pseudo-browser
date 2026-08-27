"""Verification display for the browser window: lights, regressions, banners.

Split out of browser_window.py. This half owns everything that turns a
VerificationResult into something on screen, plus the re-verification worker's lifecycle
and the panic key's indicator.

It renders verdicts; it never decides one. Every judgement still belongs to the guards.
See session_lifecycle.py for why this is a mixin rather than a separate object.
"""

from __future__ import annotations

import queue
import tkinter as tk

from .. import config
from ..privacy import privacy_guard
from ..sessions import session_manager
from ..verdict import Verdict
from . import verify_worker
from .panels import chrome
from .window_shell import WindowShell

_COLOUR = chrome.COLOUR
_SHAPE = chrome.SHAPE


class VerificationUIMixin(WindowShell):
    """Status lights, regression warnings and the account banner."""

    def _arm_panic_key(self) -> None:
        """Register the panic hotkey and show its REAL state, persistently.

        Called from startup, not from the launch success path. Tying it to a
        successful launch meant that a blocked launch - the state where a user is most
        likely to want an escape hatch - left the key unregistered with nothing on
        screen saying so.

        The result goes to a permanent indicator rather than the status line. The
        status line is overwritten within a second by the launch sequence ("WE GOOD"
        at 950ms), so a user whose Ctrl+Shift+End is owned by another application
        would have seen "UNAVAILABLE" flash past and be replaced by reassurance. That
        is exactly the failure this module's docstring warns about: believing in an
        escape hatch and discovering otherwise at the moment it is needed.
        """
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
        """Forget what the previous session's verification left behind.

        Session A's warned ids survived into B, where B's first clean pass withdrew a
        warning about A and tore down B's own curtain to do it.
        """
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
        """Apply whatever the worker finished. Tk thread only.

        This is the ONLY place a worker result reaches a widget. Everything the worker
        produces arrives here as plain data.
        """
        self._drain_job = None
        try:
            if self._closing or not self.root.winfo_exists():
                return
        except tk.TclError:
            return      # interpreter already gone; a queued callback must not crash

        # Panic first: if the key was pressed, nothing else this tick matters.
        try:
            self._panic_hotkey.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self._on_panic()
            return

        for update in self._verifier.drain():
            # STALE RESULT. The session changed while this pass was running, so it
            # describes a profile that has been closed - and for a disposable session,
            # deleted. Showing it would put a verdict about a dead session onto the
            # lights of a live one.
            if update.generation != self.controller.generation:
                continue

            # Superseded within the same session: a pass that hit a 60s timeout lands
            # after the one that replaced it, and would move the lights backwards.
            if update.verification_id < self._applied_verification_id:
                continue
            self._applied_verification_id = update.verification_id

            # THE PASS RAISED AND MEASURED NOTHING. The previous result is still on
            # screen, and leaving it there unannounced would present a stale set of
            # green lights as current - the defect the worker exists to remove,
            # reached by a different route. Say so; do not silently keep the old
            # verdicts looking fresh.
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
        """Show or hide the Microsoft-account banner from the LATEST measurement.

        STATE-DRIVEN, and deliberately not wired to the regression path. Two reasons
        it could not be:

          1. `privacy.account` is reported with enforceable=False, and
             verify_worker._comparable() excludes unenforceable checks - correctly, so
             that the permanently-FAIL net.loopback does not fire a warning every
             cycle. This check would be excluded with it.
          2. Even if it were included, the transition is UNKNOWN ("no profile yet" at
             launch) -> FAIL once Edge signs itself in. find_regressions only reports
             PASS -> not-PASS, so that transition is invisible to it.

        So the banner reads the current verdict directly, every pass, and appears and
        disappears with the measurement rather than with a transition.
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
            # Names the mode directly. This read `"DISPOSABLE" if ... else "This"` and
            # then lower-cased it into the phrase "signed this {kind} session", so a
            # persistent session rendered "Edge signed this this session" - a doubled
            # word in the opening line of a warning whose whole job is to be believed.
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
            # PASS, or UNKNOWN for a reason other than an unreadable profile.
            self.account_banner.pack_forget()
            return

        # before= keeps it directly above the page area no matter when it appears.
        self.account_banner.pack(fill="x", padx=12, pady=(0, 6), before=self.stage)

    def on_open_account_settings(self) -> None:
        """Open Edge's sign-out page. Reports only that a tab was opened."""
        _opened, message = self.controller.open_account_settings()
        self.set_status(message)

    def _clear_regression_warning(self, update) -> None:
        """Take the warning back when every control it named is verifying again.

        Needed because a warning with no way to withdraw it is its own kind of false
        indicator. One failed PowerShell query flips a check to UNKNOWN for a single
        cycle; the next cycle succeeds and it is PASS again. Since only PASS ->
        not-PASS is ever reported, nothing would arrive to remove the red curtain, and
        the user would be told something changed long after it had changed back.
        """
        if not self._warned_ids:
            return
        recovered = self._warned_ids & verify_worker.passing_ids(update.result)
        self._warned_ids -= recovered
        self._refresh_regression_banner()
        if self._warned_ids:
            return          # some are still not verifying; the warning stands
        self._hide_curtain()
        self.set_status("Controls are verifying again.")

    def _refresh_regression_banner(self) -> None:
        """Keep the degraded state on screen for as long as it is true.

        The curtain is dismissible, and "Keep browsing" is a legitimate choice since a
        regression can be a PowerShell timeout. But dismissing it removed every trace,
        so a genuinely degraded session looked identical to a healthy one.
        """
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
        """A control that was verified at launch no longer verifies.

        bruhswer WARNS; it does not close the session by itself. That is deliberate.
        A verification pass can go non-PASS because a PowerShell query timed out under
        load, and auto-killing the browser on a measurement error would destroy a
        disposable session's unexported downloads over a transient. The user is told
        precisely what changed and given the action; the decision stays theirs.
        """
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
            # Cancelling directly (rather than through _cancel_all_jobs) bypasses the
            # self-removal _after's wrapper does when a job actually runs, so the id
            # must be discarded here too or it sits in _jobs until final teardown.
            self._jobs.discard(self._drain_job)
            self._drain_job = None
        self._verifier.stop()
        self._panic_hotkey.stop()
        self._reset_verification_state()

        # REFRESH THE INDICATOR HERE, not in each caller. This method is what
        # unregisters the hotkey, so it is what owes the user an honest light.
        #
        # close_session() called this and then never touched the PANIC light, so after
        # closing a session the dot stayed green and the hint still read
        # "Ctrl+Shift+End" while the listener was gone - a status light promising an
        # escape hatch that would do nothing if pressed. _on_panic() happened to get
        # this right, which is exactly how the inconsistency survived: the correct
        # behaviour lived in one caller instead of in the operation itself.
        #
        # Skipped while closing, where the widgets are about to be destroyed anyway.
        if not self._closing:
            self._refresh_panic_indicator()

    def _set_light(self, key: str, colour: str, shape: str) -> None:
        """Colour AND shape. Colour alone puts the whole meaning in hue.

        A red-green colour blindness makes PASS and FAIL the same dot, and this
        product's entire output is a row of dots.
        """
        self.lights[key].config(fg=colour, text=shape)

    def _refresh_downloads_count(self) -> None:
        """Say how many files are quarantined, not just that quarantine is on.

        The count is the fact a user acts on - a disposable session destroys those
        files on close, and a coloured dot never told them there was anything to lose.
        """
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

        # Never green. Measured platform limitation, stated permanently (SS21).
        self._set_light("LOCALHOST", config.WARN_AMBER, config.SHAPE_LIMITATION)
        self._set_light("VPN", config.OFF_GREY, config.SHAPE_LIMITATION)
        self._refresh_downloads_count()
        # Not a verdict from the verifier - a live fact about a Windows registration.
        self._refresh_panic_indicator()

        worst = self.result.category("net.")
        blocked = bool(self.result.blockers)
        self.bruh_button.config(
            fg=config.BAD_RED if blocked else
            (config.OK_GREEN if worst is Verdict.PASS else config.WARN_AMBER))

        # Every path that redraws the lights also re-evaluates the account banner, so
        # it can never lag behind the verdict it is derived from.
        self._refresh_account_banner()

    def update_session_badge(self) -> None:
        session = self.controller.snapshot()
        if not session.active or not self.controller.is_running():
            self.session_badge.config(text="NO SESSION", fg=config.FG_DIM)
            return
        # A disposable session's age is on the badge because its whole value is that it
        # gets thrown away, and "how long has this one been accumulating state" is the
        # fact a user needs to decide whether to start a fresh one.
        elapsed = session.elapsed_text()
        self.session_badge.config(
            text=f"{session.badge}  {elapsed}" if elapsed else session.badge,
            fg=config.WARN_AMBER if session.is_disposable else config.OK_GREEN)
