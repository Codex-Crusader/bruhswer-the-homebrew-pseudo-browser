"""Session lifecycle for the browser window: startup, hosting, teardown.

Split out of browser_window.py, which had grown to a thousand lines covering three
unrelated jobs. This half owns everything from "verify, then launch" through hosting
Edge inside the frame to destroying the session.

A MIXIN, not a collaborator object, and that is deliberate. These methods are woven
through BrowserWindow's own state - `hosted_hwnd`, `_host_attempts`, `root`, `stage`,
`_jobs` - and tests/test_browser_ui.py drives them as methods on the window. Extracting
a separate object would have meant either passing the window into it (the same coupling
with an extra indirection) or changing the surface the tests pin.
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
        """Verify first. The browser only appears if the checks allow it (SS9).

        A full pass starts 14 helper processes and takes 5.5s, measured. Run
        synchronously on the Tk thread this froze the window for that long on every
        launch, with the status text below never actually painting before the freeze
        started - Tk does not repaint until control returns to the event loop, and
        nothing did until the freeze was already over. Routed through _verify_async so
        the message is on screen and the window stays responsive while this runs.
        """
        # Armed BEFORE verification, so a blocked launch - the state where an escape
        # hatch matters most - still shows the panic key's true state.
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

        # Starting a new session stops the current one, which destroys a disposable
        # session's downloads. Same warning as an explicit close - the destruction is
        # identical, so hiding it here would just move the surprise. Detach first,
        # re-attach if they back out.
        if not self._confirm_disposable_downloads():
            self._reattach_input()
            self.set_status("Kept the current session; no new session started.")
            return

        # Before tearing the old session down, or the worker carries its baseline
        # across and diffs the new session's first pass against the old session's last.
        self._stop_reverification()

        # Shown and painted BEFORE the blocking stop() below, not after. stop() can
        # take up to ~22s worst case (an 8s process wait, a 12s profile-process poll,
        # a 2s settle), and painting the curtain only once that finished left the
        # window looking frozen and blank for the whole wait, with nothing on screen
        # explaining why.
        self._show_curtain(f"Starting {mode} session...", config.FG_DIM)
        self.root.update_idletasks()

        # Unconditionally, not "if is_running()". After the browser window closed on
        # its own, is_running() is False while a disposable session's profile and
        # quarantine are still on disk - so the old guard skipped the teardown the user
        # had just confirmed. stop() early-returns on a None session, so this is safe.
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

        # From here the lights stop being a launch-time snapshot. The worker re-runs
        # every check once a minute and this window redraws from whatever it finds -
        # including downgrading a light that was green at launch.
        self._start_reverification()
        # Original value, restored after an experiment. It was shortened to 250ms and a
        # blank grey stage under a "WE GOOD" status was seen shortly afterwards, so the
        # change was blamed and reverted. That attribution was NOT established:
        # find_browser_window costs a ~258ms PowerShell round trip per attempt, which is
        # far longer than the ~52ms it takes Chromium's compositor to appear, so no poll
        # interval can actually race it. The blank stage was seen while several bruhswer
        # instances were running at once, and its cause is still unknown.
        #
        # 1200ms stays because it is the value the shipped, working builds have used,
        # not because the alternative was proven bad.
        self._after(1200, self._try_host)

    def _try_host(self) -> None:
        """Poll for this session's Edge window, then host it. Verified, not assumed."""
        self._host_attempts += 1
        hwnd = self.controller.find_browser_window()
        # Having a window is not the same as being able to paint into it. Wait for the
        # compositor, or the reparent lands in the gap and the page never draws.
        if (hwnd and not embed.is_paint_ready(hwnd)
                and self._host_attempts < config.HOST_MAX_ATTEMPTS):
            self._after(120, self._try_host)
            return
        if hwnd:
            self.root.update_idletasks()
            if embed.host_window(hwnd, self.stage.winfo_id()):
                self.hosted_hwnd = hwnd
                self.controller.set_hosted_window(hwnd)
                # Without this the page renders but every keystroke is swallowed -
                # the two processes have separate input queues until they are joined.
                embed.attach_input(hwnd, self.root.winfo_id())
                embed.focus(hwnd)
                # The curtain stays UP until the resize is CONFIRMED landed. It used to
                # come down on a 950ms timer chosen to sit after two other fixed-delay
                # fits, so on a slow machine the user still watched Chromium repaint.
                self._settle_hosted()
                self._watch_job = self._after(1500, self._watch)
                return

        if self._host_attempts < config.HOST_MAX_ATTEMPTS:
            self._after(800, self._try_host)
            return

        # Honest failure: the browser IS running, it just is not inside our frame.
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
            return          # it went away while settling; _watch will report it
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

        Its own entry point rather than the <Configure> handler: that fires on every
        user resize and must stay a single cheap fit, not start a retry loop each time.
        """
        if not self.hosted_hwnd or not embed.is_alive(self.hosted_hwnd):
            return          # it went away while settling; _watch will report it

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
        """Notice if the browser goes away. Never pretend it is still there (SS34)."""
        try:
            if not self.root.winfo_exists():
                return
        except tk.TclError:
            return  # window already destroyed; a queued callback must not crash

        if self.hosted_hwnd and not embed.is_alive(self.hosted_hwnd):
            self.hosted_hwnd = None
            # The controller must forget the handle too. Windows recycles handle
            # values, so a stale one here means a later stop() can post WM_CLOSE to
            # whatever unrelated window inherited the number.
            self.controller.set_hosted_window(None)
            # The hosted WINDOW is gone. That is not the same fact as the browser
            # having closed: a session whose window was reparented or replaced is
            # still running, still under policy, and still holding a profile.
            #
            # But is_running() is a ~258ms PowerShell snapshot, and on an ordinary
            # close it is taken while Edge is still tearing down, so it will often
            # still see processes. Reporting "still open and still protected" and
            # then never asking again would latch exactly the kind of false
            # reassurance this branch exists to avoid, so KEEP POLLING either way and
            # let the message correct itself.
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

        # No hosted window, but the poller is still alive: settle the message once the
        # teardown snapshot is trustworthy rather than leaving the transient one up.
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
        """The panic key fired. Stop this session's browser at once.

        ONE-SHOT. A held or repeated key press must not start a second teardown while
        the first is still running - two concurrent destroy() passes over the same
        profile would race each other and produce a report neither of them can stand
        behind.

        No confirmation, and no download-export prompt. Panic means panic, and this is
        the one path that knowingly destroys a disposable session's unexported
        quarantine. That is stated where the key is documented, not sprung afterwards.
        """
        if self._panic_fired:
            return
        self._panic_fired = True

        # Detach first: the input queues are shared with a browser thread that is about
        # to be terminated, and leaving them joined is how bruhswer's own window hangs.
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
        # Release the shared input queue FIRST, before any dialog. Leaving bruhswer's
        # focus state tied to a browser thread that is about to die is how you get a
        # hung window on exit - and the confirmation below is a modal Tk dialog with
        # a grab, which is precisely the kind of thing that must not run while two
        # GUI threads share an input queue.
        embed.detach_input()

        # Closing the window destroys a disposable session's downloads too, so the
        # user gets the same chance to export them first. Cancelling leaves bruhswer
        # open, which is the safe direction to fail - but it has to hand keyboard
        # input back to the browser on the way out.
        if not self._confirm_disposable_downloads():
            self._reattach_input()
            self.set_status("Still open. Export your downloads, then close again.")
            return

        # Mark closing BEFORE anything else, so a drain callback already queued for
        # this instant returns immediately instead of touching widgets that are about
        # to be destroyed.
        self._closing = True
        self._stop_reverification()

        # Cancel EVERY poller, or Tk complains about a queued callback firing against
        # a destroyed interpreter. This used to cancel _watch_job alone and leave the
        # hosting and repaint timers armed.
        self._cancel_all_jobs()

        if self.controller.is_running():
            # Painted BEFORE the blocking stop() call below - see open_session for
            # why. Without this the window closing looked identical to it hanging,
            # for as long as ~22s worst case.
            self._show_curtain("Closing bruhswer...", config.FG_DIM)
            self.root.update_idletasks()
            ok, message = self.controller.stop()
            if not ok:
                # Do not claim a clean exit that did not happen (SS34).
                dialogs.cleanup_incomplete(self.root, message, self.root.destroy)
                return
        self.root.destroy()

    def _reattach_input(self) -> None:
        """Give keyboard input back to the hosted browser after a cancelled close.

        Needed because the confirmation dialog is shown AFTER detach_input(). If the
        user chooses to keep the session, bruhswer must put the shared input queue
        back or they are returned to a browser window that renders fine and swallows
        every keystroke - the exact defect that AttachThreadInput was added to fix.
        """
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
        # detach BEFORE the modal dialog, re-attach if the user backs out. Same
        # reasoning as on_close.
        embed.detach_input()
        if not self._confirm_disposable_downloads():
            self._reattach_input()
            self.set_status("Session left open.")
            return
        # No session means nothing to re-verify. Left running, the worker would keep
        # spawning 14 helper processes a minute against a profile that has just been
        # deleted, and every result would be discarded as stale anyway.
        self._stop_reverification()

        # Painted BEFORE the blocking stop() call below - see open_session for why.
        self._show_curtain("Closing session...", config.FG_DIM)
        self.root.update_idletasks()

        ok, message = self.controller.stop()
        self.hosted_hwnd = None
        self._show_curtain(message, config.OK_GREEN if ok else config.BAD_RED,
                           [("New session", self._new_persistent)])
        self.update_session_badge()
        self.set_status(message)
