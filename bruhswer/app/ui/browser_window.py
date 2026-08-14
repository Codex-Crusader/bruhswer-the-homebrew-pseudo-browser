"""The bruhswer browser window.

A real browser: a hosted Edge window with its own tabs, back/forward and reload, wrapped
in bruhswer's frame, address bar, security chrome and session lifecycle.

WHAT THIS LAYER DOES AND DOES NOT DO
    It is presentation and interaction only. Every security decision still belongs to
    SecurityVerifier, BrowserGuard, NetworkGuard, PrivacyGuard, HostGuard and
    SessionManager. This file never re-implements a check, never decides whether launch
    is allowed, and never manages a session itself (brief SS4, SS14, SS15).

    Tabs, back, forward and reload are Edge's own native controls inside the hosted
    window - not reimplementations, and not fake tabs that swap a URL in one page
    (brief SS8). bruhswer's address bar adds a second entry point that opens a real new
    tab in the running session.

HONESTY RULES BAKED INTO THIS FILE
    A status light is only green if a check actually returned PASS. LOCALHOST is
    permanently amber and reads NOT ENFORCEABLE, because Windows Firewall cannot filter
    loopback and no configuration changes that. VPN reads UNSUPPORTED. Humour never
    replaces a security fact (brief SS30).
"""

from __future__ import annotations

import queue
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from .. import config
from ..browser import embed
from ..controller import controller as ctrl
from ..downloads import quarantine
from ..privacy import privacy_guard
from ..security import verifier
from ..sessions import session_manager
from ..verdict import Verdict
from . import dialogs
from . import panic_key, verify_worker
from .verify_worker import VerifyWorker
from .panels import (
    chrome,
    host_panel,
    network_panel,
    privacy_panel,
    quarantine_panel,
    security_panel,
)

_COLOUR = chrome.COLOUR
_WORD = chrome.WORD


class BrowserWindow:
    def __init__(self) -> None:
        self.controller = ctrl.Controller()
        # ANNOTATED, not just assigned. A bare `= None` makes every static checker
        # infer the attribute's type AS None, so every later `self.result.blockers`
        # reads as an unresolved reference on NoneType - which is most of this
        # project's "unresolved reference" inspections, and it cascades into the test
        # harnesses that read `win.result.blockers` too.
        self.result: verifier.VerificationResult | None = None
        self.hosted_hwnd: int | None = None
        self._host_attempts = 0
        self._watch_job: str | None = None
        self._placeholder = True

        # Runtime re-verification. The worker does the 15 helper processes on its own
        # thread; this window only ever drains its queue. See ui/verify_worker.py for
        # why none of that may happen on the Tk thread.
        self._verifier = VerifyWorker()
        self._drain_job: str | None = None
        self._closing = False
        # check_ids currently named in a regression warning, so the warning can be
        # withdrawn once every one of them verifies again.
        self._warned_ids: set[str] = set()

        # Global panic hotkey. Owns its own listener thread; see ui/panic_key.py for
        # why a Tk-level binding cannot do this job.
        self._panic_hotkey = panic_key.PanicHotkey()
        self._panic_fired = False
        # EVERY pending `after` id. on_close() used to cancel only _watch_job, leaving
        # the _try_host / _fit_hosted / _reveal_stage / startup timers armed against a
        # root that was about to be destroyed - which is where
        #     invalid command name "..._watch"  ("after" script)
        # came from in the browser-UI suite. Cancelling one of six timers is not
        # teardown. Every schedule goes through _after() and lands in here.
        self._jobs: set[str] = set()

        # Declared here so the full set of instance state is visible in one place.
        # Annotation only, no assignment - see the note in app_ui.py.
        self.session_badge: tk.Label
        self.bruh_button: tk.Button
        self.address: tk.Entry
        self.stage: tk.Frame
        self.curtain: tk.Label
        self.curtain_actions: tk.Frame
        self.status_text: tk.Label
        self.account_banner: tk.Frame
        self.account_banner_text: tk.Label
        self.panic_hint: tk.Label
        self.lights: dict[str, tk.Label] = {}

        self.root = tk.Tk()
        self.root.title(f"{config.MOAI} {config.APP_NAME}")
        self.root.configure(bg=config.BG_DARK)
        self.root.geometry(self._opening_geometry(1280, 860))
        self.root.minsize(900, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build()
        # Cancel every pending `after` job the moment the window is destroyed, by ANY
        # route - not just through on_close().
        #
        # OBSERVED, in the browser-UI suite's relaunch step:
        #     invalid command name "2436724324992_watch"  ("after" script)
        # A queued callback was dispatched after the interpreter had gone. on_close()
        # cancels the jobs, but anything that calls root.destroy() directly - a test, a
        # harness, a fatal dialog path - skips that and leaves them armed. The guards
        # inside _watch/_drain cannot help: Tk fails to dispatch before any Python in
        # them runs.
        #
        # It printed a Tk error without failing anything, which is the worst kind of
        # noise: it trains the reader to skip errors in this suite's output.
        self.root.bind("<Destroy>", self._on_destroy)
        self._after(120, self.startup)

    def _after(self, delay_ms: int, callback):
        """Schedule a Tk callback AND remember it, so teardown can cancel it.

        Returns the job id, so the few callers that also track a job in a named
        attribute (_watch_job, _drain_job) keep working unchanged.
        """
        job = self.root.after(delay_ms, callback)
        self._jobs.add(job)
        return job

    def _cancel_all_jobs(self) -> None:
        """Cancel every pending timer. Idempotent, and never raises."""
        for job in list(self._jobs):
            try:
                self.root.after_cancel(job)
            except (tk.TclError, ValueError):
                pass
        self._jobs.clear()
        self._watch_job = None
        self._drain_job = None

    def _on_destroy(self, event=None) -> None:
        """Tear down timers when the ROOT goes away. Idempotent and never raises.

        <Destroy> propagates from every child widget, so this fires many times during
        teardown; only the root's own event matters.
        """
        if event is not None and event.widget is not self.root:
            return
        self._closing = True
        self._cancel_all_jobs()

    @staticmethod
    def _opening_geometry(want_w: int, want_h: int) -> str:
        """Fit the window inside the taskbar-free work area, and place it there.

        A fixed 1280x860 became a 907px window whose bottom sat at the screen edge, so
        the status bar - the six verdict lights, the whole point of the product - was
        rendered underneath the taskbar and could not be seen at all. Measured on
        1920x1080 at 125%: 60px of overhang against a 43px status bar.
        """
        left, top, area_w, area_h = embed.work_area()
        # Leave room for the title bar and borders the frame adds around the content.
        chrome_h, chrome_w = 47, 18
        w = max(900, min(want_w, area_w - chrome_w))
        h = max(600, min(want_h, area_h - chrome_h))
        x = left + max(0, (area_w - w - chrome_w) // 2)
        y = top + max(0, (area_h - h - chrome_h) // 2)
        return f"{w}x{h}+{x}+{y}"

    # ------------------------------------------------------------------ layout

    def _build(self) -> None:
        head = tk.Frame(self.root, bg=config.BG_DARK)
        head.pack(fill="x", padx=12, pady=(10, 4))

        mark = tk.Frame(head, bg=config.BG_DARK)
        mark.pack(side="left")
        tk.Label(mark, text=config.MOAI, font=("Segoe UI Emoji", 18),
                 bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left", padx=(0, 8))
        tk.Label(mark, text=config.WORDMARK_HEAD, font=("Segoe UI", 18, "bold"),
                 bg=config.BG_DARK, fg=config.BRAND_YELLOW).pack(side="left")
        tk.Label(mark, text=config.WORDMARK_TAIL, font=("Segoe UI", 18, "bold"),
                 bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left")

        self.session_badge = tk.Label(head, text="", font=("Consolas", 10, "bold"),
                                      bg=config.BG_DARK, fg=config.FG_DIM)
        self.session_badge.pack(side="left", padx=16)

        self.bruh_button = tk.Button(
            head, text="BRUH", font=("Consolas", 10, "bold"), bd=0, padx=14, pady=5,
            bg=config.BG_RAISED, fg=config.FG_DIM, cursor="hand2",
            activebackground=config.BG_RAISED, command=self.open_security_panel)
        self.bruh_button.pack(side="right")

        tk.Button(head, text="☰", font=("Segoe UI", 12), bd=0, padx=12, pady=3,
                  bg=config.BG_RAISED, fg=config.BRAND_WHITE, cursor="hand2",
                  activebackground=config.BG_RAISED,
                  command=self.open_menu).pack(side="right", padx=6)

        bar = tk.Frame(self.root, bg=config.BG_PANEL)
        bar.pack(fill="x", padx=12, pady=(0, 6))

        # NOT a second address bar. The browser below has a real one that navigates
        # within a tab; duplicating it would be redundant and slightly dishonest,
        # because this field cannot navigate an existing tab - doing that would need a
        # control channel into the browser, and Stage 4 measured that a compromised
        # browser can reach localhost, so bruhswer refuses to have one (SS25).
        #
        # What it CAN do, safely, is hand a URL to the running session as a new tab
        # using a fixed argv. So it is labelled as exactly that.
        tk.Label(bar, text="OPEN IN NEW TAB", font=("Consolas", 8, "bold"),
                 bg=config.BG_PANEL, fg=config.FG_DIM).pack(side="left", padx=(12, 8))

        # The Entry sits inside a padded frame because tk.Entry has no text inset, so
        # the caret and the placeholder rendered flush against the field's edge.
        field = tk.Frame(bar, bg=config.BG_RAISED)
        field.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=8)
        self.address = tk.Entry(field, font=("Segoe UI", 11), bd=0,
                                bg=config.BG_RAISED, fg=config.BRAND_WHITE,
                                insertbackground=config.BRAND_YELLOW,
                                relief="flat")
        self.address.pack(fill="x", expand=True, padx=10, pady=6)
        self.address.bind("<Return>", lambda e: self.on_navigate())
        self.address.insert(0, "Search, or type a web address")
        self.address.bind("<FocusIn>", self.clear_placeholder)
        # Clicking here must actively TAKE focus back from the hosted browser. With the
        # input queues attached, a click alone does not move focus, which is why this
        # field only worked some of the time.
        self.address.bind("<Button-1>", self._focus_address)

        for text, cmd in (("Open", self.on_navigate), ("Blank tab", self.on_new_tab)):
            tk.Button(bar, text=text, font=("Segoe UI", 10), bd=0, padx=14, pady=6,
                      bg=config.BG_RAISED, fg=config.BRAND_WHITE, cursor="hand2",
                      activebackground=config.BG_RAISED,
                      command=cmd).pack(side="left", padx=(0, 8), pady=8)

        # Account banner. Packed only when a live measurement says an account is
        # attached; see _refresh_account_banner for why this is state-driven and not
        # wired to the regression path.
        self.account_banner = tk.Frame(self.root, bg=config.BG_RAISED)
        self.account_banner_text = tk.Label(
            self.account_banner, text="", font=("Segoe UI", 9), anchor="w",
            justify="left", wraplength=820,
            bg=config.BG_RAISED, fg=config.WARN_AMBER)
        self.account_banner_text.pack(side="left", padx=(12, 8), pady=8)
        tk.Button(self.account_banner, text="Open Edge settings to sign out",
                  font=("Segoe UI", 9), bd=0, padx=12, pady=4,
                  bg=config.BG_PANEL, fg=config.BRAND_WHITE, cursor="hand2",
                  activebackground=config.BRAND_YELLOW, activeforeground="#111111",
                  command=self.on_open_account_settings).pack(
            side="right", padx=12, pady=8)

        # Where the real Edge window gets hosted.
        self.stage = tk.Frame(self.root, bg="#000000")
        self.stage.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.stage.bind("<Configure>", self._fit_hosted)
        # Clicking anywhere on the page area hands keyboard focus back to the browser.
        # Tk will happily keep focus on its own address bar otherwise, and the user
        # ends up typing into a widget that is not the page.
        self.stage.bind("<Button-1>", self._focus_browser)
        self.root.bind("<FocusIn>", self._focus_browser)

        self.curtain = tk.Label(
            self.stage, text=f"{config.MOAI}\n\nBRUH CHECK\n\nChecking whether this "
                             f"website can touch your stuff...",
            font=("Consolas", 12), bg="#000000", fg=config.FG_DIM, justify="center")
        self.curtain.place(relx=0.5, rely=0.5, anchor="center")
        self.curtain_actions = tk.Frame(self.stage, bg="#000000")

        status = tk.Frame(self.root, bg=config.BG_PANEL)
        status.pack(fill="x", side="bottom")
        for key in ("HOST", "NETWORK", "PRIVACY", "DOWNLOADS", "LOCALHOST", "VPN",
                    "PANIC"):
            cell = tk.Frame(status, bg=config.BG_PANEL)
            cell.pack(side="left", padx=(12, 4), pady=7)
            dot = tk.Label(cell, text="●", font=("Segoe UI", 10),
                           bg=config.BG_PANEL, fg=config.OFF_GREY)
            dot.pack(side="left", padx=(0, 5))
            tk.Label(cell, text=key, font=("Consolas", 9), bg=config.BG_PANEL,
                     fg=config.BRAND_WHITE).pack(side="left")
            self.lights[key] = dot

        # The panic key's state is PERMANENT chrome, not a status message. It must
        # still be readable at the moment the user reaches for it, which is long after
        # any transient line has been overwritten.
        self.panic_hint = tk.Label(status, text="", font=("Consolas", 8),
                                   bg=config.BG_PANEL, fg=config.FG_DIM)
        self.panic_hint.pack(side="left", padx=(0, 10))

        self.status_text = tk.Label(status, text="", font=("Segoe UI", 9),
                                    bg=config.BG_PANEL, fg=config.FG_DIM, anchor="e")
        self.status_text.pack(side="right", padx=14)

    def clear_placeholder(self, _event=None) -> None:
        if self._placeholder:
            self.address.delete(0, "end")
            self._placeholder = False

    # ----------------------------------------------------------------- startup

    def startup(self) -> None:
        """Verify first. The browser only appears if the checks allow it (SS9)."""
        # Armed BEFORE verification, so a blocked launch - the state where an escape
        # hatch matters most - still shows the panic key's true state.
        self._arm_panic_key()
        self.set_status("Running security verification...")
        self.result = self.controller.verify(session_manager.PERSISTENT)
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

        # Unconditionally, not "if is_running()". After the browser window closed on
        # its own, is_running() is False while a disposable session's profile and
        # quarantine are still on disk - so the old guard skipped the teardown the user
        # had just confirmed. stop() early-returns on a None session, so this is safe.
        _stopped, message = self.controller.stop()
        if message:
            self.set_status(message)
        self.hosted_hwnd = None
        self._host_attempts = 0

        self._show_curtain(f"Starting {mode} session...", config.FG_DIM)
        self.root.update_idletasks()

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
        if hwnd and not embed.is_paint_ready(hwnd) and self._host_attempts < 25:
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
                # Size it immediately, then again once Tk has settled the frame -
                # Chromium sizes its compositor from the first WM_SIZE it receives, and
                # a stale size is what leaves the page looking half-rendered.
                #
                # The curtain stays UP through all of this. It used to come down the
                # instant the reparent succeeded, so the user watched Chromium resize
                # and repaint itself for the next 900ms - bruhswer's frame appearing
                # first and the page popping in after it. Now the stage is revealed
                # once, onto a page that has already settled.
                self._fit_hosted()
                self._after(200, self._fit_hosted)
                self._after(900, self._fit_hosted)
                # AFTER the last fit, not before it. Revealing at 260ms left 640ms of
                # Chromium repainting visible - the exact thing this was meant to stop,
                # while a comment claimed the page had already settled.
                self._after(950, self._reveal_stage)
                self._watch_job = self._after(1500, self._watch)
                return

        if self._host_attempts < 25:
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

    # ----------------------------------------------------------------- curtain

    def _show_curtain(self, message: str, colour: str,
                      actions: list | None = None) -> None:
        """Cover the stage with a message, and offer the action it implies.

        Every one of these states used to end in "use the menu", which asks the user
        to go and find a thing when the window already knows what they need next.
        """
        self.curtain.config(text=f"{config.MOAI}\n\n{message}", fg=colour)
        self.curtain.place(relx=0.5, rely=0.5, anchor="center")
        self.curtain.lift()
        for child in self.curtain_actions.winfo_children():
            child.destroy()
        for label, command in (actions or []):
            tk.Button(self.curtain_actions, text=label, font=("Segoe UI", 10), bd=0,
                      padx=18, pady=7, bg=config.BG_RAISED, fg=config.BRAND_WHITE,
                      cursor="hand2", activebackground=config.BRAND_YELLOW,
                      activeforeground="#111111",
                      command=command).pack(side="left", padx=7)
        if actions:
            self.curtain_actions.place(relx=0.5, rely=0.5, anchor="n", y=90)
            self.curtain_actions.lift()
        else:
            self.curtain_actions.place_forget()

    def _reveal_stage(self) -> None:
        """Drop the curtain onto a page that has already been sized and painted."""
        if not self.hosted_hwnd or not embed.is_alive(self.hosted_hwnd):
            return          # it went away while settling; _watch will report it
        self._hide_curtain()
        self.set_status("WE GOOD")

    def _hide_curtain(self) -> None:
        self.curtain.place_forget()
        self.curtain_actions.place_forget()

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
        """Send keyboard focus to the hosted page, unless the user is in the address bar."""
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
            clean = title.replace(" - Microsoft Edge", "").replace(
                " - Microsoft Edge", "")
            self.status_text.config(text=clean[:90])
        self._watch_job = self._after(1500, self._watch)

    # ------------------------------------------- runtime re-verification

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

    def _start_reverification(self) -> None:
        """Begin (or re-aim) the background re-verification for the current session."""
        self._arm_panic_key()
        self._verifier.start()
        self._verifier.submit(self.controller.verification_request(
            self.controller.session.mode if self.controller.session
            else session_manager.PERSISTENT))
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
        session = self.controller.session
        checks = [c for c in self.result.checks if c.check_id == "privacy.account"]
        if not checks or session is None:
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
        # The banner deliberately STAYS UP. It is removed only when a later
        # verification pass actually re-reads the profile and finds no account -
        # never on the strength of having opened a page the user may not have used.

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
        if self._warned_ids:
            return          # some are still not verifying; the warning stands
        self._hide_curtain()
        self.set_status("Controls are verifying again.")

    def _warn_regressions(self, regressions: tuple[tuple[str, str], ...]) -> None:
        """A control that was verified at launch no longer verifies.

        bruhswer WARNS; it does not close the session by itself. That is deliberate.
        A verification pass can go non-PASS because a PowerShell query timed out under
        load, and auto-killing the browser on a measurement error would destroy a
        disposable session's unexported downloads over a transient. The user is told
        precisely what changed and given the action; the decision stays theirs.
        """
        self._warned_ids |= {check_id for check_id, _title in regressions}
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
            self._drain_job = None
        self._verifier.stop()
        self._panic_hotkey.stop()

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

    # ------------------------------------------------------------------ status

    def refresh_lights(self) -> None:
        if self.result is None:
            return
        mapping = {"HOST": "host.", "NETWORK": "net.", "PRIVACY": "privacy.",
                   "DOWNLOADS": "downloads."}
        for key, prefix in mapping.items():
            checks = self.result.by_prefix(prefix)
            if not checks:
                self.lights[key].config(fg=config.OFF_GREY)
                continue
            self.lights[key].config(fg=_COLOUR[self.result.category(prefix)])

        # Never green. Measured platform limitation, stated permanently (SS21).
        self.lights["LOCALHOST"].config(fg=config.WARN_AMBER)
        self.lights["VPN"].config(fg=config.OFF_GREY)
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
        session = self.controller.session
        if session is None or not self.controller.is_running():
            self.session_badge.config(text="NO SESSION", fg=config.FG_DIM)
            return
        if session.is_disposable:
            self.session_badge.config(text="DISPOSABLE BRUH", fg=config.WARN_AMBER)
        else:
            self.session_badge.config(text="PERSISTENT BRUH", fg=config.OK_GREEN)

    def set_status(self, text: str) -> None:
        self.status_text.config(text=text[:110])

    # ----------------------------------------------------------------- actions

    def on_navigate(self) -> None:
        text = self.address.get().strip()
        if self._placeholder or not text:
            return
        ok, message = self.controller.navigate(text)
        self.set_status(message)
        if not ok:
            # Leave the text selected so a refused address can be retyped.
            self.address.select_range(0, "end")

    def on_new_tab(self) -> None:
        _opened, message = self.controller.new_tab()
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
            ok, message = self.controller.stop()
            if not ok:
                # Do not claim a clean exit that did not happen (SS34).
                dialogs.cleanup_incomplete(self.root, message, self.root.destroy)
                return
        self.root.destroy()

    # ------------------------------------------------------------------ panels

    def _panel(self, title: str, width: int = 640, height: int = 620) -> tk.Frame:
        return chrome.scroll_panel(self.root, title, width, height)

    def open_security_panel(self) -> None:
        self.result = self.controller.verify(
            self.controller.session.mode if self.controller.session
            else session_manager.PERSISTENT)
        self.refresh_lights()
        security_panel.render(self._panel("BRUH CHECK"), self.result)

    def open_network_panel(self) -> None:
        network_panel.render(self._panel("Network"), self.result)

    def open_privacy_panel(self) -> None:
        profile = (self.controller.session.profile_dir
                   if self.controller.session else config.PROFILE_PERSISTENT)
        privacy_panel.render(self._panel("Privacy"), profile,
                             self.controller.privacy_mode)

    def open_host_panel(self) -> None:
        host_panel.render(self._panel("Host Guard"))

    def open_quarantine_panel(self) -> None:
        session_id = (self.controller.session.session_id
                      if self.controller.session else "preview")
        quarantine_panel.render(self._panel("Quarantine", height=520), session_id,
                                self._export, self._delete)

    def _export(self, item) -> None:
        target = filedialog.askdirectory(title="Export to which folder?")
        if not target:
            return
        _exported, message = self.controller.export_request(item, Path(target))
        self.set_status(message)

    def _delete(self, item) -> None:
        _deleted, message = quarantine.delete(item)
        self.set_status(message)

    def open_menu(self) -> None:
        menu = tk.Menu(self.root, tearoff=0, bg=config.BG_RAISED,
                       fg=config.BRAND_WHITE, activebackground=config.BRAND_YELLOW,
                       activeforeground="#111111", bd=0)
        menu.add_command(label="New persistent session",
                         command=lambda: self.open_session(session_manager.PERSISTENT))
        menu.add_command(label="New disposable session",
                         command=lambda: self.open_session(session_manager.DISPOSABLE))
        menu.add_separator()
        menu.add_command(label="BRUH check", command=self.open_security_panel)
        menu.add_command(label="Network", command=self.open_network_panel)
        menu.add_command(label="Privacy", command=self.open_privacy_panel)
        menu.add_command(label="Host Guard", command=self.open_host_panel)
        menu.add_command(label="Quarantine", command=self.open_quarantine_panel)
        menu.add_separator()
        menu.add_command(label="Close session", command=self.close_session)
        try:
            menu.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())
        finally:
            menu.grab_release()

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
        session = self.controller.session
        if session is None or not session.is_disposable:
            return True
        pending = session_manager.pending_quarantine(session)
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
        # spawning 15 helper processes a minute against a profile that has just been
        # deleted, and every result would be discarded as stale anyway.
        self._stop_reverification()
        ok, message = self.controller.stop()
        self.hosted_hwnd = None
        self._show_curtain(message, config.OK_GREEN if ok else config.BAD_RED,
                           [("New session", self._new_persistent)])
        self.update_session_badge()
        self.set_status(message)

    def run(self) -> None:
        self.update_session_badge()
        self.root.mainloop()
