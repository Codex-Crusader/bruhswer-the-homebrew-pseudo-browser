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

import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from .. import config
from ..browser import embed
from ..controller import controller as ctrl
from ..downloads import quarantine
from ..security import verifier
from ..sessions import session_manager
from . import panic_key
from .session_lifecycle import SessionLifecycleMixin
from .verification_ui import VerificationUIMixin
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


class BrowserWindow(SessionLifecycleMixin, VerificationUIMixin):
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

        # Runtime re-verification. The worker does the 14 helper processes on its own
        # thread; this window only ever drains its queue. See ui/verify_worker.py for
        # why none of that may happen on the Tk thread.
        self._verifier = VerifyWorker()
        self._drain_job: str | None = None
        self._closing = False
        # One-shot verification (startup, BRUH CHECK) used to be synchronous, which
        # accidentally serialised repeat clicks by freezing the window for their
        # duration. Now that it does not freeze the window, a second click while the
        # first pass is still running must be refused explicitly, or two overlapping
        # startup() calls can each decide to open a session and race each other's
        # controller.stop()/start(). See _verify_async.
        self._verify_in_flight = False
        # check_ids currently named in a regression warning, so the warning can be
        # withdrawn once every one of them verifies again.
        self._warned_ids: set[str] = set()
        self._applied_verification_id = 0

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
        self.regression_banner: tk.Frame
        self.regression_text: tk.Label
        self.panic_hint: tk.Label
        self.lights: dict[str, tk.Label] = {}
        # The word beside each dot, so a count can be appended to it.
        self.light_labels: dict[str, tk.Label] = {}

        # BEFORE _build(), because every widget reads its colours from config once, at
        # construction. bruhswer's palette is a fixed dark theme whose amber and green
        # do not clear WCAG AA on black; under high contrast that makes the status
        # lights - the whole product - hard to read for the user who most needs them.
        # High contrast wins: it is an accessibility requirement, not a preference.
        self.high_contrast = embed.high_contrast()
        if self.high_contrast:
            config.apply_high_contrast()
        elif embed.prefers_dark() is False:
            config.apply_light()

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

        `_jobs` used to only ever grow: nothing removed a completed job's id, so
        `_watch` and `_drain` - both self-rescheduling for the life of the session -
        added roughly 19,000 dead entries per hour. `_cancel_all_jobs` then had to walk
        every one of them at teardown, calling `after_cancel` on ids Tk had long since
        discarded. The callback is wrapped so a completed job removes its own id before
        the caller's code runs, whether or not it reschedules a new one.
        """
        job_id: list[str] = []

        def _run_and_forget() -> None:
            if job_id:
                self._jobs.discard(job_id[0])
            callback()

        job = self.root.after(delay_ms, _run_and_forget)
        job_id.append(job)
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

        # Regression banner. Stays up for as long as a control that verified at launch
        # still does not, INCLUDING after the user dismisses the curtain with "Keep
        # browsing" - which used to erase every trace of the warning and leave them
        # browsing a degraded session with a clean-looking window.
        self.regression_banner = tk.Frame(self.root, bg=config.BAD_RED)
        self.regression_text = tk.Label(
            self.regression_banner, text="", font=("Segoe UI", 10, "bold"), anchor="w",
            justify="left", wraplength=820, bg=config.BAD_RED, fg="#FFFFFF")
        self.regression_text.pack(side="left", padx=(12, 8), pady=8)
        tk.Button(self.regression_banner, text="What changed",
                  font=("Segoe UI", 9), bd=0, padx=12, pady=4,
                  bg=config.BG_PANEL, fg=config.BRAND_WHITE, cursor="hand2",
                  command=self.open_security_panel).pack(side="right", padx=12, pady=8)

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
            dot = tk.Label(cell, text=config.SHAPE_UNKNOWN, font=("Segoe UI", 10),
                           bg=config.BG_PANEL, fg=config.OFF_GREY)
            dot.pack(side="left", padx=(0, 5))
            name = tk.Label(cell, text=key, font=("Consolas", 9), bg=config.BG_PANEL,
                            fg=config.BRAND_WHITE)
            name.pack(side="left")
            self.lights[key] = dot
            self.light_labels[key] = name

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

    def _hide_curtain(self) -> None:
        self.curtain.place_forget()
        self.curtain_actions.place_forget()

        # The banner deliberately STAYS UP. It is removed only when a later
        # verification pass actually re-reads the profile and finds no account -
        # never on the strength of having opened a page the user may not have used.

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

    # ------------------------------------------------------------------ panels

    def _panel(self, title: str, width: int = 640, height: int = 620) -> tk.Frame:
        return chrome.scroll_panel(self.root, title, width, height)

    def open_security_panel(self) -> None:
        """A menu item, not a launch gate - but the same 5.5s pass ran synchronously
        here too, freezing the whole window on a click nobody expected to block."""
        session = self.controller.snapshot()
        mode = session.mode if session.active else session_manager.PERSISTENT
        self.set_status("Running security verification...")
        self._verify_async(mode, self._on_security_panel_verified)

    def _on_security_panel_verified(self, result: verifier.VerificationResult) -> None:
        self.result = result
        self.refresh_lights()
        security_panel.render(self._panel("BRUH CHECK"), self.result)

    def open_network_panel(self) -> None:
        network_panel.render(self._panel("Network"), self.result)

    def open_privacy_panel(self) -> None:
        privacy_panel.render(self._panel("Privacy"),
                             self.controller.snapshot().profile_dir,
                             self.controller.privacy_mode)

    def open_host_panel(self) -> None:
        host_panel.render(self._panel("Host Guard"))

    def open_quarantine_panel(self) -> None:
        session = self.controller.snapshot()
        session_id = session.session_id if session.active else "preview"
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

    def run(self) -> None:
        self.update_session_badge()
        self.root.mainloop()
