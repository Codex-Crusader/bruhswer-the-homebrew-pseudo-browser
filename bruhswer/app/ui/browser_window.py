"""The bruhswer browser window: a hosted Edge window inside bruhswer's frame.

Presentation only; every security decision belongs to the guards. A light is green
only if a check returned PASS. LOCALHOST is always amber (NOT ENFORCEABLE).
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


class BrowserWindow(SessionLifecycleMixin, VerificationUIMixin):
    def __init__(self) -> None:
        self.controller = ctrl.Controller()
        self.result: verifier.VerificationResult | None = None
        self.hosted_hwnd: int | None = None
        self._host_attempts = 0
        self._watch_job: str | None = None
        self._placeholder = True

        # Re-verification runs on the worker thread; this window only drains its queue.
        self._verifier = VerifyWorker()
        self._drain_job: str | None = None
        self._closing = False
        # Two overlapping startup() calls would race each other's stop()/start().
        self._verify_in_flight = False
        # check_ids in the current regression warning, to withdraw it on recovery.
        self._warned_ids: set[str] = set()
        self._applied_verification_id = 0

        self._panic_hotkey = panic_key.PanicHotkey()
        self._panic_fired = False
        # Every pending `after` id, so teardown cancels all of them, not one of six.
        self._jobs: set[str] = set()

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
        self.light_labels: dict[str, tk.Label] = {}

        # Before _build(): widgets read their colours once. The dark palette fails WCAG
        # AA, so Windows high contrast wins.
        self.high_contrast = embed.high_contrast()
        if self.high_contrast:
            config.apply_high_contrast()
        elif embed.prefers_dark() is False:
            config.apply_light()
        chrome.refresh_palette()

        self.root = tk.Tk()
        self.root.title(f"{config.MOAI} {config.APP_NAME}")
        self.root.configure(bg=config.BG_DARK)
        self.root.geometry(self._opening_geometry(1280, 860))
        self.root.minsize(900, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build()
        # Cancel timers however the root is destroyed, not only through on_close().
        self.root.bind("<Destroy>", self._on_destroy)
        self._after(120, self.startup)

    def _after(self, delay_ms: int, callback):
        """Schedule a Tk callback and track its id until it runs, so teardown can cancel
        it. A finished job removes its own id; `_jobs` once grew ~19,000 entries/hour."""
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
        """Cancel timers when the ROOT is destroyed. <Destroy> also fires per child."""
        if event is not None and event.widget is not self.root:
            return
        self._closing = True
        self._cancel_all_jobs()

    @staticmethod
    def _opening_geometry(want_w: int, want_h: int) -> str:
        """Fit the window inside the work area. A fixed 1280x860 hid the status bar
        under the taskbar (measured at 1920x1080, 125%)."""
        left, top, area_w, area_h = embed.work_area()
        chrome_h, chrome_w = 47, 18
        w = max(900, min(want_w, area_w - chrome_w))
        h = max(600, min(want_h, area_h - chrome_h))
        x = left + max(0, (area_w - w - chrome_w) // 2)
        y = top + max(0, (area_h - h - chrome_h) // 2)
        return f"{w}x{h}+{x}+{y}"


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

        # Opens a NEW tab. Navigating an existing tab would need a control channel into
        # the browser, which bruhswer refuses to have.
        tk.Label(bar, text="OPEN IN NEW TAB", font=("Consolas", 8, "bold"),
                 bg=config.BG_PANEL, fg=config.FG_DIM).pack(side="left", padx=(12, 8))

        # Padded frame: tk.Entry has no text inset.
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
        # With attached input queues, a click alone does not take focus back.
        self.address.bind("<Button-1>", self._focus_address)

        for text, cmd in (("Open", self.on_navigate), ("Blank tab", self.on_new_tab)):
            tk.Button(bar, text=text, font=("Segoe UI", 10), bd=0, padx=14, pady=6,
                      bg=config.BG_RAISED, fg=config.BRAND_WHITE, cursor="hand2",
                      activebackground=config.BG_RAISED,
                      command=cmd).pack(side="left", padx=(0, 8), pady=8)

        # Regression banner. Stays up while a control is still failing, even after
        # "Keep browsing" dismisses the curtain.
        self.regression_banner = tk.Frame(self.root, bg=config.BAD_RED)
        self.regression_text = tk.Label(
            self.regression_banner, text="", font=("Segoe UI", 10, "bold"), anchor="w",
            justify="left", wraplength=820, bg=config.BAD_RED, fg="#FFFFFF")
        self.regression_text.pack(side="left", padx=(12, 8), pady=8)
        tk.Button(self.regression_banner, text="What changed",
                  font=("Segoe UI", 9), bd=0, padx=12, pady=4,
                  bg=config.BG_PANEL, fg=config.BRAND_WHITE, cursor="hand2",
                  command=self.open_security_panel).pack(side="right", padx=12, pady=8)

        # Account banner, shown only while a measurement finds an attached account.
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

        self.stage = tk.Frame(self.root, bg="#000000")
        self.stage.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.stage.bind("<Configure>", self._fit_hosted)
        # A click on the page area gives keyboard focus back to the browser.
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

        # Panic key state is permanent chrome, not a status line that gets overwritten.
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


    def _show_curtain(self, message: str, colour: str,
                      actions: list | None = None) -> None:
        """Cover the stage with a message and buttons for the next action."""
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

        # The banner stays until a later pass finds no account.

    def set_status(self, text: str) -> None:
        self.status_text.config(text=text[:110])


    def on_navigate(self) -> None:
        text = self.address.get().strip()
        if self._placeholder or not text:
            return
        ok, message = self.controller.navigate(text)
        self.set_status(message)
        if not ok:
            self.address.select_range(0, "end")

    def on_new_tab(self) -> None:
        _opened, message = self.controller.new_tab()
        self.set_status(message)


    def _panel(self, title: str, width: int = 900, height: int = 660) -> tk.Frame:
        return chrome.scroll_panel(self.root, title, width, height)

    def open_security_panel(self) -> None:
        """Show the checks panel. The pass runs off the Tk thread."""
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
