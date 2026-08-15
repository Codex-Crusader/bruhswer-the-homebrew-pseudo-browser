"""bruhswer control panel — tkinter, standard library only.

Design rules taken from the brief:
  SS6   the browser feels normal; the personality lives in labels and messages
  SS7   status labels represent real measured state, never intentions
  SS44  security and privacy are shown separately and never conflated
  SS66  no dark patterns: nothing hides a protection or makes "turn it off" the big button

The humour is in the wording. The verdicts are not. A control that was not verified is
never coloured green, whatever it would do to the joke.
"""

from __future__ import annotations

import functools
import tkinter as tk
from tkinter import filedialog, ttk

from .. import config
from ..controller import controller as ctrl
from ..downloads import quarantine
from ..host import host_guard
from ..network import network_guard
from ..privacy import privacy_guard
from ..security import verifier
from ..sessions import session_manager
from .panels import chrome, network_panel

# Derived from panels.chrome, never restated: this module used to keep its own copy and
# could drift from the browser window.
_DOT = {verdict: ("●", colour) for verdict, colour in chrome.COLOUR.items()}
_WORD = chrome.WORD


class BruhswerUI:
    def __init__(self) -> None:
        self.controller = ctrl.Controller()
        self.root = tk.Tk()
        self.root.title(f"{config.MOAI} {config.APP_NAME}")
        self.root.configure(bg=config.BG_DARK)
        self.root.geometry("880x720")
        self.root.minsize(760, 620)
        # Annotated for the same reason as BrowserWindow.result - see the note there.
        self._result: verifier.VerificationResult | None = None

        # Declared here so the whole of this window's state is visible in one place.
        # Annotation only, no assignment: that registers the attribute without
        # widening its type to include None, which would make every later use of it
        # an Optional-access warning.
        self.tab_status: tk.Frame
        self.tab_network: tk.Frame
        self.tab_host: tk.Frame
        self.tab_privacy: tk.Frame
        self.tab_downloads: tk.Frame
        self.mode_var: tk.StringVar
        self.status_line: tk.Label
        self.btn_stop: tk.Button
        self.btn_launch: tk.Button
        self.status_body: tk.Frame
        self.host_body: tk.Frame
        self.downloads_body: tk.Frame

        self._build()
        self.refresh()

    @property
    def _checked(self) -> verifier.VerificationResult:
        """The current verification result, which every render path requires.

        refresh() sets `_result` before any render runs, so this precondition already
        held - it was just implicit, which left every `self._checked.checks` reading as
        an attribute access on None to any checker. Raising here states the contract
        instead of hiding it behind an AttributeError.
        """
        result = self._result
        if result is None:
            raise RuntimeError("render called before refresh(): no result yet")
        return result

    # --- construction -----------------------------------------------------------

    def _build(self) -> None:
        self._build_header()
        notebook = ttk.Notebook(self.root)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=config.BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=config.BG_PANEL,
                        foreground=config.BRAND_WHITE, padding=(16, 8), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", config.BG_RAISED)],
                  foreground=[("selected", config.BRAND_YELLOW)])
        notebook.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        self.tab_status = self._tab(notebook, "BRUH CHECK")
        self.tab_network = self._tab(notebook, "Network")
        self.tab_host = self._tab(notebook, "Host Guard")
        self.tab_privacy = self._tab(notebook, "Privacy")
        self.tab_downloads = self._tab(notebook, "Quarantine")

        self._build_status_tab()
        self._build_network_tab()
        self._build_host_tab()
        self._build_privacy_tab()
        self._build_downloads_tab()
        self._build_footer()

    @staticmethod
    def _tab(notebook: ttk.Notebook, label: str) -> tk.Frame:
        frame = tk.Frame(notebook, bg=config.BG_DARK)
        notebook.add(frame, text=label)
        return frame

    def _build_header(self) -> None:
        head = tk.Frame(self.root, bg=config.BG_DARK)
        head.pack(fill="x", padx=18, pady=(16, 6))

        wordmark = tk.Frame(head, bg=config.BG_DARK)
        wordmark.pack(side="left")
        tk.Label(wordmark, text=config.MOAI, font=("Segoe UI Emoji", 26),
                 bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left", padx=(0, 10))
        # Wordmark: "bruh" yellow + "swer" white, one word, one line (SS33).
        tk.Label(wordmark, text=config.WORDMARK_HEAD, font=("Segoe UI", 26, "bold"),
                 bg=config.BG_DARK, fg=config.BRAND_YELLOW).pack(side="left")
        tk.Label(wordmark, text=config.WORDMARK_TAIL, font=("Segoe UI", 26, "bold"),
                 bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left")

        tk.Label(head, text=config.TAGLINE, font=("Segoe UI", 10),
                 bg=config.BG_DARK, fg=config.FG_DIM).pack(
        side="left", padx=16, pady=(14, 0))

        controls = tk.Frame(head, bg=config.BG_DARK)
        controls.pack(side="right")
        self.mode_var = tk.StringVar(value=session_manager.PERSISTENT)
        for text, value in (("Private", session_manager.PERSISTENT),
                            ("Disposable", session_manager.DISPOSABLE)):
            tk.Radiobutton(controls, text=text, value=value, variable=self.mode_var,
                           bg=config.BG_DARK, fg=config.BRAND_WHITE,
                           selectcolor=config.BG_PANEL,
                           activebackground=config.BG_DARK,
                           activeforeground=config.BRAND_YELLOW,
                           font=("Segoe UI", 9), bd=0,
                           highlightthickness=0).pack(side="left", padx=4)

    def _build_footer(self) -> None:
        foot = tk.Frame(self.root, bg=config.BG_PANEL)
        foot.pack(fill="x", side="bottom")
        self.status_line = tk.Label(
            foot, text="", font=("Segoe UI", 10), bg=config.BG_PANEL,
            fg=config.FG_DIM, anchor="w", padx=14, pady=10)
        self.status_line.pack(side="left", fill="x", expand=True)

        self.btn_stop = tk.Button(
            foot, text="Close session", command=self.on_stop,
            bg=config.BG_RAISED, fg=config.BRAND_WHITE, bd=0, padx=16, pady=8,
            font=("Segoe UI", 10), activebackground=config.BG_RAISED,
            activeforeground=config.BRAND_WHITE, cursor="hand2")
        self.btn_stop.pack(side="right", padx=(6, 14), pady=8)

        self.btn_launch = tk.Button(
            foot, text="Launch bruhswer", command=self.on_launch,
            bg=config.BRAND_YELLOW, fg="#111111", bd=0, padx=22, pady=8,
            font=("Segoe UI", 10, "bold"), activebackground="#E0B516",
            cursor="hand2")
        self.btn_launch.pack(side="right", pady=8)

        tk.Button(foot, text="Re-check", command=self.refresh,
                  bg=config.BG_RAISED, fg=config.BRAND_WHITE, bd=0, padx=14, pady=8,
                  font=("Segoe UI", 10), cursor="hand2").pack(
        side="right", padx=6, pady=8)

    # --- tabs -------------------------------------------------------------------

    @staticmethod
    def _scroll_area(parent: tk.Frame) -> tk.Frame:
        canvas = tk.Canvas(parent, bg=config.BG_DARK, highlightthickness=0)
        bar = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=config.BG_DARK)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(window, width=e.width))
        canvas.configure(yscrollcommand=bar.set)
        canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        return inner

    def _build_status_tab(self) -> None:
        self.status_body = self._scroll_area(self.tab_status)

    def _build_network_tab(self) -> None:
        body = self._scroll_area(self.tab_network)
        self._section(body, "What the browser may reach")
        for label, state in network_guard.policy_summary():
            row = tk.Frame(body, bg=config.BG_DARK)
            row.pack(fill="x", padx=18, pady=2)
            # The SHARED map, not a second inline copy. This dict was the other
            # half of the same defect: it also lacked the new IPv6 state, so the
            # --panel UI would have died with a KeyError building this tab.
            colour = network_panel.state_colour(state)
            tk.Label(row, text=label, font=("Segoe UI", 10), width=26, anchor="w",
                     bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left")
            tk.Label(row, text=network_panel.state_label(state),
                     font=("Consolas", 10, "bold"),
                     bg=config.BG_DARK, fg=colour).pack(side="left")

        self._note(body,
                   "NOT ENFORCEABLE is not a bug we can fix. Windows Firewall does not "
                   "filter loopback traffic, so no rule can stop the browser reaching "
                   "127.0.0.1 or this PC's own address. We measured it, we could not "
                   "beat it, and we are not going to pretend otherwise.")
        self._note(body, config.CAPTIVE_PORTAL_WARNING)
        self._section(body, "Setting up network policy")
        self._note(body,
                   "Firewall rules need Administrator once. bruhswer never elevates "
                   "itself: run tools/bruhswer-netpolicy.ps1 as administrator to apply "
                   "or remove them. It prints every change and has a full rollback.")

    def _build_host_tab(self) -> None:
        self.host_body = self._scroll_area(self.tab_host)

    def _build_privacy_tab(self) -> None:
        body = self._scroll_area(self.tab_privacy)
        self._section(body, "What bruhswer turns off, and what it costs you")
        for setting in privacy_guard.STANDARD:
            row = tk.Frame(body, bg=config.BG_PANEL)
            row.pack(fill="x", padx=18, pady=3)
            tk.Label(row, text=setting.key, font=("Consolas", 9), anchor="w",
                     bg=config.BG_PANEL, fg=config.BRAND_YELLOW).pack(
                fill="x", padx=10, pady=(6, 0))
            tk.Label(row, text=f"Reduces: {setting.reduces}", font=("Segoe UI", 9),
                     anchor="w", justify="left", wraplength=740,
                     bg=config.BG_PANEL, fg=config.BRAND_WHITE).pack(fill="x", padx=10)
            tk.Label(row,
                     text=f"Costs: {setting.costs}   |   "
                          f"Fingerprint: {setting.fingerprint_effect}",
                     font=("Segoe UI", 8), anchor="w", justify="left", wraplength=740,
                     bg=config.BG_PANEL, fg=config.FG_DIM).pack(
                fill="x", padx=10, pady=(0, 6))

        self._section(body, "Things bruhswer refuses to do")
        for name, why in privacy_guard.REJECTED:
            self._note(body, f"{name} - {why}")

    def _build_downloads_tab(self) -> None:
        self.downloads_body = self._scroll_area(self.tab_downloads)

    # --- helpers ----------------------------------------------------------------

    @staticmethod
    def _section(parent: tk.Frame, title: str) -> None:
        tk.Label(parent, text=title.upper(), font=("Segoe UI", 9, "bold"),
                 bg=config.BG_DARK, fg=config.FG_DIM, anchor="w").pack(
            fill="x", padx=18, pady=(16, 6))

    @staticmethod
    def _note(parent: tk.Frame, text: str) -> None:
        tk.Label(parent, text=text, font=("Segoe UI", 9), justify="left",
                 wraplength=780, anchor="w", bg=config.BG_DARK,
                 fg=config.FG_DIM).pack(fill="x", padx=18, pady=4)

    @staticmethod
    def _check_row(parent: tk.Frame, check) -> None:
        row = tk.Frame(parent, bg=config.BG_DARK)
        row.pack(fill="x", padx=18, pady=1)
        if not check.enforceable:
            glyph, colour, word = "●", config.BAD_RED, "NOT ENFORCEABLE"
        else:
            glyph, colour = _DOT[check.verdict]
            word = _WORD[check.verdict]
        tk.Label(row, text=glyph, font=("Segoe UI", 11), bg=config.BG_DARK,
                 fg=colour).pack(side="left", padx=(0, 8))
        tk.Label(row, text=check.title, font=("Segoe UI", 10), width=38, anchor="w",
                 bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left")
        tk.Label(row, text=word, font=("Consolas", 9, "bold"), width=16, anchor="w",
                 bg=config.BG_DARK, fg=colour).pack(side="left")
        detail = tk.Label(parent, text=check.detail, font=("Segoe UI", 8),
                          justify="left", wraplength=740, anchor="w",
                          bg=config.BG_DARK, fg=config.FG_DIM)
        detail.pack(fill="x", padx=(52, 18), pady=(0, 5))

    @staticmethod
    def _clear(frame: tk.Frame) -> None:
        for child in frame.winfo_children():
            child.destroy()

    # --- actions ----------------------------------------------------------------

    def refresh(self) -> None:
        self.status_line.config(
            text="Checking whether this website can touch your stuff...")
        self.root.update_idletasks()

        mode = self.mode_var.get()
        self._result = self.controller.verify(mode)
        self._render_status()
        self._render_host()
        self._render_downloads()

        blockers = self._checked.blockers
        if blockers:
            self.status_line.config(
                text="BRUH. NO. " + "; ".join(c.title for c in blockers),
                fg=config.BAD_RED)
            self.btn_launch.config(state="disabled", bg=config.OFF_GREY)
        else:
            self.status_line.config(text="bruhswer READY", fg=config.OK_GREEN)
            self.btn_launch.config(state="normal", bg=config.BRAND_YELLOW)

    def _render_status(self) -> None:
        body = self.status_body
        self._clear(body)

        self._section(body, "Bruh check")
        for name, verdict, blurb in ctrl.summarise(self._checked):
            row = tk.Frame(body, bg=config.BG_DARK)
            row.pack(fill="x", padx=18, pady=2)
            glyph, colour = _DOT[verdict]
            tk.Label(row, text=glyph, font=("Segoe UI", 12), bg=config.BG_DARK,
                     fg=colour).pack(side="left", padx=(0, 8))
            tk.Label(row, text=name, font=("Consolas", 10, "bold"), width=13,
                     anchor="w", bg=config.BG_DARK,
                     fg=config.BRAND_WHITE).pack(side="left")
            tk.Label(row, text=_WORD[verdict], font=("Consolas", 10), width=10,
                     anchor="w", bg=config.BG_DARK, fg=colour).pack(side="left")
            tk.Label(row, text=blurb, font=("Segoe UI", 9), anchor="w",
                     bg=config.BG_DARK, fg=config.FG_DIM).pack(side="left")

        # Statements of fact rather than verdicts. LOCALHOST lives here so the
        # limitation is on the front page, not buried in a tab (SS14, SS34).
        colours = {"ok": config.OK_GREEN, "warn": config.WARN_AMBER,
                   "off": config.OFF_GREY}
        session = self.controller.session
        for name, value, kind, blurb in ctrl.fixed_status_rows(session):
            row = tk.Frame(body, bg=config.BG_DARK)
            row.pack(fill="x", padx=18, pady=2)
            tk.Label(row, text="●", font=("Segoe UI", 12), bg=config.BG_DARK,
                     fg=colours[kind]).pack(side="left", padx=(0, 8))
            tk.Label(row, text=name, font=("Consolas", 10, "bold"), width=13,
                     anchor="w", bg=config.BG_DARK,
                     fg=config.BRAND_WHITE).pack(side="left")
            tk.Label(row, text=value, font=("Consolas", 10), width=17, anchor="w",
                     bg=config.BG_DARK, fg=colours[kind]).pack(side="left")
            tk.Label(row, text=blurb, font=("Segoe UI", 9), anchor="w",
                     justify="left", wraplength=430, bg=config.BG_DARK,
                     fg=config.FG_DIM).pack(side="left")

        self._section(body, "Security  -  can something reach my stuff")
        for check in self._checked.checks:
            if check.check_id.split(".")[0] in ("edge", "browser", "net", "controller"):
                self._check_row(body, check)

        self._section(body, "Privacy  -  what can a website learn")
        for check in self._checked.checks:
            if check.check_id.split(".")[0] in ("privacy", "dns", "downloads"):
                self._check_row(body, check)

        self._section(body, "What bruhswer is not")
        self._note(body,
                   "bruhswer is not a virtual machine and does not claim to be one. It "
                   "does not stop a browser exploit, a Windows kernel bug, or a fully "
                   "compromised PC. It reduces what a website can reach and learn, and "
                   "it refuses to start when the controls it can check are missing.")

    def _render_host(self) -> None:
        body = self.host_body
        self._clear(body)
        checks = self._checked.by_prefix("host.")

        self._section(body, "Host guard  -  what other devices on this network can reach")
        for check in checks:
            self._check_row(body, check)

        fixes = host_guard.remediations(checks)
        if not fixes:
            self._note(body, "Nothing here needs your attention right now.")
            return

        self._section(body, "Suggested fixes  -  none of these happen without you")
        for fix in fixes:
            card = tk.Frame(body, bg=config.BG_PANEL)
            card.pack(fill="x", padx=18, pady=6)
            tk.Label(card, text=fix["title"], font=("Segoe UI", 10, "bold"), anchor="w",
                     bg=config.BG_PANEL, fg=config.BRAND_YELLOW).pack(
                fill="x", padx=12, pady=(8, 2))
            for key, prefix in (("risk", "Risk"), ("change", "Change"),
                                ("rollback", "Undo")):
                tk.Label(card, text=f"{prefix}: {fix[key]}", font=("Segoe UI", 9),
                         justify="left", wraplength=720, anchor="w",
                         bg=config.BG_PANEL, fg=config.BRAND_WHITE).pack(
                    fill="x", padx=12, pady=1)
            tk.Label(card, text="Needs Administrator. Run tools/bruhswer-hostguard.ps1 "
                               "and approve the prompt; it prints every change first.",
                     font=("Segoe UI", 8), anchor="w", wraplength=720, justify="left",
                     bg=config.BG_PANEL, fg=config.FG_DIM).pack(fill="x", padx=12,
                                                                pady=(2, 10))

    def _render_downloads(self) -> None:
        body = self.downloads_body
        self._clear(body)
        session_id = (self.controller.session.session_id
                      if self.controller.session else "preview")
        items = quarantine.list_quarantine(session_id)

        self._section(body, f"{config.MOAI} Quarantine")
        self._note(body,
                   "Downloads land here instead of your Downloads folder. bruhswer does "
                   "not run them and does not scan them - it cannot tell you a file is "
                   "safe, only that it has not been let out.")
        if not items:
            self._note(body, "Nothing in quarantine.")
            return

        for item in items:
            card = tk.Frame(body, bg=config.BG_PANEL)
            card.pack(fill="x", padx=18, pady=5)
            tk.Label(card, text=item.display_name, font=("Consolas", 10), anchor="w",
                     bg=config.BG_PANEL, fg=config.BRAND_WHITE).pack(
                fill="x", padx=12, pady=(8, 0))
            note = f"{item.size:,} bytes"
            if item.is_executable_type:
                note += "   -   this is a program. It is NOT being executed."
            tk.Label(card, text=note, font=("Segoe UI", 8), anchor="w",
                     bg=config.BG_PANEL,
                     fg=config.WARN_AMBER if item.is_executable_type else config.FG_DIM
                     ).pack(fill="x", padx=12)
            buttons = tk.Frame(card, bg=config.BG_PANEL)
            buttons.pack(fill="x", padx=12, pady=8)
            tk.Button(buttons, text="Export...", bd=0, padx=12, pady=4,
                      font=("Segoe UI", 9), bg=config.BG_RAISED,
                      fg=config.BRAND_WHITE, cursor="hand2",
                      command=functools.partial(self.on_export, item)
                      ).pack(side="left")
            tk.Button(buttons, text="Delete", bd=0, padx=12, pady=4,
                      font=("Segoe UI", 9), bg=config.BG_RAISED,
                      fg=config.BRAND_WHITE, cursor="hand2",
                      command=functools.partial(self.on_delete, item)
                      ).pack(side="left", padx=6)

    def on_launch(self) -> None:
        outcome = self.controller.start(self.mode_var.get())
        self._result = outcome.result
        self._render_status()
        self._render_downloads()
        self.status_line.config(
            text=outcome.message,
            fg=config.OK_GREEN if outcome.launched else config.BAD_RED)

    def on_stop(self) -> None:
        ok, message = self.controller.stop()
        self.status_line.config(
            text=message, fg=config.OK_GREEN if ok else config.BAD_RED)
        self.refresh()

    def on_export(self, item: quarantine.QuarantinedFile) -> None:
        # The destination comes from the USER's folder picker. A webpage can never
        # reach this value (brief SS36, SS40).
        target = filedialog.askdirectory(title="Export to which folder?")
        if not target:
            return
        from pathlib import Path
        ok, message = self.controller.export_request(item, Path(target))
        self.status_line.config(
            text=message, fg=config.OK_GREEN if ok else config.BAD_RED)

    def on_delete(self, item: quarantine.QuarantinedFile) -> None:
        ok, message = quarantine.delete(item)
        self.status_line.config(
            text=message, fg=config.OK_GREEN if ok else config.BAD_RED)
        self._render_downloads()

    def run(self) -> None:
        self.root.mainloop()
