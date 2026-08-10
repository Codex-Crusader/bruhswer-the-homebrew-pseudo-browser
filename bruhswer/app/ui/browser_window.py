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
from ..sessions import session_manager
from ..verdict import Verdict
from . import dialogs
from .panels import (
    chrome,
    host_panel,
    network_panel,
    privacy_panel,
    quarantine_panel,
    security_panel,
)

# Kept as module-level names because this window's own status lights use them. The
# definitions live in panels.chrome so that every panel and this window render a
# verdict identically - two colours for one verdict would read as a security claim.
_COLOUR = chrome.COLOUR
_WORD = chrome.WORD


class BrowserWindow:
    def __init__(self) -> None:
        self.controller = ctrl.Controller()
        self.result = None
        self.hosted_hwnd: int | None = None
        self._host_attempts = 0
        self._watch_job: str | None = None
        self._placeholder = True

        # Declared here so the full set of instance state is visible in one place.
        # Annotation only, no assignment - see the note in app_ui.py.
        self.session_badge: tk.Label
        self.bruh_button: tk.Button
        self.address: tk.Entry
        self.stage: tk.Frame
        self.curtain: tk.Label
        self.status_text: tk.Label
        self.lights: dict[str, tk.Label] = {}

        self.root = tk.Tk()
        self.root.title(f"{config.MOAI} {config.APP_NAME}")
        self.root.configure(bg=config.BG_DARK)
        self.root.geometry("1280x860")
        self.root.minsize(900, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build()
        self.root.after(120, self.startup)

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

        self.address = tk.Entry(bar, font=("Segoe UI", 11), bd=0,
                                bg=config.BG_RAISED, fg=config.BRAND_WHITE,
                                insertbackground=config.BRAND_YELLOW,
                                relief="flat")
        self.address.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=8,
                          ipady=6)
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

        status = tk.Frame(self.root, bg=config.BG_PANEL)
        status.pack(fill="x", side="bottom")
        for key in ("HOST", "NETWORK", "PRIVACY", "DOWNLOADS", "LOCALHOST", "VPN"):
            cell = tk.Frame(status, bg=config.BG_PANEL)
            cell.pack(side="left", padx=(12, 4), pady=7)
            dot = tk.Label(cell, text="●", font=("Segoe UI", 10),
                           bg=config.BG_PANEL, fg=config.OFF_GREY)
            dot.pack(side="left", padx=(0, 5))
            tk.Label(cell, text=key, font=("Consolas", 9), bg=config.BG_PANEL,
                     fg=config.BRAND_WHITE).pack(side="left")
            self.lights[key] = dot

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
        self.set_status("Running security verification...")
        self.result = self.controller.verify(session_manager.PERSISTENT)
        self.refresh_lights()

        if self.result.blockers:
            reasons = "\n".join(f"  • {c.title}" for c in self.result.blockers)
            self.curtain.config(
                text=f"{config.MOAI}\n\nBRUH. NO.\n\n"
                     f"Required security controls could not be verified.\n"
                     f"Browser launch has been blocked.\n\n{reasons}\n\n"
                     f"Open the menu for details.",
                fg=config.BAD_RED)
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

        if self.controller.is_running():
            _stopped, message = self.controller.stop()
            self.set_status(message)
        self.hosted_hwnd = None
        self._host_attempts = 0

        self.curtain.config(text=f"{config.MOAI}\n\nStarting {mode} session...",
                            fg=config.FG_DIM)
        self.curtain.lift()
        self.root.update_idletasks()

        outcome = self.controller.start(mode)
        self.result = outcome.result
        self.refresh_lights()

        if not outcome.launched:
            self.curtain.config(text=f"{config.MOAI}\n\nBRUH. NO.\n\n{outcome.message}",
                                fg=config.BAD_RED)
            self.set_status("Launch blocked")
            return

        self.update_session_badge()
        self.set_status(outcome.message)
        self.root.after(1200, self._try_host)

    def _try_host(self) -> None:
        """Poll for this session's Edge window, then host it. Verified, not assumed."""
        self._host_attempts += 1
        hwnd = self.controller.find_browser_window()
        if hwnd:
            self.root.update_idletasks()
            if embed.host_window(hwnd, self.stage.winfo_id()):
                self.hosted_hwnd = hwnd
                self.controller.set_hosted_window(hwnd)
                # Without this the page renders but every keystroke is swallowed -
                # the two processes have separate input queues until they are joined.
                embed.attach_input(hwnd, self.root.winfo_id())
                embed.focus(hwnd)
                self.curtain.place_forget()
                # Size it immediately, then again once Tk has settled the frame -
                # Chromium sizes its compositor from the first WM_SIZE it receives, and
                # a stale size is what leaves the page looking half-rendered.
                self._fit_hosted()
                self.root.after(200, self._fit_hosted)
                self.root.after(900, self._fit_hosted)
                self.set_status("WE GOOD")
                self._watch_job = self.root.after(1500, self._watch)
                return

        if self._host_attempts < 25:
            self.root.after(800, self._try_host)
            return

        # Honest failure: the browser IS running, it just is not inside our frame.
        self.curtain.config(
            text=f"{config.MOAI}\n\nThe browser is running, but bruhswer could not host\n"
                 f"its window inside this frame.\n\n"
                 f"It is open as a separate window and is still fully protected -\n"
                 f"firewall policy, quarantine and session rules all still apply.",
            fg=config.WARN_AMBER)
        self.set_status("Browser running in its own window")

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
            self.curtain.config(
                text=f"{config.MOAI}\n\nThe browser window closed.\n\n"
                     f"Use the menu to start a new session.",
                fg=config.WARN_AMBER)
            self.curtain.place(relx=0.5, rely=0.5, anchor="center")
            self.set_status("Browser closed")
            self.update_session_badge()
            return
        title = self.controller.browser_title()
        if title:
            clean = title.replace(" - Microsoft​ Edge", "").replace(
                " - Microsoft Edge", "")
            self.status_text.config(text=clean[:90])
        self._watch_job = self.root.after(1500, self._watch)

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

        worst = self.result.category("net.")
        blocked = bool(self.result.blockers)
        self.bruh_button.config(
            fg=config.BAD_RED if blocked else
            (config.OK_GREEN if worst is Verdict.PASS else config.WARN_AMBER))

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

        # Cancel the poller first, or Tk complains about a queued callback firing
        # against a destroyed interpreter.
        if self._watch_job is not None:
            try:
                self.root.after_cancel(self._watch_job)
            except tk.TclError:
                pass
            self._watch_job = None

        if self.controller.is_running():
            ok, message = self.controller.stop()
            if not ok:
                # Do not claim a clean exit that did not happen (SS34).
                dialogs.cleanup_incomplete(self.root, message, self.root.destroy)
                return
        self.root.destroy()

    # ------------------------------------------------------------------ panels

    # Each opener does the same three things: refresh whatever state the panel needs,
    # open the scrolling shell, hand both to the module that knows how to draw it.
    # The drawing lives in panels/ so that this class stays about the window.

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
        """Ask before destroying downloads. Returns False if the user cancels.

        The window decides WHETHER to ask - only a disposable session with files
        pending needs the question. The dialog itself lives in dialogs.py along with
        the detach/re-attach rule its callers have to honour.
        """
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
        ok, message = self.controller.stop()
        self.hosted_hwnd = None
        self.curtain.config(text=f"{config.MOAI}\n\n{message}",
                            fg=config.OK_GREEN if ok else config.BAD_RED)
        self.curtain.place(relx=0.5, rely=0.5, anchor="center")
        self.update_session_badge()
        self.set_status(message)

    def run(self) -> None:
        self.update_session_badge()
        self.root.mainloop()
