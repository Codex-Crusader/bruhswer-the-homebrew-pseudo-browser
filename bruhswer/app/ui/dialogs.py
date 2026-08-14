"""Modal confirmations.

THE RULE: callers must release the shared input queue (embed.detach_input) BEFORE
showing anything here, and re-attach if the user backs out. A modal Tk grab while two
GUI threads share an input queue hangs the window.
"""

from __future__ import annotations

import tkinter as tk

from .. import config


def _accept(answer: dict, window: tk.Toplevel) -> None:
    """Record the choice, then close. A named function rather than a lambda wrapping
    a tuple of two calls: dict.__setitem__ and Widget.destroy both return None, so
    using them as tuple elements to sequence side effects is opaque, and every
    inspector flags a call-that-returns-nothing used as a value."""
    answer["go"] = True
    window.destroy()


def _close_anyway(window: tk.Toplevel, then) -> None:
    """Dismiss the warning, then run the caller's continuation. Same reasoning."""
    window.destroy()
    then()


def confirm_disposable_downloads(root: tk.Tk, pending: list) -> bool:
    """Ask before destroying downloads. Returns False if the user cancels."""
    answer = {"go": False}
    win = tk.Toplevel(root)
    win.title(f"{config.MOAI} bruhswer")
    win.configure(bg=config.BG_DARK)
    win.transient(root)
    win.grab_set()

    tk.Label(win, text=f"{config.MOAI}  This will delete {len(pending)} download(s)",
             font=("Segoe UI", 12, "bold"), bg=config.BG_DARK,
             fg=config.WARN_AMBER).pack(padx=22, pady=(18, 6))

    names = "\n".join(f"  • {p.name}" for p in pending[:8])
    if len(pending) > 8:
        names += f"\n  ... and {len(pending) - 8} more"
    tk.Label(win, text="This is a disposable session, so its quarantine is destroyed "
                       "with it:\n\n" + names,
             font=("Segoe UI", 10), justify="left", wraplength=460,
             bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(padx=22, pady=(0, 4))
    tk.Label(win, text="Export anything you want to keep first. bruhswer cannot get "
                       "these back.",
             font=("Segoe UI", 9), justify="left", wraplength=460,
             bg=config.BG_DARK, fg=config.FG_DIM).pack(padx=22, pady=(0, 14))

    row = tk.Frame(win, bg=config.BG_DARK)
    row.pack(pady=(0, 18))
    tk.Button(row, text="Keep the session open", bd=0, padx=16, pady=6,
              font=("Segoe UI", 10), bg=config.BG_RAISED, fg=config.BRAND_WHITE,
              cursor="hand2", command=win.destroy).pack(side="left", padx=6)
    tk.Button(row, text="Close and delete", bd=0, padx=16, pady=6,
              font=("Segoe UI", 10), bg=config.BG_RAISED, fg=config.BAD_RED,
              cursor="hand2",
              command=lambda: _accept(answer, win)).pack(side="left", padx=6)

    root.wait_window(win)
    return answer["go"]


# `tk.Tk`, not `tk.Misc`: these dialogs call transient(), which needs a real
# window manager rather than any widget, and both callers pass the root.
def cleanup_incomplete(root: tk.Tk, message: str, on_close_anyway) -> None:
    """Report a teardown that did not fully succeed. Never claim a clean exit (SS34)."""
    warn = tk.Toplevel(root)
    warn.title("bruhswer")
    warn.configure(bg=config.BG_DARK)
    tk.Label(warn, text=f"{config.MOAI}  Session cleanup incomplete",
             font=("Segoe UI", 12, "bold"), bg=config.BG_DARK,
             fg=config.BAD_RED).pack(padx=20, pady=(18, 6))
    tk.Label(warn, text=message, font=("Segoe UI", 10), wraplength=420,
             justify="left", bg=config.BG_DARK,
             fg=config.BRAND_WHITE).pack(padx=20, pady=(0, 14))
    tk.Button(warn, text="Close anyway", bd=0, padx=16, pady=6,
              bg=config.BG_RAISED, fg=config.BRAND_WHITE, cursor="hand2",
              command=lambda: _close_anyway(warn, on_close_anyway)
              ).pack(pady=(0, 18))
