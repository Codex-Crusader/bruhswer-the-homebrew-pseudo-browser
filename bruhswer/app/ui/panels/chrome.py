"""Shared panel furniture: the scrolling shell, a heading, a status line.

Every panel is the same shape - a scrollable dark frame full of coloured status rows -
so the shape lives in one place. The colour and word maps live here too, because a
verdict must look the same everywhere it appears. Two panels rendering PASS in two
different colours would be a UI bug that reads as a security statement.
"""

from __future__ import annotations

import tkinter as tk

from ... import config
from ...verdict import Verdict

# The single source of truth for what a verdict looks like. UNKNOWN is amber and is
# never rendered as green anywhere in the application.
COLOUR = {Verdict.PASS: config.OK_GREEN,
          Verdict.FAIL: config.BAD_RED,
          Verdict.UNKNOWN: config.WARN_AMBER}
WORD = {Verdict.PASS: "OK", Verdict.FAIL: "EXPOSED", Verdict.UNKNOWN: "UNKNOWN"}


def scroll_panel(root: tk.Misc, title: str, width: int = 640,
                 height: int = 620) -> tk.Frame:
    """Open a scrollable Toplevel and return the frame panels should pack into."""
    win = tk.Toplevel(root)
    win.title(f"{config.MOAI} {title}")
    win.configure(bg=config.BG_DARK)
    win.geometry(f"{width}x{height}")
    canvas = tk.Canvas(win, bg=config.BG_DARK, highlightthickness=0)
    bar = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, bg=config.BG_DARK)
    inner.bind("<Configure>",
               lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    window = canvas.create_window((0, 0), window=inner, anchor="nw")
    canvas.bind("<Configure>", lambda e: canvas.itemconfig(window, width=e.width))
    canvas.configure(yscrollcommand=bar.set)
    canvas.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")
    return inner


def heading(parent: tk.Misc, text: str) -> None:
    tk.Label(parent, text=text.upper(), font=("Segoe UI", 9, "bold"),
             bg=config.BG_DARK, fg=config.FG_DIM, anchor="w").pack(
        fill="x", padx=16, pady=(14, 5))


def line(parent: tk.Misc, label: str, value: str, colour: str, note: str = "") -> None:
    row = tk.Frame(parent, bg=config.BG_DARK)
    row.pack(fill="x", padx=16, pady=1)
    tk.Label(row, text="●", font=("Segoe UI", 10), bg=config.BG_DARK,
             fg=colour).pack(side="left", padx=(0, 7))
    tk.Label(row, text=label, font=("Segoe UI", 10), width=34, anchor="w",
             bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left")
    tk.Label(row, text=value, font=("Consolas", 9), anchor="w",
             bg=config.BG_DARK, fg=colour).pack(side="left")
    if note:
        tk.Label(parent, text=note, font=("Segoe UI", 8), justify="left",
                 wraplength=560, anchor="w", bg=config.BG_DARK,
                 fg=config.FG_DIM).pack(fill="x", padx=(44, 16), pady=(0, 4))


def paragraph(parent: tk.Misc, text: str, colour: str = config.FG_DIM,
              font: tuple = ("Segoe UI", 9), pady: int = 6) -> None:
    tk.Label(parent, text=text, font=font, justify="left", wraplength=580,
             anchor="w", bg=config.BG_DARK, fg=colour).pack(
        fill="x", padx=16, pady=pady)
