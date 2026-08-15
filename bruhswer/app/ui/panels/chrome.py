"""Shared panel furniture, and the one definition of what a verdict looks like."""

from __future__ import annotations

import tkinter as tk

from ... import config
from ...verdict import Verdict

# Single source of truth. Everything that renders a verdict points here, so the control
# panel and the browser window cannot drift and show the same verdict two ways.
COLOUR = {Verdict.PASS: config.OK_GREEN,
          Verdict.FAIL: config.BAD_RED,
          Verdict.UNKNOWN: config.WARN_AMBER}
WORD = {Verdict.PASS: "OK", Verdict.FAIL: "EXPOSED", Verdict.UNKNOWN: "UNKNOWN"}

# Colour AND a word for every verdict, so the state survives being read by someone who
# cannot separate the colours. A dot alone carries the whole meaning in hue.
SHAPE = {Verdict.PASS: "●", Verdict.FAIL: "■", Verdict.UNKNOWN: "▲"}
NOT_ENFORCEABLE_SHAPE = "▬"


def check_line(parent: tk.Misc, check) -> None:
    """One check, with its verdict AND the kind of evidence behind it."""
    if not check.enforceable:
        line(parent, check.title, "NOT ENFORCEABLE", config.WARN_AMBER, check.detail,
             shape=NOT_ENFORCEABLE_SHAPE, note_prefix=check.evidence_note())
        return
    line(parent, check.title, WORD[check.verdict], COLOUR[check.verdict], check.detail,
         shape=SHAPE[check.verdict], note_prefix=check.evidence_note())


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


def line(parent: tk.Misc, label: str, value: str, colour: str, note: str = "",
         shape: str = "●", note_prefix: str = "") -> None:
    row = tk.Frame(parent, bg=config.BG_DARK)
    row.pack(fill="x", padx=16, pady=1)
    tk.Label(row, text=shape, font=("Segoe UI", 10), bg=config.BG_DARK,
             fg=colour).pack(side="left", padx=(0, 7))
    tk.Label(row, text=label, font=("Segoe UI", 10), width=34, anchor="w",
             bg=config.BG_DARK, fg=config.BRAND_WHITE).pack(side="left")
    tk.Label(row, text=value, font=("Consolas", 9), anchor="w",
             bg=config.BG_DARK, fg=colour).pack(side="left")
    if note_prefix:
        tk.Label(row, text=f"({note_prefix})", font=("Segoe UI", 8), anchor="w",
                 bg=config.BG_DARK, fg=config.FG_DIM).pack(side="left", padx=(8, 0))
    if note:
        tk.Label(parent, text=note, font=("Segoe UI", 8), justify="left",
                 wraplength=560, anchor="w", bg=config.BG_DARK,
                 fg=config.FG_DIM).pack(fill="x", padx=(44, 16), pady=(0, 4))


def paragraph(parent: tk.Misc, text: str, colour: str = config.FG_DIM,
              font: tuple = ("Segoe UI", 9), pady: int = 6) -> None:
    tk.Label(parent, text=text, font=font, justify="left", wraplength=580,
             anchor="w", bg=config.BG_DARK, fg=colour).pack(
        fill="x", padx=16, pady=pady)
