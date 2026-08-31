"""Shared panel furniture, and the one definition of what a verdict looks like."""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont

from ... import config
from ...verdict import Verdict


# Single source of truth. Everything that renders a verdict points here, so the control
# panel and the browser window cannot drift and show the same verdict two ways.
def _verdict_colours() -> dict[Verdict, str]:
    return {Verdict.PASS: config.OK_GREEN,
            Verdict.FAIL: config.BAD_RED,
            Verdict.UNKNOWN: config.WARN_AMBER}


def refresh_palette() -> None:
    """Re-read the verdict colours after a theme switch. Updates COLOUR in place,
    because browser_window and verification_ui alias this dict at import."""
    COLOUR.update(_verdict_colours())


COLOUR = _verdict_colours()
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


def scroll_panel(root: tk.Misc, title: str, width: int = 900,
                 height: int = 660) -> tk.Frame:
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


LABEL_FONT = ("Segoe UI", 10)
LABEL_WIDTH = 34
_label_font: tkfont.Font | None = None


def _elide(text: str, width_chars: int) -> str:
    """Shorten to fit the label column, keeping BOTH ends of the text.

    Cutting the tail would be wrong here: 11 of the privacy preference keys share
    their first 34 characters, so a head-only label renders eleven different
    settings - each with its own verdict - as the same string.
    """
    global _label_font
    if _label_font is None:
        _label_font = tkfont.Font(font=LABEL_FONT)
    limit = _label_font.measure("0" * width_chars)
    if _label_font.measure(text) <= limit:
        return text
    for keep in range(len(text) - 1, 3, -1):
        head = keep // 2
        candidate = text[:head] + "…" + text[len(text) - (keep - head):]
        if _label_font.measure(candidate) <= limit:
            return candidate
    return "…"


def line(parent: tk.Misc, label: str, value: str, colour: str, note: str = "",
         shape: str = "●", note_prefix: str = "",
         label_width: int = LABEL_WIDTH) -> None:
    row = tk.Frame(parent, bg=config.BG_DARK)
    row.pack(fill="x", padx=16, pady=1)
    tk.Label(row, text=shape, font=("Segoe UI", 10), bg=config.BG_DARK,
             fg=colour).pack(side="left", padx=(0, 7))
    tk.Label(row, text=_elide(label, label_width), font=LABEL_FONT,
             width=label_width, anchor="w", bg=config.BG_DARK,
             fg=config.BRAND_WHITE).pack(side="left", padx=(0, 10))
    tk.Label(row, text=value, font=("Consolas", 9), anchor="w",
             bg=config.BG_DARK, fg=colour).pack(side="left")
    if note_prefix:
        tk.Label(row, text=f"({note_prefix})", font=("Segoe UI", 8), anchor="w",
                 bg=config.BG_DARK, fg=config.FG_DIM).pack(side="left", padx=(8, 0))
    if note:
        tk.Label(parent, text=note, font=("Segoe UI", 8), justify="left",
                 wraplength=560, anchor="w", bg=config.BG_DARK,
                 fg=config.FG_DIM).pack(fill="x", padx=(44, 16), pady=(0, 4))


def paragraph(parent: tk.Misc, text: str, colour: str | None = None,
              font: tuple = ("Segoe UI", 9), pady: int = 6) -> None:
    tk.Label(parent, text=text, font=font, justify="left", wraplength=580,
             anchor="w", bg=config.BG_DARK, fg=colour or config.FG_DIM).pack(
        fill="x", padx=16, pady=pady)
