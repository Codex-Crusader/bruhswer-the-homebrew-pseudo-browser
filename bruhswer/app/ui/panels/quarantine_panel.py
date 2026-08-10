"""Quarantine - lists what landed here. Export and delete are caller-supplied callbacks;
this module never moves a file or builds a path."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable

from ... import config
from ...downloads import quarantine
from . import chrome

_WHAT_THIS_IS = ("Downloads land here instead of your Downloads folder. bruhswer does "
                 "not run them and does not scan them - it cannot tell you a file is "
                 "safe, only that it has not been let out.")


def render(body: tk.Misc, session_id: str, on_export: Callable,
           on_delete: Callable) -> None:
    chrome.heading(body, f"{config.MOAI} Quarantine")
    chrome.paragraph(body, _WHAT_THIS_IS, pady=4)

    items = quarantine.list_quarantine(session_id)
    if not items:
        tk.Label(body, text="Nothing in quarantine.", font=("Segoe UI", 10),
                 bg=config.BG_DARK, fg=config.FG_DIM, anchor="w").pack(
            fill="x", padx=16, pady=8)
        return

    for item in items:
        _card(body, item, on_export, on_delete)


def _card(body: tk.Misc, item, on_export: Callable, on_delete: Callable) -> None:
    card = tk.Frame(body, bg=config.BG_PANEL)
    card.pack(fill="x", padx=16, pady=5)
    tk.Label(card, text=item.display_name, font=("Consolas", 10), anchor="w",
             bg=config.BG_PANEL, fg=config.BRAND_WHITE).pack(
        fill="x", padx=10, pady=(8, 0))

    note = f"{item.size:,} bytes"
    if item.is_executable_type:
        note += "   -   this is a program. It is NOT being executed."
    tk.Label(card, text=note, font=("Segoe UI", 8), anchor="w", bg=config.BG_PANEL,
             fg=config.WARN_AMBER if item.is_executable_type else config.FG_DIM
             ).pack(fill="x", padx=10)

    buttons = tk.Frame(card, bg=config.BG_PANEL)
    buttons.pack(fill="x", padx=10, pady=8)
    tk.Button(buttons, text="Export...", bd=0, padx=12, pady=4,
              font=("Segoe UI", 9), bg=config.BG_RAISED, fg=config.BRAND_WHITE,
              cursor="hand2",
              command=lambda i=item: on_export(i)).pack(side="left")
    tk.Button(buttons, text="Delete", bd=0, padx=12, pady=4,
              font=("Segoe UI", 9), bg=config.BG_RAISED, fg=config.BRAND_WHITE,
              cursor="hand2",
              command=lambda i=item: on_delete(i)).pack(side="left", padx=6)
