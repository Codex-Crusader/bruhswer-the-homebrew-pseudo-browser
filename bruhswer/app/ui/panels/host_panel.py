"""Host Guard - what other devices on this network can reach.

Shows fixes; applies none.
"""

from __future__ import annotations

import tkinter as tk

from ... import config
from ...host import host_guard
from . import chrome

_CONSENT = ("Host-wide changes need Administrator and your explicit consent. bruhswer "
            "never makes them by itself, and nothing a webpage does can trigger them. "
            "Run:\n"
            "  tools\\bruhswer-hostguard.ps1 -Action plan\n"
            "  tools\\bruhswer-hostguard.ps1 -Action fix-sharing\n"
            "  tools\\bruhswer-hostguard.ps1 -Action revert")


def render(body: tk.Misc) -> None:
    checks = host_guard.evaluate()
    chrome.heading(body, "What other devices on this network can reach")
    for check in checks:
        chrome.line(body, check.title, chrome.WORD[check.verdict],
                    chrome.COLOUR[check.verdict], check.detail)

    fixes = host_guard.remediations(checks)
    chrome.heading(body, "Suggested fixes")
    if not fixes:
        tk.Label(body, text="Nothing here needs your attention right now.",
                 font=("Segoe UI", 9), bg=config.BG_DARK, fg=config.FG_DIM,
                 anchor="w").pack(fill="x", padx=16)
    for fix in fixes:
        chrome.paragraph(body,
                         f"• {fix['title']}\n   Risk: {fix['risk']}\n"
                         f"   Change: {fix['change']}\n   Undo: {fix['rollback']}",
                         colour=config.BRAND_WHITE, pady=4)

    chrome.paragraph(body, _CONSENT, font=("Consolas", 8), pady=10)
