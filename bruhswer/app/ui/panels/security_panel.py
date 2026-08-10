"""BRUH CHECK - every check the verifier produced, grouped by what it answers.

Renders a VerificationResult that was computed elsewhere. It does not re-run a check
and it does not decide whether anything is allowed.
"""

from __future__ import annotations

import tkinter as tk

from ... import config
from . import chrome

_GROUPS = [("Security  -  can something reach my stuff",
            ("edge", "browser", "net", "controller")),
           ("Privacy  -  what can a website learn",
            ("privacy", "dns", "downloads")),
           ("Host  -  what other devices on this network can reach", ("host",))]

_NOT_A_VM = ("bruhswer is not a virtual machine and does not claim to be one. It does "
             "not stop a browser exploit, a Windows kernel bug, or a fully compromised "
             "PC. It reduces what a website can reach and learn, and it refuses to "
             "start when the controls it can check are missing.")


def render(body: tk.Misc, result) -> None:
    for heading, prefixes in _GROUPS:
        chrome.heading(body, heading)
        for check in result.checks:
            if check.check_id.split(".")[0] not in prefixes:
                continue
            # An unenforceable check is never shown as a verdict. It is a statement
            # about the platform, and rendering it green or red would both be lies.
            if not check.enforceable:
                chrome.line(body, check.title, "NOT ENFORCEABLE", config.WARN_AMBER,
                            check.detail)
            else:
                chrome.line(body, check.title, chrome.WORD[check.verdict],
                            chrome.COLOUR[check.verdict], check.detail)

    chrome.heading(body, "What bruhswer is not")
    chrome.paragraph(body, _NOT_A_VM)
