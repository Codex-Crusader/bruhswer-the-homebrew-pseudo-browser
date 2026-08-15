"""BRUH CHECK - renders a VerificationResult. Re-runs nothing, decides nothing."""

from __future__ import annotations

import tkinter as tk

from . import chrome

_GROUPS = [("Security  -  can something reach my stuff",
            ("edge", "browser", "net", "controller")),
           ("Privacy  -  what can a website learn",
            ("privacy", "dns", "downloads")),
           ("Host  -  what other devices on this network can reach", ("host",))]

_EVIDENCE_KEY = (
    "The bracketed note after each verdict says what it rests on. "
    "'measured now' means bruhswer observed the thing itself during this check. "
    "'configuration read back' means it read a setting and did NOT watch it take "
    "effect. 'earlier measurement' means a result from this project's Stage 4 testing "
    "that is not re-run. 'reasoned, not measured' means it was worked out from other "
    "facts. An OK backed by a setting is not the same as an OK backed by a measurement, "
    "so they do not say the same thing."
)

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
            chrome.check_line(body, check)

    chrome.heading(body, "How to read these")
    chrome.paragraph(body, _EVIDENCE_KEY)

    chrome.heading(body, "What bruhswer is not")
    chrome.paragraph(body, _NOT_A_VM)
