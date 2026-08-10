"""Network - what the browser is permitted to reach, and what cannot be enforced."""

from __future__ import annotations

import tkinter as tk

from ... import config
from ...network import network_guard
from . import chrome

_STATE_COLOUR = {"ALLOWED": config.FG_DIM,
                 "BLOCKED": config.OK_GREEN,
                 "NOT ENFORCEABLE": config.WARN_AMBER}

_NO_VPN = ("No VPN is configured and no kill switch has been demonstrated. bruhswer "
           "will not pretend to offer one.")


def render(body: tk.Misc, result) -> None:
    chrome.heading(body, "What the browser may reach")
    for label, state in network_guard.policy_summary():
        chrome.line(body, label, state, _STATE_COLOUR[state])

    chrome.heading(body, "DNS and VPN")
    for check in [c for c in (result.checks if result else [])
                  if c.check_id.startswith("dns.")]:
        chrome.line(body, check.title, chrome.WORD[check.verdict],
                    chrome.COLOUR[check.verdict], check.detail)
    # Grey, not red. bruhswer has no VPN and says so rather than scoring itself
    # against a feature it deliberately does not have.
    chrome.line(body, "VPN", "UNSUPPORTED", config.OFF_GREY, _NO_VPN)

    chrome.heading(body, "Note")
    chrome.paragraph(body, config.CAPTIVE_PORTAL_WARNING)
