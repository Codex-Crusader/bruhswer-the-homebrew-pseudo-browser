"""Network - what the browser is permitted to reach, and what cannot be enforced."""

from __future__ import annotations

import tkinter as tk

from ... import config
from ...network import network_guard
from . import chrome


def state_colour(state) -> str:
    """Colour for one PolicyState. Shared by every UI - see config.POLICY_STATE_COLOUR.

    Never raises. The strict `dict[state]` this replaced took the whole Network panel
    offline with a KeyError the moment policy_summary() gained a fourth state; a
    missing colour must degrade to a loud colour, not to no panel.
    """
    return config.POLICY_STATE_COLOUR.get(
        str(state), config.POLICY_STATE_UNKNOWN_COLOUR)


def state_label(state) -> str:
    """What to print. An unrecognised state says so rather than showing raw prose."""
    text = str(state)
    if text in config.POLICY_STATE_COLOUR:
        return text
    return f"{config.POLICY_STATE_UNKNOWN_LABEL}: {text}"


_NO_VPN = ("No VPN is configured and no kill switch has been demonstrated. bruhswer "
           "will not pretend to offer one.")


def render(body: tk.Misc, result) -> None:
    chrome.heading(body, "What the browser may reach")
    for label, state in network_guard.policy_summary():
        # The evidence note is what stops a green BLOCKED row - which rests on the
        # Stage 4 gate A16 experiment - from reading as a measurement taken just now.
        chrome.line(body, label, state_label(state), state_colour(state),
                    note_prefix=str(network_guard.policy_evidence(state)))

    chrome.heading(body, "DNS and VPN")
    for check in [c for c in (result.checks if result else [])
                  if c.check_id.startswith("dns.")]:
        chrome.check_line(body, check)
    # Grey, not red: an absent feature is not a failed one.
    chrome.line(body, "VPN", "UNSUPPORTED", config.OFF_GREY, _NO_VPN)

    chrome.heading(body, "Note")
    chrome.paragraph(body, config.CAPTIVE_PORTAL_WARNING)
