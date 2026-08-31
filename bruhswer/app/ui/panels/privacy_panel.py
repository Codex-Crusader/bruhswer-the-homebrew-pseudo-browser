"""Privacy - the settings actually present in this profile, read back from disk.

This panel used to render every setting green because it appeared in
privacy_guard.STANDARD, i.e. it showed intentions and called them state. Chromium
reverts some preferences written from outside (privacy_guard.REJECTED), so "we wrote
it" was never evidence. It asks the profile now.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path

from ... import config
from ...privacy import privacy_guard
from . import chrome

# A recorded comparison run against stock Edge, not live state. Rendered dim and
# labelled as past, because this panel exists from getting that distinction wrong once.
_COMPARISON = (("Third-party cookies", "RESTRICTED"),
               ("Permissions", "CONSERVATIVE"),
               ("WebRTC local-IP exposure", "RESTRICTED"))

_COMPARISON_NOTE = ("Result of a recorded comparison against stock Edge, not a live "
                    "reading of this profile.")

_ENTROPY_NOTE = ("All 9 identity values measured (User-Agent, platform, languages, "
                 "timezone, screen, CPU count, memory, canvas, WebGL) were identical "
                 "to stock Edge. That means bruhswer adds no entropy. It does NOT mean "
                 "you cannot be fingerprinted, and it is a past measurement, not a "
                 "live check.")

_NO_PROFILE = ("No session has run yet, so there is no profile to read. These are "
               "written and re-verified when a session starts.")

# Chromium preference keys are long and differ only at the end.
_KEY_WIDTH = 58


def render(body: tk.Misc, profile: Path, privacy_mode: str) -> None:
    applied, expected, missing = privacy_guard.verify_applied(profile, privacy_mode)
    not_applied = set(missing)
    no_profile_yet = missing == [privacy_guard.NO_PROFILE_YET]

    chrome.heading(body, "Measured against stock Edge")
    for label, value in _COMPARISON:
        chrome.line(body, label, value, config.FG_DIM, _COMPARISON_NOTE)
    chrome.line(body, "Fingerprint entropy", "NO INCREASE MEASURED", config.FG_DIM,
                _ENTROPY_NOTE)

    chrome.heading(body, f"Settings in this profile  ({applied} of {expected} "
                         f"confirmed present)")
    if no_profile_yet:
        chrome.paragraph(body, _NO_PROFILE, colour=config.WARN_AMBER, pady=4)

    for setting in privacy_guard.settings_for(privacy_mode):
        if no_profile_yet:
            value, colour = "NOT YET WRITTEN", config.WARN_AMBER
        elif setting.key in not_applied:
            value, colour = "NOT APPLIED", config.BAD_RED
        else:
            value, colour = "CONFIRMED", config.OK_GREEN
        chrome.line(body, setting.key, value, colour,
                    f"Reduces: {setting.reduces}   |   Costs: {setting.costs}",
                    label_width=_KEY_WIDTH)

    chrome.heading(body, "Things bruhswer refuses to do")
    for name, why in privacy_guard.REJECTED:
        chrome.paragraph(body, f"• {name}\n   {why}", pady=3)
