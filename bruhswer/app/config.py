"""BRUHWSER configuration: fixed paths, fixed policy, no dynamic execution.

Everything here is a literal authored in this file. Nothing is ever derived from a URL,
a filename, an HTTP header, a downloaded file, or any other browser-controlled input
(brief SS15, SS48). Why each value is what it is: docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "bruhswer"
TAGLINE = "Browse the internet. Trust absolutely nothing."
MOAI = "\N{MOYAI}"
WORDMARK_HEAD = "bruh"
WORDMARK_TAIL = "swer"

# --- brand ---------------------------------------------------------------------
BRAND_YELLOW = "#F5C518"
BRAND_WHITE = "#FFFFFF"
BG_DARK = "#111315"
BG_PANEL = "#1A1D20"
BG_RAISED = "#23272B"
FG_DIM = "#8B949E"
OK_GREEN = "#3FB950"
WARN_AMBER = "#D29922"
BAD_RED = "#F85149"
OFF_GREY = "#6E7681"

# Contrast ratios are measured by tests/test_accessibility.py, not asserted here.
_HIGH_CONTRAST = {
    "BG_DARK": "#000000",
    "BG_PANEL": "#000000",
    "BG_RAISED": "#1A1A1A",
    "BRAND_WHITE": "#FFFFFF",
    "BRAND_YELLOW": "#FFFF00",
    "FG_DIM": "#D9D9D9",
    "OK_GREEN": "#4AE04A",
    "WARN_AMBER": "#FFC93C",
    "BAD_RED": "#FF6B6B",
    "OFF_GREY": "#B0B0B0",
}

_LIGHT = {
    "BG_DARK": "#F5F6F7",
    "BG_PANEL": "#E8EAEC",
    "BG_RAISED": "#DCDFE3",
    "BRAND_WHITE": "#16191C",
    "BRAND_YELLOW": "#7A5B00",
    "FG_DIM": "#55606B",
    "OK_GREEN": "#116329",
    "WARN_AMBER": "#7A4E00",
    "BAD_RED": "#B01B12",
    "OFF_GREY": "#5B646D",
}


def _apply(palette: dict[str, str]) -> None:
    globals().update(palette)
    globals()["POLICY_STATE_COLOUR"] = {
        "ALLOWED": palette["FG_DIM"],
        "BLOCKED": palette["OK_GREEN"],
        "RULE SET, EFFECT NOT MEASURED": palette["WARN_AMBER"],
        "NOT ENFORCEABLE": palette["WARN_AMBER"],
    }
    globals()["POLICY_STATE_UNKNOWN_COLOUR"] = palette["BAD_RED"]


def apply_high_contrast() -> None:
    """Switch to the high-contrast palette. Call BEFORE any widget is built. One-way."""
    _apply(_HIGH_CONTRAST)


def apply_light() -> None:
    """Switch to the light palette. Call BEFORE any widget is built. One-way."""
    _apply(_LIGHT)


# Keyed by network_guard.PolicyState's VALUE, so this module need not import the
# network layer. ONE map: every UI reads it, none keeps a copy.
POLICY_STATE_COLOUR = {
    "ALLOWED": FG_DIM,
    "BLOCKED": OK_GREEN,
    "RULE SET, EFFECT NOT MEASURED": WARN_AMBER,
    "NOT ENFORCEABLE": WARN_AMBER,
}

# A state no UI has been taught. RED: the reporting contract is broken.
POLICY_STATE_UNKNOWN_COLOUR = BAD_RED
POLICY_STATE_UNKNOWN_LABEL = "UNRECOGNISED POLICY STATE"

# Shapes, so a verdict is never carried by colour alone. chrome.SHAPE covers the three
# verdicts; these two are for the rows that are not verdicts at all.
SHAPE_UNKNOWN = "\u25cb"
SHAPE_LIMITATION = "\u25ac"

# --- paths ---------------------------------------------------------------------
# All BRUHWSER state lives under one directory. Nothing is written anywhere else.
_LOCALAPPDATA = os.environ.get("LOCALAPPDATA")
if not _LOCALAPPDATA:
    raise RuntimeError(
        "bruhswer is Windows-only: it wraps Microsoft Edge and enforces its controls "
        "through the Windows Firewall and Windows ACLs. LOCALAPPDATA is not set, so "
        "this is not a Windows environment. Set LOCALAPPDATA to run the "
        "platform-independent unit tests on another OS.")

ROOT = Path(_LOCALAPPDATA) / "BRUHWSER"
PROFILE_PERSISTENT = ROOT / "profiles" / "persistent"
PROFILE_DISPOSABLE_ROOT = ROOT / "profiles" / "disposable"
QUARANTINE = ROOT / "quarantine"
LOGS = ROOT / "logs"
STATE = ROOT / "state"

# Fixed absolute paths, checked in order. Never taken from PATH, which the user's own
# environment can write.
EDGE_CANDIDATES = (
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
)

EDGE_EXPECTED_SUBJECT_CN = "Microsoft Corporation"

# --- Windows tooling (fixed absolute paths) -------------------------------------
# CREATE_NO_WINDOW. Passed as `creationflags` to every helper process, or each of the
# dozens of PowerShell and icacls calls would pop up a console window.
NO_WINDOW = 0x08000000

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
POWERSHELL = SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
ICACLS = SYSTEM32 / "icacls.exe"

# FILE_ATTRIBUTE_REPARSE_POINT. The test that actually detects a directory junction:
# Path.is_symlink() returns False for one, so the obvious check is inert.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# --- runtime re-verification ----------------------------------------------------
# One pass starts 14 helper processes and takes 5.5s measured, so it runs on a worker
# thread and never on the Tk thread. See app/ui/verify_worker.py.
VERIFY_INTERVAL_SECONDS = 60.0

# Tk-thread queue poll. Cheap and non-blocking, NOT a verification.
VERIFY_DRAIN_MS = 250

# Bounded join on teardown; the worker can be inside a 60s subprocess call.
VERIFY_JOIN_TIMEOUT_SECONDS = 2.0

# Slice the worker sleeps in, so a submitted request is picked up promptly.
VERIFY_WAKE_POLL_SECONDS = 0.25

# --- hosting the browser window -------------------------------------------------
# Resize, then CONFIRM it landed (embed.is_fitted), rather than wait a fixed time.
FIT_MAX_ATTEMPTS = 3
FIT_RETRY_MS = 120
HOST_MAX_ATTEMPTS = 25

# --- disposable session overwrite -----------------------------------------------
# HYGIENE, not an erasure guarantee - see session_manager.NOT_GUARANTEED.
#
# The cap exists because a profile cache runs to gigabytes. The small files hold the
# identifying material and sit far below it. Files above it are skipped and COUNTED,
# and the count is reported to the user.
DISPOSABLE_OVERWRITE_MAX_BYTES = 8 * 1024 * 1024

OVERWRITE_CHUNK_BYTES = 256 * 1024

# --- self-integrity -------------------------------------------------------------
HASH_CHUNK_BYTES = 128 * 1024

# --- panic key ------------------------------------------------------------------
# Ctrl+Shift+End, registered globally so it fires while the browser has focus.
PANIC_MOD_ALT = 0x0001
PANIC_MOD_CONTROL = 0x0002
PANIC_MOD_SHIFT = 0x0004
PANIC_MOD_NOREPEAT = 0x4000     # holding the keys fires once, not repeatedly
PANIC_VK_END = 0x23

PANIC_HOTKEY_MODIFIERS = PANIC_MOD_CONTROL | PANIC_MOD_SHIFT | PANIC_MOD_NOREPEAT
PANIC_HOTKEY_VK = PANIC_VK_END
PANIC_HOTKEY_LABEL = "Ctrl+Shift+End"

# Only has to be unique within the registering thread, which registers exactly one.
PANIC_HOTKEY_ID = 1

# TerminateProcess is asynchronous, so an exit must be waited for to be CONFIRMED.
PANIC_EXIT_WAIT_MS = 2000

PANIC_JOIN_TIMEOUT_SECONDS = 2.0

# --- network policy -------------------------------------------------------------
# DELIBERATELY BRUHWSER while the product name is lowercase `bruhswer`. Renaming these
# is a migration, not a case change: the app would fail closed on "rule not present"
# while two perfectly good rules sat on the host under the old name.
RULE_PREFIX = "BRUHWSER"

# Measured effective in Stage 4 gate A16. Deliberately NOT included: 100.64.0.0/10
# (CGNAT), which some ISPs put the user's own path to the internet inside.
BLOCKED_IPV4 = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)

# Treated separately on purpose (brief SS23): IPv4 rules do not protect IPv6.
BLOCKED_IPV6 = (
    "fc00::/7",
    "fe80::/10",
)

CAPTIVE_PORTAL_WARNING = (
    "Network policy blocks private address ranges. On a network with a captive "
    "portal (hotel/airport sign-in pages), the sign-in page may be unreachable "
    "until you turn network policy off, sign in, and turn it back on."
)

# NOT enforceable: Windows Firewall does not filter loopback, so no rule stops the
# browser reaching these. Listed for honest reporting only (brief SS21).
DEV_SERVICE_PORTS = (
    63342,  # PyCharm built-in server
    5173,   # Vite
    3000,   # common Node/React dev server
    5000,   # common Flask default
    8000,   # common Django / python -m http.server
    8080,   # common alternate HTTP
    9229,   # Node inspector
    11434,  # Ollama
)

# --- Edge command line ----------------------------------------------------------
# None of these weakens a security control. What is never passed, and why, is
# DANGEROUS_FLAGS below.
BASE_EDGE_FLAGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-breakpad",
    "--no-service-autorun",
    # Measured: without this a fresh profile lands on an ad/redirect page.
    "--disable-features=EdgeShoppingAssistant,EdgeCollections,MsaAutoSignIn",
    # Suppresses the "Restore pages" bubble. Hides a prompt, disables no control.
    "--hide-crash-restore-bubble",
    # Measured: stops the SYNC of a fresh profile into the Windows account. It does
    # NOT stop the sign-in, which no switch prevents - privacy_guard reports that
    # residual as NOT ENFORCEABLE rather than hiding it.
    "--disable-sync",
)

DANGEROUS_FLAGS = (
    "--no-sandbox",
    "--disable-web-security",
    "--ignore-certificate-errors",
    "--allow-running-insecure-content",
    "--disable-site-isolation-trials",
    "--disable-gpu-sandbox",
    "--remote-debugging-port",
    "--remote-debugging-pipe",
    "--load-extension",
)

# --- IPC ------------------------------------------------------------------------
# There is NONE, and that is the design: the UI and the controller run in the same
# process, so the UI calls Controller methods directly. tests/test_security.py asserts
# bruhswer opens no listening socket and no named pipe. See docs/ARCHITECTURE.md.


def ensure_dirs() -> None:
    for p in (ROOT, PROFILE_PERSISTENT, PROFILE_DISPOSABLE_ROOT, QUARANTINE, LOGS, STATE):
        p.mkdir(parents=True, exist_ok=True)


def find_edge() -> Path | None:
    for p in EDGE_CANDIDATES:
        if p.is_file():
            return p
    return None
