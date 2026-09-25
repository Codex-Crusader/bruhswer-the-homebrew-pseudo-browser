"""Fixed paths and policy. Every value is a literal; none comes from browser input.
The reasons for the values are in docs/ARCHITECTURE.md."""

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


# Keyed by network_guard.PolicyState value, so config imports nothing.
POLICY_STATE_COLOUR = {
    "ALLOWED": FG_DIM,
    "BLOCKED": OK_GREEN,
    "RULE SET, EFFECT NOT MEASURED": WARN_AMBER,
    "NOT ENFORCEABLE": WARN_AMBER,
}

# A state no UI has been taught. RED: the reporting contract is broken.
POLICY_STATE_UNKNOWN_COLOUR = BAD_RED
POLICY_STATE_UNKNOWN_LABEL = "UNRECOGNISED POLICY STATE"

# Shapes for rows that are not verdicts; chrome.SHAPE covers the verdicts.
SHAPE_UNKNOWN = "\u25cb"
SHAPE_LIMITATION = "\u25ac"

# --- paths ---------------------------------------------------------------------
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

# Checked in order. Never taken from PATH.
EDGE_CANDIDATES = (
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
)

# Whole-field matches; a substring accepted "CN=Not Microsoft Corporation Ltd". The
# issuer CN is not pinned: Microsoft rotates it (PCA 2011, PCA 2024).
EDGE_EXPECTED_SUBJECT_CN = "Microsoft Corporation"
EDGE_EXPECTED_SUBJECT_O = "Microsoft Corporation"
EDGE_EXPECTED_ISSUER_O = "Microsoft Corporation"

# --- Windows tooling ------------------------------------------------------------
# CREATE_NO_WINDOW, so helper processes do not flash a console.
NO_WINDOW = 0x08000000

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
POWERSHELL = SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
ICACLS = SYSTEM32 / "icacls.exe"

# Detects a junction; Path.is_symlink() returns False for one.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Mark of the Web, which makes SmartScreen check an opened file. shutil.copy2 drops it
# on Python 3.11 (measured), so export writes it. Zone 3 is URLZONE_INTERNET.
ZONE_IDENTIFIER_STREAM = "Zone.Identifier"
ZONE_ID_INTERNET = 3

# --- runtime re-verification ----------------------------------------------------
# A pass takes ~2.4s (measured), so it runs on a worker thread, never the Tk thread.
VERIFY_INTERVAL_SECONDS = 60.0

# Tk-thread queue poll, not a verification.
VERIFY_DRAIN_MS = 250

# Bounded join on teardown; the worker can be inside a 60s subprocess call.
VERIFY_JOIN_TIMEOUT_SECONDS = 2.0

VERIFY_WAKE_POLL_SECONDS = 0.25

# --- hosting the browser window -------------------------------------------------
FIT_MAX_ATTEMPTS = 3
FIT_RETRY_MS = 120
HOST_MAX_ATTEMPTS = 25

# --- disposable session overwrite -----------------------------------------------
# Not erasure. Caches run to gigabytes; larger files are skipped and reported.
DISPOSABLE_OVERWRITE_MAX_BYTES = 8 * 1024 * 1024

OVERWRITE_CHUNK_BYTES = 256 * 1024

# --- self-integrity -------------------------------------------------------------
HASH_CHUNK_BYTES = 128 * 1024

# --- panic key ------------------------------------------------------------------
# Ctrl+Shift+End, global so it fires while the browser has focus.
PANIC_MOD_ALT = 0x0001
PANIC_MOD_CONTROL = 0x0002
PANIC_MOD_SHIFT = 0x0004
PANIC_MOD_NOREPEAT = 0x4000     # holding the keys fires once, not repeatedly
PANIC_VK_END = 0x23

PANIC_HOTKEY_MODIFIERS = PANIC_MOD_CONTROL | PANIC_MOD_SHIFT | PANIC_MOD_NOREPEAT
PANIC_HOTKEY_VK = PANIC_VK_END
PANIC_HOTKEY_LABEL = "Ctrl+Shift+End"

PANIC_HOTKEY_ID = 1

PANIC_EXIT_WAIT_MS = 2000

PANIC_JOIN_TIMEOUT_SECONDS = 2.0

# --- network policy -------------------------------------------------------------
# Stays BRUHWSER: renaming would orphan the rules already on users' machines.
RULE_PREFIX = "BRUHWSER"

# Measured effective (gate A16). Not CGNAT 100.64.0.0/10: some ISPs route through it.
BLOCKED_IPV4 = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)

BLOCKED_IPV6 = (
    "fc00::/7",
    "fe80::/10",
)

CAPTIVE_PORTAL_WARNING = (
    "Network policy blocks private address ranges. On a network with a captive "
    "portal (hotel/airport sign-in pages), the sign-in page may be unreachable "
    "until you turn network policy off, sign in, and turn it back on."
)

# Reachable anyway (loopback is not filtered); listed for reporting only.
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
BASE_EDGE_FLAGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-breakpad",
    "--no-service-autorun",
    # Measured: without this a fresh profile lands on an ad/redirect page.
    "--disable-features=EdgeShoppingAssistant,EdgeCollections,MsaAutoSignIn",
    "--hide-crash-restore-bubble",
    # Measured: stops the sync, not the sign-in (reported NOT ENFORCEABLE).
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

# There is no IPC: the UI and controller share one process, and a test asserts no
# listening socket or named pipe exists.


def ensure_dirs() -> None:
    for p in (ROOT, PROFILE_PERSISTENT, PROFILE_DISPOSABLE_ROOT, QUARANTINE, LOGS, STATE):
        p.mkdir(parents=True, exist_ok=True)


def find_edge() -> Path | None:
    for p in EDGE_CANDIDATES:
        if p.is_file():
            return p
    return None
