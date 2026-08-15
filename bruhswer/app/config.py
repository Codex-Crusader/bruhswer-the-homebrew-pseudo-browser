"""BRUHWSER configuration: fixed paths, fixed policy, no dynamic execution.

Everything here is a literal authored in this file. Nothing in this module is ever
derived from a URL, a filename, an HTTP header, a downloaded file, or any other
browser-controlled input (brief SS15, SS48).
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "bruhswer"
TAGLINE = "Browse the internet. Trust absolutely nothing."
MOAI = "\N{MOYAI}"

# The wordmark renders as one word on one line: head in yellow, tail in white.
# Stage 6 SS33 settled the spelling: lowercase `bruhswer`, "bruh" yellow + "swer" white.
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

# High-contrast palette, applied by apply_high_contrast() when Windows says the user
# has that mode on. Every colour here was chosen to clear WCAG AA (4.5:1) against the
# black background, which the ordinary palette's amber and green do not - and a status
# light nobody can read is the same defect as one that lies.
# tests/test_accessibility.py computes the ratios rather than trusting this comment.
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


def apply_high_contrast() -> None:
    """Switch the palette to the high-contrast one. Call BEFORE any widget is built.

    Rebinds the module globals rather than threading a theme object through every
    widget: each colour is read once, at widget-construction time, so doing this first
    is sufficient and touches no call site. It is one-way - bruhswer does not follow a
    theme change mid-session, and it does not claim to.
    """
    globals().update(_HIGH_CONTRAST)
    globals()["POLICY_STATE_COLOUR"] = {
        "ALLOWED": _HIGH_CONTRAST["FG_DIM"],
        "BLOCKED": _HIGH_CONTRAST["OK_GREEN"],
        "RULE SET, EFFECT NOT MEASURED": _HIGH_CONTRAST["WARN_AMBER"],
        "NOT ENFORCEABLE": _HIGH_CONTRAST["WARN_AMBER"],
    }
    globals()["POLICY_STATE_UNKNOWN_COLOUR"] = _HIGH_CONTRAST["BAD_RED"]


# Colour for each network_guard.PolicyState, by the state's VALUE so this module does
# not have to import the network layer.
#
# ONE map, used by every UI. There used to be two - one in app/ui/panels/network_panel.py
# and an inline one in app/ui/app_ui.py - and when policy_summary() gained a fourth
# state both of them KeyError'd, taking the Network panel and the --panel UI offline.
# Duplicated lookup tables keyed on another module's output do not stay in step.
#
# Only BLOCKED is green, and only because the rows carrying it rest on the empirical
# gate-A16 measurement. A state whose text says it was not verified never renders in
# the same colour as one that was.
POLICY_STATE_COLOUR = {
    "ALLOWED": FG_DIM,
    "BLOCKED": OK_GREEN,
    "RULE SET, EFFECT NOT MEASURED": WARN_AMBER,
    "NOT ENFORCEABLE": WARN_AMBER,
}

# A state no UI has been taught. RED, deliberately: an unrecognised state means the
# reporting contract between network_guard and the UI is broken, which is a louder
# problem than any single row's verdict. Amber would quietly normalise a new,
# unreviewed claim; green would be the defect this project exists to avoid.
POLICY_STATE_UNKNOWN_COLOUR = BAD_RED
POLICY_STATE_UNKNOWN_LABEL = "UNRECOGNISED POLICY STATE"

# Shapes for the status lights, so a verdict is never carried by colour alone. A
# red-green colour blindness affects roughly 1 in 12 men, and this product's entire
# output is a row of coloured dots - PASS and FAIL rendering as the same shape means
# the security state is unreadable to them. chrome.SHAPE covers the three verdicts;
# these two are for the rows that are not verdicts at all.
SHAPE_UNKNOWN = "○"
SHAPE_LIMITATION = "▬"

# Light palette, applied when Windows says the user prefers light apps. bruhswer is
# dark by default and that is a deliberate look, but a fixed dark window on a machine
# set to light is the app ignoring a stated preference.
#
# Same bar as the high-contrast palette, and tests/test_accessibility.py measures it:
# indicators clear 3:1 and text clears 4.5:1 against the light background. The verdict
# hues are DARKENED rather than reused - the dark theme's #3FB950 green is only 1.9:1
# on white, so keeping it would have made the status lights unreadable.
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


def apply_light() -> None:
    """Switch to the light palette. Call BEFORE any widget is built.

    Same one-way rebinding as apply_high_contrast(), for the same reason: each colour
    is read once at widget-construction time. bruhswer does not follow a theme change
    mid-session and does not claim to.
    """
    globals().update(_LIGHT)
    globals()["POLICY_STATE_COLOUR"] = {
        "ALLOWED": _LIGHT["FG_DIM"],
        "BLOCKED": _LIGHT["OK_GREEN"],
        "RULE SET, EFFECT NOT MEASURED": _LIGHT["WARN_AMBER"],
        "NOT ENFORCEABLE": _LIGHT["WARN_AMBER"],
    }
    globals()["POLICY_STATE_UNKNOWN_COLOUR"] = _LIGHT["BAD_RED"]


# --- paths ---------------------------------------------------------------------
# All BRUHWSER state lives under one directory. Nothing is written anywhere else.
_LOCALAPPDATA = os.environ.get("LOCALAPPDATA")
if not _LOCALAPPDATA:
    # Was os.environ["LOCALAPPDATA"], which died with a bare KeyError off Windows.
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

# Edge. Fixed absolute paths, checked in order. Never taken from PATH, because PATH is
# writable by the user's environment and this is a security-sensitive lookup.
EDGE_CANDIDATES = (
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
)

# The publisher BRUHWSER expects for its browser runtime. Verified at every launch.
EDGE_EXPECTED_SUBJECT_CN = "Microsoft Corporation"

# --- Windows tooling (fixed absolute paths) -------------------------------------
# CREATE_NO_WINDOW. bruhswer is a GUI application, but every PowerShell and icacls call
# it makes would otherwise pop up a black console window - dozens of them during
# startup verification. Passed as `creationflags` to every helper process.
NO_WINDOW = 0x08000000

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
POWERSHELL = SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
ICACLS = SYSTEM32 / "icacls.exe"

# FILE_ATTRIBUTE_REPARSE_POINT, from the Win32 file-attribute set.
#
# Named here rather than written as a bare 0x400 at each site, because it is the single
# most load-bearing constant in bruhswer's delete and export paths and it was previously
# duplicated three times across two modules. It is the test that actually detects a
# directory junction: MEASURED in this project, Path.is_symlink() returns FALSE for a
# junction created with `mklink /J`, so the obvious-looking symlink check is silently
# inert against the exact thing it appears to defend against.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# --- runtime re-verification ----------------------------------------------------
# A full verification starts 14 helper processes (13 PowerShell + 1 icacls).
#
# MEASURED, not estimated, and RE-MEASURED after HostGuard's seven queries were made
# concurrent and the duplicate IPv6 probe removed: one complete pass now takes 5.5
# SECONDS on this machine and produces 31 checks. It was 8.31s across 15 processes.
#
# That is still the number that settles the design - a Tk `after()` callback doing this
# would freeze the window for five seconds, once a minute, for the life of the session.
# It runs on a worker thread and never on the Tk thread. See app/ui/verify_worker.py.
#
# Re-measure with verifier.VerificationResult.total_ms if the guards change again;
# tests/test_evidence_model.py asserts the timings are collected, not what they are.
#
# 60s between cycles: long enough that the helper processes are a rounding error on
# battery and CPU, short enough that a control which silently stopped applying is
# surfaced while the user is still in the session that it affects.
VERIFY_INTERVAL_SECONDS = 60.0

# How often the Tk thread drains the worker's result queue. This is a cheap, non
# blocking queue poll, NOT a verification, so it can be frequent without cost.
VERIFY_DRAIN_MS = 250

# Upper bound on how long teardown waits for the worker to notice it should stop.
# The worker can be blocked inside a subprocess call with its own 60s timeout, so this
# is a bounded join, not a guarantee - see the shutdown notes in verify_worker.py.
VERIFY_JOIN_TIMEOUT_SECONDS = 2.0

# Slice the worker sleeps in while waiting out VERIFY_INTERVAL_SECONDS, so a newly
# submitted request is picked up promptly instead of waiting out the whole cycle.
VERIFY_WAKE_POLL_SECONDS = 0.25

# --- hosting the browser window -------------------------------------------------
# After reparenting Edge, bruhswer resizes it to the stage and then CONFIRMS the resize
# landed (embed.is_fitted) before dropping the curtain. This replaced fixed 200/900/950ms
# timers, which were a guess at how long Chromium takes: too short and the user watched
# the page repaint, too long and startup felt slow for no reason.
#
# Three attempts, because the check is a verification and not a wait - if the window is
# not the right size after three resize-and-confirm rounds, something is wrong that more
# rounds will not fix, and the curtain must come up anyway rather than hang.
FIT_MAX_ATTEMPTS = 3
FIT_RETRY_MS = 120

# --- disposable session overwrite -----------------------------------------------
# Before a disposable profile is deleted, its files are overwritten with random bytes.
# This is HYGIENE, not an erasure guarantee - see session_manager.NOT_GUARANTEED and
# the docstring on _overwrite_tree, which state exactly what it cannot promise.
#
# The size cap exists because a browser profile's cache is routinely hundreds of
# megabytes to several gigabytes. Overwriting all of it would turn closing a session
# into a multi-minute operation, and a user who cancels that gets neither the overwrite
# nor a timely close. The small files are the ones that hold the identifying material -
# Cookies, Login Data, History, Web Data, the Local Storage LevelDB - and they sit far
# below this cap.
#
# Files ABOVE the cap are skipped and COUNTED, and the count is reported to the user.
# Silently skipping them would be the false-coverage failure this project treats as a
# defect in its own right.
DISPOSABLE_OVERWRITE_MAX_BYTES = 8 * 1024 * 1024

# Written in chunks so a large file never has to be held in memory at once.
OVERWRITE_CHUNK_BYTES = 256 * 1024

# --- self-integrity -------------------------------------------------------------
# Read size for hashing bruhswer's own source files. Same reasoning as above: chunked
# so no file is ever pulled into memory whole.
HASH_CHUNK_BYTES = 128 * 1024

# --- panic key ------------------------------------------------------------------
# Ctrl+Shift+End. Registered globally so it works while the hosted browser has focus,
# which is the only time it matters.
#
# Win32 modifier and virtual-key codes, named rather than inlined as bare hex.
PANIC_MOD_ALT = 0x0001
PANIC_MOD_CONTROL = 0x0002
PANIC_MOD_SHIFT = 0x0004
PANIC_MOD_NOREPEAT = 0x4000     # holding the keys must fire once, not repeatedly
PANIC_VK_END = 0x23

PANIC_HOTKEY_MODIFIERS = PANIC_MOD_CONTROL | PANIC_MOD_SHIFT | PANIC_MOD_NOREPEAT
PANIC_HOTKEY_VK = PANIC_VK_END
PANIC_HOTKEY_LABEL = "Ctrl+Shift+End"

# Per-thread hotkey id. Only has to be unique within the registering thread, and the
# listener thread registers exactly one.
PANIC_HOTKEY_ID = 1

# How long to wait for a terminated process to actually exit before giving up on
# CONFIRMING it. TerminateProcess is asynchronous, so without this bruhswer would be
# reporting a request as though it were an outcome.
PANIC_EXIT_WAIT_MS = 2000

# Bounded join for the hotkey listener thread on teardown.
PANIC_JOIN_TIMEOUT_SECONDS = 2.0

# --- network policy -------------------------------------------------------------
# Firewall rule prefix. DELIBERATELY left as BRUHWSER while the product name is
# lowercase `bruhswer` (Stage 6 SS33 standardised the USER-FACING name).
#
# These are genuinely different strings - BRUHWSER vs bruhswer, "WSER" vs "SWER" - so
# renaming would not be a case change, it would be a migration. The failure mode is
# bad: the app would fail closed with "rule not present" while two perfectly good
# rules sat on the host under the old name, and the user's browser would stop
# launching for a cosmetic rename. Rule names are internal plumbing; the product name
# the user sees is in the UI, and the rule Description already says bruhswer created it.
RULE_PREFIX = "BRUHWSER"

# Ranges the browser is blocked from reaching. Measured effective in Stage 4 gate A16:
# the router became unreachable (ERR_NETWORK_ACCESS_DENIED) while the internet stayed
# up, because traffic ROUTED THROUGH the gateway is not traffic addressed TO it.
#
# Deliberately NOT included: 100.64.0.0/10 (CGNAT). Some ISPs and mobile hotspots put
# the user's own path to the internet inside it, so blocking it could break normal
# browsing. Brief SS19: do not blindly block ranges legitimate operation depends on.
BLOCKED_IPV4 = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)

# IPv6 equivalents: unique-local and link-local. Treated separately from IPv4 on
# purpose (brief SS23) -- IPv4 rules do not protect IPv6.
BLOCKED_IPV6 = (
    "fc00::/7",
    "fe80::/10",
)

# Captive portals frequently live on RFC1918. If a network needs one, these rules will
# block it and the user must disable network policy to log in. Documented, not hidden.
CAPTIVE_PORTAL_WARNING = (
    "Network policy blocks private address ranges. On a network with a captive "
    "portal (hotel/airport sign-in pages), the sign-in page may be unreachable "
    "until you turn network policy off, sign in, and turn it back on."
)

# Local development services. Listed so the UI can be specific about what is exposed.
# Configurable rather than hard-coded to one port (brief SS21).
#
# IMPORTANT: these are NOT enforceable. Windows Firewall does not filter loopback, so
# no rule can stop the browser reaching them. Measured in Stage 4 gate A16 and
# confirmed against a live PyCharm service. Listed for honest reporting only.
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
# Flags applied to every BRUHWSER session. Each one has a reason; none of them
# weakens a security control.
#
# NOT USED, ever: --no-sandbox, --disable-web-security, --ignore-certificate-errors,
# --allow-running-insecure-content, --disable-site-isolation-trials. Those would
# disable the only real process boundary this architecture has (Stage 4 gate A3).
BASE_EDGE_FLAGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-breakpad",
    "--no-service-autorun",
    # Measured: without this flag set, a fresh profile launched with only
    # --no-first-run ended up on an ad/redirect page ("Redirecting... and 1 more page").
    # With bruhswer's flags it opens exactly the page that was asked for.
    "--disable-features=EdgeShoppingAssistant,EdgeCollections,MsaAutoSignIn",
    # Suppresses the "Restore pages" bubble after an unclean shutdown. It hides a
    # prompt; it disables no security control. Paired with session.restore_on_startup
    # so a crashed session never silently reopens the previous tabs.
    "--hide-crash-restore-bubble",
    # MEASURED, and added late: on a windowed launch with a BRAND-NEW profile, Edge
    # automatically signed in with the Windows account and recorded sync consent.
    # A fresh "disposable" profile came up already carrying the user's identity and
    # synced favourites - which made the disposable-session claim materially wrong.
    #
    # Measured on a fresh profile, windowed, twice:
    #     without this flag : account_info=1, email present, sync_consent=True
    #     with this flag    : account_info=1, email present, sync_consent=None
    #
    # So this stops the SYNC, and it is worth having for that alone. It does NOT stop
    # the sign-in: the account record is still written to the profile, and no
    # command-line switch prevents that. Only machine-wide Edge policy
    # (BrowserSignin=0) does, and bruhswer refuses to write policy that would change
    # every Edge instance on the PC. The residual is therefore reported as
    # NOT ENFORCEABLE by privacy_guard.verify_account_signin(), never hidden.
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
# There is NONE, and that is the design.
#
# An earlier iteration reserved a named pipe (\\.\pipe\bruhswer-control) and a verb
# allow-list here for a control channel between the UI and the controller. It was never
# built, because it was never needed: the UI and the controller run in the SAME Python
# process, so the UI calls Controller methods directly. Nothing has to be serialised,
# parsed, authenticated or authorised, so none of that can be got wrong.
#
# The reserved constants were deleted rather than kept "for later". Stage 4 measured
# that a compromised browser process can reach 127.0.0.1 and that no firewall rule
# stops it, so ANY local control endpoint is reachable by the exact thing bruhswer
# exists to contain. A dormant pipe name in config is an invitation to implement one;
# a documented refusal is not. tests/test_security.py asserts that bruhswer's source
# opens no listening socket and no named pipe at all.


def ensure_dirs() -> None:
    for p in (ROOT, PROFILE_PERSISTENT, PROFILE_DISPOSABLE_ROOT, QUARANTINE, LOGS, STATE):
        p.mkdir(parents=True, exist_ok=True)


def find_edge() -> Path | None:
    for p in EDGE_CANDIDATES:
        if p.is_file():
            return p
    return None
