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

# --- paths ---------------------------------------------------------------------
# All BRUHWSER state lives under one directory. Nothing is written anywhere else.
ROOT = Path(os.environ["LOCALAPPDATA"]) / "BRUHWSER"
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
