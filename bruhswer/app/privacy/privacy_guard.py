"""PrivacyGuard - reduce what websites learn, without making the browser unique.

A spoof that makes bruhswer MORE identifiable is rejected: a browser reporting 4 CPU
cores, a 1000x1000 screen and a UTC timezone on a Windows laptop is rarer than one
reporting the truth, and rarity is what fingerprinting feeds on. So nothing here spoofs
hardware, screen, timezone, locale, fonts, canvas, WebGL or the User-Agent. It turns
OFF collection surfaces and ON protections Edge already ships, which millions of Edge
users also run.

Written into bruhswer's OWN profile directory only. It never writes Edge enterprise
policy (HKCU\\Software\\Policies\\Microsoft\\Edge), which would change every Edge
instance on the machine, including the user's ordinary browsing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..logging_setup import get_logger

_log = get_logger("privacy")

# Sentinel returned by verify_applied when no session has ever run, so the caller can
# tell "not applied yet" apart from "applied and did not stick".
NO_PROFILE_YET = "<no session has run yet>"

# "The Preferences file exists and could not be parsed". Three different facts -
# not applied yet, unreadable, clean read - and collapsing any two of them is how this
# module produced a green light it had not earned.
PREFS_UNREADABLE = "<preferences unreadable>"


@dataclass(frozen=True)
class PrivacySetting:
    """One setting, with the reasoning the brief (SS29) requires for each."""

    key: str
    value: object
    reduces: str
    costs: str
    fingerprint_effect: str


# Chromium preference paths, applied to bruhswer's profile. Values chosen so the
# resulting configuration stays a COMMON one.
STANDARD: tuple[PrivacySetting, ...] = (
    PrivacySetting("profile.block_third_party_cookies", True,
                   "cross-site tracking cookies",
                   "a few sites with third-party logins may need an exception",
                   "neutral - widely used, and Edge is moving this way by default"),
    PrivacySetting("profile.cookie_controls_mode", 1,
                   "third-party cookies in normal browsing",
                   "same as above", "neutral"),
    PrivacySetting("enable_do_not_track", True,
                   "a request not to be tracked",
                   "voluntary and widely ignored",
                   "slightly identifying on its own, but extremely common"),
    PrivacySetting("profile.default_content_setting_values.geolocation", 2,
                   "physical location",
                   "map sites must be granted location manually",
                   "neutral - a denied permission looks the same as a declined prompt"),
    PrivacySetting("profile.default_content_setting_values.media_stream_camera", 2,
                   "camera access", "video calls need a manual grant", "neutral"),
    PrivacySetting("profile.default_content_setting_values.media_stream_mic", 2,
                   "microphone access", "voice calls need a manual grant", "neutral"),
    PrivacySetting("profile.default_content_setting_values.notifications", 2,
                   "notification prompts and a push identifier",
                   "no site notifications", "neutral"),
    PrivacySetting("profile.default_content_setting_values.sensors", 2,
                   "motion and orientation sensor readings", "almost nothing on a PC",
                   "neutral"),
    PrivacySetting("profile.default_content_setting_values.usb_guard", 2,
                   "USB device enumeration", "WebUSB apps stop working", "neutral"),
    PrivacySetting("profile.default_content_setting_values.bluetooth_guard", 2,
                   "Bluetooth device enumeration", "Web Bluetooth stops working",
                   "neutral"),
    PrivacySetting("profile.default_content_setting_values.serial_guard", 2,
                   "serial device access", "Web Serial stops working", "neutral"),
    PrivacySetting("profile.default_content_setting_values.clipboard", 2,
                   "silent clipboard reads", "paste buttons may need a manual grant",
                   "neutral"),
    PrivacySetting("safebrowsing.enabled", True,
                   "nothing - this is a SECURITY control, kept ON deliberately",
                   "sends URL metadata to Microsoft for malware and phishing checks",
                   "neutral"),
    PrivacySetting("autofill.profile_enabled", False,
                   "names, addresses and phone numbers offered to forms",
                   "no autofill", "neutral"),
    PrivacySetting("autofill.credit_card_enabled", False,
                   "stored card details", "no card autofill", "neutral"),
    PrivacySetting("payments.can_make_payment_enabled", False,
                   "whether a payment method exists - a real fingerprinting signal",
                   "Payment Request sites fall back to normal checkout", "improves"),
    PrivacySetting("search.suggest_enabled", False,
                   "every keystroke in the address bar going to a search provider",
                   "no inline search suggestions", "neutral"),
    PrivacySetting("alternate_error_pages.enabled", False,
                   "failed URLs sent to a suggestion service", "plain error pages",
                   "neutral"),
    PrivacySetting("webrtc.ip_handling_policy", "default_public_interface_only",
                   "local network IP addresses exposed to any page via WebRTC",
                   "some peer-to-peer calling may pick a slower path",
                   "improves - stops a LAN-address leak without disabling WebRTC"),
    PrivacySetting("webrtc.multiple_routes_enabled", False,
                   "additional local candidate addresses", "as above", "improves"),
    PrivacySetting("webrtc.nonproxied_udp_enabled", False,
                   "UDP paths that bypass configured proxying", "as above", "improves"),
)

# Maximum Privacy adds only things that are still COMMON configurations.
MAXIMUM_EXTRA: tuple[PrivacySetting, ...] = (
    PrivacySetting("profile.default_content_setting_values.cookies", 4,
                   "all cookies discarded when the session ends",
                   "you are signed out of everything each time",
                   "neutral"),
    PrivacySetting("profile.default_content_setting_values.javascript_jit", 2,
                   "JIT-based exploit surface - a SECURITY gain, not privacy",
                   "heavy web apps run noticeably slower",
                   "neutral"),
)

# Deliberately REJECTED. Recorded so the reasoning is auditable rather than implied.
REJECTED: tuple[tuple[str, str], ...] = (
    ("User-Agent override",
     "A non-standard UA is rarer than the real one and is trivially contradicted by "
     "feature detection, so it increases entropy instead of reducing it."),
    ("Screen resolution spoofing",
     "Reported size then disagrees with the actual window, which is itself a signal."),
    ("Timezone / locale spoofing",
     "Contradicts HTTP language headers and observable latency; makes the "
     "profile rarer."),
    ("Canvas / WebGL noise injection",
     "Detectable as noise, and unstable output is a stronger identifier than a common "
     "GPU string. Needs engine support Edge does not expose to us."),
    ("hardware_concurrency / device memory spoofing",
     "Cannot be applied consistently from outside the engine; partial spoofing is "
     "worse than none."),
    ("Disabling WebRTC entirely",
     "Breaks video calling for a leak that ip_handling_policy already closes."),
    ("Disabling Safe Browsing",
     "Trades real malware protection for a marginal metadata gain. Brief SS30 and the "
     "project's own rules forbid it."),
    ("Forcing session.restore_on_startup as a preference",
     "MEASURED: Edge rewrites it on every launch - 21 of 22 settings stuck, this one "
     "never did, across three consecutive sessions. Same class as the password-manager "
     "preference below. bruhswer solves the problem the browser cannot object to "
     "instead: it closes the window with a real WM_CLOSE so the profile is never marked "
     "as crashed, and passes --hide-crash-restore-bubble, which is a launch flag Edge "
     "cannot revert."),
    ("Disabling the browser password manager (credentials_enable_service)",
     "MEASURED: Chromium treats this as a tracked preference and reverts an externally "
     "written value. That protection exists to stop malware silently reconfiguring the "
     "browser, and it is working correctly. The only way around it is machine-wide Edge "
     "policy, which would change every Edge profile on the PC - far broader than "
     "bruhswer is allowed to be. Turn it off in Edge's own settings inside a bruhswer "
     "session if you want it off in persistent mode; disposable sessions discard it "
     "anyway."),
)


def settings_for(mode: str) -> tuple[PrivacySetting, ...]:
    return STANDARD + MAXIMUM_EXTRA if mode == "maximum" else STANDARD


def _write_prefs(prefs_path: Path, prefs: dict) -> bool:
    """Replace Preferences atomically. False if the filesystem refused.

    Never raises: the callers run inside Controller.start(), which has no handler,
    and the read-back checks are what report a write that did not land.
    """
    tmp = prefs_path.with_suffix(".bruhswer-tmp")
    try:
        tmp.write_text(json.dumps(prefs, separators=(",", ":")), encoding="utf-8")
        tmp.replace(prefs_path)
    except OSError as exc:
        _log.error("could not write Preferences: %s", exc.__class__.__name__)
        tmp.unlink(missing_ok=True)
        return False
    return True


def _read_prefs(prefs_path: Path) -> dict | None:
    """The parsed Preferences object, or None if it could not be read as one.

    A file that parses to a list, a string or null is as unreadable as one that does
    not parse at all: every caller indexes it as a mapping, and those reached the
    callers as an AttributeError instead of the "could not look" answer they render.
    """
    try:
        prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return prefs if isinstance(prefs, dict) else None


def _assign(tree: dict, dotted: str, value: object) -> None:
    parts = dotted.split(".")
    node = tree
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):  # a scalar already sits here; do not clobber
            return
    node[parts[-1]] = value


def apply_to_profile(profile_dir: Path, mode: str) -> int:
    """Write privacy preferences into the profile. Returns how many were written.

    Chromium owns this file while it runs, so this must happen BEFORE launch. Chromium
    may also normalise or drop entries it does not recognise -- which is why
    `verify_applied` reads the file back rather than assuming success.
    """
    default_dir = profile_dir / "Default"
    default_dir.mkdir(parents=True, exist_ok=True)
    prefs_path = default_dir / "Preferences"

    prefs = _read_prefs(prefs_path)
    if prefs is None:
        if prefs_path.is_file():
            _log.warning("existing Preferences unreadable; writing a fresh file")
        prefs = {}

    chosen = settings_for(mode)
    for setting in chosen:
        _assign(prefs, setting.key, setting.value)

    if not _write_prefs(prefs_path, prefs):
        return 0
    _log.info("applied %d privacy settings in %s mode", len(chosen), mode)
    return len(chosen)


def apply_download_directory(profile_dir: Path, download_dir: Path) -> None:
    """Point the browser's downloads at bruhswer's quarantine.

    A PREFERENCE, NOT A FLAG. `--download-directory=` is not a real Chromium switch;
    Edge ignored it silently and downloads went to the user's real Downloads folder, so
    the quarantine claim was false while every test passed. Found with a download
    probe, not by reading.

    `download.prompt_for_download = False` matters as much as the directory: with a
    prompt the user could steer a hostile download anywhere.
    """
    default_dir = profile_dir / "Default"
    default_dir.mkdir(parents=True, exist_ok=True)
    prefs_path = default_dir / "Preferences"

    prefs = _read_prefs(prefs_path) or {}

    target = str(download_dir)
    _assign(prefs, "download.default_directory", target)
    _assign(prefs, "download.prompt_for_download", False)
    _assign(prefs, "download.directory_upgrade", True)
    _assign(prefs, "savefile.default_directory", target)

    if _write_prefs(prefs_path, prefs):
        _log.info("download directory pointed at quarantine")


def verify_download_directory(profile_dir: Path, download_dir: Path) -> tuple[bool, str]:
    """Read it back. 'We wrote it' is not evidence - see the note above."""
    prefs_path = profile_dir / "Default" / "Preferences"
    if not prefs_path.is_file():
        return False, "no profile yet"
    prefs = _read_prefs(prefs_path)
    if prefs is None:
        # "Could not read the file" is not "downloads are not quarantined". The caller
        # must not turn a locked or mid-rewrite Preferences file into a critical FAIL.
        return False, PREFS_UNREADABLE

    download = prefs.get("download", {})
    if not isinstance(download, dict):
        return False, PREFS_UNREADABLE
    got = download.get("default_directory")
    prompt = download.get("prompt_for_download")
    if got != str(download_dir):
        return False, f"download directory is {got!r}, expected {str(download_dir)!r}"
    if prompt is not False:
        return False, "browser would prompt for a save location"
    return True, "downloads are directed to quarantine"


def verify_account_signin(profile_dir: Path) -> tuple[bool, str]:
    """Is a Microsoft account signed into this profile? Returns (signed_in, detail).

    This exists because the answer turned out to be yes. A brand-new DISPOSABLE session
    opened with the developer's Microsoft account signed in and their favourites
    synced; the profile held an email, full name, account id and tenant id. So a
    disposable session is fresh, but Edge repopulates it with the user's identity
    within seconds of launch.

    `--disable-sync` stops the syncing; nothing on the command line stops the SIGN-IN,
    so this reads the profile rather than assuming the flag was enough. The caller
    renders it NOT ENFORCEABLE - the only control that works is machine-wide Edge
    policy. The remedy is to sign out inside the session, in Edge's Settings > Profiles.
    """
    prefs_path = profile_dir / "Default" / "Preferences"
    if not prefs_path.is_file():
        return False, "no profile yet"
    prefs = _read_prefs(prefs_path)
    if prefs is None:
        # A sentinel, not a bare False. "Could not read the file" used to reach the
        # caller in the same (False, ...) shape as "read it, found no account", so a
        # locked or mid-rewrite Preferences file produced a GREEN privacy light
        # asserting a fact nobody had established. UNKNOWN is acceptable here; green
        # is not.
        return False, PREFS_UNREADABLE

    accounts = prefs.get("account_info") or []
    if not isinstance(accounts, list):
        return False, PREFS_UNREADABLE
    signed_in = any(isinstance(a, dict) and a.get("email") for a in accounts)
    sync_consent = bool(prefs.get("sync_consent_recorded"))

    if not signed_in:
        return False, "No Microsoft account is signed into this profile."
    # The email itself is NEVER returned or logged - only the fact that one is there.
    return True, (f"{len(accounts)} Microsoft account(s) signed in"
                  + (" and sync consent is recorded" if sync_consent
                     else "; sync is disabled") + ".")


def verify_applied(profile_dir: Path, mode: str) -> tuple[int, int, list[str]]:
    """Read the profile back. Returns (applied, expected, list of settings that did not
    stick). Chromium rewrites this file, so 'we wrote it' is not evidence."""
    prefs_path = profile_dir / "Default" / "Preferences"
    if not prefs_path.is_file():
        # Not a failure: settings are written at launch, so before the first session
        # there is simply nothing to read. The caller distinguishes this case.
        return 0, len(settings_for(mode)), [NO_PROFILE_YET]
    prefs = _read_prefs(prefs_path)
    if prefs is None:
        return 0, len(settings_for(mode)), ["Preferences file unreadable"]

    missing: list[str] = []
    applied = 0
    for setting in settings_for(mode):
        node: object = prefs
        for part in setting.key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                node = None
                break
        if node == setting.value:
            applied += 1
        else:
            missing.append(setting.key)
    return applied, len(settings_for(mode)), missing
