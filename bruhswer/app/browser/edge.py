"""Edge runtime - discovery, verification, and launch with a fixed argument list.

bruhswer implements no browser: no HTML parser, no JavaScript engine, no network stack,
no sandbox of its own. Edge provides all of it, runs its renderers on AppContainer
tokens at UNTRUSTED integrity, and is in-box and Microsoft-signed, so it adds no new
supply-chain trust root.

What Edge does NOT give us, and this module must never imply otherwise: the browser
process itself runs as an ordinary user process. Chromium's sandbox contains renderers,
not the broker.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .. import config, sysquery
from ..logging_setup import get_logger
from ..verdict import (Check, EvidenceKind, UnknownReason, Verdict,
                       reason_for_probe)

_log = get_logger("edge")

# The only two non-http targets bruhswer may pass, both literals authored here and
# never derived from input. edge://settings/profiles exists because Edge signs even a
# disposable profile into the user's account, and this makes the remedy a button.
#
# What is NOT relaxed: `edge:` stays in urls.py's _FORBIDDEN_SCHEMES, so nothing typed
# or supplied by a page reaches it; membership is tested by EXACT EQUALITY, never a
# prefix, which would admit edge://settings/profiles/../../whatever; and only
# Controller.open_account_settings() passes it, with no argument.
BLANK = "about:blank"
PROFILES_SETTINGS = "edge://settings/profiles"
_DISABLE_FEATURES = "--disable-features="

_ALLOWED_NON_HTTP = (BLANK, PROFILES_SETTINGS)


def verify_runtime(edge_path: Path | None) -> list[Check]:
    """Is the browser we are about to launch the one we expect?"""
    checks: list[Check] = []

    if edge_path is None:
        checks.append(Check(
            "edge.present", "Browser runtime found", Verdict.FAIL, critical=True,
            detail="Microsoft Edge was not found at any expected location.",
            evidence=f"searched={[str(p) for p in config.EDGE_CANDIDATES]}",
            evidence_kind=EvidenceKind.LIVE))
        return checks

    checks.append(Check(
        "edge.present", "Browser runtime found", Verdict.PASS, critical=True,
        detail=f"Microsoft Edge at {edge_path}", evidence=str(edge_path),
        evidence_kind=EvidenceKind.LIVE))

    probe = sysquery.authenticode(str(edge_path))
    raw = probe.value
    if not isinstance(raw, dict):
        checks.append(Check(
            "edge.signature", "Browser is signed by Microsoft", Verdict.UNKNOWN,
            critical=True,
            detail=("bruhswer could not read the browser's Authenticode signature, so "
                    "it cannot confirm the program it is about to launch is the one "
                    "Microsoft shipped."),
            evidence=probe.reason(),
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=(reason_for_probe(probe.status) if not probe.ok
                            else UnknownReason.MALFORMED_OUTPUT)))
        return checks

    status = str(raw.get("Status", ""))
    subject = str(raw.get("Subject", ""))
    trusted = status == "Valid" and config.EDGE_EXPECTED_SUBJECT_CN in subject
    if trusted:
        checks.append(Check(
            "edge.signature", "Browser is signed by Microsoft", Verdict.PASS,
            critical=True,
            detail=f"Signature {status}, signed by {config.EDGE_EXPECTED_SUBJECT_CN}.",
            evidence=f"status={status} subject={subject[:80]} {probe.reason()}",
            evidence_kind=EvidenceKind.LIVE))
        return checks

    # Edge updates itself in the background, and during the swap the on-disk image can
    # be zero length or momentarily unsigned - which otherwise reads like a compromised
    # browser. Those signs are CONSISTENT with an update, they do not establish one, so
    # the verdict stays UNKNOWN and stays critical; only the explanation changes.
    #
    # Both conditions, and the conjunction is the point: a VALID signature belonging to
    # the wrong signer is an established finding and stays FAIL even with a stray .tmp
    # in the directory. Only an inconclusive status may be re-read as a swap.
    update_signs = (_update_in_progress_signs(edge_path)
                    if status in _INCONCLUSIVE_SIGNATURE_STATUSES else [])
    if update_signs:
        checks.append(Check(
            "edge.signature", "Browser is signed by Microsoft", Verdict.UNKNOWN,
            critical=True,
            detail=("The browser's signature could not be verified. Edge may be part "
                    "way through updating itself, which briefly leaves the program "
                    "file in this state. Wait a minute and check again. If it does "
                    "not clear, do not use this browser."),
            evidence=f"status={status} subject={subject[:80]} signs={update_signs}",
            evidence_kind=EvidenceKind.LIVE,
            # Read, and inconclusive. Different from a query that never completed.
            unknown_reason=UnknownReason.MALFORMED_OUTPUT))
        return checks

    checks.append(Check(
        "edge.signature", "Browser is signed by Microsoft", Verdict.FAIL, critical=True,
        detail=f"Signature status {status!r}; expected a valid Microsoft signature.",
        evidence=f"status={status} subject={subject[:80]} signs=none",
        evidence_kind=EvidenceKind.LIVE))
    return checks


# "Could not establish", as opposed to "established and it is wrong".
_INCONCLUSIVE_SIGNATURE_STATUSES = ("UnknownError", "NotSigned", "Incompatible")


def _update_in_progress_signs(edge_path: Path) -> list[str]:
    """Facts consistent with Edge replacing its own binary, as a list of what was seen.

    Never raises: a filesystem that refuses to answer is no evidence, which is not the
    same as evidence of nothing.
    """
    signs: list[str] = []
    try:
        if edge_path.stat().st_size == 0:
            signs.append("binary is zero bytes")
    except OSError:
        signs.append("binary could not be stat'd")

    try:
        if any(edge_path.parent.glob("msedge.exe.old")):
            signs.append("msedge.exe.old present")
        if any(edge_path.parent.glob("*.tmp")):
            signs.append("updater temp file present")
    except OSError:
        pass
    return signs


def _merge_disable_features(argv: list[str]) -> list[str]:
    """Collapse repeated --disable-features switches into one, order preserved.

    Chromium keeps a single value per switch name, so emitting the switch twice
    discards one set entirely rather than combining them.
    """
    features: list[str] = []
    out: list[str] = []
    for arg in argv:
        if arg.startswith(_DISABLE_FEATURES):
            features.extend(name for name
                            in arg[len(_DISABLE_FEATURES):].split(",") if name)
        else:
            out.append(arg)
    if features:
        out.append(_DISABLE_FEATURES + ",".join(dict.fromkeys(features)))
    return out


def build_command(edge_path: Path, profile_dir: Path, extra_flags: tuple[str, ...],
                  url: str | None = None) -> list[str]:
    """Build the argv list. Explicit list, never a string, never a shell.

    `url` is only ever a bruhswer constant or a value the user typed into bruhswer's
    own UI, and travels as a distinct argv element so it cannot become another flag.
    """
    argv = [str(edge_path), f"--user-data-dir={profile_dir}"]
    argv.extend(config.BASE_EDGE_FLAGS)
    argv.extend(extra_flags)

    for flag in argv[1:]:
        for bad in config.DANGEROUS_FLAGS:
            if flag.startswith(bad):
                raise ValueError(f"refusing to launch with {bad}")

    argv = _merge_disable_features(argv)

    if url:
        # Exact membership, never a prefix test. Everything outside the two-item
        # allowlist must be http(s), which excludes file://, javascript: and data:.
        if url not in _ALLOWED_NON_HTTP and not (
                url.startswith("https://") or url.startswith("http://")):
            raise ValueError("only http(s) URLs may be passed to the browser")
        argv.append(url)
    return argv


def open_account_settings(edge_path: Path, profile_dir: Path) -> bool:
    """Open Edge's own profile settings page in the running session, as a new tab.

    The only caller of PROFILES_SETTINGS, and it takes no URL argument, so no call path
    lets anyone choose a different edge:// destination.

    IT DOES NOT SIGN ANYONE OUT, and no caller may report that it did. Whether an
    account is still attached is answered only by re-reading the profile, which
    privacy_guard.verify_account_signin does on the next pass.
    """
    argv = build_command(edge_path, profile_dir, (), PROFILES_SETTINGS)
    try:
        subprocess.run(argv, capture_output=True, timeout=30, shell=False,
                       creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _log.warning("could not open account settings: %s", exc.__class__.__name__)
        return False
    _log.info("opened the browser's account settings page")
    return True


def launch(argv: list[str]) -> subprocess.Popen[bytes]:
    """Start Edge. shell=False, explicit argv, no environment inheritance games."""
    _log.info("launching browser runtime with %d arguments", len(argv))
    return subprocess.Popen(argv, shell=False, close_fds=True,
                            creationflags=config.NO_WINDOW)


def open_in_running_session(edge_path: Path, profile_dir: Path, url: str) -> bool:
    """Open a URL as a NEW TAB in the session that is already running.

    Chromium hands the URL to the instance already using that profile. Measured: window
    count unchanged, same HWND, title updated - a real tab, not a new window. Needs no
    DevTools port, no automation channel and no localhost listener.
    """
    argv = build_command(edge_path, profile_dir, (), url)
    try:
        subprocess.run(argv, capture_output=True, timeout=30, shell=False,
                       creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _log.warning("navigation failed: %s", exc.__class__.__name__)
        return False
    _log.info("navigated the running session to a new tab")
    return True
