"""Edge runtime — discovery, verification, and launch with a fixed argument list.

bruhswer does NOT implement a browser. No HTML parser, no JavaScript engine, no CSS
engine, no network stack, no sandbox of its own (brief SS4). Microsoft Edge provides all
of that, and Stage 4 measured why it is the right base on this machine:

  A3  Edge renderers run on AppContainer tokens at UNTRUSTED integrity with ZERO
      privileges. Chrome's renderers on this machine were restricted but NOT
      AppContainer -- measurably one mechanism short.
  B17 Edge is in-box and Microsoft-signed, so it adds no new supply-chain trust root.
      That is the same test that rejected the QEMU binaries.

What Edge does NOT give us, and this module must never imply otherwise: the browser
process itself runs as an ordinary user process (Stage 4 gate A4). Chromium's sandbox
contains renderers, not the broker.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .. import config, sysquery
from ..logging_setup import get_logger
from ..verdict import Check, Verdict

_log = get_logger("edge")

# The one non-http target bruhswer ever passes. A literal, never derived from input.
BLANK = "about:blank"


def verify_runtime(edge_path: Path | None) -> list[Check]:
    """Is the browser we are about to launch the one we expect?"""
    checks: list[Check] = []

    if edge_path is None:
        checks.append(Check(
            "edge.present", "Browser runtime found", Verdict.FAIL, critical=True,
            detail="Microsoft Edge was not found at any expected location.",
            evidence=f"searched={[str(p) for p in config.EDGE_CANDIDATES]}"))
        return checks

    checks.append(Check(
        "edge.present", "Browser runtime found", Verdict.PASS, critical=True,
        detail=f"Microsoft Edge at {edge_path}", evidence=str(edge_path)))

    # The path is one of bruhswer's own constants, already confirmed to exist, so
    # nothing external reaches this query.
    raw = sysquery.authenticode(str(edge_path))
    if not isinstance(raw, dict):
        checks.append(Check(
            "edge.signature", "Browser is signed by Microsoft", Verdict.UNKNOWN,
            critical=True, detail="Could not read the Authenticode signature.",
            evidence="signature query returned nothing"))
        return checks

    status = str(raw.get("Status", ""))
    subject = str(raw.get("Subject", ""))
    trusted = status == "Valid" and config.EDGE_EXPECTED_SUBJECT_CN in subject
    checks.append(Check(
        "edge.signature", "Browser is signed by Microsoft",
        Verdict.PASS if trusted else Verdict.FAIL, critical=True,
        detail=(f"Signature {status}, signed by {config.EDGE_EXPECTED_SUBJECT_CN}."
                if trusted else
                f"Signature status {status!r}; expected a valid Microsoft signature."),
        evidence=f"status={status} subject={subject[:80]}"))
    return checks


def build_command(edge_path: Path, profile_dir: Path, extra_flags: tuple[str, ...],
                  url: str | None = None) -> list[str]:
    """Build the argv list. Explicit list, never a string, never a shell.

    `url` is only ever a bruhswer constant or a value the USER typed into bruhswer's own
    UI. It is never taken from page content, a download, or an IPC message -- and even
    then it is passed as a distinct argv element, so it cannot become another flag.
    """
    argv = [str(edge_path), f"--user-data-dir={profile_dir}"]
    argv.extend(config.BASE_EDGE_FLAGS)
    argv.extend(extra_flags)

    for flag in argv[1:]:
        for bad in config.DANGEROUS_FLAGS:
            if flag.startswith(bad):
                raise ValueError(f"refusing to launch with {bad}")

    if url:
        # "about:blank" is a bruhswer literal used for profile seeding - it loads
        # nothing, contacts nothing, and resolves nothing. Everything else must be
        # http(s), which excludes file://, javascript:, data: and UNC paths.
        if url != BLANK and not (url.startswith("https://") or url.startswith("http://")):
            raise ValueError("only http(s) URLs may be passed to the browser")
        argv.append(url)
    return argv


def launch(argv: list[str]) -> subprocess.Popen[bytes]:
    """Start Edge. shell=False, explicit argv, no environment inheritance games."""
    _log.info("launching browser runtime with %d arguments", len(argv))
    return subprocess.Popen(argv, shell=False, close_fds=True,
                            creationflags=config.NO_WINDOW)


def open_in_running_session(edge_path: Path, profile_dir: Path, url: str) -> bool:
    """Open a URL as a NEW TAB in the session that is already running.

    Chromium hands a URL to the instance already using that profile instead of starting
    a second browser. Measured: window count unchanged, same HWND, title updated - so
    this is a real tab, not a new window.

    This is how bruhswer's address bar navigates. It needs no DevTools port, no
    automation channel and no localhost listener - the three things brief SS25 forbids -
    and the URL travels as its own argv element, so it cannot become a flag.
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
