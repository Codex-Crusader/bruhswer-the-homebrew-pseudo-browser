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
from ..verdict import (Check, EvidenceKind, UnknownReason, Verdict,
                       reason_for_probe)

_log = get_logger("edge")

# THE NON-HTTP TARGETS BRUHSWER MAY PASS. Exactly two, both literals authored here,
# neither ever derived from input.
#
# This used to read "the one non-http target bruhswer ever passes" and name only
# about:blank. That invariant is AMENDED, not quietly bypassed, because a second one
# now exists and leaving the old sentence in place would make this file lie about its
# own behaviour.
#
# The addition is edge://settings/profiles, and the reason is specific. Edge signs even
# a brand-new disposable profile into the user's Microsoft account by itself; bruhswer
# measures that and reports it, but until now the remedy was a sentence in the docs
# telling the user to go and find a settings page. This constant makes the remedy a
# button.
#
# WHAT IS *NOT* RELAXED, and this is the part that matters:
#   - `urls.py` is untouched. `edge:` remains in its _FORBIDDEN_SCHEMES, so the address
#     bar still refuses it. Nothing a user types and nothing a page supplies can reach
#     this target.
#   - membership below is tested by EXACT EQUALITY, never a prefix or a startswith. A
#     prefix test would admit edge://settings/profiles/../../whatever.
#   - only Controller.open_account_settings() passes it, with no argument, so there is
#     no call path that lets a caller choose the value.
BLANK = "about:blank"
PROFILES_SETTINGS = "edge://settings/profiles"

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

    # LIVE: config.find_edge() stat'd this path during this pass.
    checks.append(Check(
        "edge.present", "Browser runtime found", Verdict.PASS, critical=True,
        detail=f"Microsoft Edge at {edge_path}", evidence=str(edge_path),
        evidence_kind=EvidenceKind.LIVE))

    # The path is one of bruhswer's own constants, already confirmed to exist, so
    # nothing external reaches this query.
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

    # NOT trusted. Before calling that a FAIL, distinguish "this binary is wrong" from
    # "this binary is being replaced right now".
    #
    # Edge updates itself in the background. During the swap the on-disk image can be
    # zero length or momentarily unsigned, and the previous version is left beside it
    # as a `.old` sibling. bruhswer would report "Signature status 'UnknownError';
    # expected a valid Microsoft signature" - which reads like a compromised browser
    # and sends the user looking for an attack that is not there.
    #
    # WORDING IS DELIBERATE, and this is the honest limit of the evidence: a zero-byte
    # binary and a `.old` sibling are CONSISTENT with an update, they do not establish
    # one. The same state is what a half-finished tamper looks like. So the check says
    # the signature could not be verified and offers the update as a likely reason -
    # it does not assert that an update is in progress.
    #
    # The verdict stays UNKNOWN and stays critical, so launch is still blocked. Only
    # the explanation changes; the safety posture does not.
    # BOTH conditions, and the conjunction is the point. A signature that is VALID but
    # belongs to the wrong signer is a definite, established finding - somebody else's
    # signed binary is sitting at Edge's path - and it must stay FAIL even if a stray
    # .tmp file happens to be in that directory. Only an INCONCLUSIVE status is
    # eligible to be re-read as "swap in progress".
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
            # The signature really was read; it came back inconclusive. That is a
            # different admission from a query that never completed.
            unknown_reason=UnknownReason.MALFORMED_OUTPUT))
        return checks

    checks.append(Check(
        "edge.signature", "Browser is signed by Microsoft", Verdict.FAIL, critical=True,
        detail=f"Signature status {status!r}; expected a valid Microsoft signature.",
        evidence=f"status={status} subject={subject[:80]} signs=none",
        evidence_kind=EvidenceKind.LIVE))
    return checks


# Authenticode statuses that mean "could not establish", as opposed to "established and
# it is wrong". A NotSigned/UnknownError on a file that is also mid-swap is the update
# case; the same status on a stable file is a genuine failure.
_INCONCLUSIVE_SIGNATURE_STATUSES = ("UnknownError", "NotSigned", "Incompatible")


def _update_in_progress_signs(edge_path: Path) -> list[str]:
    """Observable, checkable facts consistent with Edge replacing its own binary.

    Returns the list of signs found, so the evidence string records WHAT was observed
    rather than a bare boolean. Never raises: a filesystem that refuses to answer is
    simply no evidence, which is not the same as evidence of nothing.
    """
    signs: list[str] = []
    try:
        if edge_path.stat().st_size == 0:
            signs.append("binary is zero bytes")
    except OSError:
        signs.append("binary could not be stat'd")

    try:
        # Chromium's updater stages the outgoing image beside the new one.
        if any(edge_path.parent.glob("msedge.exe.old")):
            signs.append("msedge.exe.old present")
        # A new version lands in a sibling directory named for its version, and the
        # updater's own temp files sit alongside it during the swap.
        if any(edge_path.parent.glob("*.tmp")):
            signs.append("updater temp file present")
    except OSError:
        pass
    return signs


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
        # EXACT membership, never a prefix test. `url.startswith(PROFILES_SETTINGS)`
        # would admit edge://settings/profiles<anything>, which is a different page and
        # possibly a different origin. Everything not in that two-item allowlist must
        # be http(s), which excludes file://, javascript:, data: and UNC paths.
        if url not in _ALLOWED_NON_HTTP and not (
                url.startswith("https://") or url.startswith("http://")):
            raise ValueError("only http(s) URLs may be passed to the browser")
        argv.append(url)
    return argv


def open_account_settings(edge_path: Path, profile_dir: Path) -> bool:
    """Open Edge's own profile settings page in the running session, as a new tab.

    This is the ONLY caller of PROFILES_SETTINGS, and it takes no URL argument - the
    target is a constant compiled into this function, so there is no path by which a
    caller, a page, or a user could choose a different edge:// destination.

    IT DOES NOT SIGN ANYONE OUT, and no caller may report that it did. It opens the
    page where the user can do that themselves. Whether an account is still attached is
    a separate question, answered only by re-reading the profile - which
    privacy_guard.verify_account_signin does on the next verification pass.
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
