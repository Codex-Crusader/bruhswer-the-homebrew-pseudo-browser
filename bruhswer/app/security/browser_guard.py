"""BrowserGuard: the browser's data stays in bruhswer's own, ACL-tightened profile.

Not a sandbox: the browser process runs on the user's token and can read the whole
user profile (gate A4).
"""

from __future__ import annotations

import getpass
import subprocess
from collections.abc import Sequence
from pathlib import Path

from .. import config
from ..browser import tokens
from ..logging_setup import get_logger
from ..verdict import Check, EvidenceKind, UnknownReason, Verdict

_log = get_logger("browserguard")


def harden_profile_dir(profile_dir: Path) -> tuple[bool, str]:
    """Restrict the profile folder to this user. No `/T`: with it, icacls returned 0
    while every file lost access. The folder's (OI)(CI) grant reaches children anyway."""
    profile_dir.mkdir(parents=True, exist_ok=True)
    user = getpass.getuser()
    try:
        proc = subprocess.run(
            [str(config.ICACLS), str(profile_dir),
             "/inheritance:r",
             "/grant", f"{user}:(OI)(CI)F",
             "/grant", "*S-1-5-18:(OI)(CI)F",   # SYSTEM, so Windows can service it
             "/Q"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, shell=False, creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"ACL hardening failed: {exc.__class__.__name__}"
    if proc.returncode != 0:
        return False, "ACL hardening reported errors."

    # icacls returning 0 is not proof; read the profile back.
    ok, detail = _profile_is_readable(profile_dir)
    if not ok:
        return False, f"ACL hardening left the profile unusable: {detail}"
    return True, "Profile folder restricted to this user account."


def _profile_is_readable(profile_dir: Path) -> tuple[bool, str]:
    """Can bruhswer still read and write inside the profile after hardening?"""
    probe = profile_dir / ".bruhswer-acl-probe"
    try:
        probe.write_text("probe", encoding="utf-8")
        probe.read_text(encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return False, f"{exc.__class__.__name__} on a write/read probe"

    prefs = profile_dir / "Default" / "Preferences"
    if prefs.is_file():
        try:
            prefs.read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"{exc.__class__.__name__} reading Preferences"
    return True, "readable"


def _read_acl(profile_dir: Path) -> str:
    try:
        proc = subprocess.run([str(config.ICACLS), str(profile_dir)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60, shell=False,
                              creationflags=config.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


def _is_within(candidate: Path, ancestor: Path) -> bool:
    """True if candidate is ancestor or under it. Both sides resolved (8.3 names,
    junctions) and lowered (Windows paths are case-insensitive)."""
    try:
        here = Path(str(_resolved(candidate)).lower())
        there = Path(str(_resolved(ancestor)).lower())
        return here == there or here.is_relative_to(there)
    except (OSError, ValueError):
        return False


def _resolved(path: Path) -> Path:
    """resolve() where possible, the original path where the filesystem refuses."""
    try:
        return path.resolve()
    except (OSError, ValueError):
        return path


def verify(profile_dir: Path, argv: list[str]) -> list[Check]:
    checks: list[Check] = []
    root = config.ROOT.resolve()

    # --- profile confinement ----------------------------------------------------
    try:
        resolved = profile_dir.resolve()
        inside = resolved.is_relative_to(root)
    except OSError:
        resolved, inside = profile_dir, False

    checks.append(Check(
        "browser.profile.location", "Browser profile is inside bruhswer",
        Verdict.PASS if inside else Verdict.FAIL, critical=True,
        detail=(f"Profile is at {resolved}." if inside else
                "Profile points outside the bruhswer folder. Launch blocked."),
        evidence=f"profile={resolved} root={root}",
        evidence_kind=EvidenceKind.LIVE))

    # --- the browser must not be pointed at the user's real profiles ------------
    local_appdata = config.ROOT.parent
    forbidden_parents = [
        local_appdata / "Microsoft" / "Edge" / "User Data",
        local_appdata / "Google" / "Chrome" / "User Data",
    ]
    # Ancestry, not string prefix: "User Data-Evil" starts with "User Data".
    collides = any(_is_within(resolved, p) for p in forbidden_parents)
    checks.append(Check(
        "browser.profile.separate", "Separate from your normal browser profile",
        Verdict.PASS if not collides else Verdict.FAIL, critical=True,
        detail=("bruhswer uses its own profile; your everyday browser data is untouched."
                if not collides else "Profile overlaps your normal browser data."),
        evidence=f"collides={collides}",
        evidence_kind=EvidenceKind.LIVE))

    # --- ACL ---------------------------------------------------------------------
    acl = _read_acl(profile_dir)
    if not acl:
        checks.append(Check(
            "browser.profile.acl", "Profile folder permissions", Verdict.UNKNOWN,
            critical=False,
            detail=("bruhswer could not read the profile folder's permissions, so it "
                    "cannot say who else can reach the browsing data."),
            evidence="icacls returned nothing",
            evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=UnknownReason.UNREADABLE))
    else:
        broad = [token for token in ("Everyone", "BUILTIN\\Users",
                                     "ALL APPLICATION PACKAGES")
                 if token in acl]
        checks.append(Check(
            "browser.profile.acl", "Profile folder permissions",
            Verdict.PASS if not broad else Verdict.FAIL, critical=False,
            detail=("Restricted to your account." if not broad else
                    f"Readable by: {', '.join(broad)}"),
            evidence=f"broad_principals={broad}",
            evidence_kind=EvidenceKind.READ_BACK))

    # --- command line -------------------------------------------------------------
    found_dangerous = [flag for flag in argv[1:]
                       for bad in config.DANGEROUS_FLAGS if flag.startswith(bad)]
    checks.append(Check(
        "browser.cmdline", "No security-weakening browser flags",
        Verdict.PASS if not found_dangerous else Verdict.FAIL, critical=True,
        detail=("The browser is started with its sandbox and TLS checks intact."
                if not found_dangerous else
                f"Refusing these flags: {found_dangerous}"),
        evidence=f"dangerous={found_dangerous}",
        # INFERENCE: inspects the argv bruhswer built; asks Windows nothing.
        evidence_kind=EvidenceKind.INFERENCE))

    profile_flags = [a for a in argv if a.startswith("--user-data-dir=")]
    checks.append(Check(
        "browser.cmdline.profile", "Browser told to use exactly one profile",
        Verdict.PASS if len(profile_flags) == 1 else Verdict.FAIL, critical=True,
        detail=("One profile directory specified." if len(profile_flags) == 1
                else f"{len(profile_flags)} profile arguments found."),
        evidence=f"count={len(profile_flags)}",
        evidence_kind=EvidenceKind.INFERENCE))

    # --- the boundary that actually exists, stated accurately ---------------------
    weakening = [flag for flag in found_dangerous
                 if flag.startswith(("--no-sandbox", "--disable-gpu-sandbox",
                                     "--disable-site-isolation-trials"))]
    checks.append(Check(
        "browser.sandbox.flags", "Browser started with its sandbox intact",
        Verdict.PASS if not weakening else Verdict.FAIL, critical=False,
        detail=("bruhswer passed no flag that weakens the renderer sandbox. "
                "Whether the sandbox is actually in force is measured separately, "
                "from the live processes."
                if not weakening else
                f"Sandbox-weakening flags on the command line: {weakening}"),
        evidence=f"weakening={weakening}",
        evidence_kind=EvidenceKind.INFERENCE))

    return checks


def verify_renderer_sandbox(
        renderer_pids: Sequence[int] | None) -> list[Check]:
    """Measure the renderers' tokens; the sandbox is build-dependent. None = the query
    failed, [] = no renderers, otherwise measure them."""
    if renderer_pids is None:
        return [Check(
            "browser.sandbox", "Renderer sandbox (measured)", Verdict.UNKNOWN,
            critical=False,
            detail=("bruhswer could not ask Windows which renderer processes are "
                    "running, so it cannot say whether page content is contained. "
                    "This is a failed measurement, not a finding about the browser."),
            evidence="renderer pid query failed",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.PROBE_ERROR)]

    if not renderer_pids:
        return [Check(
            "browser.sandbox", "Renderer sandbox (measured)", Verdict.UNKNOWN,
            critical=False,
            detail="No renderer processes were found to measure.",
            evidence="no renderer pids",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.NO_SESSION)]

    facts = tokens.summarise_renderers(renderer_pids)
    measured = facts["measured"]
    unreadable = facts["unreadable"]
    if measured == 0:
        return [Check(
            "browser.sandbox", "Renderer sandbox (measured)", Verdict.UNKNOWN,
            critical=False,
            detail="Renderer processes exist but their tokens could not be read.",
            evidence=f"pids={len(renderer_pids)} readable=0",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.UNREADABLE)]

    contained = facts["untrusted"]
    appcontainer = facts["appcontainer"]

    # Before the PASS branch: an unreadable renderer is UNKNOWN, never dropped from
    # the count (that once reported "All 2" of 3).
    if unreadable:
        return [Check(
            "browser.sandbox", "Renderer sandbox (measured)", Verdict.UNKNOWN,
            critical=False,
            detail=(f"{unreadable} of {measured + unreadable} renderer process(es) "
                    f"could not have their tokens read, so bruhswer cannot say whether "
                    f"page content is contained. The {measured} it could read were "
                    f"{contained} UNTRUSTED. This is reported as UNKNOWN rather than "
                    f"passing on the ones that happened to be readable."),
            evidence=f"pids={len(renderer_pids)} readable={measured} "
                     f"unreadable={unreadable} untrusted={contained}",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.PARTIAL_EVIDENCE)]

    if contained == measured:
        verdict = Verdict.PASS
        detail = (f"All {measured} renderer process(es) run at UNTRUSTED integrity"
                  + (f", {appcontainer} of them in an AppContainer" if appcontainer
                     else "")
                  + ". Web pages are contained by Edge's own sandbox. The browser "
                    "process itself is NOT sandboxed - see Security notes.")
    elif contained:
        verdict = Verdict.FAIL
        detail = (f"Only {contained} of {measured} renderer process(es) run at "
                  f"UNTRUSTED integrity. Some page content is less contained than "
                  f"expected on this machine.")
    else:
        verdict = Verdict.FAIL
        detail = (f"None of the {measured} renderer process(es) run at UNTRUSTED "
                  f"integrity. The renderer sandbox is not behaving as bruhswer "
                  f"expects on this machine - do not rely on it.")

    return [Check("browser.sandbox", "Renderer sandbox (measured)", verdict,
                  critical=False, detail=detail,
                  evidence=f"measured={measured} unreadable={unreadable} "
                           f"untrusted={contained} "
                           f"appcontainer={appcontainer} "
                           f"zero_privileges={facts['zero_privileges']} "
                           f"worst_integrity={facts['worst_integrity']}",
                  evidence_kind=EvidenceKind.LIVE)]
