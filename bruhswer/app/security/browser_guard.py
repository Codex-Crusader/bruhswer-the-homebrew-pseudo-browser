"""BrowserGuard — the browser's own data stays where bruhswer put it.

Two honest framings, and the difference matters:

  - A dedicated, ACL-tightened profile directory keeps bruhswer's browsing state out of
    the user's ordinary Edge/Chrome profiles and out of their documents. That is real,
    and it is worth doing (brief SS12).
  - It is NOT a sandbox. Stage 4 gate A4 measured that the browser PROCESS runs on an
    ordinary user token and can read the whole user profile regardless of where its own
    data lives. This module is hygiene and defence in depth, not confinement, and the
    UI must never present it as confinement.
"""

from __future__ import annotations

import getpass
import subprocess
from pathlib import Path

from .. import config
from ..browser import tokens
from ..logging_setup import get_logger
from ..verdict import Check, Verdict

_log = get_logger("browserguard")


def harden_profile_dir(profile_dir: Path) -> tuple[bool, str]:
    """Restrict the profile folder to this user, removing inherited access.

    NO `/T`. This is not a style choice - an earlier version used `/inheritance:r`
    together with `/T`, which applies the grant to every existing FILE as well. The
    `(OI)(CI)` flags are container-inheritance flags and are inherit-only on a file, so
    each file lost its inherited access and gained nothing effective in return. icacls
    still returned 0 while the profile became unreadable, and bruhswer's own Preferences
    file started raising PermissionError.

    Setting the ACL on the DIRECTORY alone is both correct and sufficient: Windows
    propagates (OI)(CI) entries to children that inherit, and newly created files pick
    them up automatically.

    icacls is given an explicit argument list with no shell. The only substituted value
    is the profile path, which bruhswer built itself from config constants.
    """
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

    # Prove the profile is still usable. icacls returning 0 is NOT evidence that the
    # result is correct - that is exactly how the bug above went unnoticed.
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
    """True if candidate is ancestor or sits under it.

    Both sides are resolved before comparison. Resolving only the candidate left an
    asymmetry: if LOCALAPPDATA were an 8.3 short path, or AppData\\Local were redirected
    through a junction, the two would never match and this critical check would PASS for
    a profile that IS the user's real browser data. Lowered as well, because Windows
    paths are case-insensitive and is_relative_to is not.
    """
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
        evidence=f"profile={resolved} root={root}"))

    # --- the browser must not be pointed at the user's real profiles ------------
    forbidden_parents = [
        Path(config.os.environ["LOCALAPPDATA"]) / "Microsoft" / "Edge" / "User Data",
        Path(config.os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data",
    ]
    # Path ancestry, not string prefix. "User Data-Evil" starts with "User Data" while
    # being a different directory, which made this fail a launch it should have allowed.
    collides = any(_is_within(resolved, p) for p in forbidden_parents)
    checks.append(Check(
        "browser.profile.separate", "Separate from your normal browser profile",
        Verdict.PASS if not collides else Verdict.FAIL, critical=True,
        detail=("bruhswer uses its own profile; your everyday browser data is untouched."
                if not collides else "Profile overlaps your normal browser data."),
        evidence=f"collides={collides}"))

    # --- ACL ---------------------------------------------------------------------
    acl = _read_acl(profile_dir)
    if not acl:
        checks.append(Check(
            "browser.profile.acl", "Profile folder permissions", Verdict.UNKNOWN,
            critical=False, detail="Could not read the folder's permissions.",
            evidence="icacls returned nothing"))
    else:
        broad = [token for token in ("Everyone", "BUILTIN\\Users",
                                     "ALL APPLICATION PACKAGES")
                 if token in acl]
        checks.append(Check(
            "browser.profile.acl", "Profile folder permissions",
            Verdict.PASS if not broad else Verdict.FAIL, critical=False,
            detail=("Restricted to your account." if not broad else
                    f"Readable by: {', '.join(broad)}"),
            evidence=f"broad_principals={broad}"))

    # --- command line -------------------------------------------------------------
    found_dangerous = [flag for flag in argv[1:]
                       for bad in config.DANGEROUS_FLAGS if flag.startswith(bad)]
    checks.append(Check(
        "browser.cmdline", "No security-weakening browser flags",
        Verdict.PASS if not found_dangerous else Verdict.FAIL, critical=True,
        detail=("The browser is started with its sandbox and TLS checks intact."
                if not found_dangerous else
                f"Refusing these flags: {found_dangerous}"),
        evidence=f"dangerous={found_dangerous}"))

    profile_flags = [a for a in argv if a.startswith("--user-data-dir=")]
    checks.append(Check(
        "browser.cmdline.profile", "Browser told to use exactly one profile",
        Verdict.PASS if len(profile_flags) == 1 else Verdict.FAIL, critical=True,
        detail=("One profile directory specified." if len(profile_flags) == 1
                else f"{len(profile_flags)} profile arguments found."),
        evidence=f"count={len(profile_flags)}"))

    # --- the boundary that actually exists, stated accurately ---------------------
    checks.append(Check(
        "browser.sandbox.flags", "Browser started with its sandbox intact",
        Verdict.PASS, critical=False,
        detail=("bruhswer never passes --no-sandbox or any flag that weakens the "
                "renderer sandbox. Whether the sandbox is actually in force is "
                "measured separately, from the live processes."),
        evidence="DANGEROUS_FLAGS enforced in edge.build_command"))

    return checks


def verify_renderer_sandbox(renderer_pids: list[int]) -> list[Check]:
    """MEASURE the renderer sandbox, rather than asserting it.

    This check used to be a hardcoded PASS quoting a Stage 4 measurement taken on one
    machine with one Edge build. That is exactly the "green light nobody verified" this
    project treats as a vulnerability - on the same machine, Chrome's renderers were
    restricted but NOT AppContainer, so the property is genuinely build-dependent.

    With no session running there is nothing to measure, and the honest answer is
    UNKNOWN.
    """
    if not renderer_pids:
        return [Check(
            "browser.sandbox", "Renderer sandbox (measured)", Verdict.UNKNOWN,
            critical=False,
            detail="No browser session is running, so there is nothing to measure yet.",
            evidence="no renderer pids")]

    facts = tokens.summarise_renderers(renderer_pids)
    measured = facts["measured"]
    if measured == 0:
        return [Check(
            "browser.sandbox", "Renderer sandbox (measured)", Verdict.UNKNOWN,
            critical=False,
            detail="Renderer processes exist but their tokens could not be read.",
            evidence=f"pids={len(renderer_pids)} readable=0")]

    contained = facts["untrusted"]
    appcontainer = facts["appcontainer"]

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
                  evidence=f"measured={measured} untrusted={contained} "
                           f"appcontainer={appcontainer} "
                           f"zero_privileges={facts['zero_privileges']} "
                           f"worst_integrity={facts['worst_integrity']}")]
