"""SecurityVerifier — the one place that decides whether bruhswer may launch.

Fail-closed (brief SS8, SS9): a critical check must PASS. UNKNOWN blocks. There is no
"continue anyway" button, and no browser-reachable way to turn this off.

The verifier does not trust its own intentions. It asks the operating system what is
actually true, and reports UNKNOWN when it cannot find out -- because a green light
that was never verified is the exact defect this project treats as a vulnerability.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .. import sysquery
from ..browser import edge
from ..host import host_guard
from ..logging_setup import get_logger
from ..network import network_guard
from ..privacy import privacy_guard
from ..verdict import Check, Verdict, worst
from . import browser_guard, integrity

_log = get_logger("verifier")

# "Asked, and there are none" - as opposed to None, which means "could not ask".
# A module-level tuple rather than a mutable [] default, so nothing can append to it.
NO_RENDERERS: tuple[int, ...] = ()


@dataclass
class VerificationResult:
    checks: list[Check] = field(default_factory=list)

    @property
    def blockers(self) -> list[Check]:
        return [c for c in self.checks if c.blocks_launch]

    @property
    def may_launch(self) -> bool:
        return not self.blockers

    def by_prefix(self, prefix: str) -> list[Check]:
        return [c for c in self.checks if c.check_id.startswith(prefix)]

    def category(self, prefix: str) -> Verdict:
        subset = self.by_prefix(prefix)
        return worst(subset) if subset else Verdict.UNKNOWN


def verify_all(profile_dir: Path, argv: list[str], mode: str,
               edge_path: Path | None,
               download_dir: Path | None = None,
               renderer_pids: Sequence[int] | None = NO_RENDERERS
               ) -> VerificationResult:
    """`renderer_pids` has THREE meaningful values, not two:

        []      asked Windows, found no renderer processes
        [...]   these are the renderers; measure their tokens
        None    the query FAILED, so nothing is known either way

    The default is the empty list, meaning "no session, nothing to measure" - which is
    the right answer for the pre-launch call in Controller.start(). None is reserved
    for a genuine measurement failure and must be passed explicitly.
    """
    result = VerificationResult()

    result.checks.extend(edge.verify_runtime(edge_path))
    if edge_path is not None:
        result.checks.extend(browser_guard.verify(profile_dir, argv))
        # Measured, not assumed: what the renderer tokens actually are on THIS machine.
        #
        # Passed straight through, NOT as `renderer_pids or []`. That idiom collapsed
        # None ("could not ask Windows") into [] ("asked, and there are none"), which
        # is the distinction embed.renderer_pids_for_profile exists to preserve.
        result.checks.extend(
            browser_guard.verify_renderer_sandbox(renderer_pids))
        result.checks.extend(network_guard.verify(edge_path))
    result.checks.extend(host_guard.evaluate())
    result.checks.extend(_controller_checks())
    result.checks.extend(integrity.verify())
    result.checks.extend(_privacy_checks(profile_dir, mode))
    if download_dir is not None:
        result.checks.extend(_download_checks(profile_dir, download_dir))
    result.checks.extend(_dns_checks())

    verdicts: dict[str, int] = {}
    for check in result.checks:
        verdicts[str(check.verdict)] = verdicts.get(str(check.verdict), 0) + 1
    _log.info("verification complete: %s blockers=%d", verdicts, len(result.blockers))
    return result


def _controller_checks() -> list[Check]:
    elevated = sysquery.is_elevated()
    if elevated is None:
        return [Check("controller.privilege", "bruhswer runs unelevated",
                      Verdict.UNKNOWN, critical=True,
                      detail="Could not determine bruhswer's privilege level.",
                      evidence="is_elevated=None")]
    return [Check(
        "controller.privilege", "bruhswer runs unelevated",
        Verdict.PASS if not elevated else Verdict.FAIL, critical=True,
        detail=("Running as a normal user, with no Administrator rights."
                if not elevated else
                "bruhswer is running as Administrator. Close it and start it normally "
                "- an elevated browser is a worse outcome, not a better one."),
        evidence=f"elevated={elevated}")]


def _privacy_checks(profile_dir: Path, mode: str) -> list[Check]:
    applied, expected, missing = privacy_guard.verify_applied(profile_dir, mode)
    if expected == 0:
        return []
    if missing == [privacy_guard.NO_PROFILE_YET]:
        verdict, detail = (Verdict.UNKNOWN,
                           f"No bruhswer session has run yet, so there is no profile to "
                           f"check. All {expected} settings are written and re-verified "
                           f"when a session starts.")
    elif applied == expected:
        verdict, detail = Verdict.PASS, f"All {expected} privacy settings are in place."
    elif applied == 0:
        verdict, detail = (Verdict.UNKNOWN,
                           "Privacy settings could not be read back from the profile.")
    else:
        verdict, detail = (Verdict.FAIL,
                           f"{applied} of {expected} settings applied. "
                           f"Not applied: {', '.join(missing[:4])}"
                           + (" ..." if len(missing) > 4 else ""))
    checks = [Check("privacy.settings", "Privacy settings applied", verdict,
                    critical=False, detail=detail,
                    evidence=f"applied={applied}/{expected} missing={missing[:10]}")]

    # Measured, not assumed. See privacy_guard.verify_account_signin for why this
    # check exists at all. Reported as NOT ENFORCEABLE rather than FAIL, because
    # bruhswer has no in-scope way to prevent the sign-in - and never as PASS while
    # an account is actually present.
    signed_in, sign_detail = privacy_guard.verify_account_signin(profile_dir)
    if sign_detail == "no profile yet":
        checks.append(Check(
            "privacy.account", "Browser account sign-in", Verdict.UNKNOWN,
            critical=False,
            detail="No session has run yet, so there is no profile to read.",
            evidence=sign_detail))
    elif sign_detail == privacy_guard.PREFS_UNREADABLE:
        # "Could not read the file" is NOT "no account is signed in". This branch used
        # to fall through to the else below and render as a green PASS asserting that
        # no Microsoft account was attached - on the strength of a file bruhswer had
        # just failed to parse.
        checks.append(Check(
            "privacy.account", "Browser account sign-in", Verdict.UNKNOWN,
            critical=False,
            detail=("The profile's Preferences file could not be read, so bruhswer "
                    "cannot tell whether Edge has signed this session into a Microsoft "
                    "account. Treat this session as NOT anonymous until it can."),
            evidence=sign_detail))
    elif signed_in:
        checks.append(Check(
            "privacy.account", "Browser account sign-in", Verdict.FAIL,
            critical=False, enforceable=False,
            detail=("Edge has signed this profile into a Microsoft account by itself. "
                    "Syncing is disabled, but your identity is still attached to this "
                    "session, and a disposable session is NOT anonymous. bruhswer "
                    "cannot stop this: only machine-wide Edge policy can, and it will "
                    "not change every Edge profile on your PC. Sign out inside the "
                    "session, in Settings > Profiles."),
            evidence=sign_detail))
    else:
        checks.append(Check(
            "privacy.account", "Browser account sign-in", Verdict.PASS,
            critical=False,
            detail="No Microsoft account is signed into this profile.",
            evidence=sign_detail))
    return checks


def _download_checks(profile_dir: Path, download_dir: Path) -> list[Check]:
    """CRITICAL. If this is wrong, downloads land in the user's real Downloads folder.

    That is not hypothetical - it is exactly what bruhswer did until a download probe
    caught it. The check is critical because a silently-wrong download path turns the
    quarantine feature into a false claim, and a false security claim is the one defect
    class this project treats as a vulnerability in its own right.
    """
    ok, detail = privacy_guard.verify_download_directory(profile_dir, download_dir)
    if not ok and detail == "no profile yet":
        return [Check("downloads.quarantine", "Downloads go to quarantine",
                      Verdict.UNKNOWN, critical=False,
                      detail="No session has run yet; set and verified at launch.",
                      evidence=detail)]
    return [Check(
        "downloads.quarantine", "Downloads go to quarantine",
        Verdict.PASS if ok else Verdict.FAIL, critical=True,
        detail=("Downloads are directed to bruhswer's quarantine folder, and the "
                "browser will not ask where to save."
                if ok else f"Downloads would NOT be quarantined: {detail}"),
        evidence=f"expected={download_dir} ok={ok} detail={detail}")]


def _dns_checks() -> list[Check]:
    """DNS is reported UNKNOWN, deliberately.

    Stage 4 could not establish whether this machine's DNS is encrypted: a local
    resolver (NextDNS) sits in the path, so an external diagnostic cannot see what the
    browser actually sent, and packet capture needs a driver this project will not
    install. Brief SS24 is explicit that those measurements must not be reused and that
    fabricated certainty is not acceptable.
    """
    doh = sysquery.doh_servers()
    auto = [d for d in doh if str(d.get("AutoUpgrade")).lower() in ("true", "1")]
    servers = sysquery.dns_servers()
    configured = sorted({s for entry in servers
                         for s in (entry.get("ServerAddresses") or [])})
    templated = {str(d.get("ServerAddress")) for d in doh}
    without = [s for s in configured if s not in templated]

    detail = (f"{len(doh)} encrypted-DNS templates known to Windows, "
              f"{len(auto)} set to auto-upgrade.")
    if without:
        detail += f" Resolvers with no known encrypted option: {', '.join(without)}."
    detail += (" bruhswer cannot confirm whether queries actually leave encrypted, "
               "so this is reported as UNKNOWN rather than guessed.")

    return [Check("dns.encrypted", "DNS is encrypted", Verdict.UNKNOWN,
                  critical=False, detail=detail,
                  evidence=f"templates={len(doh)} auto={len(auto)} "
                           f"configured={configured} untemplated={without}")]
