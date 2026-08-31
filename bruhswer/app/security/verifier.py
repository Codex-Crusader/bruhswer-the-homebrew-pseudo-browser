"""SecurityVerifier — the one place that decides whether bruhswer may launch.

Fail-closed (brief SS8, SS9): a critical check must PASS. UNKNOWN blocks. There is no
"continue anyway" button, and no browser-reachable way to turn this off.

The verifier does not trust its own intentions. It asks the operating system what is
actually true, and reports UNKNOWN when it cannot find out -- because a green light
that was never verified is the exact defect this project treats as a vulnerability.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .. import sysquery
from ..browser import edge
from ..host import host_guard
from ..logging_setup import get_logger
from ..network import network_guard
from ..privacy import privacy_guard
from ..verdict import (Check, EvidenceKind, UnknownReason, Verdict,
                       reason_for_probe, worst)
from . import browser_guard, integrity

_log = get_logger("verifier")

# "Asked, and there are none" - as opposed to None, which means "could not ask".
# A module-level tuple rather than a mutable [] default, so nothing can append to it.
NO_RENDERERS: tuple[int, ...] = ()


@dataclass(frozen=True)
class GuardTiming:
    """How long one guard took, and how many checks it produced.

    Collected into the result object rather than a module-level list, so it needs no
    locking - the UI thread and the verify worker each build their own.
    """

    name: str
    duration_ms: float
    checks: int


@dataclass
class VerificationResult:
    checks: list[Check] = field(default_factory=list)
    timings: list[GuardTiming] = field(default_factory=list)

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

    @property
    def total_ms(self) -> float:
        return sum(t.duration_ms for t in self.timings)

    def slowest(self, limit: int = 3) -> list[GuardTiming]:
        return sorted(self.timings, key=lambda t: t.duration_ms, reverse=True)[:limit]


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

    def run(name: str, guard: Callable[[], list[Check]]) -> None:
        """Run one guard, record what it cost, and never let it take the pass down.

        A guard that raised used to abort the whole pass, costing the user every OTHER
        light including the critical ones. A crash now costs exactly its own checks and
        surfaces as an UNKNOWN naming the guard.
        """
        started = time.perf_counter()
        try:
            produced = guard()
        except Exception as exc:                    # noqa: BLE001  # lint: allow broad-except - one guard must not take down the pass
            _log.exception("guard %s raised; the rest of the pass continues", name)
            produced = [Check(
                f"{name}.guard", f"{name} checks ran", Verdict.UNKNOWN, critical=False,
                detail=(f"bruhswer's {name} checks could not run, so nothing they "
                        f"cover was established this pass."),
                evidence=f"{exc.__class__.__name__}",
                evidence_kind=EvidenceKind.INFERENCE,
                unknown_reason=UnknownReason.PROBE_ERROR)]
        elapsed = (time.perf_counter() - started) * 1000.0
        result.checks.extend(produced)
        result.timings.append(GuardTiming(name, elapsed, len(produced)))

    run("edge", lambda: edge.verify_runtime(edge_path))
    if edge_path is not None:
        run("browser", lambda: browser_guard.verify(profile_dir, argv))
        # Measured, not assumed: what the renderer tokens actually are on THIS machine.
        #
        # Passed straight through, NOT as `renderer_pids or []`. That idiom collapsed
        # None ("could not ask Windows") into [] ("asked, and there are none"), which
        # is the distinction embed.renderer_pids_for_profile exists to preserve.
        run("sandbox", lambda: browser_guard.verify_renderer_sandbox(renderer_pids))
        run("network", lambda: network_guard.verify(edge_path))
    run("host", host_guard.evaluate)
    run("controller", _controller_checks)
    run("integrity", integrity.verify)
    run("privacy", lambda: _privacy_checks(profile_dir, mode))
    if download_dir is not None:
        run("downloads", lambda: _download_checks(profile_dir, download_dir))
    run("dns", _dns_checks)

    verdicts: dict[str, int] = {}
    for check in result.checks:
        verdicts[str(check.verdict)] = verdicts.get(str(check.verdict), 0) + 1
    _log.info("verification complete: %s blockers=%d in %.0fms (slowest: %s)",
              verdicts, len(result.blockers), result.total_ms,
              ", ".join(f"{t.name}={t.duration_ms:.0f}ms" for t in result.slowest()))
    return result


def _controller_checks() -> list[Check]:
    """bruhswer's own privilege level. LIVE - it reads THIS process's token.

    critical=True, so UNKNOWN blocks launch - which is why sysquery only ever memoises
    a definite True/False.
    """
    probe = sysquery.is_elevated_probe()
    if probe.value is None:
        return [Check("controller.privilege", "bruhswer runs unelevated",
                      Verdict.UNKNOWN, critical=True,
                      detail=("bruhswer could not determine its own privilege level, "
                              "so it cannot confirm it is running as a normal user. "
                              "Launch is blocked rather than assumed safe."),
                      evidence=probe.reason(),
                      evidence_kind=EvidenceKind.LIVE,
                      unknown_reason=reason_for_probe(probe.status))]
    elevated = probe.value
    return [Check(
        "controller.privilege", "bruhswer runs unelevated",
        Verdict.PASS if not elevated else Verdict.FAIL, critical=True,
        detail=("Running as a normal user, with no Administrator rights."
                if not elevated else
                "bruhswer is running as Administrator. Close it and start it normally "
                "- an elevated browser is a worse outcome, not a better one."),
        evidence=f"elevated={elevated} {probe.reason()}",
        evidence_kind=EvidenceKind.LIVE)]


def _privacy_checks(profile_dir: Path, mode: str) -> list[Check]:
    applied, expected, missing = privacy_guard.verify_applied(profile_dir, mode)
    if expected == 0:
        return []
    reason = UnknownReason.NONE
    if missing == [privacy_guard.NO_PROFILE_YET]:
        verdict, detail = (Verdict.UNKNOWN,
                           f"No bruhswer session has run yet, so there is no profile to "
                           f"check. All {expected} settings are written and re-verified "
                           f"when a session starts.")
        reason = UnknownReason.NO_PROFILE_YET
    elif applied == expected:
        verdict, detail = (Verdict.PASS,
                           f"All {expected} privacy settings are present in the "
                           f"profile as bruhswer wrote them. This is what the profile "
                           f"file says; bruhswer has not observed the browser acting "
                           f"on each setting.")
    elif applied == 0:
        verdict, detail = (Verdict.UNKNOWN,
                           "Privacy settings could not be read back from the profile.")
        reason = UnknownReason.UNREADABLE
    else:
        verdict, detail = (Verdict.FAIL,
                           f"{applied} of {expected} settings applied. "
                           f"Not applied: {', '.join(missing[:4])}"
                           + (" ..." if len(missing) > 4 else ""))
    checks = [Check("privacy.settings", "Privacy settings applied", verdict,
                    critical=False, detail=detail,
                    evidence=f"applied={applied}/{expected} missing={missing[:10]}",
                    evidence_kind=EvidenceKind.READ_BACK,
                    unknown_reason=reason)]

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
            evidence=sign_detail, evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=UnknownReason.NO_PROFILE_YET))
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
            evidence=sign_detail, evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=UnknownReason.UNREADABLE))
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
            evidence=sign_detail, evidence_kind=EvidenceKind.READ_BACK))
    else:
        checks.append(Check(
            "privacy.account", "Browser account sign-in", Verdict.PASS,
            critical=False,
            detail="No Microsoft account is recorded in this profile.",
            evidence=sign_detail, evidence_kind=EvidenceKind.READ_BACK))
    return checks


def _download_checks(profile_dir: Path, download_dir: Path) -> list[Check]:
    """CRITICAL. If this is wrong, downloads land in the user's real Downloads folder.

    That is not hypothetical - it is exactly what bruhswer did until a download probe
    caught it. The check is critical because a silently-wrong download path turns the
    quarantine feature into a false claim, and a false security claim is the one defect
    class this project treats as a vulnerability in its own right.

    TITLE WORDING IS DELIBERATE, for the same reason as integrity._TITLE. It was
    "Downloads go to quarantine" - a statement about what will happen to a file, made
    on the strength of reading two keys out of JSON. The narrower title is what the
    evidence supports, and it still catches the defect this check was written for
    (Edge ignoring --download-directory), which showed up as the preference being absent.
    """
    ok, detail = privacy_guard.verify_download_directory(profile_dir, download_dir)
    if not ok and detail == "no profile yet":
        return [Check("downloads.quarantine", _DOWNLOAD_TITLE,
                      Verdict.UNKNOWN, critical=False,
                      detail="No session has run yet; set and verified at launch.",
                      evidence=detail, evidence_kind=EvidenceKind.READ_BACK,
                      unknown_reason=UnknownReason.NO_PROFILE_YET)]
    if not ok and detail == privacy_guard.PREFS_UNREADABLE:
        # "Could not read the file" is NOT "downloads would not be quarantined". This
        # check is critical, so UNKNOWN still blocks launch - fail-closed is preserved -
        # but it no longer reports a definite FAIL on the strength of a file bruhswer
        # just failed to parse.
        return [Check(
            "downloads.quarantine", _DOWNLOAD_TITLE,
            Verdict.UNKNOWN, critical=True,
            detail=("The profile's Preferences file could not be read, so bruhswer "
                    "cannot tell whether downloads would be quarantined. Treat this "
                    "session as unverified until it can."),
            evidence=detail, evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=UnknownReason.UNREADABLE)]
    return [Check(
        "downloads.quarantine", _DOWNLOAD_TITLE,
        Verdict.PASS if ok else Verdict.FAIL, critical=True,
        detail=("The profile's download preferences point at bruhswer's quarantine "
                "folder and have 'ask where to save' turned off. Read back from the "
                "profile just now; bruhswer has not downloaded a file during this "
                "check to watch where it lands."
                if ok else f"Downloads would NOT be quarantined: {detail}"),
        evidence=f"expected={download_dir} ok={ok} detail={detail}",
        evidence_kind=EvidenceKind.READ_BACK)]


_DOWNLOAD_TITLE = "Download folder is set to quarantine"


def _dns_checks() -> list[Check]:
    """DNS is reported UNKNOWN, deliberately.

    Stage 4 could not establish whether this machine's DNS is encrypted: a local
    resolver (NextDNS) sits in the path, so an external diagnostic cannot see what the
    browser actually sent, and packet capture needs a driver this project will not
    install. Brief SS24 is explicit that those measurements must not be reused and that
    fabricated certainty is not acceptable.
    """
    doh_probe = sysquery.doh_servers()
    servers_probe = sysquery.dns_servers()

    if not doh_probe.ok and not servers_probe.ok:
        return [Check(
            "dns.encrypted", "DNS is encrypted", Verdict.UNKNOWN, critical=False,
            detail=("bruhswer could not read this PC's DNS configuration, so it cannot "
                    "even describe which resolvers are in use - let alone whether "
                    "queries leave encrypted."),
            evidence=f"doh={doh_probe.reason()} servers={servers_probe.reason()}",
            evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=reason_for_probe(doh_probe.status))]

    doh = doh_probe.value
    auto = [d for d in doh if str(d.get("AutoUpgrade")).lower() in ("true", "1")]
    configured = sorted({s for entry in servers_probe.value
                         for s in (entry.get("ServerAddresses") or [])})
    templated = {str(d.get("ServerAddress")) for d in doh}
    without = [s for s in configured if s not in templated]

    detail = (f"{len(doh)} encrypted-DNS templates known to Windows, "
              f"{len(auto)} set to auto-upgrade.")
    if without:
        detail += f" Resolvers with no known encrypted option: {', '.join(without)}."
    detail += (" bruhswer cannot confirm whether queries actually leave encrypted, "
               "so this is reported as UNKNOWN rather than guessed.")

    # One probe failing is not zero rows. Counting an unread list as "none found"
    # is the overclaim this project treats as a defect.
    partial = not (doh_probe.ok and servers_probe.ok)
    if partial:
        detail += (" Part of this PC's DNS configuration could not be read, so the "
                   "counts above cover only what was readable.")

    return [Check("dns.encrypted", "DNS is encrypted", Verdict.UNKNOWN,
                  critical=False, detail=detail,
                  evidence=f"templates={len(doh)} auto={len(auto)} "
                           f"configured={configured} untemplated={without} "
                           f"{doh_probe.reason()}",
                  evidence_kind=EvidenceKind.READ_BACK,
                  unknown_reason=(UnknownReason.PARTIAL_EVIDENCE if partial
                                  else UnknownReason.NEVER_MEASURED))]
