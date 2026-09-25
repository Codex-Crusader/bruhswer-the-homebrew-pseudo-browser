"""The one place that decides whether bruhswer may launch.

Fail-closed: a critical check must PASS, and UNKNOWN blocks. There is no "continue
anyway". Checks ask the OS what is true and report UNKNOWN when they cannot find out.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
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

# "Asked, and there are none", as opposed to None, "could not ask".
NO_RENDERERS: tuple[int, ...] = ()

# A crashed guard's check is "<category>.guard.<name>", so its category's status row
# shows the crash.
_GUARD_FAILURE_SEGMENT = "guard"


def guard_failure_id(category: str, name: str) -> str:
    return f"{category}.{_GUARD_FAILURE_SEGMENT}.{name}"


def guard_failure_category(check_id: str) -> str | None:
    """The category of a crashed guard's check, or None for any other check."""
    parts = check_id.split(".")
    if len(parts) == 3 and parts[1] == _GUARD_FAILURE_SEGMENT:
        return parts[0]
    return None


@dataclass(frozen=True)
class GuardTiming:
    """One guard's duration, check count, and the check_id prefix all its checks carry."""

    name: str
    duration_ms: float
    checks: int
    category: str


@dataclass
class VerificationResult:
    checks: list[Check] = field(default_factory=list)
    timings: list[GuardTiming] = field(default_factory=list)
    # Measured; guards overlap, so this is not the sum of their durations.
    wall_ms: float = 0.0

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

    def slowest(self, limit: int = 3) -> list[GuardTiming]:
        return sorted(self.timings, key=lambda t: t.duration_ms, reverse=True)[:limit]


def _run_guard(name: str, category: str,
               guard: Callable[[], list[Check]]) -> tuple[list[Check], GuardTiming]:
    """Run one guard. Never raises: a crash becomes one CRITICAL UNKNOWN, because the
    guard's own checks are absent and blocks_launch() cannot see an absent check."""
    started = time.perf_counter()
    try:
        produced = guard()
    except Exception as exc:                    # noqa: BLE001  # lint: allow broad-except - one guard must not take down the pass
        _log.exception("guard %s raised; the rest of the pass continues", name)
        produced = [Check(
            guard_failure_id(category, name), f"{name} checks could not run",
            Verdict.UNKNOWN,
            critical=True,
            detail=(f"bruhswer's {name} checks could not run, so nothing they "
                    f"cover was established this pass, and the browser will not "
                    f"launch until they do."),
            evidence=f"{exc.__class__.__name__}",
            evidence_kind=EvidenceKind.INFERENCE,
            unknown_reason=UnknownReason.PROBE_ERROR)]
    elapsed = (time.perf_counter() - started) * 1000.0
    return produced, GuardTiming(name, elapsed, len(produced), category)


def verify_all(profile_dir: Path, argv: list[str], mode: str,
               edge_path: Path | None,
               download_dir: Path | None = None,
               renderer_pids: Sequence[int] | None = NO_RENDERERS
               ) -> VerificationResult:
    """Run every guard. `renderer_pids`: [] = asked, none found; None = query failed.

    The guards are independent and read-only and mostly wait on PowerShell, so they
    run at once (measured 4.7 s serial, 2.4 s parallel). Results are collected in
    submission order, so check order never depends on thread timing.
    """
    guards: list[tuple[str, str, Callable[[], list[Check]]]] = [
        ("edge", "edge", lambda: edge.verify_runtime(edge_path))]
    if edge_path is not None:
        guards += [
            ("browser", "browser", lambda: browser_guard.verify(profile_dir, argv)),
            # Not `renderer_pids or []`, which turned None into [].
            ("sandbox", "browser",
             lambda: browser_guard.verify_renderer_sandbox(renderer_pids)),
            ("network", "net", lambda: network_guard.verify(edge_path)),
        ]
    guards += [
        ("host", "host", lambda: host_guard.evaluate()),
        ("controller", "controller", lambda: _controller_checks()),
        ("integrity", "controller", lambda: integrity.verify()),
        ("privacy", "privacy", lambda: _privacy_checks(profile_dir, mode)),
    ]
    if download_dir is not None:
        guards.append(("downloads", "downloads",
                       lambda: _download_checks(profile_dir, download_dir)))
    guards.append(("dns", "dns", lambda: _dns_checks()))

    result = VerificationResult()
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(guards),
                            thread_name_prefix="bruhswer-guard") as pool:
        futures = [pool.submit(_run_guard, *guard) for guard in guards]
        for future in futures:
            produced, timing = future.result()
            result.checks.extend(produced)
            result.timings.append(timing)
    result.wall_ms = (time.perf_counter() - started) * 1000.0

    verdicts: dict[str, int] = {}
    for check in result.checks:
        verdicts[str(check.verdict)] = verdicts.get(str(check.verdict), 0) + 1
    _log.info("verification complete: %s blockers=%d in %.0fms (slowest: %s)",
              verdicts, len(result.blockers), result.wall_ms,
              ", ".join(f"{t.name}={t.duration_ms:.0f}ms" for t in result.slowest()))
    return result


def _controller_checks() -> list[Check]:
    """Whether bruhswer itself is elevated. Critical, so UNKNOWN blocks launch."""
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

    # NOT ENFORCEABLE, not FAIL: bruhswer cannot prevent Edge's sign-in.
    signed_in, sign_detail = privacy_guard.verify_account_signin(profile_dir)
    if sign_detail == "no profile yet":
        checks.append(Check(
            "privacy.account", "Browser account sign-in", Verdict.UNKNOWN,
            critical=False,
            detail="No session has run yet, so there is no profile to read.",
            evidence=sign_detail, evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=UnknownReason.NO_PROFILE_YET))
    elif sign_detail == privacy_guard.PREFS_UNREADABLE:
        # An unreadable file is not "no account"; this was once a green PASS.
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
    """CRITICAL: if wrong, downloads land in the real Downloads folder, as they once did.

    The title says the folder is SET, not that files go there: it rests on reading the
    preferences, not on watching a download.
    """
    ok, detail = privacy_guard.verify_download_directory(profile_dir, download_dir)
    if not ok and detail == "no profile yet":
        return [Check("downloads.quarantine", _DOWNLOAD_TITLE,
                      Verdict.UNKNOWN, critical=False,
                      detail="No session has run yet; set and verified at launch.",
                      evidence=detail, evidence_kind=EvidenceKind.READ_BACK,
                      unknown_reason=UnknownReason.NO_PROFILE_YET)]
    if not ok and detail == privacy_guard.PREFS_UNREADABLE:
        # An unreadable file is UNKNOWN (still blocks launch), not a definite FAIL.
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
    """Always UNKNOWN: whether queries leave encrypted cannot be measured from here
    without a packet-capture driver bruhswer will not install."""
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

    # One failed probe is not zero rows.
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
