"""Controller: a fixed, closed set of verbs.

No run_shell, no eval, no dispatcher from a string to code. The surface is small by
construction, because a compromised browser can reach localhost.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from ..browser import edge, embed, urls
from ..downloads import quarantine
from ..logging_setup import get_logger
from ..privacy import privacy_guard
from ..security import browser_guard, verifier
from ..sessions import session_manager
from ..verdict import Verdict, worst

_log = get_logger("controller")

MODE_STANDARD = "standard"
MODE_MAXIMUM = "maximum"


@dataclass
class LaunchOutcome:
    launched: bool
    message: str
    result: verifier.VerificationResult
    session: session_manager.Session | None = None


@dataclass(frozen=True)
class SessionSnapshot:
    """An immutable view of the session for the UI, so `controller.session` cannot turn
    None between two reads. Starts no subprocess; ask is_running() for liveness."""

    active: bool
    mode: str
    session_id: str
    profile_dir: Path
    is_disposable: bool
    generation: int
    elapsed_seconds: float

    @property
    def badge(self) -> str:
        if not self.active:
            return "NO SESSION"
        return "DISPOSABLE BRUH" if self.is_disposable else "PERSISTENT BRUH"

    def elapsed_text(self) -> str:
        """How long this session has been open, as m:ss or h:mm:ss."""
        if not self.active:
            return ""
        total = int(self.elapsed_seconds)
        hours, rest = divmod(total, 3600)
        minutes, seconds = divmod(rest, 60)
        if hours:
            return f"{hours}:{minutes:02d}:{seconds:02d}"
        return f"{minutes}:{seconds:02d}"


NO_SESSION = SessionSnapshot(
    active=False, mode="", session_id="", profile_dir=config.PROFILE_PERSISTENT,
    is_disposable=False, generation=0, elapsed_seconds=0.0)


@dataclass(frozen=True)
class VerificationRequest:
    """Everything a verification pass needs, passed by value to the worker thread.

    The worker must not read `controller.session`: stop() deletes a disposable profile
    concurrently. A result whose `generation` is stale is dropped, not shown.
    """

    profile_dir: Path
    argv: tuple[str, ...]
    privacy_mode: str
    edge_path: Path | None
    download_dir: Path | None
    session_id: str | None
    generation: int
    # `generation` cannot order two passes within ONE session; this can.
    verification_id: int = 0


def run_verification(request: VerificationRequest) -> verifier.VerificationResult:
    """Verification from a snapshot. Touches no shared state; safe on a worker thread."""
    renderers = (embed.renderer_pids_for_profile(request.profile_dir)
                 if request.session_id is not None else [])
    return verifier.verify_all(
        request.profile_dir, list(request.argv), request.privacy_mode,
        request.edge_path, download_dir=request.download_dir,
        renderer_pids=renderers)


class Controller:
    """Owns the session lifecycle. Holds no browser-supplied state."""

    def __init__(self) -> None:
        config.ensure_dirs()
        self.edge_path = config.find_edge()
        self.session: session_manager.Session | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._hosted_hwnd: int | None = None
        self.privacy_mode = MODE_STANDARD
        # Bumped on every session change; results from an older generation are dropped.
        self._generation = 0
        self._verification_seq = 0

    @property
    def generation(self) -> int:
        return self._generation

    def snapshot(self) -> SessionSnapshot:
        """A coherent, immutable view of the session. Never touches a subprocess."""
        session = self.session
        if session is None:
            return SessionSnapshot(
                active=False, mode="", session_id="",
                profile_dir=config.PROFILE_PERSISTENT, is_disposable=False,
                generation=self._generation, elapsed_seconds=0.0)
        elapsed = (datetime.now(timezone.utc) - session.created).total_seconds()
        return SessionSnapshot(
            active=True, mode=session.mode, session_id=session.session_id,
            profile_dir=session.profile_dir, is_disposable=session.is_disposable,
            generation=self._generation, elapsed_seconds=max(0.0, elapsed))


    def verification_request(
            self, mode: str = session_manager.PERSISTENT) -> VerificationRequest:
        """Snapshot the state a pass needs. UI thread only; starts no process."""
        profile = self._profile_for_preview(mode)
        argv = self._build_argv(profile) if self.edge_path else []
        download_dir = (quarantine.quarantine_dir_for(self.session.session_id)
                        if self.session is not None else None)
        self._verification_seq += 1
        return VerificationRequest(
            profile_dir=profile,
            argv=tuple(argv),
            privacy_mode=self.privacy_mode,
            edge_path=self.edge_path,
            download_dir=download_dir,
            session_id=None if self.session is None else self.session.session_id,
            generation=self._generation,
            verification_id=self._verification_seq)

    def verify(self, mode: str = session_manager.PERSISTENT
               ) -> verifier.VerificationResult:
        """Run every check without launching. BLOCKING: it starts a dozen helper
        processes. Timers must use verification_request() and run_verification()."""
        return run_verification(self.verification_request(mode))

    def status(self) -> dict:
        return {
            "session": None if self.session is None else self.session.mode,
            "session_id": None if self.session is None else self.session.session_id,
            "browser_running": self.is_running(),
            "privacy_mode": self.privacy_mode,
            "edge": str(self.edge_path) if self.edge_path else None,
        }

    def is_running(self) -> bool:
        if self._process is not None and self._process.poll() is None:
            return True
        # The launcher can exit after handing off, so a dead Popen proves nothing.
        if self.session is not None:
            return bool(embed.edge_pids_for_profile(self.session.profile_dir))
        return False

    def find_browser_window(self) -> int | None:
        """HWND of this session's Edge window, if it has one yet."""
        if self.session is None:
            return None
        return embed.find_browser_window(
            embed.edge_pids_for_profile(self.session.profile_dir))

    def pending_disposable_downloads(self) -> list:
        """Quarantined files a disposable session would destroy. Empty otherwise."""
        session = self.session
        if session is None or not session.is_disposable:
            return []
        return session_manager.pending_quarantine(session)

    def set_hosted_window(self, hwnd: int | None) -> None:
        """Told by the UI which window it hosted, so titles can be read back."""
        self._hosted_hwnd = hwnd

    def browser_title(self) -> str:
        hwnd = self._hosted_hwnd
        return embed.window_title(hwnd) if hwnd else ""


    def start(self, mode: str, url: str | None = None) -> LaunchOutcome:
        if self.is_running():
            return LaunchOutcome(False, "A bruhswer session is already open.",
                                 self.verify(mode))

        if self.edge_path is None:
            return LaunchOutcome(False, "Microsoft Edge was not found on this PC.",
                                 self.verify(mode))

        session = session_manager.create(mode)

        ok, acl_message = browser_guard.harden_profile_dir(session.profile_dir)
        if not ok:
            _log.error("profile hardening failed: %s", acl_message)
            if session.is_disposable:
                session_manager.destroy(session)
            return LaunchOutcome(
                False, f"BRUH. NO. Could not secure the browser profile: {acl_message}",
                self.verify(mode))

        privacy_guard.apply_to_profile(session.profile_dir, self.privacy_mode)
        privacy_guard.apply_download_directory(
            session.profile_dir, quarantine.quarantine_dir_for(session.session_id))

        argv = self._build_argv(session.profile_dir, url)
        result = verifier.verify_all(
            session.profile_dir, argv, self.privacy_mode, self.edge_path,
            download_dir=quarantine.quarantine_dir_for(session.session_id))

        if not result.may_launch:
            reasons = "; ".join(c.title for c in result.blockers)
            _log.error("launch blocked: %s", reasons)
            if session.is_disposable:
                session_manager.destroy(session)
            return LaunchOutcome(
                False,
                "BRUH. NO. Browser launch blocked because required security controls "
                "could not be verified: " + reasons,
                result)

        self.session = session
        self._generation += 1
        self._process = edge.launch(argv)
        _log.info("session started mode=%s", session.mode)
        return LaunchOutcome(True, "bruhswer READY", result, session)


    def stop(self) -> tuple[bool, str]:
        messages: list[str] = []

        # Bumped first: a pass finishing during the 12s stop would otherwise match.
        self._generation += 1

        # Close like a user first; a kill marks the profile crashed (tab restore offer).
        if self._hosted_hwnd and embed.is_alive(self._hosted_hwnd):
            embed.request_close(self._hosted_hwnd)

        if self._process is not None and self._process.poll() is None:
            try:
                self._process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self._process.terminate()
        self._process = None
        self._hosted_hwnd = None

        # The launcher may have handed off; stop anything still using this profile.
        if self.session is not None:
            self._stop_profile_processes(self.session.profile_dir)

        session, self.session = self.session, None
        if session is None:
            return True, "No session was open."

        if session.is_disposable:
            destroyed, detail = session_manager.destroy(session)
            messages.append(detail)
            return destroyed, " ".join(messages)

        messages.append("Persistent session closed; its profile was kept.")
        return True, " ".join(messages)


    def panic_stop(self) -> tuple[bool, str]:
        """Stop this session's browser IMMEDIATELY; stop() can take 20 seconds.

        Kills only processes proven to be this session's (see
        embed.attributed_edge_processes). The message reports only what was observed.
        """
        session = self.session
        if session is None:
            return False, "No session was open."

        self._generation += 1

        processes = embed.attributed_edge_processes(session.profile_dir)
        if processes is None:
            # Could not enumerate, which is not "nothing was running".
            _log.error("panic: could not enumerate this session's browser processes")
            return False, ("PANIC: bruhswer could not ask Windows which browser "
                           "processes belong to this session, so it stopped nothing. "
                           "Close the browser manually.")

        report = embed.terminate_attributed(processes)
        _log.warning("panic: terminated=%d confirmed=%d refused=%d failed=%d",
                     report.terminated, report.confirmed_exited, report.refused,
                     report.failed)

        self._process = None
        self._hosted_hwnd = None
        self.session = None

        parts = [f"PANIC: {report.terminated} browser process(es) terminated"]
        if report.confirmed_exited < report.terminated:
            parts.append(f"{report.confirmed_exited} confirmed exited")
        if report.refused:
            parts.append(f"{report.refused} left alone (identity no longer matched)")
        if report.failed:
            parts.append(f"{report.failed} could not be terminated")
        if report.already_gone:
            parts.append(f"{report.already_gone} could not be opened")
        message = "; ".join(parts) + "."

        # Success only if every process was SEEN to stop. Having asked once reported
        # "0 terminated; 9 left alone" as success.
        clean = (report.refused == 0 and report.failed == 0
                 and report.already_gone == 0
                 and report.confirmed_exited == report.terminated)
        if not clean:
            message += (" bruhswer could NOT confirm the browser stopped. Check for "
                        "remaining Microsoft Edge windows yourself.")

        if session.is_disposable:
            # Through destroy(), so panic keeps the reparse-point guards.
            destroyed, detail = session_manager.destroy(session)
            if not destroyed:
                return False, (message + " The disposable profile was NOT fully "
                                         "destroyed: " + detail)
            return clean, message + " " + detail

        return clean, message + " The persistent profile was kept."


    def navigate(self, text: str) -> tuple[bool, str]:
        """Open the address-bar text in a new tab. The only user input the controller
        takes: normalised to an http(s) or search URL, or refused."""
        if not self.is_running() or self.session is None:
            return False, "No bruhswer session is open."
        try:
            url = urls.normalise(text)
        except urls.RefusedURL as exc:
            return False, f"BRUH. NO. {exc}"

        if self.edge_path is None:
            return False, "Microsoft Edge was not found on this PC."
        ok = edge.open_in_running_session(self.edge_path, self.session.profile_dir, url)
        if not ok:
            return False, "Could not hand that address to the browser."
        host = urls.display_host(url)
        return True, f"Opened {host}" if host else "Opened a new tab"

    def new_tab(self) -> tuple[bool, str]:
        return self.navigate(urls.BLANK)

    def open_account_settings(self) -> tuple[bool, str]:
        """Open Edge's profile settings, a constant destination. The message says the
        page OPENED, not that the user signed out; the next pass checks that."""
        if not self.is_running() or self.session is None:
            return False, "No bruhswer session is open."
        if self.edge_path is None:
            return False, "Microsoft Edge was not found on this PC."
        if not edge.open_account_settings(self.edge_path, self.session.profile_dir):
            return False, "Could not open the browser's settings page."
        return True, ("Opened Edge's profile settings. Sign out there, then re-run "
                      "BRUH check to confirm the account is gone.")


    def export_request(self, item: quarantine.QuarantinedFile,
                       destination_dir: Path) -> tuple[bool, str]:
        """Export one quarantined file to a folder from the user's own picker."""
        _log.info("export requested from session %s",
                  self.session.session_id if self.session else "<none>")
        return quarantine.export(item, destination_dir)

    def preview_launch_command(self, profile_dir: Path | None = None) -> list[str]:
        """The exact argv bruhswer would launch with, for tests and audits."""
        if self.edge_path is None:
            return []
        target = profile_dir or self._profile_for_preview(session_manager.PERSISTENT)
        return self._build_argv(target)


    @staticmethod
    def _stop_profile_processes(profile_dir: Path, timeout: float = 12.0) -> int:
        """Ask this session's browser processes to stop, then confirm they did."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            pids = embed.edge_pids_for_profile(profile_dir)
            if not pids:
                return 0
            time.sleep(1.0)

        pids = embed.edge_pids_for_profile(profile_dir)
        for pid in pids:
            try:
                subprocess.run(
                    [str(config.POWERSHELL), "-NoProfile", "-NonInteractive",
                     "-Command", f"Stop-Process -Id {int(pid)} -Force "
                                 f"-ErrorAction SilentlyContinue"],
                    capture_output=True, timeout=30, shell=False,
                    creationflags=config.NO_WINDOW)
            except (OSError, subprocess.TimeoutExpired):
                pass
        time.sleep(2.0)
        remaining = embed.edge_pids_for_profile(profile_dir)
        if remaining:
            _log.warning("%d browser process(es) still running after stop",
                         len(remaining))
        return len(remaining)

    def _profile_for_preview(self, mode: str) -> Path:
        if self.session is not None:
            return self.session.profile_dir
        return (config.PROFILE_PERSISTENT if mode == session_manager.PERSISTENT
                else config.PROFILE_DISPOSABLE_ROOT / "preview")

    def _build_argv(self, profile_dir: Path, url: str | None = None) -> list[str]:
        # No --download-directory: it is not a real Chromium switch, and downloads went
        # to the real Downloads folder. Quarantine is a profile preference instead.
        if self.edge_path is None:
            raise RuntimeError("_build_argv called with no browser runtime found")
        extra: tuple[str, ...] = ()
        if self.privacy_mode == MODE_MAXIMUM:
            extra = ("--disable-features=InterestCohort,PrivacySandboxSettings4",)
        return edge.build_command(self.edge_path, profile_dir, extra, url)


# (label, check categories, description). Every guard category must appear here, or
# its checks reach no row; a test enforces it. DOWNLOADS shows only during a session.
STATUS_ROWS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("HOST", ("host",), "This PC's exposure to the network"),
    ("BROWSER", ("edge", "browser"), "Signed runtime, profile isolation and sandbox"),
    ("NETWORK", ("net",), "Where the browser may connect"),
    ("DNS", ("dns",), "Whether name lookups are encrypted"),
    ("PRIVACY", ("privacy",), "Tracking and data minimisation"),
    ("DOWNLOADS", ("downloads",), "Where downloaded files land"),
    ("CONTROLLER", ("controller",), "bruhswer's own privileges"),
)
_OPTIONAL_ROWS = frozenset({"DOWNLOADS"})


def summarise(result: verifier.VerificationResult) -> list[tuple[str, Verdict, str]]:
    """Category rollup for the status panel (brief SS7)."""
    rows = []
    for label, categories, description in STATUS_ROWS:
        checks = [c for category in categories for c in result.by_prefix(f"{category}.")]
        if not checks and label in _OPTIONAL_ROWS:
            continue
        rows.append((label, worst(checks) if checks else Verdict.UNKNOWN, description))
    return rows


def fixed_status_rows(session) -> list[tuple[str, str, str, str]]:
    """(label, value, colour_kind, blurb) rows that are facts, not verdicts, so
    colour_kind is "ok"/"warn"/"off". LOCALHOST is never green."""
    if session is None:
        session_value, session_blurb = "NONE", "No session is open"
    elif session.mode == session_manager.DISPOSABLE:
        session_value = "DISPOSABLE"
        session_blurb = "Profile is destroyed when you close it"
    else:
        session_value = "PERSISTENT"
        session_blurb = "Profile is kept between sessions"

    return [
        ("SESSION", session_value, "ok", session_blurb),
        ("LOCALHOST", "NOT ENFORCEABLE", "warn",
         "Services on this PC stay reachable from the browser. Windows Firewall "
         "cannot filter loopback. bruhswer does not claim to block them."),
        ("VPN", "UNSUPPORTED", "off",
         "No VPN is configured and no kill switch has been demonstrated"),
    ]
