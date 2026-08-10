"""Controller — a fixed, closed set of verbs. Nothing else exists.

There is no execute_command, no run_shell, no run_powershell, no eval, no exec, and no
way to ask the controller to run something of your choosing (brief SS15). The verbs are
methods on this class; there is no dispatcher that maps an arbitrary string to code.

This matters more here than in the earlier VM designs, because Stage 4 measured that a
compromised browser process CAN reach localhost and that nothing can stop it. So the
controller's attack surface has to be small by construction rather than by filtering.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..browser import edge, embed, urls
from ..downloads import quarantine
from ..logging_setup import get_logger
from ..privacy import privacy_guard
from ..security import browser_guard, verifier
from ..sessions import session_manager
from ..verdict import Verdict

_log = get_logger("controller")

MODE_STANDARD = "standard"
MODE_MAXIMUM = "maximum"


@dataclass
class LaunchOutcome:
    launched: bool
    message: str
    result: verifier.VerificationResult
    session: session_manager.Session | None = None


class Controller:
    """Owns the session lifecycle. Holds no browser-supplied state."""

    def __init__(self) -> None:
        config.ensure_dirs()
        self.edge_path = config.find_edge()
        self.session: session_manager.Session | None = None
        self._process = None
        self._hosted_hwnd: int | None = None
        self.privacy_mode = MODE_STANDARD

    # --- STATUS / VERIFY --------------------------------------------------------

    def verify(self, mode: str = session_manager.PERSISTENT) -> verifier.VerificationResult:
        """Run every check without launching anything."""
        profile = self._profile_for_preview(mode)
        argv = self._build_argv(profile) if self.edge_path else []
        renderers = (embed.renderer_pids_for_profile(self.session.profile_dir)
                     if self.session is not None else [])
        return verifier.verify_all(profile, argv, self.privacy_mode, self.edge_path,
                                   renderer_pids=renderers)

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
        # Edge's launcher process can exit after handing off to an existing instance,
        # so a dead Popen handle is not proof the browser is gone. Ask the OS.
        if self.session is not None:
            return bool(embed.edge_pids_for_profile(self.session.profile_dir))
        return False

    def find_browser_window(self) -> int | None:
        """HWND of this session's Edge window, if it has one yet."""
        if self.session is None:
            return None
        return embed.find_browser_window(
            embed.edge_pids_for_profile(self.session.profile_dir))

    def set_hosted_window(self, hwnd: int | None) -> None:
        """Told by the UI which window it hosted, so titles can be read back."""
        self._hosted_hwnd = hwnd

    def browser_title(self) -> str:
        hwnd = self._hosted_hwnd
        return embed.window_title(hwnd) if hwnd else ""

    # --- START ------------------------------------------------------------------

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
            # An unusable profile is a broken session, not a warning to log and ignore.
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
        self._process = edge.launch(argv)
        _log.info("session started mode=%s", session.mode)
        return LaunchOutcome(True, "bruhswer READY", result, session)

    # --- STOP -------------------------------------------------------------------

    def stop(self) -> tuple[bool, str]:
        messages: list[str] = []

        # Ask the window to close first, the way a user would. Killing the process
        # leaves the profile flagged as crashed, which makes the NEXT launch offer to
        # restore the previous session's tabs - bad for a browser built around
        # controlled session state.
        if self._hosted_hwnd and embed.is_alive(self._hosted_hwnd):
            embed.request_close(self._hosted_hwnd)

        if self._process is not None and self._process.poll() is None:
            try:
                self._process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self._process.terminate()
        self._process = None
        self._hosted_hwnd = None

        # Terminating the launcher does not always take the browser with it: Edge's
        # first process can exit after handing off. Stop anything still using this
        # profile, or a "destroyed" disposable profile would stay locked and alive.
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

    # --- NAVIGATE ---------------------------------------------------------------

    def navigate(self, text: str) -> tuple[bool, str]:
        """Address-bar navigation. Opens a new tab in the running session.

        `text` is the only place user input enters the controller. It is normalised to
        an http(s) URL or a search URL, or refused - never passed through raw, never
        given to a shell, and never used to build a path.
        """
        if not self.is_running() or self.session is None:
            return False, "No bruhswer session is open."
        try:
            url = urls.normalise(text)
        except urls.RefusedURL as exc:
            return False, f"BRUH. NO. {exc}"

        ok = edge.open_in_running_session(self.edge_path, self.session.profile_dir, url)
        if not ok:
            return False, "Could not hand that address to the browser."
        host = urls.display_host(url)
        return True, f"Opened {host}" if host else "Opened a new tab"

    def new_tab(self) -> tuple[bool, str]:
        return self.navigate(urls.BLANK)

    # --- EXPORT_REQUEST ---------------------------------------------------------

    def export_request(self, item: quarantine.QuarantinedFile,
                       destination_dir: Path) -> tuple[bool, str]:
        """Export one quarantined file. The DESTINATION comes from the user's own
        folder picker in bruhswer's UI -- never from a webpage, a download, or an IPC
        message. bruhswer does not run the file."""
        _log.info("export requested from session %s",
                  self.session.session_id if self.session else "<none>")
        return quarantine.export(item, destination_dir)

    def preview_launch_command(self, profile_dir: Path | None = None) -> list[str]:
        """The exact argv bruhswer would launch with. Read-only.

        Public so tests and audits can inspect the command line without reaching
        into a private method - the launch command is a security-relevant fact,
        not an implementation detail.
        """
        if self.edge_path is None:
            return []
        target = profile_dir or self._profile_for_preview(session_manager.PERSISTENT)
        return self._build_argv(target)

    # --- internals --------------------------------------------------------------

    @staticmethod
    def _stop_profile_processes(profile_dir: Path, timeout: float = 12.0) -> int:
        """Ask this session's browser processes to stop, then confirm they did."""
        import time as _time

        deadline = _time.time() + timeout
        while _time.time() < deadline:
            pids = embed.edge_pids_for_profile(profile_dir)
            if not pids:
                return 0
            _time.sleep(1.0)

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
        _time.sleep(2.0)
        remaining = embed.edge_pids_for_profile(profile_dir)
        if remaining:
            _log.warning("%d browser process(es) still running after stop", len(remaining))
        return len(remaining)

    def _profile_for_preview(self, mode: str) -> Path:
        if self.session is not None:
            return self.session.profile_dir
        return (config.PROFILE_PERSISTENT if mode == session_manager.PERSISTENT
                else config.PROFILE_DISPOSABLE_ROOT / "preview")

    def _build_argv(self, profile_dir: Path, url: str | None = None) -> list[str]:
        # NOTE: there is deliberately no --download-directory here. It is not a real
        # Chromium switch; Edge ignored it and downloads went to the user's real
        # Downloads folder. The quarantine location is set as a PROFILE PREFERENCE in
        # privacy_guard.apply_download_directory() and verified on every launch.
        extra: tuple[str, ...] = ()
        if self.privacy_mode == MODE_MAXIMUM:
            extra = ("--disable-features=InterestCohort,PrivacySandboxSettings4",)
        return edge.build_command(self.edge_path, profile_dir, extra, url)


def summarise(result: verifier.VerificationResult) -> list[tuple[str, Verdict, str]]:
    """Category rollup for the status panel (brief SS7)."""
    rows = [
        ("HOST", result.category("host."), "This PC's exposure to the network"),
        ("BROWSER", result.category("browser."), "Profile isolation and sandbox"),
        ("NETWORK", result.category("net."), "Where the browser may connect"),
        ("DNS", result.category("dns."), "Whether name lookups are encrypted"),
        ("PRIVACY", result.category("privacy."), "Tracking and data minimisation"),
        ("CONTROLLER", result.category("controller."), "bruhswer's own privileges"),
    ]
    if result.by_prefix("downloads."):
        rows.insert(5, ("DOWNLOADS", result.category("downloads."),
                        "Where downloaded files land"))
    return rows


def fixed_status_rows(session) -> list[tuple[str, str, str, str]]:
    """Rows that are statements of fact, not verdicts (brief SS34).

    Returns (label, value, colour_kind, blurb). `colour_kind` is one of
    "ok" / "warn" / "off" - deliberately NOT a Verdict, because none of these is a
    check that passed or failed. LOCALHOST in particular must never render green:
    it is a measured platform limitation, and pretending otherwise is the one thing
    this project refuses to do.
    """
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
