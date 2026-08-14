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


@dataclass(frozen=True)
class VerificationRequest:
    """An immutable snapshot of everything a verification pass needs.

    EXISTS SO VERIFICATION CAN RUN OFF THE UI THREAD SAFELY.

    `Controller.verify()` reads `self.session` and `self.privacy_mode` while it runs.
    That is fine on one thread, but the re-verification worker runs concurrently with
    `start()` and `stop()` - and `stop()` DELETES a disposable profile directory. A
    worker holding `self.session` could therefore be reading a profile path that the UI
    thread is in the middle of destroying, and would report checks about a session that
    no longer exists.

    So the UI thread builds one of these under its own control, hands it over by value,
    and the worker calls `run_verification()` below, which touches no shared state at
    all. `generation` lets a result that arrives after the session changed be dropped
    rather than displayed.
    """

    profile_dir: Path
    argv: tuple[str, ...]
    privacy_mode: str
    edge_path: Path | None
    download_dir: Path | None
    session_id: str | None
    generation: int


def run_verification(request: VerificationRequest) -> verifier.VerificationResult:
    """Pure verification from a snapshot. Safe to call on a worker thread.

    Reads no controller attribute and mutates nothing. The renderer-PID query lives
    here rather than in the snapshot because it is itself a ~258ms PowerShell call and
    belongs on the worker, not on the UI thread that built the request.
    """
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
        # Annotated: a Popen is assigned to this later, so a bare `= None` makes the
        # attribute's inferred type None and every later assignment an error.
        self._process: subprocess.Popen[bytes] | None = None
        self._hosted_hwnd: int | None = None
        self.privacy_mode = MODE_STANDARD
        # Bumped every time the session changes. A verification result carrying an old
        # generation describes a session that is gone and is discarded rather than
        # shown - see VerificationRequest.
        self._generation = 0

    @property
    def generation(self) -> int:
        return self._generation

    # --- STATUS / VERIFY --------------------------------------------------------

    def verification_request(
            self, mode: str = session_manager.PERSISTENT) -> VerificationRequest:
        """Snapshot the state a verification needs. MUST be called on the UI thread.

        Cheap and non-blocking on purpose: it copies attributes and builds an argv
        list, and does not start a single helper process. All the slow work happens in
        run_verification(), which takes only this snapshot.
        """
        profile = self._profile_for_preview(mode)
        argv = self._build_argv(profile) if self.edge_path else []
        download_dir = (quarantine.quarantine_dir_for(self.session.session_id)
                        if self.session is not None else None)
        return VerificationRequest(
            profile_dir=profile,
            argv=tuple(argv),
            privacy_mode=self.privacy_mode,
            edge_path=self.edge_path,
            download_dir=download_dir,
            session_id=None if self.session is None else self.session.session_id,
            generation=self._generation)

    def verify(self, mode: str = session_manager.PERSISTENT) -> verifier.VerificationResult:
        """Run every check without launching anything.

        BLOCKING, and it starts 15 helper processes. Kept for the synchronous callers
        (startup, the BRUH panel, the tests). Anything on a timer must go through
        verification_request() + run_verification() on a worker instead.
        """
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
        self._generation += 1
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
        self._generation += 1
        if session is None:
            return True, "No session was open."

        if session.is_disposable:
            destroyed, detail = session_manager.destroy(session)
            messages.append(detail)
            return destroyed, " ".join(messages)

        messages.append("Persistent session closed; its profile was kept.")
        return True, " ".join(messages)

    # --- PANIC ------------------------------------------------------------------

    def panic_stop(self) -> tuple[bool, str]:
        """Stop this session's browser IMMEDIATELY. Deliberately not stop().

        WHY NOT stop(): that path is graceful by design - it posts WM_CLOSE, waits up
        to 8 seconds for the launcher, and then waits up to 12 more before force
        targeting anything. Twenty seconds is not a panic. The graceful path exists for
        good reasons (a clean exit avoids the profile being marked as crashed, which
        would make the next launch offer to restore tabs), and this is an explicit,
        documented exception to it rather than a replacement.

        THE ACCEPTED COST, stated rather than discovered later: force-killing leaves
        the profile marked as crashed. `--hide-crash-restore-bubble` and
        `session.restore_on_startup` already blunt what the user sees, and a disposable
        profile is deleted immediately afterwards anyway. For a panic control that is
        the right trade.

        WHAT IT WILL NOT DO: touch any Edge process it cannot prove belongs to this
        session. Attribution is by exact `--user-data-dir` match plus a process
        creation time re-checked against the opened handle, so a recycled PID - even
        one that became another msedge.exe, i.e. the user's own browser - is refused.

        The returned message describes only what was OBSERVED. If the profile could not
        be destroyed because files were still locked, it says so; it never prints
        "destroyed and verified gone" on the strength of having asked.
        """
        session = self.session
        if session is None:
            return False, "No session was open."

        processes = embed.attributed_edge_processes(session.profile_dir)
        if processes is None:
            # Could not enumerate. Saying "nothing was running" here would be a claim
            # bruhswer just failed to establish, on the one path where being wrong
            # matters most.
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
        self._generation += 1

        parts = [f"PANIC: {report.terminated} browser process(es) terminated"]
        if report.confirmed_exited < report.terminated:
            # TerminateProcess is asynchronous. Only the ones actually observed to exit
            # may be described as gone.
            parts.append(f"{report.confirmed_exited} confirmed exited")
        if report.refused:
            parts.append(f"{report.refused} left alone (identity no longer matched)")
        if report.failed:
            parts.append(f"{report.failed} could not be terminated")
        if report.already_gone:
            parts.append(f"{report.already_gone} could not be opened")
        message = "; ".join(parts) + "."

        # WHETHER THIS COUNTS AS SUCCESS. Returning True here on the strength of having
        # ASKED is the panic-shaped version of this project's oldest defect, and a real
        # walkthrough produced exactly that: "0 terminated; 9 left alone" was reported
        # as a green success while nine Edge processes were still running and the
        # controller had already forgotten the session.
        #
        # So success requires every process observed to be in a terminal state:
        # everything terminated was confirmed exited, nothing was refused, nothing
        # failed, and nothing was left unopenable (an OpenProcess failure may mean the
        # process is gone, but it may equally mean bruhswer could not look - and
        # "could not look" is not "it stopped").
        clean = (report.refused == 0 and report.failed == 0
                 and report.already_gone == 0
                 and report.confirmed_exited == report.terminated)
        if not clean:
            message += (" bruhswer could NOT confirm the browser stopped. Check for "
                        "remaining Microsoft Edge windows yourself.")

        if session.is_disposable:
            # Still through session_manager.destroy(), which keeps the reparse-point
            # and containment guards. Panic does not get a shortcut around those.
            destroyed, detail = session_manager.destroy(session)
            if not destroyed:
                return False, (message + " The disposable profile was NOT fully "
                                         "destroyed: " + detail)
            return clean, message + " " + detail

        return clean, message + " The persistent profile was kept."

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
        """Open Edge's profile settings, where the user can sign out. Closed verb.

        Takes no argument. The destination is a constant inside edge.py, so this cannot
        be steered anywhere else.

        The message says the page was OPENED. It does not say the user was signed out,
        because bruhswer has not checked and could not have - that is established only
        by re-reading the profile, which the next verification pass does.
        """
        if not self.is_running() or self.session is None:
            return False, "No bruhswer session is open."
        if self.edge_path is None:
            return False, "Microsoft Edge was not found on this PC."
        if not edge.open_account_settings(self.edge_path, self.session.profile_dir):
            return False, "Could not open the browser's settings page."
        return True, ("Opened Edge's profile settings. Sign out there, then re-run "
                      "BRUH check to confirm the account is gone.")

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
        # Every caller checks edge_path first (start() refuses without it, and both
        # verification_request() and preview_launch_command() guard). Stating the
        # precondition here turns an implicit invariant into a checked one.
        if self.edge_path is None:
            raise RuntimeError("_build_argv called with no browser runtime found")
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
