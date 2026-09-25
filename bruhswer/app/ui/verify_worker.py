"""Re-run the checks every minute during a session, so the lights stay current.

The worker thread NEVER touches a Tk object: Tk is not thread-safe. Results leave
through a queue that the Tk thread drains.

The thread is a daemon because it can sit in a 60s subprocess timeout. That is safe
only because it owns no cleanup; if it ever does, build real cancellation.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass

from .. import config
from ..controller import controller as ctrl
from ..logging_setup import get_logger
from ..security import verifier
from ..verdict import Verdict

_log = get_logger("verifyworker")


@dataclass(frozen=True)
class VerificationUpdate:
    """One completed pass, plus what changed since the last one."""

    # None until a first pass has ever succeeded.
    result: verifier.VerificationResult | None
    generation: int
    verification_id: int = 0
    # (check_id, title) of checks that went PASS -> not PASS. The id lets the UI see
    # the control recover and withdraw the warning.
    regressions: tuple[tuple[str, str], ...] = ()
    # The pass raised; `result` is the previous one and must be shown as stale.
    measurement_failed: bool = False


def _comparable(result: verifier.VerificationResult) -> dict[str, Verdict]:
    """check_id -> verdict for enforceable checks. net.loopback is a permanent FAIL."""
    return {c.check_id: c.verdict for c in result.checks if c.enforceable}


def passing_ids(result: verifier.VerificationResult) -> frozenset[str]:
    """check_ids that are currently PASS."""
    return frozenset(check_id for check_id, verdict in _comparable(result).items()
                     if verdict is Verdict.PASS)


def find_regressions(previous: verifier.VerificationResult | None,
                     current: verifier.VerificationResult
                     ) -> tuple[tuple[str, str], ...]:
    """Checks that were PASS and now are not, UNKNOWN included. Staying non-PASS is not
    reported again, or the warning would repeat every minute."""
    if previous is None:
        return ()
    before = _comparable(previous)
    after = _comparable(current)
    titles = {c.check_id: c.title for c in previous.checks}
    titles.update((c.check_id, c.title) for c in current.checks)
    changed = [check_id for check_id, verdict in after.items()
               if before.get(check_id) is Verdict.PASS and verdict is not Verdict.PASS]

    # A vanished check is normal (downloads.* exists only during a session), unless a
    # guard in its category crashed: then the absence IS the crash.
    crashed = {category for c in current.checks
               if (category := verifier.guard_failure_category(c.check_id))}
    vanished = [check_id for check_id, verdict in before.items()
                if verdict is Verdict.PASS and check_id not in after
                and check_id.split(".", 1)[0] in crashed]
    return tuple((check_id, titles.get(check_id, check_id))
                 for check_id in changed + vanished)


class VerifyWorker:
    """Owns the background thread and the queue. Created and driven by the Tk thread."""

    def __init__(self, interval: float = config.VERIFY_INTERVAL_SECONDS) -> None:
        self._interval = interval
        self._results: queue.Queue[VerificationUpdate] = queue.Queue()
        self._requests: queue.Queue[ctrl.VerificationRequest] = queue.Queue()
        # A fresh Event per thread; clearing a shared one would revive a stuck old thread.
        self._stop = threading.Event()
        # Wakes the worker early on submit().
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._previous: verifier.VerificationResult | None = None


    def start(self) -> None:
        if self._thread is not None:
            return
        # A new event: a cleared shared one left the restarted worker dead.
        self._stop = threading.Event()
        stop = self._stop
        self._thread = threading.Thread(
            target=self._loop, args=(stop,), name="bruhswer-verify", daemon=True)
        self._thread.start()
        _log.info("re-verification worker started, interval=%.0fs", self._interval)

    def submit(self, request: ctrl.VerificationRequest) -> None:
        """Hand the worker a snapshot, replacing any not yet picked up. Tk thread only."""
        self._drain_requests()
        self._requests.put(request)
        self._wake.set()

    def _drain_requests(self) -> None:
        while True:
            try:
                self._requests.get_nowait()
            except queue.Empty:
                return

    def drain(self) -> list[VerificationUpdate]:
        """Take everything the worker has finished. Call from the Tk thread only."""
        out: list[VerificationUpdate] = []
        while True:
            try:
                out.append(self._results.get_nowait())
            except queue.Empty:
                return out

    def stop(self) -> None:
        """Ask the worker to finish. Returns quickly."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            # Bounded, so closing never waits on a 60s PowerShell timeout.
            thread.join(timeout=config.VERIFY_JOIN_TIMEOUT_SECONDS)
        self._thread = None

        self._previous = None
        self._drain_requests()
        self._wake.clear()


    def _loop(self, stop: threading.Event) -> None:
        """The worker body. Takes its own stop event, so a later start() cannot revive
        this thread."""
        request: ctrl.VerificationRequest | None = None
        while not stop.is_set():
            try:
                request = self._requests.get_nowait()
            except queue.Empty:
                pass

            if request is not None:
                try:
                    self._run_once(request)
                except Exception:              # noqa: BLE001  # lint: allow broad-except - nothing may kill this thread
                    _log.exception("verification cycle failed; worker continues")

            if self._sleep(stop):
                break
        _log.info("re-verification worker stopped")

    def _sleep(self, stop: threading.Event) -> bool:
        """Wait out the interval, waking on stop or submit. True means stop."""
        deadline = time.monotonic() + self._interval
        while time.monotonic() < deadline:
            if stop.wait(config.VERIFY_WAKE_POLL_SECONDS):
                return True
            if self._wake.is_set():
                self._wake.clear()
                return False
        return False

    def _run_once(self, request: ctrl.VerificationRequest) -> None:
        try:
            result = ctrl.run_verification(request)
        except Exception:                          # noqa: BLE001  # lint: allow broad-except - a crashed pass must not kill the worker
            # Published, not just logged, or the last result would look current.
            _log.exception("verification pass failed; worker continues")
            self._results.put(VerificationUpdate(
                result=self._previous, generation=request.generation,
                verification_id=request.verification_id,
                regressions=(), measurement_failed=True))
            return

        regressions = find_regressions(self._previous, result)
        self._previous = result
        if regressions:
            _log.warning("controls regressed since the last pass: %s",
                         ", ".join(check_id for check_id, _title in regressions))
        self._results.put(VerificationUpdate(
            result=result, generation=request.generation,
            verification_id=request.verification_id,
            regressions=regressions))
