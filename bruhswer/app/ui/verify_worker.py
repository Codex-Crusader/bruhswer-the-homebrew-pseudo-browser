"""Re-run the security checks while a session is open, without freezing the window.

bruhswer used to verify ONCE, at launch, and leave the status lights showing that one
measurement for the life of the session. A deleted firewall rule, an Edge update that
changed the renderer sandbox, a loosened profile ACL - none of it moved them. An
indicator measured an hour ago and presented as current is the same defect as one never
measured, wearing a timestamp.

A full pass starts 14 helper processes and takes 5.5s measured, so it runs on a worker
thread; results go onto a queue.Queue that a short `after()` tick drains.

THE WORKER NEVER TOUCHES A TK OBJECT - not a widget, not `after()`, not a StringVar. Tk
is not thread-safe and calling into it from here does not raise a helpful error, it
corrupts the interpreter. Everything leaves through the queue and is applied by the Tk
thread in `drain()`.

Shutdown: the worker can be blocked inside `subprocess.run(..., timeout=60)` and cannot
observe the stop event until that returns, so the thread is a daemon rather than making
bruhswer wait a minute to exit. That is only acceptable because this worker owns NO
cleanup - it reads state and reports it, and session teardown is the Tk thread's job.
If it ever acquires a destructive responsibility the daemon flag has to go and real
cancellation has to be built.
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

    # Optional, because the measurement_failed path carries the PREVIOUS result -
    # which is None until a first pass has ever succeeded.
    result: verifier.VerificationResult | None
    generation: int
    verification_id: int = 0
    # (check_id, title) for checks that were PASS last time and are not PASS now. The
    # ID rides along so the UI can tell when a warned control RECOVERS: only PASS ->
    # not-PASS is reported, so without it a one-cycle UNKNOWN would leave "something
    # changed while you were browsing" on screen with nothing able to clear it.
    regressions: tuple[tuple[str, str], ...] = ()
    # The pass RAISED and nothing was measured. `result` is then the PREVIOUS result
    # (or None) and the UI must present it as stale, never as fresh green lights.
    measurement_failed: bool = False


def _comparable(result: verifier.VerificationResult) -> dict[str, Verdict]:
    """check_id -> verdict, for the enforceable checks only.

    Unenforceable checks are excluded because they describe the PLATFORM, not this
    run's configuration. `net.loopback` is a permanent FAIL by design; treating it as
    a regression every cycle would bury the transitions that mean something.
    """
    return {c.check_id: c.verdict for c in result.checks if c.enforceable}


def passing_ids(result: verifier.VerificationResult) -> frozenset[str]:
    """check_ids that are currently PASS. Used to notice a warned control recovering."""
    return frozenset(check_id for check_id, verdict in _comparable(result).items()
                     if verdict is Verdict.PASS)


def find_regressions(previous: verifier.VerificationResult | None,
                     current: verifier.VerificationResult
                     ) -> tuple[tuple[str, str], ...]:
    """Checks that were PASS and no longer are.

    ANY non-PASS counts, not just FAIL: "we can no longer tell" is not a quieter kind
    of good news, and leaving the previous green light up would be the original defect.

    Only PASS -> not-PASS is reported. A check that was already UNKNOWN and stays
    UNKNOWN is not news, and re-warning every 60 seconds would train the user to
    dismiss the warning that matters.
    """
    if previous is None:
        return ()
    before = _comparable(previous)
    after = _comparable(current)
    titles = {c.check_id: c.title for c in current.checks}
    return tuple(
        (check_id, titles.get(check_id, check_id))
        for check_id, verdict in after.items()
        if before.get(check_id) is Verdict.PASS and verdict is not Verdict.PASS)


class VerifyWorker:
    """Owns the background thread and the queue. Created and driven by the Tk thread."""

    def __init__(self, interval: float = config.VERIFY_INTERVAL_SECONDS) -> None:
        self._interval = interval
        self._results: queue.Queue[VerificationUpdate] = queue.Queue()
        self._requests: queue.Queue[ctrl.VerificationRequest] = queue.Queue()
        # A FRESH Event per thread. stop() clears _thread after a bounded join, but a
        # worker stuck in a 60s helper call is still alive, and clearing a SHARED event
        # in the next start() would revive it - two loops sharing `_previous`, and
        # spurious "something changed" curtains comparing two different sessions.
        self._stop = threading.Event()
        # Cuts the between-cycles wait short on submit(). Without it a mid-cycle
        # request sat untouched for up to a full interval.
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._previous: verifier.VerificationResult | None = None

    # --- Tk-thread API ----------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        # A NEW event, not a cleared one. Without this the second start() spawns a
        # thread whose _loop re-reads a still-set event and exits, leaving
        # re-verification permanently dead with the lights frozen but still presented
        # as current. New, so a thread unwinding from a previous stop() keeps its own
        # set event and exits rather than being revived. Pinned by
        # test_worker_restarts_after_stop.
        self._stop = threading.Event()
        stop = self._stop
        self._thread = threading.Thread(
            target=self._loop, args=(stop,), name="bruhswer-verify", daemon=True)
        self._thread.start()
        _log.info("re-verification worker started, interval=%.0fs", self._interval)

    def submit(self, request: ctrl.VerificationRequest) -> None:
        """Hand the worker a fresh snapshot. Call from the Tk thread only.

        Replaces any request not yet picked up: a queue of stale snapshots would mean
        the worker verifying a session that has already been closed, and only the most
        recent one is ever interesting.
        """
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
        """Ask the worker to finish. Returns quickly; see the shutdown note above."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            # BOUNDED join. A worker blocked in a 60s subprocess timeout will not be
            # here in time, and bruhswer must not hang its own close waiting for a
            # PowerShell query. The daemon flag covers the rest.
            thread.join(timeout=config.VERIFY_JOIN_TIMEOUT_SECONDS)
        self._thread = None

        # These live on the object, not the thread: the next session starts clean.
        self._previous = None
        self._drain_requests()
        self._wake.clear()

    # --- worker thread ----------------------------------------------------------

    def _loop(self, stop: threading.Event) -> None:
        """The worker body. Touches no Tk object, by construction.

        Takes ITS OWN stop event as an argument rather than reading self._stop, so a
        later start() replacing that attribute cannot resurrect this thread.
        """
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
                    # _run_once guards the verification but not publishing its result.
                    _log.exception("verification cycle failed; worker continues")

            # Returns early on EITHER signal: stop, or a newly submitted request.
            if self._sleep(stop):
                break
        _log.info("re-verification worker stopped")

    def _sleep(self, stop: threading.Event) -> bool:
        """Wait out the interval. True if the worker should stop.

        Polls both signals rather than blocking on one: Python has no wait-for-any-of
        primitive, and the slice is short enough that a submit() feels immediate.
        """
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
            # Losing the thread would stop re-verification and leave the last result on
            # screen looking current. Returning silently does the same by another
            # route, so the failure is published rather than only logged.
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
