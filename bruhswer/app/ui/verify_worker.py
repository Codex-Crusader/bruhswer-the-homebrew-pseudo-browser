"""Re-run the security checks while a session is open, without freezing the window.

WHY THIS EXISTS
    bruhswer used to verify ONCE, at launch, and then leave six status lights showing
    that one measurement for as long as the session stayed open. A firewall rule
    deleted by another admin tool, an Edge update that changed the renderer sandbox, a
    profile whose ACL was loosened - none of it moved the lights. The user went on
    reading a green indicator that described a moment that had passed.

    This project's rule is that a security indicator which was never measured is a
    vulnerability. An indicator that WAS measured, an hour ago, and is presented as
    current, is the same defect wearing a timestamp.

WHY IT NEEDS A THREAD
    A full pass starts 14 helper processes - 13 PowerShell plus one icacls - and takes
    5.5 seconds measured. Running that from a Tk `after()` callback would freeze the
    window for five seconds, once a minute, forever.

    So: a worker thread runs the checks, results go onto a `queue.Queue`, and a short
    `after()` tick on the Tk thread drains the queue.

THE RULE THAT MATTERS MOST
    THE WORKER NEVER TOUCHES A TK OBJECT. Not a widget, not `after()`, not `destroy()`,
    not a StringVar. Tk is not thread-safe, and calling into it from here does not
    raise a helpful error - it corrupts the interpreter or hard-crashes the process.
    Everything this thread produces leaves through the queue and is applied by the Tk
    thread in `drain()`.

SHUTDOWN, STATED HONESTLY
    The worker can be blocked inside `subprocess.run(..., timeout=60)` when the user
    closes the window. It cannot observe the stop event until that helper returns, and
    setting the event does NOT cancel the child process. The thread is therefore a
    daemon: bruhswer exits promptly and Python tears the thread down rather than
    waiting up to a minute for a PowerShell query nobody wants any more.

    That is only acceptable because this worker owns NO cleanup. It never deletes a
    profile, never destroys a session, never writes to the quarantine. It reads state
    and reports it. Session teardown is the Tk thread's job and always was. If this
    worker ever acquires a destructive responsibility, the daemon flag has to go and
    real cancellation has to be built - so it must not acquire one.
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
    # (check_id, title) for checks that were PASS last time and are not PASS now.
    #
    # The ID is carried alongside the title so the UI can tell when a warned control
    # RECOVERS. Without it the window could raise a warning it had no way to take
    # back: a single failed PowerShell query flips a check to UNKNOWN for one cycle,
    # the next cycle succeeds and it returns to PASS, and because only PASS ->
    # not-PASS is ever reported, nothing would arrive to clear the warning. The user
    # would be left staring at "something changed while you were browsing" over a
    # session where nothing had.
    regressions: tuple[tuple[str, str], ...] = ()
    # True when the pass RAISED and nothing was measured. `result` is then the
    # PREVIOUS result (or None), and the UI must present it as stale rather than
    # current - never as a fresh set of green lights.
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

    ANY non-PASS counts, not just FAIL. A control that used to verify and now cannot be
    verified at all is exactly as important under this project's rule as one that
    verifiably broke - "we can no longer tell" is not a quieter kind of good news, and
    leaving the previous green light up while it is true would be the original defect
    all over again.

    Only PASS -> not-PASS is reported. A check that was already UNKNOWN and stays
    UNKNOWN is not news, and re-warning about it every 60 seconds would train the user
    to dismiss the warning that matters.
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
        # A FRESH Event per thread, not one shared across the object's life.
        # stop() clears _thread after a bounded join, but a worker stuck in a 60s
        # helper call is still alive; if the next start() then cleared a SHARED
        # event, that old thread would resume its loop and run alongside the new
        # one - two verification loops sharing `_previous`, producing extra helper
        # batches and spurious "something changed" curtains built from a comparison
        # across two different sessions.
        self._stop = threading.Event()
        # Set by submit() to cut the between-cycles wait short. Without it a request
        # handed over mid-cycle sat untouched until the full interval expired, so a
        # "re-verify this session now" could be up to a minute late - and the GUI
        # walkthrough caught exactly that, having passed previously only when the
        # submit happened to land near the start of a cycle.
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._previous: verifier.VerificationResult | None = None

    # --- Tk-thread API ----------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        # CLEAR THE STOP EVENT FIRST. Without this, the second start() in a session's
        # life spawns a thread whose _loop immediately re-reads a still-set event and
        # exits - so closing a session and opening a new one left re-verification
        # permanently dead, with submit() queueing requests nothing would ever read and
        # the status lights frozen on the last result while still presented as current.
        #
        # That is the launch-time-snapshot defect this whole module exists to remove,
        # reintroduced by one missing line. test_worker_restarts_after_stop pins it.
        # A NEW Event, so any thread still unwinding from a previous stop() keeps
        # its own set event and exits, rather than being revived by this clear().
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
        while True:
            try:
                self._requests.get_nowait()
            except queue.Empty:
                break
        self._requests.put(request)
        self._wake.set()

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

        # Drop the baseline: it lives on this object, not the thread, so without this
        # the next session's first pass is diffed against the previous session's last.
        self._previous = None

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

            # Wait for the interval, but return early for EITHER signal: stop (so
            # closing bruhswer does not leave a thread in a 60-second nap) or a newly
            # submitted request (so re-verifying a session is prompt rather than
            # whenever the cycle happens to come round).
            if self._sleep(stop):
                break
        _log.info("re-verification worker stopped")

    def _sleep(self, stop: threading.Event) -> bool:
        """Wait out the interval. True if the worker should stop.

        Polls both signals rather than blocking on one, because Python has no
        wait-for-any-of-these-events primitive. The slice is short enough that a
        submit() feels immediate and long enough that this costs nothing.
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
            # A crash in here must not kill the worker: losing the thread would
            # silently stop re-verification and leave the last result on screen
            # looking current, which is the exact failure this module exists to end.
            _log.exception("verification pass failed; worker continues")
            # AND IT MUST NOT RETURN SILENTLY EITHER. Logging and returning left the
            # UI with no idea the pass had failed, so it kept the previous result and
            # its green lights and went on presenting them as current - the same
            # stale-indicator defect, just reached by a different route. Publishing an
            # explicit failed-measurement update lets the window say so.
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
