"""Tests for runtime re-verification.

The part worth testing here is not the thread - it is the DECISION about what counts as
a control that stopped holding. Getting that wrong in either direction is bad in a way
this project cares about:

  too quiet  a control silently degrades and the light stays green, which is the
             launch-time-snapshot defect the worker exists to end
  too loud   the user is warned every 60 seconds about a check that was already
             UNKNOWN and has not changed, and learns to dismiss the warning that
             actually means something

`find_regressions` is a pure function over two results, so all of that is testable
without Tk, without a browser, and without a thread.
"""

from __future__ import annotations

import queue
import sys
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.security.verifier import VerificationResult  # noqa: E402
from app.ui import verify_worker  # noqa: E402
from app.verdict import Check, Verdict  # noqa: E402


def _result(*checks: Check) -> VerificationResult:
    return VerificationResult(checks=list(checks))


def _check(check_id: str, verdict: Verdict, *, enforceable: bool = True,
           critical: bool = False) -> Check:
    return Check(check_id, f"title for {check_id}", verdict,
                 detail="", evidence="", critical=critical, enforceable=enforceable)


class TestFindRegressions(unittest.TestCase):

    def test_no_previous_result_is_never_a_regression(self):
        """The first pass has nothing to compare against."""
        current = _result(_check("net.rule.x", Verdict.FAIL))
        self.assertEqual(verify_worker.find_regressions(None, current), ())

    def test_pass_to_fail_is_reported(self):
        before = _result(_check("net.rule.x", Verdict.PASS))
        after = _result(_check("net.rule.x", Verdict.FAIL))
        self.assertEqual(verify_worker.find_regressions(before, after),
                         (("net.rule.x", "title for net.rule.x"),))

    def test_pass_to_unknown_is_also_reported(self):
        """'We can no longer verify this' is not a quieter kind of good news.

        Under this project's rule UNKNOWN never rounds up to PASS, so a control that
        drops from verified to unverifiable must move the indicator exactly as a
        verified failure does.
        """
        before = _result(_check("browser.sandbox", Verdict.PASS))
        after = _result(_check("browser.sandbox", Verdict.UNKNOWN))
        self.assertEqual(verify_worker.find_regressions(before, after),
                         (("browser.sandbox", "title for browser.sandbox"),))

    def test_already_unknown_and_still_unknown_is_not_reported(self):
        """Otherwise dns.encrypted, a permanent UNKNOWN, would fire every 60 seconds."""
        before = _result(_check("dns.encrypted", Verdict.UNKNOWN))
        after = _result(_check("dns.encrypted", Verdict.UNKNOWN))
        self.assertEqual(verify_worker.find_regressions(before, after), ())

    def test_already_failing_and_still_failing_is_not_reported(self):
        before = _result(_check("net.rule.x", Verdict.FAIL))
        after = _result(_check("net.rule.x", Verdict.FAIL))
        self.assertEqual(verify_worker.find_regressions(before, after), ())

    def test_recovery_is_not_reported_as_a_regression(self):
        before = _result(_check("net.rule.x", Verdict.FAIL))
        after = _result(_check("net.rule.x", Verdict.PASS))
        self.assertEqual(verify_worker.find_regressions(before, after), ())

    def test_unenforceable_checks_are_excluded(self):
        """net.loopback is a permanent, by-design FAIL describing the PLATFORM.

        If it were compared, every single cycle would report a regression and the
        warning would be worthless.
        """
        before = _result(_check("net.loopback", Verdict.PASS, enforceable=False))
        after = _result(_check("net.loopback", Verdict.FAIL, enforceable=False))
        self.assertEqual(verify_worker.find_regressions(before, after), ())

    def test_a_check_that_disappears_is_not_reported(self):
        """Checks come and go with session state - downloads.* only exists once a
        session is open. A vanished check is not a failed one."""
        before = _result(_check("downloads.quarantine", Verdict.PASS))
        after = _result(_check("net.rule.x", Verdict.PASS))
        self.assertEqual(verify_worker.find_regressions(before, after), ())

    def test_multiple_regressions_are_all_reported(self):
        before = _result(_check("a", Verdict.PASS), _check("b", Verdict.PASS),
                         _check("c", Verdict.PASS))
        after = _result(_check("a", Verdict.FAIL), _check("b", Verdict.UNKNOWN),
                        _check("c", Verdict.PASS))
        self.assertEqual(set(verify_worker.find_regressions(before, after)),
                         {("a", "title for a"), ("b", "title for b")})


class TestWorkerLifecycle(unittest.TestCase):
    """The threading contract, exercised without Tk and without real verification."""

    def test_submit_keeps_only_the_newest_request(self):
        """A backlog of snapshots would mean verifying sessions that already closed."""
        worker = verify_worker.VerifyWorker(interval=0.01)
        for generation in range(5):
            worker.submit(_FakeRequest(generation))
        self.assertEqual(worker._requests.qsize(), 1)  # lint: allow protected-access - asserts the worker's threading contract
        self.assertEqual(worker._requests.get_nowait().generation, 4)  # lint: allow protected-access - asserts the worker's threading contract

    def test_stop_returns_promptly_even_while_a_pass_is_running(self):
        """Closing bruhswer must not block on an in-flight PowerShell query.

        Simulates the real hazard: the worker is inside a slow call when the user
        closes the window. stop() must return in well under the length of that call.
        """
        worker = verify_worker.VerifyWorker(interval=0.01)
        entered = threading.Event()

        def slow_verification(_request):
            entered.set()
            time.sleep(3.0)          # stands in for subprocess.run(timeout=60)
            return _result()

        original = verify_worker.ctrl.run_verification
        verify_worker.ctrl.run_verification = slow_verification
        try:
            worker.start()
            worker.submit(_FakeRequest(0))
            self.assertTrue(entered.wait(timeout=5.0), "worker never started a pass")
            started = time.perf_counter()
            worker.stop()
            elapsed = time.perf_counter() - started
        finally:
            verify_worker.ctrl.run_verification = original

        self.assertLess(
            elapsed, 2.5,
            f"stop() blocked for {elapsed:.1f}s; bruhswer would hang on close")

    def test_a_crashing_pass_does_not_kill_the_worker(self):
        """If the thread dies, re-verification stops silently and the last result stays
        on screen looking current - the exact defect the worker exists to prevent."""
        worker = verify_worker.VerifyWorker(interval=0.01)
        calls: queue.Queue[int] = queue.Queue()

        def sometimes_explodes(request):
            calls.put(request.generation)
            if request.generation == 0:
                raise RuntimeError("boom")
            return _result(_check("ok", Verdict.PASS))

        original = verify_worker.ctrl.run_verification
        verify_worker.ctrl.run_verification = sometimes_explodes
        try:
            worker.start()
            worker.submit(_FakeRequest(0))
            time.sleep(0.3)
            worker.submit(_FakeRequest(1))
            deadline = time.time() + 5.0
            seen: list[int] = []
            while time.time() < deadline and 1 not in seen:
                try:
                    seen.append(calls.get(timeout=0.2))
                except queue.Empty:
                    pass
            worker.stop()
        finally:
            verify_worker.ctrl.run_verification = original

        self.assertIn(0, seen, "the exploding pass never ran")
        self.assertIn(1, seen, "worker died on the exception and stopped verifying")


class TestWorkerRestartsAfterStop(unittest.TestCase):
    """Regression: closing a session and opening a new one killed re-verification.

    stop() sets the shutdown Event; start() did not clear it. So the SECOND start()
    in a session's life spawned a thread that read a still-set event and exited at
    once. submit() then queued requests nobody would ever read, the drain loop found
    nothing forever, and the status lights stayed frozen on the last result while
    still being presented as current - the launch-time-snapshot defect the worker
    exists to remove, reintroduced by one missing line.

    This is the ordinary path, not an edge case: close session -> "New session".
    """

    def test_worker_restarts_after_stop(self):
        worker = verify_worker.VerifyWorker(interval=0.01)
        ran: queue.Queue[int] = queue.Queue()

        def record_and_pass(request):
            # A real function, not a lambda abusing a tuple to sequence two
            # expressions. queue.put() returns None, so using it as a value was both
            # opaque and something every inspector flags.
            ran.put(request.generation)
            return _result(_check("ok", Verdict.PASS))

        original = verify_worker.ctrl.run_verification
        verify_worker.ctrl.run_verification = record_and_pass
        try:
            worker.start()
            worker.submit(_FakeRequest(0))
            self.assertEqual(ran.get(timeout=5.0), 0, "first cycle never ran")

            worker.stop()               # user closes the session

            worker.start()              # user opens a new one
            worker.submit(_FakeRequest(1))
            try:
                seen = ran.get(timeout=5.0)
            except queue.Empty:
                self.fail("worker never ran again after stop()/start(); "
                          "re-verification was silently dead for the new session")
            self.assertEqual(seen, 1)
            self.assertIsNotNone(worker._thread)  # lint: allow protected-access - asserts the worker's threading contract
            self.assertTrue(worker._thread.is_alive())  # lint: allow protected-access - asserts the worker's threading contract
        finally:
            verify_worker.ctrl.run_verification = original
            worker.stop()


class TestSubmitWakesTheWorker(unittest.TestCase):
    """Regression: a submitted request waited out the whole interval.

    Found by the GUI walkthrough, which asks for a re-verification and waits for it to
    reach the UI. It had been passing on luck - only when the submit happened to land
    near the start of a cycle. With a 60s interval, a request handed over just after a
    pass began sat untouched for nearly a minute, so "re-verify this session now" was
    up to a minute late for the user too.
    """

    def test_a_submit_mid_cycle_is_picked_up_promptly(self):
        # An interval far longer than the test's patience: if submit() does not cut
        # the wait short, this cannot pass.
        worker = verify_worker.VerifyWorker(interval=30.0)
        seen: queue.Queue[int] = queue.Queue()

        def record(request):
            seen.put(request.generation)
            return _result(_check("ok", Verdict.PASS))

        original = verify_worker.ctrl.run_verification
        verify_worker.ctrl.run_verification = record
        try:
            worker.start()
            worker.submit(_FakeRequest(0))
            self.assertEqual(seen.get(timeout=5.0), 0, "first pass never ran")

            # The worker is now inside its 30s wait. A fresh submit must interrupt it.
            started = time.perf_counter()
            worker.submit(_FakeRequest(1))
            try:
                self.assertEqual(seen.get(timeout=5.0), 1)
            except queue.Empty:
                self.fail("submit() did not wake the worker; the request would have "
                          "waited out the full interval")
            self.assertLess(time.perf_counter() - started, 5.0)
        finally:
            verify_worker.ctrl.run_verification = original
            worker.stop()


class TestWarningCanBeWithdrawn(unittest.TestCase):
    """Regression: a transient failure raised a warning nothing could ever clear.

    One failed PowerShell query flips a check to UNKNOWN for a single cycle. The next
    cycle succeeds and it is PASS again - but find_regressions only ever reports
    PASS -> not-PASS, so no later update mentions the check, and a red "something
    changed while you were browsing" curtain would stay up over a session where
    nothing had. passing_ids() is what lets the window take the warning back.
    """

    def test_passing_ids_reports_recovery(self):
        recovered = _result(_check("browser.sandbox", Verdict.PASS),
                            _check("net.rule.x", Verdict.FAIL))
        ids = verify_worker.passing_ids(recovered)
        self.assertIn("browser.sandbox", ids)
        self.assertNotIn("net.rule.x", ids)

    def test_passing_ids_excludes_unenforceable_checks(self):
        result = _result(_check("net.loopback", Verdict.PASS, enforceable=False))
        self.assertNotIn("net.loopback", verify_worker.passing_ids(result))

    def test_a_flap_produces_a_regression_then_a_recovery(self):
        """The full transient sequence, as the window would see it."""
        good = _result(_check("browser.sandbox", Verdict.PASS))
        blip = _result(_check("browser.sandbox", Verdict.UNKNOWN))

        regressions = verify_worker.find_regressions(good, blip)
        self.assertEqual([cid for cid, _t in regressions], ["browser.sandbox"])

        # Next cycle recovers. Nothing is reported as a regression...
        self.assertEqual(verify_worker.find_regressions(blip, good), ())
        # ...so the ONLY thing that can clear the warning is the passing set.
        self.assertIn("browser.sandbox", verify_worker.passing_ids(good))


class _FakeRequest:
    """Minimal stand-in for a VerificationRequest - only `generation` is read here."""

    def __init__(self, generation: int) -> None:
        self.generation = generation


if __name__ == "__main__":
    unittest.main(verbosity=2)
