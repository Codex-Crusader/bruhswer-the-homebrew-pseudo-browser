"""Runtime re-verification: mainly what counts as a control that stopped holding.
Too quiet leaves a stale green light; too loud trains the user to dismiss warnings."""

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

from app.security.verifier import VerificationResult, guard_failure_id  # noqa: E402
from app.ui import verification_ui, verify_worker  # noqa: E402
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
        """PASS -> UNKNOWN is a regression like PASS -> FAIL."""
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
        """net.loopback is a permanent FAIL; comparing it would warn every cycle."""
        before = _result(_check("net.loopback", Verdict.PASS, enforceable=False))
        after = _result(_check("net.loopback", Verdict.FAIL, enforceable=False))
        self.assertEqual(verify_worker.find_regressions(before, after), ())

    def test_a_check_that_disappears_is_not_reported(self):
        """downloads.* exists only during a session; vanishing is not failing."""
        before = _result(_check("downloads.quarantine", Verdict.PASS))
        after = _result(_check("net.rule.x", Verdict.PASS))
        self.assertEqual(verify_worker.find_regressions(before, after), ())

    def test_a_check_that_vanishes_because_its_guard_crashed_is_reported(self):
        """A crash replaces the guard's checks with a new id, so nothing warned."""
        before = _result(_check("browser.sandbox", Verdict.PASS),
                         _check("browser.cmdline", Verdict.PASS))
        after = _result(_check("browser.cmdline", Verdict.PASS),
                        _check(guard_failure_id("browser", "sandbox"), Verdict.UNKNOWN))
        self.assertEqual(verify_worker.find_regressions(before, after),
                         (("browser.sandbox", "title for browser.sandbox"),))

    def test_a_crash_in_another_category_does_not_report_a_vanished_check(self):
        """downloads.quarantine vanishing when a session closes is still not news."""
        before = _result(_check("downloads.quarantine", Verdict.PASS))
        after = _result(_check(guard_failure_id("dns", "dns"), Verdict.UNKNOWN))
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
        self.assertEqual(worker._requests.qsize(), 1)  # lint: allow protected-access
        self.assertEqual(
            worker._requests.get_nowait().generation, 4)  # lint: allow protected-access

    def test_stop_returns_promptly_even_while_a_pass_is_running(self):
        """stop() returns promptly while the worker is inside a slow call."""
        worker = verify_worker.VerifyWorker(interval=0.01)
        entered = threading.Event()

        def slow_verification(_request):
            entered.set()
            time.sleep(3.0)
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
        """A dead thread would leave the last result looking current."""
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
    """Regression: after stop(), a second start() exited at once on the still-set
    event, freezing the lights. The ordinary close-then-new-session path."""

    def test_worker_restarts_after_stop(self):
        worker = verify_worker.VerifyWorker(interval=0.01)
        ran: queue.Queue[int] = queue.Queue()

        def record_and_pass(request):
            ran.put(request.generation)
            return _result(_check("ok", Verdict.PASS))

        original = verify_worker.ctrl.run_verification
        verify_worker.ctrl.run_verification = record_and_pass
        try:
            worker.start()
            worker.submit(_FakeRequest(0))
            self.assertEqual(ran.get(timeout=5.0), 0, "first cycle never ran")

            worker.stop()

            worker.start()
            worker.submit(_FakeRequest(1))
            try:
                seen = ran.get(timeout=5.0)
            except queue.Empty:
                self.fail("worker never ran again after stop()/start(); "
                          "re-verification was silently dead for the new session")
            self.assertEqual(seen, 1)
            self.assertIsNotNone(worker._thread)  # lint: allow protected-access
            self.assertTrue(worker._thread.is_alive())  # lint: allow protected-access
        finally:
            verify_worker.ctrl.run_verification = original
            worker.stop()


class TestSubmitWakesTheWorker(unittest.TestCase):
    """Regression: a mid-cycle submit waited out the whole 60s interval."""

    def test_a_submit_mid_cycle_is_picked_up_promptly(self):
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
    """Regression: a one-cycle UNKNOWN raised a warning nothing could clear;
    passing_ids() lets the window withdraw it."""

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

        self.assertEqual(verify_worker.find_regressions(blip, good), ())
        self.assertIn("browser.sandbox", verify_worker.passing_ids(good))


class _FakeRequest:
    """Minimal stand-in for a VerificationRequest."""

    def __init__(self, generation: int, verification_id: int = 0) -> None:
        self.generation = generation
        self.verification_id = verification_id


class _StubController:
    """Enough of Controller for _verify_async: one method, and a record of calls."""

    def __init__(self) -> None:
        self.requested_modes: list[str] = []

    def verification_request(self, mode: str) -> str:
        self.requested_modes.append(mode)
        return f"request-for-{mode}"


class _FakeRoot:
    @staticmethod
    def winfo_exists() -> bool:
        return True


class _AsyncVerifyWindow(verification_ui.VerificationUIMixin):
    """Just enough for _verify_async. _tick() stands in for one Tk `after` cycle."""

    def __init__(self) -> None:
        self.controller = _StubController()
        self.root = _FakeRoot()
        self._closing = False
        self._verify_in_flight = False
        self.status = ""
        self._pending: list = []

    def _after(self, _delay_ms, callback):
        self._pending.append(callback)
        return len(self._pending)

    def set_status(self, text: str) -> None:
        self.status = text

    def _tick(self) -> None:
        due, self._pending = self._pending, []
        for callback in due:
            callback()


class TestVerifyAsyncRunsOffTheCallingThread(unittest.TestCase):
    """_verify_async, behind startup() and BRUH CHECK, which once froze the window
    for the whole pass. Real threads, mocked run_verification."""

    def test_request_is_built_synchronously_before_any_thread_could_run(self):
        """verification_request() runs on the calling thread, before any worker."""
        win = _AsyncVerifyWindow()
        win._verify_async(  # lint: allow protected-access
            "persistent", lambda _result: None)
        self.assertEqual(win.controller.requested_modes, ["persistent"])

    def test_result_reaches_on_done_via_a_tick_not_the_background_thread(self):
        calling_thread = threading.current_thread()
        seen_from: list[threading.Thread] = []

        def fake_run_verification(request):
            self.assertEqual(request, "request-for-persistent")
            return _result(_check("ok", Verdict.PASS))

        def on_done(result):
            seen_from.append(threading.current_thread())
            seen_from.append(result)

        original = verification_ui.ctrl.run_verification
        verification_ui.ctrl.run_verification = fake_run_verification
        try:
            win = _AsyncVerifyWindow()
            win._verify_async("persistent", on_done)  # lint: allow protected-access
            deadline = time.monotonic() + 5.0
            while not seen_from and time.monotonic() < deadline:
                win._tick()  # lint: allow protected-access
                time.sleep(0.01)
        finally:
            verification_ui.ctrl.run_verification = original

        self.assertTrue(seen_from, "on_done was never called")
        # on_done runs on the _tick() thread, never the worker.
        self.assertIs(seen_from[0], calling_thread)
        self.assertIs(seen_from[1].checks[0].verdict, Verdict.PASS)

    def test_a_crashing_pass_reports_a_status_instead_of_hanging(self):
        def fake_run_verification(_request):
            raise RuntimeError("boom")

        original = verification_ui.ctrl.run_verification
        verification_ui.ctrl.run_verification = fake_run_verification
        try:
            win = _AsyncVerifyWindow()
            received: list = []
            win._verify_async(  # lint: allow protected-access
                "persistent", received.append)
            deadline = time.monotonic() + 5.0
            while not win.status and time.monotonic() < deadline:
                win._tick()  # lint: allow protected-access
                time.sleep(0.01)
        finally:
            verification_ui.ctrl.run_verification = original

        self.assertEqual(received, [], "on_done ran on a failed pass")
        self.assertTrue(win.status, "no status was ever set for the failed pass")

    def test_a_second_call_while_one_is_running_is_refused_not_raced(self):
        """The old frozen window serialised double-clicks by accident; async needs an
        explicit guard, or two startup() calls race."""
        gate = threading.Event()
        calls = 0

        def fake_run_verification(_request):
            nonlocal calls
            calls += 1
            if calls == 1:
                gate.wait(timeout=5.0)
            return _result(_check("ok", Verdict.PASS))

        original = verification_ui.ctrl.run_verification
        verification_ui.ctrl.run_verification = fake_run_verification
        try:
            win = _AsyncVerifyWindow()
            win._verify_async(  # lint: allow protected-access
                "persistent", lambda _result: None)
            self.assertEqual(win.controller.requested_modes, ["persistent"])

            # The double-click.
            win._verify_async(  # lint: allow protected-access
                "persistent", lambda _result: None)
            self.assertEqual(win.controller.requested_modes, ["persistent"],
                            "the second call was not refused: it built its own request")
            self.assertTrue(win.status, "the refusal must say something, not be silent")

            def in_flight() -> bool:
                return win._verify_in_flight  # lint: allow protected-access

            gate.set()
            deadline = time.monotonic() + 5.0
            while in_flight() and time.monotonic() < deadline:
                win._tick()  # lint: allow protected-access
                time.sleep(0.01)
            self.assertFalse(in_flight(), "flag was never cleared")

            # A call after the first finishes goes through.
            received: list = []
            win._verify_async(  # lint: allow protected-access
                "persistent", received.append)
            deadline = time.monotonic() + 5.0
            while not received and time.monotonic() < deadline:
                win._tick()  # lint: allow protected-access
                time.sleep(0.01)
            self.assertEqual(len(received), 1,
                            "the flag stayed stuck after the first pass")
        finally:
            verification_ui.ctrl.run_verification = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
