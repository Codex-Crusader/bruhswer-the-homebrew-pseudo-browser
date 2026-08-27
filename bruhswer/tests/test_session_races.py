"""The lifecycle races no other suite covers.

The browser suites drive the happy path end to end. They do NOT cover what happens when
a background verification pass and a session teardown overlap, and that is exactly where
a stale verdict about a destroyed session can reach the lights of a live one.

Four scenarios, all from the release checklist, none of them previously tested:

    regression -> recovery -> re-verification
    close-session racing a verification pass that is already running
    panic during startup, during use, and during teardown
    no stale UI from a previous session appearing in the next one

These run against the mixin and the controller directly, with fake widgets. No browser,
no Tk, milliseconds. That is only possible because BrowserWindow was split: the
verification display used to be welded to a live window, so this logic could not be
reached without launching Edge.
"""

from __future__ import annotations

import queue
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.browser import embed  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.security import verifier  # noqa: E402
from app.sessions import session_manager  # noqa: E402
from app.ui import session_lifecycle, verify_worker  # noqa: E402
from app.ui.session_lifecycle import SessionLifecycleMixin  # noqa: E402
from app.ui.verification_ui import VerificationUIMixin  # noqa: E402
from app.verdict import Check, EvidenceKind, Verdict  # noqa: E402


def _check(check_id: str, verdict: Verdict) -> Check:
    return Check(check_id, check_id, verdict, "detail",
                 evidence_kind=EvidenceKind.LIVE)


def _result(*checks: Check) -> verifier.VerificationResult:
    return verifier.VerificationResult(checks=list(checks))


class _FakeWidget:
    """Enough tkinter surface for the verification and lifecycle mixins, no more."""

    def __init__(self) -> None:
        self.kw: dict = {}
        self.packed = False

    def config(self, **kw) -> None:
        self.kw.update(kw)

    def cget(self, key: str):
        return self.kw.get(key, "")

    def pack(self, **_kw) -> None:
        self.packed = True

    def pack_forget(self) -> None:
        self.packed = False

    @staticmethod
    def winfo_exists() -> bool:
        return True

    @staticmethod
    def update_idletasks() -> None:
        pass


class _FakeHotkey:
    def __init__(self) -> None:
        self.events: queue.Queue = queue.Queue()
        self.available = True
        self.started = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.started = False


class _FakeVerifier:
    def __init__(self) -> None:
        self.pending: list = []
        self.stopped = 0

    def drain(self) -> list:
        out, self.pending = self.pending, []
        return out

    def stop(self) -> None:
        self.stopped += 1

    def start(self) -> None:  # lint: allow could-be-static
        pass


class _FakeController:
    def __init__(self, generation: int = 1) -> None:
        self.generation = generation
        self._pending_downloads: list = []

    def pending_disposable_downloads(self) -> list:
        return self._pending_downloads

    @staticmethod
    def snapshot() -> ctrl.SessionSnapshot:
        return ctrl.NO_SESSION


class _Window(VerificationUIMixin):
    """The verification half, on fake widgets."""

    def __init__(self) -> None:
        self.controller = _FakeController()
        self.result: verifier.VerificationResult | None = None
        self._verifier = _FakeVerifier()
        self._panic_hotkey = _FakeHotkey()
        self._panic_fired = False
        self._warned_ids: set[str] = set()
        self._applied_verification_id = 0
        self._closing = False
        self._drain_job = None
        self.root = _FakeWidget()
        self.stage = _FakeWidget()
        self.lights = {k: _FakeWidget() for k in
                       ("HOST", "NETWORK", "PRIVACY", "DOWNLOADS", "LOCALHOST",
                        "VPN", "PANIC")}
        self.light_labels = {k: _FakeWidget() for k in self.lights}
        self.panic_hint = _FakeWidget()
        self.account_banner = _FakeWidget()
        self.account_banner_text = _FakeWidget()
        self.regression_banner = _FakeWidget()
        self.regression_text = _FakeWidget()
        self.bruh_button = _FakeWidget()
        self.session_badge = _FakeWidget()
        self.status = ""
        self.curtain_shown: list[str] = []
        self.curtain_hidden = 0
        self.panics = 0

    # --- the shell surface the mixin calls ---------------------------------------
    def _after(self, _delay_ms, _callback):  # lint: allow could-be-static
        return "job"

    def _show_curtain(self, message, _colour, _actions=None) -> None:
        self.curtain_shown.append(message)

    def _hide_curtain(self) -> None:
        self.curtain_hidden += 1

    def set_status(self, text: str) -> None:
        self.status = text

    def open_security_panel(self) -> None:  # lint: allow could-be-static
        pass

    def close_session(self) -> None:  # lint: allow could-be-static
        pass

    def _on_panic(self) -> None:
        self.panics += 1


def _update(generation: int, result, *, verification_id: int = 1,
            regressions=(), measurement_failed: bool = False):
    return verify_worker.VerificationUpdate(
        result=result, generation=generation, verification_id=verification_id,
        regressions=tuple(regressions), measurement_failed=measurement_failed)


class TestRegressionRecoveryCycle(unittest.TestCase):
    """regression -> recovery -> re-verification, the full round trip."""

    def setUp(self):
        self.win = _Window()

    def test_a_regression_raises_the_curtain_and_the_banner(self):
        self.win._warn_regressions((("net.rule.x", "Firewall rule x"),))
        self.assertIn("net.rule.x", self.win._warned_ids)
        self.assertTrue(self.win.regression_banner.packed,
                        "the persistent banner did not appear")
        self.assertTrue(self.win.curtain_shown)

    def test_recovery_withdraws_both(self):
        self.win._warn_regressions((("net.rule.x", "Firewall rule x"),))
        self.win._clear_regression_warning(
            _update(1, _result(_check("net.rule.x", Verdict.PASS))))
        self.assertEqual(self.win._warned_ids, set())
        self.assertFalse(self.win.regression_banner.packed,
                         "the banner stayed up after the control recovered")
        self.assertGreater(self.win.curtain_hidden, 0)

    def test_partial_recovery_keeps_the_warning(self):
        """One of two recovering is not recovery."""
        self.win._warn_regressions((("a", "A"), ("b", "B")))
        self.win._clear_regression_warning(
            _update(1, _result(_check("a", Verdict.PASS),
                               _check("b", Verdict.FAIL))))
        self.assertEqual(self.win._warned_ids, {"b"})
        self.assertTrue(self.win.regression_banner.packed,
                        "the banner was withdrawn while a control still did not verify")

    def test_the_banner_survives_dismissing_the_curtain(self):
        """'Keep browsing' is legitimate; erasing every trace of it is not."""
        self.win._warn_regressions((("a", "A"),))
        self.win._hide_curtain()            # what the "Keep browsing" button does
        self.assertTrue(self.win.regression_banner.packed,
                        "dismissing the curtain left no sign the session is degraded")


class TestCloseSessionRacesVerification(unittest.TestCase):
    """A pass that finishes after the session it describes has gone."""

    def setUp(self):
        self.win = _Window()

    def test_a_result_from_the_previous_generation_is_dropped(self):
        self.win.controller.generation = 5
        self.win._verifier.pending = [
            _update(4, _result(_check("host.firewall", Verdict.PASS)))]
        self.win._drain()
        self.assertIsNone(self.win.result,
                          "a verdict about a closed session reached the live lights")

    def test_a_superseded_pass_cannot_move_the_lights_backwards(self):
        fresh = _result(_check("host.firewall", Verdict.PASS))
        stale = _result(_check("host.firewall", Verdict.FAIL))
        self.win._verifier.pending = [_update(1, fresh, verification_id=9)]
        self.win._drain()
        self.assertIs(self.win.result, fresh)

        # A slower pass, submitted earlier, lands afterwards.
        self.win._verifier.pending = [_update(1, stale, verification_id=4)]
        self.win._drain()
        self.assertIs(self.win.result, fresh,
                      "an older measurement overwrote a newer one")

    def test_a_failed_measurement_does_not_refresh_the_verdicts(self):
        good = _result(_check("host.firewall", Verdict.PASS))
        self.win._verifier.pending = [_update(1, good, verification_id=1)]
        self.win._drain()
        self.win._verifier.pending = [
            _update(1, good, verification_id=2, measurement_failed=True)]
        self.win._drain()
        self.assertIn("FAILED to run", self.win.status)

    def test_draining_while_closing_touches_nothing(self):
        self.win._closing = True
        self.win._verifier.pending = [
            _update(1, _result(_check("host.firewall", Verdict.PASS)))]
        self.win._drain()
        self.assertIsNone(self.win.result)


class TestNoStaleUiAcrossSessions(unittest.TestCase):

    def setUp(self):
        self.win = _Window()

    def test_a_session_change_forgets_the_previous_warnings(self):
        self.win._warn_regressions((("net.rule.x", "Firewall rule x"),))
        self.win._reset_verification_state()
        self.assertEqual(self.win._warned_ids, set())
        self.assertFalse(self.win.regression_banner.packed)

    def test_the_new_session_does_not_withdraw_the_old_ones_warning(self):
        """Session A's warned ids leaking into B made B's first clean pass call
        _hide_curtain() and report recovery for a session that no longer existed."""
        self.win._warn_regressions((("net.rule.x", "Firewall rule x"),))
        self.win._reset_verification_state()
        hidden_before = self.win.curtain_hidden

        self.win.controller.generation = 2
        self.win._verifier.pending = [
            _update(2, _result(_check("net.rule.x", Verdict.PASS)),
                    verification_id=1)]
        self.win._drain()
        self.assertEqual(self.win.curtain_hidden, hidden_before,
                         "the new session's curtain was torn down to withdraw a "
                         "warning about the previous session")

    def test_stopping_reverification_is_what_performs_the_reset(self):
        """The wiring, not just the reset. open_session() and close_session() both go
        through _stop_reverification, so if it stops resetting, every test above still
        passes while the real flow leaks state across sessions again."""
        self.win._warn_regressions((("net.rule.x", "Firewall rule x"),))
        self.win._applied_verification_id = 42
        self.win._stop_reverification()
        self.assertEqual(self.win._warned_ids, set())
        self.assertEqual(self.win._applied_verification_id, 0)

    def test_the_applied_id_resets_so_the_new_session_is_not_ignored(self):
        """Without this, session B's ids restart below A's and every pass is dropped."""
        self.win._applied_verification_id = 99
        self.win._reset_verification_state()
        self.win.controller.generation = 2
        fresh = _result(_check("host.firewall", Verdict.PASS))
        self.win._verifier.pending = [_update(2, fresh, verification_id=1)]
        self.win._drain()
        self.assertIs(self.win.result, fresh,
                      "the new session's first result was dropped as stale")


class TestPanicAtEveryPointInTheLifecycle(unittest.TestCase):

    def test_panic_during_a_drain_pre_empts_the_results(self):
        win = _Window()
        win._panic_hotkey.events.put("pressed")  # lint: allow protected-access
        win._verifier.pending = [  # lint: allow protected-access
            _update(1, _result(_check("host.firewall", Verdict.PASS)))]
        win._drain()  # lint: allow protected-access
        self.assertEqual(win.panics, 1)
        self.assertIsNone(win.result,
                          "verification results were applied after the panic key fired")

    def test_panic_before_any_result_still_fires(self):
        """Panic during startup: nothing has been measured yet."""
        win = _Window()
        win._panic_hotkey.events.put("pressed")  # lint: allow protected-access
        win._drain()  # lint: allow protected-access
        self.assertEqual(win.panics, 1)

    def test_stopping_reverification_disarms_the_panic_light(self):
        """The light must not promise an escape hatch that was unregistered."""
        win = _Window()
        win._arm_panic_key()  # lint: allow protected-access
        self.assertEqual(win.lights["PANIC"].cget("fg"), config.OK_GREEN)
        win._panic_hotkey.available = False  # lint: allow protected-access
        win._stop_reverification()  # lint: allow protected-access
        self.assertEqual(win.lights["PANIC"].cget("fg"), config.BAD_RED)
        self.assertIn("UNAVAILABLE", win.panic_hint.cget("text"))


class TestGenerationIsBumpedBeforeTeardown(unittest.TestCase):
    """A pass completing DURING teardown must not carry a matching generation."""

    def test_stop_bumps_before_it_waits_for_the_browser(self):
        controller = ctrl.Controller()
        controller.session = session_manager.Session(
            mode=session_manager.DISPOSABLE, session_id="0123456789abcdef",
            profile_dir=config.PROFILE_DISPOSABLE_ROOT / "0123456789abcdef",
            created=datetime.now(timezone.utc))
        before = controller.generation
        seen: list[int] = []

        original_pids = embed.edge_pids_for_profile
        original_destroy = session_manager.destroy

        def record_pids(_profile):
            seen.append(controller.generation)
            return set()

        embed.edge_pids_for_profile = record_pids
        session_manager.destroy = lambda _s: (True, "destroyed")
        try:
            controller.stop()
        finally:
            embed.edge_pids_for_profile = original_pids
            session_manager.destroy = original_destroy

        self.assertTrue(seen, "teardown never asked which processes were running")
        self.assertEqual(
            seen[0], before + 1,
            "the generation was still the old one while teardown was in progress, so a "
            "pass finishing in that window would have been applied to a dead session")

    def test_stop_with_no_session_still_bumps(self):
        controller = ctrl.Controller()
        before = controller.generation
        controller.stop()
        self.assertEqual(controller.generation, before + 1)

    def test_panic_stop_bumps_before_terminating(self):
        controller = ctrl.Controller()
        controller.session = session_manager.Session(
            mode=session_manager.PERSISTENT, session_id="fedcba9876543210",
            profile_dir=config.PROFILE_PERSISTENT,
            created=datetime.now(timezone.utc))
        before = controller.generation
        seen: list[int] = []

        original = embed.attributed_edge_processes

        def record_processes(_profile):
            seen.append(controller.generation)
            return None

        embed.attributed_edge_processes = record_processes
        try:
            controller.panic_stop()
        finally:
            embed.attributed_edge_processes = original

        self.assertEqual(seen, [before + 1])


class TestTheWorkerBaselineDoesNotCrossSessions(unittest.TestCase):

    def test_stop_drops_the_previous_result(self):
        worker = verify_worker.VerifyWorker(interval=0.01)
        worker._previous = _result(  # lint: allow protected-access
            _check("net.rule.x", Verdict.PASS))
        worker.stop()
        self.assertIsNone(
            worker._previous,  # lint: allow protected-access
            "the next session's first pass would be diffed against this one's last")

    def test_no_regression_is_reported_without_a_baseline(self):
        self.assertEqual(
            verify_worker.find_regressions(
                None, _result(_check("net.rule.x", Verdict.FAIL))),
            ())


class TestSessionSnapshotIsCoherent(unittest.TestCase):

    def test_an_absent_session_reports_inactive(self):
        snapshot = ctrl.Controller().snapshot()
        self.assertFalse(snapshot.active)
        self.assertEqual(snapshot.badge, "NO SESSION")
        self.assertEqual(snapshot.elapsed_text(), "")

    def test_elapsed_time_is_reported_for_a_live_session(self):
        controller = ctrl.Controller()
        controller.session = session_manager.Session(
            mode=session_manager.DISPOSABLE, session_id="0123456789abcdef",
            profile_dir=config.PROFILE_DISPOSABLE_ROOT / "0123456789abcdef",
            created=datetime.now(timezone.utc) - timedelta(seconds=125))
        snapshot = controller.snapshot()
        self.assertTrue(snapshot.active)
        self.assertTrue(snapshot.is_disposable)
        self.assertEqual(snapshot.badge, "DISPOSABLE BRUH")
        self.assertEqual(snapshot.elapsed_text(), "2:05")

    def test_a_long_session_reports_hours(self):
        controller = ctrl.Controller()
        controller.session = session_manager.Session(
            mode=session_manager.PERSISTENT, session_id="0123456789abcdef",
            profile_dir=config.PROFILE_PERSISTENT,
            created=datetime.now(timezone.utc) - timedelta(hours=2, minutes=3, seconds=4))
        self.assertEqual(controller.snapshot().elapsed_text(), "2:03:04")


class _FakeLifecycleController:
    """Records when stop() was called relative to the curtain, and nothing else."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.running = True

    @staticmethod
    def pending_disposable_downloads() -> list:
        return []

    def is_running(self) -> bool:
        return self.running

    def stop(self):
        self.calls.append("stop")
        self.running = False
        return True, "stopped"

    def start(self, _mode, url=None):
        self.calls.append("start")
        return ctrl.LaunchOutcome(True, "started", _result())


class _LifecycleWindow(SessionLifecycleMixin):
    """The lifecycle half, on fakes. Enough surface for open_session, close_session
    and on_close - not the full BrowserWindow contract."""

    def __init__(self) -> None:
        self.controller = _FakeLifecycleController()
        self.root = _FakeWidget()
        self.result = None
        self.hosted_hwnd = None
        self._host_attempts = 0
        self._closing = False
        self._panic_fired = False
        self.status = ""
        self.calls: list[str] = []

    # --- the shell surface the mixin calls, both from WindowShell and from the
    # other mixin (VerificationUIMixin), which is not mixed in here -----------------
    def _after(self, _delay_ms, _callback):  # lint: allow could-be-static
        return "job"

    def _show_curtain(self, message, _colour, _actions=None) -> None:
        self.calls.append(f"curtain:{message.splitlines()[0]}")
        self.controller.calls.append(f"curtain:{message.splitlines()[0]}")

    def _hide_curtain(self) -> None:  # lint: allow could-be-static
        pass

    def set_status(self, text: str) -> None:
        self.status = text

    def _cancel_all_jobs(self) -> None:  # lint: allow could-be-static
        pass

    def refresh_lights(self) -> None:  # lint: allow could-be-static
        pass

    def update_session_badge(self) -> None:  # lint: allow could-be-static
        pass

    def _arm_panic_key(self) -> None:  # lint: allow could-be-static
        pass

    def _refresh_panic_indicator(self) -> None:  # lint: allow could-be-static
        pass

    def _start_reverification(self) -> None:  # lint: allow could-be-static
        pass

    def _stop_reverification(self) -> None:  # lint: allow could-be-static
        pass


@mock.patch.object(session_lifecycle, "embed", autospec=True)
@mock.patch.object(session_lifecycle, "dialogs", autospec=True)
class TestCurtainPaintsBeforeTheBlockingCall(unittest.TestCase):
    """F-2: open_session, close_session and on_close each block on
    controller.stop() (up to ~22s worst case: an 8s process wait, a 12s
    profile-process poll, a 2s settle) or controller.start() (its own ~5.5s
    verification pass). The curtain explaining that must be PAINTED - not just
    scheduled - before the block starts, or the window looks frozen and blank for
    the entire wait with nothing on screen saying why.

    root.update_idletasks() is what forces the paint; there is no fake for that
    effect, so what these pin is the cheaper, necessary half: _show_curtain runs
    before controller.stop(), not after.
    """

    def _assert_curtain_before_stop(self, order: list[str]) -> None:
        self.assertIn("stop", order, f"controller.stop() was never called: {order}")
        curtains = [i for i, c in enumerate(order) if c.startswith("curtain")]
        self.assertTrue(curtains, f"no curtain was shown at all before closing: {order}")
        self.assertLess(curtains[0], order.index("stop"),
                        f"curtain did not paint before stop(): {order}")

    def test_open_session_shows_the_curtain_before_stopping_the_old_session(
            self, mock_dialogs, _mock_embed):
        mock_dialogs.confirm_disposable_downloads.return_value = True
        win = _LifecycleWindow()
        win.open_session(session_manager.PERSISTENT)
        self._assert_curtain_before_stop(win.controller.calls)

    def test_close_session_shows_the_curtain_before_stopping(
            self, mock_dialogs, _mock_embed):
        mock_dialogs.confirm_disposable_downloads.return_value = True
        win = _LifecycleWindow()
        win.close_session()
        self._assert_curtain_before_stop(win.controller.calls)

    def test_on_close_shows_the_curtain_before_stopping_a_running_session(
            self, mock_dialogs, _mock_embed):
        mock_dialogs.confirm_disposable_downloads.return_value = True
        win = _LifecycleWindow()
        win.controller.running = True
        win.root.destroy = lambda: None
        win.on_close()
        self._assert_curtain_before_stop(win.controller.calls)

    def test_on_close_with_no_running_session_does_not_need_a_curtain(
            self, mock_dialogs, _mock_embed):
        """Nothing to stop, so no curtain is required - this must not regress into
        expecting one where there is nothing to wait for."""
        mock_dialogs.confirm_disposable_downloads.return_value = True
        win = _LifecycleWindow()
        win.controller.running = False
        win.root.destroy = lambda: None
        win.on_close()
        self.assertNotIn("stop", win.controller.calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
