"""Tests for the panic key and the account-settings path.

The panic key TERMINATES processes, which raises the bar on attribution from "good
enough to count" to "good enough to kill". The tests that matter are the ones proving
bruhswer refuses to kill anything whose identity it cannot still confirm - because the
failure mode is terminating the user's own browser, and the constraint that it must
never do that outranks panic completeness.

The refusal test uses a REAL process with a REAL creation time rather than a mock, so
it measures the actual Win32 behaviour instead of restating the implementation.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import config  # noqa: E402
from app.browser import edge, embed  # noqa: E402
from app.ui import panic_key  # noqa: E402


def _spawn_victim() -> subprocess.Popen:
    """A harmless child process that sits still until terminated."""
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        shell=False, creationflags=config.NO_WINDOW)


def _creation_of(pid: int) -> int | None:
    handle = embed.KERNEL32.OpenProcess(
        embed.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        # protected-access: measures the real Win32 identity helpers
        return embed._creation_filetime(handle)  # lint: allow protected-access
    finally:
        embed.KERNEL32.CloseHandle(ctypes.wintypes.HANDLE(handle))


class TestTerminationAttribution(unittest.TestCase):
    """The PID-reuse guard, measured rather than asserted."""

    def test_a_wrong_creation_time_is_refused_and_the_process_survives(self):
        """This is the whole safety property.

        A PID can be recycled between enumeration and termination. Checking only the
        image name would not catch a PID that became ANOTHER msedge.exe - which is the
        user's own browser, the one thing bruhswer must never kill. Comparing the
        creation time read back from the opened handle identifies the process INSTANCE,
        so a mismatch must be refused.
        """
        victim = _spawn_victim()
        try:
            real = _creation_of(victim.pid)
            self.assertIsNotNone(real, "could not read the victim's creation time")

            # Same PID, wrong instance identity - exactly what PID reuse looks like.
            #
            # One SECOND off, not one tick. The comparison is deliberately made at
            # microsecond resolution (the two Windows sources have different
            # precision), so a 100ns offset is the SAME instance and must not be
            # refused. A recycled PID is a different process created at a different
            # time, which is orders of magnitude further away than this.
            stale = embed.EdgeProcess(victim.pid, real + 10_000_000)
            report = embed.terminate_attributed([stale])

            self.assertEqual(report.refused, 1, "bruhswer did not refuse a stale PID")
            self.assertEqual(report.terminated, 0)
            time.sleep(0.3)
            self.assertIsNone(victim.poll(),
                              "bruhswer TERMINATED a process whose identity had "
                              "changed - this would kill the user's own browser")
        finally:
            victim.kill()
            victim.wait(timeout=10)

    def test_a_matching_creation_time_is_terminated_and_confirmed(self):
        """The guard must not be so strict that panic never works."""
        victim = _spawn_victim()
        try:
            real = _creation_of(victim.pid)
            self.assertIsNotNone(real)
            report = embed.terminate_attributed([embed.EdgeProcess(victim.pid, real)])

            self.assertEqual(report.terminated, 1)
            self.assertEqual(report.refused, 0)
            # TerminateProcess is asynchronous, so the report distinguishes "asked" from
            # "observed to have exited". This one should be confirmed.
            self.assertEqual(report.confirmed_exited, 1)
            self.assertIsNotNone(victim.poll(), "the process is still running")
        finally:
            if victim.poll() is None:
                victim.kill()
            victim.wait(timeout=10)

    def test_an_already_dead_pid_is_counted_not_crashed_on(self):
        victim = _spawn_victim()
        real = _creation_of(victim.pid)
        victim.kill()
        victim.wait(timeout=10)
        time.sleep(0.2)
        report = embed.terminate_attributed([embed.EdgeProcess(victim.pid, real or 1)])
        self.assertEqual(report.terminated, 0)
        self.assertEqual(report.attempted, 1)

    def test_empty_input_does_nothing(self):
        report = embed.terminate_attributed([])
        self.assertEqual(report.attempted, 0)


class TestCreationTimePrecision(unittest.TestCase):
    """The bug that made the panic key completely inert.

    Found by the real GUI walkthrough: "0 terminated; 9 left alone (identity no longer
    matched)" with nine live Edge processes still running. Every process was refused.

    Cause: the two creation-time sources have DIFFERENT PRECISION.
        GetProcessTimes    full 100ns resolution
        CIM CreationDate   truncated to microseconds (always a multiple of 10 ticks)
    so `==` essentially never holds.

    The original unit test missed it because it read BOTH sides with GetProcessTimes -
    self-consistent, and therefore proof of nothing about the path that actually runs.
    These tests compare the two REAL sources.
    """

    @staticmethod
    def _cim_creation(pid: int) -> int | None:
        script = ('@(Get-CimInstance Win32_Process -Filter "ProcessId=' + str(pid) +
                  '" | ForEach-Object { [string]$_.CreationDate.ToFileTimeUtc() }) '
                  '-join ","')
        proc = subprocess.run(
            [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, shell=False, creationflags=config.NO_WINDOW)
        raw = (proc.stdout or "").strip().split(",")[0]
        return int(raw) if raw.isdigit() else None

    def test_the_two_sources_disagree_at_100ns_resolution(self):
        """Pins the measurement, so nobody 'simplifies' the comparison back to ==."""
        victim = _spawn_victim()
        try:
            time.sleep(0.8)
            from_handle = _creation_of(victim.pid)
            enumerated = self._cim_creation(victim.pid)
            if enumerated is None or from_handle is None:
                self.skipTest("could not read both creation-time sources")

            self.assertEqual(enumerated % 10, 0,
                             "CIM value is expected to be microsecond-truncated")
            self.assertTrue(
                embed.same_process_instance(enumerated, from_handle),
                f"the two sources do not match even at microsecond resolution: "
                f"cim={enumerated} handle={from_handle}")
        finally:
            victim.kill()
            victim.wait(timeout=10)

    def test_a_real_enumerated_process_is_actually_terminated(self):
        """End to end through the REAL enumeration path, not a hand-built value.

        This is the test that would have caught the inert panic key.
        """
        victim = _spawn_victim()
        try:
            time.sleep(0.8)
            enumerated = self._cim_creation(victim.pid)
            if enumerated is None:
                self.skipTest("could not read the CIM creation time")

            report = embed.terminate_attributed(
                [embed.EdgeProcess(victim.pid, enumerated)])
            self.assertEqual(report.refused, 0,
                             "a genuinely matching process was refused - the panic "
                             "key would stop nothing")
            self.assertEqual(report.terminated, 1)
            self.assertIsNotNone(victim.poll())
        finally:
            if victim.poll() is None:
                victim.kill()
            victim.wait(timeout=10)

    def test_a_different_microsecond_is_still_refused(self):
        """The looser comparison must not have destroyed the guard."""
        self.assertFalse(embed.same_process_instance(134311582068932890,
                                                     134311582068942898))
        self.assertTrue(embed.same_process_instance(134311582068932890,
                                                    134311582068932898))


class TestAttributedEnumeration(unittest.TestCase):

    def test_a_profile_with_no_browser_returns_empty_not_none(self):
        """[] means 'asked, found none'. None means 'could not ask'. Never confused."""
        result = embed.attributed_edge_processes(Path(r"C:\no-such-bruhswer-profile"))
        self.assertIsNotNone(result, "a successful query must not report failure")
        self.assertEqual(result, [])

    def test_matching_is_case_insensitive_and_quote_insensitive(self):
        """subprocess quotes an argument only when it contains a space, so the same
        profile appears quoted on one machine and bare on another."""
        # protected-access: measures the real Win32 identity helpers.
        bare = embed._normalise_cmdline(  # lint: allow protected-access
            r'--user-data-dir=C:\Users\someone\Profile')
        quoted = embed._normalise_cmdline(  # lint: allow protected-access
            r'--user-data-dir="C:\Users\someone\Profile"')
        self.assertEqual(bare, quoted)


class TestPanicHotkeyRegistration(unittest.TestCase):

    def test_it_registers_and_releases(self):
        hotkey = panic_key.PanicHotkey()
        try:
            self.assertTrue(hotkey.start(), hotkey.status_text)
            self.assertTrue(hotkey.available)
            self.assertIn(config.PANIC_HOTKEY_LABEL, hotkey.status_text)
        finally:
            hotkey.stop()
        self.assertFalse(hotkey.available, "the hotkey was not released on stop()")

    def test_a_conflicting_registration_reports_unavailable_never_armed(self):
        """Two bruhswer instances, or any other app owning the combination.

        The second instance must SAY it has no panic key. Silently degrading to
        something weaker under the same name would leave the user believing in an
        escape hatch they do not have.
        """
        first = panic_key.PanicHotkey()
        second = panic_key.PanicHotkey()
        try:
            self.assertTrue(first.start(), first.status_text)
            self.assertFalse(second.start(),
                             "two registrations of the same hotkey both succeeded")
            self.assertFalse(second.available)
            self.assertIn("UNAVAILABLE", second.status_text)
        finally:
            second.stop()
            first.stop()

    def test_the_hotkey_is_released_for_the_next_instance(self):
        first = panic_key.PanicHotkey()
        first.start()
        first.stop()
        second = panic_key.PanicHotkey()
        try:
            self.assertTrue(second.start(),
                            "the combination stayed locked after stop()")
        finally:
            second.stop()


class TestAccountSettingsTarget(unittest.TestCase):
    """B8: the settings page is reachable ONLY through bruhswer's own constant."""

    def test_the_settings_page_is_accepted_by_exact_equality(self):
        argv = edge.build_command(Path("msedge.exe"), Path("p"), (),
                                  edge.PROFILES_SETTINGS)
        self.assertEqual(argv[-1], edge.PROFILES_SETTINGS)

    def test_a_prefix_of_the_settings_page_is_refused(self):
        """startswith() would admit these. Exact membership does not."""
        for hostile in ("edge://settings/profiles/../../evil",
                        "edge://settings/profilesEVIL",
                        "edge://settings/profiles?x=1",
                        "edge://settings"):
            with self.subTest(url=hostile):
                with self.assertRaises(ValueError):
                    edge.build_command(Path("msedge.exe"), Path("p"), (), hostile)

    def test_other_internal_schemes_are_still_refused(self):
        for hostile in ("chrome://settings", "edge://flags", "about:config",
                        "view-source:https://x.com", "file:///C:/"):
            with self.subTest(url=hostile):
                with self.assertRaises(ValueError):
                    edge.build_command(Path("msedge.exe"), Path("p"), (), hostile)

    def test_the_address_bar_still_refuses_edge_urls(self):
        """urls.py must NOT have been loosened to make B8 work."""
        from app.browser import urls
        for hostile in ("edge://settings/profiles", "edge://flags"):
            with self.subTest(url=hostile):
                with self.assertRaises(urls.RefusedURL):
                    urls.normalise(hostile)

    def test_the_allowlist_holds_exactly_two_entries(self):
        """A growing allowlist is how this becomes a general internal-URL channel."""
        # protected-access: measures the real Win32 identity helpers
        self.assertEqual(len(edge._ALLOWED_NON_HTTP), 2)  # lint: allow protected-access
        # protected-access: measures the real Win32 identity helpers
        self.assertIn(edge.BLANK, edge._ALLOWED_NON_HTTP)  # lint: allow protected-access
        self.assertIn(edge.PROFILES_SETTINGS,
                      edge._ALLOWED_NON_HTTP)  # lint: allow protected-access


if __name__ == "__main__":
    unittest.main(verbosity=2)
