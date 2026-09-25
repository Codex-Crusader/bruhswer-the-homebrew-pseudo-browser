"""Regression tests named after the overclaims they exist to prevent.

A security indicator that was never measured is a VULNERABILITY, not a documentation
bug. Every defect below was live in shipped code, produced a green or confident
indicator, and passed the static suite - which checks STRUCTURE (no shell=True, no
listener, no dynamic execution) and none of these were structural. Each collapsed
"could not measure" into "measured, and it was fine".

Every test here is written to FAIL against the pre-fix code. A regression test that
would have passed before the fix documents nothing.

  1. RendererSandbox   an unreadable renderer token was dropped from the denominator,
                       so 3 renderers with 1 unreadable token reported
                       "All 2 renderer process(es) run at UNTRUSTED integrity" - PASS.
  2. AccountSignin     an unreadable Preferences file returned the same (False, ...)
                       shape as a clean read finding no account, and rendered as
                       PASS "No Microsoft account is signed into this profile."
  3. IPv6Summary       policy_summary() printed "IPv6 local ranges - BLOCKED" with the
                       same confidence as the IPv4 rows, which rest on an empirical
                       gate A16 measurement. No equivalent IPv6 measurement exists.
  4. DownloadDirectory an unreadable Preferences file fell through to the same branch
                       as a clean read that found the wrong directory, so a locked or
                       mid-rewrite file produced a CRITICAL FAIL asserting "Downloads
                       would NOT be quarantined" on a file it had just failed to parse.
  5. WrongShapedPrefs  a Preferences file that PARSES but is not an object reached the
                       same readers as an AttributeError, not as the sentinel they
                       render as UNKNOWN. Two of them run inside Controller.start(),
                       which has no handler.
  6. CrashedGuard      a guard that raised became one NON-critical UNKNOWN, and the
                       critical checks it would have produced were absent, so a crash
                       in the edge, browser or network guard left may_launch True. Its
                       check was also named outside every status row's category.
  7. SharingGroups     sharing groups were matched by English display name, so on a
                       non-English Windows every group read "0 of 0 enabled" - PASS.

TestGuardsRunConcurrently is not an overclaim. It lives here because this suite runs
in CI and already holds the guard table the test needs.
"""

from __future__ import annotations

import contextlib
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import config, sysquery  # noqa: E402
from app.browser import tokens  # noqa: E402
from app.network import network_guard  # noqa: E402
from app.privacy import privacy_guard  # noqa: E402
from app.security import browser_guard, verifier  # noqa: E402
from app.verdict import Verdict  # noqa: E402


def _facts(pid: int, *, readable: bool, integrity: str | None = "UNTRUSTED"):
    return tokens.TokenFacts(pid, readable, integrity, 0, readable=readable)


def _probe(value, status=sysquery.ProbeStatus.OK):
    """A successful sysquery.Probe carrying `value`, for mocking a query."""
    return sysquery.Probe(value, status, 0.0)


class TestUnreadableRendererIsNeverGreen(unittest.TestCase):
    """Defect 1. A process nobody could measure is not a process that passed."""

    def test_unreadable_token_forces_unknown_not_pass(self):
        def fake_read(pid):
            return _facts(pid, readable=(pid != 3))

        with mock.patch.object(tokens, "read", fake_read):
            checks = browser_guard.verify_renderer_sandbox([1, 2, 3])

        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertIs(
            check.verdict, Verdict.UNKNOWN,
            f"3 renderers with 1 unreadable token reported {check.verdict}: "
            f"{check.detail}")
        # The count the user sees must be the TOTAL, not the readable subset. The
        # original wording said "All 2 renderer process(es)" while three were running.
        self.assertIn("3", check.detail)
        self.assertIn("unreadable=1", check.evidence)

    def test_all_readable_and_untrusted_still_passes(self):
        """The fix must not make the check permanently unknowable."""
        with mock.patch.object(tokens, "read",
                               lambda pid: _facts(pid, readable=True)):
            checks = browser_guard.verify_renderer_sandbox([1, 2, 3])
        self.assertIs(checks[0].verdict, Verdict.PASS)
        self.assertIn("All 3", checks[0].detail)

    def test_readable_but_not_untrusted_still_fails(self):
        with mock.patch.object(
                tokens, "read",
                lambda pid: _facts(pid, readable=True, integrity="MEDIUM")):
            checks = browser_guard.verify_renderer_sandbox([1, 2])
        self.assertIs(checks[0].verdict, Verdict.FAIL)

    def test_summarise_reports_the_unreadable_count(self):
        with mock.patch.object(tokens, "read",
                               lambda pid: _facts(pid, readable=(pid == 1))):
            summary = tokens.summarise_renderers([1, 2, 3])
        self.assertEqual(summary["measured"], 1)
        self.assertEqual(summary["unreadable"], 2)


class TestFailedRendererQueryIsNotSilence(unittest.TestCase):
    """Defect 1b. A failed QUERY said the same thing as 'no browser is running'.

    renderer_pids_for_profile returned a bare [] on timeout, on OSError, and on a
    clean run that found nothing. During a live session one PowerShell hiccup
    therefore produced a check reading "No browser session is running, so there is
    nothing to measure yet" - a statement that is plainly false with the browser
    visible on screen, and, once re-verification existed, the trigger for a red
    warning curtain over a session where nothing had actually changed.
    """

    def test_query_failure_says_it_could_not_measure(self):
        checks = browser_guard.verify_renderer_sandbox(None)
        self.assertIs(checks[0].verdict, Verdict.UNKNOWN)
        self.assertIn("could not ask", checks[0].detail)
        self.assertNotIn("No browser session is running", checks[0].detail)

    def test_genuinely_no_renderers_still_says_so(self):
        checks = browser_guard.verify_renderer_sandbox([])
        self.assertIs(checks[0].verdict, Verdict.UNKNOWN)
        # Must not claim "no browser session is running" - an empty list is also what
        # a LIVE session with no renderer processes right now looks like (startup, or
        # every tab discarded), and that claim would be false while the browser is on
        # screen. Must not claim a session exists either - [] is also the pre-launch
        # default, when there genuinely is none.
        self.assertNotIn("No browser session is running", checks[0].detail)
        self.assertNotIn("session", checks[0].detail)

    def test_the_two_states_do_not_share_a_message(self):
        failed = browser_guard.verify_renderer_sandbox(None)[0]
        empty = browser_guard.verify_renderer_sandbox([])[0]
        self.assertNotEqual(failed.detail, empty.detail)
        self.assertNotEqual(failed.evidence, empty.evidence)


class TestUnreadablePreferencesIsNeverGreen(unittest.TestCase):
    """Defect 2. 'Could not read the file' is not 'no account is signed in'."""

    def test_unreadable_preferences_returns_the_sentinel(self):
        with mock.patch.object(Path, "is_file", lambda self: True), \
             mock.patch.object(Path, "read_text",
                               lambda self, **kw: "{ this is not json"):
            signed_in, detail = privacy_guard.verify_account_signin(Path("profile"))
        self.assertFalse(signed_in)
        self.assertEqual(detail, privacy_guard.PREFS_UNREADABLE)

    def test_unreadable_preferences_renders_as_unknown_not_pass(self):
        with mock.patch.object(privacy_guard, "verify_account_signin",
                               lambda p: (False, privacy_guard.PREFS_UNREADABLE)), \
             mock.patch.object(privacy_guard, "verify_applied",
                               lambda p, m: (2, 2, [])):
            # protected-access: pins an internal branch that produced a false PASS.
            checks = verifier._privacy_checks(  # lint: allow protected-access
                Path("profile"), "standard")

        account = [c for c in checks if c.check_id == "privacy.account"]
        self.assertEqual(len(account), 1, "privacy.account check went missing")
        self.assertIs(
            account[0].verdict, Verdict.UNKNOWN,
            f"unreadable Preferences reported {account[0].verdict}: "
            f"{account[0].detail}")
        # And it must not assert the thing it could not check.
        self.assertNotIn("No Microsoft account is signed into this profile",
                         account[0].detail)

    def test_a_clean_read_with_no_account_still_passes(self):
        """The fix must not turn a genuine clean result into a permanent UNKNOWN."""
        with mock.patch.object(
                privacy_guard, "verify_account_signin",
                lambda p: (False, "No Microsoft account is signed into this profile.")), \
             mock.patch.object(privacy_guard, "verify_applied",
                               lambda p, m: (2, 2, [])):
            # protected-access: pins an internal branch that produced a false PASS.
            checks = verifier._privacy_checks(  # lint: allow protected-access
                Path("profile"), "standard")
        account = next(c for c in checks if c.check_id == "privacy.account")
        self.assertIs(account.verdict, Verdict.PASS)


class TestUnreadableDownloadPrefsIsNeverAFail(unittest.TestCase):
    """Defect 4. 'Could not read the file' is not 'downloads are not quarantined'."""

    def test_unreadable_preferences_returns_the_sentinel(self):
        with mock.patch.object(Path, "is_file", lambda self: True), \
             mock.patch.object(Path, "read_text",
                               lambda self, **kw: "{ this is not json"):
            ok, detail = privacy_guard.verify_download_directory(
                Path("profile"), Path("quarantine"))
        self.assertFalse(ok)
        self.assertEqual(detail, privacy_guard.PREFS_UNREADABLE)

    def test_unreadable_preferences_renders_as_unknown_not_fail(self):
        with mock.patch.object(
                privacy_guard, "verify_download_directory",
                lambda p, d: (False, privacy_guard.PREFS_UNREADABLE)):
            checks = verifier._download_checks(  # lint: allow protected-access
                Path("profile"), Path("quarantine"))

        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertIs(
            check.verdict, Verdict.UNKNOWN,
            f"unreadable Preferences reported {check.verdict}: {check.detail}")
        # Critical + UNKNOWN still blocks launch - fail-closed is preserved.
        self.assertTrue(check.critical)
        # And it must not assert the thing it could not check.
        self.assertNotIn("Downloads would NOT be quarantined", check.detail)

    def test_a_clean_read_that_actually_fails_is_still_a_fail(self):
        """The fix must not turn a genuine misconfiguration into a permanent UNKNOWN."""
        with mock.patch.object(
                privacy_guard, "verify_download_directory",
                lambda p, d: (False, "download directory is 'C:/wrong', expected ...")):
            checks = verifier._download_checks(  # lint: allow protected-access
                Path("profile"), Path("quarantine"))
        self.assertIs(checks[0].verdict, Verdict.FAIL)

    def test_a_clean_read_that_passes_still_passes(self):
        with mock.patch.object(
                privacy_guard, "verify_download_directory",
                lambda p, d: (True, "downloads are directed to quarantine")):
            checks = verifier._download_checks(  # lint: allow protected-access
                Path("profile"), Path("quarantine"))
        self.assertIs(checks[0].verdict, Verdict.PASS)


class TestWrongShapedPreferencesIsUnreadableNotACrash(unittest.TestCase):
    """Defect 5. A Preferences file that parses but is not an object.

    Defects 2 and 4 fixed the case where the file does not parse. A file that parses
    to a list, a string or null was never covered: every reader here indexes it as a
    mapping, so those three inputs left the guards raising AttributeError instead of
    returning the sentinel the callers already know how to render as UNKNOWN. Two of
    the four readers run inside Controller.start(), which has no handler.

    Written against a REAL file on disk rather than a patched read_text, so it reads
    the way production does.
    """

    MALFORMED = ('[]', 'null', '"a string"', '{"download": "not an object"}',
                 '{"account_info": {"not": "a list"}}')

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.profile = Path(self._tmp.name)
        (self.profile / "Default").mkdir()
        self.prefs = self.profile / "Default" / "Preferences"
        self.quarantine = self.profile / "quarantine"
        self.addCleanup(self._tmp.cleanup)

    def test_no_reader_raises_on_a_preferences_file_that_is_not_an_object(self):
        for payload in self.MALFORMED:
            with self.subTest(preferences=payload):
                self.prefs.write_text(payload, encoding="utf-8")
                privacy_guard.verify_account_signin(self.profile)
                privacy_guard.verify_download_directory(self.profile, self.quarantine)
                privacy_guard.verify_applied(self.profile, "standard")
                self.prefs.write_text(payload, encoding="utf-8")
                privacy_guard.apply_to_profile(self.profile, "standard")
                self.prefs.write_text(payload, encoding="utf-8")
                privacy_guard.apply_download_directory(self.profile, self.quarantine)

    def test_a_non_object_file_is_reported_as_unreadable_not_as_a_clean_read(self):
        for payload in ('[]', 'null', '"a string"'):
            with self.subTest(preferences=payload):
                self.prefs.write_text(payload, encoding="utf-8")
                signed_in, detail = privacy_guard.verify_account_signin(self.profile)
                self.assertFalse(signed_in)
                self.assertEqual(detail, privacy_guard.PREFS_UNREADABLE)
                ok, detail = privacy_guard.verify_download_directory(
                    self.profile, self.quarantine)
                self.assertFalse(ok)
                self.assertEqual(detail, privacy_guard.PREFS_UNREADABLE)

    def test_a_wrong_shaped_account_list_is_not_read_as_nobody_signed_in(self):
        self.prefs.write_text('{"account_info": {"not": "a list"}}', encoding="utf-8")
        signed_in, detail = privacy_guard.verify_account_signin(self.profile)
        self.assertFalse(signed_in)
        self.assertEqual(detail, privacy_guard.PREFS_UNREADABLE)

    def test_a_wrong_shaped_download_section_is_not_read_as_misconfigured(self):
        """It must reach the critical check as UNKNOWN, never as a definite FAIL."""
        self.prefs.write_text('{"download": "not an object"}', encoding="utf-8")
        ok, detail = privacy_guard.verify_download_directory(
            self.profile, self.quarantine)
        self.assertFalse(ok)
        self.assertEqual(detail, privacy_guard.PREFS_UNREADABLE)

    def test_a_well_formed_file_is_still_read_normally(self):
        """The guard must not turn every real profile into a permanent UNKNOWN."""
        privacy_guard.apply_download_directory(self.profile, self.quarantine)
        ok, detail = privacy_guard.verify_download_directory(
            self.profile, self.quarantine)
        self.assertTrue(ok, detail)
        signed_in, detail = privacy_guard.verify_account_signin(self.profile)
        self.assertFalse(signed_in)
        self.assertNotEqual(detail, privacy_guard.PREFS_UNREADABLE)


class TestIPv6IsNotClaimedAsMeasured(unittest.TestCase):
    """Defect 3. The IPv6 rule is verified as PRESENT; its EFFECT never was."""

    def test_policy_summary_does_not_say_ipv6_is_blocked(self):
        rows = dict(network_guard.policy_summary())
        self.assertIn("IPv6 local ranges", rows)
        self.assertIsNot(
            rows["IPv6 local ranges"], network_guard.PolicyState.BLOCKED,
            "policy_summary still claims IPv6 is BLOCKED with the same confidence as "
            "the IPv4 rows, which rest on the empirical gate A16 measurement")

    def test_ipv4_rows_are_untouched(self):
        """The IPv4 claims ARE measured and must not be weakened by this change."""
        rows = dict(network_guard.policy_summary())
        self.assertIs(rows["Router"], network_guard.PolicyState.BLOCKED)
        self.assertIs(rows["Private IPv4 ranges"], network_guard.PolicyState.BLOCKED)
        self.assertIs(rows["LAN devices"], network_guard.PolicyState.BLOCKED)

    def test_loopback_rows_remain_not_enforceable(self):
        rows = dict(network_guard.policy_summary())
        self.assertIs(rows["Localhost (127.0.0.1)"],
                      network_guard.PolicyState.NOT_ENFORCEABLE)
        self.assertIs(rows["This PC's own IP"],
                      network_guard.PolicyState.NOT_ENFORCEABLE)

    def test_every_policy_state_has_a_colour_in_the_network_panel(self):
        """Found by the GUI walkthrough, invisible to 141 unit tests.

        `network_panel` looked its colour up with a strict `_STATE_COLOUR[state]`, so
        the moment policy_summary() gained the "RULE SET, EFFECT NOT MEASURED" state,
        the ENTIRE Network panel died with a KeyError. A change made to stop bruhswer
        overclaiming about IPv6 took the panel offline instead, and every unit test
        still passed because nothing tied the two modules together.

        This is that tie. Any new policy state must be given a colour deliberately -
        the runtime fallback keeps the panel alive, but it must not become the silent
        way that new states get their colour chosen for them.
        """
        missing = [str(state) for _label, state in network_guard.policy_summary()
                   if str(state) not in config.POLICY_STATE_COLOUR]
        self.assertEqual(
            missing, [],
            f"policy_summary() returns state(s) the Network panel has no colour "
            f"for: {missing}")

    def test_no_unmeasured_policy_state_is_rendered_green(self):
        """A state whose text says it was not verified must never look verified."""
        from app.ui.panels import network_panel

        for _label, state in network_guard.policy_summary():
            colour = network_panel.state_colour(state)
            if "NOT MEASURED" in str(state) or "NOT ENFORCEABLE" in str(state):
                with self.subTest(state=state):
                    self.assertNotEqual(
                        colour, config.OK_GREEN,
                        f"{state!r} renders green despite saying it was not verified")

    def test_an_unrecognised_state_falls_back_to_a_cautious_colour(self):
        """The fallback must not be green or a calm grey."""
        from app.ui.panels import network_panel

        # RED, not amber: an unrecognised state means the reporting contract between
        # network_guard and the UI is broken, which is louder than any one row.
        colour = network_panel.state_colour("SOMETHING NOBODY TAUGHT THE UI")
        self.assertEqual(colour, config.POLICY_STATE_UNKNOWN_COLOUR)
        self.assertNotEqual(colour, config.OK_GREEN)
        # And it must SAY it is unrecognised rather than printing raw prose.
        self.assertIn(config.POLICY_STATE_UNKNOWN_LABEL,
                      network_panel.state_label("SOMETHING NOBODY TAUGHT THE UI"))

    def test_every_policy_state_member_has_a_colour(self):
        """Stronger than checking only the states policy_summary happens to return:
        adding an enum member without a colour must fail here, not on screen."""
        for state in network_guard.PolicyState:
            with self.subTest(state=state):
                self.assertIn(str(state), config.POLICY_STATE_COLOUR)

    def test_an_unknown_ipv6_effect_check_exists(self):
        with mock.patch.object(network_guard.sysquery, "bruhswer_rules",
                               lambda: _probe([])), \
             mock.patch.object(network_guard.sysquery, "is_elevated_probe",
                               lambda: _probe(False)), \
             mock.patch.object(network_guard.sysquery, "network_profiles",
                               lambda: _probe([])):
            checks = network_guard.verify(Path("msedge.exe"))

        effect = [c for c in checks if c.check_id == "net.rule.ipv6.effect"]
        self.assertEqual(len(effect), 1, "no IPv6 effectiveness check was emitted")
        self.assertIs(effect[0].verdict, Verdict.UNKNOWN)
        self.assertFalse(effect[0].critical,
                         "an unmeasurable property must not block launch")


# Every guard verify_all runs, the attribute it looks up to run it, and the category
# its checks report under. A guard that verify_all gains without an entry here fails
# test_the_table_covers_every_guard, and a category that drifts from verify_all's
# fails test_the_table_categories_match_verify_all.
_GUARDS: dict[str, tuple[object, str, str]] = {
    "edge": (verifier.edge, "verify_runtime", "edge"),
    "browser": (browser_guard, "verify", "browser"),
    "sandbox": (browser_guard, "verify_renderer_sandbox", "browser"),
    "network": (network_guard, "verify", "net"),
    "host": (verifier.host_guard, "evaluate", "host"),
    "controller": (verifier, "_controller_checks", "controller"),
    "integrity": (verifier.integrity, "verify", "controller"),
    "privacy": (verifier, "_privacy_checks", "privacy"),
    "downloads": (verifier, "_download_checks", "downloads"),
    "dns": (verifier, "_dns_checks", "dns"),
}


def _passing(name: str, category: str):
    """A stand-in guard that returns one critical PASS in its category."""
    def guard(*_args, **_kwargs):
        return [verifier.Check(f"{category}.stub-{name}", f"{name} stub", Verdict.PASS,
                               critical=True, detail="stub")]
    return guard


def _raising(*_args, **_kwargs):
    raise RuntimeError("guard crashed")


class TestCrashedGuardBlocksLaunch(unittest.TestCase):
    """Defect 6. A guard that RAISED left may_launch True.

    verify_all replaced the crash with one UNKNOWN at critical=False. The critical
    checks that guard would have produced were simply absent, and blocks_launch() only
    looks at critical checks, so a crash in the edge, browser or network guard removed
    exactly the checks that should have stopped the launch. The existing
    test_no_guard_crashed only shows that no guard crashed on one machine.
    """

    @staticmethod
    def _verify(crashing: str | None):
        with contextlib.ExitStack() as stack:
            for name, (owner, attr, category) in _GUARDS.items():
                stack.enter_context(mock.patch.object(
                    owner, attr,
                    _raising if name == crashing else _passing(name, category)))
            return verifier.verify_all(Path("profile"), [], "standard",
                                       Path("msedge.exe"), download_dir=Path("dl"))

    def test_the_table_covers_every_guard(self):
        ran = {t.name for t in self._verify(None).timings}
        self.assertEqual(ran, set(_GUARDS),
                         "verify_all runs a guard this test does not make crash")

    def test_the_table_categories_match_verify_all(self):
        ran = {t.name: t.category for t in self._verify(None).timings}
        self.assertEqual(ran, {name: entry[2] for name, entry in _GUARDS.items()})

    def test_with_no_crash_the_stubs_allow_launch(self):
        """Without this, every assertion below could pass for an unrelated reason."""
        self.assertTrue(self._verify(None).may_launch)

    def test_with_no_crash_every_row_is_green(self):
        """The baseline for test_a_crash_turns_its_row_off_green."""
        from app.controller import controller as ctrl

        rows = {label: verdict for label, verdict, _desc
                in ctrl.summarise(self._verify(None))}
        self.assertEqual(set(rows.values()), {Verdict.PASS}, rows)

    def test_any_guard_that_raises_blocks_launch(self):
        for name in _GUARDS:
            with self.subTest(guard=name):
                result = self._verify(name)
                self.assertFalse(result.may_launch,
                                 f"a crash in the {name} guard still allowed launch")
                failed = [c for c in result.blockers
                          if verifier.guard_failure_category(c.check_id)]
                self.assertEqual(len(failed), 1)
                self.assertIs(failed[0].verdict, Verdict.UNKNOWN)
                self.assertIsNot(failed[0].unknown_reason,
                                 verifier.UnknownReason.NONE)

    def test_every_guard_category_reaches_a_status_row(self):
        """A crashed sandbox guard was named `sandbox.guard`, under no row's prefix,
        so the BROWSER row stayed green while launch was blocked. And `edge.` reached
        no row at all, so an unsigned browser left every row green."""
        from app.controller import controller as ctrl

        covered = {category for _label, categories, _desc in ctrl.STATUS_ROWS
                   for category in categories}
        for timing in self._verify(None).timings:
            with self.subTest(guard=timing.name):
                self.assertIn(timing.category, covered)

    def test_a_crash_turns_its_row_off_green(self):
        from app.controller import controller as ctrl

        row_for = {category: label for label, categories, _desc in ctrl.STATUS_ROWS
                   for category in categories}
        for name, (_owner, _attr, category) in _GUARDS.items():
            with self.subTest(guard=name):
                rows = {label: verdict for label, verdict, _desc
                        in ctrl.summarise(self._verify(name))}
                self.assertIsNot(rows[row_for[category]], Verdict.PASS,
                                 f"a crash in the {name} guard left "
                                 f"{row_for[category]} green")



class TestGuardsRunConcurrently(unittest.TestCase):
    """The pass took the SUM of its guards (5.0 s measured); it should take the slowest.

    Deterministic, not timed: a Barrier only opens when every guard is running at
    once, so a serial pass breaks it and every guard reports a crash.
    """

    _WAIT_SECONDS = 10

    @staticmethod
    def _verify_with(make_guard):
        with contextlib.ExitStack() as stack:
            for index, (name, (owner, attr, category)) in enumerate(_GUARDS.items()):
                stack.enter_context(mock.patch.object(
                    owner, attr, make_guard(index, name, category)))
            return verifier.verify_all(Path("profile"), [], "standard",
                                       Path("msedge.exe"), download_dir=Path("dl"))

    def test_every_guard_is_running_at_the_same_time(self):
        barrier = threading.Barrier(len(_GUARDS), timeout=self._WAIT_SECONDS)

        def make_guard(_index, name, category):
            passing = _passing(name, category)

            def guard(*args, **kwargs):
                barrier.wait()
                return passing(*args, **kwargs)
            return guard

        result = self._verify_with(make_guard)
        crashed = [c.check_id for c in result.checks
                   if verifier.guard_failure_category(c.check_id)]
        self.assertEqual(crashed, [], "guards did not all run at once")

    def test_check_order_is_submission_order_even_when_finishing_in_reverse(self):
        done = [threading.Event() for _ in _GUARDS]

        def make_guard(index, name, category):
            passing = _passing(name, category)

            def guard(*args, **kwargs):
                if index + 1 < len(done) and not done[index + 1].wait(
                        self._WAIT_SECONDS):
                    raise RuntimeError("the later guard never finished")
                produced = passing(*args, **kwargs)
                done[index].set()
                return produced
            return guard

        result = self._verify_with(make_guard)
        self.assertEqual([t.name for t in result.timings], list(_GUARDS))
        self.assertEqual([c.check_id for c in result.checks],
                         [f"{category}.stub-{name}"
                          for name, (_o, _a, category) in _GUARDS.items()])

    def test_wall_time_is_measured_not_summed(self):
        result = self._verify_with(lambda _i, name, category: _passing(name, category))
        self.assertGreater(result.wall_ms, 0.0)
        self.assertFalse(hasattr(result, "total_ms"),
                         "a summed duration would misreport an overlapping pass")


class TestSharingGroupsAreMatchedByResourceId(unittest.TestCase):
    """Defect 7. Sharing groups were matched by their English display names.

    DisplayGroup is translated, so on a non-English Windows no rule matched and every
    group read "0 of 0 enabled", which rendered PASS.
    """

    QUERY = sysquery._Q_SHARING_GROUPS  # lint: allow protected-access

    def test_the_query_does_not_match_on_display_names(self):
        self.assertNotIn("DisplayGroup", self.QUERY)
        ids = re.findall(r"@FirewallAPI\.dll,-(\d+)", self.QUERY)
        self.assertEqual(len(ids), 3)

    @unittest.skipUnless(sys.platform == "win32", "reads FirewallAPI.dll")
    def test_every_group_id_exists_in_firewallapi(self):
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32 = ctypes.WinDLL("user32")
        kernel32.LoadLibraryExW.restype = wintypes.HMODULE
        kernel32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE,
                                            wintypes.DWORD]
        user32.LoadStringW.argtypes = [wintypes.HINSTANCE, wintypes.UINT,
                                       wintypes.LPWSTR, ctypes.c_int]
        as_data_file = 0x2
        module = kernel32.LoadLibraryExW(
            str(config.SYSTEM32 / "FirewallAPI.dll"), None, as_data_file)
        self.assertTrue(module, "FirewallAPI.dll could not be loaded")
        buffer = ctypes.create_unicode_buffer(256)
        for resource_id in re.findall(r"-(\d+)'", self.QUERY):
            with self.subTest(resource_id=resource_id):
                self.assertGreater(
                    user32.LoadStringW(module, int(resource_id), buffer, len(buffer)), 0)

    def test_a_group_with_no_rules_is_not_described_as_checked_rules(self):
        from app.host import host_guard

        probes = {name: _probe([]) for name in
                  ("profiles", "firewall", "remote", "listeners")}
        probes["smb"] = _probe(None)
        probes["defender"] = _probe(None)
        probes["sharing"] = _probe([
            {"Group": "Remote Desktop", "InGroup": 0, "Total": 0, "Enabled": 0},
            {"Group": "File and Printer Sharing", "InGroup": 32, "Total": 0,
             "Enabled": 0},
        ])
        with mock.patch.object(host_guard, "_gather", lambda: probes):
            checks = {c.check_id: c for c in host_guard.evaluate()}
        self.assertIn("no Remote Desktop firewall rules",
                      checks["host.sharing.remote-desktop"].detail)
        self.assertIn("None of this group's 32 rules apply to the Public",
                      checks["host.sharing.file-and-printer-sharing"].detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
