"""Regression tests named after the overclaims they exist to prevent.

This project's governing rule is that a security indicator which was never measured is
a VULNERABILITY, not a documentation bug. These three defects were all live in shipped
code, all produced a green or confident indicator, and all passed the existing 52-test
static suite - because that suite checks bruhswer's STRUCTURE (no shell=True, no
listener, no dynamic execution) and none of these were structural. They were each a
place where "could not measure" was collapsed into "measured, and it was fine".

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
                       mid-rewrite Preferences file produced a CRITICAL FAIL asserting
                       "Downloads would NOT be quarantined" - on a file bruhswer had
                       just failed to parse, on the one check in the suite marked
                       critical.
"""

from __future__ import annotations

import sys
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
