"""The evidence model is only worth having if it cannot rot.

A check declares HOW it knows what it claims. `EvidenceKind` defaults to INFERENCE so
that forgetting to declare one understates rather than overstates - but a silent
understatement is still a wrong label, and nothing stops a new check from claiming LIVE
for a preference read. These tests are what stops it.

    1. every check the verifier emits is in the frozen table below, with the kind the
       table says. A new check_id fails here until somebody decides what it knows.
    2. every UNKNOWN carries a reason code. "UNKNOWN" with no reason is the bare
       indicator this project treats as a defect.
    3. ProbeStatus and UnknownReason stay in step, so reason_for_probe() cannot
       silently collapse a new status into PROBE_ERROR.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app import config, sysquery  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.verdict import (Check, EvidenceKind, UnknownReason,  # noqa: E402
                         Verdict, reason_for_probe)

LIVE = EvidenceKind.LIVE
READ = EvidenceKind.READ_BACK
HIST = EvidenceKind.HISTORICAL
INFER = EvidenceKind.INFERENCE

# check_id -> the evidence it is allowed to claim.
#
# LIVE means bruhswer observed the property it names during the pass. READ_BACK means it
# read a setting and the enforcement was not observed. HISTORICAL means a Stage 4 result
# that nothing re-runs. INFERENCE means it was reasoned out.
#
# Changing an entry here is changing a security claim. Do it deliberately.
EXPECTED: dict[str, EvidenceKind] = {
    "edge.present": LIVE,
    "edge.signature": LIVE,

    "browser.profile.location": LIVE,
    "browser.profile.separate": LIVE,
    "browser.profile.acl": READ,
    "browser.cmdline": INFER,
    "browser.cmdline.profile": INFER,
    "browser.sandbox.flags": INFER,
    "browser.sandbox": LIVE,

    # Rule presence is read back; that the rules STOP Edge is gate A16, and historical.
    "net.rule.BRUHWSER-edge-deny-ipv4-private": READ,
    "net.rule.BRUHWSER-edge-deny-ipv6-local": READ,
    "net.rule.unexpected": READ,
    "net.tamper": INFER,
    "net.rule.ipv6.effect": HIST,
    "net.loopback": HIST,
    "net.devservices": HIST,

    "host.network": READ,
    "host.firewall": READ,
    "host.sharing.file-and-printer-sharing": READ,
    "host.sharing.network-discovery": READ,
    "host.sharing.remote-desktop": READ,
    "host.smb": READ,
    "host.remoteadmin": LIVE,
    "host.discovery.services": LIVE,
    "host.listeners": LIVE,
    "host.defender": READ,

    "controller.privilege": LIVE,
    "controller.integrity": LIVE,

    "privacy.settings": READ,
    "privacy.account": READ,
    "downloads.quarantine": READ,
    "dns.encrypted": READ,
}

# Guards emit one of these if they raise; verifier.verify_all names them after the guard.
_GUARD_FAILURE_SUFFIX = ".guard"


def _live_result():
    return ctrl.Controller().verify()


class TestEveryCheckDeclaresItsEvidence(unittest.TestCase):
    """A real pass on this machine, against the frozen table."""

    @classmethod
    def setUpClass(cls):
        cls.result = _live_result()

    def test_the_pass_produced_checks_at_all(self):
        """Guard against this whole suite passing vacuously."""
        self.assertGreaterEqual(len(self.result.checks), 20,
                                f"only {len(self.result.checks)} checks were produced")

    def test_no_guard_crashed(self):
        """A crashed guard would hide the checks this suite is meant to inspect."""
        crashed = [c.check_id for c in self.result.checks
                   if c.check_id.endswith(_GUARD_FAILURE_SUFFIX)]
        self.assertEqual(crashed, [], f"guards raised: {crashed}")

    def test_every_check_id_is_in_the_table(self):
        unknown = sorted({c.check_id for c in self.result.checks} - set(EXPECTED))
        self.assertEqual(
            unknown, [],
            f"check(s) with no declared evidence kind: {unknown}. Add them to "
            f"EXPECTED after deciding what each one actually knows.")

    def test_every_check_claims_the_evidence_the_table_allows(self):
        for check in self.result.checks:
            expected = EXPECTED.get(check.check_id)
            if expected is None:
                continue        # reported by the test above
            with self.subTest(check_id=check.check_id):
                self.assertIs(
                    check.evidence_kind, expected,
                    f"{check.check_id} claims {check.evidence_kind} but the evidence "
                    f"model says {expected}: {check.detail[:90]}")

    def test_every_unknown_carries_a_reason(self):
        bare = [c.check_id for c in self.result.checks
                if c.verdict is Verdict.UNKNOWN
                and c.unknown_reason is UnknownReason.NONE]
        self.assertEqual(
            bare, [],
            f"UNKNOWN with no reason code: {bare}. 'Could not verify' without saying "
            f"why is the bare indicator this project treats as a defect.")

    def test_no_settled_check_carries_a_reason(self):
        """A PASS or FAIL with an unknown_reason is a contradiction."""
        wrong = [(c.check_id, str(c.unknown_reason)) for c in self.result.checks
                 if c.verdict is not Verdict.UNKNOWN
                 and c.unknown_reason is not UnknownReason.NONE]
        self.assertEqual(wrong, [], f"settled checks carrying a reason code: {wrong}")

    def test_the_pass_recorded_per_guard_timing(self):
        self.assertTrue(self.result.timings, "no guard timings were recorded")
        self.assertGreater(self.result.total_ms, 0.0)
        for timing in self.result.timings:
            with self.subTest(guard=timing.name):
                self.assertGreaterEqual(timing.duration_ms, 0.0)


class TestEvidenceKindIsNotDecoration(unittest.TestCase):
    """The label has to constrain the wording, or it is just an enum nobody reads."""

    @classmethod
    def setUpClass(cls):
        cls.result = _live_result()

    # Phrases that assert an OBSERVED behaviour. A check that only read a setting back
    # must not use them: "downloads go to quarantine" is a claim about what happens to a
    # file, and reading two keys out of JSON does not establish it.
    BEHAVIOURAL = ("will not ask", "cannot reach", "are directed to", "go to quarantine",
                   "is blocked from", "packets are")

    def test_read_back_checks_do_not_assert_observed_behaviour(self):
        offenders = []
        for check in self.result.checks:
            if check.evidence_kind is not READ or check.verdict is not Verdict.PASS:
                continue
            low = check.detail.lower()
            for phrase in self.BEHAVIOURAL:
                if phrase in low:
                    offenders.append(f"{check.check_id}: {phrase!r}")
        self.assertEqual(
            offenders, [],
            f"read-back check(s) asserting observed behaviour: {offenders}")

    def test_historical_checks_do_not_claim_to_be_current(self):
        offenders = [c.check_id for c in self.result.checks
                     if c.evidence_kind is HIST
                     and ("measured now" in c.detail.lower()
                          or "just now" in c.detail.lower())]
        self.assertEqual(offenders, [], f"historical check(s) claiming currency: "
                                        f"{offenders}")

    def test_evidence_note_distinguishes_every_kind(self):
        """Each kind must render differently, or the UI cannot tell them apart."""
        notes = {kind: Check("x", "x", Verdict.PASS, "d", evidence_kind=kind).
                 evidence_note() for kind in EvidenceKind}
        self.assertEqual(len(set(notes.values())), len(EvidenceKind),
                         f"two evidence kinds render the same phrase: {notes}")

    def test_an_unknown_note_names_its_reason(self):
        check = Check("x", "x", Verdict.UNKNOWN, "d",
                      unknown_reason=UnknownReason.PERMISSION_DENIED)
        self.assertIn("PERMISSION_DENIED", check.evidence_note())


class TestProbeStatusAndUnknownReasonStayInStep(unittest.TestCase):
    """reason_for_probe maps by VALUE, so drift between the two enums is silent."""

    def test_every_failure_status_has_its_own_reason(self):
        missing = [str(s) for s in sysquery.ProbeStatus
                   if s is not sysquery.ProbeStatus.OK
                   and str(s) not in {r.value for r in UnknownReason}]
        self.assertEqual(
            missing, [],
            f"ProbeStatus member(s) with no matching UnknownReason: {missing}. "
            f"reason_for_probe() would collapse them into PROBE_ERROR, which is the "
            f"exact conflation the reason codes exist to remove.")

    def test_each_failure_status_maps_to_a_distinct_reason(self):
        statuses = [s for s in sysquery.ProbeStatus if s is not sysquery.ProbeStatus.OK]
        mapped = [reason_for_probe(s) for s in statuses]
        self.assertEqual(len(set(mapped)), len(statuses),
                         f"two probe statuses map to one reason: "
                         f"{list(zip([str(s) for s in statuses], mapped, strict=True))}")

    def test_an_unrecognised_status_is_not_silently_ok(self):
        self.assertIs(reason_for_probe("SOMETHING_NEW"), UnknownReason.PROBE_ERROR)
        self.assertIsNot(reason_for_probe("SOMETHING_NEW"), UnknownReason.NONE)


class TestElevationCacheCannotBrickLaunch(unittest.TestCase):
    """controller.privilege is critical=True, so UNKNOWN blocks launch.

    Memoising a failed measurement would therefore block EVERY launch for the rest of
    the process's life, recoverable only by restarting bruhswer.
    """

    def setUp(self):
        sysquery.reset_elevation_cache()

    def tearDown(self):
        sysquery.reset_elevation_cache()

    def test_a_failed_measurement_is_never_cached(self):
        calls = []

        def failing():
            calls.append(1)
            return sysquery.Probe(None, sysquery.ProbeStatus.TIMEOUT, 0.0)

        original = sysquery._measure_elevation  # noqa: SLF001  # lint: allow protected-access - pins the caching rule
        sysquery._measure_elevation = failing  # lint: allow protected-access
        try:
            self.assertIsNone(sysquery.is_elevated())
            self.assertIsNone(sysquery.is_elevated())
        finally:
            sysquery._measure_elevation = original  # lint: allow protected-access
        self.assertEqual(len(calls), 2,
                         "a failed elevation measurement was cached; one timeout at "
                         "startup would block launch for the process lifetime")

    def test_a_definite_answer_is_measured_once(self):
        calls = []

        def answering():
            calls.append(1)
            return sysquery.Probe(False, sysquery.ProbeStatus.OK, 0.0)

        original = sysquery._measure_elevation  # noqa: SLF001  # lint: allow protected-access - pins the caching rule
        sysquery._measure_elevation = answering  # lint: allow protected-access
        try:
            self.assertIs(sysquery.is_elevated(), False)
            self.assertIs(sysquery.is_elevated(), False)
            self.assertIs(sysquery.is_elevated(), False)
        finally:
            sysquery._measure_elevation = original  # lint: allow protected-access
        self.assertEqual(len(calls), 1,
                         "elevation was re-measured; it cannot change while the "
                         "process runs and each query costs a PowerShell round trip")

    def test_a_cached_false_still_reaches_the_verifier_as_pass(self):
        sysquery.reset_elevation_cache()
        result = _live_result()
        privilege = [c for c in result.checks
                     if c.check_id == "controller.privilege"]
        self.assertEqual(len(privilege), 1)
        self.assertIsNot(privilege[0].verdict, Verdict.UNKNOWN,
                         f"privilege check is UNKNOWN: {privilege[0].detail}")


class TestProbeFailuresAreNotFindings(unittest.TestCase):
    """A query that did not run must never read as a measurement that did."""

    def test_a_failed_rule_query_does_not_claim_the_rules_are_missing(self):
        from app.network import network_guard

        failed = sysquery.Probe([], sysquery.ProbeStatus.TIMEOUT, 0.0, "timed out")
        original = network_guard.sysquery.bruhswer_rules
        network_guard.sysquery.bruhswer_rules = lambda: failed
        try:
            checks = network_guard.verify(config.EDGE_CANDIDATES[0])
        finally:
            network_guard.sysquery.bruhswer_rules = original

        rules = [c for c in checks if c.check_id.startswith("net.rule.BRUHWSER")]
        self.assertEqual(len(rules), 2, "the rule checks vanished on a failed query")
        for check in rules:
            with self.subTest(check_id=check.check_id):
                self.assertIs(check.verdict, Verdict.UNKNOWN)
                self.assertIs(check.unknown_reason, UnknownReason.TIMEOUT)
                self.assertNotIn("not present", check.detail.lower())
                # Fail-closed is preserved: critical + UNKNOWN still blocks launch.
                self.assertTrue(check.blocks_launch)

    def test_a_failed_sharing_query_keeps_the_same_check_ids(self):
        """A check_id that vanishes is a PASS that silently leaves the lights.

        find_regressions only iterates the checks it can see, so a disappearing id is
        invisible to it - the light goes out with nothing reported.
        """
        from app.host import host_guard

        ok_ids = {c.check_id for c in host_guard.evaluate()
                  if c.check_id.startswith("host.sharing")}

        failed = sysquery.Probe([], sysquery.ProbeStatus.PERMISSION_DENIED, 0.0)
        original = host_guard.sysquery.sharing_groups
        host_guard.sysquery.sharing_groups = lambda: failed
        try:
            failed_ids = {c.check_id for c in host_guard.evaluate()
                          if c.check_id.startswith("host.sharing")}
        finally:
            host_guard.sysquery.sharing_groups = original

        self.assertEqual(
            ok_ids, failed_ids,
            "the sharing check_ids change when the query fails, so those checks "
            "vanish from the lights instead of reporting that they are unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
