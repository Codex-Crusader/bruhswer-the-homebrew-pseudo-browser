"""The only three verdicts bruhswer uses, and the shape of a check result.

A security indicator that lies is itself a vulnerability, so there are exactly three
verdicts, UNKNOWN is never silently promoted to PASS, and every Check carries its
evidence.

`enforceable=False` marks a control that CANNOT exist on this platform, as opposed to
one that merely failed. Windows Firewall cannot filter loopback, so "browser cannot
reach 127.0.0.1" is a FAIL no amount of configuration will fix.

`EvidenceKind` exists because PASS says a check succeeded, not how bruhswer knows. A
live token read, a preference read out of a JSON file, and a claim reasoned from
bruhswer's own privilege level all rendered as the same green dot, and careful `detail`
wording does not fix that - the dot is what people read.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Verdict(enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value


class EvidenceKind(enum.Enum):
    """How a check knows what it claims. Ordered weakest-last.

    LIVE vs READ_BACK is the distinction this project keeps getting wrong: a firewall
    rule can be present, enabled and correctly scoped, and still not stop a packet.
    """

    # Observed on this machine during this pass: a live token, a file hashed now,
    # processes actually running.
    LIVE = "live measurement"

    # A SETTING read back from the OS or a profile file just now. Proves the
    # configuration exists, NOT that it is enforced, so detail text on a READ_BACK
    # check must be phrased as a statement about configuration.
    READ_BACK = "read-back"

    # A real experiment from an earlier stage, not re-run this pass. It describes a
    # moment that has passed; the machine and both builds may have moved since.
    HISTORICAL = "historical evidence"

    # Reasoned rather than measured. The weakest kind, and the DEFAULT, so a check
    # whose author forgot to declare one understates what bruhswer knows.
    INFERENCE = "inference"

    def __str__(self) -> str:
        return self.value


class UnknownReason(enum.Enum):
    """WHY a check came back UNKNOWN.

    A missing cmdlet, a refused query, a slow helper and a property nobody has ever
    measured call for four different responses. The probe-level codes mirror
    `sysquery.ProbeStatus` by value, so a reason carries from the failed query to the
    light on screen without anything inventing one in between.
    """

    NONE = ""

    # --- carried up from a failed sysquery probe --------------------------------
    TIMEOUT = "TIMEOUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED = "UNSUPPORTED"
    LAUNCH_FAILED = "LAUNCH_FAILED"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    PROBE_ERROR = "PROBE_ERROR"

    # --- reasons that are about bruhswer's own state, not a failed query --------
    # Nothing is running yet, so the property has nothing to be true of.
    NO_SESSION = "NO_SESSION"
    # No profile has been created, so there is no file to read a setting out of.
    NO_PROFILE_YET = "NO_PROFILE_YET"
    # The artefact exists and bruhswer could not read it. NOT the same as it being
    # absent, and never to be reported as a clean negative result.
    UNREADABLE = "UNREADABLE"
    # Part of the population was measured and part could not be. Reported as UNKNOWN
    # rather than passing on the subset that happened to be readable.
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    # No measurement of this property exists - not here, not in an earlier stage.
    # An honest admission of a gap, as opposed to a measurement that failed.
    NEVER_MEASURED = "NEVER_MEASURED"
    # The query succeeded and the property simply has no value in the current state -
    # a network category with no network attached, for instance. Distinct from every
    # code above, all of which mean bruhswer tried to find out and could not.
    NOT_APPLICABLE = "NOT_APPLICABLE"

    def __str__(self) -> str:
        return self.value


def reason_for_probe(status) -> UnknownReason:
    """Map a `sysquery.ProbeStatus` onto the matching `UnknownReason`.

    BY VALUE, not by importing sysquery: this module is the leaf of the dependency
    graph. test_evidence_model.py asserts the two enums stay in step, so a new
    ProbeStatus nobody mapped fails the build rather than becoming PROBE_ERROR here.
    """
    try:
        return UnknownReason(str(status))
    except ValueError:
        return UnknownReason.PROBE_ERROR


@dataclass(frozen=True)
class Check:
    """One verified property. `detail` is shown to the user; `evidence` is logged."""

    check_id: str
    title: str
    verdict: Verdict
    detail: str
    evidence: str = ""
    critical: bool = False
    enforceable: bool = True
    # Defaults to the WEAKEST kind on purpose: forgetting to declare one must never be
    # how a check acquires a stronger claim than it earned. test_evidence_model.py
    # fails the build if any check the verifier emits is left on the default.
    evidence_kind: EvidenceKind = EvidenceKind.INFERENCE
    unknown_reason: UnknownReason = UnknownReason.NONE

    @property
    def blocks_launch(self) -> bool:
        """Fail-closed: a critical check blocks launch unless it PASSES, and UNKNOWN
        blocks too - that is the point of having three verdicts.

        A known-unenforceable control is the exception. Refusing to launch because
        Windows cannot filter loopback would make the product unusable while changing
        nothing about the user's exposure, so it is surfaced prominently instead.
        """
        if not self.enforceable:
            return False
        return self.critical and self.verdict is not Verdict.PASS

    def indicator(self) -> str:
        if not self.enforceable:
            return "NOT ENFORCEABLE"
        return {Verdict.PASS: "OK", Verdict.FAIL: "EXPOSED",
                Verdict.UNKNOWN: "UNKNOWN"}[self.verdict]

    def evidence_note(self) -> str:
        """One short phrase naming what this verdict rests on, written for a user.

        Rendered next to the verdict everywhere, so a green dot backed by a preference
        read cannot be mistaken for one backed by a live measurement.
        """
        if (self.verdict is Verdict.UNKNOWN
                and self.unknown_reason is not UnknownReason.NONE):
            return f"not established: {self.unknown_reason}"
        return {
            EvidenceKind.LIVE: "measured now",
            EvidenceKind.READ_BACK: "configuration read back; enforcement not observed",
            EvidenceKind.HISTORICAL: "earlier measurement, not re-run now",
            EvidenceKind.INFERENCE: "reasoned, not measured",
        }[self.evidence_kind]


def worst(checks: list[Check]) -> Verdict:
    """Aggregate. Any FAIL wins, then any UNKNOWN. Unenforceable checks are excluded
    because they describe the platform, not this run's configuration."""
    live = [c for c in checks if c.enforceable]
    if any(c.verdict is Verdict.FAIL for c in live):
        return Verdict.FAIL
    if any(c.verdict is Verdict.UNKNOWN for c in live):
        return Verdict.UNKNOWN
    return Verdict.PASS
