"""The only three verdicts bruhswer uses, and the shape of a check result.

Stage 1-4 of this project established one rule above all others: a security indicator
that lies is itself a vulnerability. So there are exactly three verdicts, UNKNOWN is
never silently promoted to PASS, and every Check carries the evidence it was based on.

`enforceable=False` marks a control that CANNOT exist on this platform, as opposed to
one that merely failed. Both are honest; they are different facts and the UI shows them
differently. Example: Windows Firewall cannot filter loopback, so "browser cannot reach
127.0.0.1" is a FAIL that no amount of configuration will fix. Measured in Stage 4 gate
A16 -- see docs/research/STAGE-4-VERIFICATION.md.

Every Check also declares an `EvidenceKind`. PASS says a check succeeded; it does not
say how bruhswer knows. These three all rendered as the same green dot:

    browser.sandbox       read the live renderer tokens, this pass
    downloads.quarantine  read a preference out of a JSON file
    net.tamper            reasoned from bruhswer's own privilege level

Careful `detail` wording does not fix that, because the dot is what people read.
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
    That is why Stage 4 had to measure gate A16 rather than trust the readback.
    """

    # bruhswer observed the property it names, on this machine, during this pass.
    # Reading a live process token, hashing a file that is on disk right now,
    # enumerating processes that are actually running.
    LIVE = "live measurement"

    # bruhswer read a SETTING back from the OS or from a profile file, just now. This
    # proves the configuration exists and says what bruhswer intended. It does NOT
    # prove the configuration is being enforced, and any detail text on a READ_BACK
    # check must be phrased as a statement about configuration.
    READ_BACK = "read-back"

    # The claim rests on a measurement taken in an earlier research stage, on this
    # project's hardware, and NOT re-run during this pass. Still evidence - it was a
    # real experiment - but it describes a moment that has passed, and the machine,
    # the Windows build and the Edge build may all have moved since.
    HISTORICAL = "historical evidence"

    # Derived by reasoning from other facts rather than measured. The weakest kind,
    # and the DEFAULT, so that a check whose author forgot to declare one understates
    # what bruhswer knows instead of overstating it.
    INFERENCE = "inference"

    def __str__(self) -> str:
        return self.value


class UnknownReason(enum.Enum):
    """WHY a check came back UNKNOWN.

    A missing cmdlet, a refused query, a slow helper and a property nobody has ever
    measured call for four different responses from the user. The probe-level codes
    mirror `sysquery.ProbeStatus` by value, so a reason carries straight from the
    failed query to the light on screen without anything inventing one in between.
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

    BY VALUE, not by importing sysquery. This module is the leaf of bruhswer's
    dependency graph - every guard imports it and it imports nothing back - and that is
    worth keeping. The two enums share their string values exactly, and
    tests/test_evidence_model.py asserts that they stay in step, so a new ProbeStatus
    that nobody mapped fails the build rather than silently becoming PROBE_ERROR here.
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
    # Defaults to the WEAKEST kind on purpose - see EvidenceKind.INFERENCE. Forgetting
    # to declare one must never be the way a check acquires a stronger claim than it
    # earned. tests/test_evidence_model.py fails the build if any check the verifier
    # emits is left on the default.
    evidence_kind: EvidenceKind = EvidenceKind.INFERENCE
    unknown_reason: UnknownReason = UnknownReason.NONE

    @property
    def blocks_launch(self) -> bool:
        """Fail-closed rule (brief SS9).

        A critical check blocks launch unless it PASSES. UNKNOWN blocks too -- that is
        the entire point of having three verdicts instead of two.

        A known-unenforceable control is the one exception: it is a documented platform
        limitation, not a missing control, and refusing to ever launch because Windows
        cannot filter loopback would make the product unusable while changing nothing
        about the user's actual exposure. It is surfaced prominently instead.
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
        """One short phrase naming what kind of knowledge this verdict rests on.

        Written for a user, not a log. Rendered next to the verdict everywhere a check
        is shown, so a green dot backed by a preference read cannot be mistaken for one
        backed by a live measurement.
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
