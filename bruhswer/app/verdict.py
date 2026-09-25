"""The three verdicts and the shape of a check result.

UNKNOWN is never promoted to PASS. `enforceable=False` marks a control the platform
cannot provide at all (loopback filtering). `EvidenceKind` says HOW a PASS is known,
because a live measurement and a settings read looked like the same green dot.
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
    """How a check knows what it claims, strongest first."""

    # Observed on this machine during this pass.
    LIVE = "live measurement"

    # A setting read back now: proves it is configured, not that it is enforced.
    READ_BACK = "read-back"

    # A measurement from an earlier stage, not re-run.
    HISTORICAL = "historical evidence"

    # Reasoned, not measured. The default, so forgetting one understates.
    INFERENCE = "inference"

    def __str__(self) -> str:
        return self.value


class UnknownReason(enum.Enum):
    """Why a check came back UNKNOWN. The probe codes mirror sysquery.ProbeStatus."""

    NONE = ""

    # From a failed sysquery probe.
    TIMEOUT = "TIMEOUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED = "UNSUPPORTED"
    LAUNCH_FAILED = "LAUNCH_FAILED"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    PROBE_ERROR = "PROBE_ERROR"

    # About bruhswer's own state, not a failed query.
    NO_SESSION = "NO_SESSION"
    NO_PROFILE_YET = "NO_PROFILE_YET"
    # Exists but could not be read: never a clean negative.
    UNREADABLE = "UNREADABLE"
    # Only part could be measured.
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    # No measurement exists at all.
    NEVER_MEASURED = "NEVER_MEASURED"
    # The query worked; the property has no value now (e.g. no network attached).
    NOT_APPLICABLE = "NOT_APPLICABLE"

    def __str__(self) -> str:
        return self.value


def reason_for_probe(status) -> UnknownReason:
    """Map a sysquery.ProbeStatus to an UnknownReason by value; this module imports
    nothing. A test keeps the two enums in step."""
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
    # The weakest kind by default; a test fails any check left on it.
    evidence_kind: EvidenceKind = EvidenceKind.INFERENCE
    unknown_reason: UnknownReason = UnknownReason.NONE

    @property
    def blocks_launch(self) -> bool:
        """A critical check blocks launch unless it PASSES, so UNKNOWN blocks too. An
        unenforceable control never blocks; it is shown instead."""
        if not self.enforceable:
            return False
        return self.critical and self.verdict is not Verdict.PASS

    def indicator(self) -> str:
        if not self.enforceable:
            return "NOT ENFORCEABLE"
        return {Verdict.PASS: "OK", Verdict.FAIL: "EXPOSED",
                Verdict.UNKNOWN: "UNKNOWN"}[self.verdict]

    def evidence_note(self) -> str:
        """A short phrase for the user naming what this verdict rests on."""
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
    """Any FAIL wins, then any UNKNOWN. Unenforceable checks are excluded."""
    live = [c for c in checks if c.enforceable]
    if any(c.verdict is Verdict.FAIL for c in live):
        return Verdict.FAIL
    if any(c.verdict is Verdict.UNKNOWN for c in live):
        return Verdict.UNKNOWN
    return Verdict.PASS
