"""The only three verdicts bruhswer uses, and the shape of a check result.

Stage 1-4 of this project established one rule above all others: a security indicator
that lies is itself a vulnerability. So there are exactly three verdicts, UNKNOWN is
never silently promoted to PASS, and every Check carries the evidence it was based on.

`enforceable=False` marks a control that CANNOT exist on this platform, as opposed to
one that merely failed. Both are honest; they are different facts and the UI shows them
differently. Example: Windows Firewall cannot filter loopback, so "browser cannot reach
127.0.0.1" is a FAIL that no amount of configuration will fix. Measured in Stage 4 gate
A16 -- see docs/research/STAGE-4-VERIFICATION.md.
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


def worst(checks: list[Check]) -> Verdict:
    """Aggregate. Any FAIL wins, then any UNKNOWN. Unenforceable checks are excluded
    because they describe the platform, not this run's configuration."""
    live = [c for c in checks if c.enforceable]
    if any(c.verdict is Verdict.FAIL for c in live):
        return Verdict.FAIL
    if any(c.verdict is Verdict.UNKNOWN for c in live):
        return Verdict.UNKNOWN
    return Verdict.PASS
