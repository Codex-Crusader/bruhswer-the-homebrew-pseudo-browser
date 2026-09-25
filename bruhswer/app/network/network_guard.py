"""Verifies the browser's firewall policy, unelevated. Applying it is the elevated
tools/bruhswer-netpolicy.ps1.

Measured (gates A16/A17): a -Program-scoped Block rule stops Edge reaching the router
while the internet and other programs are unaffected, and the browser's token cannot
remove it. Loopback cannot be filtered, so localhost is NOT ENFORCEABLE, never OK.
"""

from __future__ import annotations

import enum
import ipaddress

from .. import config, sysquery
from ..logging_setup import get_logger
from ..verdict import (Check, EvidenceKind, UnknownReason, Verdict,
                       reason_for_probe)

_log = get_logger("network")


class PolicyState(enum.Enum):
    """What bruhswer can say about one policy row. An enum, not prose: a UI matching
    prose against its own table raised KeyError when the IPv6 row changed."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    # The rule is present, but its effect on the browser was never measured.
    RULE_UNMEASURED = "RULE SET, EFFECT NOT MEASURED"
    NOT_ENFORCEABLE = "NOT ENFORCEABLE"

    def __str__(self) -> str:
        return self.value


def _expected_rule_names() -> dict[str, str]:
    """Rule name -> the address set it must cover."""
    return {
        f"{config.RULE_PREFIX}-edge-deny-ipv4-private": ",".join(config.BLOCKED_IPV4),
        f"{config.RULE_PREFIX}-edge-deny-ipv6-local": ",".join(config.BLOCKED_IPV6),
    }


def _normalise(addresses) -> set[str]:
    """Windows reports CIDR as dotted masks (10.0.0.0/255.0.0.0); normalise both forms."""
    out: set[str] = set()
    for raw in addresses or []:
        text = str(raw).strip()
        if not text:
            continue
        try:
            out.add(str(ipaddress.ip_network(text, strict=False)))
        except ValueError:
            out.add(text.lower())
    return out


# IPv6Connectivity values that mean no usable IPv6 path.
_NO_IPV6_STATES = ("nointernet", "disconnected", "localnetwork")


def _ipv6_connectivity() -> str:
    """This host's IPv6 adapter state, or 'unknown'. Context only, not evidence that
    the rule works."""
    probe = sysquery.network_profiles()
    if not probe.ok:
        return "unknown"
    states = {str(p.get("IPv6Connectivity", "")).strip().lower()
              for p in probe.value}
    states.discard("")
    if not states:
        return "unknown"
    return ",".join(sorted(states))


def _ipv6_connectivity_note(state: str) -> str:
    if state == "unknown":
        return (" Windows did not report this host's IPv6 connectivity, so bruhswer "
                "cannot say whether IPv6 is in use here either.")
    if all(s in _NO_IPV6_STATES for s in state.split(",")):
        return (f" Separately, Windows reports no IPv6 internet path on this host "
                f"({state}), which limits the exposure - but that is the network's "
                f"current state, not something bruhswer enforces, and it can change "
                f"the moment the PC joins another network.")
    return (f" Windows reports IPv6 connectivity on this host ({state}), so the "
            f"unmeasured rule is covering a path that is actually live.")


def verify(edge_path) -> list[Check]:
    """Verify network policy from the host side. Returns Checks, never raises."""
    checks: list[Check] = []
    rules = sysquery.bruhswer_rules()

    # A failed query is not an absent rule: UNKNOWN (still blocks), not "rule missing".
    if not rules.ok:
        reason = reason_for_probe(rules.status)
        for name in _expected_rule_names():
            checks.append(Check(
                check_id=f"net.rule.{name}", title=f"Firewall rule {name}",
                verdict=Verdict.UNKNOWN, critical=True,
                detail=("bruhswer could not ask Windows about its firewall rules, so "
                        "it cannot tell whether this rule is in place. This is a "
                        "failed query, not a finding that the rule is missing."),
                evidence=rules.reason(),
                evidence_kind=EvidenceKind.READ_BACK,
                unknown_reason=reason))
        checks.append(Check(
            check_id="net.rule.unexpected", title="No unexpected bruhswer rules",
            verdict=Verdict.UNKNOWN, critical=True,
            detail="The firewall rule list could not be read, so bruhswer cannot say "
                   "whether anything unrecognised is present under its own prefix.",
            evidence=rules.reason(),
            evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=reason))
        checks.extend(_tamper_check())
        checks.extend(_platform_limits())
        return checks

    by_name = {str(r.get("Name", "")): r for r in rules.value}

    for name, expected_csv in _expected_rule_names().items():
        expected = _normalise(expected_csv.split(","))
        rule = by_name.get(name)

        if rule is None:
            checks.append(Check(
                check_id=f"net.rule.{name}", title=f"Firewall rule {name}",
                verdict=Verdict.FAIL, critical=True,
                detail="Rule is not present. Run Network Policy setup.",
                evidence=f"expected={sorted(expected)} found=none {rules.reason()}",
                evidence_kind=EvidenceKind.READ_BACK))
            continue

        problems = []
        if str(rule.get("Enabled", "")).lower() not in ("true", "1"):
            problems.append("rule is disabled")
        if str(rule.get("Action", "")).lower() != "block":
            problems.append(f"action is {rule.get('Action')!r}, expected Block")
        if str(rule.get("Direction", "")).lower() != "outbound":
            problems.append(f"direction is {rule.get('Direction')!r}, expected Outbound")

        program = str(rule.get("Program", "")).strip().lower()
        if program != str(edge_path).lower():
            problems.append("rule is not scoped to the expected browser executable")

        actual = _normalise(rule.get("Remote"))
        missing = expected - actual
        if missing:
            problems.append(f"missing addresses: {sorted(missing)}")

        if problems:
            checks.append(Check(
                check_id=f"net.rule.{name}", title=f"Firewall rule {name}",
                verdict=Verdict.FAIL, critical=True,
                detail="; ".join(problems),
                evidence=f"expected={sorted(expected)} actual={sorted(actual)} "
                         f"{rules.reason()}",
                evidence_kind=EvidenceKind.READ_BACK))
        else:
            # A read-back of the rule, not proof it stops Edge (gate A16, not re-run).
            checks.append(Check(
                check_id=f"net.rule.{name}", title=f"Firewall rule {name}",
                verdict=Verdict.PASS, critical=True,
                detail=("The rule is present, enabled, scoped to the browser, and "
                        "covers every range bruhswer asked for. This is the rule's "
                        "definition read back from Windows; no traffic was sent to "
                        "confirm the rule stops the browser during this check."),
                evidence=f"addresses={sorted(actual)} {rules.reason()}",
                evidence_kind=EvidenceKind.READ_BACK))

    # A rule under bruhswer's prefix that bruhswer did not write is stale or planted.
    unexpected = sorted(set(by_name) - set(_expected_rule_names()))
    checks.append(Check(
        check_id="net.rule.unexpected", title="No unexpected bruhswer rules",
        verdict=Verdict.PASS if not unexpected else Verdict.FAIL, critical=True,
        detail=("No unrecognised rules under the bruhswer prefix."
                if not unexpected else f"Unrecognised rules present: {unexpected}"),
        evidence=f"unexpected={unexpected} {rules.reason()}",
        evidence_kind=EvidenceKind.READ_BACK))

    checks.extend(_tamper_check())
    checks.extend(_platform_limits())
    return checks


def _tamper_check() -> list[Check]:
    """Whether the browser could delete bruhswer's rules. INFERENCE: it measures
    bruhswer's token, and Edge inherits it as a child."""
    probe = sysquery.is_elevated_probe()
    if probe.value is None:
        return [Check(
            check_id="net.tamper", title="Rules resist browser tampering",
            verdict=Verdict.UNKNOWN, critical=False,
            detail=("bruhswer could not determine its own privilege level, so it "
                    "cannot reason about whether the browser could change firewall "
                    "rules."),
            evidence=probe.reason(),
            evidence_kind=EvidenceKind.INFERENCE,
            unknown_reason=reason_for_probe(probe.status))]

    if probe.value:
        return [Check(
            check_id="net.tamper", title="Rules resist browser tampering",
            verdict=Verdict.FAIL, critical=False,
            detail=("bruhswer is running as Administrator, so a browser it launches "
                    "inherits that. The firewall rules would NOT resist tampering by "
                    "the browser. Close bruhswer and start it normally."),
            evidence=f"controller_elevated=True {probe.reason()}",
            evidence_kind=EvidenceKind.INFERENCE)]

    return [Check(
        check_id="net.tamper", title="Rules resist browser tampering",
        verdict=Verdict.PASS, critical=False,
        detail=("Reasoned, not measured directly: bruhswer is running unelevated "
                "(measured this pass), the browser is started as its child and so "
                "inherits the same unelevated token, and Stage 4 gate A17 established "
                "that such a token cannot create, delete or disable firewall rules. "
                "bruhswer did not attempt a privileged operation during this check."),
        evidence=f"controller_elevated=False {probe.reason()}; "
                 f"browser_token=inherited, not measured; a17=historical",
        evidence_kind=EvidenceKind.INFERENCE)]


def _platform_limits() -> list[Check]:
    """The rows that rest on Stage 4 and are never re-measured. All HISTORICAL."""
    ipv6 = _ipv6_connectivity()
    return [
        # IPv6: presence is checked above; the effect was never measured.
        Check(
            check_id="net.rule.ipv6.effect",
            title="IPv6 blocking proven to stop the browser",
            verdict=Verdict.UNKNOWN, critical=False,
            detail=("The IPv6 Block rule is present and correctly formed, but unlike "
                    "the IPv4 rule its effect on the browser has never been measured "
                    "on this machine. Gate A16 proved the IPv4 rule empirically; there "
                    "is no equivalent IPv6 result, so bruhswer reports UNKNOWN instead "
                    "of assuming the two behave the same."
                    + _ipv6_connectivity_note(ipv6)),
            evidence=f"ipv4_effect=gate A16 measured; ipv6_effect=not measured; "
                     f"host_ipv6={ipv6}",
            evidence_kind=EvidenceKind.HISTORICAL,
            unknown_reason=UnknownReason.NEVER_MEASURED),

        Check(
            check_id="net.loopback", title="Localhost / host services blocked",
            verdict=Verdict.FAIL, critical=True, enforceable=False,
            detail=("Windows Firewall cannot filter loopback, so the browser can reach "
                    "127.0.0.1 and this PC's own IP. No setting fixes this."),
            evidence=("Stage 4 gate A16: rules naming 127.0.0.1 and the host IP did "
                      "not block Edge"),
            evidence_kind=EvidenceKind.HISTORICAL),

        Check(
            check_id="net.devservices", title="Local development services blocked",
            verdict=Verdict.FAIL, critical=False, enforceable=False,
            detail=("Services on localhost stay reachable for the same reason. Ports "
                    "bruhswer knows about: "
                    + ", ".join(str(p) for p in config.DEV_SERVICE_PORTS) + "."),
            evidence="Stage 4 gate A16 confirmed a live PyCharm service on 63342",
            evidence_kind=EvidenceKind.HISTORICAL),
    ]


def policy_summary() -> list[tuple[str, PolicyState]]:
    """The policy rows for the UI. IPv6 is not "BLOCKED": unlike IPv4 (gate A16) its
    effect was never measured, and a probe from bruhswer's own process would not test
    a rule scoped to msedge.exe."""
    return [
        ("Internet", PolicyState.ALLOWED),
        ("Router", PolicyState.BLOCKED),
        ("LAN devices", PolicyState.BLOCKED),
        ("Private IPv4 ranges", PolicyState.BLOCKED),
        ("IPv6 local ranges", PolicyState.RULE_UNMEASURED),
        ("Localhost (127.0.0.1)", PolicyState.NOT_ENFORCEABLE),
        ("This PC's own IP", PolicyState.NOT_ENFORCEABLE),
        ("Development services", PolicyState.NOT_ENFORCEABLE),
    ]


# The evidence behind each state, printed beside it: "Router - BLOCKED" rests on gate
# A16, measured once, not now.
POLICY_EVIDENCE = {
    PolicyState.ALLOWED: EvidenceKind.INFERENCE,
    PolicyState.BLOCKED: EvidenceKind.HISTORICAL,
    PolicyState.RULE_UNMEASURED: EvidenceKind.READ_BACK,
    PolicyState.NOT_ENFORCEABLE: EvidenceKind.HISTORICAL,
}


def policy_evidence(state) -> EvidenceKind:
    """Evidence kind for one policy row; an unknown state gets the weakest, INFERENCE."""
    return POLICY_EVIDENCE.get(state, EvidenceKind.INFERENCE)
