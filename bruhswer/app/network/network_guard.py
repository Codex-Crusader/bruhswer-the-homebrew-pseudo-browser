"""NetworkGuard — verifies the browser's network policy. Never applies it.

Division of responsibility, and it is deliberate:

  - APPLYING firewall rules needs Administrator. That lives in the elevated one-shot
    `tools/bruhswer-netpolicy.ps1`, which the user runs knowingly, with a rollback.
  - VERIFYING them does not. That is this module, and it runs unelevated, which is how
    bruhswer normally runs (brief SS16).

The mechanism this rests on is the strongest thing Stage 4 measured:

  A16 PASS  a -Program scoped outbound Block rule stops Edge reaching the router
            (REACHED -> BLOCKED -> REACHED, ERR_NETWORK_ACCESS_DENIED) while the
            internet stays up and other programs are unaffected.
  A17 PASS  the browser-process token CANNOT create, delete or disable those rules --
            both the NetSecurity cmdlets and netsh refuse without elevation.

And the limit, which is stated just as loudly:

  A16 FAIL  rules explicitly naming 127.0.0.1 and the host's own LAN IP did NOT block
            Edge. Windows Firewall does not filter loopback. No configuration fixes
            this, so localhost protection is reported NOT ENFORCEABLE, never as OK.

This is not a VM boundary and this module must never imply that it is.
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
    """What bruhswer can say about one row of network policy.

    A TYPE, not a display string, and the difference was a real defect.

    policy_summary() used to return prose, and each UI pattern-matched that prose
    against its own hard-coded colour dict. When the IPv6 row stopped claiming
    "BLOCKED" - correctly, because its effect was never measured - both dicts missed
    the new string. `panels/network_panel.py` raised KeyError and the Network panel
    vanished entirely; `app_ui.py` would have done the same to the --panel UI. A change
    made to stop bruhswer overclaiming took two screens offline instead, and every unit
    test passed, because nothing tied the producing module to the consuming ones.

    Security meaning must not depend on matching prose. The enum carries the MEANING;
    each UI maps meaning to colour, and a test asserts every member has one.
    """

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    # The rule exists and is correctly formed, but its effect on the browser has never
    # been measured on this machine. Distinct from BLOCKED, which on the IPv4 rows
    # rests on the empirical gate-A16 result.
    RULE_UNMEASURED = "RULE SET, EFFECT NOT MEASURED"
    # The platform cannot enforce it at all. Not a failure to configure.
    NOT_ENFORCEABLE = "NOT ENFORCEABLE"

    def __str__(self) -> str:
        return self.value


def _expected_rule_names() -> dict[str, str]:
    """Rule name -> the address set it must cover. Mirrors the elevated one-shot."""
    return {
        f"{config.RULE_PREFIX}-edge-deny-ipv4-private": ",".join(config.BLOCKED_IPV4),
        f"{config.RULE_PREFIX}-edge-deny-ipv6-local": ",".join(config.BLOCKED_IPV6),
    }


def _normalise(addresses) -> set[str]:
    """Windows reports CIDR back as dotted masks (10.0.0.0/255.0.0.0). Normalise both
    forms so a rule readback can be compared with what bruhswer asked for."""
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


# Values Get-NetConnectionProfile reports for IPv6Connectivity when the adapter has no
# usable IPv6 path. Named rather than inlined so the comparison below reads as policy.
_NO_IPV6_STATES = ("nointernet", "disconnected", "localnetwork")


def _ipv6_connectivity() -> str:
    """What Windows says about this host's IPv6 reachability, or 'unknown'.

    ADAPTER STATE ONLY. This says nothing about whether bruhswer's firewall rule works
    - it is context for the reader, not evidence for the check, and the caller's detail
    text is written so the two cannot be confused.
    """
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

    # A FAILED QUERY IS NOT AN ABSENT RULE. `bruhswer_rules()` used to return a bare
    # `[]` whether the rules were missing or PowerShell had timed out, and every
    # net.rule.* check is critical=True - so one slow query claimed "Rule is not
    # present. Run Network Policy setup.", blocked the launch, and later fired a
    # regression curtain. Fail-closed is preserved (UNKNOWN on a critical check still
    # blocks); bruhswer now says it could not look rather than asserting a finding.
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
            # "Present, enabled, scoped to the browser, covering all ranges" next to a
            # green dot reads as "the browser cannot reach those ranges". What bruhswer
            # did was read the rule's definition back. That it STOPS Edge is a separate
            # claim resting on gate A16, which this pass does not re-run.
            checks.append(Check(
                check_id=f"net.rule.{name}", title=f"Firewall rule {name}",
                verdict=Verdict.PASS, critical=True,
                detail=("The rule is present, enabled, scoped to the browser, and "
                        "covers every range bruhswer asked for. This is the rule's "
                        "definition read back from Windows; no traffic was sent to "
                        "confirm the rule stops the browser during this check."),
                evidence=f"addresses={sorted(actual)} {rules.reason()}",
                evidence_kind=EvidenceKind.READ_BACK))

    # Extra rules under bruhswer's prefix that bruhswer did not author. Brief SS9 lists
    # "unexpected network rule" as a launch blocker, and it is right to: a rule we do
    # not recognise under our own name is either stale or planted.
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
    """Whether the browser could delete bruhswer's own firewall rules.

    THIS CHECK MEASURES THE WRONG PROCESS. is_elevated() reports BRUHSWER's token; that
    Edge is also unelevated follows from it being launched as a child. Sound, but
    reasoning - hence INFERENCE rather than a green dot citing gate A17.
    """
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
    # Once. The detail and the evidence string both wanted this, and calling the helper
    # twice cost a second ~400ms network_profiles probe for the same answer.
    ipv6 = _ipv6_connectivity()
    return [
        # IPv6: the rule's PRESENCE is checked above and can honestly PASS. Its EFFECT
        # has never been measured on this machine, and that asymmetry with IPv4 was
        # invisible because policy_summary() simply printed "BLOCKED" for both.
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

        # The honest limitation. Reported every single time, never hidden, never green.
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
    """What the policy actually is, for the UI. No claim beyond what was measured.

    The IPv6 row is deliberately NOT "BLOCKED", and the difference from the IPv4 rows
    is the whole point of this docstring.

    Every other "BLOCKED" here rests on gate A16, which measured the effect
    EMPIRICALLY: the router went from REACHED to BLOCKED to REACHED again as the rule
    was applied and removed, with ERR_NETWORK_ACCESS_DENIED in the browser. Nothing
    equivalent was ever run for IPv6. The rule is present and correctly formed - that
    is what `verify()` above checks, and it PASSES honestly - but "a correctly formed
    Block rule exists" and "the browser cannot reach fc00::/7" are different claims,
    and this table was making the second one on the strength of the first.

    bruhswer also cannot close the gap from here. The rules are `-Program` scoped to
    msedge.exe, so a probe sent from bruhswer's own process would measure nothing about
    Edge - the identical error that made the original localhost claim wrong - and
    `app/` is forbidden from importing `socket` at all (tests/test_security.py).
    """
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


# What kind of evidence each policy state rests on. Separate from policy_summary()
# because the tests read that as a dict, and a third tuple element would break them.
#
# The row that made this necessary is "Router - BLOCKED". BLOCKED renders green, and
# green is what a live measurement looks like everywhere else - but the proof behind it
# is gate A16, run once and never re-run. The state is not downgraded; the panel prints
# the evidence kind beside it so "measured earlier" stops looking like "measured now".
POLICY_EVIDENCE = {
    PolicyState.ALLOWED: EvidenceKind.INFERENCE,
    PolicyState.BLOCKED: EvidenceKind.HISTORICAL,
    PolicyState.RULE_UNMEASURED: EvidenceKind.READ_BACK,
    PolicyState.NOT_ENFORCEABLE: EvidenceKind.HISTORICAL,
}


def policy_evidence(state) -> EvidenceKind:
    """Evidence kind for one policy row. Never raises.

    An unrecognised state falls back to INFERENCE - the weakest kind - for the same
    reason state_colour() falls back to red: a state nobody taught this module must not
    inherit a stronger claim than anyone checked.
    """
    return POLICY_EVIDENCE.get(state, EvidenceKind.INFERENCE)
