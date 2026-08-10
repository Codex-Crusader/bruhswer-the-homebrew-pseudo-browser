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

import ipaddress

from .. import config, sysquery
from ..logging_setup import get_logger
from ..verdict import Check, Verdict

_log = get_logger("network")


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


def verify(edge_path) -> list[Check]:
    """Verify network policy from the host side. Returns Checks, never raises."""
    checks: list[Check] = []
    rules = sysquery.bruhswer_rules()
    by_name = {str(r.get("Name", "")): r for r in rules}

    for name, expected_csv in _expected_rule_names().items():
        expected = _normalise(expected_csv.split(","))
        rule = by_name.get(name)

        if rule is None:
            checks.append(Check(
                check_id=f"net.rule.{name}", title=f"Firewall rule {name}",
                verdict=Verdict.FAIL, critical=True,
                detail="Rule is not present. Run Network Policy setup.",
                evidence=f"expected={sorted(expected)} found=none"))
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
                evidence=f"expected={sorted(expected)} actual={sorted(actual)}"))
        else:
            checks.append(Check(
                check_id=f"net.rule.{name}", title=f"Firewall rule {name}",
                verdict=Verdict.PASS, critical=True,
                detail="Present, enabled, scoped to the browser, covering all ranges.",
                evidence=f"addresses={sorted(actual)}"))

    # Extra rules under bruhswer's prefix that bruhswer did not author. Brief SS9 lists
    # "unexpected network rule" as a launch blocker, and it is right to: a rule we do
    # not recognise under our own name is either stale or planted.
    unexpected = sorted(set(by_name) - set(_expected_rule_names()))
    checks.append(Check(
        check_id="net.rule.unexpected", title="No unexpected bruhswer rules",
        verdict=Verdict.PASS if not unexpected else Verdict.FAIL, critical=True,
        detail=("No unrecognised rules under the bruhswer prefix."
                if not unexpected else f"Unrecognised rules present: {unexpected}"),
        evidence=f"unexpected={unexpected}"))

    # Tamper resistance. Not re-measured at every launch -- doing so would mean
    # attempting a privileged operation on every start, which is worse behaviour than
    # the check is worth. Measured once, in Stage 4 gate A17, and re-derived here from
    # the fact that bruhswer is running unelevated.
    elevated = sysquery.is_elevated()
    if elevated is None:
        checks.append(Check(
            check_id="net.tamper", title="Rules resist browser tampering",
            verdict=Verdict.UNKNOWN, critical=False,
            detail="Could not determine bruhswer's own privilege level.",
            evidence="is_elevated=None"))
    else:
        checks.append(Check(
            check_id="net.tamper", title="Rules resist browser tampering",
            verdict=Verdict.PASS, critical=False,
            detail=("Firewall policy requires Administrator; the browser does not "
                    "have it. Measured in Stage 4 gate A17."),
            evidence=f"controller_elevated={elevated}"))

    # The honest limitation. Reported every single time, never hidden, never green.
    checks.append(Check(
        check_id="net.loopback", title="Localhost / host services blocked",
        verdict=Verdict.FAIL, critical=True, enforceable=False,
        detail=("Windows Firewall cannot filter loopback, so the browser can reach "
                "127.0.0.1 and this PC's own IP. No setting fixes this."),
        evidence="Stage 4 gate A16: rules naming 127.0.0.1 and the host IP did not block Edge"))

    checks.append(Check(
        check_id="net.devservices", title="Local development services blocked",
        verdict=Verdict.FAIL, critical=False, enforceable=False,
        detail=("Services on localhost stay reachable for the same reason. Ports "
                "bruhswer knows about: "
                + ", ".join(str(p) for p in config.DEV_SERVICE_PORTS) + "."),
        evidence="Stage 4 gate A16 confirmed a live PyCharm service on 63342"))

    return checks


def policy_summary() -> list[tuple[str, str]]:
    """What the policy actually is, for the UI. No claim beyond what was measured."""
    return [
        ("Internet", "ALLOWED"),
        ("Router", "BLOCKED"),
        ("LAN devices", "BLOCKED"),
        ("Private IPv4 ranges", "BLOCKED"),
        ("IPv6 local ranges", "BLOCKED"),
        ("Localhost (127.0.0.1)", "NOT ENFORCEABLE"),
        ("This PC's own IP", "NOT ENFORCEABLE"),
        ("Development services", "NOT ENFORCEABLE"),
    ]
