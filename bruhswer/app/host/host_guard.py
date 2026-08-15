"""HostGuard — protects this PC from other devices on the same network.

This is a different problem from everything else in bruhswer. The rest of the app asks
"what can a website reach?"; HostGuard asks "what can the laptop at the next table
reach?" (brief SS10, SS11). It is useful even when the browser is not running.

It DETECTS and EXPLAINS. It never silently changes host configuration. Stage 4 found
this machine on university Wi-Fi with File and Printer Sharing enabled on the Public
profile and SMB signing off; the correct response is to tell the user and offer a
narrow, reversible fix they approve -- not to reconfigure their PC behind their back
(brief SS42, SS70).

Every check here is a READ_BACK except `host.listeners` and `host.remoteadmin`, which
enumerate sockets and services that are open right now. HostGuard asks Windows what its
settings are; it never sends a packet at this PC from another machine. "File and Printer
Sharing is disabled for Public" is a configuration fact - "no device on this Wi-Fi can
reach this PC" is a claim bruhswer has never tested.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .. import sysquery
from ..logging_setup import get_logger
from ..verdict import Check, EvidenceKind, UnknownReason, Verdict, reason_for_probe

_log = get_logger("host")


def _gather() -> dict:
    """Run this module's seven queries at once and return them by name.

    Measured: HostGuard was 5213ms of a 9398ms pass, entirely spent waiting on
    PowerShell. The queries are read-only, touch no shared state, and none depends on
    another's result, so they are genuinely independent.

    Only the WAITING overlaps. Each probe still runs its own fixed script, keeps its own
    status, and is attributed on its own - a batched god-script would have turned seven
    reason codes into one.
    """
    queries = {
        "profiles": sysquery.network_profiles,
        "firewall": sysquery.firewall_profiles,
        "sharing": sysquery.sharing_groups,
        "smb": sysquery.smb_config,
        "remote": sysquery.remote_admin_status,
        "listeners": sysquery.wildcard_listeners,
        "defender": sysquery.defender_status,
    }
    with ThreadPoolExecutor(max_workers=len(queries),
                            thread_name_prefix="bruhswer-host") as pool:
        futures = {name: pool.submit(fn) for name, fn in queries.items()}
        return {name: future.result() for name, future in futures.items()}


# Wildcard-bound ports that are normal on any Windows machine. Flagging these would
# train the user to ignore the warning, which is worse than not warning at all.
_EXPECTED_WILDCARD_PORTS = {135, 445, 5040, 7680, 49664, 49665, 49666, 49667,
                            49668, 49669, 49670, 49671, 49672, 49673, 49674}

# The sharing groups queried, as (check_id suffix, display name). Named here so a
# failed query can emit the SAME check_ids the success path does: find_regressions only
# iterates the checks it can see, so an id that disappears is a PASS that silently
# vanishes from the lights rather than one that regresses.
_SHARING_GROUPS = (
    ("file-and-printer-sharing", "File and Printer Sharing"),
    ("network-discovery", "Network Discovery"),
    ("remote-desktop", "Remote Desktop"),
)


def _unmeasured(check_id: str, title: str, what: str, probe,
                critical: bool = False) -> Check:
    """One UNKNOWN check for a query that did not come back.

    Every failure here used to render as a bare "Could not read X", which reads like a
    glitch whether the cause was a timeout under load, a Windows edition with no such
    cmdlet, or an access denial that will never resolve. Those are three different next
    actions for the user.
    """
    reason = reason_for_probe(probe.status)
    advice = {
        UnknownReason.TIMEOUT:
            "The query did not finish in time. This is usually load, not a problem "
            "with the setting; it will normally clear on the next pass.",
        UnknownReason.PERMISSION_DENIED:
            "Windows refused the query. bruhswer runs unelevated by design and will "
            "not ask for Administrator to read this.",
        UnknownReason.UNSUPPORTED:
            "This edition of Windows does not provide the query bruhswer uses, so "
            "this control cannot be checked from here at all.",
    }.get(reason, "bruhswer could not complete the query.")
    return Check(
        check_id, title, Verdict.UNKNOWN, critical=critical,
        detail=f"{what} was not established. {advice}",
        evidence=probe.reason(),
        evidence_kind=EvidenceKind.READ_BACK,
        unknown_reason=reason)


def evaluate() -> list[Check]:
    checks: list[Check] = []
    probes = _gather()

    # --- network category -------------------------------------------------------
    profiles = probes["profiles"]
    if not profiles.ok:
        checks.append(_unmeasured("host.network", "Network category",
                                  "This PC's network category", profiles))
    else:
        active = [p for p in profiles.value
                  if p.get("IPv4Connectivity") == "Internet"] or profiles.value
        if not active:
            # Query succeeded; there is genuinely no network. Not a failed measurement.
            checks.append(Check(
                "host.network", "Network category", Verdict.UNKNOWN, critical=False,
                detail="Windows reports no connected network, so there is no network "
                       "category for this PC right now.",
                evidence=f"profiles=0 {profiles.reason()}",
                evidence_kind=EvidenceKind.READ_BACK,
                unknown_reason=UnknownReason.NOT_APPLICABLE))
        else:
            primary = active[0]
            category = str(primary.get("NetworkCategory", ""))
            name = str(primary.get("Name", "?"))
            on_untrusted = category in ("Public",)
            checks.append(Check(
                "host.network", "Network category",
                Verdict.PASS if on_untrusted else Verdict.UNKNOWN, critical=False,
                detail=(f"'{name}' is {category}."
                        + (" Windows applies its restrictive profile." if on_untrusted
                           else " On an untrusted network, Public is safer.")),
                evidence=f"category={category} {profiles.reason()}",
                evidence_kind=EvidenceKind.READ_BACK,
                # The category read fine. What is unknown on a non-Public network is
                # whether this network is trustworthy, which nobody has measured.
                unknown_reason=(UnknownReason.NONE if on_untrusted
                                else UnknownReason.NEVER_MEASURED)))

    # --- firewall ---------------------------------------------------------------
    fw = probes["firewall"]
    if not fw.ok:
        checks.append(_unmeasured("host.firewall", "Windows Firewall",
                                  "Whether Windows Firewall is enabled", fw,
                                  critical=True))
    elif not fw.value:
        checks.append(Check(
            "host.firewall", "Windows Firewall", Verdict.UNKNOWN, critical=True,
            detail="Windows returned no firewall profiles at all, which bruhswer "
                   "cannot interpret as either enabled or disabled.",
            evidence=f"profiles=0 {fw.reason()}",
            evidence_kind=EvidenceKind.READ_BACK,
            unknown_reason=UnknownReason.MALFORMED_OUTPUT))
    else:
        disabled = [str(p.get("Name")) for p in fw.value if not p.get("Enabled")]
        checks.append(Check(
            "host.firewall", "Windows Firewall",
            Verdict.PASS if not disabled else Verdict.FAIL, critical=True,
            detail=("All profiles are enabled. This is what Windows reports the "
                    "setting to be; bruhswer has not tested the firewall by sending "
                    "traffic at this PC."
                    if not disabled else f"DISABLED for: {', '.join(disabled)}"),
            evidence=f"disabled={disabled} {fw.reason()}",
            evidence_kind=EvidenceKind.READ_BACK))

    # --- inbound sharing exposure ----------------------------------------------
    sharing = probes["sharing"]
    if not sharing.ok:
        for key, name in _SHARING_GROUPS:
            checks.append(_unmeasured(
                f"host.sharing.{key}", name,
                f"Whether {name} is enabled on the Public profile", sharing))
    else:
        for group in sharing.value:
            name = str(group.get("Group", "?"))
            enabled = int(group.get("Enabled") or 0)
            total = int(group.get("Total") or 0)
            key = name.lower().replace(" ", "-")
            exposed = enabled > 0
            checks.append(Check(
                f"host.sharing.{key}", name,
                Verdict.FAIL if exposed else Verdict.PASS, critical=False,
                detail=(f"{enabled} of {total} rules are enabled for the Public "
                        f"profile. Other devices on this network may reach this PC."
                        if exposed else
                        "No rules in this group are enabled for the Public profile."),
                evidence=f"enabled={enabled}/{total} {sharing.reason()}",
                evidence_kind=EvidenceKind.READ_BACK))

    # --- SMB --------------------------------------------------------------------
    smb = probes["smb"]
    if not smb.ok or smb.value is None:
        checks.append(_unmeasured("host.smb", "SMB hardening",
                                  "The SMB server's configuration", smb))
    else:
        problems = []
        if smb.value.get("SMB1"):
            problems.append("SMBv1 is enabled")
        if not smb.value.get("RequireSigning"):
            problems.append("SMB signing is not required")
        checks.append(Check(
            "host.smb", "SMB hardening",
            Verdict.FAIL if problems else Verdict.PASS, critical=False,
            detail=("; ".join(problems) if problems
                    else "SMBv1 is off and signing is required."),
            evidence=f"smb1={smb.value.get('SMB1')} "
                     f"signing={smb.value.get('RequireSigning')} {smb.reason()}",
            evidence_kind=EvidenceKind.READ_BACK))

    # --- remote administration ---------------------------------------------------
    remote = probes["remote"]
    if not remote.ok:
        checks.append(_unmeasured("host.remoteadmin", "Remote administration",
                                  "Which remote-management services are running",
                                  remote))
    elif not remote.value:
        checks.append(Check(
            "host.remoteadmin", "Remote administration", Verdict.UNKNOWN,
            critical=False,
            detail="Windows returned no service records at all, so bruhswer cannot "
                   "say whether remote administration is running.",
            evidence=f"services=0 {remote.reason()}",
            evidence_kind=EvidenceKind.LIVE,
            unknown_reason=UnknownReason.MALFORMED_OUTPUT))
    else:
        running = [str(s.get("Name")) for s in remote.value
                   if str(s.get("Status")) == "Running"]
        # SSDP and function discovery are chatty on a LAN but are not remote admin.
        admin_running = [n for n in running if n in ("TermService", "WinRM",
                                                    "RemoteRegistry")]
        # LIVE: Status is what the service is doing; StartType would be the readback.
        checks.append(Check(
            "host.remoteadmin", "Remote administration",
            Verdict.PASS if not admin_running else Verdict.FAIL, critical=False,
            detail=("Remote Desktop, WinRM and Remote Registry are not running."
                    if not admin_running else
                    "Running and potentially reachable: " + ", ".join(admin_running)),
            evidence=f"running={running} {remote.reason()}",
            evidence_kind=EvidenceKind.LIVE))

        discovery = [n for n in running if n in ("SSDPSRV", "upnphost", "FDResPub")]
        if discovery:
            checks.append(Check(
                "host.discovery.services", "Network discovery services",
                Verdict.UNKNOWN, critical=False,
                detail=("Running: " + ", ".join(discovery) + ". These announce this PC "
                        "on a local network, but whether they are actually reachable "
                        "depends on firewall rules bruhswer checks separately."),
                evidence=f"discovery={discovery} {remote.reason()}",
                evidence_kind=EvidenceKind.LIVE,
                # The services ARE running - that part is measured. What is unknown is
                # their reachability, and nobody has measured that from another host.
                unknown_reason=UnknownReason.NEVER_MEASURED))

    # --- unexpected listeners ---------------------------------------------------
    listeners = probes["listeners"]
    if not listeners.ok:
        checks.append(_unmeasured("host.listeners", "Unexpected listening services",
                                  "Which sockets are listening on all interfaces",
                                  listeners))
    else:
        # An empty list is now a real finding: the envelope proves the query ran.
        ports = sorted({int(item.get("LocalPort", 0)) for item in listeners.value})
        unexpected = [p for p in ports if p not in _EXPECTED_WILDCARD_PORTS]
        checks.append(Check(
            "host.listeners", "Unexpected listening services",
            Verdict.PASS if not unexpected else Verdict.FAIL, critical=False,
            detail=("Only standard Windows services are listening on all interfaces."
                    if not unexpected else
                    "Listening on all network interfaces: "
                    + ", ".join(str(p) for p in unexpected)),
            evidence=f"wildcard_ports={ports} {listeners.reason()}",
            evidence_kind=EvidenceKind.LIVE))

    # --- Defender (never changed by bruhswer, only observed) --------------------
    dfn = probes["defender"]
    if not dfn.ok or dfn.value is None:
        checks.append(_unmeasured("host.defender", "Microsoft Defender",
                                  "Microsoft Defender's status", dfn))
    else:
        off = []
        if not dfn.value.get("RealTime"):
            off.append("real-time protection is off")
        if not dfn.value.get("Tamper"):
            off.append("tamper protection is off")
        checks.append(Check(
            "host.defender", "Microsoft Defender",
            Verdict.PASS if not off else Verdict.FAIL, critical=False,
            detail=("Real-time and tamper protection are on."
                    + (" Controlled Folder Access is on." if dfn.value.get("CFA") else
                       " Controlled Folder Access is off.")
                    if not off else "; ".join(off)),
            evidence=f"rtp={dfn.value.get('RealTime')} tamper={dfn.value.get('Tamper')} "
                     f"cfa={dfn.value.get('CFA')} {dfn.reason()}",
            evidence_kind=EvidenceKind.READ_BACK))

    return checks


def remediations(checks: list[Check]) -> list[dict]:
    """Narrow, reversible fixes for what was actually found. Nothing is applied here.

    Each entry names the exact change so the user can read it before agreeing, and
    every one is scoped to the Public profile or a single setting -- never a blanket
    "harden everything" (brief SS42).
    """
    found = {c.check_id: c for c in checks}
    out: list[dict] = []

    sharing = found.get("host.sharing.file-and-printer-sharing")
    if sharing is not None and sharing.verdict is Verdict.FAIL:
        out.append({
            "id": "disable-public-file-sharing",
            "title": "Turn off File and Printer Sharing on Public networks",
            "risk": ("Other devices on this Wi-Fi may be able to reach this PC's file "
                     "sharing service. On a university or cafe network that is a real "
                     "exposure."),
            "change": ("Disable the 'File and Printer Sharing' firewall rules that "
                       "apply to the Public profile only. Home and work networks are "
                       "unaffected."),
            "rollback": "Re-enable the same rule group for the Public profile.",
            "elevated": True,
        })

    smb = found.get("host.smb")
    if smb is not None and smb.verdict is Verdict.FAIL:
        out.append({
            "id": "require-smb-signing",
            "title": "Require SMB signing",
            "risk": "Without signing, SMB sessions are easier to relay or tamper with.",
            "change": "Set RequireSecuritySignature to true on the SMB server.",
            "rollback": "Set RequireSecuritySignature back to its previous value.",
            "elevated": True,
        })

    return out
