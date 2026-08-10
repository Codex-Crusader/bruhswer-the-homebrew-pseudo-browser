"""HostGuard — protects this PC from other devices on the same network.

This is a different problem from everything else in bruhswer. The rest of the app asks
"what can a website reach?"; HostGuard asks "what can the laptop at the next table
reach?" (brief SS10, SS11). It is useful even when the browser is not running.

It DETECTS and EXPLAINS. It never silently changes host configuration. Stage 4 found
this machine on university Wi-Fi with File and Printer Sharing enabled on the Public
profile and SMB signing off; the correct response is to tell the user and offer a
narrow, reversible fix they approve -- not to reconfigure their PC behind their back
(brief SS42, SS70).
"""

from __future__ import annotations

from .. import sysquery
from ..logging_setup import get_logger
from ..verdict import Check, Verdict

_log = get_logger("host")

# Wildcard-bound ports that are normal on any Windows machine. Flagging these would
# train the user to ignore the warning, which is worse than not warning at all.
_EXPECTED_WILDCARD_PORTS = {135, 445, 5040, 7680, 49664, 49665, 49666, 49667,
                            49668, 49669, 49670, 49671, 49672, 49673, 49674}


def evaluate() -> list[Check]:
    checks: list[Check] = []

    # --- network category -------------------------------------------------------
    profiles = sysquery.network_profiles()
    active = [p for p in profiles if p.get("IPv4Connectivity") == "Internet"] or profiles
    if not active:
        checks.append(Check("host.network", "Network category", Verdict.UNKNOWN,
                            "Could not read the network profile.", critical=False))
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
            evidence=f"category={category}"))

    # --- firewall ---------------------------------------------------------------
    fw = sysquery.firewall_profiles()
    if not fw:
        checks.append(Check("host.firewall", "Windows Firewall", Verdict.UNKNOWN,
                            "Could not read firewall profiles.", critical=True))
    else:
        disabled = [str(p.get("Name")) for p in fw if not p.get("Enabled")]
        checks.append(Check(
            "host.firewall", "Windows Firewall",
            Verdict.PASS if not disabled else Verdict.FAIL, critical=True,
            detail=("All profiles enabled." if not disabled
                    else f"DISABLED for: {', '.join(disabled)}"),
            evidence=f"disabled={disabled}"))

    # --- inbound sharing exposure ----------------------------------------------
    for group in sysquery.sharing_groups():
        name = str(group.get("Group", "?"))
        enabled = int(group.get("Enabled") or 0)
        total = int(group.get("Total") or 0)
        key = name.lower().replace(" ", "-")
        exposed = enabled > 0
        checks.append(Check(
            f"host.sharing.{key}", name,
            Verdict.FAIL if exposed else Verdict.PASS, critical=False,
            detail=(f"{enabled} of {total} rules are enabled for the Public profile. "
                    "Other devices on this network may reach this PC."
                    if exposed else "Not exposed on the Public profile."),
            evidence=f"enabled={enabled}/{total}"))

    # --- SMB --------------------------------------------------------------------
    smb = sysquery.smb_config()
    if smb is None:
        checks.append(Check("host.smb", "SMB configuration", Verdict.UNKNOWN,
                            "Could not read SMB server configuration.", critical=False))
    else:
        problems = []
        if smb.get("SMB1"):
            problems.append("SMBv1 is enabled")
        if not smb.get("RequireSigning"):
            problems.append("SMB signing is not required")
        checks.append(Check(
            "host.smb", "SMB hardening",
            Verdict.FAIL if problems else Verdict.PASS, critical=False,
            detail=("; ".join(problems) if problems
                    else "SMBv1 off and signing required."),
            evidence=f"smb1={smb.get('SMB1')} signing={smb.get('RequireSigning')}"))

    # --- remote administration ---------------------------------------------------
    remote = sysquery.remote_admin_status()
    if not remote:
        checks.append(Check("host.remoteadmin", "Remote administration", Verdict.UNKNOWN,
                            "Could not read remote-management service state.",
                            critical=False))
    else:
        running = [str(s.get("Name")) for s in remote
                   if str(s.get("Status")) == "Running"]
        # SSDP and function discovery are chatty on a LAN but are not remote admin.
        admin_running = [n for n in running if n in ("TermService", "WinRM",
                                                    "RemoteRegistry")]
        checks.append(Check(
            "host.remoteadmin", "Remote administration",
            Verdict.PASS if not admin_running else Verdict.FAIL, critical=False,
            detail=("Remote Desktop, WinRM and Remote Registry are not running."
                    if not admin_running else
                    "Running and potentially reachable: " + ", ".join(admin_running)),
            evidence=f"running={running}"))

        discovery = [n for n in running if n in ("SSDPSRV", "upnphost", "FDResPub")]
        if discovery:
            checks.append(Check(
                "host.discovery.services", "Network discovery services",
                Verdict.UNKNOWN, critical=False,
                detail=("Running: " + ", ".join(discovery) + ". These announce this PC "
                        "on a local network, but whether they are actually reachable "
                        "depends on firewall rules bruhswer checks separately."),
                evidence=f"discovery={discovery}"))

    # --- unexpected listeners ---------------------------------------------------
    listeners = sysquery.wildcard_listeners()
    if not listeners:
        checks.append(Check("host.listeners", "Unexpected listening services",
                            Verdict.UNKNOWN, "Could not enumerate listening sockets.",
                            critical=False))
    else:
        ports = sorted({int(item.get("LocalPort", 0)) for item in listeners})
        unexpected = [p for p in ports if p not in _EXPECTED_WILDCARD_PORTS]
        checks.append(Check(
            "host.listeners", "Unexpected listening services",
            Verdict.PASS if not unexpected else Verdict.FAIL, critical=False,
            detail=("Only standard Windows services are listening on all interfaces."
                    if not unexpected else
                    "Listening on all network interfaces: "
                    + ", ".join(str(p) for p in unexpected)),
            evidence=f"wildcard_ports={ports}"))

    # --- Defender (never changed by bruhswer, only observed) --------------------
    dfn = sysquery.defender_status()
    if dfn is None:
        checks.append(Check("host.defender", "Microsoft Defender", Verdict.UNKNOWN,
                            "Could not read Defender status.", critical=False))
    else:
        off = []
        if not dfn.get("RealTime"):
            off.append("real-time protection is off")
        if not dfn.get("Tamper"):
            off.append("tamper protection is off")
        checks.append(Check(
            "host.defender", "Microsoft Defender",
            Verdict.PASS if not off else Verdict.FAIL, critical=False,
            detail=("Real-time and tamper protection on."
                    + (" Controlled Folder Access on." if dfn.get("CFA") else
                       " Controlled Folder Access is off.")
                    if not off else "; ".join(off)),
            evidence=f"rtp={dfn.get('RealTime')} tamper={dfn.get('Tamper')} cfa={dfn.get('CFA')}"))

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
