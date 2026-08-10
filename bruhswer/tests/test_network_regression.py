"""Network regression suite — SS12 scope, SS13 browser self-bypass.

Requires the network policy to be applied (tools/bruhswer-netpolicy.ps1 -Action apply).

WHY THIS EXISTS SEPARATELY FROM THE OTHER TESTS
-----------------------------------------------
Two claims were being asserted rather than measured.

SS13 asks for the self-bypass test to be run "through the browser process itself... Do
not use an elevated process for the browser-side test." The app's `net.tamper` check
INFERS tamper-resistance from "bruhswer is unelevated" plus the Stage 4 A17
measurement. That is reasonable, but it is not a test. This file actually attempts the
bypasses, unelevated, in the same token class as the browser process (Stage 4 gate A4
measured the Edge browser process to be token-equivalent to an ordinary user process:
same user SID, MEDIUM integrity, 0 restricting SIDs, 5 privileges).

It also covers the case Stage 4 never tried: creating a PERMISSIVE REPLACEMENT rule.
Deleting the block is not the only way out - adding a broad Allow would be another.

SS12's last point, "unrelated applications are not accidentally blocked", had no
standing test at all. If a future change widened those rules from `-Program msedge.exe`
to machine-wide, nothing in the existing suite would have caught it, and the first
symptom would be the user's other software losing the network.

SAFETY
------
Every attempt here is EXPECTED to fail. If one unexpectedly succeeds, the test removes
what it created before reporting - it must never leave a permissive rule behind. It
changes nothing on success paths, and needs no elevation.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

import _env  # noqa: E402
from app import config, sysquery  # noqa: E402

CURL = os.path.join(os.environ["SystemRoot"], "System32", "curl.exe")
# Discovered at run time - see tests/_env.py. Hardcoding one machine's
# gateway made this suite pass while probing an address that did not exist.
ROUTER = _env.require_gateway()
PROBE_RULE = "bruhswer-SELFTEST-should-never-exist"

_passed: list[str] = []
_failed: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (_passed if ok else _failed).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))


def ps(script: str) -> str:
    proc = subprocess.run(
        [str(config.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=180, shell=False)
    return (proc.stdout or "").strip()


def cleanup_probe_rule() -> int:
    """Remove anything this test managed to create. Runs even on the happy path."""
    ps(f"Get-NetFirewallRule -DisplayName '{PROBE_RULE}' -ErrorAction SilentlyContinue "
       f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue")
    out = ps(f"@(Get-NetFirewallRule -DisplayName '{PROBE_RULE}' "
             f"-ErrorAction SilentlyContinue).Count")
    try:
        return int(out or 0)
    except ValueError:
        return -1


def main() -> int:
    print("bruhswer network regression  -  SS12 scope, SS13 self-bypass")
    print("=" * 74)

    edge = config.find_edge()
    if edge is None:
        print("Microsoft Edge not found; cannot run.")
        return 1

    rules = sysquery.bruhswer_rules()
    if len(rules) < 2:
        print(f"\nNetwork policy is not applied ({len(rules)} rules found).")
        print("Run: tools\\bruhswer-netpolicy.ps1 -Action apply")
        return 1

    elevated = sysquery.is_elevated()
    print(f"\nRunning elevated: {elevated}   (must be False - SS13 forbids testing "
          f"browser privileges from an elevated process)")
    if elevated is not False:
        print("REFUSING: this test is meaningless unless it runs unelevated.")
        return 1

    # ---------------------------------------------------------------- SS13
    print("\nSS13  Can a process with the browser's privileges undo its own rules?")

    target = f"{config.RULE_PREFIX}-edge-deny-ipv4-private"

    out = ps(f"try {{ Remove-NetFirewallRule -DisplayName '{target}' -ErrorAction Stop; "
             f"'DELETED' }} catch {{ 'REFUSED:' + $_.Exception.GetType().Name }}")
    check("cannot DELETE its own block rule", not out.startswith("DELETED"), out)

    out = ps(f"try {{ Set-NetFirewallRule -DisplayName '{target}' -Enabled False "
             f"-ErrorAction Stop; 'DISABLED' }} catch {{ 'REFUSED:' + "
             f"$_.Exception.GetType().Name }}")
    check("cannot DISABLE its own block rule", not out.startswith("DISABLED"), out)

    out = ps(f"try {{ Set-NetFirewallRule -DisplayName '{target}' -RemoteAddress Any "
             f"-ErrorAction Stop; 'MODIFIED' }} catch {{ 'REFUSED:' + "
             f"$_.Exception.GetType().Name }}")
    check("cannot MODIFY its own block rule", not out.startswith("MODIFIED"), out)

    # The case Stage 4 never tried: do not delete the block, out-vote it.
    out = ps(f"try {{ New-NetFirewallRule -DisplayName '{PROBE_RULE}' "
             f"-Direction Outbound -Action Allow -Program '{edge}' "
             f"-RemoteAddress Any -Profile Any -ErrorAction Stop | Out-Null; "
             f"'CREATED' }} catch {{ 'REFUSED:' + $_.Exception.GetType().Name }}")
    check("cannot CREATE a permissive replacement rule",
          not out.startswith("CREATED"), out)

    out = ps("try { Set-NetFirewallProfile -Profile Public -Enabled False "
             "-ErrorAction Stop; 'DISABLED-FIREWALL' } catch { 'REFUSED:' + "
             "$_.Exception.GetType().Name }")
    check("cannot DISABLE the firewall profile",
          not out.startswith("DISABLED-FIREWALL"), out)

    left = cleanup_probe_rule()
    check("no probe rule left behind", left == 0, f"remaining={left}")

    # ---------------------------------------------------------------- SS12
    print("\nSS12  Are the rules still scoped to the browser only?")

    for rule in rules:
        program = str(rule.get("Program", "")).lower()
        check(f"{rule.get('Name')} names only the browser executable",
              program == str(edge).lower(), program or "<no program filter>")

    # The regression that would otherwise go unnoticed: a rule accidentally widened to
    # every program. curl.exe is not the browser, so it must still reach the router.
    proc = subprocess.run([CURL, "-s", "-m", "8", "-o", os.devnull,
                           f"http://{ROUTER}/"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", shell=False)
    check("an UNRELATED program still reaches the router",
          proc.returncode == 0,
          f"curl exit {proc.returncode} (0 = reached, so scoping holds)")

    proc = subprocess.run([CURL, "-s", "-m", "8", "-o", os.devnull, "https://1.1.1.1/"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", shell=False)
    check("an UNRELATED program still reaches the internet",
          proc.returncode == 0, f"curl exit {proc.returncode}")

    # ---------------------------------------------------------------- verdict
    print("\n" + "=" * 74)
    print(f"PASSED {len(_passed)}   FAILED {len(_failed)}")
    if _failed:
        for name in _failed:
            print(f"  FAILED: {name}")
        print("\nA failure here means a security control regressed. Do not ship.")
        return 1
    print("\nBrowser-privilege bypass attempts all refused; rules remain browser-scoped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
