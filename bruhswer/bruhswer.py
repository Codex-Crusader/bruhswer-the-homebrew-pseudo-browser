"""bruhswer entry point.

    python bruhswer.py              launch the browser
    python bruhswer.py --panel      the security control panel, without a browser
    python bruhswer.py --check      run every verification, print it, no UI
    python bruhswer.py --hostguard  host exposure only, no browser involved
    python bruhswer.py --uninstall  show and remove everything bruhswer left

--check and --hostguard launch no browser and change nothing.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import config, sysquery  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.logging_setup import get_logger  # noqa: E402
from app.sessions import session_manager  # noqa: E402
from app.verdict import Verdict  # noqa: E402

_MARK = {Verdict.PASS: "PASS", Verdict.FAIL: "FAIL", Verdict.UNKNOWN: "UNKNOWN"}


def _use_utf8_stdio() -> None:
    """Make stdout and stderr UTF-8. Redirected, Python uses the ANSI codepage and
    `--check > out.txt` died on its first line (measured)."""
    for stream in (sys.stdout, sys.stderr):
        # getattr: reconfigure is not part of the TextIO protocol.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def run_check() -> int:
    controller = ctrl.Controller()
    result = controller.verify(session_manager.PERSISTENT)

    print(f"{config.MOAI} bruhswer  -  {config.TAGLINE}")
    print("=" * 78)
    print("\nBRUH CHECK\n")
    for name, verdict, blurb in ctrl.summarise(result):
        print(f"  {name:<12} {_MARK[verdict]:<8} {blurb}")

    print("\nDETAIL\n")
    for check in result.checks:
        mark = "NOT ENFORCEABLE" if not check.enforceable else _MARK[check.verdict]
        print(f"  [{mark:<15}] {check.title}")
        print(f"      {check.detail}")

    blockers = result.blockers
    print("\n" + "=" * 78)
    if blockers:
        print("BRUH. NO. Browser launch blocked because required security controls")
        print("could not be verified:")
        for check in blockers:
            print(f"  - {check.title}: {check.detail}")
        return 1

    print("bruhswer READY  -  all critical controls verified.")
    print("\nReminder: this is not a virtual machine. It reduces what a website can")
    print("reach and learn. It does not make you immune to anything.")
    return 0


def run_hostguard() -> int:
    """Host exposure only. No browser, no session, no changes."""
    from app.host import host_guard

    checks = host_guard.evaluate()
    print(f"{config.MOAI} bruhswer HOST GUARD")
    print("=" * 78)
    print("\nWhat other devices on this network might reach on this PC.\n")

    for check in checks:
        mark = {Verdict.PASS: "OK", Verdict.FAIL: "EXPOSED",
                Verdict.UNKNOWN: "UNKNOWN"}[check.verdict]
        print(f"  {mark:<9} {check.title}")
        print(f"            {check.detail}")

    exposed = [c for c in checks if c.verdict is Verdict.FAIL]
    unknown = [c for c in checks if c.verdict is Verdict.UNKNOWN]
    fixes = host_guard.remediations(checks)

    print("\n" + "=" * 78)
    if not exposed and not unknown:
        print("WE GOOD  -  nothing exposed that bruhswer knows how to check.")
        return 0

    if exposed:
        print(f"SUS  -  {len(exposed)} finding(s) exposed:")
        for check in exposed:
            print(f"  - {check.title}")
    if unknown:
        print(f"\n{len(unknown)} thing(s) could not be determined and are reported as")
        print("UNKNOWN rather than assumed fine:")
        for check in unknown:
            print(f"  - {check.title}")

    if fixes:
        print("\nbruhswer can fix these, but will not do it on its own:")
        for fix in fixes:
            print(f"\n  {fix['title']}")
            print(f"    risk   : {fix['risk']}")
            print(f"    change : {fix['change']}")
            print(f"    undo   : {fix['rollback']}")
        print("\n  Run as administrator, and it will explain everything again and wait")
        print("  for you to type FIX before changing anything:")
        print("    tools\\bruhswer-hostguard.ps1 -Action fix-sharing")
        print("    tools\\bruhswer-hostguard.ps1 -Action revert")
    return 0


def _is_reparse_point(path: Path) -> bool:
    """True for a symlink OR a directory junction, which is_symlink() misses."""
    try:
        info = path.stat(follow_symlinks=False)
    except OSError:
        return True
    return bool(getattr(info, "st_file_attributes", 0)
                & config.FILE_ATTRIBUTE_REPARSE_POINT)


def run_uninstall() -> int:
    """Show and remove everything bruhswer put on this machine. The firewall rules
    outlive bruhswer and would leave Edge unable to reach the LAN, so the commands to
    remove them are printed."""
    print(f"{config.MOAI} bruhswer - remove everything")
    print("=" * 78)

    rules = sysquery.bruhswer_rules()
    print("\n1. FIREWALL RULES  (need Administrator - bruhswer will not elevate itself)")
    if not rules.ok:
        # A failed query must not read as "no rules to remove".
        print(f"     could not read the firewall rules ({rules.status}). Check for "
              f"rules named {config.RULE_PREFIX}-* yourself before assuming none exist.")
    elif rules.value:
        for rule in rules.value:
            print(f"     {rule.get('Name')}")
        print("\n   These are what stop the browser reaching your router and LAN.")
        print("   LEAVING THEM BEHIND after deleting bruhswer means Edge stays blocked")
        print("   with nothing left on the machine to explain it. Remove them with:")
        print("\n     powershell -ExecutionPolicy Bypass -File "
              "tools\\bruhswer-netpolicy.ps1 -Action remove")
    else:
        print("     none present")

    state_file = config.STATE / "hostguard-rollback.json"
    print("\n2. HOST CHANGES made by Host Guard")
    if state_file.is_file():
        print("     A rollback record exists, so Host Guard has changed this PC's")
        print("     firewall profile or SMB settings. Undo them BEFORE deleting the")
        print("     record, or the original state is lost:")
        print("\n     powershell -ExecutionPolicy Bypass -File "
              "tools\\bruhswer-hostguard.ps1 -Action revert")
    else:
        print("     none - Host Guard has not changed this PC")

    print("\n3. BRUHSWER'S OWN DATA")
    removable = [config.PROFILE_PERSISTENT, config.PROFILE_DISPOSABLE_ROOT,
                 config.QUARANTINE, config.LOGS]
    for path in removable:
        if path.is_dir():
            count = sum(1 for _ in path.rglob("*"))
            print(f"     {path}  ({count} items)")

    answer = input("\nDelete bruhswer's profiles, quarantine and logs now? "
                   "Type DELETE to confirm: ")
    if answer != "DELETE":
        print("Cancelled. Nothing was removed.")
        return 0

    if config.QUARANTINE.is_dir() and any(config.QUARANTINE.rglob("*")):
        print("\n  NOTE: quarantine is not empty. Anything in it will be destroyed.")
        again = input("  Still delete? Type DELETE again: ")
        if again != "DELETE":
            print("Cancelled. Nothing was removed.")
            return 0

    for path in removable:
        # A junction at one of bruhswer's own paths is redirection or damage; never
        # delete through it.
        if _is_reparse_point(path):
            print(f"  SKIPPED: {path} is a link or junction, not a folder. Refusing "
                  f"to delete through it - check what it points at before removing "
                  f"it by hand.")
            continue
        shutil.rmtree(path, ignore_errors=True)
        print(f"  removed: {path}  ->  gone={not path.exists()}")

    print("\n  The state folder is kept, because it holds the Host Guard rollback")
    print(f"  record: {config.STATE}")
    print("\nDone. Delete the bruhswer folder itself when the steps above are complete.")
    return 0


def main() -> int:
    _use_utf8_stdio()
    config.ensure_dirs()
    session_manager.sweep_orphans()

    if "--uninstall" in sys.argv[1:]:
        return run_uninstall()

    # Before any window exists; see embed.enable_dpi_awareness.
    from app.browser import embed  # noqa: E402 - must happen before Tk starts
    mode = embed.enable_dpi_awareness()
    get_logger("startup").info("DPI awareness: %s", mode)

    if "--hostguard" in sys.argv[1:]:
        return run_hostguard()

    if "--check" in sys.argv[1:]:
        return run_check()

    if "--panel" in sys.argv[1:]:
        from app.ui.app_ui import BruhswerUI
        BruhswerUI().run()
        return 0

    from app.ui.browser_window import BrowserWindow
    BrowserWindow().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
