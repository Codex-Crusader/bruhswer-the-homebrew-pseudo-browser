"""bruhswer entry point.

    python bruhswer.py              launch the browser
    python bruhswer.py --panel      the security control panel, without a browser
    python bruhswer.py --check      run every verification, print it, no UI
    python bruhswer.py --hostguard  host exposure only, no browser involved
    python bruhswer.py --uninstall  show and remove everything bruhswer left

--check exists so the security verification can be run headless, in tests and in CI,
without a display.

--hostguard exists because Host Guard answers a different question from the rest of
bruhswer: not "what can a website reach?" but "what can the laptop at the next table
reach?". That question matters whether or not the browser is running (brief SS11), so
it must be answerable without starting one.

Neither mode launches a browser, and neither changes anything.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import config  # noqa: E402
from app.controller import controller as ctrl  # noqa: E402
from app.logging_setup import get_logger  # noqa: E402
from app.sessions import session_manager  # noqa: E402
from app.verdict import Verdict  # noqa: E402

_MARK = {Verdict.PASS: "PASS", Verdict.FAIL: "FAIL", Verdict.UNKNOWN: "UNKNOWN"}


def _use_utf8_stdio() -> None:
    """Make the text modes UTF-8 before anything is printed.

    MEASURED: `python bruhswer.py --check > out.txt` crashed with UnicodeEncodeError
    before printing a single line. When stdout is a pipe or a file rather than a
    console, Python picks the legacy ANSI codepage (cp1252 here), which cannot encode
    the moai in config.MOAI. Every text mode - --check, --hostguard, --uninstall - died
    on its first print, and so did the whole regression suite under CI, where stdout is
    always a pipe.

    The fix belongs here rather than in the strings: dropping the emoji would hide the
    defect while leaving every other non-ASCII character in the security output
    (arrows, bullets, accented CA subject names) able to kill a security report
    mid-sentence. A truncated security verdict is a worse failure than a missing glyph.

    `errors="replace"` so that even an unexpected character degrades to a visible
    placeholder instead of terminating the report.
    """
    for stream in (sys.stdout, sys.stderr):
        # getattr rather than a direct call. `reconfigure` is a TextIOWrapper method,
        # not part of the TextIO protocol, so calling it directly is an unresolved
        # reference to every static checker. Behaviour is unchanged - the old code
        # caught AttributeError for precisely this case; the lookup is now explicit.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            # Not a reconfigurable text stream (redirected oddly, or already closed).
            # Printing may still fail, but bruhswer must not fail to START over it.
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
    """Host exposure only. No browser, no session, no changes (brief SS11)."""
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


def run_uninstall() -> int:
    """Show and remove everything bruhswer has put on this machine.

    THE REASON THIS EXISTS: bruhswer's firewall rules are scoped to the browser and
    survive independently of bruhswer. Someone who applies network policy and then
    deletes the folder is left with Edge permanently unable to reach their own router
    or NAS, with nothing on the machine to explain why. That is a genuine harm caused
    by uninstalling, and a security tool must not leave that behind.

    Removes what it can unelevated, and prints the exact commands for what it cannot.
    """
    import shutil

    from app import sysquery

    print(f"{config.MOAI} bruhswer - remove everything")
    print("=" * 78)

    rules = sysquery.bruhswer_rules()
    print("\n1. FIREWALL RULES  (need Administrator - bruhswer will not elevate itself)")
    if rules:
        for rule in rules:
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
        # Refuse to follow a link out of bruhswer's own data root. These four paths
        # are bruhswer's own constants, so a junction sitting at one of them is not a
        # normal state - it is either a deliberate redirection or damage, and either
        # way turning a recursive delete loose on its target is the wrong response.
        if path.is_symlink():
            print(f"  SKIPPED: {path} is a link, not a folder. Refusing to delete "
                  f"through it - check what it points at before removing it by hand.")
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

    # Before ANY window is created. Tk is DPI-unaware by default while Edge is
    # per-monitor aware; hosting one inside the other with that mismatch makes Windows
    # virtualise the parent's coordinates but not the child's, and the page renders at
    # the wrong scale or clipped. Windows ignores this call once a window exists.
    from app.browser import embed  # noqa: E402 - must happen before Tk starts
    mode = embed.enable_dpi_awareness()
    get_logger("startup").info("DPI awareness: %s", mode)

    if "--hostguard" in sys.argv[1:]:
        return run_hostguard()

    if "--check" in sys.argv[1:]:
        return run_check()

    if "--panel" in sys.argv[1:]:
        # The original control panel, kept because it is useful without a browser.
        from app.ui.app_ui import BruhswerUI
        BruhswerUI().run()
        return 0

    from app.ui.browser_window import BrowserWindow
    BrowserWindow().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
