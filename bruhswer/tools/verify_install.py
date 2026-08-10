"""Install the built installer, verify it, uninstall it, verify nothing is left.

    python tools\\verify_install.py ..\\installer\\Output\\bruhswer-<version>-setup.exe

Per-user, no Administrator, and it uninstalls what it installs. Run it on a machine
with no existing bruhswer install - it refuses to start if one is present, because
uninstalling somebody's real installation to satisfy a checklist would be rude.

WHY THIS EXISTS AS A SCRIPT
    The 0.9.1 release shipped with eight unticked install boxes because the check was
    manual and nobody had a machine free. The first automated attempt then PASSED its
    "no tests/ in the install" assertions while looking at a directory the installer
    never writes to - the application is nested one level down, under {app}\\bruhswer.
    A check that passes because it is looking in the wrong place is worse than no check,
    so the layout is asserted explicitly below.

WHAT IT STILL DOES NOT PROVE
    It runs on a machine that already has Python and Edge, so it cannot exercise the
    prerequisite refusals. Those need a clean Windows image and are still unverified.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import winreg
from pathlib import Path

APP = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "bruhswer"
PKG = APP / "bruhswer"
START = (Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu"
         / "Programs" / "bruhswer")
USER_DATA = Path(os.environ["LOCALAPPDATA"]) / "BRUHWSER"
UNINST_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

_results: list[bool] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    _results.append(passed)
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))


def uninstall_entries() -> list[str]:
    found = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINST_KEY) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                sub = winreg.EnumKey(key, i)
                if "bruhswer" in sub.lower():
                    found.append(sub)
    except OSError:
        pass
    return found


def main(setup: Path) -> int:
    print(f"bruhswer install verification\n  artifact: {setup}\n")

    print("1. Pre-install state")
    if APP.exists() or uninstall_entries():
        print("  REFUSED: bruhswer is already installed. Uninstall it first; this "
              "script will not remove an installation it did not create.")
        return 2
    check("nothing installed to begin with", True, str(APP))

    print("\n2. Silent install")
    r = subprocess.run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                        "/TASKS=startmenuicon"], capture_output=True, text=True)
    time.sleep(3)
    check("installer exited 0", r.returncode == 0, f"rc={r.returncode}")
    check("install directory created", APP.is_dir(), str(APP))

    wanted = ["bruhswer.py", "app", "tools"]
    present = [w for w in wanted if (PKG / w).exists()]
    check("application files present", len(present) == len(wanted),
          f"{present} under {PKG}")
    check("licence and docs shipped",
          (APP / "LICENSE").exists() and (APP / "docs").is_dir())
    check("uninstaller present",
          (APP / "uninstall").is_dir() or any(APP.glob("unins*.exe")))

    print("\n3. What must NOT have shipped")
    for junk in ("tests", ".venv", "profiles", "logs", ".git", "__pycache__"):
        check(f"no {junk}/ in the install",
              not (PKG / junk).exists() and not (APP / junk).exists())

    print("\n4. Registration and shortcuts")
    check("appears in Installed apps", bool(uninstall_entries()),
          str(uninstall_entries()))
    check("Start Menu shortcut created", START.exists(), str(START))

    print("\n5. The installed copy runs from a clean working directory")
    probe = subprocess.run([sys.executable, str(PKG / "bruhswer.py"), "--check"],
                           capture_output=True, text=True, cwd=str(PKG),
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=300)
    # A non-zero exit is a legitimate "launch blocked" verdict. Only the absence of the
    # report means the installed copy could not run at all.
    check("installed app produced its report", "BRUH CHECK" in (probe.stdout or ""),
          f"exit={probe.returncode}, non-zero can be a correct blocked verdict")

    print("\n6. Silent uninstall")
    unins = next(iter(APP.glob("unins*.exe")), None) or APP / "uninstall" / "unins000.exe"
    check("uninstaller found", unins.exists(), str(unins))
    if unins.exists():
        u = subprocess.run([str(unins), "/VERYSILENT", "/SUPPRESSMSGBOXES",
                            "/NORESTART"], capture_output=True, text=True)
        time.sleep(5)
        check("uninstaller exited 0", u.returncode == 0, f"rc={u.returncode}")

    print("\n7. Nothing left behind")
    left = [str(p.relative_to(APP)) for p in APP.rglob("*")][:12] if APP.exists() else []
    check("install directory removed", not APP.exists(), f"leftovers: {left}")
    check("uninstall registration removed", not uninstall_entries())
    check("Start Menu shortcut removed", not START.exists())

    print("\n8. User data untouched")
    check("user data left alone, not silently deleted", USER_DATA.exists(),
          str(USER_DATA))

    print("\n" + "=" * 66)
    failed = len(_results) - sum(_results)
    print(f"{sum(_results)} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(Path(sys.argv[1]).resolve()))
