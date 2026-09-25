"""Install the built installer, verify it, uninstall it, verify nothing is left.

    python tools\\verify_install.py ..\\installer\\Output\\bruhswer-<version>-setup.exe

Per-user, no Administrator. Refuses to start if bruhswer is already installed. The
install layout ({app}\\bruhswer) is asserted, because an early version checked the
wrong folder and passed. Prerequisite refusals need a clean Windows image and are
not covered.
"""

from __future__ import annotations

import os
import shutil
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
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
          + (f"  -  {detail}" if detail else ""))


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


def _data_census() -> dict[str, tuple[int, int]]:
    """subfolder -> (file count, total bytes) of the user's bruhswer data, taken
    before install and after uninstall."""
    out: dict[str, tuple[int, int]] = {}
    for name in ("profiles", "quarantine", "logs", "state"):
        folder = USER_DATA / name
        if not folder.is_dir():
            out[name] = (0, 0)
            continue
        files = [f for f in folder.rglob("*") if f.is_file()]
        out[name] = (len(files), sum(f.stat().st_size for f in files))
    return out


def _system_changes_present() -> bool:
    """Firewall rules or a Host Guard rollback record still present, checked
    independently of the uninstaller."""
    if (USER_DATA / "state" / "hostguard-rollback.json").is_file():
        return True
    probe = subprocess.run(
        [str(Path(os.environ["SystemRoot"]) / "System32" / "netsh.exe"),
         "advfirewall", "firewall", "show", "rule",
         "name=BRUHWSER-edge-deny-ipv4-private"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60, shell=False)
    return probe.returncode == 0


def _backup_user_data() -> Path | None:
    """Back up the REAL %LOCALAPPDATA%\\BRUHWSER first: the uninstall is real, and in
    0.11.0 it deleted a 110 MB profile. Returns the backup path, or None."""
    if not USER_DATA.is_dir() or not any(USER_DATA.iterdir()):
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = Path(os.environ["TEMP"]) / f"bruhswer-userdata-{stamp}"
    shutil.copytree(USER_DATA, target, dirs_exist_ok=True)
    files = sum(1 for f in target.rglob("*") if f.is_file())
    size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    print(f"  backed up {files} file(s), {size / 1024 / 1024:.1f} MB")
    print(f"  -> {target}")
    return target


def main(setup: Path) -> int:
    print(f"bruhswer install verification\n  artifact: {setup}\n")

    print("0. Protecting the real user data this script is about to risk")
    backup = _backup_user_data()
    check("user data backed up, or there was none to back up",
          backup is not None or not USER_DATA.is_dir()
          or not any(USER_DATA.iterdir()),
          str(backup) if backup else "no existing user data")

    before = _data_census()

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

    # The only check on a REAL install that the manifest shipped and is fresh.
    manifest = PKG / "app" / "security" / "MANIFEST.sha256"
    check("file manifest shipped", manifest.is_file(), str(manifest))

    if manifest.is_file():
        verdict = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); "
             "from app.security import integrity; "
             "r = integrity.check_tree(); "
             "print('OK' if r.ok else 'DRIFT', r.matched, r.total, "
             "r.changed[:3], r.missing[:3], r.unexpected[:3])",
             str(PKG)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, shell=False)
        out = (verdict.stdout or "").strip()
        check("installed files match the shipped manifest", out.startswith("OK"),
              out or (verdict.stderr or "")[:160])

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
    # A non-zero exit is a legitimate verdict; only a missing report is a failure.
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
    after = _data_census()
    # Per folder: the root always survives (state\ is kept), so checking it alone
    # passed while a 110 MB profile was deleted.
    for name in ("profiles", "quarantine", "state"):
        was, now = before.get(name), after.get(name)
        check(f"{name}/ unchanged by install and uninstall", was == now,
              f"before={was} after={now}")

    # Nothing REMOVED; logs/ legitimately grows from step 5's --check.
    was_logs, now_logs = before.get("logs", (0, 0)), after.get("logs", (0, 0))
    check("logs/ not deleted (may grow; the installed app ran)",
          now_logs[0] >= was_logs[0] and now_logs[1] >= was_logs[1],
          f"before={was_logs} after={now_logs}")

    print("\n9. Cleanup instructions for the system-wide changes")
    # The undo scripts must survive the uninstall, which deletes the install folder.
    expect_kit = _system_changes_present()
    kit = USER_DATA / "cleanup"
    if not expect_kit:
        check("no cleanup kit needed (no system-wide changes found)", True)
    else:
        check("cleanup kit written where the uninstall cannot remove it",
              kit.is_dir(), str(kit))
        for name in ("HOW-TO-CLEAN-UP.txt", "bruhswer-netpolicy.ps1",
                     "bruhswer-hostguard.ps1"):
            check(f"  {name} present", (kit / name).is_file())
        guide = kit / "HOW-TO-CLEAN-UP.txt"
        if guide.is_file():
            text = guide.read_text(encoding="utf-8", errors="replace")
            check("  guide names only scripts that are actually there",
                  all((kit / s).is_file() for s in
                      ("bruhswer-netpolicy.ps1", "bruhswer-hostguard.ps1")
                      if s in text))

    print("\n" + "=" * 66)
    failed = len(_results) - sum(_results)
    print(f"{sum(_results)} passed, {failed} failed")

    if backup is not None:
        # Kept: if step 8 failed, it is the only copy of the user's profile.
        print(f"\nUser data backup kept at:\n  {backup}")
        if failed:
            print("Step 8 reported a change. RESTORE FROM THE BACKUP ABOVE before "
                  "running anything else against this machine.")
        else:
            print("Nothing was lost; delete it whenever you like.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(Path(sys.argv[1]).resolve()))
